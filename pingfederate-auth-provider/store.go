package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

const (
	// postgresTablePrefix is the prefix of every table this provider keeps in
	// Obot's database: oauth2-proxy's session tables and the group tables
	// below. It must agree with postgresTablePrefix in the manifest.
	postgresTablePrefix = "pingfederate_"
	// userGroupsTable and seenGroupsTable must agree with postgresTables in
	// the manifest, which tells Obot to drop them when the provider is
	// deconfigured.
	userGroupsTable = postgresTablePrefix + "user_groups"
	seenGroupsTable = postgresTablePrefix + "seen_groups"

	// userGroupsTTL is how long a user's recorded groups answer Obot's
	// lookups without the user being seen again.
	userGroupsTTL = 24 * time.Hour
	// seenGroupsTTL is how long a group stays in the group picker after the
	// last time any member signed in with it.
	seenGroupsTTL = 90 * 24 * time.Hour
	// maxSeenGroups bounds the groups listed in the group picker, besides the
	// declared ones.
	maxSeenGroups = 10000
	// rewriteInterval is how often an unchanged record is written again, to
	// keep it from expiring. A change is written at once.
	rewriteInterval = time.Hour
	// pruneInterval is how often expired rows are deleted.
	pruneInterval = time.Hour
)

// groupStore remembers each user's groups, for the lookups Obot makes without
// a token, and every group seen, for the group picker. Every replica of Obot
// runs its own copy of the provider, so in a multi-replica deployment the
// store must be shared: postgresGroupStore. Without a database, memoryGroupStore
// keeps the same records in this process.
type groupStore interface {
	// setUserGroups records groups for a user under each of keys. source
	// identifies the observation, normally a fingerprint of the access token
	// the groups were read with: a user's groups change only with a new
	// token, so a repeat from the same source need not be written again.
	setUserGroups(ctx context.Context, keys, groups []string, source string) error
	// userGroups returns the groups recorded for key, and whether any are.
	userGroups(ctx context.Context, key string) ([]string, bool, error)
	// addSeenGroups records that groups exist.
	addSeenGroups(ctx context.Context, groups []string) error
	// seenGroups returns the recorded groups, most recently seen first, up
	// to maxSeenGroups.
	seenGroups(ctx context.Context) ([]string, error)
}

// memoryGroupStore keeps the records in this process. It loses them on a
// restart and does not share them with other replicas.
type memoryGroupStore struct {
	users *expirable.LRU[string, []string]

	mu   sync.Mutex
	seen map[string]time.Time // group name -> when it was last seen
	now  func() time.Time
}

func newMemoryGroupStore() *memoryGroupStore {
	return &memoryGroupStore{
		users: expirable.NewLRU[string, []string](cacheSize, nil, userGroupsTTL),
		seen:  map[string]time.Time{},
		now:   time.Now,
	}
}

func (m *memoryGroupStore) setUserGroups(_ context.Context, keys, groups []string, _ string) error {
	for _, key := range keys {
		m.users.Add(key, groups)
	}
	return nil
}

func (m *memoryGroupStore) userGroups(_ context.Context, key string) ([]string, bool, error) {
	groups, ok := m.users.Get(key)
	return groups, ok, nil
}

func (m *memoryGroupStore) addSeenGroups(_ context.Context, groups []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, name := range groups {
		m.seen[name] = now
	}
	// When full, drop the groups seen least recently, as the PostgreSQL store
	// lists only the most recently seen.
	for len(m.seen) > maxSeenGroups {
		var oldest string
		var oldestAt time.Time
		for name, at := range m.seen {
			if oldest == "" || at.Before(oldestAt) {
				oldest, oldestAt = name, at
			}
		}
		delete(m.seen, oldest)
	}
	return nil
}

func (m *memoryGroupStore) seenGroups(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := m.now().Add(-seenGroupsTTL)
	names := make([]string, 0, len(m.seen))
	for name, at := range m.seen {
		if at.After(cutoff) {
			names = append(names, name)
		} else {
			delete(m.seen, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if a, b := m.seen[names[i]], m.seen[names[j]]; !a.Equal(b) {
			return a.After(b)
		}
		return names[i] < names[j]
	})
	return names, nil
}

type userGroupsRow struct {
	UserKey   string    `gorm:"primaryKey"`
	Groups    string    // a JSON array of group names
	UpdatedAt time.Time `gorm:"index"`
}

type seenGroupRow struct {
	Name       string    `gorm:"primaryKey"`
	LastSeenAt time.Time `gorm:"index"`
}

// postgresGroupStore keeps the records in Obot's database, shared by every
// replica and kept across restarts.
type postgresGroupStore struct {
	db *gorm.DB
	// written remembers what this process last wrote for a key, from which
	// observation, and when, so that the request path writes only new
	// observations and occasional renewals rather than on every request.
	written *expirable.LRU[string, writtenRecord]
	now     func() time.Time
}

type writtenRecord struct {
	value string
	at    time.Time
}

// openPostgresGroupStore connects to Obot's database and creates the tables.
// They are created only here, when the provider starts: Obot drops them when
// the provider is deconfigured, possibly while it is still running on another
// replica, and a write must not bring them back.
func openPostgresGroupStore(cfg *settings) (*postgresGroupStore, error) {
	db, err := gorm.Open(postgres.Open(cfg.PostgresConnectionDSN), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get postgres connection: %w", err)
	}
	if cfg.PostgresMaxConnections > 0 {
		sqlDB.SetMaxOpenConns(cfg.PostgresMaxConnections)
	}
	if cfg.PostgresMaxIdleConnections > 0 {
		sqlDB.SetMaxIdleConns(cfg.PostgresMaxIdleConnections)
	}
	if cfg.PostgresConnectionLifetimeSeconds > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(cfg.PostgresConnectionLifetimeSeconds) * time.Second)
	}
	if err := migrateWithRetry(db, userGroupsTable, &userGroupsRow{}); err != nil {
		return nil, err
	}
	if err := migrateWithRetry(db, seenGroupsTable, &seenGroupRow{}); err != nil {
		return nil, err
	}
	return &postgresGroupStore{
		db:      db,
		written: expirable.NewLRU[string, writtenRecord](cacheSize, nil, rewriteInterval),
		now:     time.Now,
	}, nil
}

// migrateWithRetry creates or updates a table. Every replica starts the
// provider when it is first configured, and creating the same table at the
// same moment can fail on all but one of them, so a failure is retried after
// the winner has had time to finish.
func migrateWithRetry(db *gorm.DB, table string, model any) error {
	var err error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		if err = db.Table(table).AutoMigrate(model); err == nil {
			return nil
		}
	}
	return fmt.Errorf("create table %s: %w", table, err)
}

// due reports whether value must be written for key: it is new, or it was
// last written long enough ago that it needs renewing.
//
// A value is new when it differs from what this process last wrote, or comes
// from another observation. Comparing values alone is not enough with several
// replicas: if this one wrote X, another then wrote Y, and the user's groups
// changed back to X, skipping the identical X would leave Y in place.
func (p *postgresGroupStore) due(key, value string) bool {
	last, ok := p.written.Get(key)
	return !ok || last.value != value || p.now().Sub(last.at) >= rewriteInterval
}

func (p *postgresGroupStore) setUserGroups(ctx context.Context, keys, groups []string, source string) error {
	encoded, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	now := p.now()
	var rows []userGroupsRow
	for _, key := range keys {
		if p.due("user:"+key, source+"\x00"+string(encoded)) {
			rows = append(rows, userGroupsRow{UserKey: key, Groups: string(encoded), UpdatedAt: now})
		}
	}
	if len(rows) == 0 {
		return nil
	}
	if err := p.db.WithContext(ctx).Table(userGroupsTable).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_key"}},
		DoUpdates: clause.AssignmentColumns([]string{"groups", "updated_at"}),
	}).Create(&rows).Error; err != nil {
		return fmt.Errorf("record user groups: %w", err)
	}
	for _, row := range rows {
		p.written.Add("user:"+row.UserKey, writtenRecord{value: source + "\x00" + row.Groups, at: now})
	}
	return nil
}

func (p *postgresGroupStore) userGroups(ctx context.Context, key string) ([]string, bool, error) {
	var row userGroupsRow
	err := p.db.WithContext(ctx).Table(userGroupsTable).
		Where("user_key = ? AND updated_at > ?", key, p.now().Add(-userGroupsTTL)).
		Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("look up user groups: %w", err)
	}
	var groups []string
	if err := json.Unmarshal([]byte(row.Groups), &groups); err != nil {
		return nil, false, fmt.Errorf("decode user groups: %w", err)
	}
	if groups == nil {
		groups = []string{}
	}
	return groups, true, nil
}

func (p *postgresGroupStore) addSeenGroups(ctx context.Context, groups []string) error {
	now := p.now()
	var rows []seenGroupRow
	for _, name := range groups {
		if p.due("seen:"+name, "") {
			rows = append(rows, seenGroupRow{Name: name, LastSeenAt: now})
		}
	}
	if len(rows) == 0 {
		return nil
	}
	if err := p.db.WithContext(ctx).Table(seenGroupsTable).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"last_seen_at"}),
	}).Create(&rows).Error; err != nil {
		return fmt.Errorf("record seen groups: %w", err)
	}
	for _, row := range rows {
		p.written.Add("seen:"+row.Name, writtenRecord{at: now})
	}
	return nil
}

func (p *postgresGroupStore) seenGroups(ctx context.Context) ([]string, error) {
	var names []string
	if err := p.db.WithContext(ctx).Table(seenGroupsTable).
		Where("last_seen_at > ?", p.now().Add(-seenGroupsTTL)).
		Order("last_seen_at DESC").Limit(maxSeenGroups).
		Pluck("name", &names).Error; err != nil {
		return nil, fmt.Errorf("list seen groups: %w", err)
	}
	return names, nil
}

// prune deletes expired rows. Expired rows are already ignored, so this only
// keeps the tables from growing.
func (p *postgresGroupStore) prune(ctx context.Context) error {
	now := p.now()
	if err := p.db.WithContext(ctx).Table(userGroupsTable).
		Where("updated_at <= ?", now.Add(-userGroupsTTL)).Delete(&userGroupsRow{}).Error; err != nil {
		return fmt.Errorf("prune user groups: %w", err)
	}
	if err := p.db.WithContext(ctx).Table(seenGroupsTable).
		Where("last_seen_at <= ?", now.Add(-seenGroupsTTL)).Delete(&seenGroupRow{}).Error; err != nil {
		return fmt.Errorf("prune seen groups: %w", err)
	}
	return nil
}

// pruneEvery prunes expired rows until ctx ends.
func (p *postgresGroupStore) pruneEvery(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := p.prune(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("failed to prune expired group records", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// filterGroups returns the trimmed, non-empty, de-duplicated names in order.
func filterGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	seen := map[string]bool{}
	for _, g := range groups {
		if g = strings.TrimSpace(g); g != "" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

// sortGroupNames sorts names case-insensitively, then exactly, which is the
// order the group picker pages through.
func sortGroupNames(names []string) {
	sort.Slice(names, func(i, j int) bool {
		if a, b := strings.ToLower(names[i]), strings.ToLower(names[j]); a != b {
			return a < b
		}
		return names[i] < names[j]
	})
}
