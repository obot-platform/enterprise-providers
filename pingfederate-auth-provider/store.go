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
	// renewInterval is how often a record that has not changed is written
	// again, to keep an active user's record, or a group in use, from
	// expiring. Anything newer is written at once.
	renewInterval = time.Hour
	// pruneInterval is how often expired rows are deleted.
	pruneInterval = time.Hour
)

// groupStore remembers each user's groups, for the lookups Obot makes without
// a token, and every group seen, for the group picker. Every replica of Obot
// runs its own copy of the provider, so in a multi-replica deployment the
// store must be shared: postgresGroupStore. Without a database, memoryGroupStore
// keeps the same records in this process.
type groupStore interface {
	// recordUserGroups records a user's groups, as observed at observedAt:
	// when userinfo answered, or when the ID token they came from was issued.
	// An observation older than the one recorded is ignored, so that a
	// replica holding an older answer cannot overwrite a newer one, whatever
	// order the writes arrive in. It also records that the groups exist, for
	// the group picker.
	recordUserGroups(ctx context.Context, key string, groups []string, observedAt time.Time) error
	// userGroups returns the groups recorded for key, and whether any are.
	userGroups(ctx context.Context, key string) ([]string, bool, error)
	// seenGroups returns the recorded groups, most recently seen first, up
	// to maxSeenGroups.
	seenGroups(ctx context.Context) ([]string, error)
}

// memoryGroupStore keeps the records in this process. It loses them on a
// restart and does not share them with other replicas.
type memoryGroupStore struct {
	users *expirable.LRU[string, observedGroups]

	mu   sync.Mutex
	seen map[string]time.Time // group name -> when it was last seen
	now  func() time.Time
}

func newMemoryGroupStore() *memoryGroupStore {
	return &memoryGroupStore{
		users: expirable.NewLRU[string, observedGroups](cacheSize, nil, userGroupsTTL),
		seen:  map[string]time.Time{},
		now:   time.Now,
	}
}

// observedGroups is a user's groups as observed at a point in time.
type observedGroups struct {
	groups     []string
	observedAt time.Time
}

func (m *memoryGroupStore) recordUserGroups(ctx context.Context, key string, groups []string, observedAt time.Time) error {
	m.mu.Lock()
	if current, ok := m.users.Peek(key); !ok || !observedAt.Before(current.observedAt) {
		m.users.Add(key, observedGroups{groups: groups, observedAt: observedAt})
	}
	m.mu.Unlock()
	return m.addSeenGroups(ctx, groups)
}

func (m *memoryGroupStore) userGroups(_ context.Context, key string) ([]string, bool, error) {
	current, ok := m.users.Get(key)
	return current.groups, ok, nil
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
	UserKey string `gorm:"primaryKey"`
	Groups  string // a JSON array of group names
	// ObservedAt is when the groups were observed, which orders writes.
	ObservedAt time.Time
	// UpdatedAt is when the row was last written, which expires it.
	UpdatedAt time.Time `gorm:"index"`
}

type seenGroupRow struct {
	Name       string    `gorm:"primaryKey"`
	LastSeenAt time.Time `gorm:"index"`
}

// postgresGroupStore keeps the records in Obot's database, shared by every
// replica and kept across restarts.
//
// Writes are conditional upserts, so that whether a row changes is decided by
// PostgreSQL, atomically, from what the row holds, and not by anything a
// replica remembers. A request that brings nothing newer than the row matches
// no condition, and PostgreSQL leaves the row as it is.
type postgresGroupStore struct {
	db  *gorm.DB
	now func() time.Time
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
	return &postgresGroupStore{db: db, now: time.Now}, nil
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

// recordUserGroups reads before it writes. Most requests repeat what is
// recorded, and a plain read takes no lock, while an INSERT ... ON CONFLICT
// DO UPDATE locks the conflicting row even when its WHERE leaves the row
// unchanged: a group every user is in would have its row locked by every
// request. So one read decides whether anything is newer or due for renewal,
// and only then do the conditional upserts run. They keep their conditions,
// so that PostgreSQL still decides, atomically, between replicas writing at
// the same time.
const (
	// readRecorded returns the user's recorded observation, if any, and
	// which of their groups were seen recently enough to need no renewal.
	readRecorded = `SELECT
	(SELECT observed_at FROM ` + userGroupsTable + ` WHERE user_key = @key) AS observed_at,
	(SELECT updated_at FROM ` + userGroupsTable + ` WHERE user_key = @key) AS updated_at,
	CAST(COALESCE((SELECT json_agg(name) FROM ` + seenGroupsTable + `
		WHERE name IN (SELECT jsonb_array_elements_text(CAST(@groups AS jsonb)))
		AND last_seen_at > @renewBefore), '[]') AS text) AS fresh_groups`

	// upsertUserGroups writes a user's groups if the observation is newer
	// than the recorded one, or if it is the same observation and the row is
	// due for renewal, which keeps an active user's row from expiring.
	upsertUserGroups = `INSERT INTO ` + userGroupsTable + ` AS t (user_key, groups, observed_at, updated_at)
	VALUES (@key, @groups, @observedAt, @now)
	ON CONFLICT (user_key) DO UPDATE
	SET groups = EXCLUDED.groups, observed_at = EXCLUDED.observed_at, updated_at = EXCLUDED.updated_at
	WHERE EXCLUDED.observed_at > COALESCE(t.observed_at, '-infinity')
	   OR (EXCLUDED.observed_at = t.observed_at AND t.updated_at <= @renewBefore)`

	// upsertSeenGroups records groups for the group picker, renewing each at
	// most once per renewInterval. Rows are written in name order, so that
	// two statements locking overlapping groups lock them in the same order.
	upsertSeenGroups = `INSERT INTO ` + seenGroupsTable + ` AS t (name, last_seen_at)
	SELECT name, CAST(@now AS timestamptz)
	FROM (SELECT DISTINCT jsonb_array_elements_text(CAST(@seen AS jsonb)) AS name) AS names
	ORDER BY name
	ON CONFLICT (name) DO UPDATE
	SET last_seen_at = EXCLUDED.last_seen_at
	WHERE t.last_seen_at <= @renewBefore`
)

func (p *postgresGroupStore) recordUserGroups(ctx context.Context, key string, groups []string, observedAt time.Time) error {
	if groups == nil {
		groups = []string{}
	}
	encoded, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	now := p.now()
	observedAt = truncateToPostgres(observedAt)
	args := map[string]any{
		"key":         key,
		"groups":      string(encoded),
		"observedAt":  observedAt,
		"now":         now,
		"renewBefore": now.Add(-renewInterval),
	}
	db := p.db.WithContext(ctx)

	var recorded struct {
		ObservedAt  *time.Time
		UpdatedAt   *time.Time
		FreshGroups string // a JSON array of group names
	}
	if err := db.Raw(readRecorded, args).Row().Scan(&recorded.ObservedAt, &recorded.UpdatedAt, &recorded.FreshGroups); err != nil {
		return fmt.Errorf("read recorded groups: %w", err)
	}

	userDue := recorded.ObservedAt == nil || recorded.UpdatedAt == nil ||
		observedAt.After(*recorded.ObservedAt) ||
		(observedAt.Equal(*recorded.ObservedAt) && !recorded.UpdatedAt.After(now.Add(-renewInterval)))
	if userDue {
		if err := db.Exec(upsertUserGroups, args).Error; err != nil {
			return fmt.Errorf("record user groups: %w", err)
		}
	}

	var freshGroups []string
	if err := json.Unmarshal([]byte(recorded.FreshGroups), &freshGroups); err != nil {
		return fmt.Errorf("decode recorded groups: %w", err)
	}
	fresh := map[string]bool{}
	for _, name := range freshGroups {
		fresh[name] = true
	}
	var seenDue []string
	for _, name := range groups {
		if !fresh[name] {
			seenDue = append(seenDue, name)
		}
	}
	if len(seenDue) > 0 {
		encodedSeen, err := json.Marshal(seenDue)
		if err != nil {
			return err
		}
		args["seen"] = string(encodedSeen)
		if err := db.Exec(upsertSeenGroups, args).Error; err != nil {
			return fmt.Errorf("record seen groups: %w", err)
		}
	}
	return nil
}

// truncateToPostgres drops what PostgreSQL's timestamps cannot hold, so that
// the same observation compares equal to itself once stored.
func truncateToPostgres(t time.Time) time.Time {
	return t.Truncate(time.Microsecond)
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
