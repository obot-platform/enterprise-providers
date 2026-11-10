package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // Registers the "pgx" database/sql driver.
	sessionstore "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/postgres"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// The tables share the manifest's postgresTablePrefix, which namespaces them alongside oauth2-proxy's session
// tables, and Obot drops them with the rest when the provider is deconfigured.
const (
	usersTable       = "pingfederate_directory_users"
	membershipsTable = "pingfederate_directory_memberships"
)

// errUnknownUser means no groups were ever recorded for a user.
var errUnknownUser = errors.New("no groups are recorded for this user")

// groupStore records the groups that PingFederate released for each user at sign-in and token refresh.
//
// PingFederate has no API to list groups or a user's groups, so these tables are the provider's directory: a user's
// groups are what their most recent tokens said, and the groups that exist are the groups at least one recorded user
// is in. Rows are keyed by the raw group value from the groups claim, which is the group's identity in Obot.
type groupStore struct {
	db *sql.DB
}

func openGroupStore(ctx context.Context, dsn string, maxOpen, maxIdle, lifetimeSeconds int) (*groupStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if maxOpen > 0 {
		db.SetMaxOpenConns(maxOpen)
	}
	if maxIdle > 0 {
		db.SetMaxIdleConns(maxIdle)
	}
	if lifetimeSeconds > 0 {
		db.SetConnMaxLifetime(time.Duration(lifetimeSeconds) * time.Second)
	}

	s := &groupStore{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// prepareDatabase creates oauth2-proxy's session tables and this provider's group tables, and opens the group store.
//
// Every Obot replica runs its own provider, and they start together, but concurrent CREATE TABLE statements for one
// table can fail in PostgreSQL. So the tables are created while holding an advisory lock, which serializes the
// replicas: the first creates them, and the rest find them. The lock is held by a transaction, so that it holds through
// a transaction-pooling proxy, and it is released when the transaction ends. Everything done under it is bounded by
// ctx, so a replica stalled on the database cannot keep the others waiting; nothing under it reaches PingFederate.
// oauth2-proxy migrates its tables again when the proxy is created, which then only reads the catalog.
func prepareDatabase(ctx context.Context, opts Options, sessionTablePrefix string) (*groupStore, error) {
	db, err := sql.Open("pgx", opts.PostgresConnectionDSN)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("take the startup lock: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, startupLockKey); err != nil {
		return nil, fmt.Errorf("take the startup lock: %w", err)
	}

	if err := migrateSessionTables(ctx, opts.PostgresConnectionDSN, sessionTablePrefix); err != nil {
		return nil, err
	}
	return openGroupStore(ctx, opts.PostgresConnectionDSN, opts.PostgresMaxConnections, opts.PostgresMaxIdleConnections, opts.PostgresConnectionLifetimeSeconds)
}

// migrateSessionTables creates oauth2-proxy's session and session lock tables as its PostgreSQL session store does.
func migrateSessionTables(ctx context.Context, dsn, prefix string) error {
	gdb, err := gorm.Open(gormpostgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	if sqlDB, err := gdb.DB(); err == nil {
		defer sqlDB.Close()
	}
	gdb = gdb.WithContext(ctx)
	if err := gdb.Table(prefix + "sessions").AutoMigrate(&sessionstore.Session{}); err != nil {
		return fmt.Errorf("create session tables: %w", err)
	}
	if err := gdb.Table(prefix + "session_locks").AutoMigrate(&sessionstore.SessionLock{}); err != nil {
		return fmt.Errorf("create session tables: %w", err)
	}
	return nil
}

// startupLockKey names the startup lock. It differs from the key migrate locks, so that migrating while holding it
// cannot wait on itself.
const startupLockKey = "pingfederate_startup"

// migrate creates the tables. Every Obot replica runs its own provider, and replicas start together, but concurrent
// CREATE ... IF NOT EXISTS statements for one table can fail in PostgreSQL. So the statements run in one transaction
// that first takes an advisory lock, which serializes the replicas: the first creates the tables, the rest find them.
func (s *groupStore) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create group tables: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, usersTable); err != nil {
		return fmt.Errorf("create group tables: %w", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS ` + usersTable + ` (
			user_id TEXT PRIMARY KEY,
			token_issued_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + membershipsTable + ` (
			user_id TEXT NOT NULL REFERENCES ` + usersTable + `(user_id) ON DELETE CASCADE,
			-- Bytewise ("C") collation keeps the listing order, and so the cursor, the same on every database, and
			-- lets the group_name index serve the listing's range and order as well as equality lookups.
			group_name TEXT COLLATE "C" NOT NULL,
			PRIMARY KEY (user_id, group_name)
		)`,
		`CREATE INDEX IF NOT EXISTS ` + membershipsTable + `_group_name ON ` + membershipsTable + ` (group_name)`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create group tables: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create group tables: %w", err)
	}
	return nil
}

// setUserGroups records groups as userID's groups according to an ID token issued at issuedAt. A user may have
// several sessions, refreshed at different times and served by different replicas, so the newest token wins rather
// than the latest request:
//
//   - groups from an older token than the recorded ones are not written;
//   - groups from a newer token replace them;
//   - groups from a token issued in the same second, whose iat cannot tell which is newer, can only remove groups.
//     Two such tokens differ only if PingFederate's answer changed within that second, and withholding a group until
//     the next refresh is the safe way to be wrong.
//
// It reports whether anything was written. groups must already be normalized by normalizeGroups.
func (s *groupStore) setUserGroups(ctx context.Context, userID string, groups []string, issuedAt time.Time) (bool, error) {
	if groups == nil {
		// A nil slice is sent as NULL, and "group_name = ANY(NULL)" would keep every old membership.
		groups = []string{}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	// Make sure the user's row exists, then lock it, so that concurrent writes for one user run one after the other
	// and each sees what the one before it recorded.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO `+usersTable+` (user_id, token_issued_at, updated_at) VALUES ($1, to_timestamp(0), now())
		 ON CONFLICT (user_id) DO NOTHING`, userID); err != nil {
		return false, fmt.Errorf("record user: %w", err)
	}
	var recordedAt time.Time
	if err := tx.QueryRowContext(ctx,
		`SELECT token_issued_at FROM `+usersTable+` WHERE user_id = $1 FOR UPDATE`, userID).Scan(&recordedAt); err != nil {
		return false, fmt.Errorf("record user: %w", err)
	}
	if recordedAt.After(issuedAt) {
		return false, nil
	}
	tie := recordedAt.Equal(issuedAt)

	if _, err := tx.ExecContext(ctx,
		`UPDATE `+usersTable+` SET token_issued_at = $2, updated_at = now() WHERE user_id = $1`, userID, issuedAt); err != nil {
		return false, fmt.Errorf("record user: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM `+membershipsTable+` WHERE user_id = $1 AND NOT (group_name = ANY($2))`, userID, groups); err != nil {
		return false, fmt.Errorf("remove old memberships: %w", err)
	}
	if !tie {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO `+membershipsTable+` (user_id, group_name) SELECT $1, unnest($2::text[])
			 ON CONFLICT DO NOTHING`, userID, groups); err != nil {
			return false, fmt.Errorf("add memberships: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// userGroups returns the groups recorded for userID, or errUnknownUser when none were ever recorded.
func (s *groupStore) userGroups(ctx context.Context, userID string) ([]string, error) {
	var known bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM `+usersTable+` WHERE user_id = $1)`, userID).Scan(&known); err != nil {
		return nil, err
	}
	if !known {
		return nil, errUnknownUser
	}
	return s.queryNames(ctx,
		`SELECT group_name FROM `+membershipsTable+` WHERE user_id = $1 ORDER BY group_name`, userID)
}

// listGroups returns up to limit groups whose name contains filter, ordered by name and starting after the name after.
// It also reports whether more groups follow. The filter is case-insensitive in the database's default collation, so
// that letters beyond ASCII fold too. Names are ordered bytewise, by the column's collation, so that the cursor means
// the same thing on every replica and database.
func (s *groupStore) listGroups(ctx context.Context, filter, after string, limit int) ([]string, bool, error) {
	names, err := s.queryNames(ctx,
		`SELECT DISTINCT group_name FROM `+membershipsTable+`
		 WHERE group_name > $1 AND ($2 = '' OR group_name COLLATE "default" ILIKE '%' || $2 || '%' ESCAPE '\')
		 ORDER BY group_name LIMIT $3`, after, escapeLike(filter), limit+1)
	if err != nil {
		return nil, false, err
	}
	if len(names) > limit {
		return names[:limit], true, nil
	}
	return names, false, nil
}

// knownGroups returns which of names are a group of at least one recorded user.
func (s *groupStore) knownGroups(ctx context.Context, names []string) ([]string, error) {
	return s.queryNames(ctx,
		`SELECT DISTINCT group_name FROM `+membershipsTable+` WHERE group_name = ANY($1) ORDER BY group_name`, names)
}

func (s *groupStore) queryNames(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// maxGroupLength bounds a group value. Group IDs travel in query strings and list cursors, and no real group name or
// DN is anywhere near this long.
const maxGroupLength = 1024

// normalizeGroups trims, drops empty, overlong and duplicate values, and sorts, so that equal sets compare equal.
// Dropping a value can only withhold a group, never grant one.
func normalizeGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if g = strings.TrimSpace(g); g == "" {
			continue
		}
		if len(g) > maxGroupLength {
			fmt.Printf("WARNING: pingfederate-auth-provider: ignoring a group value of %d bytes, longer than the %d allowed\n", len(g), maxGroupLength)
			continue
		}
		out = append(out, g)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
