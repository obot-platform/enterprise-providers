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

func (s *groupStore) migrate(ctx context.Context) error {
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
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create group tables: %w", err)
		}
	}
	return nil
}

// setUserGroups replaces the groups recorded for userID with the groups in an ID token issued at issuedAt, unless the
// groups already recorded come from a newer token. A user may have several sessions, refreshed at different times and
// served by different replicas, so the newest token wins rather than the latest request. It reports whether the
// groups were written. groups must already be normalized by normalizeGroups.
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

	// The upsert locks the user's row, whether or not it updates it, so concurrent writes for one user run one after
	// the other.
	result, err := tx.ExecContext(ctx,
		`INSERT INTO `+usersTable+` (user_id, token_issued_at, updated_at) VALUES ($1, $2, now())
		 ON CONFLICT (user_id) DO UPDATE SET token_issued_at = excluded.token_issued_at, updated_at = excluded.updated_at
		 WHERE `+usersTable+`.token_issued_at <= excluded.token_issued_at`, userID, issuedAt)
	if err != nil {
		return false, fmt.Errorf("record user: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil {
		return false, err
	} else if n == 0 {
		return false, nil
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM `+membershipsTable+` WHERE user_id = $1 AND NOT (group_name = ANY($2))`, userID, groups); err != nil {
		return false, fmt.Errorf("remove old memberships: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO `+membershipsTable+` (user_id, group_name) SELECT $1, unnest($2::text[])
		 ON CONFLICT DO NOTHING`, userID, groups); err != nil {
		return false, fmt.Errorf("add memberships: %w", err)
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
