package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// testPostgresEnv names a PostgreSQL DSN for the tests that need a database. They are skipped without one:
//
//	docker run -d --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
//	PINGFEDERATE_TEST_POSTGRES_DSN='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./...
const testPostgresEnv = "PINGFEDERATE_TEST_POSTGRES_DSN"

// testDSN returns a DSN whose tables live in a schema of the test's own, dropped when the test ends.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(testPostgresEnv)
	if dsn == "" {
		t.Skipf("%s is not set", testPostgresEnv)
	}

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	schema := fmt.Sprintf("pingfederate_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Error(err)
		}
	})

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

var issuedClock = time.Now()

// issued returns successive token issue times.
func issued() time.Time {
	issuedClock = issuedClock.Add(time.Second)
	return issuedClock
}

func at(seconds int) time.Time { return time.Unix(1_700_000_000+int64(seconds), 0) }

func testStore(t *testing.T) *groupStore {
	t.Helper()
	store, err := openGroupStore(t.Context(), testDSN(t), 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.db.Close() })
	return store
}

func TestStoreReplacesUserGroups(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)

	if _, err := store.userGroups(ctx, "alice"); !errors.Is(err, errUnknownUser) {
		t.Fatalf("unknown user: err = %v, want errUnknownUser", err)
	}

	for _, step := range [][]string{
		{"admins", "engineering"},
		{"engineering", "sales"},
		{},
	} {
		if _, err := store.setUserGroups(ctx, "alice", step, issued()); err != nil {
			t.Fatal(err)
		}
		got, err := store.userGroups(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, step) {
			t.Fatalf("userGroups = %q, want %q", got, step)
		}
	}

	// A user who has no groups is known, which is different from a user never seen.
	if got, err := store.userGroups(ctx, "alice"); err != nil || len(got) != 0 {
		t.Fatalf("userGroups = %q, %v; want no groups and no error", got, err)
	}
}

func TestStoreListsGroupsWithMembers(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)

	for user, groups := range map[string][]string{
		"alice": {"admins", "engineering"},
		"bob":   {"engineering", "100%_done"},
		"carol": {"Sales"},
		"dave":  {"cn=Équipe Paris,ou=groups"},
	} {
		if _, err := store.setUserGroups(ctx, user, groups, issued()); err != nil {
			t.Fatal(err)
		}
	}

	page := func(filter, after string, limit int) ([]string, bool) {
		t.Helper()
		names, more, err := store.listGroups(ctx, filter, after, limit)
		if err != nil {
			t.Fatal(err)
		}
		return names, more
	}

	var all []string
	after := ""
	for {
		names, more := page("", after, 2)
		all = append(all, names...)
		if !more {
			break
		}
		after = names[len(names)-1]
	}
	if want := []string{"100%_done", "Sales", "admins", "cn=Équipe Paris,ou=groups", "engineering"}; !slices.Equal(all, want) {
		t.Fatalf("paged listing = %q, want %q", all, want)
	}

	if names, _ := page("SALES", "", 10); !slices.Equal(names, []string{"Sales"}) {
		t.Fatalf("filter is not case-insensitive: %q", names)
	}
	if names, _ := page("équipe", "", 10); !slices.Equal(names, []string{"cn=Équipe Paris,ou=groups"}) {
		t.Fatalf("filter does not fold non-ASCII case: %q", names)
	}
	// LIKE wildcards in the filter match themselves.
	if names, _ := page("%", "", 10); !slices.Equal(names, []string{"100%_done"}) {
		t.Fatalf("filter %% matched %q", names)
	}
	if names, _ := page("_", "", 10); !slices.Equal(names, []string{"100%_done"}) {
		t.Fatalf("filter _ matched %q", names)
	}

	// A group nobody is in any more is no longer listed.
	if _, err := store.setUserGroups(ctx, "carol", nil, issued()); err != nil {
		t.Fatal(err)
	}
	known, err := store.knownGroups(ctx, []string{"Sales", "engineering", "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(known, []string{"engineering"}) {
		t.Fatalf("knownGroups = %q, want [engineering]", known)
	}
}

func TestStoreMigrationIsSafeAcrossReplicas(t *testing.T) {
	// Every Obot replica runs its own provider, and they start together against a database without the tables.
	dsn := testDSN(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			store, err := openGroupStore(t.Context(), dsn, 0, 0, 0)
			if err != nil {
				errs <- err
				return
			}
			_ = store.db.Close()
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a replica failed to start: %v", err)
	}
}

func TestStoreMigrationIsIdempotent(t *testing.T) {
	store := testStore(t)
	if err := store.migrate(t.Context()); err != nil {
		t.Fatalf("second migration: %v", err)
	}
}

func TestRecorderWritesOnlyChanges(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)
	recorder := newGroupRecorder(store)

	updatedAt := func() time.Time {
		t.Helper()
		var at time.Time
		if err := store.db.QueryRowContext(ctx, "SELECT updated_at FROM "+usersTable+" WHERE user_id = 'alice'").Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}

	if err := recorder.record(ctx, "alice", []string{"b", "a"}, at(1)); err != nil {
		t.Fatal(err)
	}
	first := updatedAt()

	// The same token is not written again.
	if err := recorder.record(ctx, "alice", []string{"a", " b", "a"}, at(1)); err != nil {
		t.Fatal(err)
	}
	if got := updatedAt(); !got.Equal(first) {
		t.Fatal("unchanged groups were written again")
	}

	if err := recorder.record(ctx, "alice", []string{"a"}, at(2)); err != nil {
		t.Fatal(err)
	}
	if got, err := store.userGroups(ctx, "alice"); err != nil || !slices.Equal(got, []string{"a"}) {
		t.Fatalf("userGroups = %q, %v; want [a]", got, err)
	}
}

func TestRecorderDoesNotRememberFailedWrites(t *testing.T) {
	store := testStore(t)
	recorder := newGroupRecorder(store)

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := recorder.record(canceled, "alice", []string{"a"}, at(1)); err == nil {
		t.Fatal("record succeeded with a canceled context")
	}
	if err := recorder.record(t.Context(), "alice", []string{"a"}, at(1)); err != nil {
		t.Fatal(err)
	}
	if got, err := store.userGroups(t.Context(), "alice"); err != nil || !slices.Equal(got, []string{"a"}) {
		t.Fatalf("a failed write was remembered as written: %q, %v", got, err)
	}
}

func TestStoreKeepsGroupsFromTheNewestToken(t *testing.T) {
	ctx := t.Context()
	store := testStore(t)

	if wrote, err := store.setUserGroups(ctx, "alice", []string{"a"}, at(2)); err != nil || !wrote {
		t.Fatalf("setUserGroups = %v, %v", wrote, err)
	}
	if wrote, err := store.setUserGroups(ctx, "alice", []string{"a", "b"}, at(1)); err != nil || wrote {
		t.Fatalf("groups from an older token: setUserGroups = %v, %v; want no write", wrote, err)
	}
	if wrote, err := store.setUserGroups(ctx, "alice", []string{"c"}, at(3)); err != nil || !wrote {
		t.Fatalf("groups from a newer token: setUserGroups = %v, %v; want a write", wrote, err)
	}
	if got, err := store.userGroups(ctx, "alice"); err != nil || !slices.Equal(got, []string{"c"}) {
		t.Fatalf("userGroups = %q, %v; want [c]", got, err)
	}
}

func TestStoreTokensOfTheSameSecondOnlyRemoveGroups(t *testing.T) {
	// Two ID tokens issued in the same second carry the same iat, so neither is known to be newer. A difference between
	// them may only take groups away, until a token of a later second settles it.
	ctx := t.Context()
	store := testStore(t)

	for _, step := range []struct {
		groups []string
		at     time.Time
		want   []string
	}{
		{groups: []string{"a", "b"}, at: at(2), want: []string{"a", "b"}},
		{groups: []string{"a", "c"}, at: at(2), want: []string{"a"}},
		{groups: []string{"a", "b", "c"}, at: at(2), want: []string{"a"}},
		{groups: []string{"b", "c"}, at: at(3), want: []string{"b", "c"}},
	} {
		if _, err := store.setUserGroups(ctx, "alice", step.groups, step.at); err != nil {
			t.Fatal(err)
		}
		if got, err := store.userGroups(ctx, "alice"); err != nil || !slices.Equal(got, step.want) {
			t.Fatalf("after %q at %v: userGroups = %q, %v; want %q", step.groups, step.at.Unix(), got, err, step.want)
		}
	}
}

func TestRecorderAppliesARemovalFromATokenOfTheSameSecond(t *testing.T) {
	// Two sessions of one user, issued in the same second, disagree about a group. Whether they are served by one
	// replica or two, the removal is applied.
	ctx := t.Context()
	store := testStore(t)
	one, other := newGroupRecorder(store), newGroupRecorder(store)

	for _, step := range []struct {
		recorder *groupRecorder
		groups   []string
	}{
		{recorder: one, groups: []string{"admins", "engineering"}},
		{recorder: one, groups: []string{"engineering"}},
		{recorder: one, groups: []string{"admins", "engineering"}},
		{recorder: other, groups: []string{"admins", "engineering"}},
	} {
		if err := step.recorder.record(ctx, "alice", step.groups, at(5)); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := store.userGroups(ctx, "alice"); err != nil || !slices.Equal(got, []string{"engineering"}) {
		t.Fatalf("userGroups = %q, %v; want [engineering]", got, err)
	}
}

func TestNormalizeGroupsDropsOverlongValues(t *testing.T) {
	long := strings.Repeat("x", maxGroupLength+1)
	if got := normalizeGroups([]string{long, "a"}); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("normalizeGroups kept an overlong value")
	}
}

func TestStartupNeedsOneConnection(t *testing.T) {
	// A transaction-pooling proxy with one backend, or a pool that waiting replicas have filled, leaves the replica
	// holding the startup lock a single connection to work with.
	dsn := testDSN(t)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := u.Query().Get("search_path")

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	role := schema + "_one"
	for _, stmt := range []string{
		"CREATE ROLE " + role + " LOGIN PASSWORD 'one' CONNECTION LIMIT 1",
		"GRANT USAGE, CREATE ON SCHEMA " + schema + " TO " + role,
	} {
		if _, err := admin.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	// Roles outlive the test's schema, so the role is dropped before the connection used to drop it is closed.
	t.Cleanup(func() {
		defer admin.Close()
		for _, stmt := range []string{"DROP OWNED BY " + role, "DROP ROLE " + role} {
			if _, err := admin.Exec(stmt); err != nil {
				t.Error(err)
			}
		}
	})

	u.User = url.UserPassword(role, "one")
	store, err := prepareDatabase(t.Context(), Options{PostgresConnectionDSN: u.String()}, "pingfederate_")
	if err != nil {
		t.Fatalf("startup with one connection: %v", err)
	}
	defer store.db.Close()

	// The limit applies to starting. PostgreSQL may still count the closed startup connection for a moment.
	if _, err := admin.Exec("ALTER ROLE " + role + " CONNECTION LIMIT -1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.setUserGroups(t.Context(), "alice", []string{"a"}, at(1)); err != nil {
		t.Fatalf("the store does not work after startup: %v", err)
	}
}
