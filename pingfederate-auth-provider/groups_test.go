package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func idTokenWithGroups(groups ...string) string {
	claims, _ := json.Marshal(map[string]any{"sub": "sub-1", "email": "ada@example.com", "groups": groups})
	return "h." + base64.RawURLEncoding.EncodeToString(claims) + ".s"
}

func recordedGroups(t *testing.T, s *server, id string) string {
	t.Helper()
	rec, groups := listGroups(t, s, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("groups(%s): status = %d", id, rec.Code)
	}
	return groupNames(groups)
}

// A session keeps the groups of the ID token it was created with, and
// PingFederate issues no new ID token on refresh by default, so the current
// groups come from userinfo, asked once per access token.
func TestRecordSessionTakesCurrentGroupsFromUserinfo(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "groups": []any{"current"}})
	s := newTestServer(t, upstream.URL, time.Minute)

	for range 3 {
		ss := state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("stale"), Groups: []string{"stale"}}
		s.recordSession(t.Context(), &ss)
		if got := groupNames(ss.GroupInfos); got != "pingfederate/current=current" {
			t.Fatalf("GroupInfos = %q, want the userinfo groups", got)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("userinfo calls = %d, want 1 for one access token", calls.Load())
	}
	if got := recordedGroups(t, s, "sub-1"); got != "pingfederate/current=current" {
		t.Errorf("recorded groups = %q", got)
	}

}

// An empty groups claim in userinfo means the user has no groups now.
func TestRecordSessionTakesEmptyUserinfoGroups(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "groups": []any{}})
	s := newTestServer(t, upstream.URL, time.Minute)

	ss := state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("stale"), Groups: []string{"stale"}}
	s.recordSession(t.Context(), &ss)
	if got := recordedGroups(t, s, "sub-1"); got != "" {
		t.Errorf("recorded groups = %q, want none", got)
	}
}

// When PingFederate releases groups only in the ID token, userinfo has no
// groups claim, and the session's groups stand.
func TestRecordSessionKeepsSessionGroupsWithoutUserinfoClaim(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "email": "ada@example.com"})
	s := newTestServer(t, upstream.URL, time.Minute)

	for range 2 {
		ss := state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("from-token"), Groups: []string{"from-token"}}
		s.recordSession(t.Context(), &ss)
	}
	if got := recordedGroups(t, s, "sub-1"); got != "pingfederate/from-token=from-token" {
		t.Errorf("recorded groups = %q", got)
	}
	if calls.Load() != 1 {
		t.Errorf("userinfo calls = %d, want 1: the missing claim is remembered too", calls.Load())
	}
}

// A failing userinfo endpoint falls back to the session's groups, and is not
// asked again on every request.
func TestRecordSessionFallsBackWhenUserinfoFails(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(upstream.Close)
	s := newTestServer(t, upstream.URL, time.Minute)

	for range 3 {
		ss := state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("from-session"), Groups: []string{"from-session"}}
		s.recordSession(t.Context(), &ss)
		if got := groupNames(ss.GroupInfos); got != "pingfederate/from-session=from-session" {
			t.Fatalf("GroupInfos = %q", got)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("userinfo calls = %d, want 1 within the retry interval", calls.Load())
	}
}

// End to end: PingFederate's defaults release groups only in userinfo and
// issue no ID token on refresh. A change to the user's groups must still reach
// Obot after the next refresh, without the user signing in again.
func TestGroupChangesFollowRefresh(t *testing.T) {
	cfg := defaultIDPConfig()
	cfg.GroupsInIDToken = false
	cfg.GroupsInUserinfo = true
	cfg.OmitIDTokenOnRefresh = true
	idp := startIDP(t, cfg, false)
	p := mustStartProvider(t, idp.Issuer(), map[string]string{"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION": "1s"})

	p.mustLogin(t)
	p.mustGetState(t)
	if status, groups := p.groups(t, "sub-ada"); status != http.StatusOK || groupNames(groups) != "pingfederate/admins=admins,pingfederate/devs=devs" {
		t.Fatalf("groups after sign-in = %d %q", status, groupNames(groups))
	}

	user := adaUser
	user.Groups = []string{"devs"}
	idp.SetUser(user)

	// Session age is measured in whole seconds, so wait past the next tick.
	time.Sleep(2100 * time.Millisecond)
	ss := p.mustGetState(t)
	if len(ss.SetCookies) == 0 || idp.Counts().Refresh != 1 {
		t.Fatalf("expected a refresh: setCookies=%v refreshes=%d", ss.SetCookies, idp.Counts().Refresh)
	}

	// The refreshed session, with its new access token, comes back in
	// cookies, and the browser sends it from the next request on.
	header := http.Header{}
	for _, c := range ss.SetCookies {
		header.Add("Set-Cookie", c)
	}
	u, _ := url.Parse(p.url)
	p.jar.SetCookies(u, (&http.Response{Header: header}).Cookies())
	ss = p.mustGetState(t)
	if got := groupNames(ss.GroupInfos); got != "pingfederate/devs=devs" {
		t.Errorf("groups in state after refresh = %q, want the current groups", got)
	}
	if status, groups := p.groups(t, "sub-ada"); status != http.StatusOK || groupNames(groups) != "pingfederate/devs=devs" {
		t.Errorf("groups after refresh = %d %q, want the current groups", status, groupNames(groups))
	}
}

// testPostgresDSN returns the database for the Postgres tests, which run only
// when PINGFEDERATE_TEST_POSTGRES_DSN is set, and drops the provider's tables
// before and after each test.
func testPostgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("PINGFEDERATE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set PINGFEDERATE_TEST_POSTGRES_DSN to run the Postgres tests")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	drop := func() {
		for _, table := range []string{userGroupsTable, seenGroupsTable, postgresTablePrefix + "sessions", postgresTablePrefix + "session_locks"} {
			if err := db.Exec("DROP TABLE IF EXISTS " + table).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	drop()
	t.Cleanup(func() {
		drop()
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return dsn
}

func openTestPostgresStore(t *testing.T, dsn string) *postgresGroupStore {
	t.Helper()
	o := validOptions()
	o.PostgresConnectionDSN = dsn
	cfg, err := o.resolve()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openPostgresGroupStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := store.db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return store
}

func TestPostgresGroupStore(t *testing.T) {
	dsn := testPostgresDSN(t)
	a := openTestPostgresStore(t, dsn)
	b := openTestPostgresStore(t, dsn) // a second replica
	ctx := t.Context()

	if _, ok, err := b.userGroups(ctx, "sub-1"); err != nil || ok {
		t.Fatalf("unknown user: ok=%v err=%v", ok, err)
	}
	if err := a.setUserGroups(ctx, []string{"sub-1", "ada@example.com"}, []string{"admins", "devs"}, "t1"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"sub-1", "ada@example.com"} {
		if groups, ok, err := b.userGroups(ctx, key); err != nil || !ok || len(groups) != 2 {
			t.Errorf("userGroups(%s) on the other replica = %v %v %v", key, groups, ok, err)
		}
	}

	// A change is written at once, even within the rewrite interval.
	if err := a.setUserGroups(ctx, []string{"sub-1"}, []string{"devs"}, "t2"); err != nil {
		t.Fatal(err)
	}
	if groups, _, _ := b.userGroups(ctx, "sub-1"); len(groups) != 1 || groups[0] != "devs" {
		t.Errorf("changed groups = %v", groups)
	}
	// So is a change back to what this replica last wrote after another
	// replica wrote something else: each observation comes with a new token.
	if err := b.setUserGroups(ctx, []string{"sub-1"}, []string{"admins", "devs"}, "t3"); err != nil {
		t.Fatal(err)
	}
	if err := a.setUserGroups(ctx, []string{"sub-1"}, []string{"devs"}, "t4"); err != nil {
		t.Fatal(err)
	}
	if groups, _, _ := b.userGroups(ctx, "sub-1"); len(groups) != 1 || groups[0] != "devs" {
		t.Errorf("groups after both replicas wrote = %v, want the latest write", groups)
	}

	// No groups is a recorded answer, not a missing one.
	if err := a.setUserGroups(ctx, []string{"loner"}, nil, "t5"); err != nil {
		t.Fatal(err)
	}
	if groups, ok, _ := b.userGroups(ctx, "loner"); !ok || groups == nil || len(groups) != 0 {
		t.Errorf("user without groups = %#v %v, want an empty list", groups, ok)
	}

	if err := a.addSeenGroups(ctx, []string{"admins", "devs"}); err != nil {
		t.Fatal(err)
	}
	if seen, err := b.seenGroups(ctx); err != nil || len(seen) != 2 {
		t.Errorf("seen groups on the other replica = %v %v", seen, err)
	}

	// Records expire and are pruned.
	later := time.Now().Add(userGroupsTTL + time.Minute)
	b.now = func() time.Time { return later }
	if _, ok, _ := b.userGroups(ctx, "sub-1"); ok {
		t.Error("an expired record still answers")
	}
	if err := b.prune(ctx); err != nil {
		t.Fatal(err)
	}
	var count int64
	b.db.Table(userGroupsTable).Count(&count)
	if count != 0 {
		t.Errorf("%d user rows survived pruning", count)
	}
	if seen, _ := b.seenGroups(ctx); len(seen) != 2 {
		t.Errorf("seen groups expire after %v, not %v; got %v", seenGroupsTTL, userGroupsTTL, seen)
	}
}

// An unchanged record is renewed only once per rewrite interval, so that the
// request path does not write on every request.
func TestPostgresGroupStoreRenewsUnchangedRecords(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	ctx := t.Context()
	start := time.Now().Truncate(time.Second)
	store.now = func() time.Time { return start }

	updatedAt := func() time.Time {
		var row userGroupsRow
		if err := store.db.Table(userGroupsTable).Where("user_key = ?", "sub-1").Take(&row).Error; err != nil {
			t.Fatal(err)
		}
		return row.UpdatedAt
	}

	if err := store.setUserGroups(ctx, []string{"sub-1"}, []string{"devs"}, "t1"); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return start.Add(rewriteInterval / 2) }
	if err := store.setUserGroups(ctx, []string{"sub-1"}, []string{"devs"}, "t1"); err != nil {
		t.Fatal(err)
	}
	if got := updatedAt(); !got.Equal(start) {
		t.Errorf("unchanged record rewritten early: updated_at = %v, want %v", got, start)
	}
	store.now = func() time.Time { return start.Add(rewriteInterval) }
	if err := store.setUserGroups(ctx, []string{"sub-1"}, []string{"devs"}, "t1"); err != nil {
		t.Fatal(err)
	}
	if got := updatedAt(); !got.Equal(start.Add(rewriteInterval)) {
		t.Errorf("unchanged record not renewed: updated_at = %v", got)
	}
}

// Two providers sharing Obot's database, as two replicas of Obot do: groups
// recorded by one answer lookups and the group picker on the other.
func TestGroupsSharedAcrossReplicas(t *testing.T) {
	dsn := testPostgresDSN(t)
	idp := startIDP(t, defaultIDPConfig(), false)
	env := map[string]string{"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN": dsn}

	first := mustStartProvider(t, idp.Issuer(), env)
	first.mustLogin(t)
	first.mustGetState(t)

	second := mustStartProvider(t, idp.Issuer(), env)
	if status, groups := second.groups(t, "sub-ada"); status != http.StatusOK || groupNames(groups) != "pingfederate/admins=admins,pingfederate/devs=devs" {
		t.Errorf("groups on the other replica = %d %q", status, groupNames(groups))
	}

	resp, err := http.Get(second.url + "/obot-list-auth-groups?limit=50")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var page struct {
		Items state.GroupInfoList `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if got := groupNames(page.Items); got != "pingfederate/admins=admins,pingfederate/devs=devs" {
		t.Errorf("group picker on the other replica = %q", got)
	}
}

// Obot drops the tables when the provider is deconfigured, possibly while the
// provider still runs on another replica. A write after that must fail rather
// than bring the tables back.
func TestPostgresGroupStoreDoesNotRecreateDroppedTables(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	ctx := t.Context()

	for _, table := range []string{userGroupsTable, seenGroupsTable} {
		if err := store.db.Exec("DROP TABLE " + table).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := store.setUserGroups(ctx, []string{"sub-1"}, []string{"devs"}, "t1"); err == nil {
		t.Error("recording groups after the table was dropped should fail")
	}
	if err := store.addSeenGroups(ctx, []string{"devs"}); err == nil {
		t.Error("recording seen groups after the table was dropped should fail")
	}
	for _, table := range []string{userGroupsTable, seenGroupsTable} {
		if store.db.Migrator().HasTable(table) {
			t.Errorf("table %s was recreated", table)
		}
	}
}
