package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func idTokenWithGroups(groups ...string) string {
	return idTokenFor("sub-1", groups...)
}

func idTokenFor(subject string, groups ...string) string {
	claims, _ := json.Marshal(map[string]any{"sub": subject, "email": "ada@example.com", "groups": groups, "iat": time.Now().Unix()})
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

// Current groups come from userinfo, once per access token: the session's
// ID token is not reissued on refresh.
func TestRecordSessionTakesCurrentGroupsFromUserinfo(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "email": "ada@example.com", "groups": []any{"current"}})
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
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "email": "ada@example.com", "groups": []any{}})
	s := newTestServer(t, upstream.URL, time.Minute)

	ss := state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("stale"), Groups: []string{"stale"}}
	s.recordSession(t.Context(), &ss)
	if got := recordedGroups(t, s, "sub-1"); got != "" {
		t.Errorf("recorded groups = %q, want none", got)
	}
}

// No groups claim in userinfo means no groups: PingFederate omits an empty
// attribute.
func TestUserinfoWithoutGroupsClaimMeansNoGroups(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "email": "ada@example.com"})
	s := newTestServer(t, upstream.URL, time.Minute)
	s.rememberGroups(t.Context(), "sub-1", []string{"admins"}, time.Now().Add(-time.Hour))

	for range 2 {
		ss := state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("admins")}
		s.recordSession(t.Context(), &ss)
	}
	if got := recordedGroups(t, s, "sub-1"); got != "" {
		t.Errorf("recorded groups = %q, want none", got)
	}
	if calls.Load() != 1 {
		t.Errorf("userinfo calls = %d, want 1 for one access token", calls.Load())
	}
}

// A failing userinfo endpoint falls back to the session's groups, and is not
// asked again on every request.
func TestRecordSessionFallsBackWhenUserinfoFails(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the code under test sends GET or POST; a HEAD is a probe from
		// the environment, such as a sandbox discovering the listening port.
		if r.Method == http.MethodHead {
			return
		}
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

// With PingFederate's defaults, a group change reaches Obot after the next
// refresh.
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

// testPostgresDSN skips the test without PINGFEDERATE_TEST_POSTGRES_DSN, and
// drops the provider's tables before and after it.
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
	t0 := time.Now().Truncate(time.Second)

	if _, ok, err := b.userGroups(ctx, "sub-1"); err != nil || ok {
		t.Fatalf("unknown user: ok=%v err=%v", ok, err)
	}
	if err := a.recordUserGroups(ctx, "sub-1", []string{"admins", "devs"}, t0); err != nil {
		t.Fatal(err)
	}
	if groups, ok, err := b.userGroups(ctx, "sub-1"); err != nil || !ok || len(groups) != 2 {
		t.Errorf("userGroups on the other replica = %v %v %v", groups, ok, err)
	}
	if seen, err := b.seenGroups(ctx); err != nil || len(seen) != 2 {
		t.Errorf("seen groups on the other replica = %v %v", seen, err)
	}

	// Replica A's older observation, sent again after B's newer one, must lose.
	if err := b.recordUserGroups(ctx, "sub-1", []string{"devs"}, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := a.recordUserGroups(ctx, "sub-1", []string{"admins", "devs"}, t0); err != nil {
		t.Fatal(err)
	}
	if groups, _, _ := b.userGroups(ctx, "sub-1"); len(groups) != 1 || groups[0] != "devs" {
		t.Errorf("groups after an older observation arrived = %v, want the newer observation", groups)
	}

	// A newer observation is written whichever replica sends it, including a
	// change back to groups recorded before.
	if err := a.recordUserGroups(ctx, "sub-1", []string{"admins", "devs"}, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if groups, _, _ := b.userGroups(ctx, "sub-1"); len(groups) != 2 {
		t.Errorf("groups after a newer observation = %v", groups)
	}

	// No groups is a recorded answer, not a missing one.
	if err := a.recordUserGroups(ctx, "loner", nil, t0); err != nil {
		t.Fatal(err)
	}
	if groups, ok, _ := b.userGroups(ctx, "loner"); !ok || groups == nil || len(groups) != 0 {
		t.Errorf("user without groups = %#v %v, want an empty list", groups, ok)
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

// A repeated observation writes nothing but a renewal per renewInterval.
func TestPostgresGroupStoreRenewsUnchangedRecords(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	ctx := t.Context()
	start := time.Now().Truncate(time.Second)
	observed := start.Add(-time.Minute)
	store.now = func() time.Time { return start }

	updatedAt := func() time.Time {
		var row userGroupsRow
		if err := store.db.Table(userGroupsTable).Where("user_key = ?", "sub-1").Take(&row).Error; err != nil {
			t.Fatal(err)
		}
		return row.UpdatedAt
	}
	lastSeen := func() time.Time {
		var row seenGroupRow
		if err := store.db.Table(seenGroupsTable).Where("name = ?", "devs").Take(&row).Error; err != nil {
			t.Fatal(err)
		}
		return row.LastSeenAt
	}

	if err := store.recordUserGroups(ctx, "sub-1", []string{"devs"}, observed); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return start.Add(renewInterval / 2) }
	if err := store.recordUserGroups(ctx, "sub-1", []string{"devs"}, observed); err != nil {
		t.Fatal(err)
	}
	if got := updatedAt(); !got.Equal(start) {
		t.Errorf("repeated observation rewritten early: updated_at = %v, want %v", got, start)
	}
	if got := lastSeen(); !got.Equal(start) {
		t.Errorf("seen group rewritten early: last_seen_at = %v, want %v", got, start)
	}
	store.now = func() time.Time { return start.Add(renewInterval) }
	if err := store.recordUserGroups(ctx, "sub-1", []string{"devs"}, observed); err != nil {
		t.Fatal(err)
	}
	if got := updatedAt(); !got.Equal(start.Add(renewInterval)) {
		t.Errorf("repeated observation not renewed: updated_at = %v", got)
	}
	if got := lastSeen(); !got.Equal(start.Add(renewInterval)) {
		t.Errorf("seen group not renewed: last_seen_at = %v", got)
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

// After Obot drops the tables, a write must fail, not recreate them.
func TestPostgresGroupStoreDoesNotRecreateDroppedTables(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	ctx := t.Context()

	for _, table := range []string{userGroupsTable, seenGroupsTable} {
		if err := store.db.Exec("DROP TABLE " + table).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := store.recordUserGroups(ctx, "sub-1", []string{"devs"}, time.Now()); err == nil {
		t.Error("recording groups after the tables were dropped should fail")
	}
	for _, table := range []string{userGroupsTable, seenGroupsTable} {
		if store.db.Migrator().HasTable(table) {
			t.Errorf("table %s was recreated", table)
		}
	}
}

// A userinfo failure keeps the recorded groups, rather than the session's,
// which may include groups since removed.
func TestUserinfoFailureKeepsRecordedGroups(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the code under test sends GET or POST; a HEAD is a probe from
		// the environment, such as a sandbox discovering the listening port.
		if r.Method == http.MethodHead {
			return
		}
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer fresh" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "sub-1", "email": "ada@example.com", "groups": []any{"devs"}})
	}))
	t.Cleanup(upstream.Close)
	s := newTestServer(t, upstream.URL, time.Minute)

	// The current groups, read with a fresh token, are recorded.
	ss := state.SerializableState{AccessToken: "fresh", IDToken: idTokenWithGroups("admins", "devs")}
	s.recordSession(t.Context(), &ss)
	if got := recordedGroups(t, s, "sub-1"); got != "pingfederate/devs=devs" {
		t.Fatalf("recorded groups = %q", got)
	}

	// A request with the old token: userinfo fails, and the sign-in groups
	// (still holding admins) must not overwrite the record.
	ss = state.SerializableState{AccessToken: "expired", IDToken: idTokenWithGroups("admins", "devs")}
	s.recordSession(t.Context(), &ss)
	if got := recordedGroups(t, s, "sub-1"); got != "pingfederate/devs=devs" {
		t.Errorf("recorded groups after a userinfo failure = %q, want them kept", got)
	}

	// Obot's profile request with the old token answers from the cached ID
	// token claims, and must not record their groups either.
	if rec, _ := getUserInfo(t, s, "Bearer expired"); rec.Code != http.StatusOK {
		t.Fatalf("user info with the old token: status = %d", rec.Code)
	}
	if got := recordedGroups(t, s, "sub-1"); got != "pingfederate/devs=devs" {
		t.Errorf("recorded groups after the profile fallback = %q, want them kept", got)
	}

	// A user never recorded stays unrecorded, rather than having the
	// session's groups taken as current.
	ss = state.SerializableState{AccessToken: "expired-2", IDToken: idTokenFor("sub-2", "admins")}
	s.recordSession(t.Context(), &ss)
	if rec, _ := listGroups(t, s, "sub-2"); rec.Code != http.StatusInternalServerError {
		t.Errorf("unrecorded user after a userinfo failure: status = %d, want 500", rec.Code)
	}
}

// Userinfo must answer for the session's subject before its groups are used.
func TestUserinfoForAnotherSubjectIsIgnored(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "someone-else", "groups": []any{"admins"}})
	s := newTestServer(t, upstream.URL, time.Minute)

	ss := state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("devs")}
	s.recordSession(t.Context(), &ss)
	if rec, _ := listGroups(t, s, "sub-1"); rec.Code != http.StatusInternalServerError {
		t.Errorf("groups(sub-1): status = %d, want nothing recorded", rec.Code)
	}
	if rec, _ := listGroups(t, s, "someone-else"); rec.Code != http.StatusInternalServerError {
		t.Errorf("groups(someone-else): status = %d, want nothing recorded", rec.Code)
	}
}

func TestValidateEndpointURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "https", url: "https://sso.example.com:9031"},
		{name: "http on localhost", url: "http://localhost:9031"},
		{name: "http on IPv4 loopback", url: "http://127.0.0.1:9031/as/token.oauth2"},
		{name: "http on IPv6 loopback", url: "http://[::1]:9031"},
		{name: "http elsewhere", url: "http://sso.example.com", wantErr: true},
		{name: "http on a private address", url: "http://10.0.0.5", wantErr: true},
		{name: "credentials", url: "https://user:pass@sso.example.com", wantErr: true},
		{name: "relative", url: "/as/token.oauth2", wantErr: true},
		{name: "other scheme", url: "ftp://sso.example.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateEndpointURL("endpoint", tt.url); (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// The in-memory store orders, expires and bounds seen groups like PostgreSQL.
func TestMemoryGroupStoreSeenGroups(t *testing.T) {
	store := newMemoryGroupStore()
	ctx := t.Context()
	now := time.Now()
	store.now = func() time.Time { return now }
	if err := store.addSeenGroups(ctx, []string{"old", "kept"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.addSeenGroups(ctx, []string{"new", "kept"}); err != nil {
		t.Fatal(err)
	}
	if seen, _ := store.seenGroups(ctx); strings.Join(seen, ",") != "kept,new,old" {
		t.Errorf("seen = %v, want the recently seen first, a repeat sighting counting as recent", seen)
	}

	now = now.Add(seenGroupsTTL - 30*time.Minute)
	if seen, _ := store.seenGroups(ctx); strings.Join(seen, ",") != "kept,new" {
		t.Errorf("seen = %v, want old expired", seen)
	}

	for i := range maxSeenGroups {
		now = now.Add(time.Millisecond)
		if err := store.addSeenGroups(ctx, []string{fmt.Sprintf("g%05d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	seen, _ := store.seenGroups(ctx)
	if len(seen) != maxSeenGroups || slices.Contains(seen, "kept") || slices.Contains(seen, "new") {
		t.Errorf("full store holds %d groups; the least recently seen should have been dropped", len(seen))
	}
}

// Every replica starts the provider at once when it is first configured; all
// of them must manage to open the store.
func TestPostgresGroupStoreConcurrentStart(t *testing.T) {
	dsn := testPostgresDSN(t)
	errs := make(chan error, 4)
	for range cap(errs) {
		go func() {
			o := validOptions()
			o.PostgresConnectionDSN = dsn
			cfg, err := o.resolve()
			if err != nil {
				errs <- err
				return
			}
			store, err := openPostgresGroupStore(cfg)
			if err == nil {
				if sqlDB, dbErr := store.db.DB(); dbErr == nil {
					_ = sqlDB.Close()
				}
			}
			errs <- err
		}()
	}
	for range cap(errs) {
		if err := <-errs; err != nil {
			t.Errorf("open store: %v", err)
		}
	}
}

// Refreshing and expired sessions record nothing, so replaying an old cookie
// cannot keep groups the user lost.
func TestRefreshingOrExpiredSessionRecordsNothing(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "email": "ada@example.com", "groups": []any{"admins"}})
	s := newTestServer(t, upstream.URL, time.Minute)

	ss := state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("admins"), SetCookies: []string{"obot_access_token=refreshed"}}
	s.recordSession(t.Context(), &ss)
	if rec, _ := listGroups(t, s, "sub-1"); rec.Code != http.StatusInternalServerError {
		t.Errorf("refreshing request: status = %d, want nothing recorded", rec.Code)
	}

	expired := time.Now().Add(-time.Minute)
	ss = state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("admins"), ExpiresOn: &expired}
	s.recordSession(t.Context(), &ss)
	if rec, _ := listGroups(t, s, "sub-1"); rec.Code != http.StatusInternalServerError {
		t.Errorf("expired session: status = %d, want nothing recorded", rec.Code)
	}

	current := time.Now().Add(time.Hour)
	ss = state.SerializableState{AccessToken: "tok", IDToken: idTokenWithGroups("admins"), ExpiresOn: &current}
	s.recordSession(t.Context(), &ss)
	if got := recordedGroups(t, s, "sub-1"); got != "pingfederate/admins=admins" {
		t.Errorf("current session: recorded groups = %q", got)
	}
}

func TestTokenGroupsTTL(t *testing.T) {
	cfg := &settings{refreshDuration: 5 * time.Minute}
	if got := tokenGroupsTTL(cfg); got != 5*time.Minute {
		t.Errorf("ttl = %v, want the refresh duration", got)
	}
	cfg.refreshDuration = 0
	if got := tokenGroupsTTL(cfg); got != cacheTTL {
		t.Errorf("ttl = %v, want %v without a refresh duration", got, cacheTTL)
	}
}

// The in-memory store orders observations the same way as the PostgreSQL one.
func TestMemoryGroupStoreIgnoresOlderObservations(t *testing.T) {
	store := newMemoryGroupStore()
	ctx := t.Context()
	t0 := time.Now()
	if err := store.recordUserGroups(ctx, "sub-1", []string{"devs"}, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.recordUserGroups(ctx, "sub-1", []string{"admins", "devs"}, t0); err != nil {
		t.Fatal(err)
	}
	if groups, _, _ := store.userGroups(ctx, "sub-1"); len(groups) != 1 || groups[0] != "devs" {
		t.Errorf("groups = %v, want the newer observation", groups)
	}
	if err := store.recordUserGroups(ctx, "sub-1", []string{"admins", "devs"}, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if groups, _, _ := store.userGroups(ctx, "sub-1"); len(groups) != 2 {
		t.Errorf("groups = %v, want the newest observation", groups)
	}
}

// Repeating an observation leaves the rows untouched: the read finds nothing
// to write, so no write statement runs at all.
func TestPostgresGroupStoreRepeatedObservationDoesNotWrite(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	ctx := t.Context()
	observed := time.Now().Add(-time.Minute)
	rowVersion := func(table, where string, arg any) string {
		var xmin string
		if err := store.db.Raw("SELECT xmin::text FROM "+table+" WHERE "+where, arg).Scan(&xmin).Error; err != nil {
			t.Fatal(err)
		}
		return xmin
	}
	if err := store.recordUserGroups(ctx, "sub-1", []string{"devs"}, observed); err != nil {
		t.Fatal(err)
	}
	userVersion, seenVersion := rowVersion(userGroupsTable, "user_key = ?", "sub-1"), rowVersion(seenGroupsTable, "name = ?", "devs")
	for range 3 {
		if err := store.recordUserGroups(ctx, "sub-1", []string{"devs"}, observed); err != nil {
			t.Fatal(err)
		}
	}
	if got := rowVersion(userGroupsTable, "user_key = ?", "sub-1"); got != userVersion {
		t.Errorf("user row rewritten by a repeated observation: xmin %s -> %s", userVersion, got)
	}
	if got := rowVersion(seenGroupsTable, "name = ?", "devs"); got != seenVersion {
		t.Errorf("seen group rewritten by a repeated observation: xmin %s -> %s", seenVersion, got)
	}
}

// Removal from the last group reaches Obot after the next refresh, though
// userinfo then omits the groups claim.
func TestRemovalFromAllGroupsFollowsRefresh(t *testing.T) {
	cfg := defaultIDPConfig()
	cfg.GroupsInIDToken = false
	cfg.GroupsInUserinfo = true
	cfg.OmitIDTokenOnRefresh = true
	idp := startIDP(t, cfg, false)
	p := mustStartProvider(t, idp.Issuer(), map[string]string{"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION": "1s"})

	p.mustLogin(t)
	p.mustGetState(t)
	if status, groups := p.groups(t, "sub-ada"); status != http.StatusOK || len(groups) != 2 {
		t.Fatalf("groups after sign-in = %d %q", status, groupNames(groups))
	}

	user := adaUser
	user.Groups = nil
	idp.SetUser(user)
	time.Sleep(2100 * time.Millisecond)

	// The refreshing request records from the refreshed session itself, so
	// the client does not even need to send the new cookies back.
	ss := p.mustGetState(t)
	if len(ss.SetCookies) == 0 {
		t.Fatal("expected a refresh")
	}
	if status, groups := p.groups(t, "sub-ada"); status != http.StatusOK || len(groups) != 0 {
		t.Errorf("groups after removal from all groups = %d %q, want none", status, groupNames(groups))
	}
}

// A refreshing request records from the refreshed session.
func TestRefreshingRequestRecordsFromRefreshedSession(t *testing.T) {
	cfg := defaultIDPConfig()
	cfg.OmitIDTokenOnRefresh = true
	idp := startIDP(t, cfg, false)
	p := mustStartProvider(t, idp.Issuer(), map[string]string{"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION": "1s"})

	p.mustLogin(t)
	p.mustGetState(t)
	user := adaUser
	user.Groups = []string{"devs"}
	idp.SetUser(user)
	time.Sleep(2100 * time.Millisecond)

	ss := p.mustGetState(t) // the refreshed cookies are deliberately not applied
	if len(ss.SetCookies) == 0 {
		t.Fatal("expected a refresh")
	}
	// Loading the refreshed session must not refresh it again.
	if got := idp.Counts().Refresh; got != 1 {
		t.Errorf("refresh token grants = %d, want 1", got)
	}
	if got := groupNames(ss.GroupInfos); got != "pingfederate/devs=devs" {
		t.Errorf("groups in the refreshing request's state = %q, want the refreshed session's", got)
	}
	if status, groups := p.groups(t, "sub-ada"); status != http.StatusOK || groupNames(groups) != "pingfederate/devs=devs" {
		t.Errorf("recorded groups = %d %q, want the refreshed session's", status, groupNames(groups))
	}
}

// Without a userinfo endpoint, groups come from the ID token, ordered by its
// iat; a token without one cannot be ordered, and records nothing.
func TestIDTokenWithoutIssuedAtRecordsNothing(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	claims, _ := json.Marshal(map[string]any{"sub": "sub-1", "groups": []string{"admins"}})
	ss := state.SerializableState{AccessToken: "tok", IDToken: "h." + base64.RawURLEncoding.EncodeToString(claims) + ".s"}
	s.recordSession(t.Context(), &ss)
	if rec, _ := listGroups(t, s, "sub-1"); rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want nothing recorded", rec.Code)
	}
}

// A future observation is treated as current.
func TestFutureObservationIsCapped(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	s.rememberGroups(t.Context(), "sub-1", []string{"admins"}, time.Now().Add(24*time.Hour))
	s.rememberGroups(t.Context(), "sub-1", []string{"devs"}, time.Now().Add(time.Millisecond))
	if got := recordedGroups(t, s, "sub-1"); got != "pingfederate/devs=devs" {
		t.Errorf("recorded groups = %q, want the later observation", got)
	}
}

// A repeated observation must not lock rows, or a group every user is in
// would serialize every request.
func TestPostgresRepeatedObservationTakesNoLocks(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	ctx := t.Context()
	observed := time.Now().Add(-time.Minute)
	if err := store.recordUserGroups(ctx, "sub-1", []string{"everyone"}, observed); err != nil {
		t.Fatal(err)
	}

	locker := openTestPostgresStore(t, dsn)
	tx := locker.db.Begin()
	t.Cleanup(func() { tx.Rollback() })
	for _, lock := range []string{
		"SELECT 1 FROM " + userGroupsTable + " WHERE user_key = 'sub-1' FOR UPDATE",
		"SELECT 1 FROM " + seenGroupsTable + " WHERE name = 'everyone' FOR UPDATE",
	} {
		if err := tx.Exec(lock).Error; err != nil {
			t.Fatal(err)
		}
	}

	timeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := store.recordUserGroups(timeout, "sub-1", []string{"everyone"}, observed); err != nil {
		t.Errorf("repeated observation blocked on locked rows: %v", err)
	}
}

// Replicas writing overlapping groups at once, with every write due, must not
// deadlock or fail.
func TestPostgresConcurrentOverlappingWrites(t *testing.T) {
	dsn := testPostgresDSN(t)
	stores := []*postgresGroupStore{openTestPostgresStore(t, dsn), openTestPostgresStore(t, dsn)}
	ctx := t.Context()
	groupSets := [][]string{{"a", "b", "c", "d"}, {"d", "c", "b", "a"}, {"b", "d"}, {"c", "a"}}
	errs := make(chan error, 64)
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store := stores[i%len(stores)]
			// Each write is a newer observation and every seen group is due,
			// so every statement writes.
			at := time.Now().Add(time.Duration(i) * time.Millisecond)
			errs <- store.recordUserGroups(ctx, fmt.Sprintf("user-%d", i%8), groupSets[i%len(groupSets)], at)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent write: %v", err)
		}
	}
}

func TestCookieFamily(t *testing.T) {
	for name, want := range map[string]string{
		"obot_access_token":    "obot_access_token",
		"obot_access_token_0":  "obot_access_token",
		"obot_access_token_12": "obot_access_token",
		"obot_access_token_x":  "obot_access_token_x",
		"_csrf":                "_csrf",
		"name_":                "name_",
	} {
		if got := cookieFamily(name); got != want {
			t.Errorf("cookieFamily(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestExpireSupersededCookies(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, name := range []string{"obot_access_token", "obot_access_token_1", "_csrf", "other_1"} {
		req.AddCookie(&http.Cookie{Name: name, Value: "old"})
	}
	fresh := (&http.Cookie{Name: "obot_access_token_0", Value: "new", Path: "/", Domain: "obot.example.com", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}).String()

	expired := expireSupersededCookies(req, []string{fresh})
	header := http.Header{"Set-Cookie": expired}
	var names []string
	for _, c := range (&http.Response{Header: header}).Cookies() {
		names = append(names, c.Name)
		if c.MaxAge >= 0 || c.Value != "" || c.Path != "/" || c.Domain != "obot.example.com" || !c.Secure || !c.HttpOnly {
			t.Errorf("deletion of %s = %+v, want an expired cookie with the fresh cookie's attributes", c.Name, c)
		}
	}
	// Only the session's own family is touched, and never a name the refresh set.
	if strings.Join(names, ",") != "obot_access_token,obot_access_token_1" {
		t.Errorf("expired %v, want the unsplit cookie and the stale chunk", names)
	}

	// A refresh that cleared the session deletes its own cookies; there is
	// nothing to copy attributes from, and nothing more to do.
	cleared := (&http.Cookie{Name: "obot_access_token", Path: "/", MaxAge: -1}).String()
	if got := expireSupersededCookies(req, []string{cleared}); len(got) != 0 {
		t.Errorf("after a clearing refresh: %v, want nothing", got)
	}
}

// When the refreshed session cannot be loaded, nothing is recorded from it:
// the refreshing request's own, pre-refresh state is not recorded either.
func TestRefreshedSessionThatCannotBeLoadedRecordsNothing(t *testing.T) {
	idp := startIDP(t, defaultIDPConfig(), false)
	p := mustStartProvider(t, idp.Issuer(), nil)
	p.mustLogin(t)

	req := httptest.NewRequest(http.MethodGet, p.url+"/", nil)
	u, _ := url.Parse(p.url)
	for _, c := range p.jar.Cookies(u) {
		req.AddCookie(c)
	}
	if _, ok := p.srv.refreshedState(req, []string{"obot_access_token=not-a-session; Path=/"}); ok {
		t.Error("a refreshed cookie that is not a valid session should not load")
	}
	// The valid cookie the request carried is of the same family, and is
	// dropped, so the old session is not loaded in its place.
	if _, ok := p.srv.refreshedState(req, []string{"obot_access_token_0=not-a-session; Path=/"}); ok {
		t.Error("the request's old session cookie should not be loaded in place of the refreshed one")
	}
}

// A group name containing a NUL character cannot be stored by PostgreSQL, and
// would make every write of the user's groups fail; it is dropped.
func TestPostgresGroupNameWithNULIsDropped(t *testing.T) {
	if got := filterGroups([]string{"ok", "bad\x00x", " ok "}); strings.Join(got, "|") != "ok" {
		t.Errorf("filterGroups = %q", got)
	}
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	if err := store.recordUserGroups(t.Context(), "sub-1", filterGroups([]string{"ok", "bad\x00x"}), time.Now()); err != nil {
		t.Fatalf("recording with a NUL group name dropped: %v", err)
	}
	if groups, ok, _ := store.userGroups(t.Context(), "sub-1"); !ok || strings.Join(groups, "|") != "ok" {
		t.Errorf("groups = %v %v", groups, ok)
	}
}

// Pruning locks expired groups in name order and skips any a sign-in holds,
// so it cannot deadlock with recordUserGroups, which locks in name order too.
func TestPostgresPruneSkipsLockedGroups(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	ctx := t.Context()
	long := time.Now().Add(-seenGroupsTTL - time.Hour)
	store.now = func() time.Time { return long }
	if err := store.recordUserGroups(ctx, "sub-1", []string{"a", "b"}, long); err != nil {
		t.Fatal(err)
	}
	store.now = time.Now

	locker := openTestPostgresStore(t, dsn)
	tx := locker.db.Begin()
	t.Cleanup(func() { tx.Rollback() })
	if err := tx.Exec("SELECT 1 FROM " + seenGroupsTable + " WHERE name = 'a' FOR UPDATE").Error; err != nil {
		t.Fatal(err)
	}

	timeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := store.prune(timeout); err != nil {
		t.Fatalf("prune blocked on a locked group: %v", err)
	}
	var names []string
	store.db.Table(seenGroupsTable).Order("name").Pluck("name", &names)
	if strings.Join(names, ",") != "a" {
		t.Errorf("seen groups after prune = %v, want only the locked one left", names)
	}
}

// An expired row answers no lookups, so any observation replaces it, even one
// older than the expired row's, rather than waiting for pruning.
func TestPostgresExpiredRowIsReplaced(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	ctx := t.Context()
	start := time.Now().Truncate(time.Second)
	store.now = func() time.Time { return start }
	if err := store.recordUserGroups(ctx, "sub-1", []string{"new"}, start); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return start.Add(userGroupsTTL + time.Minute) }
	if _, ok, _ := store.userGroups(ctx, "sub-1"); ok {
		t.Fatal("the row should have expired")
	}
	if err := store.recordUserGroups(ctx, "sub-1", []string{"older"}, start.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if groups, ok, _ := store.userGroups(ctx, "sub-1"); !ok || strings.Join(groups, "|") != "older" {
		t.Errorf("groups = %v %v, want the expired row replaced", groups, ok)
	}
}

// Groups seen at the same moment are listed in name order, so the cut at
// maxSeenGroups is stable.
func TestPostgresSeenGroupsOrderIsStable(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	// Insert in reverse name order, all at the same moment, so that only the
	// tie-breaker, not the order rows were written in, puts them in name order.
	at := time.Now()
	store.now = func() time.Time { return at }
	for i, name := range []string{"c", "b", "a"} {
		if err := store.recordUserGroups(t.Context(), fmt.Sprintf("sub-%d", i), []string{name}, at); err != nil {
			t.Fatal(err)
		}
	}
	if seen, _ := store.seenGroups(t.Context()); strings.Join(seen, ",") != "a,b,c" {
		t.Errorf("seen = %v, want name order for equal times", seen)
	}
}

// The columns the queries compare are NOT NULL, so the read and the upsert
// cannot disagree about a NULL.
func TestPostgresColumnsAreNotNull(t *testing.T) {
	dsn := testPostgresDSN(t)
	store := openTestPostgresStore(t, dsn)
	for table, columns := range map[string][]string{
		userGroupsTable: {"groups", "observed_at", "updated_at"},
		seenGroupsTable: {"last_seen_at"},
	} {
		for _, column := range columns {
			var nullable string
			if err := store.db.Raw("SELECT is_nullable FROM information_schema.columns WHERE table_name = ? AND column_name = ?", table, column).Scan(&nullable).Error; err != nil {
				t.Fatal(err)
			}
			if nullable != "NO" {
				t.Errorf("%s.%s is_nullable = %q, want NO", table, column, nullable)
			}
		}
	}
}

func TestUserinfoRetryDelay(t *testing.T) {
	for failures, want := range map[int]time.Duration{
		1:  5 * time.Second,
		2:  10 * time.Second,
		3:  20 * time.Second,
		4:  40 * time.Second,
		5:  time.Minute,
		50: time.Minute,
	} {
		if got := userinfoRetryDelay(failures); got != want {
			t.Errorf("userinfoRetryDelay(%d) = %v, want %v", failures, got, want)
		}
	}
}

// Failures in a row back off, and an answer clears them.
func TestUserinfoFailuresBackOff(t *testing.T) {
	var calls atomic.Int32
	var down atomic.Bool
	down.Store(true)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		calls.Add(1)
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "sub-1"})
	}))
	t.Cleanup(upstream.Close)
	s := newTestServer(t, upstream.URL, 0)

	for want := 1; want <= 3; want++ {
		if _, ok, asked := s.currentGroups(t.Context(), "tok", "sub-1", releasedClaims{}); ok || !asked {
			t.Fatalf("failure %d: ok=%v asked=%v", want, ok, asked)
		}
		failure, _ := s.tokenGroupsFailed.Get("tok")
		if failure.failures != want {
			t.Fatalf("failures = %d, want %d", failure.failures, want)
		}
		if wait := time.Until(failure.retryAt); wait <= userinfoRetryDelay(want)-time.Second || wait > userinfoRetryDelay(want) {
			t.Errorf("failure %d: retry in %v, want about %v", want, wait, userinfoRetryDelay(want))
		}
		// Within the delay, userinfo is not asked.
		if _, _, asked := s.currentGroups(t.Context(), "tok", "sub-1", releasedClaims{}); asked {
			t.Errorf("failure %d: userinfo asked again within the delay", want)
		}
		// Let the delay pass.
		failure.retryAt = time.Now().Add(-time.Millisecond)
		s.tokenGroupsFailed.Add("tok", failure)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("userinfo calls = %d, want 3", got)
	}

	down.Store(false)
	if _, ok, _ := s.currentGroups(t.Context(), "tok", "sub-1", releasedClaims{}); !ok {
		t.Fatal("userinfo answer after recovery not used")
	}
	if _, failed := s.tokenGroupsFailed.Get("tok"); failed {
		t.Error("the failures were not cleared by an answer")
	}
}

// A request cancelled while asking userinfo says nothing about userinfo: the
// provider's request carries on, and its answer is kept for the next request.
func TestCancelledRequestIsNotAUserinfoFailure(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1"})
	s := newTestServer(t, upstream.URL, 0)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s.currentGroups(ctx, "tok", "sub-1", releasedClaims{})
	if _, failed := s.tokenGroupsFailed.Get("tok"); failed {
		t.Fatal("a cancelled request was remembered as a userinfo failure")
	}
	if _, ok, asked := s.currentGroups(t.Context(), "tok", "sub-1", releasedClaims{}); !ok || asked {
		t.Errorf("next request: ok=%v asked=%v, want the answer the cancelled request got", ok, asked)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("userinfo calls = %d, want 1", got)
	}
}

// A hanging userinfo is a failure once the provider's timeout passes, even
// if the caller gave up first.
func TestHangingUserinfoIsAFailure(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		calls.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); upstream.Close() })
	s := newTestServer(t, upstream.URL, 0)
	s.userinfoTimeout = 300 * time.Millisecond

	// The caller's deadline, like Obot's, passes before the provider's timeout.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	s.currentGroups(ctx, "tok", "sub-1", releasedClaims{})
	if _, failed := s.tokenGroupsFailed.Get("tok"); !failed {
		t.Fatal("a hanging userinfo was not remembered as a failure")
	}
	start := time.Now()
	if _, _, asked := s.currentGroups(t.Context(), "tok", "sub-1", releasedClaims{}); asked {
		t.Error("userinfo asked again within the retry delay")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("the next request waited %v", elapsed)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("userinfo calls = %d, want 1", got)
	}
}
