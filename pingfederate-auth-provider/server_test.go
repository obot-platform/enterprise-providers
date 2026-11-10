package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// newTestServer builds a server without oauth2-proxy, for the endpoints that
// do not need a session.
func newTestServer(t *testing.T, userinfoURL string, cacheTTL time.Duration) *server {
	t.Helper()
	o := validOptions()
	o.UserinfoCacheTTL = cacheTTL.String()
	cfg, err := o.resolve()
	if err != nil {
		t.Fatal(err)
	}
	s := &server{
		cfg:               cfg,
		httpClient:        http.DefaultClient,
		userinfoURL:       userinfoURL,
		listenURL:         "http://127.0.0.1:9999",
		store:             newMemoryGroupStore(),
		tokenGroups:       expirable.NewLRU[string, userinfoGroups](cacheSize, nil, time.Hour),
		tokenGroupsFailed: expirable.NewLRU[string, userinfoFailure](cacheSize, nil, 2*tokenGroupsMaxRetry),
		idTokenClaims:     expirable.NewLRU[string, map[string]any](cacheSize, nil, time.Hour),
	}
	s.userinfoTimeout = userinfoTimeout
	s.directory = newGroupDirectory(cfg.knownGroups, s.store)
	if cacheTTL > 0 {
		s.userinfo = expirable.NewLRU[string, userinfoAnswer](cacheSize, nil, cacheTTL)
	}
	return s
}

func userinfoServer(t *testing.T, calls *atomic.Int32, claims map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the code under test sends GET or POST; a HEAD is a probe from
		// the environment, such as a sandbox discovering the listening port.
		if r.Method == http.MethodHead {
			return
		}
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(claims)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func getUserInfo(t *testing.T, s *server, authorization string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	s.getUserInfo(rec, req)
	var body map[string]any
	if rec.Code == http.StatusOK {
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode user info: %v", err)
		}
	}
	return rec, body
}

func listGroups(t *testing.T, s *server, id string) (*httptest.ResponseRecorder, state.GroupInfoList) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/obot-list-user-auth-groups", strings.NewReader(id))
	rec := httptest.NewRecorder()
	s.listUserAuthGroups(rec, req)
	var groups state.GroupInfoList
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &groups); err != nil {
			t.Fatalf("decode groups: %v", err)
		}
	}
	return rec, groups
}

func TestGetUserInfoShapesProfileAndRecordsGroups(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{
		"sub":     "sub-1",
		"email":   "ada@example.com",
		"name":    "Ada Lovelace",
		"picture": "https://img.example.com/ada.png",
		"groups":  []string{"admins", "devs"},
		"custom":  "kept",
	})
	s := newTestServer(t, upstream.URL, 5*time.Minute)

	rec, profile := getUserInfo(t, s, "Bearer tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	for key, want := range map[string]string{
		"id": "sub-1", "name": "Ada Lovelace", "email": "ada@example.com",
		"picture": "https://img.example.com/ada.png", "custom": "kept", "sub": "sub-1",
	} {
		if profile[key] != want {
			t.Errorf("profile[%s] = %v, want %q", key, profile[key], want)
		}
	}

	rec, groups := listGroups(t, s, "sub-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("groups(sub-1) status = %d: %s", rec.Code, rec.Body)
	}
	if len(groups) != 2 || groups[0].ID != "pingfederate/admins" || groups[0].Name != "admins" || groups[1].ID != "pingfederate/devs" {
		t.Errorf("groups(sub-1) = %+v", groups)
	}
	// Groups are recorded under the subject only: no user can choose another
	// user's subject, but an email-like claim may be chosen or shared.
	if rec, _ := listGroups(t, s, "ada@example.com"); rec.Code != http.StatusInternalServerError {
		t.Errorf("groups by email: status = %d, want 500", rec.Code)
	}
}

func TestGetUserInfoCachesUpstreamCalls(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "email": "ada@example.com"})

	cached := newTestServer(t, upstream.URL, 5*time.Minute)
	for range 3 {
		if rec, _ := getUserInfo(t, cached, "Bearer tok"); rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("upstream calls with cache = %d, want 1", calls.Load())
	}

	calls.Store(0)
	uncached := newTestServer(t, upstream.URL, 0)
	for range 3 {
		if rec, _ := getUserInfo(t, uncached, "Bearer tok"); rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
	}
	if calls.Load() != 3 {
		t.Errorf("upstream calls without cache = %d, want 3", calls.Load())
	}
}

func TestGetUserInfoFallsBackToIDTokenClaims(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, nil) // rejects everything but "tok"
	s := newTestServer(t, upstream.URL, time.Minute)

	rec, _ := getUserInfo(t, s, "Bearer unknown")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("without cached claims: status = %d, want 400", rec.Code)
	}

	s.idTokenClaims.Add("unknown", map[string]any{"sub": "sub-2", "email": "bob@example.com", "given_name": "Bob", "family_name": "Builder"})
	rec, profile := getUserInfo(t, s, "Bearer unknown")
	if rec.Code != http.StatusOK {
		t.Fatalf("with cached claims: status = %d: %s", rec.Code, rec.Body)
	}
	if profile["id"] != "sub-2" || profile["name"] != "Bob Builder" || profile["email"] != "bob@example.com" {
		t.Errorf("profile = %v", profile)
	}

	noEndpoint := newTestServer(t, "", time.Minute)
	noEndpoint.idTokenClaims.Add("unknown", map[string]any{"sub": "sub-3"})
	if rec, profile := getUserInfo(t, noEndpoint, "Bearer unknown"); rec.Code != http.StatusOK || profile["id"] != "sub-3" {
		t.Errorf("without a userinfo endpoint: status = %d, profile = %v", rec.Code, profile)
	}
}

// Obot looks a user's groups up by the profile's id, so a userinfo answer
// that is not for the session's subject must not become a profile.
func TestGetUserInfoRejectsUserinfoForAnotherSubject(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "someone-else", "email": "eve@example.com", "groups": []string{"admins"}})
	s := newTestServer(t, upstream.URL, time.Minute)
	s.idTokenClaims.Add("tok", map[string]any{"sub": "sub-1", "email": "ada@example.com"})

	if rec, profile := getUserInfo(t, s, "Bearer tok"); rec.Code != http.StatusBadGateway || profile != nil {
		t.Errorf("status = %d, profile = %v, want 502 and no profile", rec.Code, profile)
	}
	for _, id := range []string{"sub-1", "someone-else"} {
		if rec, _ := listGroups(t, s, id); rec.Code != http.StatusInternalServerError {
			t.Errorf("groups(%s): status = %d, want nothing recorded", id, rec.Code)
		}
	}
}

func TestGetUserInfoRejectsUserinfoWithoutSubject(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"email": "ada@example.com", "groups": []string{"admins"}})
	s := newTestServer(t, upstream.URL, time.Minute)

	if rec, profile := getUserInfo(t, s, "Bearer tok"); rec.Code != http.StatusBadGateway || profile != nil {
		t.Errorf("without ID token claims: status = %d, profile = %v, want 502 and no profile", rec.Code, profile)
	}
	s.idTokenClaims.Add("tok", map[string]any{"sub": "sub-1"})
	if rec, profile := getUserInfo(t, s, "Bearer tok"); rec.Code != http.StatusBadGateway || profile != nil {
		t.Errorf("with ID token claims: status = %d, profile = %v, want 502 and no profile", rec.Code, profile)
	}
}

// A replica that has not seen the session cannot compare subjects, and
// accepts userinfo's answer for the holder of the access token.
func TestGetUserInfoWithoutIDTokenClaimsUsesUserinfoSubject(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "groups": []string{"admins"}})
	s := newTestServer(t, upstream.URL, time.Minute)

	if rec, profile := getUserInfo(t, s, "Bearer tok"); rec.Code != http.StatusOK || profile["id"] != "sub-1" {
		t.Fatalf("status = %d, profile = %v", rec.Code, profile)
	}
	if rec, groups := listGroups(t, s, "sub-1"); rec.Code != http.StatusOK || len(groups) != 1 {
		t.Errorf("groups(sub-1): status = %d, groups = %+v", rec.Code, groups)
	}
}

func TestGetUserInfoRequiresToken(t *testing.T) {
	s := newTestServer(t, "http://127.0.0.1:1", time.Minute)
	if rec, _ := getUserInfo(t, s, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if rec, _ := getUserInfo(t, s, "Bearer "); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestGetUserInfoWithoutGroupsClaimRecordsNoGroups(t *testing.T) {
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "email": "ada@example.com"})
	s := newTestServer(t, upstream.URL, time.Minute)
	s.rememberGroups(t.Context(), "sub-1", []string{"admins"}, time.Now().Add(-time.Hour))

	if rec, _ := getUserInfo(t, s, "Bearer tok"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec, groups := listGroups(t, s, "sub-1"); rec.Code != http.StatusOK || len(groups) != 0 {
		t.Errorf("groups = %d %+v, want none: userinfo omits an empty groups claim", rec.Code, groups)
	}
}

func TestListUserAuthGroups(t *testing.T) {
	s := newTestServer(t, "", time.Minute)

	if rec, _ := listGroups(t, s, "  "); rec.Code != http.StatusBadRequest {
		t.Errorf("empty id: status = %d, want 400", rec.Code)
	}
	if rec, _ := listGroups(t, s, "nobody"); rec.Code != http.StatusInternalServerError {
		t.Errorf("unknown id: status = %d, want 500 so Obot does not replace its stored memberships with none", rec.Code)
	}

	s.rememberGroups(t.Context(), "loner", nil, time.Now())
	rec, groups := listGroups(t, s, "loner")
	if rec.Code != http.StatusOK || groups == nil || len(groups) != 0 {
		t.Errorf("known user without groups: status = %d, groups = %#v, want an empty list", rec.Code, groups)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "[]" {
		t.Errorf("body = %q, want []", body)
	}

	s.rememberGroups(t.Context(), "trimmed", []string{" ops ", "", "sec"}, time.Now())
	if _, groups := listGroups(t, s, "trimmed\n"); len(groups) != 2 || groups[0].ID != "pingfederate/ops" || groups[1].Name != "sec" {
		t.Errorf("groups = %+v", groups)
	}
}

func TestRecordSession(t *testing.T) {
	// Without a userinfo endpoint, the ID token is the only source of groups.
	s := newTestServer(t, "", time.Minute)
	idToken := "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"sub-9","email":"z@example.com","iat":`+strconv.FormatInt(time.Now().Unix(), 10)+`,"groups":["admins","devs"]}`)) + ".s"

	ss := state.SerializableState{AccessToken: "tok", IDToken: idToken, User: "sub-9", Email: "z@example.com"}
	s.recordSession(t.Context(), &ss)
	if len(ss.GroupInfos) != 2 || ss.GroupInfos[0].ID != "pingfederate/admins" || ss.GroupInfos[1].Name != "devs" {
		t.Errorf("GroupInfos from ID token claims = %+v", ss.GroupInfos)
	}
	if rec, groups := listGroups(t, s, "sub-9"); rec.Code != http.StatusOK || len(groups) != 2 {
		t.Errorf("groups(sub-9): status = %d, groups = %+v", rec.Code, groups)
	}
	if rec, _ := listGroups(t, s, "z@example.com"); rec.Code != http.StatusInternalServerError {
		t.Errorf("groups by email: status = %d, want 500: groups are recorded under the subject only", rec.Code)
	}
	if claims, ok := s.idTokenClaims.Get("tok"); !ok || claims["sub"] != "sub-9" {
		t.Errorf("ID token claims not cached by access token: %v %v", claims, ok)
	}

	// The session's own group list is not used: oauth2-proxy keeps it from
	// sign-in, and it loses the claim's type.
	ss = state.SerializableState{AccessToken: "tok2", IDToken: idToken, User: "sub-9", Groups: []string{"from-session"}}
	s.recordSession(t.Context(), &ss)
	if got := groupNames(ss.GroupInfos); got != "pingfederate/admins=admins,pingfederate/devs=devs" {
		t.Errorf("GroupInfos = %q, want the ID token's", got)
	}

	// Without a userinfo endpoint, groups come from the ID token, observed
	// when it was issued: a session without one says nothing current, and
	// records nothing.
	ss = state.SerializableState{AccessToken: "tok3", User: "u", Groups: []string{"g"}}
	s.recordSession(t.Context(), &ss)
	if rec, _ := listGroups(t, s, "u"); rec.Code != http.StatusInternalServerError {
		t.Errorf("groups without ID token: status = %d, want nothing recorded", rec.Code)
	}
	if _, ok := s.idTokenClaims.Get("tok3"); ok {
		t.Error("no claims should be cached without an ID token")
	}

	// A garbage ID token is tolerated, and records nothing: an empty list
	// would make Obot drop the user's memberships.
	ss = state.SerializableState{AccessToken: "tok4", IDToken: "garbage", User: "v"}
	s.recordSession(t.Context(), &ss)
	if rec, _ := listGroups(t, s, "v"); rec.Code != http.StatusInternalServerError {
		t.Errorf("garbage token: status = %d, want nothing recorded", rec.Code)
	}

	// Nothing identifies the user: nothing is recorded.
	ss = state.SerializableState{AccessToken: "tok5"}
	s.recordSession(t.Context(), &ss)
	if rec, _ := listGroups(t, s, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("empty id: status = %d", rec.Code)
	}
}

func TestRecordSessionSplitsDelimitedGroups(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	s.cfg.GroupsDelimiter = ","
	record := func(groupsJSON string) state.GroupInfoList {
		t.Helper()
		idToken := "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"sub-d","groups":`+groupsJSON+`}`)) + ".s"
		ss := state.SerializableState{AccessToken: "tok-" + groupsJSON, IDToken: idToken}
		s.recordSession(t.Context(), &ss)
		return ss.GroupInfos
	}

	// A single delimited string is split.
	if got := groupNames(record(`"Domain Admins, devs"`)); got != "pingfederate/Domain Admins=Domain Admins,pingfederate/devs=devs" {
		t.Errorf("GroupInfos from delimited string = %q", got)
	}
	// A list is never split, so an element containing the delimiter, such as
	// an LDAP DN, cannot turn into other groups.
	if got := groupNames(record(`["cn=x,ou=admins", "devs"]`)); got != "pingfederate/cn=x,ou=admins=cn=x,ou=admins,pingfederate/devs=devs" {
		t.Errorf("GroupInfos from a list = %q, want each element kept whole", got)
	}

	s.cfg.GroupsDelimiter = ""
	if got := groupNames(record(`"CN=Admins,OU=Groups"`)); got != "pingfederate/CN=Admins,OU=Groups=CN=Admins,OU=Groups" {
		t.Errorf("GroupInfos without delimiter = %q, want the value kept whole", got)
	}
}

func TestProfileID(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	if p := s.profile(map[string]any{"sub": "s", "email": "e"}); p["id"] != "s" {
		t.Errorf("id = %v, want sub", p["id"])
	}
	// Groups are recorded under the subject only, so the email is never an id.
	if p := s.profile(map[string]any{"email": "e"}); p["id"] != "" {
		t.Errorf("id = %v, want none without a subject", p["id"])
	}
	s.cfg.EmailClaim = "mail"
	if p := s.profile(map[string]any{"sub": "s", "mail": "m", "email": "e"}); p["id"] != "s" || p["email"] != "m" || p["name"] != "m" {
		t.Errorf("custom email claim: %v", p)
	}
	if p := s.profile(map[string]any{}); p["id"] != "" || p["name"] != "" {
		t.Errorf("empty claims: %v", p)
	}
	if _, ok := s.profile(map[string]any{"sub": "s"})["email"]; ok {
		t.Error("email should be absent when the claim is missing")
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":   "abc",
		"bearer abc":   "abc",
		"BEARER  abc ": "abc",
		"abc":          "abc",
		"":             "",
		"Bearer ":      "",
	}
	for in, want := range cases {
		if got := bearerToken(in); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRootReportsListenURL(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(s.listenURL)) })
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "http://127.0.0.1:9999" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// Claims are read as oauth2-proxy copies them into a session, so values the
// two agree on compare equal however the identity provider releases them.
func TestSessionClaimMatchesOAuth2Proxy(t *testing.T) {
	claims := map[string]any{
		"email":   "ada@example.com",
		"names":   []any{"ada", "lovelace"},
		"number":  float64(42),
		"null":    nil,
		"profile": map[string]any{"login": "ada"},
	}
	for name, want := range map[string]any{
		"email":         "ada@example.com",
		"names":         []any{"ada", "lovelace"},
		"number":        float64(42),
		"profile.login": "ada",
	} {
		var expected string
		if err := util.CoerceClaim(want, &expected); err != nil {
			t.Fatal(err)
		}
		if got := sessionClaim(claims, name); got != expected {
			t.Errorf("sessionClaim(%q) = %q, want %q as oauth2-proxy gives it", name, got, expected)
		}
	}
	// A claim named with a dot that is present, even as null, is not looked
	// up as a path, as oauth2-proxy does.
	dotted := map[string]any{"a.b": nil, "a": map[string]any{"b": "x@y.com"}}
	if claimValue(dotted, "a.b") != nil {
		t.Error(`claim "a.b" present as null should be missing, not read from a.b's path`)
	}
	for _, name := range []string{"null", "missing", "profile.missing", ""} {
		if claimValue(claims, name) != nil || sessionClaim(claims, name) != "" {
			t.Errorf("claim %q should be missing", name)
		}
	}
}

// A preferred_username released as an array, in the ID token or only in
// userinfo, must not refuse a session that agrees with userinfo.
func TestCheckUserinfoClaimsWithNonStringClaims(t *testing.T) {
	names := []any{"ada"}
	var calls atomic.Int32
	upstream := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "email": "ada@example.com", "preferred_username": names})
	s := newTestServer(t, upstream.URL, time.Minute)
	// The provider's own userinfo answer for the token, as recordSession asks.
	if _, ok, _ := s.currentGroups(t.Context(), "tok", "sub-1"); !ok {
		t.Fatal("userinfo was not answered for sub-1")
	}
	// The session as oauth2-proxy builds it from the same claims.
	var sessionName string
	if err := util.CoerceClaim(names, &sessionName); err != nil {
		t.Fatal(err)
	}
	ss := state.SerializableState{AccessToken: "tok", Email: "ada@example.com", PreferredUsername: sessionName}

	if got := s.checkUserinfoClaims(ss, "sub-1", map[string]any{"sub": "sub-1", "preferred_username": names}); got != userinfoConsistent {
		t.Errorf("array claim in the ID token: verdict %d, want consistent", got)
	}
	if got := s.checkUserinfoClaims(ss, "sub-1", map[string]any{"sub": "sub-1"}); got != userinfoConsistent {
		t.Errorf("array claim only in userinfo: verdict %d, want consistent", got)
	}
	ss.PreferredUsername = "eve"
	if got := s.checkUserinfoClaims(ss, "sub-1", map[string]any{"sub": "sub-1"}); got != userinfoContradicts {
		t.Errorf("different username only in userinfo: verdict %d, want contradicts", got)
	}

	// The array is only in the ID token, and userinfo does not release it:
	// oauth2-proxy took it from the ID token, so there is nothing to compare.
	quiet := userinfoServer(t, &calls, map[string]any{"sub": "sub-1", "email": "ada@example.com"})
	s = newTestServer(t, quiet.URL, time.Minute)
	if _, ok, _ := s.currentGroups(t.Context(), "tok", "sub-1"); !ok {
		t.Fatal("userinfo was not answered for sub-1")
	}
	ss.PreferredUsername = sessionName
	if got := s.checkUserinfoClaims(ss, "sub-1", map[string]any{"sub": "sub-1", "preferred_username": names}); got != userinfoConsistent {
		t.Errorf("array claim only in the ID token: verdict %d, want consistent", got)
	}
}

// Numbers in userinfo read exactly, as oauth2-proxy reads them, so a large or
// decimal preferred_username compares equal to the session's.
func TestUserinfoNumbersReadAsOAuth2ProxyReadsThem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sub":"sub-1","preferred_username":12345678901234567,"email":1.10}`))
	}))
	t.Cleanup(srv.Close)
	s := newTestServer(t, srv.URL, time.Minute)
	if _, ok, _ := s.currentGroups(t.Context(), "tok", "sub-1"); !ok {
		t.Fatal("userinfo was not answered for sub-1")
	}
	answer, _ := s.tokenGroups.Get("tok")
	if answer.preferredUsername != "12345678901234567" || answer.email != "1.10" {
		t.Errorf("answer = username %q, email %q, want the numbers as written", answer.preferredUsername, answer.email)
	}
}
