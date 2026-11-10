package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// fakePingFederate serves the endpoints oauth2-proxy and the provider use, shaped like PingFederate with its default
// OpenID Connect policy: the ID token carries the subject alone, and the profile and groups come from userinfo.
type fakePingFederate struct {
	t      *testing.T
	server *httptest.Server
	signer jose.Signer
	key    *rsa.PrivateKey

	mu sync.Mutex
	// userinfo is what the userinfo endpoint answers.
	userinfo map[string]any
	// idTokenClaims are added to the ID token.
	idTokenClaims map[string]any
	// omitRefreshIDToken leaves the ID token out of refresh responses, as PingFederate does unless "Return ID Token
	// on Refresh Grant" is enabled.
	omitRefreshIDToken bool
	// issuedAt is the iat of the next ID token. Each token advances it by a second, so that tokens issued in one
	// test are ordered as they would be in real time.
	issuedAt time.Time
}

func newFakePingFederate(t *testing.T) *fakePingFederate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePingFederate{
		t:      t,
		signer: signer,
		key:    key,
		userinfo: map[string]any{
			"sub":                "alice",
			"email":              "alice@example.com",
			"name":               "Alice Anderson",
			"preferred_username": "alice",
			"groups":             []string{"cn=engineering,ou=groups,dc=example,dc=com", "cn=obot-admins,ou=groups,dc=example,dc=com"},
		},
		idTokenClaims: map[string]any{},
		issuedAt:      time.Now().Add(-time.Minute),
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakePingFederate) issuer() string { return f.server.URL }

// caPEM is the PEM of the fake's self-signed certificate, which the provider must be told to trust.
func (f *fakePingFederate) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}))
}

func (f *fakePingFederate) set(update func(*fakePingFederate)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	update(f)
}

func (f *fakePingFederate) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var response any
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		response = map[string]any{
			"issuer":                                f.issuer(),
			"authorization_endpoint":                f.issuer() + "/as/authorization.oauth2",
			"token_endpoint":                        f.issuer() + "/as/token.oauth2",
			"userinfo_endpoint":                     f.issuer() + "/idp/userinfo.openid",
			"jwks_uri":                              f.issuer() + "/pf/JWKS",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
	case "/pf/JWKS":
		response = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}}
	case "/as/token.oauth2":
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		token := map[string]any{"access_token": "access-" + time.Now().Format(time.RFC3339Nano), "token_type": "Bearer", "expires_in": 7200, "refresh_token": "refresh"}
		if r.Form.Get("grant_type") != "refresh_token" || !f.omitRefreshIDToken {
			token["id_token"] = f.idToken()
		}
		response = token
	case "/idp/userinfo.openid":
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer access-") {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		response = f.userinfo
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		f.t.Error(err)
	}
}

func (f *fakePingFederate) idToken() string {
	claims := map[string]any{"iss": f.issuer(), "sub": f.userinfo["sub"], "aud": "obot", "exp": time.Now().Add(time.Hour).Unix(), "iat": f.issuedAt.Unix()}
	f.issuedAt = f.issuedAt.Add(time.Second)
	for k, v := range f.idTokenClaims {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		f.t.Fatal(err)
	}
	signed, err := f.signer.Sign(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func testOptions(t *testing.T, issuer, caPEM string) Options {
	t.Helper()
	return Options{
		ClientID:                 "obot",
		ClientSecret:             "secret",
		IssuerURL:                issuer,
		CACertificate:            caPEM,
		ObotServerURL:            "https://obot.example",
		AuthCookieSecret:         base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))),
		AuthEmailDomains:         "*",
		AuthTokenRefreshDuration: "1h",
	}
}

// testServer builds the provider as main does, against the fake and a test database, and returns it with the
// oauth2-proxy provider so a test can sign a user in without a browser.
func testServer(t *testing.T, f *fakePingFederate) (*server, providers.Provider) {
	t.Helper()
	opts := testOptions(t, f.issuer(), f.caPEM())
	opts.PostgresConnectionDSN = testDSN(t)
	caFile, err := writeCACertificate(opts.CACertificate)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := newHTTPClient(opts.CACertificate)
	if err != nil {
		t.Fatal(err)
	}
	userInfoURL, err := discoverUserInfoURL(t.Context(), httpClient, opts.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	proxyOpts, err := buildOAuthProxyOptions(opts, caFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(proxyOpts); err != nil {
		t.Fatal(err)
	}
	proxy, err := oauth2proxy.NewOAuthProxy(proxyOpts, oauth2proxy.NewValidator(proxyOpts.EmailDomains, proxyOpts.AuthenticatedEmailsFile))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := providers.NewProvider(proxyOpts.Providers[0])
	if err != nil {
		t.Fatal(err)
	}
	store, err := openGroupStore(t.Context(), opts.PostgresConnectionDSN, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.db.Close() })
	return &server{proxy: proxy, store: store, groups: newGroupRecorder(store), httpClient: httpClient, userInfoURL: userInfoURL}, provider
}

func signIn(t *testing.T, provider providers.Provider) *sessions.SessionState {
	t.Helper()
	session, err := provider.Redeem(t.Context(), "https://obot.example/", "code", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.EnrichSession(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	return session
}

// getStateFor asks the provider for the state of a request carrying session's cookie.
func getStateFor(t *testing.T, s *server, session *sessions.SessionState) (int, state.SerializableState) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://obot.example/", nil)
	saved := httptest.NewRecorder()
	if err := s.proxy.SaveSession(saved, request, session); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range saved.Result().Cookies() {
		request.AddCookie(cookie)
	}
	body, err := json.Marshal(state.SerializableRequest{Method: http.MethodGet, URL: request.URL.String(), Header: request.Header})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.getState(response, httptest.NewRequest(http.MethodPost, "/obot-get-state", bytes.NewReader(body)))
	var ss state.SerializableState
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &ss); err != nil {
			t.Fatal(err)
		}
	}
	return response.Code, ss
}

func userGroupIDs(t *testing.T, s *server, userID string) (int, []string) {
	t.Helper()
	response := httptest.NewRecorder()
	s.listUserGroups(response, httptest.NewRequest(http.MethodPost, "/obot-list-user-auth-groups", strings.NewReader(userID)))
	if response.Code != http.StatusOK {
		return response.Code, nil
	}
	var infos state.GroupInfoList
	if err := json.Unmarshal(response.Body.Bytes(), &infos); err != nil {
		t.Fatal(err)
	}
	return response.Code, infos.IDs()
}

func expire(session *sessions.SessionState) {
	old := time.Now().Add(-2 * time.Hour)
	session.CreatedAt = &old
	session.ExpiresOn = &old
}

func TestSignInRecordsGroupsFromUserinfo(t *testing.T) {
	f := newFakePingFederate(t)
	s, provider := testServer(t, f)

	// Obot asks for a user's groups by the ID that /obot-get-user-info reports; nothing is recorded before sign-in.
	if code, _ := userGroupIDs(t, s, "alice"); code != http.StatusInternalServerError {
		t.Fatalf("groups of a user never seen: HTTP %d, want 500 so Obot keeps what it has", code)
	}

	session := signIn(t, provider)
	if session.User != "alice" || session.Email != "alice@example.com" {
		t.Fatalf("session identity = %q, %q", session.User, session.Email)
	}

	code, ss := getStateFor(t, s, session)
	if code != http.StatusOK {
		t.Fatalf("get-state: HTTP %d", code)
	}
	want := []string{
		"pingfederate/cn=engineering%2Cou=groups%2Cdc=example%2Cdc=com",
		"pingfederate/cn=obot-admins%2Cou=groups%2Cdc=example%2Cdc=com",
	}

	info := httptest.NewRecorder()
	userInfoRequest := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
	userInfoRequest.Header.Set("Authorization", "Bearer "+ss.AccessToken)
	s.getUserInfo(info, userInfoRequest)
	var profile map[string]string
	if err := json.Unmarshal(info.Body.Bytes(), &profile); err != nil || info.Code != http.StatusOK {
		t.Fatalf("get-user-info: HTTP %d: %s", info.Code, info.Body)
	}
	if profile["id"] != "alice" || profile["name"] != "Alice Anderson" {
		t.Fatalf("profile = %v", profile)
	}

	if code, got := userGroupIDs(t, s, profile["id"]); code != http.StatusOK || !slices.Equal(got, want) {
		t.Fatalf("user groups = HTTP %d %q, want %q", code, got, want)
	}

	list := httptest.NewRecorder()
	s.handler("0").ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/obot-list-auth-groups", nil))
	if !strings.Contains(list.Body.String(), `"name":"cn=engineering,ou=groups,dc=example,dc=com"`) {
		t.Fatalf("group listing does not name the group by its value: %s", list.Body)
	}
}

func TestRefreshReplacesRecordedGroups(t *testing.T) {
	f := newFakePingFederate(t)
	s, provider := testServer(t, f)
	session := signIn(t, provider)
	if code, _ := getStateFor(t, s, session); code != http.StatusOK {
		t.Fatalf("get-state: HTTP %d", code)
	}

	// alice leaves obot-admins in the directory, and her tokens are refreshed.
	f.set(func(f *fakePingFederate) {
		f.userinfo["groups"] = []string{"cn=engineering,ou=groups,dc=example,dc=com"}
	})
	expire(session)
	code, ss := getStateFor(t, s, session)
	if code != http.StatusOK {
		t.Fatalf("get-state after refresh: HTTP %d", code)
	}
	if len(ss.SetCookies) == 0 {
		t.Fatal("the session was not refreshed")
	}
	want := []string{"pingfederate/cn=engineering%2Cou=groups%2Cdc=example%2Cdc=com"}
	if _, got := userGroupIDs(t, s, "alice"); !slices.Equal(got, want) {
		t.Fatalf("recorded groups = %q, want %q", got, want)
	}

	// A group with no members left is no longer offered.
	list := httptest.NewRecorder()
	s.handler("0").ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/obot-list-auth-groups?name=admins", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "obot-admins") {
		t.Fatalf("group listing: HTTP %d: %s", list.Code, list.Body)
	}

	// Removing every group is recorded too: an empty claim is an empty list, not a missing one.
	f.set(func(f *fakePingFederate) { delete(f.userinfo, "groups") })
	expire(session)
	if code, _ = getStateFor(t, s, session); code != http.StatusOK {
		t.Fatalf("get-state without groups: HTTP %d", code)
	}
	if code, got := userGroupIDs(t, s, "alice"); code != http.StatusOK || len(got) != 0 {
		t.Fatalf("recorded groups = HTTP %d %q, want none", code, got)
	}
}

func TestGroupsInIDTokenAreUsed(t *testing.T) {
	// With "Include User Info in ID Token" enabled, PingFederate puts the groups in the ID token instead.
	f := newFakePingFederate(t)
	f.idTokenClaims["groups"] = []string{"sales"}
	f.idTokenClaims["email"] = "alice@example.com"
	s, provider := testServer(t, f)

	if code, _ := getStateFor(t, s, signIn(t, provider)); code != http.StatusOK {
		t.Fatalf("get-state: HTTP %d", code)
	}
	if _, got := userGroupIDs(t, s, "alice"); !slices.Equal(got, []string{"pingfederate/sales"}) {
		t.Fatalf("recorded groups = %q", got)
	}
}

func TestSingleGroupStringIsOneGroup(t *testing.T) {
	// An attribute that is not marked multi-valued in the OpenID Connect policy is released as a string.
	f := newFakePingFederate(t)
	f.userinfo["groups"] = "cn=sales,ou=groups,dc=example,dc=com"
	s, provider := testServer(t, f)

	if code, _ := getStateFor(t, s, signIn(t, provider)); code != http.StatusOK {
		t.Fatalf("get-state: HTTP %d", code)
	}
	if _, got := userGroupIDs(t, s, "alice"); !slices.Equal(got, []string{"pingfederate/cn=sales%2Cou=groups%2Cdc=example%2Cdc=com"}) {
		t.Fatalf("recorded groups = %q", got)
	}
}

func TestUnverifiedEmailIsRejected(t *testing.T) {
	f := newFakePingFederate(t)
	f.idTokenClaims["email"] = "alice@example.com"
	f.idTokenClaims["email_verified"] = false
	_, provider := testServer(t, f)

	if _, err := provider.Redeem(t.Context(), "https://obot.example/", "code", "verifier"); err == nil {
		t.Fatal("signed in with an email that PingFederate says is unverified")
	}
}

func TestOlderSessionDoesNotRestoreGroups(t *testing.T) {
	// Two browsers hold sessions for the same user. After a group is removed, the session refreshed first must not
	// have its answer undone by the other, older session, whichever replica serves it.
	f := newFakePingFederate(t)
	s, provider := testServer(t, f)
	older := signIn(t, provider)
	newer := signIn(t, provider)

	f.set(func(f *fakePingFederate) {
		f.userinfo["groups"] = []string{"cn=engineering,ou=groups,dc=example,dc=com"}
	})
	expire(newer)
	if code, _ := getStateFor(t, s, newer); code != http.StatusOK {
		t.Fatalf("get-state: HTTP %d", code)
	}

	// Another replica, with nothing remembered, serves the older session.
	other := &server{proxy: s.proxy, store: s.store, groups: newGroupRecorder(s.store), httpClient: s.httpClient, userInfoURL: s.userInfoURL}
	for _, replica := range []*server{s, other} {
		if code, _ := getStateFor(t, replica, older); code != http.StatusOK {
			t.Fatalf("get-state: HTTP %d", code)
		}
	}
	want := []string{"pingfederate/cn=engineering%2Cou=groups%2Cdc=example%2Cdc=com"}
	if _, got := userGroupIDs(t, s, "alice"); !slices.Equal(got, want) {
		t.Fatalf("recorded groups = %q, want %q", got, want)
	}
}

func TestRefreshWithoutIDTokenSignsOut(t *testing.T) {
	// The ID token is recent, so only a comparison with the pre-refresh token can tell that no new one came back.
	f := newFakePingFederate(t)
	f.omitRefreshIDToken = true
	s, provider := testServer(t, f)
	session := signIn(t, provider)

	expire(session)
	if code, _ := getStateFor(t, s, session); code != http.StatusUnauthorized {
		t.Fatalf("get-state after a refresh without an ID token: HTTP %d, want 401", code)
	}
}

func TestRefreshToleratesClockSkew(t *testing.T) {
	// PingFederate's clock runs ten minutes behind Obot's. Its ID tokens look old, but each refresh returns a new one.
	f := newFakePingFederate(t)
	f.issuedAt = time.Now().Add(-10 * time.Minute)
	s, provider := testServer(t, f)
	session := signIn(t, provider)

	for range 2 {
		expire(session)
		if code, _ := getStateFor(t, s, session); code != http.StatusOK {
			t.Fatalf("get-state after a refresh with a new ID token: HTTP %d, want 200", code)
		}
	}
}

func TestIDTokenIssuedAt(t *testing.T) {
	token := func(claims string) string {
		return "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
	}
	if got, ok := idTokenIssuedAt(token(`{"iat":1700000000}`)); !ok || got.Unix() != 1700000000 {
		t.Fatalf("idTokenIssuedAt = %v, %v", got, ok)
	}
	for _, bad := range []string{token(`{}`), token(`{"iat":"soon"}`), "not-a-jwt"} {
		if _, ok := idTokenIssuedAt(bad); ok {
			t.Errorf("idTokenIssuedAt(%q) succeeded", bad)
		}
	}
}

func TestStartupIsSafeAcrossReplicas(t *testing.T) {
	// Every Obot replica runs its own provider, and they start together against a database without the tables.
	f := newFakePingFederate(t)
	dsn := testDSN(t)
	caFile, err := writeCACertificate(f.caPEM())
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			opts := testOptions(t, f.issuer(), f.caPEM())
			opts.PostgresConnectionDSN = dsn
			proxyOpts, err := buildOAuthProxyOptions(opts, caFile)
			if err == nil {
				err = validation.Validate(proxyOpts)
			}
			if err == nil {
				var store *groupStore
				if store, err = prepareDatabase(t.Context(), opts, proxyOpts.Session.Postgres.TableNamePrefix); err == nil {
					_ = store.db.Close()
					_, err = oauth2proxy.NewOAuthProxy(proxyOpts, oauth2proxy.NewValidator(proxyOpts.EmailDomains, proxyOpts.AuthenticatedEmailsFile))
				}
			}
			if err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a replica failed to start: %v", err)
	}
}
