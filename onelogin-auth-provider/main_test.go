package main

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/client"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/onelogintest"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/profile"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

func TestAPICredentialsConfigured(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		want         bool
		wantErr      bool
	}{
		{
			name:         "both present",
			clientID:     "0123456789abcdef",
			clientSecret: "fedcba9876543210",
			want:         true,
			wantErr:      false,
		},
		{
			name:         "both absent",
			clientID:     "",
			clientSecret: "",
			want:         false,
			wantErr:      false,
		},
		{
			name:         "only client ID",
			clientID:     "0123456789abcdef",
			clientSecret: "",
			want:         false,
			wantErr:      true,
		},
		{
			name:         "only client secret",
			clientID:     "",
			clientSecret: "fedcba9876543210",
			want:         false,
			wantErr:      true,
		},
		{
			name:         "both whitespace-only",
			clientID:     "  ",
			clientSecret: "\n\t ",
			want:         false,
			wantErr:      false,
		},
		{
			name:         "client ID with a whitespace-only client secret",
			clientID:     "0123456789abcdef",
			clientSecret: " \n",
			want:         false,
			wantErr:      true,
		},
		{
			name:         "client secret with a whitespace-only client ID",
			clientID:     "\t",
			clientSecret: "fedcba9876543210",
			want:         false,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := apiCredentialsConfigured(tt.clientID, tt.clientSecret)
			if (err != nil) != tt.wantErr {
				t.Fatalf("apiCredentialsConfigured() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("apiCredentialsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIBaseURL(t *testing.T) {
	tests := []struct {
		name      string
		issuerURL string
		override  string
		want      string
		wantErr   bool
	}{
		{
			name:      "defaults to the issuer's scheme and host",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "",
			want:      "https://example.onelogin.com",
			wantErr:   false,
		},
		{
			name:      "override wins",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "https://api.us.onelogin.com/",
			want:      "https://api.us.onelogin.com",
			wantErr:   false,
		},
		{
			name:      "whitespace-only override counts as absent",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  " ",
			want:      "https://example.onelogin.com",
			wantErr:   false,
		},
		{
			name:      "issuer without a scheme",
			issuerURL: "example.onelogin.com/oidc/2",
			override:  "",
			want:      "",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := apiBaseURL(tt.issuerURL, tt.override)
			if (err != nil) != tt.wantErr {
				t.Fatalf("apiBaseURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("apiBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRegisterDirectoryRoutesWithoutAPIClient(t *testing.T) {
	mux := http.NewServeMux()
	(&server{}).registerDirectoryRoutes(mux)
	// Stands in for the oauth2-proxy handler that main registers at /.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	tests := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{
			name:   "list groups",
			method: http.MethodGet,
			target: "/obot-list-auth-groups?name=eng&limit=10",
			body:   "",
		},
		{
			name:   "get groups",
			method: http.MethodGet,
			target: "/obot-get-auth-groups?ids=onelogin/123",
			body:   "",
		},
		{
			// GetGroupsHandler answers IDs of other providers without calling fetch, so this also checks that the
			// 503 comes before any of the handler's own work.
			name:   "get groups with no OneLogin IDs",
			method: http.MethodGet,
			target: "/obot-get-auth-groups?ids=okta/00g1",
			body:   "",
		},
		{
			name:   "list user groups",
			method: http.MethodPost,
			target: "/obot-list-user-auth-groups",
			body:   "263801284",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body)))

			if rec.Code == http.StatusTeapot {
				t.Fatalf("%s %s fell through to the oauth2-proxy handler", tt.method, tt.target)
			}
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != directoryUnavailableMessage {
				t.Errorf("body = %q, want %q", got, directoryUnavailableMessage)
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
				t.Errorf("Content-Type = %q, want text/plain", got)
			}
		})
	}
}

// newTestDirectoryServer returns a server whose directory endpoints call a fake OneLogin admin API, with roles
// named obot-engineering, obot-operations and Security, and users who are active, suspended, or hold no roles.
// The role-name cache starts filled.
func newTestDirectoryServer(t *testing.T) (*onelogintest.Server, *http.ServeMux) {
	t.Helper()

	fake := onelogintest.New(t, []onelogintest.Role{
		{
			ID:   1100002,
			Name: "obot-engineering",
		},
		{
			ID:   1100003,
			Name: "obot-operations",
		},
		{
			ID:   1100004,
			Name: "Security",
		},
	}, []onelogintest.User{
		{
			ID:      300000001,
			RoleIDs: []int64{1100002, 1100004},
			Status:  1,
		},
		{
			ID:      300000002,
			RoleIDs: nil,
			Status:  1,
		},
		{
			ID:      300000003,
			RoleIDs: []int64{1100002},
			Status:  2,
		},
	})

	apiClient := client.New(fake.URL, onelogintest.ClientID, onelogintest.ClientSecret)
	roles := profile.NewRoleCache(apiClient)
	if err := roles.Refresh(t.Context()); err != nil {
		t.Fatalf("failed to fill the role-name cache: %v", err)
	}

	mux := http.NewServeMux()
	(&server{
		apiClient: apiClient,
		roles:     roles,
	}).registerDirectoryRoutes(mux)

	return fake, mux
}

func TestDirectoryRoutes(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		wantStatus int
		wantIDs    []string
		wantBody   string
	}{
		{
			name:       "list groups",
			method:     http.MethodGet,
			target:     "/obot-list-auth-groups?name=OBOT&limit=10",
			body:       "",
			wantStatus: http.StatusOK,
			wantIDs:    []string{"onelogin/1100002", "onelogin/1100003"},
			wantBody:   "",
		},
		{
			name:       "list groups with a cursor from another provider",
			method:     http.MethodGet,
			target:     "/obot-list-auth-groups?limit=10&cursor=eyJ2IjoxLCJwIjoib2t0YSIsImwiOjEwLCJ0IjowLCJuIjoieCJ9",
			body:       "",
			wantStatus: http.StatusBadRequest,
			wantIDs:    nil,
			wantBody:   "invalid cursor",
		},
		{
			name:       "get groups",
			method:     http.MethodGet,
			target:     "/obot-get-auth-groups?ids=onelogin/1100004,onelogin/1100099,onelogin/abc,okta/00g1",
			body:       "",
			wantStatus: http.StatusOK,
			wantIDs:    []string{"onelogin/1100004"},
			wantBody:   "",
		},
		{
			name:       "list user groups",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       "300000001\n",
			wantStatus: http.StatusOK,
			wantIDs:    []string{"onelogin/1100002", "onelogin/1100004"},
			wantBody:   "",
		},
		{
			name:       "list user groups of a user without roles",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       "300000002",
			wantStatus: http.StatusOK,
			wantIDs:    []string{},
			wantBody:   "[]",
		},
		{
			name:       "list user groups of a suspended user",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       "300000003",
			wantStatus: http.StatusForbidden,
			wantIDs:    nil,
			wantBody:   "OneLogin account is not active (status 2: suspended)",
		},
		{
			name:       "list user groups of a deleted user",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       "300000099",
			wantStatus: http.StatusForbidden,
			wantIDs:    nil,
			wantBody:   "OneLogin user was not found",
		},
		{
			name:       "list user groups of an invalid user ID",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       "00u1abcd",
			wantStatus: http.StatusBadRequest,
			wantIDs:    nil,
			wantBody:   "invalid OneLogin user ID",
		},
		{
			name:       "list user groups without a user ID",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       " ",
			wantStatus: http.StatusBadRequest,
			wantIDs:    nil,
			wantBody:   "user ID is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mux := newTestDirectoryServer(t)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body)))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body %q", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBody)
			}
			if tt.wantIDs == nil {
				return
			}

			if got := responseGroupIDs(t, tt.target, rec.Body.Bytes()); !slices.Equal(got, tt.wantIDs) {
				t.Errorf("ids = %v, want %v", got, tt.wantIDs)
			}
		})
	}
}

// responseGroupIDs returns the group IDs in the body of a directory endpoint's response.
func responseGroupIDs(t *testing.T, target string, body []byte) []string {
	t.Helper()

	var groups state.GroupInfoList
	if strings.HasPrefix(target, "/obot-list-user-auth-groups") {
		if err := json.Unmarshal(body, &groups); err != nil {
			t.Fatalf("failed to decode body %q: %v", body, err)
		}
	} else {
		var list authcommon.GroupList
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatalf("failed to decode body %q: %v", body, err)
		}
		groups = list.Items
	}

	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	return ids
}

func TestListGroupsCursorRoundTrip(t *testing.T) {
	fake, mux := newTestDirectoryServer(t)

	listPage := func(target string) (int, authcommon.GroupPage) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

		var page authcommon.GroupPage
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatalf("failed to decode body %q: %v", rec.Body.String(), err)
			}
		}
		return rec.Code, page
	}

	status, first := listPage("/obot-list-auth-groups?name=obot&limit=1")
	if status != http.StatusOK || len(first.Items) != 1 || first.Items[0].ID != "onelogin/1100002" || first.NextCursor == "" {
		t.Fatalf("first page = %d, %+v, want obot-engineering and a cursor", status, first)
	}

	status, second := listPage("/obot-list-auth-groups?name=obot&limit=1&cursor=" + first.NextCursor)
	if status != http.StatusOK || len(second.Items) != 1 || second.Items[0].ID != "onelogin/1100003" || second.NextCursor != "" {
		t.Fatalf("second page = %d, %+v, want obot-operations and no cursor", status, second)
	}

	// OneLogin got its own cursor back, alone.
	requests := fake.Requests()
	last := requests[len(requests)-1].Query()
	if len(last) != 1 || last.Get("cursor") == "" {
		t.Errorf("second page query = %v, want only a cursor", last)
	}

	// A cursor replayed against another filter is refused before OneLogin is called.
	if status, _ := listPage("/obot-list-auth-groups?name=sec&limit=1&cursor=" + first.NextCursor); status != http.StatusBadRequest {
		t.Errorf("status with a changed filter = %d, want %d", status, http.StatusBadRequest)
	}
	if got := len(fake.Requests()); got != len(requests) {
		t.Errorf("calls after a changed filter = %d, want %d", got, len(requests))
	}
}

func TestDirectoryRoutesRateLimited(t *testing.T) {
	fake, mux := newTestDirectoryServer(t)
	fake.SetRateLimited(true, "30")

	serve := func(method, target, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
		return rec
	}

	// The 429 itself.
	rec := serve(http.MethodPost, "/obot-list-user-auth-groups", "300000001")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d, body %q", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After = %q, want 30", got)
	}
	if !strings.Contains(rec.Body.String(), "rate limit") {
		t.Errorf("body = %q, want it to mention the rate limit", rec.Body.String())
	}

	// OneLogin recovers at once, but nothing calls it until the wait is over.
	fake.SetRateLimited(false, "")
	calls := len(fake.Requests())

	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		wantStatus int
	}{
		{
			name:       "list user groups",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       "300000001",
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "list groups",
			method:     http.MethodGet,
			target:     "/obot-list-auth-groups?limit=10",
			body:       "",
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			// The role-name cache answers this without OneLogin.
			name:       "get cached groups",
			method:     http.MethodGet,
			target:     "/obot-get-auth-groups?ids=onelogin/1100002",
			body:       "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get uncached groups",
			method:     http.MethodGet,
			target:     "/obot-get-auth-groups?ids=onelogin/1100099",
			body:       "",
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serve(tt.method, tt.target, tt.body)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body %q", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}

	if got := len(fake.Requests()); got != calls {
		t.Errorf("calls to OneLogin while waiting = %d, want 0", got-calls)
	}
}

func TestRequireAPIClient(t *testing.T) {
	tests := []struct {
		name           string
		apiClient      *client.Client
		wantStatus     int
		wantNextCalled bool
	}{
		{
			name:           "without an API client",
			apiClient:      nil,
			wantStatus:     http.StatusServiceUnavailable,
			wantNextCalled: false,
		},
		{
			name:           "with an API client",
			apiClient:      client.New("https://example.onelogin.com", "id", "secret"),
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nextCalled bool
			handler := (&server{
				apiClient: tt.apiClient,
			}).requireAPIClient(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			})

			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, "/obot-list-auth-groups", nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if nextCalled != tt.wantNextCalled {
				t.Errorf("next called = %v, want %v", nextCalled, tt.wantNextCalled)
			}
		})
	}
}

func TestGetUserInfo(t *testing.T) {
	// Stands in for OneLogin's userinfo endpoint, <issuer>/me. The body is the one OneLogin returned in the phase 0b
	// capture.
	oneLogin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oidc/2/me" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer good-token" {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"email":"user@example.com","family_name":"Testing1","given_name":"Grant","name":"Grant Testing1","preferred_username":"grant_testing1","sub":"263801284","updated_at":1792006400}`))
	}))
	defer oneLogin.Close()

	srv := &server{
		issuerURL: oneLogin.URL + "/oidc/2",
	}

	tests := []struct {
		name          string
		authorization string
		wantStatus    int
		wantUser      *profile.UserInfo
	}{
		{
			name:          "valid token",
			authorization: "Bearer good-token",
			wantStatus:    http.StatusOK,
			wantUser: &profile.UserInfo{
				ID:      "263801284",
				Name:    "Grant Testing1",
				IconURL: "",
			},
		},
		{
			name:          "no token",
			authorization: "",
			wantStatus:    http.StatusUnauthorized,
			wantUser:      nil,
		},
		{
			name:          "token OneLogin rejects",
			authorization: "Bearer bad-token",
			wantStatus:    http.StatusInternalServerError,
			wantUser:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}

			rec := httptest.NewRecorder()
			srv.getUserInfo(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body %q", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantUser == nil {
				return
			}

			if strings.Contains(rec.Body.String(), "icon_url") {
				t.Errorf("body = %q, want no icon_url", rec.Body.String())
			}

			var got profile.UserInfo
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("failed to decode body %q: %v", rec.Body.String(), err)
			}
			if got != *tt.wantUser {
				t.Errorf("user = %+v, want %+v", got, *tt.wantUser)
			}
		})
	}
}

// newTestOAuthProxy returns an oauth2-proxy configured as main configures it, against a stand-in OIDC issuer that
// serves only discovery.
func newTestOAuthProxy(t *testing.T) *oauth2proxy.OAuthProxy {
	t.Helper()

	var issuerURL string
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oidc/2/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuerURL,
			"authorization_endpoint":                issuerURL + "/auth",
			"token_endpoint":                        issuerURL + "/token",
			"userinfo_endpoint":                     issuerURL + "/me",
			"jwks_uri":                              issuerURL + "/certs",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(issuer.Close)
	issuerURL = issuer.URL + "/oidc/2"

	legacyOpts := options.NewLegacyOptions()
	legacyOpts.LegacyProvider.ProviderType = "oidc"
	legacyOpts.LegacyProvider.ProviderName = "oidc"
	legacyOpts.LegacyProvider.ClientID = "client-id"
	legacyOpts.LegacyProvider.ClientSecret = "client-secret"
	legacyOpts.LegacyProvider.OIDCIssuerURL = issuerURL
	legacyOpts.LegacyProvider.Scope = "openid email profile"

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		t.Fatalf("failed to convert legacy options: %v", err)
	}
	opts.Server.BindAddress = ""
	opts.MetricsServer.BindAddress = ""
	opts.Cookie.Name = "obot_access_token"
	opts.Cookie.Secret = "0123456789abcdef0123456789abcdef"
	opts.RawRedirectURL = "http://localhost:8080/"
	opts.EmailDomains = []string{"*"}
	opts.Logging.RequestEnabled = false
	opts.Logging.AuthEnabled = false
	opts.Logging.StandardEnabled = false

	if err := validation.Validate(opts); err != nil {
		t.Fatalf("failed to validate options: %v", err)
	}

	proxy, err := oauth2proxy.NewOAuthProxy(opts, oauth2proxy.NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile))
	if err != nil {
		t.Fatalf("failed to create oauth2 proxy: %v", err)
	}

	return proxy
}

func TestOAuthCallback(t *testing.T) {
	handler := oauthCallback(newTestOAuthProxy(t))

	tests := []struct {
		name       string
		target     string
		wantStatus int
		wantBody   string
	}{
		{
			// What OneLogin sends for a user who has not been given access to the app (phase 0b, A8).
			name:       "access denied",
			target:     "/oauth2/callback?error=access_denied&error_description=End-user+does+not+have+access+to+this+application&state=abc",
			wantStatus: http.StatusForbidden,
			wantBody:   accessDeniedMessage,
		},
		{
			name:       "other error",
			target:     "/oauth2/callback?error=invalid_scope&error_description=some+of+requested+scopes+are+not+whitelisted&state=abc",
			wantStatus: http.StatusForbidden,
			wantBody:   "The upstream identity provider returned an error: invalid_scope",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, tt.target, nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if body := html.UnescapeString(rec.Body.String()); !strings.Contains(body, tt.wantBody) {
				t.Errorf("body does not contain %q:\n%s", tt.wantBody, body)
			}
		})
	}
}
