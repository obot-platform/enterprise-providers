package main

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/internal/onelogintest"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/client"
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
			name:      "override with an empty query",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "https://api.us.onelogin.com/?",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "override with an empty fragment",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "https://api.us.onelogin.com#",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "override with a path",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "https://api.us.onelogin.com/api/2",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "issuer without a scheme",
			issuerURL: "example.onelogin.com/oidc/2",
			override:  "",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "issuer over http",
			issuerURL: "http://example.onelogin.com/oidc/2",
			override:  "",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "issuer over http on a loopback host",
			issuerURL: "http://127.0.0.1:8080/oidc/2",
			override:  "",
			want:      "http://127.0.0.1:8080",
			wantErr:   false,
		},
		{
			name:      "override over http",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "http://api.us.onelogin.com",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "override over http on localhost",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "http://localhost:8080",
			want:      "http://localhost:8080",
			wantErr:   false,
		},
		{
			name:      "override over http on an IPv4 loopback address",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "http://127.0.0.1:8080/",
			want:      "http://127.0.0.1:8080",
			wantErr:   false,
		},
		{
			name:      "override over http on the IPv6 loopback address",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "http://[::1]:8080",
			want:      "http://[::1]:8080",
			wantErr:   false,
		},
		{
			name:      "override over http on a host that only starts with localhost",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "http://localhost.example.com",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "override with another scheme",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "ftp://api.us.onelogin.com",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "override without a scheme",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "api.us.onelogin.com",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "override without a host",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "https:///api",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "override with a query",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "https://api.us.onelogin.com/?region=us",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "override with user info",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "https://user:pass@api.us.onelogin.com",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "unparseable override",
			issuerURL: "https://example.onelogin.com/oidc/2",
			override:  "https://api.us.onelogin.com:port",
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
			body:   "300000001",
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
		name    string
		method  string
		target  string
		body    string
		wantIDs []string
	}{
		{
			name:    "list groups",
			method:  http.MethodGet,
			target:  "/obot-list-auth-groups?name=OBOT&limit=10",
			body:    "",
			wantIDs: []string{"onelogin/1100002", "onelogin/1100003"},
		},
		{
			name:    "get groups",
			method:  http.MethodGet,
			target:  "/obot-get-auth-groups?ids=onelogin/1100004,onelogin/1100099,onelogin/abc,okta/00g1",
			body:    "",
			wantIDs: []string{"onelogin/1100004"},
		},
		{
			name:    "list user groups",
			method:  http.MethodPost,
			target:  "/obot-list-user-auth-groups",
			body:    "300000001\n",
			wantIDs: []string{"onelogin/1100002", "onelogin/1100004"},
		},
		{
			name:    "list user groups of a user without roles",
			method:  http.MethodPost,
			target:  "/obot-list-user-auth-groups",
			body:    "300000002",
			wantIDs: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mux := newTestDirectoryServer(t)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body)))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d, body %q", rec.Code, http.StatusOK, rec.Body.String())
			}
			if got := responseGroupIDs(t, tt.target, rec.Body.Bytes()); !slices.Equal(got, tt.wantIDs) {
				t.Errorf("ids = %v, want %v", got, tt.wantIDs)
			}
		})
	}
}

func TestDirectoryRoutesErrors(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "list groups with a cursor from another provider",
			method:     http.MethodGet,
			target:     "/obot-list-auth-groups?limit=10&cursor=eyJ2IjoxLCJwIjoib2t0YSIsImwiOjEwLCJ0IjowLCJuIjoieCJ9",
			body:       "",
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid cursor",
		},
		{
			name:       "list user groups of a suspended user",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       "300000003",
			wantStatus: http.StatusForbidden,
			wantBody:   "OneLogin account is not active (status 2: suspended)",
		},
		{
			name:       "list user groups of a deleted user",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       "300000099",
			wantStatus: http.StatusForbidden,
			wantBody:   "OneLogin user was not found",
		},
		{
			name:       "list user groups of an invalid user ID",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       "00u1abcd",
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid OneLogin user ID",
		},
		{
			name:       "list user groups without a user ID",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       " ",
			wantStatus: http.StatusBadRequest,
			wantBody:   "user ID is required",
		},
		{
			name:       "list user groups with an oversized body",
			method:     http.MethodPost,
			target:     "/obot-list-user-auth-groups",
			body:       strings.Repeat("1", maxUserIDBodyBytes+1),
			wantStatus: http.StatusRequestEntityTooLarge,
			wantBody:   "request body too large",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake, mux := newTestDirectoryServer(t)
			calls := len(fake.Requests())

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body)))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body %q", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBody)
			}
			if tt.wantStatus == http.StatusBadRequest || tt.wantStatus == http.StatusRequestEntityTooLarge {
				if got := len(fake.Requests()); got != calls {
					t.Errorf("calls to OneLogin for a bad request = %d, want 0", got-calls)
				}
			}
		})
	}
}

// responseGroupIDs returns the group IDs in the body of a directory endpoint's response. A null list fails the test,
// because Obot expects an empty list rather than null.
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
	if groups == nil {
		t.Fatalf("body %q has null where a list of groups belongs", body)
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
	fake.RateLimit("30")

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
	fake.StopRateLimiting()
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

// newTestUserInfoServer returns a server whose GET /obot-get-user-info calls a stand-in for OneLogin's userinfo
// endpoint, <issuer>/me. The endpoint accepts only the token "good-token", and answers "huge-token" with a body over
// the size cap.
func newTestUserInfoServer(t *testing.T) *server {
	t.Helper()

	oneLogin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oidc/2/me" {
			http.NotFound(w, r)
			return
		}
		switch r.Header.Get("Authorization") {
		case "Bearer good-token":
			// The claims OneLogin's userinfo endpoint returns for the openid, email and profile scopes. sub is the
			// numeric OneLogin user ID.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"email":"user@example.com","family_name":"User","given_name":"Test","name":"Test User","preferred_username":"test_user","sub":"300000001","updated_at":1792006400}`))
		case "Bearer huge-token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"300000001","name":"` + strings.Repeat("x", 1<<20) + `"}`))
		default:
			http.Error(w, `{"error":"invalid_token"}`+strings.Repeat(" ", 1<<20), http.StatusUnauthorized)
		}
	}))
	t.Cleanup(oneLogin.Close)

	return &server{
		issuerURL:  oneLogin.URL + "/oidc/2",
		httpClient: client.NewHTTPClient(),
	}
}

func TestGetUserInfo(t *testing.T) {
	srv := newTestUserInfoServer(t)

	req := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
	req.Header.Set("Authorization", "Bearer good-token")

	rec := httptest.NewRecorder()
	srv.getUserInfo(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body %q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "icon_url") {
		t.Errorf("body = %q, want no icon_url", rec.Body.String())
	}

	var got profile.UserInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode body %q: %v", rec.Body.String(), err)
	}
	want := profile.UserInfo{
		ID:      "300000001",
		Name:    "Test User",
		IconURL: "",
	}
	if got != want {
		t.Errorf("user = %+v, want %+v", got, want)
	}
}

func TestGetUserInfoErrors(t *testing.T) {
	srv := newTestUserInfoServer(t)

	tests := []struct {
		name          string
		authorization string
		wantStatus    int
	}{
		{
			name:          "no token",
			authorization: "",
			wantStatus:    http.StatusUnauthorized,
		},
		{
			name:          "token OneLogin rejects",
			authorization: "Bearer bad-token",
			wantStatus:    http.StatusInternalServerError,
		},
		{
			name:          "oversized response",
			authorization: "Bearer huge-token",
			wantStatus:    http.StatusInternalServerError,
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
			// OneLogin's error body is cut short before it reaches the response.
			if got := rec.Body.Len(); got > 2*client.MaxErrorBodyBytes {
				t.Errorf("body length = %d, want at most %d", got, 2*client.MaxErrorBodyBytes)
			}
		})
	}
}

// newTestOAuthProxyOptions returns the options main gives oauth2-proxy, against a stand-in OIDC issuer that serves
// only discovery.
func newTestOAuthProxyOptions(t *testing.T) *options.Options {
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

	opts, err := newOAuthProxyOptions(Options{
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		IssuerURL:        issuerURL,
		ObotServerURL:    "http://localhost:8080",
		AuthEmailDomains: "*",
	}, time.Hour, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("newOAuthProxyOptions() error = %v", err)
	}

	return opts
}

func TestNewOAuthProxyOptions(t *testing.T) {
	opts := newTestOAuthProxyOptions(t)

	if len(opts.Providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(opts.Providers))
	}
	provider := opts.Providers[0]
	if provider.Type != options.OIDCProvider {
		t.Errorf("provider type = %q, want %q", provider.Type, options.OIDCProvider)
	}
	// OneLogin fails the sign-in with invalid_scope when offline_access is requested.
	if provider.Scope != "openid email profile" {
		t.Errorf("scope = %q, want %q", provider.Scope, "openid email profile")
	}
	if opts.Cookie.Secure {
		t.Error("cookie is Secure for an http Obot URL, want not")
	}
}

// newTestOAuthProxy returns an oauth2-proxy with the options main gives it, against a stand-in OIDC issuer.
func newTestOAuthProxy(t *testing.T) *oauth2proxy.OAuthProxy {
	t.Helper()

	opts := newTestOAuthProxyOptions(t)
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
			// What OneLogin sends at the callback for a user who has not been given access to the app.
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
