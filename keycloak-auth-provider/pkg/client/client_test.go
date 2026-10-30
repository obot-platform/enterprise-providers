package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestDiscoveryPreservesPrefixAndRejectsDifferentIssuer(t *testing.T) {
	var server *httptest.Server
	different := false
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/realms/staff/.well-known/openid-configuration" {
			t.Errorf("discovery path %q", r.URL.Path)
		}
		issuer := server.URL + "/auth/realms/staff"
		if different {
			issuer += "-other"
		}
		if err := json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "token_endpoint": server.URL + "/auth/realms/staff/protocol/openid-connect/token", "userinfo_endpoint": server.URL + "/auth/realms/staff/protocol/openid-connect/userinfo"}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	endpoints, err := Discover(context.Background(), "  "+server.URL+"/auth/realms/staff/ ", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if endpoints.AdminURL != server.URL+"/auth/admin/realms/staff" {
		t.Fatalf("admin URL %q", endpoints.AdminURL)
	}
	different = true
	if _, err := Discover(context.Background(), server.URL+"/auth/realms/staff", server.Client()); err == nil {
		t.Fatal("accepted discovery issuer mismatch")
	}
}

func TestCanonicalIssuer(t *testing.T) {
	for _, raw := range []string{"https://id.example/auth/realms/staff", "http://localhost:8080/realms/master", "http://127.42.0.1:8080/realms/staff", "http://[::1]:8080/realms/staff", "https://id.example/realms/Staff%20Realm"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := CanonicalIssuer(raw); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, raw := range []string{"https://user:secret@id.example/realms/a", "https://id.example/realms/a?x=y", "https://id.example/realms/a?", "http://id.example/realms/a", "http://0.0.0.0:8080/realms/a", "http://localhost.evil.example/realms/a", "https://id.example/realms/a#fragment", "https://id.example/realms/a/b", "https://id.example/realms/", "https://id.example/realms/a%2Fb", "https://id.example/auth/../realms/a", "https://id.example/realms/%2e%2e", "not a URL"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := CanonicalIssuer(raw); err == nil {
				t.Fatal("accepted unsafe issuer")
			}
		})
	}
}

func TestTokenCacheAndOne401Retry(t *testing.T) {
	var tokens, reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "directory" || r.Form.Get("client_secret") != "secret" || r.Form.Has("scope") {
				t.Errorf("unexpected service token form %v", r.Form)
			}
			number := tokens.Add(1)
			token := "old"
			if number > 1 {
				token = "new"
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"access_token": token, "expires_in": 300, "token_type": "Bearer"}); err != nil {
				t.Error(err)
			}
			return
		}
		reads.Add(1)
		if r.Header.Get("Authorization") == "Bearer old" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.EscapedPath() != "/admin/users/f:provider:u%2Fv" {
			t.Errorf("opaque user path %q", r.URL.EscapedPath())
		}
		if !r.URL.Query().Has("search") {
			t.Error("missing empty search")
		}
		if _, err := w.Write([]byte(`{}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	c := New(Endpoints{TokenURL: server.URL + "/token", AdminURL: server.URL + "/admin"}, "directory", "secret", server.Client())
	for range 2 {
		response, err := c.Get(context.Background(), "/users/"+url.PathEscape("f:provider:u/v"), url.Values{"search": {""}})
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("status %d", response.StatusCode)
		}
	}
	if tokens.Load() != 2 || reads.Load() != 3 {
		t.Fatalf("token requests %d reads %d", tokens.Load(), reads.Load())
	}
}

func TestPersistent401And403AreBounded(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var tokens, reads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					tokens.Add(1)
					if _, err := w.Write([]byte(`{"access_token":"token","expires_in":300,"token_type":"Bearer"}`)); err != nil {
						t.Error(err)
					}
					return
				}
				reads.Add(1)
				w.WriteHeader(status)
			}))
			defer server.Close()
			c := New(Endpoints{TokenURL: server.URL + "/token", AdminURL: server.URL}, "id", "secret", server.Client())
			response, err := c.Get(context.Background(), "/groups", nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			expected := int32(1)
			if status == 401 {
				expected = 2
			}
			if tokens.Load() != expected || reads.Load() != expected || response.StatusCode != status {
				t.Fatalf("tokens=%d reads=%d status=%d", tokens.Load(), reads.Load(), response.StatusCode)
			}
		})
	}
}

func TestConcurrentReadsShareToken(t *testing.T) {
	var tokens atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokens.Add(1)
			if _, err := w.Write([]byte(`{"access_token":"token","expires_in":300,"token_type":"Bearer"}`)); err != nil {
				t.Error(err)
			}
			return
		}
		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	c := New(Endpoints{TokenURL: server.URL + "/token", AdminURL: server.URL}, "id", "secret", server.Client())
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			response, err := c.Get(context.Background(), "/groups", nil)
			if err != nil {
				t.Error(err)
				return
			}
			_ = response.Body.Close()
		})
	}
	wg.Wait()
	if tokens.Load() != 1 {
		t.Fatalf("tokens %d", tokens.Load())
	}
}

func TestTokenSecretsDoNotFollowRedirectOrAppearInErrors(t *testing.T) {
	var reached atomic.Bool
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer sink.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c := New(Endpoints{TokenURL: source.URL, AdminURL: source.URL}, "id", "supersecret", source.Client())
	_, err := c.Get(context.Background(), "/groups", nil)
	if err == nil || strings.Contains(err.Error(), "supersecret") || reached.Load() {
		t.Fatalf("redirect or secret leak: %v, reached=%v", err, reached.Load())
	}
}

func TestDiscoveryRejectsUntrustedTLS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { t.Error("untrusted TLS reached HTTP handler") }))
	defer upstream.Close()
	if _, err := Discover(t.Context(), upstream.URL+"/realms/test", nil); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestWithAdminBaseURL(t *testing.T) {
	endpoints := Endpoints{
		Issuer:   "https://id.example/auth/realms/staff",
		AdminURL: "https://id.example/auth/admin/realms/staff",
	}
	for _, tc := range []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "separate host",
			raw:      "https://keycloak-admin.internal",
			expected: "https://keycloak-admin.internal/admin/realms/staff",
		},
		{
			name:     "deployment prefix and trailing slash",
			raw:      " https://keycloak-admin.internal:8443/auth/ ",
			expected: "https://keycloak-admin.internal:8443/auth/admin/realms/staff",
		},
		{
			name:     "loopback HTTP",
			raw:      "http://127.0.0.1:8080",
			expected: "http://127.0.0.1:8080/admin/realms/staff",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WithAdminBaseURL(endpoints, tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.AdminURL != tc.expected || got.Issuer != endpoints.Issuer {
				t.Fatalf("admin URL %q, issuer %q", got.AdminURL, got.Issuer)
			}
		})
	}
	for _, raw := range []string{"http://keycloak.internal:8080", "https://user:secret@keycloak.internal", "https://keycloak.internal?x=y", "https://keycloak.internal/admin", "https://keycloak.internal/realms/staff", "https://keycloak.internal/auth/../x", "https://keycloak.internal/a%2Fb", "not a URL"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := WithAdminBaseURL(endpoints, raw); err == nil {
				t.Fatal("accepted unsafe admin URL")
			}
		})
	}
}
