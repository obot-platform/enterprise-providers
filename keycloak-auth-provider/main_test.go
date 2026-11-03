package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obot-platform/enterprise-providers/keycloak-auth-provider/pkg/client"
)

func TestMembershipHandlerUnavailableIs403NotUnsupported404(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					if _, err := w.Write([]byte(`{"access_token":"token","expires_in":300,"token_type":"Bearer"}`)); err != nil {
						t.Error(err)
					}
					return
				}
				if r.URL.Path == "/users/opaque-sub/groups" {
					if _, err := w.Write([]byte(`[]`)); err != nil {
						t.Error(err)
					}
					return
				}
				if r.URL.Path != "/users/opaque-sub" {
					t.Errorf("user path %q", r.URL.Path)
				}
				w.WriteHeader(status)
				if status == 200 {
					if err := json.NewEncoder(w).Encode(map[string]any{"id": "opaque-sub", "enabled": false}); err != nil {
						t.Error(err)
					}
				}
			}))
			defer upstream.Close()
			s := server{directory: client.New(client.Endpoints{TokenURL: upstream.URL + "/token", AdminURL: upstream.URL}, "id", "secret", upstream.Client())}
			response := httptest.NewRecorder()
			s.listUserGroups(response, httptest.NewRequest(http.MethodPost, "/obot-list-user-auth-groups", strings.NewReader("opaque-sub\n")))
			if response.Code != http.StatusForbidden {
				t.Fatalf("status %d body %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMembershipHandlerRejectsOversizedBody(t *testing.T) {
	s := server{}
	response := httptest.NewRecorder()
	s.listUserGroups(response, httptest.NewRequest(http.MethodPost, "/obot-list-user-auth-groups", strings.NewReader(strings.Repeat("a", 4097))))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status %d", response.Code)
	}
}

func TestLoggingConfiguration(t *testing.T) {
	for _, enabled := range []string{"", "false", "true", "TRUE"} {
		t.Run(enabled, func(t *testing.T) {
			opts := testOptions()
			opts.LoggingEnabled = enabled
			proxyOpts, err := buildOAuthProxyOptions(opts)
			if err != nil {
				t.Fatal(err)
			}
			expected := strings.EqualFold(enabled, "true")
			if proxyOpts.Logging.AuthEnabled != expected || proxyOpts.Logging.RequestEnabled != expected || proxyOpts.Logging.StandardEnabled != expected {
				t.Fatal("logging flag not applied consistently")
			}
		})
	}
}
