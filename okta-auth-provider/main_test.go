package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/okta/okta-sdk-golang/v5/okta"
)

func TestServiceCredentialsConfigured(t *testing.T) {
	tests := []struct {
		name       string
		clientID   string
		privateKey string
		want       bool
		wantErr    bool
	}{
		{
			name:       "both present",
			clientID:   "0oa1service",
			privateKey: "-----BEGIN RSA PRIVATE KEY-----\\nMIIE\\n-----END RSA PRIVATE KEY-----",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "both absent",
			clientID:   "",
			privateKey: "",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "only client ID",
			clientID:   "0oa1service",
			privateKey: "",
			want:       false,
			wantErr:    true,
		},
		{
			name:       "only private key",
			clientID:   "",
			privateKey: "-----BEGIN RSA PRIVATE KEY-----\\nMIIE\\n-----END RSA PRIVATE KEY-----",
			want:       false,
			wantErr:    true,
		},
		{
			name:       "both whitespace-only",
			clientID:   "  ",
			privateKey: "\n\t ",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "client ID with a whitespace-only private key",
			clientID:   "0oa1service",
			privateKey: " \n",
			want:       false,
			wantErr:    true,
		},
		{
			name:       "private key with a whitespace-only client ID",
			clientID:   "\t",
			privateKey: "-----BEGIN RSA PRIVATE KEY-----\\nMIIE\\n-----END RSA PRIVATE KEY-----",
			want:       false,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serviceCredentialsConfigured(tt.clientID, tt.privateKey)
			if (err != nil) != tt.wantErr {
				t.Fatalf("serviceCredentialsConfigured() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("serviceCredentialsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegisterDirectoryRoutesWithoutServiceClient(t *testing.T) {
	mux := http.NewServeMux()
	registerDirectoryRoutes(mux, nil)
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
			target: "/obot-get-auth-groups?ids=okta/00g1",
			body:   "",
		},
		{
			// GetGroupsHandler answers IDs of other providers without calling fetch, so this also checks that the
			// 503 comes before any of the handler's own work.
			name:   "get groups with no Okta IDs",
			method: http.MethodGet,
			target: "/obot-get-auth-groups?ids=entra/00g1",
			body:   "",
		},
		{
			name:   "list user groups",
			method: http.MethodPost,
			target: "/obot-list-user-auth-groups",
			body:   "00u1",
		},
		{
			name:   "group migration mapping",
			method: http.MethodGet,
			target: "/obot-get-group-migration-mapping",
			body:   "",
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

func TestRequireServiceClient(t *testing.T) {
	tests := []struct {
		name           string
		serviceClient  *okta.APIClient
		wantStatus     int
		wantNextCalled bool
	}{
		{
			name:           "without a service client",
			serviceClient:  nil,
			wantStatus:     http.StatusServiceUnavailable,
			wantNextCalled: false,
		},
		{
			name:           "with a service client",
			serviceClient:  new(okta.APIClient),
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nextCalled bool
			handler := (&server{
				serviceClient: tt.serviceClient,
			}).requireServiceClient(func(http.ResponseWriter, *http.Request) {
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
