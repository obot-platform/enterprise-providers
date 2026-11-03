package profile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/obot-platform/enterprise-providers/keycloak-auth-provider/pkg/client"
)

func TestCheckDirectoryAccess(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tokenStatus int
		usersStatus int
		groupStatus int
		wantErr     string
		wantPaths   []string
	}{
		{
			name:        "both reads succeed",
			tokenStatus: http.StatusOK,
			usersStatus: http.StatusOK,
			groupStatus: http.StatusOK,
			wantPaths:   []string{"/users", "/groups"},
		},
		{
			name:        "wrong secret",
			tokenStatus: http.StatusUnauthorized,
			wantErr:     "credentials (HTTP 401); check the Directory Service Client ID and Secret",
		},
		{
			name:        "service accounts disabled",
			tokenStatus: http.StatusBadRequest,
			wantErr:     "credentials (HTTP 400)",
		},
		{
			name:        "missing view-users for users",
			tokenStatus: http.StatusOK,
			usersStatus: http.StatusForbidden,
			wantErr:     "lacks the realm-management view-users role",
			wantPaths:   []string{"/users"},
		},
		{
			name:        "missing view-users for groups",
			tokenStatus: http.StatusOK,
			usersStatus: http.StatusOK,
			groupStatus: http.StatusForbidden,
			wantErr:     "lacks the realm-management view-users role",
			wantPaths:   []string{"/users", "/groups"},
		},
		{
			name:        "wrong admin URL",
			tokenStatus: http.StatusOK,
			usersStatus: http.StatusNotFound,
			wantErr:     "no Admin API at ",
			wantPaths:   []string{"/users"},
		},
		{
			name:        "unexpected status",
			tokenStatus: http.StatusOK,
			usersStatus: http.StatusInternalServerError,
			wantErr:     "directory read /users returned HTTP 500",
			wantPaths:   []string{"/users"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu    sync.Mutex
				paths []string
			)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					if tc.tokenStatus != http.StatusOK {
						w.WriteHeader(tc.tokenStatus)
						return
					}
					_, _ = w.Write([]byte(`{"access_token":"directory-token","expires_in":300,"token_type":"Bearer"}`))
					return
				}
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				if r.Header.Get("Authorization") != "Bearer directory-token" {
					t.Error("missing directory token")
				}
				if query := r.URL.Query(); query.Get("max") != "1" || query.Get("briefRepresentation") != "true" {
					t.Errorf("unbounded directory read %q", r.URL.RawQuery)
				}
				status := tc.usersStatus
				if r.URL.Path == "/groups" {
					status = tc.groupStatus
				}
				w.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = w.Write([]byte(`[]`))
				}
			}))
			t.Cleanup(server.Close)

			directory := client.New(client.Endpoints{TokenURL: server.URL + "/token", AdminURL: server.URL}, "directory", "secret", server.Client())
			err := CheckDirectoryAccess(context.Background(), directory)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v, want it to contain %q", err, tc.wantErr)
			}
			if strings.Contains(tc.wantErr, "Admin API") && !strings.Contains(err.Error(), server.URL) {
				t.Fatalf("error %v does not name the admin URL", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if strings.Join(paths, ",") != strings.Join(tc.wantPaths, ",") {
				t.Fatalf("directory reads %v, want %v", paths, tc.wantPaths)
			}
		})
	}
}

func TestCheckDirectoryAccessReportsUnreachableDirectory(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	directory := client.New(client.Endpoints{TokenURL: url + "/token", AdminURL: url}, "directory", "secret", nil)
	if err := CheckDirectoryAccess(context.Background(), directory); err == nil {
		t.Fatal("expected an error for an unreachable directory")
	}
}
