package profile

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obot-platform/enterprise-providers/okta-auth-provider/pkg/client"
	"github.com/okta/okta-sdk-golang/v6/okta"
)

func TestGroupName(t *testing.T) {
	name := "Engineering"
	for _, tt := range []struct {
		name    string
		profile *okta.GroupProfile
		want    string
	}{
		{name: "missing profile"},
		{name: "empty profile", profile: &okta.GroupProfile{}},
		{name: "Okta", profile: &okta.GroupProfile{OktaUserGroupProfile: &okta.OktaUserGroupProfile{Name: &name}}, want: name},
		{name: "Active Directory", profile: &okta.GroupProfile{OktaActiveDirectoryGroupProfile: &okta.OktaActiveDirectoryGroupProfile{Name: &name}}, want: name},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := groupName(tt.profile); got != tt.want {
				t.Errorf("groupName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrivateKeyAuthAndGroupPagination(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tokenRequests, groupRequests := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/v1/token":
			tokenRequests++
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Verify that the SDK still signs client assertions with the configured RSA key.
			parts := strings.Split(r.Form.Get("client_assertion"), ".")
			if len(parts) != 3 {
				t.Error("missing signed client assertion")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`)
		case "/api/v1/groups", "/api/v1/users/user-1/groups":
			groupRequests++
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Errorf("Authorization = %q", got)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.URL.Query().Get("after") == "second" {
				fmt.Fprint(w, `[{"id":"group-2","profile":{"name":"Sales"}}]`)
				return
			}
			w.Header().Set("Link", fmt.Sprintf(`<http://%s/api/v1/groups?after=second>; rel="next"`, r.Host))
			fmt.Fprint(w, `[{"id":"group-1","profile":{"name":"Engineering"}}]`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := client.NewServiceClient("service-client", string(privateKey), server.URL, []string{"okta.groups.read"})
	if err != nil {
		t.Fatal(err)
	}
	// The SDK derives Host with URL.Hostname(), which drops the test server's port.
	service.GetConfig().Host = server.Listener.Addr().String()
	mappings, err := BuildGroupMigrationMapping(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]string)
	for _, mapping := range mappings {
		got[mapping.OldID] = mapping.NewID
	}
	if len(got) != 2 || got["okta/Engineering"] != "okta/group-1" || got["okta/Sales"] != "okta/group-2" {
		t.Errorf("unexpected group mappings: %v", got)
	}
	groups, err := FetchUserGroupInfos(context.Background(), service, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].ID != "okta/group-1" || groups[1].ID != "okta/group-2" {
		t.Errorf("unexpected user groups: %v", groups)
	}
	if tokenRequests != 1 || groupRequests != 4 {
		t.Errorf("requests: token = %d, groups = %d; want 1, 4", tokenRequests, groupRequests)
	}
}
