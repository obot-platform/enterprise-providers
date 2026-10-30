package profile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/keycloak-auth-provider/pkg/client"
)

// TestLiveKeycloakReadOnlyDirectory is opt-in and uses an operator-provisioned realm.
// It never creates, updates, disables, or deletes users/groups. It needs:
//
//	KEYCLOAK_LIVE_TEST=1
//	OBOT_KEYCLOAK_AUTH_PROVIDER_ISSUER_URL
//	OBOT_KEYCLOAK_AUTH_PROVIDER_SERVICE_CLIENT_ID
//	OBOT_KEYCLOAK_AUTH_PROVIDER_SERVICE_CLIENT_SECRET
//	KEYCLOAK_LIVE_MEMBER_ID
//	KEYCLOAK_LIVE_EXPECTED_GROUP_IDS_JSON (JSON array of full keycloak/<native-id> IDs;
//	  include both direct groups and all ancestors, at least three IDs)
//	KEYCLOAK_LIVE_EXPECTED_GROUP_COUNT (complete flat directory count, at least five)
//	KEYCLOAK_LIVE_DISABLED_USER_ID (an already disabled fixture account)
//
// KEYCLOAK_LIVE_OTHER_ISSUER_URL optionally checks cross-realm read denial.
// Credentials come only from the environment, never committed fixture files.
// Run without changing membership fixtures concurrently; native browse paging observes a changing directory.
func TestLiveKeycloakReadOnlyDirectory(t *testing.T) {
	if os.Getenv("KEYCLOAK_LIVE_TEST") != "1" {
		t.Skip("set KEYCLOAK_LIVE_TEST=1 and live fixture environment to run")
	}
	required := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("live fixture requires %s", name)
		}
		return value
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	issuer := required("OBOT_KEYCLOAK_AUTH_PROVIDER_ISSUER_URL")
	serviceID := required("OBOT_KEYCLOAK_AUTH_PROVIDER_SERVICE_CLIENT_ID")
	serviceSecret := required("OBOT_KEYCLOAK_AUTH_PROVIDER_SERVICE_CLIENT_SECRET")
	memberID := required("KEYCLOAK_LIVE_MEMBER_ID")
	disabledID := required("KEYCLOAK_LIVE_DISABLED_USER_ID")
	var expectedIDs []string
	if err := json.Unmarshal([]byte(required("KEYCLOAK_LIVE_EXPECTED_GROUP_IDS_JSON")), &expectedIDs); err != nil || len(expectedIDs) < 3 {
		t.Fatal("expected membership IDs must be a JSON array containing direct groups and ancestors (at least three)")
	}
	expected := map[string]bool{}
	for _, id := range expectedIDs {
		if !strings.HasPrefix(id, "keycloak/") || id == "keycloak/" || expected[id] {
			t.Fatal("expected membership IDs must be unique full keycloak/native IDs")
		}
		expected[id] = true
	}
	expectedCount, err := strconv.Atoi(required("KEYCLOAK_LIVE_EXPECTED_GROUP_COUNT"))
	if err != nil || expectedCount < 5 {
		t.Fatal("expected directory count must be at least five to exercise pagination")
	}
	endpoints, err := client.Discover(ctx, issuer, nil)
	if err != nil {
		t.Fatalf("live realm discovery failed: %v", err)
	}
	directory := client.New(endpoints, serviceID, serviceSecret, nil)

	t.Run("direct_and_ancestor_memberships_keep_native_ids", func(t *testing.T) {
		memberships, err := FetchUserGroupInfos(ctx, directory, memberID)
		if err != nil {
			t.Fatalf("live membership lookup failed: %v", err)
		}
		if len(memberships) != len(expected) {
			t.Fatalf("effective membership count: got %d want %d", len(memberships), len(expected))
		}
		seen := map[string]bool{}
		nativeIDs := []string{}
		for _, membership := range memberships {
			if !expected[membership.ID] || seen[membership.ID] {
				t.Fatal("effective membership IDs differ from the expected stable native IDs")
			}
			if !strings.HasPrefix(membership.Name, "/") {
				t.Fatal("membership label is not a full group path")
			}
			seen[membership.ID] = true
			nativeIDs = append(nativeIDs, strings.TrimPrefix(membership.ID, "keycloak/"))
		}
		// A fresh read and ID resolution must agree without relying on a hierarchy cache.
		resolved, err := FetchGroupsByIDs(ctx, directory, nativeIDs)
		if err != nil || len(resolved) != len(expected) {
			t.Fatalf("live membership ID resolution failed: %v", err)
		}
		for _, info := range resolved {
			if !expected[info.ID] {
				t.Fatal("group resolution changed a stable native group ID")
			}
		}
	})

	t.Run("flat_browse_pages_include_nested_groups", func(t *testing.T) {
		listed := map[string]bool{}
		cursors := map[string]bool{}
		cursor := ""
		pages := 0
		for {
			if cursors[cursor] || pages >= 1000 {
				t.Fatal("live directory pagination did not terminate")
			}
			cursors[cursor] = true
			result, err := FetchGroupPage(ctx, directory, authcommon.PageRequest{Limit: 4, Cursor: cursor})
			if err != nil {
				t.Fatalf("live browse failed: %v", err)
			}
			pages++
			for _, info := range result.Items {
				if !strings.HasPrefix(info.ID, "keycloak/") || listed[info.ID] {
					t.Fatal("browse returned duplicate or unstable native group IDs")
				}
				if !strings.HasPrefix(info.Name, "/") {
					t.Fatal("browse omitted a full group path")
				}
				listed[info.ID] = true
			}
			cursor = result.NextCursor
			if cursor == "" {
				break
			}
		}
		if pages < 2 || len(listed) != expectedCount {
			t.Fatalf("flat browse got %d groups across %d pages; want %d groups", len(listed), pages, expectedCount)
		}
		for id := range expected {
			if !listed[id] {
				t.Fatal("flat browse omitted a member group or ancestor")
			}
		}
	})

	t.Run("missing_and_disabled_users_are_denied", func(t *testing.T) {
		for _, id := range []string{"obot-keycloak-live-test-missing-id", disabledID} {
			memberships, err := FetchUserGroupInfos(ctx, directory, id)
			var unavailable *UserUnavailableError
			if !errors.As(err, &unavailable) || memberships != nil {
				t.Fatal("unavailable user did not produce the typed denial mapped to HTTP 403")
			}
		}
	})

	t.Run("confirmed_missing_group_is_omitted", func(t *testing.T) {
		id := strings.TrimPrefix(expectedIDs[0], "keycloak/")
		resolved, err := FetchGroupsByIDs(ctx, directory, []string{id, "obot-keycloak-live-test-missing-id"})
		if err != nil || len(resolved) != 1 || resolved[0].ID != expectedIDs[0] {
			t.Fatalf("live group lookup did not omit only the confirmed missing ID: %v", err)
		}
	})

	t.Run("service_account_has_only_expected_read_roles", func(t *testing.T) {
		// Inspect the trusted token endpoint's returned claims as a qualification check,
		// not as token authentication. Exercise read permissions above; never probe writes.
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {serviceID}, "client_secret": {serviceSecret}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints.TokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal("cannot create service token request")
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		transport := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := transport.Do(req)
		if err != nil {
			t.Fatal("service token request failed")
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("service token returned HTTP %d", response.StatusCode)
		}
		var token struct {
			AccessToken string `json:"access_token"`
		}
		if err := client.Decode(response.Body, &token); err != nil {
			t.Fatal("invalid service token response")
		}
		parts := strings.Split(token.AccessToken, ".")
		if len(parts) != 3 {
			t.Fatal("service token is not a JWT")
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal("cannot decode service token claims")
		}
		var claims struct {
			ResourceAccess map[string]struct {
				Roles []string `json:"roles"`
			} `json:"resource_access"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal("invalid service token claims")
		}
		allowed := map[string]bool{"view-users": true, "query-users": true, "query-groups": true}
		viewUsers := false
		for _, role := range claims.ResourceAccess["realm-management"].Roles {
			if !allowed[role] {
				t.Fatal("directory service account has an unexpected administrative role")
			}
			viewUsers = viewUsers || role == "view-users"
		}
		if !viewUsers {
			t.Fatal("directory service account does not have view-users")
		}
	})

	t.Run("directory_credentials_cannot_read_another_realm", func(t *testing.T) {
		otherIssuer := os.Getenv("KEYCLOAK_LIVE_OTHER_ISSUER_URL")
		if otherIssuer == "" {
			t.Skip("set KEYCLOAK_LIVE_OTHER_ISSUER_URL for cross-realm permission check")
		}
		other, err := client.Discover(ctx, otherIssuer, nil)
		if err != nil {
			t.Fatalf("other realm discovery failed: %v", err)
		}
		if other.Issuer == endpoints.Issuer {
			t.Fatal("cross-realm check requires a different realm")
		}
		other.TokenURL = endpoints.TokenURL // Authenticate in the original realm, read the other realm.
		isolated := client.New(other, serviceID, serviceSecret, nil)
		response, err := isolated.Get(ctx, "/groups", url.Values{"search": {"*"}, "max": {"1"}})
		if err != nil {
			t.Fatal("cross-realm read failed before permission evaluation")
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("cross-realm directory read returned HTTP %d; want 403", response.StatusCode)
		}
	})
}
