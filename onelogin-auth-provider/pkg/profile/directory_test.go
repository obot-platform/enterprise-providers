package profile

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/client"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/onelogintest"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

const (
	roleDefault     int64 = 1100001
	roleEngineering int64 = 1100002
	roleOperations  int64 = 1100003
	roleSecurity    int64 = 1100004
	roleDeleted     int64 = 1100099

	userActive    int64 = 300000001
	userNoRoles   int64 = 300000002
	userSuspended int64 = 300000003
	userLocked    int64 = 300000004
	userStale     int64 = 300000005
	userMissing   int64 = 300000099
)

var testRoles = []onelogintest.Role{
	{
		ID:   roleDefault,
		Name: "Default",
	},
	{
		ID:   roleEngineering,
		Name: "obot-engineering",
	},
	{
		ID:   roleOperations,
		Name: "obot-operations",
	},
	{
		ID:   roleSecurity,
		Name: "Security",
	},
}

var testUsers = []onelogintest.User{
	{
		ID:      userActive,
		RoleIDs: []int64{roleEngineering, roleSecurity},
		Status:  1,
	},
	{
		ID:      userNoRoles,
		RoleIDs: nil,
		Status:  1,
	},
	{
		ID:      userSuspended,
		RoleIDs: []int64{roleEngineering},
		Status:  2,
	},
	{
		ID:      userLocked,
		RoleIDs: []int64{roleEngineering},
		Status:  3,
	},
	{
		// Holds a role that has since been deleted.
		ID:      userStale,
		RoleIDs: []int64{roleOperations, roleDeleted},
		Status:  1,
	},
}

func newTestDirectory(t *testing.T) (*onelogintest.Server, *client.Client, *RoleCache) {
	t.Helper()

	fake := onelogintest.New(t, testRoles, testUsers)
	apiClient := client.New(fake.URL, onelogintest.ClientID, onelogintest.ClientSecret)

	return fake, apiClient, NewRoleCache(apiClient)
}

func groupIDs(groups state.GroupInfoList) []string {
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	return ids
}

func TestParseID(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   int64
		wantOK bool
	}{
		{
			name:   "role ID",
			input:  "1100002",
			want:   1100002,
			wantOK: true,
		},
		{
			name:   "empty",
			input:  "",
			want:   0,
			wantOK: false,
		},
		{
			name:   "zero",
			input:  "0",
			want:   0,
			wantOK: false,
		},
		{
			name:   "leading zero",
			input:  "01100002",
			want:   0,
			wantOK: false,
		},
		{
			name:   "sign",
			input:  "+1100002",
			want:   0,
			wantOK: false,
		},
		{
			name:   "negative",
			input:  "-1",
			want:   0,
			wantOK: false,
		},
		{
			name:   "path traversal",
			input:  "../users/1",
			want:   0,
			wantOK: false,
		},
		{
			name:   "Okta group ID",
			input:  "00g1abcd",
			want:   0,
			wantOK: false,
		},
		{
			name:   "too long",
			input:  "1234567890123456789",
			want:   0,
			wantOK: false,
		},
		{
			name:   "non-ASCII digit",
			input:  "١٢٣",
			want:   0,
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseID(tt.input)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("parseID(%q) = %d, %v, want %d, %v", tt.input, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestRoleCacheRefresh(t *testing.T) {
	fake, _, roles := newTestDirectory(t)
	ctx := t.Context()

	if err := roles.Refresh(ctx); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := fake.RequestCount("/api/2/roles"); got != 1 {
		t.Errorf("list calls = %d, want 1", got)
	}

	name, found, err := roles.Name(ctx, roleEngineering)
	if err != nil || !found || name != "obot-engineering" {
		t.Errorf("Name() = %q, %v, %v, want obot-engineering, true, nil", name, found, err)
	}
	if got := fake.RequestCount("/api/2/roles/1100002"); got != 0 {
		t.Errorf("role calls after a cache hit = %d, want 0", got)
	}

	// A rename and a delete show after the next refresh.
	fake.SetRoles([]onelogintest.Role{
		{
			ID:   roleEngineering,
			Name: "obot-platform-engineering",
		},
	})
	if err := roles.Refresh(ctx); err != nil {
		t.Fatalf("second Refresh() error = %v", err)
	}

	if name, _, _ := roles.Name(ctx, roleEngineering); name != "obot-platform-engineering" {
		t.Errorf("Name() after a rename = %q, want obot-platform-engineering", name)
	}
	if _, found, err := roles.Name(ctx, roleSecurity); found || err != nil {
		t.Errorf("Name() of a deleted role = %v, %v, want false, nil", found, err)
	}
}

func TestRoleCacheRefreshFailureKeepsNames(t *testing.T) {
	fake, _, roles := newTestDirectory(t)
	ctx := t.Context()

	if err := roles.Refresh(ctx); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	fake.SetRateLimited(true, "60")
	var rateLimitErr *client.RateLimitedError
	if err := roles.Refresh(ctx); !errors.As(err, &rateLimitErr) {
		t.Fatalf("Refresh() while rate limited error = %v, want a RateLimitedError", err)
	}

	// The cache still answers, without calling OneLogin.
	name, found, err := roles.Name(ctx, roleSecurity)
	if err != nil || !found || name != "Security" {
		t.Errorf("Name() = %q, %v, %v, want Security, true, nil", name, found, err)
	}

	// A miss needs OneLogin, so it fails fast.
	if _, _, err := roles.Name(ctx, roleDeleted); !errors.As(err, &rateLimitErr) {
		t.Errorf("Name() of a miss while rate limited error = %v, want a RateLimitedError", err)
	}
}

func TestRoleCacheMiss(t *testing.T) {
	fake, _, roles := newTestDirectory(t)
	ctx := t.Context()

	// The cache has never been filled, so the first lookup calls OneLogin and the second does not.
	for range 2 {
		name, found, err := roles.Name(ctx, roleOperations)
		if err != nil || !found || name != "obot-operations" {
			t.Fatalf("Name() = %q, %v, %v, want obot-operations, true, nil", name, found, err)
		}
	}
	if got := fake.RequestCount("/api/2/roles/1100003"); got != 1 {
		t.Errorf("role calls = %d, want 1", got)
	}

	// A deleted role is not found, and that is not cached.
	for range 2 {
		if _, found, err := roles.Name(ctx, roleDeleted); found || err != nil {
			t.Fatalf("Name() of a deleted role = %v, %v, want false, nil", found, err)
		}
	}
	if got := fake.RequestCount("/api/2/roles/1100099"); got != 2 {
		t.Errorf("calls for a deleted role = %d, want 2", got)
	}
}

func TestRoleCacheMissCoalesced(t *testing.T) {
	var (
		calls   atomic.Int32
		started = make(chan struct{})
		release = make(chan struct{})
		once    sync.Once
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/oauth2/v2/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":36000}`))
			return
		}

		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		_, _ = w.Write([]byte(`{"id":1100002,"name":"obot-engineering"}`))
	}))
	defer srv.Close()

	roles := NewRoleCache(client.New(srv.URL, "id", "secret"))

	const callers = 10
	var (
		wg    sync.WaitGroup
		names = make([]string, callers)
	)
	wg.Go(func() {
		names[0], _, _ = roles.Name(t.Context(), roleEngineering)
	})
	<-started
	for i := 1; i < callers; i++ {
		wg.Go(func() {
			names[i], _, _ = roles.Name(t.Context(), roleEngineering)
		})
	}
	// Give the other callers time to join the call in flight.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("role calls = %d, want 1", got)
	}
	for i, name := range names {
		if name != "obot-engineering" {
			t.Errorf("caller %d got %q, want obot-engineering", i, name)
		}
	}
}

func TestRoleCacheRun(t *testing.T) {
	fake, _, roles := newTestDirectory(t)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		roles.Run(ctx, 10*time.Millisecond)
	}()

	// Run fills the cache at once, then refreshes it on every tick.
	deadline := time.Now().Add(5 * time.Second)
	for fake.RequestCount("/api/2/roles") < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("list calls = %d after 5s, want at least 3", fake.RequestCount("/api/2/roles"))
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was canceled")
	}

	if name, found, _ := roles.Name(t.Context(), roleSecurity); !found || name != "Security" {
		t.Errorf("Name() = %q, %v, want Security, true", name, found)
	}
}

func TestFetchGroupPage(t *testing.T) {
	tests := []struct {
		name           string
		req            authcommon.PageRequest
		wantQuery      string
		wantIDs        []string
		wantNextCursor bool
	}{
		{
			name: "first page",
			req: authcommon.PageRequest{
				NameFilter: "",
				Limit:      2,
				Cursor:     "",
			},
			wantQuery:      "limit=2",
			wantIDs:        []string{"onelogin/1100001", "onelogin/1100002"},
			wantNextCursor: true,
		},
		{
			name: "last page",
			req: authcommon.PageRequest{
				NameFilter: "",
				Limit:      10,
				Cursor:     "",
			},
			wantQuery:      "limit=10",
			wantIDs:        []string{"onelogin/1100001", "onelogin/1100002", "onelogin/1100003", "onelogin/1100004"},
			wantNextCursor: false,
		},
		{
			// OneLogin matches name as a case-insensitive substring, so it is sent as is.
			name: "name filter",
			req: authcommon.PageRequest{
				NameFilter: "OBOT-",
				Limit:      10,
				Cursor:     "",
			},
			wantQuery:      "limit=10&name=OBOT-",
			wantIDs:        []string{"onelogin/1100002", "onelogin/1100003"},
			wantNextCursor: false,
		},
		{
			// OneLogin matches * literally, so no role matches.
			name: "a star is not a wildcard",
			req: authcommon.PageRequest{
				NameFilter: "obot*",
				Limit:      10,
				Cursor:     "",
			},
			wantQuery:      "limit=10&name=obot%2A",
			wantIDs:        []string{},
			wantNextCursor: false,
		},
		{
			name: "limit above the maximum",
			req: authcommon.PageRequest{
				NameFilter: "",
				Limit:      500,
				Cursor:     "",
			},
			wantQuery:      "limit=100",
			wantIDs:        []string{"onelogin/1100001", "onelogin/1100002", "onelogin/1100003", "onelogin/1100004"},
			wantNextCursor: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake, apiClient, _ := newTestDirectory(t)

			got, err := FetchGroupPage(t.Context(), apiClient, tt.req)
			if err != nil {
				t.Fatalf("FetchGroupPage() error = %v", err)
			}

			if ids := groupIDs(got.Items); !slices.Equal(ids, tt.wantIDs) {
				t.Errorf("ids = %v, want %v", ids, tt.wantIDs)
			}
			if (got.NextCursor != "") != tt.wantNextCursor {
				t.Errorf("NextCursor = %q, want one: %v", got.NextCursor, tt.wantNextCursor)
			}
			if requests := fake.Requests(); len(requests) != 1 || requests[0].RawQuery != tt.wantQuery {
				t.Errorf("requests = %v, want one with query %q", requests, tt.wantQuery)
			}
		})
	}
}

func TestFetchGroupPageCursor(t *testing.T) {
	fake, apiClient, _ := newTestDirectory(t)
	ctx := t.Context()

	var (
		req = authcommon.PageRequest{
			NameFilter: "OBOT",
			Limit:      1,
		}
		ids []string
	)
	for range 10 {
		page, err := FetchGroupPage(ctx, apiClient, req)
		if err != nil {
			t.Fatalf("FetchGroupPage() error = %v", err)
		}
		ids = append(ids, groupIDs(page.Items)...)
		if page.NextCursor == "" {
			break
		}
		req.Cursor = page.NextCursor
	}

	// The cursor carries the filter, so the second page holds the second match rather than the second role.
	if want := []string{"onelogin/1100002", "onelogin/1100003"}; !slices.Equal(ids, want) {
		t.Errorf("ids = %v, want %v", ids, want)
	}

	requests := fake.Requests()
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests))
	}
	for _, u := range requests[1:] {
		if query := u.Query(); len(query) != 1 || query.Get("cursor") == "" {
			t.Errorf("cursor request query = %q, want only a cursor", u.RawQuery)
		}
	}
}

func TestFetchGroupPageRejectedCursor(t *testing.T) {
	_, apiClient, _ := newTestDirectory(t)

	_, err := FetchGroupPage(t.Context(), apiClient, authcommon.PageRequest{
		Limit:  10,
		Cursor: "not base64!",
	})
	if !errors.Is(err, authcommon.ErrInvalidCursor) {
		t.Errorf("FetchGroupPage() error = %v, want ErrInvalidCursor", err)
	}
}

func TestFetchGroupsByIDs(t *testing.T) {
	fake, _, roles := newTestDirectory(t)
	ctx := t.Context()

	if err := roles.Refresh(ctx); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	// A role created after the refresh.
	const roleNew int64 = 1100005
	fake.SetRoles(append(slices.Clone(testRoles), onelogintest.Role{
		ID:   roleNew,
		Name: "obot-new",
	}))

	got, err := FetchGroupsByIDs(ctx, roles, []string{"1100002", "1100005", "1100099", "abc", "01100003"})
	if err != nil {
		t.Fatalf("FetchGroupsByIDs() error = %v", err)
	}

	byID := make(map[string]string, len(got))
	for _, g := range got {
		byID[g.ID] = g.Name
	}
	want := map[string]string{
		"onelogin/1100002": "obot-engineering",
		"onelogin/1100005": "obot-new",
	}
	if len(byID) != len(want) {
		t.Errorf("groups = %v, want %v", byID, want)
	}
	for id, name := range want {
		if byID[id] != name {
			t.Errorf("group %s = %q, want %q", id, byID[id], name)
		}
	}

	// The cached role costs no call, and the invalid IDs are never sent.
	for _, u := range fake.Requests() {
		switch u.Path {
		case "/api/2/roles", "/api/2/roles/1100005", "/api/2/roles/1100099":
		default:
			t.Errorf("unexpected call to %s", u.Path)
		}
	}
}

func TestFetchUserGroupInfos(t *testing.T) {
	tests := []struct {
		name            string
		userID          string
		warmCache       bool
		wantIDs         []string
		wantUnavailable bool
		wantInvalid     bool
		wantRoleCalls   int
	}{
		{
			name:            "active user, warm cache",
			userID:          "300000001",
			warmCache:       true,
			wantIDs:         []string{"onelogin/1100002", "onelogin/1100004"},
			wantUnavailable: false,
			wantInvalid:     false,
			wantRoleCalls:   0,
		},
		{
			name:            "active user, cold cache",
			userID:          "300000001",
			warmCache:       false,
			wantIDs:         []string{"onelogin/1100002", "onelogin/1100004"},
			wantUnavailable: false,
			wantInvalid:     false,
			wantRoleCalls:   2,
		},
		{
			name:            "user without roles",
			userID:          "300000002",
			warmCache:       true,
			wantIDs:         []string{},
			wantUnavailable: false,
			wantInvalid:     false,
			wantRoleCalls:   0,
		},
		{
			name:            "a deleted role is left out",
			userID:          "300000005",
			warmCache:       true,
			wantIDs:         []string{"onelogin/1100003"},
			wantUnavailable: false,
			wantInvalid:     false,
			wantRoleCalls:   1,
		},
		{
			name:            "suspended user",
			userID:          "300000003",
			warmCache:       true,
			wantIDs:         nil,
			wantUnavailable: true,
			wantInvalid:     false,
			wantRoleCalls:   0,
		},
		{
			name:            "locked user",
			userID:          "300000004",
			warmCache:       true,
			wantIDs:         nil,
			wantUnavailable: true,
			wantInvalid:     false,
			wantRoleCalls:   0,
		},
		{
			name:            "deleted user",
			userID:          "300000099",
			warmCache:       true,
			wantIDs:         nil,
			wantUnavailable: true,
			wantInvalid:     false,
			wantRoleCalls:   0,
		},
		{
			name:            "invalid user ID",
			userID:          "../roles",
			warmCache:       true,
			wantIDs:         nil,
			wantUnavailable: false,
			wantInvalid:     true,
			wantRoleCalls:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake, apiClient, roles := newTestDirectory(t)
			ctx := t.Context()

			if tt.warmCache {
				if err := roles.Refresh(ctx); err != nil {
					t.Fatalf("Refresh() error = %v", err)
				}
			}

			got, err := FetchUserGroupInfos(ctx, apiClient, roles, tt.userID)

			var unavailableErr *UserUnavailableError
			if gotUnavailable := errors.As(err, &unavailableErr); gotUnavailable != tt.wantUnavailable {
				t.Fatalf("FetchUserGroupInfos() error = %v, want a UserUnavailableError: %v", err, tt.wantUnavailable)
			}
			if gotInvalid := errors.Is(err, ErrInvalidUserID); gotInvalid != tt.wantInvalid {
				t.Fatalf("FetchUserGroupInfos() error = %v, want ErrInvalidUserID: %v", err, tt.wantInvalid)
			}
			if tt.wantIDs != nil {
				if err != nil {
					t.Fatalf("FetchUserGroupInfos() error = %v", err)
				}
				if got == nil {
					t.Error("groups = nil, want a non-nil list")
				}
				if ids := groupIDs(got); !slices.Equal(ids, tt.wantIDs) {
					t.Errorf("ids = %v, want %v", ids, tt.wantIDs)
				}
			}

			var roleCalls int
			for _, u := range fake.Requests() {
				if strings.HasPrefix(u.Path, "/api/2/roles/") {
					roleCalls++
				}
			}
			if roleCalls != tt.wantRoleCalls {
				t.Errorf("role calls = %d, want %d", roleCalls, tt.wantRoleCalls)
			}
			if tt.wantInvalid && fake.RequestCount("/api/2/users/"+tt.userID) != 0 {
				t.Error("an invalid user ID was sent to OneLogin")
			}
		})
	}
}

func TestFetchUserGroupInfosRateLimited(t *testing.T) {
	fake, apiClient, roles := newTestDirectory(t)
	fake.SetRateLimited(true, "")

	var rateLimitErr *client.RateLimitedError
	if _, err := FetchUserGroupInfos(t.Context(), apiClient, roles, "300000001"); !errors.As(err, &rateLimitErr) {
		t.Errorf("FetchUserGroupInfos() error = %v, want a RateLimitedError", err)
	}
}

func TestFetchUserGroupInfosRoleLookupFailure(t *testing.T) {
	fake, _, _ := newTestDirectory(t)
	ctx := t.Context()

	// Reading the user works, but the cache is cold and the role lookups are rejected. A partial list would drop
	// the user from groups, so the whole call fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/2/roles/") {
			http.Error(w, `{"error":"InternalServerError"}`, http.StatusInternalServerError)
			return
		}
		fake.Config.Handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	apiClient := client.New(srv.URL, onelogintest.ClientID, onelogintest.ClientSecret)
	roles := NewRoleCache(apiClient)

	if _, err := FetchUserGroupInfos(ctx, apiClient, roles, "300000001"); err == nil {
		t.Error("FetchUserGroupInfos() error = nil, want an error")
	}
}
