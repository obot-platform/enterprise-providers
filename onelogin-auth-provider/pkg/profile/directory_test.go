package profile

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/internal/onelogintest"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/client"
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

var (
	testRoles = []onelogintest.Role{
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

	testUsers = []onelogintest.User{
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
)

func newTestDirectory(t *testing.T) (*onelogintest.Server, *client.Client, *RoleCache) {
	t.Helper()

	fake := onelogintest.New(t, testRoles, testUsers)
	apiClient := client.New(fake.URL, onelogintest.ClientID, onelogintest.ClientSecret)

	return fake, apiClient, NewRoleCache(apiClient)
}

// newInMemoryRoleCache returns a RoleCache whose client calls OneLogin through transport, which serves requests in
// memory, so that the cache can be tested in a synctest bubble.
func newInMemoryRoleCache(fake *onelogintest.Server, transport http.RoundTripper) *RoleCache {
	return NewRoleCache(client.New(fake.URL, onelogintest.ClientID, onelogintest.ClientSecret, client.WithHTTPClient(&http.Client{Transport: transport})))
}

// blockPath returns a transport that serves requests from the fake in memory, except that a request for path waits
// until release is closed or the request is canceled.
func blockPath(fake *onelogintest.Server, path string, release <-chan struct{}) http.RoundTripper {
	return onelogintest.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == path {
			select {
			case <-release:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		return fake.Transport().RoundTrip(req)
	})
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
	// The listing asks for only the role IDs and names; see roleListFields.
	if requests := fake.Requests(); len(requests) == 0 || requests[0].Query().Get("fields") != roleListFields {
		t.Errorf("list requests = %v, want the first with fields=%s", requests, roleListFields)
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

	fake.RateLimit("60")
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

func TestRoleCacheMissCanceled(t *testing.T) {
	fake := onelogintest.New(t, testRoles, nil)

	synctest.Test(t, func(t *testing.T) {
		roles := newInMemoryRoleCache(fake, fake.Transport())

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if _, _, err := roles.Name(ctx, roleEngineering); !errors.Is(err, context.Canceled) {
			t.Fatalf("Name() error = %v, want context.Canceled", err)
		}
		// A lookup the caller started would run detached, so let it finish before counting calls.
		synctest.Wait()

		if got := len(fake.Requests()); got != 0 {
			t.Errorf("API calls = %d, want 0", got)
		}
		if got := fake.TokenRequests(); got != 0 {
			t.Errorf("token requests = %d, want 0", got)
		}
	})
}

func TestRoleCacheMissCoalesced(t *testing.T) {
	fake := onelogintest.New(t, testRoles, nil)

	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		roles := newInMemoryRoleCache(fake, blockPath(fake, "/api/2/roles/1100002", release))

		const callers = 10
		var (
			wg    sync.WaitGroup
			names = make([]string, callers)
			errs  = make([]error, callers)
		)
		for i := range callers {
			wg.Go(func() {
				names[i], _, errs[i] = roles.Name(t.Context(), roleEngineering)
			})
		}
		// Every caller is now waiting: one on OneLogin, and the rest on that caller's lookup.
		synctest.Wait()
		close(release)
		wg.Wait()

		if got := fake.RequestCount("/api/2/roles/1100002"); got != 1 {
			t.Errorf("role calls = %d, want 1", got)
		}
		for i := range callers {
			if errs[i] != nil || names[i] != "obot-engineering" {
				t.Errorf("caller %d got %q, %v, want obot-engineering, nil", i, names[i], errs[i])
			}
		}
	})
}

func TestRoleCacheMissOutlivesFirstCaller(t *testing.T) {
	fake := onelogintest.New(t, testRoles, nil)

	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		roles := newInMemoryRoleCache(fake, blockPath(fake, "/api/2/roles/1100002", release))

		// The first caller starts the lookup, and gives up while it is in flight.
		ctx, cancel := context.WithCancel(t.Context())
		firstErr := make(chan error, 1)
		go func() {
			_, _, err := roles.Name(ctx, roleEngineering)
			firstErr <- err
		}()
		synctest.Wait()

		var (
			name  string
			found bool
			err   error
			wg    sync.WaitGroup
		)
		wg.Go(func() {
			name, found, err = roles.Name(t.Context(), roleEngineering)
		})
		synctest.Wait()

		cancel()
		if err := <-firstErr; !errors.Is(err, context.Canceled) {
			t.Errorf("Name() of the caller that gave up error = %v, want context.Canceled", err)
		}

		// The lookup carries on for the second caller.
		close(release)
		wg.Wait()

		if err != nil || !found || name != "obot-engineering" {
			t.Errorf("Name() = %q, %v, %v, want obot-engineering, true, nil", name, found, err)
		}
		if got := fake.RequestCount("/api/2/roles/1100002"); got != 1 {
			t.Errorf("role calls = %d, want 1", got)
		}
	})
}

func TestRoleCacheRun(t *testing.T) {
	fake := onelogintest.New(t, testRoles, nil)

	synctest.Test(t, func(t *testing.T) {
		roles := newInMemoryRoleCache(fake, fake.Transport())

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			roles.Run(ctx, time.Hour)
		}()

		// Run fills the cache at once.
		synctest.Wait()
		if got := fake.RequestCount("/api/2/roles"); got != 1 {
			t.Errorf("list calls after starting = %d, want 1", got)
		}
		if name, found, _ := roles.Name(t.Context(), roleSecurity); !found || name != "Security" {
			t.Errorf("Name() = %q, %v, want Security, true", name, found)
		}

		// Then it refreshes it every interval, and not before.
		time.Sleep(time.Hour - time.Second)
		synctest.Wait()
		if got := fake.RequestCount("/api/2/roles"); got != 1 {
			t.Errorf("list calls just before the interval = %d, want 1", got)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if got := fake.RequestCount("/api/2/roles"); got != 2 {
			t.Errorf("list calls after the interval = %d, want 2", got)
		}

		cancel()
		<-done
	})
}

func TestRoleCacheRunRetriesSooner(t *testing.T) {
	fake := onelogintest.New(t, testRoles, nil)
	fake.FailPath("/api/2/roles", http.StatusInternalServerError)

	synctest.Test(t, func(t *testing.T) {
		roles := newInMemoryRoleCache(fake, fake.Transport())

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			roles.Run(ctx, 10*time.Minute)
		}()

		// listCallsAfter waits d, and returns how many times Run has listed the roles.
		listCallsAfter := func(d time.Duration) int {
			time.Sleep(d)
			synctest.Wait()
			return fake.RequestCount("/api/2/roles")
		}

		// The fill fails, and each retry comes twice as long after the last, up to the interval.
		for i, want := range []struct {
			wait  time.Duration
			calls int
		}{
			{
				wait:  0,
				calls: 1,
			},
			{
				wait:  roleCacheFirstRetry - time.Second,
				calls: 1,
			},
			{
				wait:  time.Second,
				calls: 2,
			},
			{
				wait:  2 * roleCacheFirstRetry,
				calls: 3,
			},
			{
				wait:  4 * roleCacheFirstRetry,
				calls: 4,
			},
		} {
			if got := listCallsAfter(want.wait); got != want.calls {
				t.Fatalf("step %d: list calls = %d, want %d", i, got, want.calls)
			}
		}

		// Once a refresh succeeds, the next waits the whole interval.
		fake.StopFailingPath("/api/2/roles")
		if got := listCallsAfter(8 * roleCacheFirstRetry); got != 5 {
			t.Fatalf("list calls after the retry that succeeds = %d, want 5", got)
		}
		if got := listCallsAfter(10*time.Minute - time.Second); got != 5 {
			t.Errorf("list calls just before the interval = %d, want 5", got)
		}
		if got := listCallsAfter(time.Second); got != 6 {
			t.Errorf("list calls after the interval = %d, want 6", got)
		}

		cancel()
		<-done
	})
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
			wantQuery:      "fields=id%2Cname&limit=2",
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
			wantQuery:      "fields=id%2Cname&limit=10",
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
			wantQuery:      "fields=id%2Cname&limit=10&name=OBOT-",
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
			wantQuery:      "fields=id%2Cname&limit=10&name=obot%2A",
			wantIDs:        []string{},
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

// roleCalls returns how many role lookups the fake has received.
func roleCalls(fake *onelogintest.Server) int {
	var calls int
	for _, u := range fake.Requests() {
		if strings.HasPrefix(u.Path, "/api/2/roles/") {
			calls++
		}
	}
	return calls
}

func TestFetchUserGroupInfos(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		warmCache     bool
		wantIDs       []string
		wantRoleCalls int
	}{
		{
			name:          "active user, warm cache",
			userID:        "300000001",
			warmCache:     true,
			wantIDs:       []string{"onelogin/1100002", "onelogin/1100004"},
			wantRoleCalls: 0,
		},
		{
			name:          "active user, cold cache",
			userID:        "300000001",
			warmCache:     false,
			wantIDs:       []string{"onelogin/1100002", "onelogin/1100004"},
			wantRoleCalls: 2,
		},
		{
			name:          "user without roles",
			userID:        "300000002",
			warmCache:     true,
			wantIDs:       []string{},
			wantRoleCalls: 0,
		},
		{
			name:          "a deleted role is left out",
			userID:        "300000005",
			warmCache:     true,
			wantIDs:       []string{"onelogin/1100003"},
			wantRoleCalls: 1,
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
			if err != nil {
				t.Fatalf("FetchUserGroupInfos() error = %v", err)
			}
			if got == nil {
				t.Error("groups = nil, want a non-nil list")
			}
			if ids := groupIDs(got); !slices.Equal(ids, tt.wantIDs) {
				t.Errorf("ids = %v, want %v", ids, tt.wantIDs)
			}
			if got := roleCalls(fake); got != tt.wantRoleCalls {
				t.Errorf("role calls = %d, want %d", got, tt.wantRoleCalls)
			}
		})
	}
}

func TestFetchUserGroupInfosErrors(t *testing.T) {
	tests := []struct {
		name string
		// userID is not a OneLogin user ID when wantInvalidID is true. Otherwise it names a user who cannot sign in.
		userID        string
		wantInvalidID bool
	}{
		{
			name:          "suspended user",
			userID:        "300000003",
			wantInvalidID: false,
		},
		{
			name:          "locked user",
			userID:        "300000004",
			wantInvalidID: false,
		},
		{
			name:          "deleted user",
			userID:        "300000099",
			wantInvalidID: false,
		},
		{
			name:          "invalid user ID",
			userID:        "../roles",
			wantInvalidID: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake, apiClient, roles := newTestDirectory(t)
			ctx := t.Context()

			if err := roles.Refresh(ctx); err != nil {
				t.Fatalf("Refresh() error = %v", err)
			}

			_, err := FetchUserGroupInfos(ctx, apiClient, roles, tt.userID)
			if tt.wantInvalidID {
				if !errors.Is(err, ErrInvalidUserID) {
					t.Fatalf("FetchUserGroupInfos() error = %v, want ErrInvalidUserID", err)
				}
				if got := len(fake.Requests()); got != 1 {
					t.Errorf("calls = %d, want only the refresh", got)
				}
			} else if _, ok := errors.AsType[*UserUnavailableError](err); !ok {
				t.Fatalf("FetchUserGroupInfos() error = %v, want a UserUnavailableError", err)
			}

			if got := roleCalls(fake); got != 0 {
				t.Errorf("role calls = %d, want 0", got)
			}
		})
	}
}

func TestFetchUserGroupInfosRateLimited(t *testing.T) {
	fake, apiClient, roles := newTestDirectory(t)
	fake.RateLimit("")

	var rateLimitErr *client.RateLimitedError
	if _, err := FetchUserGroupInfos(t.Context(), apiClient, roles, "300000001"); !errors.As(err, &rateLimitErr) {
		t.Errorf("FetchUserGroupInfos() error = %v, want a RateLimitedError", err)
	}
}

func TestFetchUserGroupInfosRoleLookupFailure(t *testing.T) {
	fake, apiClient, roles := newTestDirectory(t)

	// Reading the user works, but the cache is cold and the role lookups fail. A partial list would drop the user
	// from groups, so the whole call fails.
	fake.FailPath("/api/2/roles/", http.StatusInternalServerError)

	if _, err := FetchUserGroupInfos(t.Context(), apiClient, roles, "300000001"); err == nil {
		t.Error("FetchUserGroupInfos() error = nil, want an error")
	}
}
