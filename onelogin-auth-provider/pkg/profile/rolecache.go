package profile

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/client"
	"golang.org/x/sync/singleflight"
)

const (
	// RoleCacheRefreshInterval is how often Run reloads every role name. A renamed role shows its new name within it.
	RoleCacheRefreshInterval = 15 * time.Minute

	// roleListPageSize is the page size of a full role listing. OneLogin accepts 1,000 (phase 0b, A3).
	roleListPageSize = 1000

	// maxRoles caps how many roles a refresh loads. Roles beyond it are named by per-ID lookups instead.
	maxRoles = 100000
)

// RoleCache maps OneLogin role IDs to role names, so that naming a user's roles does not cost a call per role.
// Run fills it and keeps it fresh. A role it does not know is looked up with GET /api/2/roles/:id, and concurrent
// lookups of the same role share one call.
//
// Each provider process has its own cache.
type RoleCache struct {
	client *client.Client

	mu    sync.RWMutex
	names map[int64]string

	lookups singleflight.Group
}

// roleLookup is the result of one GET /api/2/roles/:id.
type roleLookup struct {
	name  string
	found bool
}

// NewRoleCache returns an empty RoleCache that calls OneLogin through apiClient.
func NewRoleCache(apiClient *client.Client) *RoleCache {
	return &RoleCache{
		client: apiClient,
		names:  map[int64]string{},
	}
}

// Run fills the cache, then refreshes it every interval until ctx is done. It returns only then, so the caller owns
// the goroutine it runs in. A failed refresh is logged, and the cache keeps the names it had.
func (r *RoleCache) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := r.Refresh(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("failed to refresh the OneLogin role-name cache", "error", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Refresh replaces the cache with every role OneLogin lists, so that deleted roles leave it and renamed roles get
// their new names.
func (r *RoleCache) Refresh(ctx context.Context) error {
	roles, err := client.ListAll[role](ctx, r.client, rolesPath, url.Values{"limit": []string{strconv.Itoa(roleListPageSize)}}, maxRoles)
	if err != nil {
		return fmt.Errorf("failed to list OneLogin roles: %w", err)
	}

	names := make(map[int64]string, len(roles))
	for _, listed := range roles {
		if listed.ID > 0 {
			names[listed.ID] = listed.Name
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = names

	return nil
}

// Name returns the name of a role. found is false when OneLogin has no such role, which means it was deleted.
func (r *RoleCache) Name(ctx context.Context, roleID int64) (name string, found bool, err error) {
	r.mu.RLock()
	name, found = r.names[roleID]
	r.mu.RUnlock()
	if found {
		return name, true, nil
	}

	// Concurrent callers share the first caller's request, and so its context.
	v, err, _ := r.lookups.Do(strconv.FormatInt(roleID, 10), func() (any, error) {
		return r.lookup(ctx, roleID)
	})
	if err != nil {
		return "", false, err
	}

	result := v.(roleLookup)
	return result.name, result.found, nil
}

// lookup fetches one role from OneLogin and caches its name. That a role was not found is not cached: Obot asks
// about a deleted role only while a policy still references it, and caching it would need its own expiry.
func (r *RoleCache) lookup(ctx context.Context, roleID int64) (roleLookup, error) {
	var fetched role
	if _, err := r.client.GetJSON(ctx, rolesPath+"/"+strconv.FormatInt(roleID, 10), nil, &fetched); err != nil {
		if client.IsNotFound(err) {
			return roleLookup{}, nil
		}
		return roleLookup{}, fmt.Errorf("failed to fetch OneLogin role %d: %w", roleID, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.names[roleID] = fetched.Name

	return roleLookup{
		name:  fetched.Name,
		found: true,
	}, nil
}
