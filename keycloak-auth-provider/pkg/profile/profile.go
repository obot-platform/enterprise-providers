// Package profile translates Keycloak identities and directory groups to Obot contracts.
package profile

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/keycloak-auth-provider/pkg/client"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

const (
	// Count bound supplements the independent 8 MiB response limit; either can reject a response.
	maxGroups              = 100000
	maxDepth               = 128
	directoryTimeout       = 30 * time.Second
	membershipTimeout      = 8 * time.Second
	groupLookupConcurrency = 8
)

// UserUnavailableError deliberately maps to 403, never the unsupported-endpoint 404.
type UserUnavailableError struct{ Reason string }

func (e *UserUnavailableError) Error() string { return e.Reason }

type UserInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IconURL string `json:"icon_url,omitempty"`
}

type group struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	Path     string `json:"path"`
	ParentID string `json:"parentId"`
}

// Keycloak can optionally escape slashes within group names as "~/" in paths.
// Accept both representations when confirming that a parentless group is a root.
func (g group) isRoot() bool {
	return g.ParentID == "" && g.Name != "" &&
		(g.Path == "/"+g.Name || g.Path == "/"+strings.ReplaceAll(g.Name, "/", "~/"))
}

func (g group) info() (state.GroupInfo, error) {
	if g.ID == "" || g.Path == "" || !strings.HasPrefix(g.Path, "/") {
		return state.GroupInfo{}, errors.New("keycloak group is missing its native ID or full path")
	}
	return state.GroupInfo{ID: "keycloak/" + g.ID, Name: g.Path}, nil
}

// GetUserInfo uses the user's token, not directory credentials or email lookup.
// Email admission policy belongs to OIDC sign-in, not profile enrichment.
func GetUserInfo(ctx context.Context, token, endpoint string) (*UserInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, directoryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	response, err := (&http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned HTTP %d", response.StatusCode)
	}
	var user struct {
		Sub        string `json:"sub"`
		Email      string `json:"email"`
		Name       string `json:"name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
		Username   string `json:"preferred_username"`
		Picture    string `json:"picture"`
	}
	if err := client.Decode(response.Body, &user); err != nil {
		return nil, err
	}
	if user.Sub == "" {
		return nil, errors.New("userinfo requires an exact subject")
	}
	name := firstNonempty(user.Name, strings.TrimSpace(user.GivenName+" "+user.FamilyName), user.Username, user.Email)
	picture, err := url.Parse(user.Picture)
	if err != nil || picture.Scheme != "https" || picture.Host == "" || picture.User != nil {
		user.Picture = ""
	}
	return &UserInfo{ID: user.Sub, Name: name, IconURL: user.Picture}, nil
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// FetchUserGroupInfos atomically returns a complete direct-plus-ancestor answer or an error.
func FetchUserGroupInfos(ctx context.Context, directory *client.Client, userID string) (state.GroupInfoList, error) {
	ctx, cancel := context.WithTimeout(ctx, membershipTimeout)
	defer cancel()
	if err := validateNativeID(userID); err != nil {
		return nil, err
	}
	var groups []group
	var userErr, groupsErr error
	var reads sync.WaitGroup
	ctx, cancelReads := context.WithCancel(ctx)
	defer cancelReads()
	reads.Go(func() {
		userErr = checkUser(ctx, directory, userID)
		if userErr != nil {
			cancelReads()
		}
	})
	reads.Go(func() {
		query := url.Values{"first": {"0"}, "max": {strconv.Itoa(maxGroups + 1)}, "briefRepresentation": {"true"}}
		status, err := read(ctx, directory, "/users/"+url.PathEscape(userID)+"/groups", query, &groups)
		if err != nil {
			groupsErr = err
		} else if status != http.StatusOK {
			groupsErr = fmt.Errorf("user memberships returned HTTP %d", status)
		} else if groups == nil || len(groups) > maxGroups {
			groupsErr = errors.New("invalid or oversized user memberships response")
		}
		// Let the status read finish so a missing/disabled user keeps its typed denial.
	})
	reads.Wait()
	if userErr != nil && !errors.Is(userErr, context.Canceled) {
		return nil, userErr
	}
	if groupsErr != nil {
		return nil, groupsErr
	}
	if userErr != nil {
		return nil, userErr
	}
	// Native OFFSET pages sort by nonunique leaf names, so fetch direct
	// membership in one bounded response. Authorization never uses browse caches.
	directSeen := map[string]bool{}
	provided := map[string]group{}
	directIDs := make([]string, 0, len(groups))
	for _, direct := range groups {
		if validateNativeID(direct.ID) != nil {
			return nil, errors.New("membership has no native group ID")
		}
		if directSeen[direct.ID] {
			return nil, errors.New("duplicate native ID in user memberships response")
		}
		directSeen[direct.ID] = true
		directIDs = append(directIDs, direct.ID)
		// Reuse brief parent links when supplied. Older versions and roots may
		// omit parentId. A path matching the native name (possibly escaped) identifies a root;
		// otherwise fetch details. Never split a path to infer ancestor IDs.
		if direct.ParentID != "" || direct.isRoot() {
			if _, err := direct.info(); err != nil {
				return nil, err
			}
			provided[direct.ID] = direct
		}
	}

	// Resolve independent groups in bounded parallel batches. Discover each
	// ancestor once, even when several direct memberships share it. The cache is
	// local to this authorization read and never uses administrative snapshots.
	memo := map[string]group{}
	scheduled := make(map[string]bool, len(directSeen))
	for id := range directSeen {
		scheduled[id] = true
	}
	frontier := directIDs
	for depth := 0; len(frontier) > 0; depth++ {
		if depth >= maxDepth {
			return nil, errors.New("keycloak group ancestry exceeds safety bounds")
		}
		detailIDs := make([]string, 0, len(frontier))
		fetched := make([]group, 0, len(frontier))
		for _, id := range frontier {
			if g, ok := provided[id]; ok {
				fetched = append(fetched, g)
			} else {
				detailIDs = append(detailIDs, id)
			}
		}
		details, err := fetchMembershipGroups(ctx, directory, detailIDs)
		if err != nil {
			return nil, err
		}
		fetched = append(fetched, details...)
		next := []string{}
		for _, g := range fetched {
			// A missing parent is meaningful only for a confirmed root. Never
			// silently truncate an ancestor chain when a detail response is incomplete.
			if g.ParentID == "" && !g.isRoot() {
				return nil, errors.New("membership group has no parent ID and is not a confirmed root")
			}
			memo[g.ID] = g
			if g.ParentID != "" && !scheduled[g.ParentID] {
				if len(scheduled) >= maxGroups {
					return nil, errors.New("keycloak group ancestry exceeds safety bounds")
				}
				scheduled[g.ParentID] = true
				next = append(next, g.ParentID)
			}
		}
		frontier = next
	}

	// All details must succeed before constructing a membership answer. Check
	// cycles and depth for every original direct chain, including chains whose
	// ancestors were also supplied as direct memberships in an earlier batch.
	result := map[string]state.GroupInfo{}
	for _, directID := range directIDs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		visiting := map[string]bool{}
		depth := 0
		for id := directID; id != ""; {
			if visiting[id] {
				return nil, errors.New("cycle in Keycloak group ancestry")
			}
			if depth >= maxDepth {
				return nil, errors.New("keycloak group ancestry exceeds safety bounds")
			}
			visiting[id] = true
			depth++
			g, ok := memo[id]
			if !ok {
				return nil, errors.New("required membership group or ancestor is unavailable")
			}
			info, err := g.info()
			if err != nil {
				return nil, err
			}
			result[id] = info
			id = g.ParentID
		}
	}
	infos := make(state.GroupInfoList, 0, len(result))
	for _, info := range result {
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID < infos[j].ID })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return infos, nil
}

func checkUser(ctx context.Context, directory *client.Client, userID string) error {
	var user struct {
		ID      string `json:"id"`
		Enabled *bool  `json:"enabled"`
	}
	status, err := read(ctx, directory, "/users/"+url.PathEscape(userID), nil, &user)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return &UserUnavailableError{Reason: "Keycloak user is unavailable"}
	}
	if status != http.StatusOK {
		return fmt.Errorf("user status lookup returned HTTP %d", status)
	}
	if user.ID != userID || user.Enabled == nil {
		return errors.New("invalid user status response")
	}
	if !*user.Enabled {
		return &UserUnavailableError{Reason: "Keycloak user is disabled"}
	}

	return nil
}

// fetchMembershipGroups cancels all pending work on any failed detail read.
// A fixed worker count bounds both network concurrency and goroutine allocation.
func fetchMembershipGroups(ctx context.Context, directory *client.Client, ids []string) ([]group, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	groups := make([]group, len(ids))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var failed sync.Once
	var firstErr error
	for range min(groupLookupConcurrency, len(ids)) {
		wg.Go(func() {
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				g, err := fetchGroup(ctx, directory, ids[index])
				if err == nil && g.ID == "" {
					err = errors.New("required membership group or ancestor is unavailable")
				}
				if err != nil {
					failed.Do(func() {
						firstErr = err
						cancel()
					})
					return
				}
				groups[index] = g
			}
		})
	}
feed:
	for index := range ids {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}

func validateNativeID(id string) error {
	if id == "" || id == "." || id == ".." {
		return errors.New("invalid native Keycloak ID")
	}
	return nil
}

func fetchGroup(ctx context.Context, directory *client.Client, id string) (group, error) {
	if err := validateNativeID(id); err != nil {
		return group{}, err
	}
	var g group
	status, err := read(ctx, directory, "/groups/"+url.PathEscape(id), nil, &g)
	if err != nil {
		return g, err
	}
	if status == http.StatusNotFound {
		return group{}, nil
	}
	if status != http.StatusOK {
		return group{}, fmt.Errorf("group lookup returned HTTP %d", status)
	}
	if g.ID != id {
		return group{}, errors.New("group lookup returned a different native ID")
	}
	if _, err := g.info(); err != nil {
		return group{}, err
	}
	return g, nil
}

// FetchGroupsByIDs omits invalid or confirmed missing IDs but fails any permission/transport/parse error.
// The shared best-effort resolver cannot be used here because it permits partial errors.
func FetchGroupsByIDs(ctx context.Context, directory *client.Client, ids []string) (state.GroupInfoList, error) {
	ctx, cancel := context.WithTimeout(ctx, directoryTimeout)
	defer cancel()
	ctx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()
	if len(ids) > authcommon.MaxGroupIDsPerRequest {
		return nil, authcommon.ErrTooManyIDs
	}
	infos := make(state.GroupInfoList, 0, len(ids))
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	sem := make(chan struct{}, groupLookupConcurrency)
	seen := map[string]bool{}
schedule:
	for _, id := range ids {
		if validateNativeID(id) != nil || seen[id] {
			continue
		}
		seen[id] = true
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break schedule
		}
		wg.Go(func() {
			defer func() { <-sem }()
			g, err := fetchGroup(ctx, directory, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
					cancelWork()
				}
				return
			}
			if g.ID != "" {
				info, _ := g.info()
				infos = append(infos, info)
			}
		})
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID < infos[j].ID })
	return infos, nil
}

func read(ctx context.Context, directory *client.Client, path string, query url.Values, out any) (int, error) {
	response, err := directory.Get(ctx, path, query)
	if err != nil {
		return 0, fmt.Errorf("keycloak directory read: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, nil
	}
	if err := client.Decode(response.Body, out); err != nil {
		return 0, fmt.Errorf("decode Keycloak directory response: %w", err)
	}
	return response.StatusCode, nil
}
