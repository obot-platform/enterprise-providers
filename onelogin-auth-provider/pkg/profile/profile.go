package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/client"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
	"golang.org/x/sync/errgroup"
)

const (
	// ProviderKind names this provider to authcommon, which bakes it into the group-list cursors it mints.
	ProviderKind = "onelogin"

	// GroupIDPrefix starts the ID of every group this provider returns. The rest is the OneLogin role ID.
	GroupIDPrefix = ProviderKind + "/"

	rolesPath = "/api/2/roles"
	usersPath = "/api/2/users"

	// roleListFields trims a role listing to what Obot uses. By default OneLogin lists every role with the IDs of all
	// its users, admins, and apps, which in a large account can make one page of roles many megabytes. The cursor
	// keeps fields, so later pages are trimmed too. GET /api/2/roles/:id rejects fields with a 400.
	roleListFields = "id,name"

	// userStatusActive is the status of a OneLogin user who can sign in.
	userStatusActive = 1

	// roleLookupConcurrency caps the concurrent role-name lookups for one user.
	roleLookupConcurrency = 8

	// maxUserInfoBytes caps how much of a userinfo response is read. A real one is a few hundred bytes.
	maxUserInfoBytes = 1 << 20
)

var (
	// ErrInvalidUserID is returned for a user ID that is not a OneLogin user ID, which is a positive integer.
	ErrInvalidUserID = errors.New("invalid OneLogin user ID")

	// userStatusDescriptions names the values of a OneLogin user's status, for the UserUnavailableError message.
	userStatusDescriptions = map[int]string{
		0: "unactivated",
		1: "active",
		2: "suspended",
		3: "locked",
		4: "password expired",
		5: "awaiting password reset",
		7: "password pending",
		8: "security questions required",
	}
)

// UserUnavailableError indicates that the OneLogin user cannot currently sign in: the user is not active, or no
// longer exists.
type UserUnavailableError struct {
	Reason string
}

func (e *UserUnavailableError) Error() string {
	return e.Reason
}

// role is a OneLogin role, as GET /api/2/roles and GET /api/2/roles/:id return it.
type role struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// oneLoginUser is the part of a OneLogin user, as GET /api/2/users/:id returns it, that directory lookups use.
type oneLoginUser struct {
	ID      int64   `json:"id"`
	RoleIDs []int64 `json:"role_ids"`
	// Status is nil when the response has no status, which should not happen.
	Status *int `json:"status"`
}

// UserInfo represents basic user profile information.
type UserInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IconURL string `json:"icon_url,omitempty"`
}

// GetUserInfo returns the authenticated user's ID and name from the OneLogin userinfo endpoint, <issuer>/me, which it
// calls through httpClient. The ID is the OIDC subject, which is the user's numeric OneLogin user ID.
// OneLogin does not support user profile photos, so IconURL is always empty.
func GetUserInfo(ctx context.Context, httpClient *http.Client, accessToken, issuerURL string) (*UserInfo, error) {
	userInfoURL := strings.TrimSuffix(issuerURL, "/") + "/me"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call userinfo endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one byte past the cap, to tell a response at the cap from one beyond it.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUserInfoBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// The error ends up in the response to Obot, so only the start of the body goes in it.
		return nil, fmt.Errorf("userinfo endpoint returned status %d: %s", resp.StatusCode, string(body[:min(len(body), client.MaxErrorBodyBytes)]))
	}
	if len(body) > maxUserInfoBytes {
		return nil, fmt.Errorf("userinfo response is larger than %d bytes", maxUserInfoBytes)
	}

	var userInfo struct {
		Sub  string `json:"sub"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}
	if userInfo.Sub == "" {
		return nil, errors.New("userinfo response has no sub claim")
	}

	return &UserInfo{
		ID:   userInfo.Sub,
		Name: userInfo.Name,
	}, nil
}

// FetchGroupPage fetches one page of the OneLogin account's roles, which Obot treats as groups. It is one call to
// GET /api/2/roles, which lists roles sorted by ID.
//
// The first page sends the name filter and the limit. OneLogin matches name as a case-insensitive substring, and
// matches * literally, so the filter is passed through as is. The continuation token is OneLogin's After-Cursor,
// which encodes the filter and the limit, and a later page sends it alone: OneLogin answers 400 when a cursor comes
// with limit or page.
func FetchGroupPage(ctx context.Context, apiClient *client.Client, req authcommon.PageRequest) (authcommon.PageResult, error) {
	query := url.Values{}
	if req.Cursor != "" {
		query.Set("cursor", req.Cursor)
	} else {
		// authcommon.ParseGroupPageRequest has already put the limit between 1 and authcommon.MaxGroupPageSize.
		query.Set("limit", strconv.Itoa(req.Limit))
		query.Set("fields", roleListFields)
		if req.NameFilter != "" {
			query.Set("name", req.NameFilter)
		}
	}

	var roles []role
	header, err := apiClient.GetJSON(ctx, rolesPath, query, &roles)
	if err != nil {
		if req.Cursor != "" && client.HasStatus(err, http.StatusBadRequest) {
			// OneLogin rejected the cursor, so Obot should restart from the first page.
			return authcommon.PageResult{}, fmt.Errorf("%w: OneLogin rejected it: %v", authcommon.ErrInvalidCursor, err)
		}
		return authcommon.PageResult{}, fmt.Errorf("failed to fetch OneLogin roles: %w", err)
	}

	items := make(state.GroupInfoList, 0, len(roles))
	for _, r := range roles {
		if r.ID <= 0 {
			continue
		}
		items = append(items, groupInfo(r.ID, r.Name))
	}

	return authcommon.PageResult{
		Items:      items,
		NextCursor: header.Get(client.AfterCursorHeader),
	}, nil
}

// FetchGroupsByIDs resolves OneLogin role IDs to their current names, from the role-name cache when it knows them
// and otherwise with one GET /api/2/roles/:id per ID. A role OneLogin no longer has, and an ID that is not a role ID,
// is left out of the result.
func FetchGroupsByIDs(ctx context.Context, roles *RoleCache, ids []string) (state.GroupInfoList, error) {
	return authcommon.ResolveGroupsByLookup(ctx, ids, func(ctx context.Context, id string) (*state.GroupInfo, error) {
		roleID, ok := parseID(id)
		if !ok {
			// OneLogin role IDs are integers, so this cannot name a role. It is not sent to OneLogin, where it would
			// become part of the request path.
			return nil, nil
		}

		name, found, err := roles.Name(ctx, roleID)
		if err != nil {
			return nil, err
		}
		if !found {
			// The role was deleted in OneLogin while a policy still references it.
			return nil, nil
		}

		info := groupInfo(roleID, name)
		return &info, nil
	})
}

// FetchUserGroupInfos returns the roles the specified OneLogin user holds. It is one call to GET /api/2/users/:id,
// whose role_ids are named from the role-name cache. A role ID the cache does not know costs one more call.
//
// A user whose status is not active, or who OneLogin no longer has, gets a UserUnavailableError. A deleted user is
// not reported as having no roles, because Obot would then keep a deleted user signed in, just without groups.
func FetchUserGroupInfos(ctx context.Context, apiClient *client.Client, roles *RoleCache, userID string) (state.GroupInfoList, error) {
	id, ok := parseID(userID)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidUserID, userID)
	}

	var user oneLoginUser
	if _, err := apiClient.GetJSON(ctx, usersPath+"/"+strconv.FormatInt(id, 10), nil, &user); err != nil {
		if client.IsNotFound(err) {
			return nil, &UserUnavailableError{Reason: "OneLogin user was not found; it may have been deleted"}
		}
		return nil, fmt.Errorf("failed to fetch OneLogin user %d: %w", id, err)
	}

	if err := ensureUserAvailable(user); err != nil {
		return nil, err
	}

	// Look the role names up concurrently. They come from the cache unless a role is new since the last refresh, so
	// this rarely calls OneLogin. Any failure fails the whole call, because a partial list would drop the user from
	// groups they are still in.
	var (
		resolved = make([]*state.GroupInfo, len(user.RoleIDs))
		g, gctx  = errgroup.WithContext(ctx)
	)
	g.SetLimit(roleLookupConcurrency)

	for i, roleID := range user.RoleIDs {
		g.Go(func() error {
			name, found, err := roles.Name(gctx, roleID)
			if err != nil {
				return err
			}
			if found {
				info := groupInfo(roleID, name)
				resolved[i] = &info
			}
			// A role that is not found was deleted after OneLogin read the user, so the user no longer holds it.
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("failed to resolve the roles of OneLogin user %d: %w", id, err)
	}

	groups := make(state.GroupInfoList, 0, len(resolved))
	for _, info := range resolved {
		if info != nil {
			groups = append(groups, *info)
		}
	}

	return groups, nil
}

// ensureUserAvailable returns a UserUnavailableError unless the user's status is active.
func ensureUserAvailable(user oneLoginUser) error {
	if user.Status == nil {
		return &UserUnavailableError{Reason: "OneLogin account has no status, so it is not known to be active"}
	}
	if *user.Status == userStatusActive {
		return nil
	}

	description, ok := userStatusDescriptions[*user.Status]
	if !ok {
		description = "unknown"
	}

	return &UserUnavailableError{Reason: fmt.Sprintf("OneLogin account is not active (status %d: %s)", *user.Status, description)}
}

// groupInfo returns the Obot group for a OneLogin role.
func groupInfo(roleID int64, name string) state.GroupInfo {
	return state.GroupInfo{
		ID:      GroupIDPrefix + strconv.FormatInt(roleID, 10),
		Name:    name,
		IconURL: nil, // OneLogin roles have no icons
	}
}

// parseID parses a OneLogin user or role ID, which is a positive integer. Only the canonical decimal form is
// accepted, so that the group ID built from the result is the one that was asked about.
func parseID(s string) (int64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}

	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != s {
		return 0, false
	}

	return id, true
}
