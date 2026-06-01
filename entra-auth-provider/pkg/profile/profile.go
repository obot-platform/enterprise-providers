package profile

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// UserInfo represents basic user profile information.
type UserInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IconURL string `json:"icon_url,omitempty"`
}

// photoCache stores profile photos as base64 data URLs.
// Photos are cached for up to 1 hour to improve performance and reduce API calls.
// Cache keys: "user:<userID>" or "group:<groupID>"
var photoCache = expirable.NewLRU[string, string](1000, nil, time.Hour)

// FetchGroupInfos retrieves all groups.
// Includes profile photos if the client has sufficient permissions.
func FetchGroupInfos(ctx context.Context, client *msgraphsdkgo.GraphServiceClient) (state.GroupInfoList, error) {
	result, err := client.Groups().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch groups: %w", err)
	}

	var groupInfos state.GroupInfoList
	if result != nil && result.GetValue() != nil {
		for _, item := range result.GetValue() {
			if group, ok := item.(*models.Group); ok {
				groupInfo := convertToGroupInfo(group)
				if groupInfo != nil {
					groupInfos = append(groupInfos, *groupInfo)
				}
			}
		}
	}

	return groupInfos, nil
}

// FetchUserGroupInfos retrieves all groups the specified user belongs to.
// Uses transitive membership to include nested groups.
// Requires application permission User.Read.All.
func FetchUserGroupInfos(ctx context.Context, client *msgraphsdkgo.GraphServiceClient, userID string) (state.GroupInfoList, error) {
	var (
		groupInfos state.GroupInfoList
		result     models.DirectoryObjectCollectionResponseable
		err        error
	)

	// Query user-specific endpoint with user ID (GUID or UPN/email)
	result, err = client.Users().ByUserId(userID).TransitiveMemberOf().Get(ctx, nil)
	if err != nil || result == nil || result.GetValue() == nil || len(result.GetValue()) == 0 {
		// The user is likely a guest user if that did not work, so look up their email to get the proper user ID.
		newUser, err := lookupGuestByEmail(ctx, client, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup user %s: %w", userID, err)
		}

		if newUser.GetId() == nil {
			// probably impossible
			return nil, fmt.Errorf("user %s has no id", userID)
		}

		result, err = client.Users().ByUserId(*newUser.GetId()).TransitiveMemberOf().Get(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch user infos for user %s: %w", userID, err)
		}

	}

	for _, item := range result.GetValue() {
		if group, ok := item.(*models.Group); ok {
			groupInfo := convertToGroupInfo(group)
			if groupInfo != nil {
				groupInfos = append(groupInfos, *groupInfo)
			}
		}
	}

	return groupInfos, nil
}

func lookupGuestByEmail(ctx context.Context, client *msgraphsdkgo.GraphServiceClient, email string) (models.Userable, error) {
	filter := fmt.Sprintf("mail eq '%[1]s' or userPrincipalName eq '%[1]s'", email)

	cfg := &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UsersRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	}

	result, err := client.Users().Get(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("searching for guest by email: %w", err)
	}

	if len(result.GetValue()) == 0 {
		return nil, fmt.Errorf("no user found for email %s", email)
	}

	return result.GetValue()[0], nil
}

// convertToGroupInfo converts a Microsoft Graph Group model to our GroupInfo structure.
func convertToGroupInfo(group *models.Group) *state.GroupInfo {
	id := getValue(group.GetId())
	if id == "" {
		return nil // Skip groups without IDs
	}

	name := getValue(group.GetDisplayName())
	if name == "" {
		name = "entra/" + id // Fallback if display name unavailable
	}

	groupInfo := &state.GroupInfo{
		ID:   "entra/" + id, // Add namespace prefix
		Name: name,
	}

	return groupInfo
}

// GetUser returns the authenticated user's id, name, and icon URL (data URL).
// Photo is fetched cache-first, then from the API on miss and cached.
func GetUserInfo(ctx context.Context, client *msgraphsdkgo.GraphServiceClient) (*UserInfo, error) {
	user, err := client.Me().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}

	var (
		userID = getValue(user.GetId())
		name   = getValue(user.GetDisplayName())
	)
	if name == "" {
		name = userID
	}

	info := &UserInfo{
		ID:   userID,
		Name: name,
	}

	// Cache-first lookup for photo
	cacheKey := fmt.Sprintf("user:%s", userID)
	if cachedPhoto, found := photoCache.Get(cacheKey); found {
		// Cache hit
		info.IconURL = cachedPhoto
	} else if dataURL := fetchUserPhoto(ctx, client); dataURL != "" {
		// Cache miss, fetch from API and cache
		photoCache.Add(cacheKey, dataURL)
		info.IconURL = dataURL
	}

	return info, nil
}

// fetchUserPhoto retrieves user photo directly from Microsoft Graph.
func fetchUserPhoto(ctx context.Context, client *msgraphsdkgo.GraphServiceClient) string {
	data, err := client.Me().Photo().Content().Get(ctx, nil)
	if err != nil || len(data) == 0 {
		return ""
	}

	return createPhotoDataURL(data)
}

// createPhotoDataURL converts binary image data to a base64 data URL.
// Detects image format and sets appropriate MIME type.
func createPhotoDataURL(data []byte) string {
	// Default to JPEG, detect PNG by magic bytes
	contentType := "image/jpeg"
	if len(data) >= 3 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E {
		contentType = "image/png"
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", contentType, encoded)
}

func getValue[T any](p *T) (v T) {
	if p == nil {
		return v
	}

	return *p
}
