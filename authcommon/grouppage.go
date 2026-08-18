package authcommon

import (
	"context"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
	"github.com/sahilm/fuzzy"
)

const (
	GroupCacheTTL        = time.Minute
	DefaultGroupPageSize = 50
	MaxGroupPageSize     = 500
)

// GroupPage is the response returned when the caller requests pagination.
type GroupPage struct {
	Items  state.GroupInfoList `json:"items"`
	Total  int                 `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
}

// GroupCache holds a complete group listing for a short period.
type GroupCache struct {
	mu        sync.Mutex
	groups    state.GroupInfoList
	fetchedAt time.Time
	ttl       time.Duration
}

func NewGroupCache(ttl time.Duration) *GroupCache {
	return &GroupCache{ttl: ttl}
}

// Get returns the cached listing, refreshing it through fetch when stale.
//
// The lock is deliberately held across the fetch so that concurrent requests coalesce into a
// single upstream enumeration rather than stampeding the identity provider.
func (c *GroupCache) Get(ctx context.Context, fetch func(context.Context) (state.GroupInfoList, error)) (state.GroupInfoList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.groups != nil && time.Since(c.fetchedAt) < c.ttl {
		return c.groups, nil
	}

	groups, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	if groups == nil {
		groups = state.GroupInfoList{}
	}

	c.groups = groups
	c.fetchedAt = time.Now()

	return groups, nil
}

// ParseGroupPageParams reads the pagination parameters. The boolean reports whether the caller
// asked for a page at all, which selects the response shape.
func ParseGroupPageParams(query url.Values) (limit int, offset int, paginated bool) {
	raw := query.Get("limit")
	if raw == "" {
		return 0, 0, false
	}

	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		limit = DefaultGroupPageSize
	}
	limit = min(limit, MaxGroupPageSize)

	if offset, err = strconv.Atoi(query.Get("offset")); err != nil || offset < 0 {
		offset = 0
	}

	return limit, offset, true
}

// filterGroups applies the optional name filter and returns the results in a stable order.
func filterGroups(groups state.GroupInfoList, nameFilter string) state.GroupInfoList {
	if nameFilter == "" {
		sorted := slices.Clone(groups)
		slices.SortFunc(sorted, func(a, b state.GroupInfo) int {
			if n := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); n != 0 {
				return n
			}
			return strings.Compare(a.ID, b.ID)
		})
		return sorted
	}

	if len(groups) == 0 {
		return state.GroupInfoList{}
	}

	names := make([]string, len(groups))
	for i, group := range groups {
		names[i] = group.Name
	}

	// fuzzy.Find orders by match quality. That ordering is deterministic for a given query, so it
	// is stable enough to page over while staying more useful than alphabetical for a search.
	matches := fuzzy.Find(nameFilter, names)
	filtered := make(state.GroupInfoList, 0, len(matches))
	for _, match := range matches {
		filtered = append(filtered, groups[match.Index])
	}

	return filtered
}

// pageGroups returns the requested window of an already-filtered listing.
func pageGroups(groups state.GroupInfoList, limit, offset int) state.GroupInfoList {
	if offset >= len(groups) {
		return state.GroupInfoList{}
	}
	return groups[offset:min(offset+limit, len(groups))]
}

// BuildGroupsResponse returns either the paginated envelope or the legacy bare array, depending on
// whether the caller asked for a page.
func BuildGroupsResponse(groups state.GroupInfoList, nameFilter string, limit, offset int, paginated bool) any {
	filtered := filterGroups(groups, nameFilter)
	if !paginated {
		return filtered
	}

	return GroupPage{
		Items:  pageGroups(filtered, limit, offset),
		Total:  len(filtered),
		Limit:  limit,
		Offset: offset,
	}
}
