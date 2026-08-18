package authcommon

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

func makeGroups(n int) state.GroupInfoList {
	groups := make(state.GroupInfoList, 0, n)
	for i := range n {
		groups = append(groups, state.GroupInfo{
			ID:   fmt.Sprintf("grp/%04d", i),
			Name: fmt.Sprintf("group-%04d", i),
		})
	}
	return groups
}

func TestParseGroupPageParams(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		wantLimit     int
		wantOffset    int
		wantPaginated bool
	}{
		{
			name:          "no limit means legacy bare array",
			query:         "",
			wantPaginated: false,
		},
		{
			name:          "offset alone does not paginate",
			query:         "offset=10",
			wantPaginated: false,
		},
		{
			name:          "limit and offset",
			query:         "limit=25&offset=50",
			wantLimit:     25,
			wantOffset:    50,
			wantPaginated: true,
		},
		{
			name:          "limit defaults when unparseable",
			query:         "limit=abc",
			wantLimit:     DefaultGroupPageSize,
			wantPaginated: true,
		},
		{
			name:          "limit defaults when zero",
			query:         "limit=0",
			wantLimit:     DefaultGroupPageSize,
			wantPaginated: true,
		},
		{
			name:          "limit defaults when negative",
			query:         "limit=-5",
			wantLimit:     DefaultGroupPageSize,
			wantPaginated: true,
		},
		{
			name:          "limit is capped",
			query:         "limit=" + strconv.Itoa(MaxGroupPageSize+1),
			wantLimit:     MaxGroupPageSize,
			wantPaginated: true,
		},
		{
			name:          "negative offset clamps to zero",
			query:         "limit=10&offset=-3",
			wantLimit:     10,
			wantOffset:    0,
			wantPaginated: true,
		},
		{
			name:          "unparseable offset clamps to zero",
			query:         "limit=10&offset=xyz",
			wantLimit:     10,
			wantOffset:    0,
			wantPaginated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := url.ParseQuery(tt.query)
			if err != nil {
				t.Fatalf("bad test query: %v", err)
			}

			limit, offset, paginated := ParseGroupPageParams(query)
			if paginated != tt.wantPaginated {
				t.Fatalf("paginated = %v, want %v", paginated, tt.wantPaginated)
			}
			if !paginated {
				return
			}
			if limit != tt.wantLimit {
				t.Errorf("limit = %d, want %d", limit, tt.wantLimit)
			}
			if offset != tt.wantOffset {
				t.Errorf("offset = %d, want %d", offset, tt.wantOffset)
			}
		})
	}
}

func TestPageGroupsCoversEveryItem(t *testing.T) {
	const total = 10000
	groups := filterGroups(makeGroups(total), "")

	seen := make(map[string]struct{}, total)
	for offset := 0; offset < total; offset += 50 {
		for _, group := range pageGroups(groups, 50, offset) {
			if _, dup := seen[group.ID]; dup {
				t.Fatalf("group %s returned on more than one page", group.ID)
			}
			seen[group.ID] = struct{}{}
		}
	}

	if len(seen) != total {
		t.Fatalf("paged over %d groups, want %d", len(seen), total)
	}
}

func TestPageGroupsBoundaries(t *testing.T) {
	groups := makeGroups(10000)

	tests := []struct {
		name          string
		limit, offset int
		wantLen       int
		wantFirst     string
	}{
		{
			name:      "first page",
			limit:     50,
			offset:    0,
			wantLen:   50,
			wantFirst: "grp/0000",
		},
		{
			name:      "final full page",
			limit:     50,
			offset:    9950,
			wantLen:   50,
			wantFirst: "grp/9950",
		},
		{
			name:      "partial last page",
			limit:     50,
			offset:    9980,
			wantLen:   20,
			wantFirst: "grp/9980",
		},
		{
			name:    "offset at end",
			limit:   50,
			offset:  10000,
			wantLen: 0,
		},
		{
			name:    "offset past end",
			limit:   50,
			offset:  99999,
			wantLen: 0,
		},
		{
			name:      "limit exceeds remainder",
			limit:     500,
			offset:    9900,
			wantLen:   100,
			wantFirst: "grp/9900",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := pageGroups(groups, tt.limit, tt.offset)
			if len(page) != tt.wantLen {
				t.Fatalf("len = %d, want %d", len(page), tt.wantLen)
			}
			if tt.wantLen > 0 && page[0].ID != tt.wantFirst {
				t.Errorf("first = %s, want %s", page[0].ID, tt.wantFirst)
			}
		})
	}
}

func TestFilterGroupsSortsByNameWhenUnfiltered(t *testing.T) {
	groups := state.GroupInfoList{
		{
			ID:   "c",
			Name: "zeta",
		},
		{
			ID:   "a",
			Name: "Alpha",
		},
		{
			ID:   "b",
			Name: "beta",
		},
	}

	got := filterGroups(groups, "")
	want := []string{"Alpha", "beta", "zeta"}
	for i, name := range want {
		if got[i].Name != name {
			t.Errorf("position %d = %q, want %q", i, got[i].Name, name)
		}
	}

	// The input must not be reordered in place; it is the shared cached slice.
	if groups[0].Name != "zeta" {
		t.Errorf("filterGroups mutated its input: %q", groups[0].Name)
	}
}

func TestFilterGroupsIsStableAcrossCalls(t *testing.T) {
	groups := makeGroups(500)

	first := filterGroups(groups, "group-01")
	second := filterGroups(groups, "group-01")

	if len(first) != len(second) {
		t.Fatalf("result lengths differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatalf("ordering not stable at %d: %s vs %s", i, first[i].ID, second[i].ID)
		}
	}
}

func TestBuildGroupsResponseShape(t *testing.T) {
	groups := makeGroups(10000)

	t.Run("bare array without limit", func(t *testing.T) {
		payload := BuildGroupsResponse(groups, "", 0, 0, false)
		list, ok := payload.(state.GroupInfoList)
		if !ok {
			t.Fatalf("payload type = %T, want state.GroupInfoList", payload)
		}
		if len(list) != 10000 {
			t.Errorf("len = %d, want 10000", len(list))
		}
	})

	t.Run("envelope with limit", func(t *testing.T) {
		payload := BuildGroupsResponse(groups, "", 50, 9950, true)
		page, ok := payload.(GroupPage)
		if !ok {
			t.Fatalf("payload type = %T, want GroupPage", payload)
		}
		if page.Total != 10000 {
			t.Errorf("total = %d, want 10000", page.Total)
		}
		if len(page.Items) != 50 {
			t.Errorf("items = %d, want 50", len(page.Items))
		}
		if page.Limit != 50 || page.Offset != 9950 {
			t.Errorf("limit/offset = %d/%d, want 50/9950", page.Limit, page.Offset)
		}
	})

	t.Run("total reflects the filtered count", func(t *testing.T) {
		payload := BuildGroupsResponse(groups, "group-0001", 10, 0, true)
		page := payload.(GroupPage)
		if page.Total == 0 || page.Total >= 10000 {
			t.Errorf("total = %d, want a filtered count between 1 and 10000", page.Total)
		}
	})
}

func TestGroupCacheServesFromCacheWithinTTL(t *testing.T) {
	cache := NewGroupCache(time.Minute)

	var calls int
	fetch := func(context.Context) (state.GroupInfoList, error) {
		calls++
		return makeGroups(3), nil
	}

	for range 5 {
		got, err := cache.Get(t.Context(), fetch)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("len = %d, want 3", len(got))
		}
	}

	if calls != 1 {
		t.Errorf("upstream called %d times, want 1", calls)
	}
}

func TestGroupCacheRefetchesAfterTTL(t *testing.T) {
	cache := NewGroupCache(time.Nanosecond)

	var calls int
	fetch := func(context.Context) (state.GroupInfoList, error) {
		calls++
		return makeGroups(1), nil
	}

	if _, err := cache.Get(t.Context(), fetch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(time.Millisecond)
	if _, err := cache.Get(t.Context(), fetch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls != 2 {
		t.Errorf("upstream called %d times, want 2", calls)
	}
}

func TestGroupCacheDoesNotCacheErrors(t *testing.T) {
	cache := NewGroupCache(time.Minute)

	wantErr := errors.New("upstream down")
	if _, err := cache.Get(t.Context(), func(context.Context) (state.GroupInfoList, error) {
		return nil, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}

	got, err := cache.Get(t.Context(), func(context.Context) (state.GroupInfoList, error) {
		return makeGroups(2), nil
	})
	if err != nil {
		t.Fatalf("unexpected error after a failed fetch: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}

// TestGroupCacheCoalescesConcurrentFetches guards the property the lock exists for: a burst of
// requests against a cold cache must produce exactly one upstream enumeration.
func TestGroupCacheCoalescesConcurrentFetches(t *testing.T) {
	cache := NewGroupCache(time.Minute)

	var (
		mu    sync.Mutex
		calls int
	)
	fetch := func(context.Context) (state.GroupInfoList, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		return makeGroups(10), nil
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := cache.Get(t.Context(), fetch); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("upstream called %d times, want 1", calls)
	}
}
