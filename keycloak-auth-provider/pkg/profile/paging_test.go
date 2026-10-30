package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/enterprise-providers/authcommon"
)

func TestNativePagesReadOnlyRequestedWindow(t *testing.T) {
	var calls atomic.Int32
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		q := r.URL.Query()
		offset, _ := strconv.Atoi(q.Get("first"))
		limit, _ := strconv.Atoi(q.Get("max"))
		exact := q.Get("exact") == "true"
		if q.Get("populateHierarchy") != "false" || q.Get("briefRepresentation") != "true" || q.Get("subGroupsCount") != "false" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
		if exact {
			if limit != maxGroups+1 || offset != 0 {
				t.Errorf("unexpected exact lookup %s", r.URL.RawQuery)
			}
			index, err := strconv.Atoi(strings.TrimPrefix(q.Get("search"), "Group"))
			if err != nil {
				t.Error(err)
			}
			offset, limit = index, 1
		} else if (limit != 50 && limit != 51) || q.Get("search") != " " {
			t.Errorf("unexpected native window %s", r.URL.RawQuery)
		}
		groups := []group{}
		for i := offset; i < min(offset+limit, 20001); i++ {
			groups = append(groups, group{
				ID:   fmt.Sprintf("id-%05d", i),
				Name: fmt.Sprintf("Group%05d", i),
				Path: fmt.Sprintf("/Group%05d", i),
			})
		}
		if err := json.NewEncoder(w).Encode(groups); err != nil {
			t.Error(err)
		}
	})
	for _, offset := range []int{0, 15000, 20000} {
		cursor := ""
		if offset != 0 {
			raw, err := json.Marshal(groupCursor{Offset: offset})
			if err != nil {
				t.Fatal(err)
			}
			cursor = string(raw)
		}
		before := calls.Load()
		page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: 50, Cursor: cursor})
		wantCalls := int32(3)
		if offset == 20000 {
			wantCalls = 1
		}
		if err != nil || len(page.Items) != min(50, 20001-offset) || calls.Load()-before != wantCalls {
			t.Fatalf("offset=%d count=%d calls=%d error=%v", offset, len(page.Items), calls.Load()-before, err)
		}
		if page.Items[0].ID != fmt.Sprintf("keycloak/id-%05d", offset) || (offset == 20000 && page.NextCursor != "") {
			t.Fatalf("incorrect native page: %+v", page)
		}
	}
}

func TestNativePagesDoNotLoseDuplicateNames(t *testing.T) {
	all := []group{
		{
			ID:   "a",
			Name: "Alpha",
			Path: "/Alpha",
		},
		{
			ID:   "z",
			Name: "Zulu",
			Path: "/Zulu",
		},
	}
	for i := range 54 {
		all = append(all, group{
			ID:       fmt.Sprintf("shared-%03d", i),
			Name:     "Shared",
			Path:     fmt.Sprintf("/Department%03d/Shared", i),
			ParentID: fmt.Sprintf("parent-%03d", i),
		})
	}
	for _, filter := range []string{"", "Shared"} {
		for _, limit := range []int{1, 2, 4, 7, 50, 100} {
			t.Run(fmt.Sprintf("filter=%s/limit=%d", filter, limit), func(t *testing.T) {
				c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
					q := r.URL.Query()
					offset, _ := strconv.Atoi(q.Get("first"))
					max, _ := strconv.Atoi(q.Get("max"))
					groups := []group{}
					for _, g := range all {
						if strings.TrimSpace(q.Get("search")) == "" || g.Name == q.Get("search") {
							groups = append(groups, g)
						}
					}
					// Reorder ties across requests, as observed in unchanged live realms.
					sort.Slice(groups, func(i, j int) bool {
						if groups[i].Name != groups[j].Name {
							return groups[i].Name < groups[j].Name
						}
						if offset%2 == 0 {
							return groups[i].ID > groups[j].ID
						}
						return groups[i].ID < groups[j].ID
					})
					groups = groups[min(offset, len(groups)):min(offset+max, len(groups))]
					if err := json.NewEncoder(w).Encode(groups); err != nil {
						t.Error(err)
					}
				})
				cursor := ""
				seen := map[string]bool{}
				for pageNumber := 0; ; pageNumber++ {
					if pageNumber > 60 {
						t.Fatal("pagination did not terminate")
					}
					page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: limit, NameFilter: filter, Cursor: cursor})
					if err != nil || len(page.Items) > limit {
						t.Fatalf("page %+v error %v", page, err)
					}
					for _, item := range page.Items {
						if seen[item.ID] {
							t.Fatalf("duplicate ID %s", item.ID)
						}
						seen[item.ID] = true
					}
					cursor = page.NextCursor
					if cursor == "" {
						break
					}
				}
				want := len(all)
				if filter != "" {
					want -= 2
				}
				if len(seen) != want {
					t.Fatalf("groups=%d want=%d", len(seen), want)
				}
			})
		}
	}
}

func TestNativePageValidationAndCancellation(t *testing.T) {
	c := directoryFixture(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("invalid cursor reached Keycloak") })
	for _, cursor := range []string{"-1", "old-snapshot-cursor", `{"offset":-1}`, `{"offset":2147483647}`, `{"after":"id"}`} {
		if _, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: 50, Cursor: cursor}); !errors.Is(err, authcommon.ErrInvalidCursor) {
			t.Fatalf("cursor %q error=%v", cursor, err)
		}
	}
	for _, limit := range []int{0, -1, 101} {
		if _, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: limit}); err == nil {
			t.Fatal("invalid limit accepted")
		}
	}
	started := make(chan struct{})
	c = directoryFixture(t, func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := FetchGroupPage(ctx, c, authcommon.PageRequest{Limit: 50})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("group page ignored caller cancellation")
	}
}

func TestNativePageRejectsIncompleteResults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "permission denied",
			status: http.StatusForbidden,
			body:   `[]`,
		},
		{
			name:   "null page",
			status: http.StatusOK,
			body:   `null`,
		},
		{
			name:   "missing native name",
			status: http.StatusOK,
			body:   `[{"id":"a","path":"/Alpha"}]`,
		},
		{
			name:   "hierarchical results",
			status: http.StatusOK,
			body:   `[{"id":"a","name":"Alpha","path":"/Alpha","subGroups":[{"id":"b","name":"Beta","path":"/Alpha/Beta"}]}]`,
		},
		{
			name:   "duplicate native ID",
			status: http.StatusOK,
			body:   `[{"id":"a","name":"Alpha","path":"/Alpha"},{"id":"a","name":"Alpha","path":"/Alpha"}]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := directoryFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Error(err)
				}
			})
			page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: 4})
			if err == nil || len(page.Items) != 0 || page.NextCursor != "" {
				t.Fatalf("invalid response returned a successful page: %+v, %v", page, err)
			}
		})
	}
}

func TestNativePageDiscardsPrefixWhenTieLookupFails(t *testing.T) {
	var calls atomic.Int32
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("exact") == "true" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		groups := []group{
			{ID: "a", Name: "Alpha", Path: "/Alpha"},
			{ID: "s1", Name: "Shared", Path: "/A/Shared"},
			{ID: "s2", Name: "Shared", Path: "/B/Shared"},
		}
		max, _ := strconv.Atoi(r.URL.Query().Get("max"))
		if err := json.NewEncoder(w).Encode(groups[:min(max, len(groups))]); err != nil {
			t.Error(err)
		}
	})
	page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: 2})
	if err == nil || len(page.Items) != 0 || page.NextCursor != "" || calls.Load() != 3 {
		t.Fatalf("tie failure returned a partial page: %+v, %v, calls=%d", page, err, calls.Load())
	}
}

func TestNativePagesUseDatabaseCollationForBoundaryCohorts(t *testing.T) {
	all := []group{}
	for i, name := range []string{"Admins", "admins", "Ádmins", "ádmins", "Admins", "Administrators", "Beta", "Zulu"} {
		all = append(all, group{
			ID:   fmt.Sprintf("group-%02d", i),
			Name: name,
			Path: fmt.Sprintf("/Department%02d/%s", i, name),
		})
	}
	var sawFourReads bool
	for _, collation := range []struct {
		name string
		key  func(string) string
	}{
		{
			name: "case sensitive",
			key:  func(s string) string { return s },
		},
		{
			name: "case insensitive",
			key:  strings.ToLower,
		},
		{
			name: "case and accent insensitive",
			key: func(s string) string {
				return strings.NewReplacer("á", "a", "é", "e").Replace(strings.ToLower(s))
			},
		},
	} {
		for _, filter := range []string{"", "adm"} {
			for _, limit := range []int{1, 2, 3, 4, 7, 100} {
				t.Run(fmt.Sprintf("%s/filter=%s/limit=%d", collation.name, filter, limit), func(t *testing.T) {
					var calls, nativeCalls atomic.Int32
					c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						q := r.URL.Query()
						offset, _ := strconv.Atoi(q.Get("first"))
						max, _ := strconv.Atoi(q.Get("max"))
						exact := q.Get("exact") == "true"
						search := strings.TrimSpace(q.Get("search"))
						if exact && (offset != 0 || max != maxGroups+1) {
							t.Errorf("unbounded or offset exact lookup: %s", r.URL.RawQuery)
						} else if !exact && (max <= 0 || max > limit+1) {
							t.Errorf("oversized native window: %s", r.URL.RawQuery)
						}
						groups := []group{}
						for _, g := range all {
							matches := search == "" || strings.Contains(strings.ToLower(collation.key(g.Name)), strings.ToLower(collation.key(search)))
							if exact {
								matches = collation.key(g.Name) == collation.key(search)
							}
							if matches {
								groups = append(groups, g)
							}
						}
						var sequence int32
						if !exact {
							sequence = nativeCalls.Add(1)
						}
						// Simulate changing order among all database-equivalent names,
						// including spellings which Go string equality distinguishes.
						sort.Slice(groups, func(i, j int) bool {
							left, right := collation.key(groups[i].Name), collation.key(groups[j].Name)
							if left != right {
								return left < right
							}
							if sequence%2 == 0 {
								return groups[i].ID > groups[j].ID
							}
							return groups[i].ID < groups[j].ID
						})
						groups = groups[min(offset, len(groups)):min(offset+max, len(groups))]
						// Keycloak sorts each SQL window again using Java String order.
						sort.SliceStable(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
						if err := json.NewEncoder(w).Encode(groups); err != nil {
							t.Error(err)
						}
					})
					seen := map[string]bool{}
					cursor := ""
					for pageNumber := 0; ; pageNumber++ {
						if pageNumber > len(all)+1 {
							t.Fatal("pagination did not terminate")
						}
						before := calls.Load()
						page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{
							Limit:      limit,
							Cursor:     cursor,
							NameFilter: filter,
						})
						if err != nil || len(page.Items) > limit {
							t.Fatalf("page=%+v error=%v", page, err)
						}
						readCount := calls.Load() - before
						if readCount > 4 {
							t.Fatalf("page made %d directory reads", readCount)
						}
						if readCount == 4 {
							sawFourReads = true
						}
						for _, item := range page.Items {
							if seen[item.ID] {
								t.Fatalf("duplicate group %s", item.ID)
							}
							seen[item.ID] = true
						}
						cursor = page.NextCursor
						if cursor == "" {
							break
						}
					}
					for _, g := range all {
						matches := filter == "" || strings.Contains(strings.ToLower(collation.key(g.Name)), strings.ToLower(collation.key(filter)))
						if seen["keycloak/"+g.ID] != matches {
							t.Fatalf("group %s listed=%v expected=%v", g.ID, seen["keycloak/"+g.ID], matches)
						}
					}
				})
			}
		}
	}
	if !sawFourReads {
		t.Fatal("fixture did not exercise a prior cohort, two native windows and boundary lookup in one page")
	}
}

func TestNativePageRequiresLookaheadInExactCohort(t *testing.T) {
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		groups := []group{
			{
				ID:   "a",
				Name: "Alpha",
				Path: "/Alpha",
			},
			{
				ID:   "b",
				Name: "Beta",
				Path: "/Beta",
			},
		}
		if r.URL.Query().Get("exact") == "true" {
			groups = groups[:1]
		}
		max, _ := strconv.Atoi(r.URL.Query().Get("max"))
		if err := json.NewEncoder(w).Encode(groups[:min(max, len(groups))]); err != nil {
			t.Error(err)
		}
	})
	page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: 1})
	if !errors.Is(err, authcommon.ErrInvalidCursor) || len(page.Items) != 0 || page.NextCursor != "" {
		t.Fatalf("changed boundary cohort returned a partial page: %+v, %v", page, err)
	}
}

func TestNativePagePaddedNameErrorsExplainRequiredRename(t *testing.T) {
	for _, name := range []string{" Team", "Team ", "\tTeam\n"} {
		for _, continuation := range []bool{false, true} {
			for _, emptyCohort := range []bool{false, true} {
				t.Run(fmt.Sprintf("name=%q/continuation=%t/empty=%t", name, continuation, emptyCohort), func(t *testing.T) {
					var calls atomic.Int32
					c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						groups := []group{
							{
								ID:   "plain",
								Name: "Team",
								Path: "/Team",
							},
						}
						if r.URL.Query().Get("exact") == "true" {
							// Reproduce GroupsResource's Java String.trim(): the
							// raw padded name cannot roundtrip to its stored ID.
							search := strings.TrimFunc(r.URL.Query().Get("search"), func(r rune) bool { return r <= 0x20 })
							if search != "Team" {
								t.Errorf("unexpected exact query %q", search)
							}
							if emptyCohort {
								groups = []group{}
							}
						} else {
							groups = append(groups, group{
								ID:   "padded",
								Name: name,
								Path: "/Parent/" + name,
							})
						}
						max, _ := strconv.Atoi(r.URL.Query().Get("max"))
						if err := json.NewEncoder(w).Encode(groups[:min(max, len(groups))]); err != nil {
							t.Error(err)
						}
					})
					cursor := ""
					if continuation {
						raw, err := json.Marshal(groupCursor{
							Name:    name,
							AfterID: "padded",
						})
						if err != nil {
							t.Fatal(err)
						}
						cursor = string(raw)
					}
					page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{
						Limit:  1,
						Cursor: cursor,
					})
					if err == nil || errors.Is(err, authcommon.ErrInvalidCursor) || !strings.Contains(err.Error(), "rename group") || len(page.Items) != 0 || page.NextCursor != "" {
						t.Fatalf("padded name did not produce an actionable compatibility error: page=%+v, err=%v", page, err)
					}
					wantCalls := int32(3)
					if continuation {
						wantCalls = 1
					}
					if calls.Load() != wantCalls {
						t.Fatalf("compatibility error made %d requests, want %d", calls.Load(), wantCalls)
					}
				})
			}
		}
	}
}

func TestNativePagePaddedNamesWorkWhenDatabaseRoundtripsIDs(t *testing.T) {
	all := []group{
		{
			ID:   "a",
			Name: "Team",
			Path: "/Team",
		},
		{
			ID:   "b",
			Name: "Team ",
			Path: "/Parent/Team ",
		},
	}
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		groups := all
		if r.URL.Query().Get("exact") != "true" {
			offset, _ := strconv.Atoi(r.URL.Query().Get("first"))
			limit, _ := strconv.Atoi(r.URL.Query().Get("max"))
			groups = all[min(offset, len(all)):min(offset+limit, len(all))]
		}
		// Simulate a PAD SPACE database whose exact equality includes both
		// records despite the API trimming the trailing space in search.
		if err := json.NewEncoder(w).Encode(groups); err != nil {
			t.Error(err)
		}
	})
	seen := map[string]bool{}
	cursor := ""
	for pageNumber := 0; ; pageNumber++ {
		if pageNumber > 3 {
			t.Fatal("pagination did not terminate")
		}
		page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{
			Limit:  1,
			Cursor: cursor,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range page.Items {
			if seen[g.ID] {
				t.Fatalf("duplicate padded cohort ID %s", g.ID)
			}
			seen[g.ID] = true
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if !seen["keycloak/a"] || !seen["keycloak/b"] || len(seen) != 2 {
		t.Fatalf("padded cohort did not preserve both IDs: %+v", seen)
	}
}

func TestNativePageDoesNotTreatUnicodeSpaceAsJavaTrimPadding(t *testing.T) {
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		groups := []group{}
		if r.URL.Query().Get("exact") != "true" {
			groups = []group{
				{
					ID:   "a",
					Name: "Alpha",
					Path: "/Alpha",
				},
				{
					ID:   "b",
					Name: "Team\u00a0",
					Path: "/Team\u00a0",
				},
			}
		}
		max, _ := strconv.Atoi(r.URL.Query().Get("max"))
		if err := json.NewEncoder(w).Encode(groups[:min(max, len(groups))]); err != nil {
			t.Error(err)
		}
	})
	_, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: 1})
	if !errors.Is(err, authcommon.ErrInvalidCursor) {
		t.Fatalf("Unicode space was incorrectly treated as Java trim padding: %v", err)
	}
}

func TestNativePagesWithResortedMixedCaseWindow(t *testing.T) {
	// Database order differs from the Java order applied after selecting each window.
	all := []group{{ID: "a", Name: "alpha", Path: "/alpha"}, {ID: "b", Name: "Beta", Path: "/Beta"}}
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		rows := append([]group{}, all...)
		if q.Get("exact") == "true" {
			rows = []group{}
			for _, g := range all {
				if g.Name == q.Get("search") {
					rows = append(rows, g)
				}
			}
		}
		first, _ := strconv.Atoi(q.Get("first"))
		max, _ := strconv.Atoi(q.Get("max"))
		rows = rows[min(first, len(rows)):min(first+max, len(rows))]
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		if err := json.NewEncoder(w).Encode(rows); err != nil {
			t.Error(err)
		}
	})
	cursor := ""
	var got []string
	for n := 0; n < 3; n++ {
		page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range page.Items {
			got = append(got, g.ID)
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(got) != 2 || got[0] != "keycloak/a" || got[1] != "keycloak/b" || cursor != "" {
		t.Fatalf("expected each of keycloak/a and keycloak/b once; got %v", got)
	}
}

func TestNativePagesRejectInconsistentWindows(t *testing.T) {
	alpha := group{ID: "a", Name: "alpha", Path: "/alpha"}
	beta := group{ID: "b", Name: "Beta", Path: "/Beta"}
	gamma := group{ID: "c", Name: "gamma", Path: "/gamma"}
	other := group{ID: "d", Name: "delta", Path: "/delta"}
	for _, tc := range []struct {
		name   string
		wide   []group
		narrow []group
		status int
	}{
		{name: "shortened window", wide: []group{alpha, beta, gamma}, narrow: []group{alpha}},
		{name: "replacement outside boundary cohort", wide: []group{alpha, beta, gamma}, narrow: []group{alpha, other}},
		{name: "removed prefix outside boundary cohort", wide: []group{alpha, beta, gamma}, narrow: []group{beta, other}},
		{name: "renamed common group", wide: []group{alpha, beta, gamma}, narrow: []group{{ID: "a", Name: "renamed", Path: "/renamed"}, beta}},
		{name: "window read forbidden", wide: []group{alpha, beta, gamma}, status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				rows := tc.wide
				if q.Get("exact") == "true" {
					rows = []group{}
					for _, g := range tc.wide {
						if g.Name == q.Get("search") {
							rows = append(rows, g)
						}
					}
				} else if q.Get("max") == "2" {
					if tc.status != 0 {
						w.WriteHeader(tc.status)
						return
					}
					rows = tc.narrow
				}
				if err := json.NewEncoder(w).Encode(rows); err != nil {
					t.Error(err)
				}
			})
			page, err := FetchGroupPage(t.Context(), c, authcommon.PageRequest{Limit: 2})
			if err == nil || len(page.Items) != 0 || page.NextCursor != "" {
				t.Fatalf("inconsistent windows returned a partial page: %+v, %v", page, err)
			}
			if tc.status == 0 && !errors.Is(err, authcommon.ErrInvalidCursor) {
				t.Fatalf("expected restartable cursor error, got %v", err)
			}
		})
	}
}
