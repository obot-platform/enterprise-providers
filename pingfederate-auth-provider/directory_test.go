package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

func listAuthGroups(t *testing.T, s *server, query string) (int, state.GroupInfoList, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/obot-list-auth-groups?"+query, nil)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	var page struct {
		Items      state.GroupInfoList `json:"items"`
		NextCursor string              `json:"nextCursor"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode page: %v", err)
		}
	}
	return rec.Code, page.Items, page.NextCursor
}

func TestDirectoryListsKnownAndSeenGroups(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	s.directory = newGroupDirectory([]string{"LDAP-Obot-Admins", " LDAP-Obot-Auditors ", ""}, s.store)

	status, items, next := listAuthGroups(t, s, "limit=50")
	if status != http.StatusOK || next != "" {
		t.Fatalf("status = %d next = %q", status, next)
	}
	if got := groupNames(items); got != "pingfederate/LDAP-Obot-Admins=LDAP-Obot-Admins,pingfederate/LDAP-Obot-Auditors=LDAP-Obot-Auditors" {
		t.Errorf("declared groups = %q", got)
	}

	s.rememberGroups(t.Context(), "sub-1", []string{"devs", "LDAP-Obot-Admins"}, time.Now())
	_, items, _ = listAuthGroups(t, s, "")
	if got := groupNames(items); got != "pingfederate/devs=devs,pingfederate/LDAP-Obot-Admins=LDAP-Obot-Admins,pingfederate/LDAP-Obot-Auditors=LDAP-Obot-Auditors" {
		t.Errorf("groups after sign-in = %q", got)
	}

	_, items, _ = listAuthGroups(t, s, "name=audit")
	if got := groupNames(items); got != "pingfederate/LDAP-Obot-Auditors=LDAP-Obot-Auditors" {
		t.Errorf("filtered groups = %q", got)
	}
}

func TestDirectoryPaginates(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	s.directory = newGroupDirectory([]string{"b", "a", "D", "c", "e"}, s.store)

	var all []string
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		status, items, next := listAuthGroups(t, s, "limit=2&cursor="+cursor)
		if status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
		for _, item := range items {
			all = append(all, item.Name)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if strings.Join(all, ",") != "a,b,c,D,e" {
		t.Errorf("paged names = %v", all)
	}

	for _, limit := range []string{"0", "x"} {
		if status, items, next := listAuthGroups(t, s, "limit="+limit); status != http.StatusOK || len(items) != 5 || next != "" {
			t.Errorf("limit=%s should use the default page size, got %d: %d items next=%q", limit, status, len(items), next)
		}
	}
	// authcommon binds cursors to this provider, the filter, and the limit, so
	// a cursor it did not mint is rejected and Obot restarts from the top.
	if status, _, _ := listAuthGroups(t, s, "cursor=zzz"); status != http.StatusBadRequest {
		t.Errorf("forged cursor: status = %d, want 400", status)
	}
}

func TestDirectoryDropsOldestSeenGroupsButKeepsDeclared(t *testing.T) {
	store := newMemoryGroupStore()
	d := newGroupDirectory([]string{"declared"}, store)
	for i := 0; i < maxSeenGroups+5; i++ {
		if err := store.addSeenGroups(t.Context(), []string{fmt.Sprintf("g%05d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	seen, err := store.seenGroups(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != maxSeenGroups || seen[0] != fmt.Sprintf("g%05d", maxSeenGroups+4) {
		t.Errorf("store holds %d seen groups, newest %q; want %d, newest first", len(seen), seen[0], maxSeenGroups)
	}
	items, _, err := d.list(t.Context(), "", 1, "")
	if err != nil || len(items) != 1 || items[0].Name != "declared" {
		t.Errorf("declared group was dropped: %v %v", items, err)
	}
	if items, _, _ := d.list(t.Context(), "g00000", 10, ""); len(items) != 0 {
		t.Errorf("oldest seen group should have been dropped, got %v", items)
	}
}

// getAuthGroups asks the way an Obot that predates the id parameter does: the
// IDs joined with commas in ids.
func getAuthGroups(t *testing.T, s *server, ids []string) (int, state.GroupInfoList) {
	t.Helper()
	q := url.Values{}
	q.Set("ids", strings.Join(ids, ","))
	return getAuthGroupsQuery(t, s, q)
}

func getAuthGroupsQuery(t *testing.T, s *server, q url.Values) (int, state.GroupInfoList) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/obot-get-auth-groups?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	var page struct {
		Items state.GroupInfoList `json:"items"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code, page.Items
}

func TestGetAuthGroupsResolvesIDsInNamespace(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	code, items := getAuthGroups(t, s, []string{"pingfederate/LDAP-Obot-Admins", "pingfederate/", " pingfederate/devs ", "pingfederate/devs"})
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if got := groupNames(items); got != "pingfederate/LDAP-Obot-Admins=LDAP-Obot-Admins,pingfederate/devs=devs" {
		t.Errorf("resolved = %q", got)
	}
	if code, _ := getAuthGroups(t, s, nil); code != http.StatusBadRequest {
		t.Errorf("without ids: status = %d, want 400", code)
	}
}

// An older Obot joins the IDs with unescaped commas, and PingFederate's groups
// are usually LDAP DNs, so every DN it sends whole must come back whole, under
// the exact ID it asked for.
func TestGetAuthGroupsKeepsDNsWhole(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	ids := []string{
		"pingfederate/cn=group.0,ou=Groups,dc=example,dc=com",
		"pingfederate/devs",
		"pingfederate/cn=Smith\\, John,ou=People, dc=example,dc=com",
		"pingfederate/cn=a/b,ou=Groups",
	}
	code, items := getAuthGroups(t, s, ids)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if len(items) != len(ids) {
		t.Fatalf("resolved %d groups, want %d: %+v", len(items), len(ids), items)
	}
	for i, id := range ids {
		if items[i].ID != id || items[i].Name != strings.TrimPrefix(id, groupIDPrefix) {
			t.Errorf("group %d = %+v, want ID %q", i, items[i], id)
		}
	}
}

// Obot sends each ID whole in a repeated id parameter, alongside the same IDs
// joined in ids (pkg/gateway/client/group.go). The id parameters are what
// count, so DNs come back exactly as asked for even where the comma-joined
// list could not be split back into them.
func TestGetAuthGroupsReadsRepeatedID(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	ids := []string{
		"pingfederate/cn=Admins,ou=Groups,dc=example,dc=com",
		// Ends like the DN above, which a comma-joined list deduplicated by
		// pieces would lose.
		"pingfederate/cn=Devs,ou=Groups,dc=example,dc=com",
		"pingfederate/Sales, EMEA/North",
	}
	q := url.Values{"id": append(slices.Clone(ids), "entra/1234", "pingfederate/", ids[0])}
	q.Set("ids", "pingfederate/cn=Admins,ou=Groups,dc=example,dc=com,pingfederate/cn=Devs")

	code, items := getAuthGroupsQuery(t, s, q)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if len(items) != len(ids) {
		t.Fatalf("resolved %+v, want %q", items, ids)
	}
	for i, id := range ids {
		if items[i].ID != id || items[i].Name != strings.TrimPrefix(id, groupIDPrefix) {
			t.Errorf("group %d = %+v, want ID %q", i, items[i], id)
		}
	}

	tooMany := url.Values{}
	for i := range authcommon.MaxGroupIDsPerRequest + 1 {
		tooMany.Add("id", fmt.Sprintf("pingfederate/g%d", i))
	}
	if code, _ := getAuthGroupsQuery(t, s, tooMany); code != http.StatusBadRequest {
		t.Errorf("%d ids: status = %d, want 400", authcommon.MaxGroupIDsPerRequest+1, code)
	}
}

func TestParseGroupIDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "plain names",
			raw:  "pingfederate/a,pingfederate/b",
			want: []string{"a", "b"},
		},
		{
			name: "DNs",
			raw:  "pingfederate/cn=a,ou=x,pingfederate/cn=b,ou=y",
			want: []string{"cn=a,ou=x", "cn=b,ou=y"},
		},
		{
			name: "pieces before the first ID are dropped",
			raw:  "ou=x,dc=y,pingfederate/a",
			want: []string{"a"},
		},
		{
			name: "duplicates and empty names are dropped",
			raw:  "pingfederate/a,pingfederate/,pingfederate/a",
			want: []string{"a"},
		},
		{
			name: "other providers' IDs are dropped, not joined onto a DN",
			raw:  "pingfederate/cn=a,ou=x,entra/1234,pingfederate/b,okta/cn=c,ou=y",
			want: []string{"cn=a,ou=x", "b"},
		},
		{
			name: "blank pieces between IDs or at the end are skipped",
			raw:  "pingfederate/a,,pingfederate/b, ,",
			want: []string{"a", "b"},
		},
		{
			name: "an empty DN component is kept",
			raw:  "pingfederate/cn=a,,ou=x,pingfederate/b",
			want: []string{"cn=a,,ou=x", "b"},
		},
		{
			name: "a blank escaped component is kept",
			raw:  `pingfederate/cn=a\, ,ou=x,pingfederate/b`,
			want: []string{`cn=a\, ,ou=x`, "b"},
		},
		{
			name: "a piece after an escaped comma continues the DN",
			raw:  `pingfederate/cn=Smith\, Jr/Sr,ou=People,pingfederate/b`,
			want: []string{`cn=Smith\, Jr/Sr,ou=People`, "b"},
		},
		{
			name: "an escaped backslash does not escape the comma after it",
			raw:  `pingfederate/cn=a\\,pingfederate/b`,
			want: []string{`cn=a\\`, "b"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGroupIDs(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("parseGroupIDs(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// The limit counts IDs, not the commas inside them.
func TestParseGroupIDsLimitCountsWholeIDs(t *testing.T) {
	dns := make([]string, authcommon.MaxGroupIDsPerRequest)
	for i := range dns {
		dns[i] = fmt.Sprintf("pingfederate/cn=group.%d,ou=Groups,dc=example,dc=com", i)
	}
	if got, err := parseGroupIDs(strings.Join(dns, ",")); err != nil || len(got) != len(dns) {
		t.Errorf("%d DNs: %d names, err = %v", len(dns), len(got), err)
	}
	dns = append(dns, "pingfederate/one-too-many")
	if _, err := parseGroupIDs(strings.Join(dns, ",")); !errors.Is(err, authcommon.ErrTooManyIDs) {
		t.Errorf("%d IDs: err = %v, want ErrTooManyIDs", len(dns), err)
	}
}

// Parsing takes time in proportion to the input, however many of its commas
// belong to one ID.
func TestParseGroupIDsIsLinear(t *testing.T) {
	raw := "pingfederate/cn=a" + strings.Repeat(",ou=x", 200_000)
	start := time.Now()
	names, err := parseGroupIDs(raw)
	if err != nil || len(names) != 1 {
		t.Fatalf("names = %d, err = %v", len(names), err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("parsing %d bytes took %v", len(raw), elapsed)
	}
}

func TestSplitLines(t *testing.T) {
	// One per line; commas belong to the name, as in an LDAP DN.
	got := splitLines("LDAP-Admins\ncn=engineering,ou=groups,dc=example,dc=com\n\n Domain Users \r\nLDAP-Admins")
	if strings.Join(got, "|") != "LDAP-Admins|cn=engineering,ou=groups,dc=example,dc=com|Domain Users" {
		t.Errorf("splitLines = %v", got)
	}
	if splitLines("") != nil {
		t.Error("empty input should give nil")
	}
}
