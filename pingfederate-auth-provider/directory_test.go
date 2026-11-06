package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

	s.rememberGroups(t.Context(), "tok", "sub-1", []string{"devs", "LDAP-Obot-Admins"})
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

func TestGetAuthGroupsResolvesIDsInNamespace(t *testing.T) {
	s := newTestServer(t, "", time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/obot-get-auth-groups?ids=pingfederate%2FLDAP-Obot-Admins,other%2Fx,pingfederate%2F,%20pingfederate%2Fdevs%20", nil)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var page struct {
		Items state.GroupInfoList `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if got := groupNames(page.Items); got != "pingfederate/LDAP-Obot-Admins=LDAP-Obot-Admins,pingfederate/devs=devs" {
		t.Errorf("resolved = %q", got)
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
