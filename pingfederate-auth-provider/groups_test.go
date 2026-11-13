package main

import (
	"slices"
	"strings"
	"testing"
)

func TestGroupIDsRoundTrip(t *testing.T) {
	values := []string{
		"engineering",
		"cn=engineering,ou=groups,dc=example,dc=com",
		"100% done",
		"already%2Cescaped",
		"Sales, EMEA",
	}
	ids := make([]string, 0, len(values))
	for _, v := range values {
		id := groupInfo(v).ID
		native, ok := strings.CutPrefix(id, groupIDPrefix)
		if !ok {
			t.Fatalf("group ID %q is outside the prefix", id)
		}
		if strings.Contains(native, ",") {
			t.Fatalf("group ID %q contains a comma, which Obot uses to separate IDs", id)
		}
		ids = append(ids, native)
	}
	if got := groupValues(ids); !slices.Equal(got, values) {
		t.Fatalf("groupValues = %q, want %q", got, values)
	}
}

func TestGroupValuesDropsIDsThisProviderCannotIssue(t *testing.T) {
	// Only the canonical escaping of a value is accepted, so each group has exactly one ID.
	for _, id := range []string{"a,b", "%zz", "%41"} {
		if got := groupValues([]string{id}); len(got) != 0 {
			t.Errorf("groupValues(%q) = %q, want none", id, got)
		}
	}
}

func TestNormalizeGroups(t *testing.T) {
	got := normalizeGroups([]string{" b ", "a", "", "b", "  "})
	if want := []string{"a", "b"}; !slices.Equal(got, want) {
		t.Fatalf("normalizeGroups = %q, want %q", got, want)
	}
	if got := normalizeGroups(nil); got == nil || len(got) != 0 {
		t.Fatalf("normalizeGroups(nil) = %#v, want an empty, non-nil slice", got)
	}
}
