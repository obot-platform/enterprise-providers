package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// groupDirectory stands in for the directory PingFederate does not expose:
// the declared Known Groups plus the groups seen in users' claims.
type groupDirectory struct {
	declared []string
	store    groupStore
}

func newGroupDirectory(known []string, store groupStore) *groupDirectory {
	return &groupDirectory{declared: filterGroups(known), store: store}
}

// list returns a page of groups whose name contains filter, sorted by name,
// after the cursor, the last name of the previous page.
func (d *groupDirectory) list(ctx context.Context, filter string, limit int, cursor string) (state.GroupInfoList, string, error) {
	seen, err := d.store.seenGroups(ctx)
	if err != nil {
		return nil, "", err
	}
	all := filterGroups(append(append([]string{}, d.declared...), seen...))
	names := make([]string, 0, len(all))
	for _, name := range all {
		if filter == "" || strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			names = append(names, name)
		}
	}
	sortGroupNames(names)

	start := 0
	if cursor != "" {
		start = sort.Search(len(names), func(i int) bool {
			if a, b := strings.ToLower(names[i]), strings.ToLower(cursor); a != b {
				return a > b
			}
			return names[i] > cursor
		})
	}
	end := min(start+limit, len(names))
	page := groupInfos(names[start:end])
	next := ""
	if end < len(names) {
		next = names[end-1]
	}
	return page, next, nil
}

// fetchGroupPage serves Obot's group picker through authcommon.
func (s *server) fetchGroupPage(ctx context.Context, req authcommon.PageRequest) (authcommon.PageResult, error) {
	items, next, err := s.directory.list(ctx, req.NameFilter, req.Limit, req.Cursor)
	if err != nil {
		return authcommon.PageResult{}, err
	}
	return authcommon.PageResult{Items: items, NextCursor: next}, nil
}

// getAuthGroups names the group IDs Obot sends, each in its own id parameter.
// A group's name is its ID without the prefix. The comma-joined ids that Obot
// also sends, for other providers, is ignored: it cannot carry an LDAP DN.
func (s *server) getAuthGroups(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["id"]
	if !slices.ContainsFunc(ids, func(id string) bool { return strings.TrimSpace(id) != "" }) {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	names, err := namesInNamespace(ids)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authcommon.GroupList{Items: groupInfos(names)}); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode groups: %v", err), http.StatusInternalServerError)
	}
}

// namesInNamespace returns the names of the IDs in this provider's namespace,
// without blanks or duplicates.
func namesInNamespace(ids []string) ([]string, error) {
	if len(ids) > authcommon.MaxGroupIDsPerRequest {
		return nil, fmt.Errorf("%w: %d ids, limit is %d", authcommon.ErrTooManyIDs, len(ids), authcommon.MaxGroupIDsPerRequest)
	}
	names := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		name, ok := strings.CutPrefix(strings.TrimSpace(id), groupIDPrefix)
		if !ok || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}
