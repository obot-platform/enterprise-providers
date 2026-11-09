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

// groupDirectory stands in for the group directory PingFederate does not
// expose. It lists the groups an administrator declared up front, so they can
// be given roles in Obot before any member has signed in, plus the groups the
// store has seen in users' claims.
type groupDirectory struct {
	declared []string
	store    groupStore
}

func newGroupDirectory(known []string, store groupStore) *groupDirectory {
	return &groupDirectory{declared: filterGroups(known), store: store}
}

// list returns one page of groups whose name contains filter, sorted by
// name. The cursor is the last name of the previous page.
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

// fetchGroupPage returns one page of the directory for authcommon's
// ListGroupsHandler, which serves Obot's group search behind the group picker.
// The continuation token is the last name of the previous page.
func (s *server) fetchGroupPage(ctx context.Context, req authcommon.PageRequest) (authcommon.PageResult, error) {
	items, next, err := s.directory.list(ctx, req.NameFilter, req.Limit, req.Cursor)
	if err != nil {
		return authcommon.PageResult{}, err
	}
	return authcommon.PageResult{Items: items, NextCursor: next}, nil
}

// getAuthGroups serves GET /obot-get-auth-groups, which Obot calls to name
// group IDs it has not stored yet. A group's name is its ID without the prefix,
// so every ID in this provider's namespace resolves, whether or not it has been
// seen.
//
// Obot sends each ID whole in a repeated id parameter, and the same IDs joined
// with commas in ids for the providers that read only that. This provider reads
// only id: PingFederate's groups are usually LDAP DNs, which contain commas, so
// the comma-joined list cannot be split back into them. It does not use
// authcommon's GetGroupsHandler, which reads ids.
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

// namesInNamespace returns the names of the whole group IDs in this provider's
// namespace, without the prefix. Other providers' IDs, blanks, and duplicates
// are dropped.
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
