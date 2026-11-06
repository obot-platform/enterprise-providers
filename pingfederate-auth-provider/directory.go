package main

import (
	"context"
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

// fetchGroupsByIDs resolves group IDs for authcommon's GetGroupsHandler. A
// group's name is its ID without the prefix, which authcommon has already
// removed, so every ID in this provider's namespace resolves, whether or not
// it has been seen.
func (s *server) fetchGroupsByIDs(_ context.Context, names []string) (state.GroupInfoList, error) {
	return groupInfos(names), nil
}
