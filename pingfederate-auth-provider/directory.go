package main

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

const maxSeenGroups = 10000

// groupDirectory stands in for the group directory PingFederate does not
// expose. It holds the groups an administrator declared up front, so they can
// be given roles in Obot before any member has signed in, plus every group
// seen in a token since the provider started.
type groupDirectory struct {
	mu    sync.Mutex
	names map[string]struct{}
	// order remembers insertion order so that, when the directory is full,
	// the oldest sign-in groups are dropped first. Declared groups are never
	// dropped.
	order    []string
	declared map[string]struct{}
}

func newGroupDirectory(known []string) *groupDirectory {
	d := &groupDirectory{names: map[string]struct{}{}, declared: map[string]struct{}{}}
	for _, name := range known {
		if name = strings.TrimSpace(name); name != "" {
			d.names[name] = struct{}{}
			d.declared[name] = struct{}{}
		}
	}
	return d
}

// remember records groups seen in a user's claims.
func (d *groupDirectory) remember(groups []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, name := range groups {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		if _, ok := d.names[name]; ok {
			continue
		}
		d.names[name] = struct{}{}
		d.order = append(d.order, name)
		for len(d.order) > maxSeenGroups {
			delete(d.names, d.order[0])
			d.order = d.order[1:]
		}
	}
}

// list returns one page of groups whose name contains filter, sorted by
// name. The cursor is the last name of the previous page.
func (d *groupDirectory) list(filter string, limit int, cursor string) (state.GroupInfoList, string) {
	d.mu.Lock()
	names := make([]string, 0, len(d.names))
	for name := range d.names {
		if filter == "" || strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			names = append(names, name)
		}
	}
	d.mu.Unlock()

	sort.Slice(names, func(i, j int) bool {
		if a, b := strings.ToLower(names[i]), strings.ToLower(names[j]); a != b {
			return a < b
		}
		return names[i] < names[j]
	})

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
	return page, next
}

// fetchGroupPage returns one page of the directory for authcommon's
// ListGroupsHandler, which serves Obot's group search behind the group picker.
// The continuation token is the last name of the previous page.
func (s *server) fetchGroupPage(_ context.Context, req authcommon.PageRequest) (authcommon.PageResult, error) {
	items, next := s.directory.list(req.NameFilter, req.Limit, req.Cursor)
	return authcommon.PageResult{Items: items, NextCursor: next}, nil
}

// fetchGroupsByIDs resolves group IDs for authcommon's GetGroupsHandler. A
// group's name is its ID without the prefix, which authcommon has already
// removed, so every ID in this provider's namespace resolves, whether or not
// it has been seen.
func (s *server) fetchGroupsByIDs(_ context.Context, names []string) (state.GroupInfoList, error) {
	return groupInfos(names), nil
}
