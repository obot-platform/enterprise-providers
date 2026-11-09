package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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

// getAuthGroups serves GET /obot-get-auth-groups?ids=, which Obot calls to
// name group IDs it has not stored yet. A group's name is its ID without the
// prefix, so every ID in this provider's namespace resolves, whether or not it
// has been seen.
//
// It does not use authcommon's GetGroupsHandler, whose parser splits the
// comma-joined ids at every comma and so breaks an LDAP DN, the form
// PingFederate's groups usually take, into pieces. This keeps a DN whole when
// Obot sends it whole; Obot's own /api/groups?ids= also splits at commas
// before asking, which this provider cannot undo.
func (s *server) getAuthGroups(w http.ResponseWriter, r *http.Request) {
	names, err := parseGroupIDs(r.URL.Query().Get("ids"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authcommon.GroupList{Items: groupInfos(names)}); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode groups: %v", err), http.StatusInternalServerError)
	}
}

// parseGroupIDs reads Obot's comma-joined group IDs and returns the names of
// those in this provider's namespace, without the prefix. Obot joins the IDs
// with commas without escaping them, so a comma may separate two IDs or belong
// to an LDAP DN, the form PingFederate's groups usually take. A piece that
// starts with a provider prefix, such as "pingfederate/" or "entra/", starts a
// new ID; no DN component can, since an attribute type has no "/". Any other
// piece, or one that follows an escaped comma, continues the ID before it.
// IDs of other providers are dropped. Blank pieces between IDs or at the end
// are dropped too, while one inside an ID, such as an empty DN component, is
// kept so that the ID comes back as it was asked for.
func parseGroupIDs(raw string) ([]string, error) {
	if raw == "" {
		return nil, errors.New("ids is required")
	}
	var (
		ids     [][]string
		blanks  int // blank pieces after the current ID, kept only if it continues
		escaped bool
	)
	for _, piece := range strings.Split(raw, ",") {
		continues := escaped
		escaped = (len(piece)-len(strings.TrimRight(piece, `\`)))%2 == 1
		trimmed := strings.TrimSpace(piece)
		switch {
		case trimmed == "" && !continues:
			blanks++
		case !continues && groupIDStart.MatchString(trimmed):
			if len(ids) == authcommon.MaxGroupIDsPerRequest {
				return nil, fmt.Errorf("%w: limit is %d", authcommon.ErrTooManyIDs, authcommon.MaxGroupIDsPerRequest)
			}
			ids = append(ids, []string{piece})
			blanks = 0
		case len(ids) > 0:
			for ; blanks > 0; blanks-- {
				ids[len(ids)-1] = append(ids[len(ids)-1], "")
			}
			ids[len(ids)-1] = append(ids[len(ids)-1], piece)
		}
	}

	names := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, pieces := range ids {
		name, ok := strings.CutPrefix(strings.TrimSpace(strings.Join(pieces, ",")), groupIDPrefix)
		if !ok || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}

// groupIDStart matches the start of an Obot group ID: a provider prefix such as
// "pingfederate/".
var groupIDStart = regexp.MustCompile(`^[A-Za-z0-9_-]+/`)
