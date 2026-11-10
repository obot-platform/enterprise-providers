package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

const (
	// providerKind must match the manifest's groupIDPrefix without its trailing slash.
	providerKind  = "pingfederate"
	groupIDPrefix = providerKind + "/"

	// maxRememberedUsers bounds the in-memory record of what was last written for each user.
	maxRememberedUsers = 100_000
)

// groupRecorder writes a user's groups to the store, skipping writes that this process knows the store already holds
// something at least as new as. Obot asks for the session state on every request, and a session's groups change only
// when its tokens do.
type groupRecorder struct {
	store *groupStore

	mu sync.Mutex
	// known holds, per user, the issue time of the newest ID token this process has seen the store hold groups from
	// or newer. The store only moves forward, so a token no newer than this needs no write, on any replica.
	known map[string]time.Time
}

func newGroupRecorder(store *groupStore) *groupRecorder {
	return &groupRecorder{store: store, known: map[string]time.Time{}}
}

// record stores groups as userID's groups according to an ID token issued at issuedAt.
func (r *groupRecorder) record(ctx context.Context, userID string, groups []string, issuedAt time.Time) error {
	r.mu.Lock()
	known, ok := r.known[userID]
	r.mu.Unlock()
	if ok && !issuedAt.After(known) {
		return nil
	}

	if _, err := r.store.setUserGroups(ctx, userID, normalizeGroups(groups), issuedAt); err != nil {
		return err
	}

	// Whether or not the write happened, the store now holds groups from a token at least this new.
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.known) >= maxRememberedUsers {
		// Forgetting only costs one redundant write per user.
		clear(r.known)
	}
	if issuedAt.After(r.known[userID]) {
		r.known[userID] = issuedAt
	}
	return nil
}

// groupInfo converts a group value from PingFederate into the group Obot sees. The name is the value itself: an LDAP
// DN from a memberOf attribute is shown whole, so that two groups with the same CN in different branches of the
// directory can be told apart, and a search matches what is shown.
func groupInfo(value string) state.GroupInfo {
	return state.GroupInfo{ID: groupIDPrefix + idEscaper.Replace(value), Name: value}
}

// idEscaper derives a group's ID from its value, which is stable for as long as PingFederate releases the same value.
// Commas are escaped because Obot sends group IDs to /obot-get-auth-groups as a comma-separated list, and LDAP DNs
// are full of them. Escaping % as well keeps the mapping reversible with url.PathUnescape.
var idEscaper = strings.NewReplacer("%", "%25", ",", "%2C")

// groupValues reverses groupInfo's IDs, which arrive without the prefix, into group values, dropping any that this
// provider could not have issued.
func groupValues(ids []string) []string {
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		if value, err := url.PathUnescape(id); err == nil && idEscaper.Replace(value) == id {
			values = append(values, value)
		}
	}
	return values
}

func groupInfos(values []string) state.GroupInfoList {
	infos := make(state.GroupInfoList, 0, len(values))
	for _, v := range values {
		infos = append(infos, groupInfo(v))
	}
	return infos
}

// listUserGroups serves POST /obot-list-user-auth-groups, whose body is the user's ID: the subject that
// /obot-get-user-info reports. A user with no recorded groups is an error rather than an empty list: Obot would store
// an empty list as the user's groups and remove them from every group, whereas an error fails the group refresh and
// changes nothing. It does not happen in practice, because Obot asks for a user's state, which records their groups,
// before it asks for their groups.
func (s *server) listUserGroups(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	userID := strings.TrimSpace(string(body))
	if userID == "" {
		http.Error(w, "user ID is required in request body", http.StatusBadRequest)
		return
	}

	groups, err := s.store.userGroups(r.Context(), userID)
	if errors.Is(err, errUnknownUser) {
		http.Error(w, "no groups are recorded for this user yet; they are recorded when the user signs in", http.StatusInternalServerError)
		return
	} else if err != nil {
		// Obot shows this response to the user, so the details go to the log.
		fmt.Printf("ERROR: pingfederate-auth-provider: failed to read the groups of a user: %v\n", err)
		http.Error(w, "failed to read the user's groups", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(groupInfos(groups)); err != nil {
		http.Error(w, "failed to encode groups", http.StatusInternalServerError)
	}
}

// fetchGroupPage backs GET /obot-list-auth-groups. The native cursor is the last group value of the previous page.
func (s *server) fetchGroupPage(ctx context.Context, req authcommon.PageRequest) (authcommon.PageResult, error) {
	names, more, err := s.store.listGroups(ctx, req.NameFilter, req.Cursor, req.Limit)
	if err != nil {
		return authcommon.PageResult{}, err
	}
	result := authcommon.PageResult{Items: groupInfos(names)}
	if more {
		result.NextCursor = names[len(names)-1]
	}
	return result, nil
}

// fetchGroupsByIDs backs GET /obot-get-auth-groups. Only groups that some recorded user is in are returned.
func (s *server) fetchGroupsByIDs(ctx context.Context, ids []string) (state.GroupInfoList, error) {
	names, err := s.store.knownGroups(ctx, groupValues(ids))
	if err != nil {
		return nil, err
	}
	return groupInfos(names), nil
}
