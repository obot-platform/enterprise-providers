package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// getState serves POST /obot-get-state: who is behind the request Obot forwards, refreshing the session when due.
//
// It is also where groups are recorded. oauth2-proxy reads the groups claim from the ID token, or from PingFederate's
// userinfo endpoint when the ID token omits it, each time it signs a user in or refreshes their tokens, so the groups
// in a fresh session are PingFederate's answer as of the session's ID token. A failure to record them fails the
// request: otherwise Obot would keep granting the access of a group the user has left.
func (s *server) getState(w http.ResponseWriter, r *http.Request) {
	var serialized state.SerializableRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&serialized); err != nil {
		http.Error(w, "invalid state request", http.StatusBadRequest)
		return
	}
	request, err := http.NewRequestWithContext(r.Context(), serialized.Method, serialized.URL, nil)
	if err != nil {
		http.Error(w, "invalid state URL", http.StatusBadRequest)
		return
	}
	request.Header = serialized.Header

	current, previousIDToken, err := authcommon.LoadFreshState(s.proxy, request)
	if err != nil {
		state.WriteStateError(w, err)
		return
	}
	issuedAt, ok := idTokenIssuedAt(current.IDToken)
	if current.User == "" || !ok {
		state.WriteStateError(w, fmt.Errorf("%w: the session has no subject or ID token", state.ErrInvalidSession))
		return
	}

	// A refresh that returns no ID token leaves the session with the claims, and the groups, of an older one. They
	// would be reported as current for as long as the refresh token lasts, so the user must sign in again instead.
	if len(current.SetCookies) > 0 && current.IDToken == previousIDToken {
		fmt.Println("ERROR: pingfederate-auth-provider: PingFederate refreshed a session without issuing a new ID token, so the user must sign in again. Enable \"Return ID Token on Refresh Grant\" in the OpenID Connect policy used by Obot's client.")
		state.WriteStateError(w, fmt.Errorf("%w: the refreshed session has no new ID token", state.ErrInvalidSession))
		return
	}

	if err := s.groups.record(r.Context(), current.User, current.Groups, issuedAt); err != nil {
		fmt.Printf("ERROR: pingfederate-auth-provider: failed to record the groups of a user: %v\n", err)
		http.Error(w, "failed to record the user's groups", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(current); err != nil {
		http.Error(w, "failed to encode state", http.StatusInternalServerError)
	}
}

// idTokenIssuedAt returns the iat of an ID token that oauth2-proxy has already verified.
func idTokenIssuedAt(idToken string) (time.Time, bool) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		IssuedAt int64 `json:"iat"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.IssuedAt <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.IssuedAt, 0), true
}
