package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// verifiedStateHandler applies Keycloak's email policy before Obot consumes an
// identity. ID tokens come only from oauth2-proxy's authenticated session store:
// oauth2-proxy verifies their signature, issuer and audience during code exchange
// and refresh. This is a claim policy check, not another JWT verifier.
func verifiedStateHandler(proxy *oauth2proxy.OAuthProxy, allowUnverified bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		current, _, err := authcommon.LoadFreshState(proxy, request)
		if err != nil {
			state.WriteStateError(w, err)
			return
		}
		if !allowUnverified {
			if reason := unverifiedEmailReason(current.IDToken); reason != "" {
				// Sign-in has already succeeded at this point, so this is the only record of why the user is signed out.
				fmt.Printf("WARNING: keycloak-auth-provider: rejected session for Keycloak user %q: %s\n", current.User, reason)
				state.WriteStateError(w, state.ErrInvalidSession)
				return
			}
		}
		if err := json.NewEncoder(w).Encode(current); err != nil {
			http.Error(w, "failed to encode state", http.StatusInternalServerError)
		}
	}
}

// unverifiedEmailReason returns why the ID token does not assert email_verified=true, with what an
// administrator can do about it, or "" when it does.
func unverifiedEmailReason(idToken string) string {
	unreadable := "the session's ID token could not be read, so its email verification is unknown"
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return unreadable
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return unreadable
	}
	var claims struct {
		EmailVerified *bool `json:"email_verified"`
	}
	switch {
	case json.Unmarshal(payload, &claims) != nil:
		return "the ID token's email_verified claim is not a boolean"
	case claims.EmailVerified == nil:
		return "the ID token does not include email_verified; restore the \"email verified\" mapper in the realm's email client scope"
	case !*claims.EmailVerified:
		return "Keycloak has not verified the user's email (email_verified is false); verify it in Keycloak, or enable Allow Unverified Emails"
	}
	return ""
}
