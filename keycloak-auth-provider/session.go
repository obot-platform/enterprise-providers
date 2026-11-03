package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
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
		current, err := state.GetSerializableState(proxy, request)
		if err != nil {
			state.WriteStateError(w, err)
			return
		}
		// The shared helper refreshes the session but returns the original session's
		// fields. Reload refreshed cookies so neither policy nor identity uses old claims.
		if len(current.SetCookies) > 0 {
			setCookies, cookieErr := replaceSessionCookies(request, current.SetCookies, proxy.CookieOptions.Name)
			if cookieErr != nil {
				state.WriteStateError(w, cookieErr)
				return
			}
			refreshed, loadErr := state.GetSerializableState(proxy, request)
			if loadErr != nil {
				state.WriteStateError(w, loadErr)
				return
			}
			refreshed.SetCookies = setCookies
			current = refreshed
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

// Replace the whole session-cookie family, not individual names: Save can switch
// between unsplit and split cookies or produce fewer chunks without clearing old ones.
// Return deletion headers too, so the browser and this request load the same session.
func replaceSessionCookies(request *http.Request, headers []string, name string) ([]string, error) {
	response := http.Response{Header: http.Header{"Set-Cookie": headers}}
	fresh := response.Cookies()
	var template *http.Cookie
	for _, cookie := range fresh {
		if isSessionCookie(cookie.Name, name) && cookie.MaxAge >= 0 && cookie.Value != "" {
			template = cookie
			break
		}
	}
	if template == nil {
		return nil, errors.New("refresh returned no session cookie")
	}
	original := request.Cookies()
	cookies := make(map[string]*http.Cookie, len(original)+len(fresh))
	for _, cookie := range original {
		if !isSessionCookie(cookie.Name, name) {
			cookies[cookie.Name] = cookie
		}
	}
	for _, cookie := range fresh {
		if cookie.MaxAge < 0 || (!cookie.Expires.IsZero() && cookie.Expires.Before(time.Now())) {
			delete(cookies, cookie.Name)
		} else {
			cookies[cookie.Name] = cookie
		}
	}
	result := append([]string{}, headers...)
	for _, cookie := range original {
		if isSessionCookie(cookie.Name, name) && cookies[cookie.Name] == nil {
			expired := *template
			expired.Name = cookie.Name
			expired.Value = ""
			expired.MaxAge = -1
			expired.Expires = time.Unix(1, 0)
			result = append(result, expired.String())
		}
	}
	request.Header.Del("Cookie")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return result, nil
}

func isSessionCookie(candidate, name string) bool {
	if candidate == name {
		return true
	}
	suffix, ok := strings.CutPrefix(candidate, name+"_")
	if !ok || suffix == "" {
		return false
	}
	for _, digit := range suffix {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
