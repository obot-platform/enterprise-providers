package authcommon

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// LoadFreshState loads the session behind request, refreshing it when due, and returns the fields of the session as
// it is after any refresh. The shared state.GetSerializableState refreshes the session but returns the fields it
// loaded before refreshing, so a caller that reads identity or claims from it would act on the old tokens.
//
// Whenever a refresh was due, the session is loaded again afterwards, whether this request refreshed it or another
// request did while this one waited for oauth2-proxy's session lock, in which case oauth2-proxy sets no cookie.
//
// When a refresh was due, it also returns the ID token the session held before, and "" when it was not. oauth2-proxy
// keeps the old ID token when a refresh response carries none, so a refreshed session whose ID token equals the
// previous one got no new ID token.
//
// request's cookies are replaced by the refreshed ones. The returned SetCookies also expire any chunk of the old
// session cookie that the refreshed session no longer uses, so the browser keeps the same session this call loaded.
func LoadFreshState(proxy *oauth2proxy.OAuthProxy, request *http.Request) (state.SerializableState, string, error) {
	session, err := loadSession(proxy, request)
	if err != nil {
		return state.SerializableState{}, "", err
	}
	if !session.IsExpired() && (proxy.CookieOptions.Refresh == 0 || session.Age() <= proxy.CookieOptions.Refresh) {
		return serializableState(session, nil), "", nil
	}

	previousIDToken := session.IDToken
	headers, err := refreshSession(proxy, request)
	if err != nil {
		return state.SerializableState{}, "", fmt.Errorf("failed to refresh token: %w", err)
	}
	var setCookies []string
	if len(headers) > 0 {
		if setCookies, err = replaceSessionCookies(request, headers, proxy.CookieOptions.Name); err != nil {
			return state.SerializableState{}, "", err
		}
	}

	refreshed, err := loadSession(proxy, request)
	if err != nil {
		return state.SerializableState{}, "", err
	}
	return serializableState(refreshed, setCookies), previousIDToken, nil
}

// loadSession loads the session behind request, with the errors state.GetSerializableState reports, which Obot
// recognizes.
func loadSession(proxy *oauth2proxy.OAuthProxy, request *http.Request) (*sessions.SessionState, error) {
	session, err := proxy.LoadCookiedSession(request)
	if err != nil {
		return nil, fmt.Errorf("failed to load cookied session: %v", err)
	}
	if session == nil {
		return nil, errors.New("state is nil")
	}
	return session, nil
}

func serializableState(session *sessions.SessionState, setCookies []string) state.SerializableState {
	return state.SerializableState{
		ExpiresOn:         session.ExpiresOn,
		AccessToken:       session.AccessToken,
		IDToken:           session.IDToken,
		PreferredUsername: session.PreferredUsername,
		User:              session.User,
		Email:             session.Email,
		Groups:            session.Groups,
		GroupInfos:        state.GroupInfoList{},
		SetCookies:        setCookies,
	}
}

// refreshSession has oauth2-proxy refresh the session behind request, as state.GetSerializableState does, and returns
// the Set-Cookie headers of the refreshed session, if this request saved one.
func refreshSession(proxy *oauth2proxy.OAuthProxy, request *http.Request) ([]string, error) {
	authRequest, err := http.NewRequestWithContext(request.Context(), request.Method, "/oauth2/auth", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request object: %v", err)
	}
	authRequest.Header = request.Header

	recorder := &responseRecorder{headers: make(http.Header)}
	proxy.ServeHTTP(recorder, authRequest)

	switch recorder.status {
	case http.StatusOK, http.StatusAccepted:
		return recorder.headers.Values("Set-Cookie"), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// oauth2-proxy rejected the session (and removes one that it fails to refresh), so the user must log in again.
		return nil, fmt.Errorf("%w: refreshing token returned %d: %s", state.ErrInvalidSession, recorder.status, recorder.body)
	default:
		return nil, fmt.Errorf("refreshing token returned unexpected status %d: %s", recorder.status, recorder.body)
	}
}

type responseRecorder struct {
	headers http.Header
	body    []byte
	status  int
}

func (r *responseRecorder) Header() http.Header { return r.headers }

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	return len(b), nil
}

func (r *responseRecorder) WriteHeader(status int) { r.status = status }

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
