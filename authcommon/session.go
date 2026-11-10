package authcommon

import (
	"errors"
	"net/http"
	"strings"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// LoadFreshState loads the session behind request, refreshing it when due, and returns the fields of the session as
// it is after any refresh. The shared state.GetSerializableState refreshes the session but returns the fields it
// loaded before refreshing, so a caller that reads identity or claims from it would act on the old tokens.
//
// When the session was refreshed, it also returns the ID token the session held before the refresh, and "" when it
// was not. oauth2-proxy keeps the old ID token when a refresh response carries none, so a refreshed session whose ID
// token equals the previous one got no new ID token.
//
// request's cookies are replaced by the refreshed ones. The returned SetCookies also expire any chunk of the old
// session cookie that the refreshed session no longer uses, so the browser keeps the same session this call loaded.
func LoadFreshState(proxy *oauth2proxy.OAuthProxy, request *http.Request) (state.SerializableState, string, error) {
	current, err := state.GetSerializableState(proxy, request)
	if err != nil || len(current.SetCookies) == 0 {
		return current, "", err
	}

	setCookies, err := replaceSessionCookies(request, current.SetCookies, proxy.CookieOptions.Name)
	if err != nil {
		return state.SerializableState{}, "", err
	}

	refreshed, err := state.GetSerializableState(proxy, request)
	if err != nil {
		return state.SerializableState{}, "", err
	}

	refreshed.SetCookies = setCookies
	return refreshed, current.IDToken, nil
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
