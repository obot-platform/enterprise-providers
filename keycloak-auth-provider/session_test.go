package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/cookie"
)

func TestUnverifiedEmailReason(t *testing.T) {
	token := func(claims string) string {
		return "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
	}
	for _, tc := range []struct {
		name    string
		idToken string
		want    string
	}{
		{
			name:    "verified",
			idToken: token(`{"email_verified":true}`),
			want:    "",
		},
		{
			name:    "explicitly unverified",
			idToken: token(`{"email_verified":false}`),
			want:    "email_verified is false",
		},
		{
			name:    "claim missing",
			idToken: token(`{}`),
			want:    "does not include email_verified",
		},
		{
			name:    "claim not a boolean",
			idToken: token(`{"email_verified":"true"}`),
			want:    "not a boolean",
		},
		{
			name:    "not a JWT",
			idToken: "opaque",
			want:    "could not be read",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := unverifiedEmailReason(tc.idToken)
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("reason %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRefreshReplacesSessionCookieFamily(t *testing.T) {
	for _, tc := range []struct {
		name      string
		oldBytes  int
		newBytes  int
		oldChunks int
		newChunks int
	}{
		{
			name:      "unsplit remains unsplit",
			oldBytes:  64,
			newBytes:  64,
			oldChunks: 1,
			newChunks: 1,
		},
		{
			name:      "unsplit to split",
			oldBytes:  64,
			newBytes:  2800,
			oldChunks: 1,
			newChunks: 2,
		},
		{
			name:      "fewer chunks",
			oldBytes:  5200,
			newBytes:  2800,
			oldChunks: 3,
			newChunks: 2,
		},
		{
			name:      "split to unsplit",
			oldBytes:  2800,
			newBytes:  64,
			oldChunks: 2,
			newChunks: 1,
		},
		{
			name:      "more chunks",
			oldBytes:  2800,
			newBytes:  5200,
			oldChunks: 2,
			newChunks: 3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := options.NewOptions()
			opts.Cookie.Name = "obot_access_token"
			opts.Cookie.Secret = strings.Repeat("x", 32)
			opts.Cookie.Expire = 24 * time.Hour
			store, err := cookie.NewCookieSessionStore(&opts.Session, &opts.Cookie)
			if err != nil {
				t.Fatal(err)
			}
			session := func(size int) *sessions.SessionState {
				data := make([]byte, size)
				if _, err := rand.Read(data); err != nil {
					t.Fatal(err)
				}
				return &sessions.SessionState{
					User:        "person",
					AccessToken: base64.RawURLEncoding.EncodeToString(data),
				}
			}
			request := httptest.NewRequest(http.MethodGet, "https://obot.example/", nil)
			oldResponse := httptest.NewRecorder()
			if err := store.Save(oldResponse, request, session(tc.oldBytes)); err != nil {
				t.Fatal(err)
			}
			oldCookies := oldResponse.Result().Cookies()
			if len(oldCookies) != tc.oldChunks {
				t.Fatalf("old cookie chunks=%d want=%d", len(oldCookies), tc.oldChunks)
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(request.URL, oldCookies)
			jar.SetCookies(request.URL, []*http.Cookie{{Name: opts.Cookie.Name + "_csrf", Value: "keep", Path: "/"}})
			for _, c := range jar.Cookies(request.URL) {
				request.AddCookie(c)
			}
			fresh := session(tc.newBytes)
			newResponse := httptest.NewRecorder()
			if err := store.Save(newResponse, request, fresh); err != nil {
				t.Fatal(err)
			}
			if got := len(newResponse.Result().Cookies()); got != tc.newChunks {
				t.Fatalf("new cookie chunks=%d want=%d", got, tc.newChunks)
			}
			headers, err := replaceSessionCookies(request, newResponse.Header().Values("Set-Cookie"), opts.Cookie.Name)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := store.Load(request)
			if err != nil || loaded.AccessToken != fresh.AccessToken {
				t.Fatalf("wrapper did not load refreshed session: %v", err)
			}
			response := http.Response{Header: http.Header{"Set-Cookie": headers}}
			jar.SetCookies(request.URL, response.Cookies())
			browserRequest := httptest.NewRequest(http.MethodGet, request.URL.String(), nil)
			for _, c := range jar.Cookies(request.URL) {
				browserRequest.AddCookie(c)
			}
			loaded, err = store.Load(browserRequest)
			if err != nil || loaded.AccessToken != fresh.AccessToken {
				t.Fatalf("browser did not load refreshed session: %v", err)
			}
			if c, err := browserRequest.Cookie(opts.Cookie.Name + "_csrf"); err != nil || c.Value != "keep" {
				t.Fatal("unrelated cookie was removed")
			}
		})
	}
}
