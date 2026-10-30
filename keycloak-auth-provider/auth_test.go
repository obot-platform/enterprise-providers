package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/obot-platform/providers/auth-providers-common/pkg/env"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// Exercise the same OIDC configuration main uses with signed tokens and real
// discovery/JWKS/token/userinfo endpoints, rather than duplicating claim checks.
func TestOIDCEmailAdmissionPolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"", "false", "true"} {
		for _, verification := range []string{"missing", "false", "true", "malformed"} {
			for _, email := range []string{"person@example.com", ""} {
				t.Run("policy="+policy+"/verified="+verification+"/email="+email, func(t *testing.T) {
					var upstream *httptest.Server
					var rawToken string
					claims := map[string]any{}
					upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						var response any
						switch r.URL.Path {
						case "/realms/test/.well-known/openid-configuration":
							response = map[string]any{"issuer": upstream.URL + "/realms/test", "authorization_endpoint": upstream.URL + "/auth", "token_endpoint": upstream.URL + "/token", "userinfo_endpoint": upstream.URL + "/userinfo", "jwks_uri": upstream.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}
						case "/keys":
							response = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}}
						case "/token":
							response = map[string]any{"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 300, "id_token": rawToken}
						case "/userinfo":
							response = claims
						default:
							http.NotFound(w, r)
							return
						}
						if err := json.NewEncoder(w).Encode(response); err != nil {
							t.Error(err)
						}
					}))
					defer upstream.Close()
					claims = map[string]any{"iss": upstream.URL + "/realms/test", "sub": "native-user-id", "aud": "test-client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "preferred_username": "person", "groups": []string{}}
					if email != "" {
						claims["email"] = email
					}
					if verification != "missing" {
						claims["email_verified"] = verification == "true"
						if verification == "malformed" {
							claims["email_verified"] = "true"
						}
					}
					payload, err := json.Marshal(claims)
					if err != nil {
						t.Fatal(err)
					}
					signed, err := signer.Sign(payload)
					if err != nil {
						t.Fatal(err)
					}
					rawToken, err = signed.CompactSerialize()
					if err != nil {
						t.Fatal(err)
					}
					opts := testOptions()
					opts.IssuerURL = upstream.URL + "/realms/test"
					opts.InsecureOIDCAllowUnverifiedEmail = policy
					proxyOpts, err := buildOAuthProxyOptions(opts)
					if err != nil {
						t.Fatal(err)
					}
					provider, err := providers.NewProvider(proxyOpts.Providers[0])
					if err != nil {
						t.Fatal(err)
					}
					session, err := provider.Redeem(t.Context(), opts.ObotServerURL+"/", "test-code", "")
					// Sign-in always succeeds so that verifiedStateHandler, below, can enforce the policy and log why.
					if verification == "malformed" && err != nil {
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					err = provider.EnrichSession(t.Context(), session)
					if email == "" {
						if err == nil {
							t.Fatal("accepted login without email")
						}
						return
					}
					if err != nil || session.User != "native-user-id" || session.Email != email {
						t.Fatalf("session identity or email changed: enrichment error %v", err)
					}
					allowed, err := provider.Authorize(t.Context(), session)
					if err != nil || !allowed {
						t.Fatalf("provider authorization failed: %v", err)
					}
					skipNonce := true
					proxyOpts.Providers[0].OIDCConfig.InsecureSkipNonce = &skipNonce
					if err := validation.Validate(proxyOpts); err != nil {
						t.Fatal(err)
					}
					proxy, err := oauth2proxy.NewOAuthProxy(proxyOpts, oauth2proxy.NewValidator(proxyOpts.EmailDomains, proxyOpts.AuthenticatedEmailsFile))
					if err != nil {
						t.Fatal(err)
					}
					stateStatus := func() int {
						request := httptest.NewRequest(http.MethodGet, "https://obot.example/", nil)
						saved := httptest.NewRecorder()
						if err := proxy.SaveSession(saved, request, session); err != nil {
							t.Fatal(err)
						}
						for _, cookie := range saved.Result().Cookies() {
							request.AddCookie(cookie)
						}
						body, err := json.Marshal(state.SerializableRequest{Method: http.MethodGet, URL: request.URL.String(), Header: request.Header})
						if err != nil {
							t.Fatal(err)
						}
						response := httptest.NewRecorder()
						verifiedStateHandler(proxy, policy == "true")(response, httptest.NewRequest(http.MethodPost, "/obot-get-state", bytes.NewReader(body)))
						return response.Code
					}
					code := stateStatus()
					want := http.StatusOK
					if policy != "true" && verification != "true" {
						want = http.StatusUnauthorized
					}
					if code != want {
						t.Fatalf("state admission HTTP %d, want %d", code, want)
					}
					if verification == "true" {
						for _, next := range []string{"missing", "false", "true"} {
							delete(claims, "email_verified")
							if next != "missing" {
								claims["email_verified"] = next == "true"
							}
							payload, err := json.Marshal(claims)
							if err != nil {
								t.Fatal(err)
							}
							signed, err := signer.Sign(payload)
							if err != nil {
								t.Fatal(err)
							}
							rawToken, err = signed.CompactSerialize()
							if err != nil {
								t.Fatal(err)
							}
							old := time.Now().Add(-2 * time.Hour)
							session.CreatedAt = &old
							session.ExpiresOn = &old
							session.RefreshToken = "refresh"
							status := stateStatus()
							want := http.StatusOK
							if policy != "true" && next != "true" {
								want = http.StatusUnauthorized
							}
							if status != want {
								t.Fatalf("refreshed verification %s: status %d want %d", next, status, want)
							}
						}
					}
					validateEmail := oauth2proxy.NewValidator(proxyOpts.EmailDomains, proxyOpts.AuthenticatedEmailsFile)
					if !validateEmail(session.Email) || validateEmail("person@other.example") {
						t.Fatal("email domain restriction changed with verification policy")
					}
				})
			}
		}
	}
}

func testOptions() Options {
	return Options{
		ClientID:                 "test-client",
		ClientSecret:             "test-secret",
		IssuerURL:                "https://id.example/realms/test",
		ObotServerURL:            "https://obot.example",
		AuthCookieSecret:         base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))),
		AuthEmailDomains:         " example.com ",
		AuthTokenRefreshDuration: "1h",
	}
}

func TestEmailPolicyEnvironmentDefaultAndInvalidValue(t *testing.T) {
	for key, value := range map[string]string{
		"OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_ID":                       "test-client",
		"OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_SECRET":                   "test-secret",
		"OBOT_KEYCLOAK_AUTH_PROVIDER_ISSUER_URL":                      "https://id.example/realms/test",
		"OBOT_SERVER_PUBLIC_URL":                                      "https://obot.example",
		"OBOT_AUTH_PROVIDER_COOKIE_SECRET":                            testOptions().AuthCookieSecret,
		"OBOT_KEYCLOAK_AUTH_PROVIDER_SERVICE_CLIENT_ID":               "directory",
		"OBOT_KEYCLOAK_AUTH_PROVIDER_SERVICE_CLIENT_SECRET":           "directory-secret",
		"OBOT_KEYCLOAK_AUTH_PROVIDER_INSECURE_ALLOW_UNVERIFIED_EMAIL": "",
	} {
		t.Setenv(key, value)
	}
	var opts Options
	if err := env.LoadEnvForStruct(&opts); err != nil {
		t.Fatal(err)
	}
	if opts.InsecureOIDCAllowUnverifiedEmail != "false" {
		t.Fatal("environment default permits unverified email")
	}
	opts.InsecureOIDCAllowUnverifiedEmail = "not-a-boolean"
	if _, err := buildOAuthProxyOptions(opts); err == nil || !strings.Contains(err.Error(), "OBOT_KEYCLOAK_AUTH_PROVIDER_INSECURE_ALLOW_UNVERIFIED_EMAIL") {
		t.Fatalf("invalid policy was not rejected: %v", err)
	}
}
