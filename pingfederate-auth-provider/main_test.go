package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func TestRunRequiresPostgres(t *testing.T) {
	t.Setenv("OBOT_PINGFEDERATE_AUTH_PROVIDER_CLIENT_ID", "obot")
	t.Setenv("OBOT_PINGFEDERATE_AUTH_PROVIDER_CLIENT_SECRET", "secret")
	t.Setenv("OBOT_PINGFEDERATE_AUTH_PROVIDER_ISSUER_URL", "https://sso.example.com")
	t.Setenv("OBOT_SERVER_URL", "https://obot.example")
	t.Setenv("OBOT_AUTH_PROVIDER_COOKIE_SECRET", "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=")
	t.Setenv("OBOT_AUTH_PROVIDER_EMAIL_DOMAINS", "*")
	t.Setenv("OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN", "")

	if err := run(); err == nil || !strings.Contains(err.Error(), "PostgreSQL") {
		t.Fatalf("run() = %v, want an error saying PostgreSQL is required", err)
	}
}

func TestOAuthProxyOptions(t *testing.T) {
	opts := testOptions(t, "https://sso.example.com:9031", "")
	opts.PostgresConnectionDSN = "postgres://example"
	proxyOpts, err := buildOAuthProxyOptions(opts, "/tmp/ca.pem")
	if err != nil {
		t.Fatal(err)
	}

	provider := proxyOpts.Providers[0]
	if provider.Scope != "openid profile email" {
		t.Errorf("scope = %q", provider.Scope)
	}
	if provider.CodeChallengeMethod != "S256" {
		t.Errorf("PKCE method = %q, want S256", provider.CodeChallengeMethod)
	}
	if provider.OIDCConfig.GroupsClaim != "groups" || provider.OIDCConfig.EmailClaim != "email" {
		t.Errorf("claims: groups %q, email %q", provider.OIDCConfig.GroupsClaim, provider.OIDCConfig.EmailClaim)
	}
	if *provider.OIDCConfig.InsecureAllowUnverifiedEmail || *provider.OIDCConfig.InsecureSkipNonce || *provider.OIDCConfig.InsecureSkipIssuerVerification {
		t.Error("an insecure OIDC option is enabled")
	}
	if len(provider.CAFiles) != 1 || !*provider.UseSystemTrustStore {
		t.Errorf("CA files %q, system trust store %v; want the CA file and the system roots", provider.CAFiles, *provider.UseSystemTrustStore)
	}
	if proxyOpts.Session.Type != options.PostgresSessionStoreType || proxyOpts.Session.Postgres.TableNamePrefix != "pingfederate_" {
		t.Errorf("session store = %q with prefix %q", proxyOpts.Session.Type, proxyOpts.Session.Postgres.TableNamePrefix)
	}
	if !proxyOpts.Cookie.Secure || proxyOpts.RawRedirectURL != "https://obot.example/" {
		t.Errorf("cookie secure %v, redirect %q", proxyOpts.Cookie.Secure, proxyOpts.RawRedirectURL)
	}
}

func TestDiscoveryRequiresMatchingHTTPSIssuer(t *testing.T) {
	f := newFakePingFederate(t)
	client, err := newHTTPClient(f.caPEM())
	if err != nil {
		t.Fatal(err)
	}

	if got, err := discoverUserInfoURL(t.Context(), client, f.issuer()); err != nil || got != f.issuer()+"/idp/userinfo.openid" {
		t.Fatalf("discoverUserInfoURL = %q, %v", got, err)
	}
	if _, err := discoverUserInfoURL(t.Context(), client, f.issuer()+"/other"); err == nil {
		t.Fatal("accepted an issuer URL that PingFederate does not report")
	}
	if _, err := discoverUserInfoURL(t.Context(), client, "http://sso.example.com"); err == nil {
		t.Fatal("accepted a plain-HTTP issuer")
	}

	// Without the CA certificate, PingFederate's certificate is not trusted.
	untrusted, err := newHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := discoverUserInfoURL(t.Context(), untrusted, f.issuer()); err == nil {
		t.Fatal("trusted a certificate from an unknown CA")
	}
}

func TestCACertificateFromObotForm(t *testing.T) {
	f := newFakePingFederate(t)
	opts := Options{IssuerURL: " " + f.issuer() + "/ ", CACertificate: strings.ReplaceAll(f.caPEM(), "\n", `\n`)}
	normalizeOptions(&opts)
	if opts.IssuerURL != f.issuer() {
		t.Fatalf("issuer URL = %q", opts.IssuerURL)
	}
	client, err := newHTTPClient(opts.CACertificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := discoverUserInfoURL(t.Context(), client, opts.IssuerURL); err != nil {
		t.Fatalf("the CA certificate as Obot submits it is not trusted: %v", err)
	}
}

func TestInvalidCACertificate(t *testing.T) {
	if _, err := newHTTPClient("not a certificate"); err == nil {
		t.Fatal("accepted a CA certificate that is not PEM")
	}
}

func TestUserInfoRequiresBearerToken(t *testing.T) {
	s := &server{}
	response := httptest.NewRecorder()
	s.getUserInfo(response, httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP %d, want 401", response.Code)
	}
}

func TestProfileName(t *testing.T) {
	for _, tc := range []struct {
		claims map[string]any
		want   string
	}{
		{map[string]any{"name": "Alice Anderson", "preferred_username": "alice"}, "Alice Anderson"},
		{map[string]any{"given_name": "Alice", "family_name": "Anderson", "preferred_username": "alice"}, "Alice Anderson"},
		{map[string]any{"preferred_username": "alice"}, "alice"},
		{map[string]any{}, ""},
	} {
		if got := profileName(tc.claims); got != tc.want {
			t.Errorf("profileName(%v) = %q, want %q", tc.claims, got, tc.want)
		}
	}
}
