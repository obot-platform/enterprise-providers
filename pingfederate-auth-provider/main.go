package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/providers/auth-providers-common/pkg/env"
)

type Options struct {
	ClientID      string `env:"OBOT_PINGFEDERATE_AUTH_PROVIDER_CLIENT_ID"`
	ClientSecret  string `env:"OBOT_PINGFEDERATE_AUTH_PROVIDER_CLIENT_SECRET"`
	IssuerURL     string `env:"OBOT_PINGFEDERATE_AUTH_PROVIDER_ISSUER_URL"`
	CACertificate string `env:"OBOT_PINGFEDERATE_AUTH_PROVIDER_CA_CERTIFICATE" optional:"true"`

	ObotServerURL                     string `env:"OBOT_SERVER_PUBLIC_URL,OBOT_SERVER_URL"`
	PostgresConnectionDSN             string `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN" optional:"true"`
	PostgresMaxConnections            int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_MAX_CONNECTIONS" optional:"true"`
	PostgresMaxIdleConnections        int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_MAX_IDLE_CONNECTIONS" optional:"true"`
	PostgresConnectionLifetimeSeconds int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_LIFETIME_SECONDS" optional:"true"`
	AuthCookieSecret                  string `usage:"Secret used to encrypt cookie" env:"OBOT_AUTH_PROVIDER_COOKIE_SECRET"`
	AuthEmailDomains                  string `usage:"Email domains allowed for authentication" default:"*" env:"OBOT_AUTH_PROVIDER_EMAIL_DOMAINS"`
	AuthTokenRefreshDuration          string `usage:"Duration to refresh auth token after" optional:"true" default:"1h" env:"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION"`
	LoggingEnabled                    string `env:"OBOT_AUTH_PROVIDER_ENABLE_LOGGING" optional:"true"`
}

type server struct {
	proxy       *oauth2proxy.OAuthProxy
	store       *groupStore
	groups      *groupRecorder
	httpClient  *http.Client
	userInfoURL string
}

func main() {
	if err := run(); err != nil {
		fmt.Printf("ERROR: pingfederate-auth-provider: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var opts Options
	if err := env.LoadEnvForStruct(&opts); err != nil {
		return fmt.Errorf("failed to load options: %w", err)
	}
	if opts.PostgresConnectionDSN == "" {
		// PingFederate has no directory API, so the groups seen at sign-in are the only record of who is in which
		// group, and they must outlive a restart and be shared by every Obot replica.
		return errors.New("the PingFederate auth provider requires Obot to use PostgreSQL, where it records the groups that PingFederate releases at sign-in")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	normalizeOptions(&opts)
	caFile, err := writeCACertificate(opts.CACertificate)
	if err != nil {
		return err
	}
	httpClient, err := newHTTPClient(opts.CACertificate)
	if err != nil {
		return err
	}
	userInfoURL, err := discoverUserInfoURL(ctx, httpClient, opts.IssuerURL)
	if err != nil {
		return err
	}

	oauthProxyOpts, err := buildOAuthProxyOptions(opts, caFile)
	if err != nil {
		return fmt.Errorf("failed to configure oauth2 proxy: %w", err)
	}
	if err := validation.Validate(oauthProxyOpts); err != nil {
		return fmt.Errorf("failed to validate options: %w", err)
	}
	oauthProxy, err := oauth2proxy.NewOAuthProxy(oauthProxyOpts, oauth2proxy.NewValidator(oauthProxyOpts.EmailDomains, oauthProxyOpts.AuthenticatedEmailsFile))
	if err != nil {
		return fmt.Errorf("failed to create oauth2 proxy: %w", err)
	}

	store, err := openGroupStore(ctx, opts.PostgresConnectionDSN, opts.PostgresMaxConnections, opts.PostgresMaxIdleConnections, opts.PostgresConnectionLifetimeSeconds)
	if err != nil {
		return err
	}

	srv := &server{
		proxy:       oauthProxy,
		store:       store,
		groups:      newGroupRecorder(store),
		httpClient:  httpClient,
		userInfoURL: userInfoURL,
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}
	listenHost := os.Getenv("OBOT_PROVIDER_LISTEN_HOST")
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}

	addr := listenHost + ":" + port
	fmt.Printf("listening on %s\n", addr)
	if err := http.ListenAndServe(addr, srv.handler(port)); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to listen and serve: %w", err)
	}
	return nil
}

func normalizeOptions(opts *Options) {
	opts.IssuerURL = strings.TrimSuffix(strings.TrimSpace(opts.IssuerURL), "/")
	// Obot's admin UI submits a multiline value with its line breaks written as \n.
	opts.CACertificate = strings.ReplaceAll(opts.CACertificate, `\n`, "\n")
}

func (s *server) handler(port string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "http://127.0.0.1:%s", port)
	})
	mux.HandleFunc("/obot-get-state", s.getState)
	mux.HandleFunc("/obot-get-user-info", s.getUserInfo)
	mux.HandleFunc("/obot-list-auth-groups", authcommon.ListGroupsHandler(providerKind, s.fetchGroupPage))
	mux.HandleFunc("/obot-get-auth-groups", authcommon.GetGroupsHandler(providerKind, s.fetchGroupsByIDs))
	mux.HandleFunc("/obot-list-user-auth-groups", s.listUserGroups)
	mux.HandleFunc("/", s.proxy.ServeHTTP)
	return mux
}

// buildOAuthProxyOptions configures sign-in and session policy in one place. caFile is the PingFederate CA bundle to
// trust in addition to the system roots, or "" for the system roots alone.
func buildOAuthProxyOptions(opts Options, caFile string) (*options.Options, error) {
	refreshDuration, err := time.ParseDuration(opts.AuthTokenRefreshDuration)
	if err != nil {
		return nil, fmt.Errorf("parse token refresh duration: %w", err)
	}
	if refreshDuration < 0 {
		return nil, errors.New("token refresh duration must be nonnegative")
	}

	cookieSecret, err := base64.StdEncoding.DecodeString(opts.AuthCookieSecret)
	if err != nil {
		return nil, fmt.Errorf("decode cookie secret: %w", err)
	}

	legacyOpts := options.NewLegacyOptions()
	legacyOpts.LegacyProvider.ProviderType = "oidc"
	legacyOpts.LegacyProvider.ProviderName = "PingFederate"
	legacyOpts.LegacyProvider.ClientID = opts.ClientID
	legacyOpts.LegacyProvider.ClientSecret = opts.ClientSecret
	legacyOpts.LegacyProvider.OIDCIssuerURL = opts.IssuerURL
	legacyOpts.LegacyProvider.Scope = "openid profile email"
	legacyOpts.LegacyProvider.OIDCGroupsClaim = "groups"
	legacyOpts.LegacyProvider.CodeChallengeMethod = "S256"
	// The legacy defaults skip the nonce. PingFederate returns it in the ID token, so verify it.
	legacyOpts.LegacyProvider.InsecureOIDCSkipNonce = false
	if caFile != "" {
		legacyOpts.LegacyProvider.ProviderCAFiles = []string{caFile}
		legacyOpts.LegacyProvider.UseSystemTrustStore = true
	}

	oauthProxyOpts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("convert legacy options: %w", err)
	}

	oauthProxyOpts.Server.BindAddress = ""
	oauthProxyOpts.MetricsServer.BindAddress = ""
	// Sessions are stored in PostgreSQL, whose session lock lets parallel requests from one browser refresh a session
	// once, as PingFederate's rolling refresh tokens require.
	oauthProxyOpts.Session.Type = options.PostgresSessionStoreType
	oauthProxyOpts.Session.Postgres.ConnectionDSN = opts.PostgresConnectionDSN
	oauthProxyOpts.Session.Postgres.MaxOpenConns = opts.PostgresMaxConnections
	oauthProxyOpts.Session.Postgres.MaxIdleConns = opts.PostgresMaxIdleConnections
	oauthProxyOpts.Session.Postgres.ConnMaxLifetime = opts.PostgresConnectionLifetimeSeconds
	oauthProxyOpts.Session.Postgres.TableNamePrefix = "pingfederate_"
	oauthProxyOpts.Cookie.Refresh = refreshDuration
	oauthProxyOpts.Cookie.Name = "obot_access_token"
	oauthProxyOpts.Cookie.Secret = string(cookieSecret)
	oauthProxyOpts.Cookie.Secure = strings.HasPrefix(opts.ObotServerURL, "https://")
	oauthProxyOpts.RawRedirectURL = opts.ObotServerURL + "/"
	if opts.AuthEmailDomains != "" {
		emailDomains := strings.Split(opts.AuthEmailDomains, ",")
		for i := range emailDomains {
			emailDomains[i] = strings.TrimSpace(emailDomains[i])
		}
		oauthProxyOpts.EmailDomains = emailDomains
	}
	loggingEnabled := strings.EqualFold(opts.LoggingEnabled, "true")
	oauthProxyOpts.Logging.RequestEnabled = loggingEnabled
	oauthProxyOpts.Logging.AuthEnabled = loggingEnabled
	oauthProxyOpts.Logging.StandardEnabled = loggingEnabled

	return oauthProxyOpts, nil
}

// newHTTPClient returns the client for calls this provider makes to PingFederate itself. It trusts the system roots
// plus caPEM, the same roots oauth2-proxy is given.
func newHTTPClient(caPEM string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(caPEM) != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("the CA certificate holds no PEM-encoded certificates")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

// writeCACertificate writes caPEM to a private file for oauth2-proxy, which reads CAs only from files.
func writeCACertificate(caPEM string) (string, error) {
	if strings.TrimSpace(caPEM) == "" {
		return "", nil
	}
	f, err := os.CreateTemp("", "pingfederate-ca-*.pem")
	if err != nil {
		return "", fmt.Errorf("create CA certificate file: %w", err)
	}
	if _, err := f.WriteString(strings.TrimSpace(caPEM) + "\n"); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write CA certificate file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("write CA certificate file: %w", err)
	}
	return f.Name(), nil
}

// discoverUserInfoURL reads PingFederate's userinfo endpoint from its discovery document, which must name issuerURL
// as the issuer. oauth2-proxy performs its own discovery for everything else.
func discoverUserInfoURL(ctx context.Context, client *http.Client, issuerURL string) (string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("the issuer URL %q must be an https URL, such as https://sso.example.com", issuerURL)
	}

	discoveryURL := issuerURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("fetch %s: status %d: %s", discoveryURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var doc struct {
		Issuer           string `json:"issuer"`
		UserInfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode %s: %w", discoveryURL, err)
	}
	if doc.Issuer != issuerURL {
		return "", fmt.Errorf("PingFederate reports its issuer as %q, which does not match the issuer URL %q; set the issuer URL to PingFederate's base URL exactly as reported", doc.Issuer, issuerURL)
	}
	if doc.UserInfoEndpoint == "" {
		return "", fmt.Errorf("%s does not name a userinfo endpoint", discoveryURL)
	}
	return doc.UserInfoEndpoint, nil
}
