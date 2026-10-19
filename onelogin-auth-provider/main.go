package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/client"
	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/profile"
	"github.com/obot-platform/providers/auth-providers-common/pkg/env"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

type Options struct {
	ClientID                          string `env:"OBOT_ONELOGIN_AUTH_PROVIDER_CLIENT_ID"`
	ClientSecret                      string `env:"OBOT_ONELOGIN_AUTH_PROVIDER_CLIENT_SECRET"`
	IssuerURL                         string `env:"OBOT_ONELOGIN_AUTH_PROVIDER_ISSUER_URL"`
	ObotServerURL                     string `env:"OBOT_SERVER_PUBLIC_URL,OBOT_SERVER_URL"`
	PostgresConnectionDSN             string `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN" optional:"true"`
	PostgresMaxConnections            int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_MAX_CONNECTIONS" optional:"true"`
	PostgresMaxIdleConnections        int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_MAX_IDLE_CONNECTIONS" optional:"true"`
	PostgresConnectionLifetimeSeconds int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_LIFETIME_SECONDS" optional:"true"`
	AuthCookieSecret                  string `usage:"Secret used to encrypt cookie" env:"OBOT_AUTH_PROVIDER_COOKIE_SECRET"`
	AuthEmailDomains                  string `usage:"Email domains allowed for authentication" default:"*" env:"OBOT_AUTH_PROVIDER_EMAIL_DOMAINS"`
	LoggingEnabled                    string `usage:"Enable oauth2-proxy logging" optional:"true" env:"OBOT_AUTH_PROVIDER_ENABLE_LOGGING"`
	AuthTokenRefreshDuration          string `usage:"Duration to refresh auth token after" optional:"true" default:"1h" env:"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION"`

	// These two are the credentials of a OneLogin API client, which Obot does not always require. Providing both
	// selects directory synchronization through the OneLogin admin API. Omitting both leaves the directory endpoints
	// unavailable, and Obot provisions users and groups through SCIM instead. Providing only one is a startup error.
	APIClientID     string `env:"OBOT_ONELOGIN_AUTH_PROVIDER_API_CLIENT_ID" optional:"true"`
	APIClientSecret string `env:"OBOT_ONELOGIN_AUTH_PROVIDER_API_CLIENT_SECRET" optional:"true"`
	// APIBaseURL overrides the base URL of the OneLogin admin API, which defaults to the scheme and host of the
	// issuer URL. Set it for an API host such as https://api.us.onelogin.com.
	APIBaseURL string `env:"OBOT_ONELOGIN_AUTH_PROVIDER_API_BASE_URL" optional:"true"`
}

const (
	// directoryUnavailableMessage is what every directory endpoint answers when the OneLogin API credentials are not
	// configured.
	directoryUnavailableMessage = "OneLogin API credentials are not configured, so directory lookups are unavailable"

	// accessDeniedMessage is what a user sees when OneLogin refuses the sign-in at the callback. OneLogin does this,
	// with error=access_denied, for a user who has not been given access to the OIDC app. It is a fixed message
	// rather than OneLogin's error_description, because the callback's query string can be crafted by anyone.
	accessDeniedMessage = "Login Failed: OneLogin denied access. Your OneLogin account may not have access to this application. Ask your OneLogin administrator to give you access."

	// maxUserIDBodyBytes caps the body of POST /obot-list-user-auth-groups, which is one OneLogin user ID of at most
	// 18 digits, with room for surrounding whitespace.
	maxUserIDBodyBytes = 64

	// maxLoggedErrorDescriptionBytes caps how much of a callback's error_description is logged. Anyone can craft the
	// callback's query string, so it is not let fill the log.
	maxLoggedErrorDescriptionBytes = 256
)

type server struct {
	// apiClient calls the OneLogin admin API. It is nil when the API credentials are not configured.
	apiClient *client.Client
	// roles names OneLogin roles for the directory endpoints. It is nil when apiClient is.
	roles     *profile.RoleCache
	issuerURL string
	// httpClient calls OneLogin's userinfo endpoint.
	httpClient *http.Client
}

// callbackProxy is the part of the oauth2-proxy that oauthCallback uses.
type callbackProxy interface {
	http.Handler
	ErrorPage(rw http.ResponseWriter, req *http.Request, code int, appError string, messages ...any)
}

func main() {
	var opts Options
	if err := env.LoadEnvForStruct(&opts); err != nil {
		fmt.Printf("ERROR: onelogin-auth-provider: failed to load options: %v\n", err)
		os.Exit(1)
	}

	opts.IssuerURL = strings.TrimSuffix(opts.IssuerURL, "/")

	refreshDuration, err := time.ParseDuration(opts.AuthTokenRefreshDuration)
	if err != nil {
		fmt.Printf("ERROR: onelogin-auth-provider: failed to parse token refresh duration: %v\n", err)
		os.Exit(1)
	}

	if refreshDuration < 0 {
		fmt.Printf("ERROR: onelogin-auth-provider: token refresh duration must be greater than 0\n")
		os.Exit(1)
	}

	cookieSecret, err := base64.StdEncoding.DecodeString(opts.AuthCookieSecret)
	if err != nil {
		fmt.Printf("ERROR: onelogin-auth-provider: failed to decode cookie secret: %v\n", err)
		os.Exit(1)
	}

	oauthProxyOpts, err := newOAuthProxyOptions(opts, refreshDuration, cookieSecret)
	if err != nil {
		fmt.Printf("ERROR: onelogin-auth-provider: %v\n", err)
		os.Exit(1)
	}

	oauthProxy, err := oauth2proxy.NewOAuthProxy(oauthProxyOpts, oauth2proxy.NewValidator(oauthProxyOpts.EmailDomains, oauthProxyOpts.AuthenticatedEmailsFile))
	if err != nil {
		fmt.Printf("ERROR: onelogin-auth-provider: failed to create oauth2 proxy: %v\n", err)
		os.Exit(1)
	}

	hasAPICredentials, err := apiCredentialsConfigured(opts.APIClientID, opts.APIClientSecret)
	if err != nil {
		fmt.Printf("ERROR: onelogin-auth-provider: invalid API credentials: %v\n", err)
		os.Exit(1)
	}

	// Only the directory endpoints call the OneLogin admin API. Without API credentials the client stays nil, and
	// those endpoints answer 503.
	var (
		httpClient = client.NewHTTPClient()
		apiClient  *client.Client
		roles      *profile.RoleCache
	)
	if hasAPICredentials {
		baseURL, err := apiBaseURL(opts.IssuerURL, opts.APIBaseURL)
		if err != nil {
			fmt.Printf("ERROR: onelogin-auth-provider: invalid API base URL: %v\n", err)
			os.Exit(1)
		}
		apiClient = client.New(baseURL, strings.TrimSpace(opts.APIClientID), strings.TrimSpace(opts.APIClientSecret), client.WithHTTPClient(httpClient))

		// The role-name cache lives as long as the process. Until its first fill completes, each role it is asked
		// about is looked up on its own.
		roles = profile.NewRoleCache(apiClient)
		go roles.Run(context.Background(), profile.RoleCacheRefreshInterval)
	}

	srv := &server{
		apiClient:  apiClient,
		roles:      roles,
		issuerURL:  opts.IssuerURL,
		httpClient: httpClient,
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		// / (exactly): Obot's readiness probe. Obot polls it until it gets a 200 and ignores the body,
		// which is the provider's local base URL by convention.
		_, _ = w.Write(fmt.Appendf(nil, "http://127.0.0.1:%s", port))
	})
	mux.HandleFunc("/obot-get-state", state.ObotGetState(oauthProxy))
	mux.HandleFunc("/obot-get-user-info", srv.getUserInfo)
	srv.registerDirectoryRoutes(mux)
	mux.HandleFunc("/oauth2/callback", oauthCallback(oauthProxy))
	mux.HandleFunc("/", oauthProxy.ServeHTTP)

	listenHost := os.Getenv("OBOT_PROVIDER_LISTEN_HOST")
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}

	addr := listenHost + ":" + port
	if err := http.ListenAndServe(addr, mux); !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("ERROR: onelogin-auth-provider: failed to listen and serve: %v\n", err)
		os.Exit(1)
	}
}

// newOAuthProxyOptions returns the oauth2-proxy options for signing in through OneLogin's OIDC app, validated.
func newOAuthProxyOptions(opts Options, refreshDuration time.Duration, cookieSecret []byte) (*options.Options, error) {
	legacyOpts := options.NewLegacyOptions()
	legacyOpts.LegacyProvider.ProviderType = "oidc"
	legacyOpts.LegacyProvider.ProviderName = "oidc"
	legacyOpts.LegacyProvider.ClientID = opts.ClientID
	legacyOpts.LegacyProvider.ClientSecret = opts.ClientSecret
	legacyOpts.LegacyProvider.OIDCIssuerURL = opts.IssuerURL
	// Unlike Okta, this requests neither offline_access nor groups. OneLogin fails the whole sign-in with
	// invalid_scope when offline_access is requested, and the authorization code flow returns a refresh token without
	// it. Obot reads groups through the directory endpoints, not from a groups claim.
	legacyOpts.LegacyProvider.Scope = "openid email profile"

	oauthProxyOpts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to convert legacy options to new options: %w", err)
	}

	oauthProxyOpts.Server.BindAddress = ""
	oauthProxyOpts.MetricsServer.BindAddress = ""
	if opts.PostgresConnectionDSN != "" {
		oauthProxyOpts.Session.Type = options.PostgresSessionStoreType
		oauthProxyOpts.Session.Postgres.ConnectionDSN = opts.PostgresConnectionDSN
		oauthProxyOpts.Session.Postgres.MaxOpenConns = opts.PostgresMaxConnections
		oauthProxyOpts.Session.Postgres.MaxIdleConns = opts.PostgresMaxIdleConnections
		oauthProxyOpts.Session.Postgres.ConnMaxLifetime = opts.PostgresConnectionLifetimeSeconds
		oauthProxyOpts.Session.Postgres.TableNamePrefix = "onelogin_"
	}
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

	if err := validation.Validate(oauthProxyOpts); err != nil {
		return nil, fmt.Errorf("failed to validate options: %w", err)
	}

	return oauthProxyOpts, nil
}

// apiCredentialsConfigured reports whether both OneLogin API credentials are configured. Whitespace-only values count
// as absent. Configuring only one of the two is an error rather than a quiet fallback to no directory, because it is
// almost certainly a mistake.
func apiCredentialsConfigured(clientID, clientSecret string) (bool, error) {
	hasClientID := strings.TrimSpace(clientID) != ""
	hasClientSecret := strings.TrimSpace(clientSecret) != ""

	switch {
	case hasClientID && hasClientSecret:
		return true, nil
	case hasClientID:
		return false, errors.New("OBOT_ONELOGIN_AUTH_PROVIDER_API_CLIENT_ID is set but OBOT_ONELOGIN_AUTH_PROVIDER_API_CLIENT_SECRET is not; set both for directory synchronization, or neither when Obot provisions users and groups through SCIM")
	case hasClientSecret:
		return false, errors.New("OBOT_ONELOGIN_AUTH_PROVIDER_API_CLIENT_SECRET is set but OBOT_ONELOGIN_AUTH_PROVIDER_API_CLIENT_ID is not; set both for directory synchronization, or neither when Obot provisions users and groups through SCIM")
	default:
		return false, nil
	}
}

// apiBaseURL returns the base URL of the OneLogin admin API: override when it is set, and otherwise the scheme and
// host of the issuer URL, which is the account's own domain, such as https://example.onelogin.com.
//
// Either way the URL must be https, because the API client sends its credentials there. Plain http is allowed only
// for a loopback host, which never leaves the machine.
func apiBaseURL(issuerURL, override string) (string, error) {
	if override = strings.TrimSpace(override); override != "" {
		u, err := parseAPIBaseURL(override)
		if err != nil {
			return "", fmt.Errorf("OBOT_ONELOGIN_AUTH_PROVIDER_API_BASE_URL: %w", err)
		}
		// API paths such as /api/2/roles are appended to the base URL, so a path of its own would double them up.
		if u.Path != "" && u.Path != "/" {
			return "", fmt.Errorf("OBOT_ONELOGIN_AUTH_PROVIDER_API_BASE_URL: %q must not have a path; use the scheme and host only, such as https://api.us.onelogin.com", override)
		}
		return strings.TrimSuffix(override, "/"), nil
	}

	u, err := parseAPIBaseURL(issuerURL)
	if err != nil {
		return "", fmt.Errorf("issuer URL: %w", err)
	}

	return u.Scheme + "://" + u.Host, nil
}

// parseAPIBaseURL parses a URL the OneLogin admin API is called at, and checks that it is absolute, is https unless
// its host is a loopback one, and has nothing that would garble the paths appended to it.
func parseAPIBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%q has no host; it must be an absolute URL such as https://example.onelogin.com", raw)
	}

	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("%q must use https; http is allowed only for a loopback host", raw)
		}
	default:
		return nil, fmt.Errorf("%q must use https", raw)
	}

	// An empty query or fragment ("…com?" or "…com#") parses to empty strings, so check for the separators too.
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%q must not have user info, a query or a fragment", raw)
	}

	return u, nil
}

// isLoopbackHost reports whether host is localhost or a loopback IP address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// registerDirectoryRoutes registers the endpoints Obot uses to read the OneLogin directory. Every one of them calls
// the admin API, so when there is no API client each answers 503 instead. They stay registered either way, so a
// directory request never falls through to the oauth2-proxy handler at /.
func (s *server) registerDirectoryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/obot-list-auth-groups", s.requireAPIClient(s.failWhenRateLimited(authcommon.ListGroupsHandler(profile.ProviderKind, s.fetchGroupPage))))
	mux.HandleFunc("/obot-get-auth-groups", s.requireAPIClient(authcommon.GetGroupsHandler(profile.ProviderKind, s.fetchGroupsByIDs)))
	mux.HandleFunc("/obot-list-user-auth-groups", s.requireAPIClient(s.listUserGroups))
}

// requireAPIClient returns next when there is an admin API client to serve it, and otherwise a handler that answers
// every request with 503 Service Unavailable.
func (s *server) requireAPIClient(next http.HandlerFunc) http.HandlerFunc {
	if s.apiClient != nil {
		return next
	}

	return func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, directoryUnavailableMessage, http.StatusServiceUnavailable)
	}
}

// failWhenRateLimited answers 503 Service Unavailable, without calling next, while the admin API client is waiting
// out a OneLogin 429. next would fail anyway, because the client fails every call fast until then, but
// authcommon's handlers report every failure as a 500.
//
// It is not used for GET /obot-get-auth-groups, whose role names mostly come from the role-name cache.
func (s *server) failWhenRateLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err, ok := errors.AsType[*client.RateLimitedError](s.apiClient.RateLimitErr()); ok {
			writeRateLimited(w, err)
			return
		}

		next(w, r)
	}
}

// writeRateLimited answers 503 Service Unavailable for a OneLogin 429, with a Retry-After of when the client will
// call OneLogin again.
func writeRateLimited(w http.ResponseWriter, err *client.RateLimitedError) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(err.RetryAfter.Seconds()))))
	http.Error(w, err.Error(), http.StatusServiceUnavailable)
}

// fetchGroupPage fetches one page of the OneLogin account's roles, which Obot treats as groups. Paging, filtering
// and cursor handling all live in authcommon.ListGroupsHandler, which serves GET /obot-list-auth-groups.
func (s *server) fetchGroupPage(ctx context.Context, req authcommon.PageRequest) (authcommon.PageResult, error) {
	return profile.FetchGroupPage(ctx, s.apiClient, req)
}

// fetchGroupsByIDs resolves OneLogin role IDs to their current names, for authcommon.GetGroupsHandler, which serves
// GET /obot-get-auth-groups.
func (s *server) fetchGroupsByIDs(ctx context.Context, ids []string) (state.GroupInfoList, error) {
	return profile.FetchGroupsByIDs(ctx, s.roles, ids)
}

// listUserGroups handles POST /obot-list-user-auth-groups: it returns the roles the specified user holds.
// The request body is the user's numeric OneLogin user ID, as plain text.
//
// It answers 403 for a user who is not active in OneLogin, or who OneLogin no longer has, and 503 while OneLogin is
// rate limiting the admin API client. Obot then keeps the user's cached groups.
func (s *server) listUserGroups(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUserIDBodyBytes)
	defer func() { _ = r.Body.Close() }()

	userIDBytes, err := io.ReadAll(r.Body)
	if err != nil {
		status := http.StatusBadRequest
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), status)
		return
	}

	userID := strings.TrimSpace(string(userIDBytes))
	if userID == "" {
		http.Error(w, "user ID is required in request body", http.StatusBadRequest)
		return
	}

	groups, err := profile.FetchUserGroupInfos(r.Context(), s.apiClient, s.roles, userID)
	if err != nil {
		var (
			unavailableErr *profile.UserUnavailableError
			rateLimitErr   *client.RateLimitedError
		)
		switch {
		case errors.Is(err, profile.ErrInvalidUserID):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.As(err, &unavailableErr):
			http.Error(w, unavailableErr.Error(), http.StatusForbidden)
		case errors.As(err, &rateLimitErr):
			writeRateLimited(w, rateLimitErr)
		default:
			http.Error(w, fmt.Sprintf("failed to fetch user groups: %v", err), http.StatusInternalServerError)
		}
		return
	}

	if groups == nil {
		groups = state.GroupInfoList{}
	}

	if err := json.NewEncoder(w).Encode(groups); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode groups: %v", err), http.StatusInternalServerError)
		return
	}
}

// getUserInfo handles GET /obot-get-user-info: it returns the ID and name of the user whose access token is in the
// Authorization header. OneLogin does not support user profile photos, so icon_url is always empty.
func (s *server) getUserInfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		http.Error(w, "no authorization token provided", http.StatusUnauthorized)
		return
	}

	u, err := profile.GetUserInfo(r.Context(), s.httpClient, token, s.issuerURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get user: %v", err), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(u); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode user info: %v", err), http.StatusInternalServerError)
		return
	}
}

// oauthCallback handles /oauth2/callback. When OneLogin redirects back with error=access_denied, it renders
// oauth2-proxy's error page with accessDeniedMessage, because oauth2-proxy's own message names only the error code.
// Every other callback goes to oauth2-proxy.
func oauthCallback(proxy callbackProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("error") != "access_denied" {
			proxy.ServeHTTP(w, r)
			return
		}

		// %q escapes the description, so that a crafted one cannot forge log lines.
		logger.Errorf("OneLogin denied the sign-in: access_denied: %q", truncate(query.Get("error_description"), maxLoggedErrorDescriptionBytes))
		// ErrorPage reads the request scope that oauth2-proxy's own middleware adds, and dereferences it, but this
		// request has not been through that middleware.
		if middlewareapi.GetRequestScope(r) == nil {
			r = middlewareapi.AddRequestScope(r, &middlewareapi.RequestScope{})
		}
		proxy.ErrorPage(w, r, http.StatusForbidden, accessDeniedMessage, accessDeniedMessage)
	}
}

// truncate returns s cut to at most n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
