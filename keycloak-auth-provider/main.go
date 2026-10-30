package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/keycloak-auth-provider/pkg/client"
	"github.com/obot-platform/enterprise-providers/keycloak-auth-provider/pkg/profile"
	"github.com/obot-platform/providers/auth-providers-common/pkg/env"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

type Options struct {
	LoggingEnabled                    string `env:"OBOT_AUTH_PROVIDER_ENABLE_LOGGING" optional:"true"`
	ClientID                          string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_ID"`
	ClientSecret                      string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_SECRET"`
	IssuerURL                         string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_ISSUER_URL"`
	ObotServerURL                     string `env:"OBOT_SERVER_PUBLIC_URL,OBOT_SERVER_URL"`
	PostgresConnectionDSN             string `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN" optional:"true"`
	PostgresMaxConnections            int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_MAX_CONNECTIONS" optional:"true"`
	PostgresMaxIdleConnections        int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_MAX_IDLE_CONNECTIONS" optional:"true"`
	PostgresConnectionLifetimeSeconds int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_LIFETIME_SECONDS" optional:"true"`
	AuthCookieSecret                  string `usage:"Secret used to encrypt cookie" env:"OBOT_AUTH_PROVIDER_COOKIE_SECRET"`
	AuthEmailDomains                  string `usage:"Email domains allowed for authentication" default:"*" env:"OBOT_AUTH_PROVIDER_EMAIL_DOMAINS"`
	AuthTokenRefreshDuration          string `usage:"Duration to refresh auth token after" optional:"true" default:"1h" env:"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION"`

	// Require explicit email verification unless the administrator opts out.
	InsecureOIDCAllowUnverifiedEmail string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_INSECURE_ALLOW_UNVERIFIED_EMAIL" default:"false" optional:"true"`

	ServiceClientID     string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_SERVICE_CLIENT_ID"`
	ServiceClientSecret string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_SERVICE_CLIENT_SECRET"`

	// AdminURL is the Keycloak base URL for Admin REST reads when /admin is not served on the issuer's host.
	AdminURL string `env:"OBOT_KEYCLOAK_AUTH_PROVIDER_ADMIN_URL" optional:"true"`
}

type server struct {
	directory   *client.Client
	userInfoURL string
}

func main() {
	var opts Options
	if err := env.LoadEnvForStruct(&opts); err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to load options: %v\n", err)
		os.Exit(1)
	}

	endpoints, err := client.Discover(context.Background(), opts.IssuerURL, nil)
	if err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: %v\n", err)
		os.Exit(1)
	}
	opts.IssuerURL = endpoints.Issuer
	if opts.AdminURL != "" {
		if endpoints, err = client.WithAdminBaseURL(endpoints, opts.AdminURL); err != nil {
			fmt.Printf("ERROR: keycloak-auth-provider: %v\n", err)
			os.Exit(1)
		}
	}

	oauthProxyOpts, err := buildOAuthProxyOptions(opts)
	if err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to configure oauth2 proxy: %v\n", err)
		os.Exit(1)
	}

	if err = validation.Validate(oauthProxyOpts); err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to validate options: %v\n", err)
		os.Exit(1)
	}

	oauthProxy, err := oauth2proxy.NewOAuthProxy(oauthProxyOpts, oauth2proxy.NewValidator(oauthProxyOpts.EmailDomains, oauthProxyOpts.AuthenticatedEmailsFile))
	if err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to create oauth2 proxy: %v\n", err)
		os.Exit(1)
	}

	srv := &server{
		directory:   client.New(endpoints, opts.ServiceClientID, opts.ServiceClientSecret, nil),
		userInfoURL: endpoints.UserInfoURL,
	}
	go checkDirectoryAccess(srv.directory)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "http://127.0.0.1:%s", port)
	})
	// buildOAuthProxyOptions already rejected an invalid policy value.
	allowUnverified, _ := allowUnverifiedEmail(opts)
	mux.HandleFunc("/obot-get-state", verifiedStateHandler(oauthProxy, allowUnverified))
	mux.HandleFunc("/obot-get-user-info", srv.getUserInfo)
	mux.HandleFunc("/obot-list-auth-groups", authcommon.ListGroupsHandler("keycloak", srv.fetchGroupPage))
	mux.HandleFunc("/obot-get-auth-groups", authcommon.GetGroupsHandler("keycloak", srv.fetchGroupsByIDs))
	mux.HandleFunc("/obot-list-user-auth-groups", srv.listUserGroups)
	mux.HandleFunc("/", oauthProxy.ServeHTTP)

	listenHost := os.Getenv("OBOT_PROVIDER_LISTEN_HOST")
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}

	addr := listenHost + ":" + port
	fmt.Printf("listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("ERROR: keycloak-auth-provider: failed to listen and serve: %v\n", err)
		os.Exit(1)
	}
}

// checkDirectoryAccess reports a broken directory configuration at startup. It only logs: a provider that
// exits locks every user out, while one that runs still signs them in.
func checkDirectoryAccess(directory *client.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := profile.CheckDirectoryAccess(ctx, directory); err != nil {
		fmt.Printf("ERROR: keycloak-auth-provider: directory check failed: %v. Group lookups for sign-ins will fail until this is fixed.\n", err)
		return
	}
	fmt.Println("keycloak-auth-provider: directory access verified")
}

// allowUnverifiedEmail reads the email verification policy. Unset means verified emails are required.
func allowUnverifiedEmail(opts Options) (bool, error) {
	if opts.InsecureOIDCAllowUnverifiedEmail == "" {
		return false, nil
	}
	allow, err := strconv.ParseBool(opts.InsecureOIDCAllowUnverifiedEmail)
	if err != nil {
		return false, fmt.Errorf("invalid OBOT_KEYCLOAK_AUTH_PROVIDER_INSECURE_ALLOW_UNVERIFIED_EMAIL: %w", err)
	}
	return allow, nil
}

// buildOAuthProxyOptions configures sign-in and session policy in one place.
func buildOAuthProxyOptions(opts Options) (*options.Options, error) {
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

	if _, err := allowUnverifiedEmail(opts); err != nil {
		return nil, err
	}

	legacyOpts := options.NewLegacyOptions()
	legacyOpts.LegacyProvider.ProviderType = "oidc"
	legacyOpts.LegacyProvider.ProviderName = "oidc"
	legacyOpts.LegacyProvider.ClientID = opts.ClientID
	legacyOpts.LegacyProvider.ClientSecret = opts.ClientSecret
	legacyOpts.LegacyProvider.OIDCIssuerURL = opts.IssuerURL
	legacyOpts.LegacyProvider.Scope = "openid email profile offline_access"
	// oauth2-proxy would refuse an unverified email at the callback, where nothing records why. The policy is
	// enforced and logged by verifiedStateHandler instead, which every identity Obot uses passes through.
	legacyOpts.LegacyProvider.InsecureOIDCAllowUnverifiedEmail = true

	oauthProxyOpts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("convert legacy options: %w", err)
	}

	oauthProxyOpts.Server.BindAddress = ""
	oauthProxyOpts.MetricsServer.BindAddress = ""
	if opts.PostgresConnectionDSN != "" {
		oauthProxyOpts.Session.Type = options.PostgresSessionStoreType
		oauthProxyOpts.Session.Postgres.ConnectionDSN = opts.PostgresConnectionDSN
		oauthProxyOpts.Session.Postgres.MaxOpenConns = opts.PostgresMaxConnections
		oauthProxyOpts.Session.Postgres.MaxIdleConns = opts.PostgresMaxIdleConnections
		oauthProxyOpts.Session.Postgres.ConnMaxLifetime = opts.PostgresConnectionLifetimeSeconds
		oauthProxyOpts.Session.Postgres.TableNamePrefix = "keycloak_"
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

	return oauthProxyOpts, nil
}

// fetchGroupPage fetches one page of realm groups. Paging, filtering and cursor
// handling all live in authcommon.ListGroupsHandler, which serves GET /obot-list-auth-groups.
func (s *server) fetchGroupPage(ctx context.Context, req authcommon.PageRequest) (authcommon.PageResult, error) {
	return profile.FetchGroupPage(ctx, s.directory, req)
}

// listUserGroups returns direct groups and every ancestor for the specified user.
// Accepts a plain text body containing the user ID.
func (s *server) listUserGroups(w http.ResponseWriter, r *http.Request) {
	userIDBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	userID := strings.TrimSpace(string(userIDBytes))
	if strings.TrimSpace(userID) == "" {
		http.Error(w, "user ID is required in request body", http.StatusBadRequest)
		return
	}

	groups, err := profile.FetchUserGroupInfos(r.Context(), s.directory, userID)
	if err != nil {
		var unavailable *profile.UserUnavailableError
		if errors.As(err, &unavailable) {
			http.Error(w, unavailable.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, fmt.Sprintf("failed to fetch user groups: %v", err), http.StatusInternalServerError)
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

// getUserInfo returns user information including ID, name, and profile picture.
func (s *server) getUserInfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		http.Error(w, "no authorization token provided", http.StatusUnauthorized)
		return
	}

	u, err := profile.GetUserInfo(r.Context(), token, s.userInfoURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get user: %v", err), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(u); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode user info: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) fetchGroupsByIDs(ctx context.Context, ids []string) (state.GroupInfoList, error) {
	return profile.FetchGroupsByIDs(ctx, s.directory, ids)
}
