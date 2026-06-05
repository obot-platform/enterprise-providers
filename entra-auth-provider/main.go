package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/enterprise-providers/entra-auth-provider/pkg/client"
	"github.com/obot-platform/enterprise-providers/entra-auth-provider/pkg/profile"
	"github.com/obot-platform/providers/auth-providers-common/pkg/env"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
	"github.com/sahilm/fuzzy"
)

type Options struct {
	ClientID              string `env:"OBOT_ENTRA_AUTH_PROVIDER_CLIENT_ID"`
	ClientSecret          string `env:"OBOT_ENTRA_AUTH_PROVIDER_CLIENT_SECRET"`
	TenantID              string `env:"OBOT_ENTRA_AUTH_PROVIDER_TENANT_ID"`
	ObotServerURL         string `env:"OBOT_SERVER_PUBLIC_URL,OBOT_SERVER_URL"`
	PostgresConnectionDSN string `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN" optional:"true"`
	AuthCookieSecret      string `usage:"Secret used to encrypt cookie" env:"OBOT_AUTH_PROVIDER_COOKIE_SECRET"`
	AuthEmailDomains      string `usage:"Email domains allowed for authentication" default:"*" env:"OBOT_AUTH_PROVIDER_EMAIL_DOMAINS"`
	LoggingEnabled        string `usage:"Enable oauth2-proxy logging" optional:"true" env:"OBOT_AUTH_PROVIDER_ENABLE_LOGGING"`
}

type server struct {
	graphClient *msgraphsdkgo.GraphServiceClient
}

func main() {
	var opts Options
	if err := env.LoadEnvForStruct(&opts); err != nil {
		fmt.Printf("failed to load options: %v\n", err)
		os.Exit(1)
	}

	if strings.ToLower(opts.TenantID) == "common" {
		fmt.Printf("ERROR: tenant ID cannot be set to 'common'. Multitenant configurations are not supported.\n")
		os.Exit(1)
	}

	cookieSecret, err := base64.StdEncoding.DecodeString(opts.AuthCookieSecret)
	if err != nil {
		fmt.Printf("failed to decode cookie secret: %v\n", err)
		os.Exit(1)
	}

	legacyOpts := options.NewLegacyOptions()
	legacyOpts.LegacyProvider.ProviderType = "entra-id"
	legacyOpts.LegacyProvider.ProviderName = "entra-id"
	legacyOpts.LegacyProvider.ClientID = opts.ClientID
	legacyOpts.LegacyProvider.ClientSecret = opts.ClientSecret
	legacyOpts.LegacyProvider.OIDCIssuerURL = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", opts.TenantID)
	legacyOpts.LegacyProvider.Scope = "openid profile email offline_access User.Read ProfilePhoto.Read.All"

	oauthProxyOpts, err := legacyOpts.ToOptions()
	if err != nil {
		fmt.Printf("failed to convert legacy options to new options: %v\n", err)
		os.Exit(1)
	}

	oauthProxyOpts.Server.BindAddress = ""
	oauthProxyOpts.MetricsServer.BindAddress = ""
	if opts.PostgresConnectionDSN != "" {
		oauthProxyOpts.Session.Type = options.PostgresSessionStoreType
		oauthProxyOpts.Session.Postgres.ConnectionDSN = opts.PostgresConnectionDSN
		oauthProxyOpts.Session.Postgres.TableNamePrefix = "entra_"
	}
	oauthProxyOpts.Cookie.Refresh = time.Hour
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

	if err = validation.Validate(oauthProxyOpts); err != nil {
		fmt.Printf("failed to validate options: %v\n", err)
		os.Exit(1)
	}

	oauthProxy, err := oauth2proxy.NewOAuthProxy(oauthProxyOpts, oauth2proxy.NewValidator(oauthProxyOpts.EmailDomains, oauthProxyOpts.AuthenticatedEmailsFile))
	if err != nil {
		fmt.Printf("failed to create oauth2 proxy: %v\n", err)
		os.Exit(1)
	}

	// Initialize graph client for group fetching
	graphClient, err := client.NewClient(opts.TenantID, opts.ClientID, opts.ClientSecret)
	if err != nil {
		fmt.Printf("entra-auth-provider: failed to initialize graph client: %v\n", err)
		os.Exit(1)
	}

	// Initialize application token manager for Microsoft Graph API calls
	srv := &server{
		graphClient: graphClient,
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fmt.Appendf(nil, "http://127.0.0.1:%s", port))
	})
	mux.HandleFunc("/obot-get-state", state.ObotGetState(oauthProxy))
	mux.HandleFunc("/obot-get-user-info", getUserInfo)
	mux.HandleFunc("/obot-list-auth-groups", srv.listGroups)
	mux.HandleFunc("/obot-list-user-auth-groups", srv.listUserGroups)
	mux.HandleFunc("/", oauthProxy.ServeHTTP)

	listenHost := os.Getenv("OBOT_PROVIDER_LISTEN_HOST")
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}

	addr := listenHost + ":" + port
	if err := http.ListenAndServe(addr, mux); !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("failed to listen and serve: %v\n", err)
		os.Exit(1)
	}
}

// listGroups returns all groups in the tenant with optional fuzzy name filtering.
// Uses application permissions. Body is ignored (no user ID needed for listing all groups).
func (s *server) listGroups(w http.ResponseWriter, r *http.Request) {
	// Note: Request body is ignored for this endpoint since we're listing all groups,
	// not user-specific groups. The body may be present for consistency with other endpoints.

	// Fetch all groups using application permissions
	groups, err := profile.FetchGroupInfos(r.Context(), s.graphClient)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch groups: %v", err), http.StatusInternalServerError)
		return
	}

	if groups == nil {
		groups = state.GroupInfoList{}
	}

	// Apply fuzzy name filtering if requested via query parameter
	nameFilter := r.URL.Query().Get("name")
	if nameFilter != "" && len(groups) > 0 {
		groupNames := make([]string, len(groups))
		for i, group := range groups {
			groupNames[i] = group.Name
		}

		matches := fuzzy.Find(nameFilter, groupNames)

		var filteredGroups state.GroupInfoList
		for _, match := range matches {
			filteredGroups = append(filteredGroups, groups[match.Index])
		}
		groups = filteredGroups
	}

	if err := json.NewEncoder(w).Encode(groups); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode groups: %v", err), http.StatusInternalServerError)
		return
	}
}

// listUserGroups returns all groups the specified user belongs to.
// Accepts a plain text body containing the user ID and queries Microsoft Graph using application permissions.
func (s *server) listUserGroups(w http.ResponseWriter, r *http.Request) {
	// Read user ID from request body (plain text, not JSON)
	userIDBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	userID := strings.TrimSpace(string(userIDBytes))
	if userID == "" {
		http.Error(w, "user ID is required in request body", http.StatusBadRequest)
		return
	}

	// Fetch user's group memberships using application permissions
	groups, err := profile.FetchUserGroupInfos(r.Context(), s.graphClient, userID)
	if err != nil {
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

// getUserInfo returns user information including profile photo and preferred name.
// The profile photo is returned as a base64 data URL for direct embedding.
// The preferred name is extracted from the OIDC ID token when available.
func getUserInfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		http.Error(w, "no authorization token provided", http.StatusUnauthorized)
		return
	}

	// Create client with minimal scope and fetch user (cache-first photo)
	userClient, err := client.NewStaticClient(token)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create client: %v", err), http.StatusInternalServerError)
		return
	}

	u, err := profile.GetUserInfo(r.Context(), userClient)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get user: %v", err), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(u); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode user info: %v", err), http.StatusInternalServerError)
		return
	}
}
