package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/pingfederate-auth-provider/pkg/oidc"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

const (
	providerName = "pingfederate-auth-provider"

	// providerKind names this provider to authcommon, which binds group
	// listing cursors to it and strips it, as a prefix, from group IDs.
	providerKind = "pingfederate"
	// groupIDPrefix namespaces the group IDs this provider reports. Obot
	// rejects groups outside the prefix declared in the manifest, so this
	// constant and the manifest's groupIDPrefix must agree.
	groupIDPrefix = providerKind + "/"

	cacheSize    = 10000
	cacheTTL     = 24 * time.Hour
	maxBodyBytes = 64 << 10

	// tokenGroupsRetry is how long to wait before asking userinfo again for
	// an access token after it failed.
	tokenGroupsRetry = time.Minute
)

// tokenGroupsTTL is how long userinfo's answer for an access token is reused:
// until the session is due for a refresh, which brings a new token, so that an
// answer is never reused much past the point it would have been asked again.
func tokenGroupsTTL(cfg *settings) time.Duration {
	if cfg.refreshDuration > 0 && cfg.refreshDuration < cacheTTL {
		return cfg.refreshDuration
	}
	return cacheTTL
}

// userinfoGroups is what userinfo reported about an access token's groups.
type userinfoGroups struct {
	// observedAt is when userinfo answered.
	observedAt time.Time
	// subject is the subject userinfo answered for.
	subject string
	// groups is the groups claim, empty when userinfo carries none:
	// PingFederate omits an empty multi-valued attribute.
	groups []string
}

// server wires oauth2-proxy (which owns the OAuth2/OIDC login flow and the
// session cookie) to the extra endpoints Obot calls on an auth provider.
type server struct {
	cfg         *settings
	proxy       *oauth2proxy.OAuthProxy
	httpClient  *http.Client
	userinfoURL string
	listenURL   string

	// store records each user's groups under every identifier Obot might use
	// for them (subject, user claim, email), and every group seen. Obot asks
	// for a user's groups by the ID it learned from /obot-get-user-info,
	// without a token, so the answer has to come from what earlier calls
	// recorded, possibly on another replica.
	store groupStore
	// tokenGroups holds, per access token, the groups userinfo reported for
	// it. A session's own groups come from its ID token, and PingFederate
	// does not issue a new ID token on refresh by default, so userinfo is
	// asked once per access token for the user's current groups.
	tokenGroups *expirable.LRU[string, userinfoGroups]
	// tokenGroupsFailed remembers, briefly, the access tokens for which
	// userinfo failed, so that a failing endpoint is not asked on every request.
	tokenGroupsFailed *expirable.LRU[string, struct{}]
	// idTokenClaims maps an access token to the claims of the ID token issued
	// with it, as a fallback profile when the userinfo endpoint is unavailable.
	idTokenClaims *expirable.LRU[string, map[string]any]
	// userinfo caches userinfo responses by access token. Obot asks for the
	// profile on nearly every request, and PingFederate should not see that.
	userinfo *expirable.LRU[string, userinfoAnswer]
	// directory answers Obot's group search and lookups.
	directory *groupDirectory
}

func newServer(ctx context.Context, cfg *settings, listenURL string) (*server, error) {
	httpClient, err := oidc.NewHTTPClient(cfg.caFiles)
	if err != nil {
		return nil, err
	}

	discovery, err := oidc.Discover(ctx, httpClient, cfg.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed for issuer %s: %w", cfg.issuerURL, err)
	}
	if discovery.Issuer != cfg.issuerURL {
		return nil, fmt.Errorf("the discovery document reports issuer %q, which does not match the configured issuer URL %q; set the issuer URL to the reported value", discovery.Issuer, cfg.issuerURL)
	}
	// oauth2-proxy sends the client secret, codes, and tokens to these
	// endpoints, and trusts the keys at the JWKS endpoint.
	for name, endpoint := range map[string]string{
		"authorization endpoint": discovery.AuthorizationEndpoint,
		"token endpoint":         discovery.TokenEndpoint,
		"JWKS endpoint":          discovery.JwksURI,
	} {
		if err := ValidateEndpointURL("the discovery document's "+name, endpoint); err != nil {
			return nil, err
		}
	}
	userinfoURL := discovery.UserinfoEndpoint
	if userinfoURL != "" {
		if err := ValidateEndpointURL("the discovery document's userinfo endpoint", userinfoURL); err != nil {
			return nil, err
		}
	}
	if userinfoURL == "" {
		slog.Warn("the discovery document has no userinfo endpoint; user profiles will be read from ID token claims only")
	}

	proxy, err := newOAuthProxyWithRetry(cfg)
	if err != nil {
		return nil, err
	}

	var store groupStore = newMemoryGroupStore()
	if cfg.PostgresConnectionDSN != "" {
		pg, err := openPostgresGroupStore(cfg)
		if err != nil {
			return nil, err
		}
		go pg.pruneEvery(ctx, pruneInterval)
		store = pg
	} else {
		slog.Info("no database is configured; user groups are kept in memory and are not shared with other replicas")
	}

	s := &server{
		cfg:               cfg,
		proxy:             proxy,
		httpClient:        httpClient,
		userinfoURL:       userinfoURL,
		listenURL:         listenURL,
		store:             store,
		tokenGroups:       expirable.NewLRU[string, userinfoGroups](cacheSize, nil, tokenGroupsTTL(cfg)),
		tokenGroupsFailed: expirable.NewLRU[string, struct{}](cacheSize, nil, tokenGroupsRetry),
		idTokenClaims:     expirable.NewLRU[string, map[string]any](cacheSize, nil, cacheTTL),
		directory:         newGroupDirectory(cfg.knownGroups, store),
	}
	if cfg.userinfoCacheTTL > 0 {
		s.userinfo = expirable.NewLRU[string, userinfoAnswer](cacheSize, nil, cfg.userinfoCacheTTL)
	}
	return s, nil
}

// newOAuthProxyWithRetry creates the oauth2-proxy, retrying a failure when
// sessions are kept in PostgreSQL: oauth2-proxy creates its session tables
// when it starts, and every replica starts the provider at once when it is
// first configured, so creating the same tables at the same moment can fail on
// all but one of them.
func newOAuthProxyWithRetry(cfg *settings) (*oauth2proxy.OAuthProxy, error) {
	proxy, err := newOAuthProxy(cfg)
	for attempt := 1; err != nil && cfg.PostgresConnectionDSN != "" && attempt < 3; attempt++ {
		slog.Warn("failed to start oauth2-proxy; retrying", "attempt", attempt, "error", err)
		time.Sleep(time.Duration(attempt) * time.Second)
		proxy, err = newOAuthProxy(cfg)
	}
	return proxy, err
}

// newOAuthProxy configures oauth2-proxy's generic OpenID Connect provider for
// PingFederate. Everything Obot-specific (cookie name, redirect URL, session
// store) mirrors the other Obot auth providers so the gateway treats this one
// the same way.
func newOAuthProxy(cfg *settings) (*oauth2proxy.OAuthProxy, error) {
	legacyOpts := options.NewLegacyOptions()
	provider := &legacyOpts.LegacyProvider
	provider.ProviderType = "oidc"
	provider.ProviderName = "PingFederate"
	provider.ClientID = cfg.ClientID
	provider.ClientSecret = cfg.ClientSecret
	provider.OIDCIssuerURL = cfg.issuerURL
	provider.Scope = cfg.scopes
	provider.OIDCEmailClaim = cfg.EmailClaim
	// The session's User field, which Obot stores as the provider user ID,
	// is the OIDC subject: oauth2-proxy's default for this provider type and
	// what Obot's other OIDC providers report. Its legacy "user ID claim"
	// option is deliberately left alone, because setting it to anything but
	// "email" silently redefines the email claim as well.
	provider.OIDCGroupsClaim = cfg.GroupsClaim
	// PingFederate is a certified OpenID provider: it echoes the nonce,
	// advertises its issuer, and supports S256 PKCE, so none of these checks
	// is configurable. They are set explicitly because oauth2-proxy's legacy
	// defaults skip nonce verification.
	provider.InsecureOIDCAllowUnverifiedEmail = false
	provider.InsecureOIDCSkipIssuerVerification = false
	provider.InsecureOIDCSkipNonce = false
	provider.CodeChallengeMethod = "S256"
	if len(cfg.caFiles) > 0 {
		provider.ProviderCAFiles = cfg.caFiles
		provider.UseSystemTrustStore = true
	}

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to convert legacy options: %w", err)
	}

	opts.Server.BindAddress = ""
	opts.MetricsServer.BindAddress = ""
	if cfg.PostgresConnectionDSN != "" {
		opts.Session.Type = options.PostgresSessionStoreType
		opts.Session.Postgres.ConnectionDSN = cfg.PostgresConnectionDSN
		opts.Session.Postgres.MaxOpenConns = cfg.PostgresMaxConnections
		opts.Session.Postgres.MaxIdleConns = cfg.PostgresMaxIdleConnections
		opts.Session.Postgres.ConnMaxLifetime = cfg.PostgresConnectionLifetimeSeconds
		opts.Session.Postgres.TableNamePrefix = "pingfederate_"
	}
	opts.Cookie.Refresh = cfg.refreshDuration
	opts.Cookie.Name = "obot_access_token"
	opts.Cookie.Secret = cfg.cookieSecret
	opts.Cookie.Secure = strings.HasPrefix(cfg.ObotServerURL, "https://")
	opts.Cookie.CSRFExpire = 30 * time.Minute
	opts.RawRedirectURL = cfg.ObotServerURL + "/"
	opts.EmailDomains = cfg.emailDomains
	opts.Logging.RequestEnabled = cfg.loggingEnabled
	opts.Logging.AuthEnabled = cfg.loggingEnabled
	opts.Logging.StandardEnabled = cfg.loggingEnabled

	if err := validation.Validate(opts); err != nil {
		return nil, fmt.Errorf("invalid oauth2-proxy configuration: %w", err)
	}

	proxy, err := oauth2proxy.NewOAuthProxy(opts, oauth2proxy.NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile))
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth2 proxy: %w", err)
	}
	return proxy, nil
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(s.listenURL))
	})
	mux.HandleFunc("/obot-get-state", s.getState)
	mux.HandleFunc("/obot-get-user-info", s.getUserInfo)
	mux.HandleFunc("/obot-list-user-auth-groups", s.listUserAuthGroups)
	mux.HandleFunc("/obot-list-auth-groups", authcommon.ListGroupsHandler(providerKind, s.fetchGroupPage))
	mux.HandleFunc("/obot-get-auth-groups", authcommon.GetGroupsHandler(providerKind, s.fetchGroupsByIDs))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/obot-") {
			// An Obot-internal endpoint this provider does not know must not
			// fall through to oauth2-proxy, whose sign-in page would be
			// mistaken for a provider failure.
			notSupported(w, r)
			return
		}
		s.proxy.ServeHTTP(w, r)
	})
	return mux
}

func notSupported(w http.ResponseWriter, r *http.Request) {
	http.Error(w, fmt.Sprintf("%s is not supported by %s", r.URL.Path, providerName), http.StatusNotFound)
}

// getState answers Obot's question "who sent this request?" from the session
// cookie, refreshing the upstream tokens when due, and records what it learned
// about the user's groups for later lookups.
func (s *server) getState(w http.ResponseWriter, r *http.Request) {
	var sr state.SerializableRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&sr); err != nil {
		http.Error(w, fmt.Sprintf("failed to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), sr.Method, sr.URL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create request object: %v", err), http.StatusBadRequest)
		return
	}
	req.Header = sr.Header

	ss, err := state.GetSerializableState(s.proxy, req)
	if err != nil {
		// An invalid session answers 401 so Obot clears the cookie instead of
		// failing the request; anything else is a provider failure.
		state.WriteStateError(w, err)
		return
	}

	s.recordSession(r.Context(), &ss)
	if len(ss.SetCookies) > 0 {
		// The state of a request that refreshed the session is the session
		// from before the refresh. Load the refreshed one from the cookies the
		// refresh set, and record from it, so that groups follow the refresh
		// even if the client never sends those cookies back.
		if refreshed, ok := s.refreshedState(req, ss.SetCookies); ok {
			s.recordSession(r.Context(), &refreshed)
			ss.GroupInfos = refreshed.GroupInfos
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ss); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode state: %v", err), http.StatusInternalServerError)
	}
}

// refreshedState loads the session a refresh just created, by replaying req
// with the cookies the refresh set in place of the ones it carried.
func (s *server) refreshedState(req *http.Request, setCookies []string) (state.SerializableState, bool) {
	header := http.Header{}
	for _, c := range setCookies {
		header.Add("Set-Cookie", c)
	}
	refreshedCookies := (&http.Response{Header: header}).Cookies()
	replaced := map[string]bool{}
	for _, c := range refreshedCookies {
		replaced[c.Name] = true
	}

	refreshedReq := req.Clone(req.Context())
	refreshedReq.Header.Del("Cookie")
	for _, c := range req.Cookies() {
		if !replaced[c.Name] {
			refreshedReq.AddCookie(c)
		}
	}
	for _, c := range refreshedCookies {
		if c.MaxAge >= 0 && c.Value != "" {
			refreshedReq.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}

	refreshed, err := state.GetSerializableState(s.proxy, refreshedReq)
	if err != nil || len(refreshed.SetCookies) > 0 {
		slog.Warn("could not load the refreshed session to record the user's groups", "error", err)
		return state.SerializableState{}, false
	}
	return refreshed, true
}

// recordSession fills in the group information for a session and records it
// under the user's subject, the identifier Obot looks a user's groups up by.
func (s *server) recordSession(ctx context.Context, ss *state.SerializableState) {
	claims := map[string]any{}
	claimsReadable := true
	if ss.IDToken != "" {
		// oauth2-proxy verified this token when it created or refreshed the
		// session, so reading its claims without re-verifying is safe.
		parsed, err := oidc.UnverifiedClaims(ss.IDToken)
		if err != nil {
			slog.Warn("could not read ID token claims", "error", err)
			claimsReadable = false
		} else {
			claims = parsed
		}
	}
	subject := oidc.StringClaim(claims, "sub")
	if subject == "" {
		// oauth2-proxy sets the session's user to the subject.
		subject = ss.User
	}

	groups, observedAt, record := s.sessionGroups(ctx, ss.AccessToken, subject, claims)
	ss.GroupInfos = groupInfos(groups)
	// The state of a request that refreshed the session is the session from
	// before the refresh, with its old access token; the refreshed one comes
	// back in cookies, and the next request records from it. Likewise a
	// session whose access token has expired, and one whose ID token cannot
	// be read, say nothing current about the user's groups.
	if len(ss.SetCookies) > 0 || (ss.ExpiresOn != nil && ss.ExpiresOn.Before(time.Now())) || !claimsReadable {
		record = false
	}
	if record {
		s.rememberGroups(ctx, subject, groups, observedAt)
	}
	if ss.AccessToken != "" && len(claims) > 0 {
		s.idTokenClaims.Add(ss.AccessToken, claims)
	}
}

// sessionGroups returns the user's groups for a session, when they were
// observed, and whether they are current enough to record for Obot's lookups.
//
// With a userinfo endpoint, which PingFederate always has, groups come from
// userinfo alone: it evaluates the user's attributes when it is asked, while a
// session's ID token is the one it was created with, which PingFederate does
// not reissue on refresh by default. A userinfo answer without the groups
// claim means the user has no groups, since PingFederate omits an empty
// attribute. If userinfo fails, nothing is recorded, and the existing record
// stands. Only without a userinfo endpoint are the ID token's groups used,
// observed when it was issued.
func (s *server) sessionGroups(ctx context.Context, token, subject string, idTokenClaims map[string]any) ([]string, time.Time, bool) {
	tokenGroups := oidc.StringsClaim(idTokenClaims, s.cfg.GroupsClaim, s.cfg.GroupsDelimiter)
	if subject == "" {
		return tokenGroups, time.Time{}, false
	}
	if s.userinfoURL == "" {
		issued := oidc.TimeClaim(idTokenClaims, "iat")
		return tokenGroups, issued, !issued.IsZero()
	}
	current, ok := s.currentGroups(ctx, token, subject)
	if !ok {
		return tokenGroups, time.Time{}, false
	}
	return current.groups, current.observedAt, true
}

// currentGroups returns what userinfo reports about the groups of the user
// behind an access token, and whether it answered for subject. It asks
// userinfo once per access token, and each refresh brings a new token, so
// groups follow PingFederate within one token refresh duration.
func (s *server) currentGroups(ctx context.Context, token, subject string) (userinfoGroups, bool) {
	if token == "" {
		return userinfoGroups{}, false
	}
	if cached, ok := s.tokenGroups.Get(token); ok {
		return cached, cached.subject == subject
	}
	if _, failed := s.tokenGroupsFailed.Get(token); failed {
		return userinfoGroups{}, false
	}
	claims, answeredAt, err := s.userinfoClaims(ctx, token)
	if err != nil {
		slog.Warn("could not read the user's current groups from userinfo; keeping their recorded groups", "error", err)
		s.tokenGroupsFailed.Add(token, struct{}{})
		return userinfoGroups{}, false
	}
	result := userinfoGroups{
		subject:    oidc.StringClaim(claims, "sub"),
		observedAt: answeredAt,
		groups:     oidc.StringsClaim(claims, s.cfg.GroupsClaim, s.cfg.GroupsDelimiter),
	}
	s.tokenGroups.Add(token, result)
	if result.subject != subject {
		// OpenID Connect requires the userinfo subject to match the ID token's
		// before the response is used.
		slog.Warn("userinfo answered for a different subject than the session's; ignoring its groups")
		return userinfoGroups{}, false
	}
	return result, true
}

// getUserInfo returns the user's profile for the access token in the
// Authorization header. Obot reads "id" (the subject, used for group lookups)
// and "name" (the user's display name).
func (s *server) getUserInfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		http.Error(w, "missing access token", http.StatusBadRequest)
		return
	}

	claims, answeredAt, err := s.userinfoClaims(r.Context(), token)
	fromUserinfo := err == nil
	if err != nil {
		cached, ok := s.idTokenClaims.Get(token)
		if !ok {
			http.Error(w, fmt.Sprintf("failed to fetch user info: %v", err), http.StatusBadRequest)
			return
		}
		slog.Warn("userinfo request failed; answering from ID token claims", "error", err)
		claims = cached
	}

	// PingFederate can release a display-name attribute only in the ID token.
	// Fill missing name fields from the already-verified session token, while
	// preserving the userinfo email and every identity/group lookup field.
	profileClaims := maps.Clone(claims)
	subject := oidc.StringClaim(claims, "sub")
	if cached, ok := s.idTokenClaims.Get(token); ok && subject != "" && oidc.StringClaim(cached, "sub") == subject {
		for _, name := range []string{s.cfg.NameClaim, "name", "given_name", "family_name", "preferred_username"} {
			if strings.TrimSpace(oidc.StringClaim(profileClaims, name)) == "" {
				if value := oidc.StringClaim(cached, name); value != "" {
					profileClaims[name] = value
				}
			}
		}
	}
	profile := s.profile(profileClaims)
	// Record groups only from a live userinfo answer: the cached ID token
	// claims are the session's, and may hold groups the user has since lost.
	// An answer without the groups claim means the user has no groups.
	if fromUserinfo && subject != "" {
		if cached, known := s.idTokenClaims.Get(token); !known || oidc.StringClaim(cached, "sub") == subject {
			groups := oidc.StringsClaim(claims, s.cfg.GroupsClaim, s.cfg.GroupsDelimiter)
			s.rememberGroups(r.Context(), subject, groups, answeredAt)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(profile); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode user info: %v", err), http.StatusInternalServerError)
	}
}

// userinfoClaims fetches the userinfo document for an access token, through
// the cache when one is configured, and returns when PingFederate gave it.
func (s *server) userinfoClaims(ctx context.Context, token string) (map[string]any, time.Time, error) {
	if s.userinfoURL == "" {
		return nil, time.Time{}, fmt.Errorf("no userinfo endpoint is configured")
	}
	if s.userinfo != nil {
		if answer, ok := s.userinfo.Get(token); ok {
			return answer.claims, answer.at, nil
		}
	}
	claims, err := oidc.Userinfo(ctx, s.httpClient, s.userinfoURL, token)
	if err != nil {
		return nil, time.Time{}, err
	}
	at := time.Now()
	if s.userinfo != nil {
		s.userinfo.Add(token, userinfoAnswer{claims: claims, at: at})
	}
	return claims, at, nil
}

// userinfoAnswer is a userinfo response and when PingFederate gave it.
type userinfoAnswer struct {
	claims map[string]any
	at     time.Time
}

// profile shapes claims into the document Obot expects from
// /obot-get-user-info. The raw claims are kept alongside the derived fields
// so nothing an administrator might want to inspect is lost.
func (s *server) profile(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims)+3)
	maps.Copy(out, claims)

	// The subject is the only identifier groups are recorded under, so it is
	// the only one Obot is given to look them up by.
	out["id"] = oidc.StringClaim(claims, "sub")
	out["name"] = oidc.DisplayName(claims, s.cfg.EmailClaim)
	if name := oidc.StringClaim(claims, s.cfg.NameClaim); strings.TrimSpace(name) != "" {
		out["name"] = name
	}
	if email := oidc.StringClaim(claims, s.cfg.EmailClaim); email != "" {
		out["email"] = email
	}
	return out
}

// listUserAuthGroups returns the groups recorded for a provider user ID. The
// request body is the bare ID. An unknown ID is reported as an error rather
// than as "no groups": Obot would persist an empty answer and drop the user's
// memberships, whereas an error keeps what it already has and retries later.
func (s *server) listUserAuthGroups(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(string(body))
	if id == "" {
		http.Error(w, "missing user ID", http.StatusBadRequest)
		return
	}

	groups, ok, err := s.store.userGroups(r.Context(), id)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to look up the groups of user %q: %v", id, err), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, fmt.Sprintf("no group information is recorded for user %q; it is recorded when the user signs in or is looked up", id), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(groupInfos(groups)); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode groups: %v", err), http.StatusInternalServerError)
	}
}

// rememberGroups records the group list, observed at observedAt, under the
// user's subject: the identifier Obot looks a user's groups up by, and the
// only one, since no user can choose another's. A failure is logged rather
// than failing the request: Obot keeps the memberships it has when a later
// lookup finds nothing.
func (s *server) rememberGroups(ctx context.Context, subject string, groups []string, observedAt time.Time) {
	if subject == "" {
		return
	}
	// An observation from the future, such as an ID token from an identity
	// provider whose clock runs fast, would outrank every later one.
	if now := time.Now(); observedAt.After(now) {
		observedAt = now
	}
	if err := s.store.recordUserGroups(ctx, subject, filterGroups(groups), observedAt); err != nil {
		slog.Warn("failed to record the user's groups", "error", err)
	}
}

// groupInfos converts raw group names into Obot's group documents, with the
// namespacing prefix Obot requires on the ID and the plain name for display.
func groupInfos(groups []string) state.GroupInfoList {
	infos := make(state.GroupInfoList, 0, len(groups))
	for _, g := range groups {
		if g = strings.TrimSpace(g); g != "" {
			infos = append(infos, state.GroupInfo{ID: groupIDPrefix + g, Name: g})
		}
	}
	return infos
}

func bearerToken(authorization string) string {
	authorization = strings.TrimLeft(authorization, " \t")
	if len(authorization) >= 7 && strings.EqualFold(authorization[:7], "bearer ") {
		authorization = authorization[7:]
	}
	return strings.TrimSpace(authorization)
}
