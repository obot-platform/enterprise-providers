package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/pingfederate-auth-provider/pkg/oidc"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

const (
	providerName = "pingfederate-auth-provider"

	// providerKind names this provider to authcommon, which binds group listing
	// cursors to it.
	providerKind = "pingfederate"
	// groupIDPrefix must match the manifest's groupIDPrefix.
	groupIDPrefix = providerKind + "/"

	cacheSize    = 10000
	cacheTTL     = 24 * time.Hour
	maxBodyBytes = 64 << 10

	// After a userinfo failure, ask again after tokenGroupsRetry, doubling up to
	// tokenGroupsMaxRetry. Short, because an unconfirmed session fails until then.
	tokenGroupsRetry    = 5 * time.Second
	tokenGroupsMaxRetry = time.Minute

	// userinfoTimeout is under Obot's 15-second state deadline, so a hanging
	// userinfo is recorded as a failure instead of cut off by Obot each time.
	userinfoTimeout = 10 * time.Second

	// confirmationMaxAge bounds how long a userinfo confirmation of a session's
	// identity lets it through userinfo failures, refreshes included.
	confirmationMaxAge = 24 * time.Hour
)

// tokenGroupsTTL reuses a token's userinfo answer until the session is due for
// a refresh, which brings a new token.
func tokenGroupsTTL(cfg *settings) time.Duration {
	if cfg.refreshDuration > 0 && cfg.refreshDuration < cacheTTL {
		return cfg.refreshDuration
	}
	return cacheTTL
}

// userinfoFailure is when userinfo may be asked again about a token.
type userinfoFailure struct {
	retryAt  time.Time
	failures int
}

// userinfoRetryDelay is the wait after the nth failure in a row.
func userinfoRetryDelay(failures int) time.Duration {
	delay := tokenGroupsRetry
	for i := 1; i < failures && delay < tokenGroupsMaxRetry; i++ {
		delay *= 2
	}
	return min(delay, tokenGroupsMaxRetry)
}

// userinfoGroups is what userinfo reported about an access token's groups.
type userinfoGroups struct {
	// observedAt is when userinfo answered.
	observedAt time.Time
	// subject is the subject userinfo answered for.
	subject string
	// email and preferredUsername are read as oauth2-proxy reads them, to
	// compare with the session (see checkUserinfoClaims).
	email             string
	preferredUsername string
	// groups is empty when the claim is missing: PingFederate omits an empty
	// multi-valued attribute.
	groups []string
}

// server wires oauth2-proxy, which runs sign-in and the session cookie, to
// the endpoints Obot calls on an auth provider.
type server struct {
	cfg         *settings
	proxy       *oauth2proxy.OAuthProxy
	httpClient  *http.Client
	userinfoURL string
	listenURL   string

	// store records each user's groups by subject, for Obot's later lookups,
	// which carry no token and may reach another replica.
	store groupStore
	// tokenGroups is the provider's userinfo answer per access token.
	tokenGroups *expirable.LRU[string, userinfoGroups]
	// tokenGroupsFailed holds tokens whose userinfo request failed recently.
	tokenGroupsFailed *expirable.LRU[string, userinfoFailure]
	// confirmedIdentities holds the identity userinfo confirmed per access
	// token, which outlives tokenGroups so it is still there at the refresh.
	confirmedIdentities *expirable.LRU[string, identityConfirmation]
	// unusableAnswers holds why userinfo's last answer for a token could not
	// be used: it refused the token, or answered incompletely.
	unusableAnswers *expirable.LRU[string, unusableAnswer]
	// userinfoReleases holds the identity claims userinfo released in its
	// last complete answer per subject, to tell an incomplete answer.
	userinfoReleases *expirable.LRU[string, releasedClaims]
	// idTokenClaims holds each access token's ID token claims, a fallback
	// profile when userinfo fails.
	idTokenClaims *expirable.LRU[string, map[string]any]
	// userinfo caches /obot-get-user-info's userinfo answers, which Obot asks
	// for on nearly every request.
	userinfo *expirable.LRU[string, userinfoAnswer]
	// directory answers Obot's group search and lookups.
	directory *groupDirectory
	// userinfoTimeout bounds currentGroups' userinfo request.
	userinfoTimeout time.Duration
	// incompleteAnswerTolerance is how long after userinfo last confirmed a
	// session an incomplete answer still lets it through: two refresh
	// periods, so a session survives a refresh while the attribute source is
	// down.
	incompleteAnswerTolerance time.Duration
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
	// oauth2-proxy sends secrets and tokens to these, and trusts the JWKS keys.
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

	proxy, err := newOAuthProxyWithRetry(cfg, discovery)
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
		tokenGroupsFailed: expirable.NewLRU[string, userinfoFailure](cacheSize, nil, 2*tokenGroupsMaxRetry),
		idTokenClaims:     expirable.NewLRU[string, map[string]any](cacheSize, nil, cacheTTL),
		directory:         newGroupDirectory(cfg.knownGroups, store),
		userinfoTimeout:   userinfoTimeout,

		incompleteAnswerTolerance: min(2*tokenGroupsTTL(cfg), confirmationMaxAge),

		confirmedIdentities: expirable.NewLRU[string, identityConfirmation](cacheSize, nil, confirmationMaxAge),
		unusableAnswers:     expirable.NewLRU[string, unusableAnswer](cacheSize, nil, confirmationMaxAge),
		userinfoReleases:    expirable.NewLRU[string, releasedClaims](cacheSize, nil, confirmationMaxAge),
	}
	if cfg.userinfoCacheTTL > 0 {
		s.userinfo = expirable.NewLRU[string, userinfoAnswer](cacheSize, nil, cfg.userinfoCacheTTL)
	}
	return s, nil
}

// newOAuthProxyWithRetry retries with PostgreSQL sessions: every replica
// creates the session tables at once on first start, and all but one can fail.
func newOAuthProxyWithRetry(cfg *settings, discovery *oidc.Discovery) (*oauth2proxy.OAuthProxy, error) {
	proxy, err := newOAuthProxy(cfg, discovery)
	for attempt := 1; err != nil && cfg.PostgresConnectionDSN != "" && attempt < 3; attempt++ {
		slog.Warn("failed to start oauth2-proxy; retrying", "attempt", attempt, "error", err)
		time.Sleep(time.Duration(attempt) * time.Second)
		proxy, err = newOAuthProxy(cfg, discovery)
	}
	return proxy, err
}

// newOAuthProxy configures oauth2-proxy for PingFederate from the discovery
// document newServer checked. oauth2-proxy's own discovery is off: nothing
// would check the endpoints a second fetch returned.
func newOAuthProxy(cfg *settings, discovery *oidc.Discovery) (*oauth2proxy.OAuthProxy, error) {
	// Go keeps the Authorization header and body across a same-host redirect,
	// even to plain HTTP, so oauth2-proxy's client follows none.
	requests.DefaultHTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	legacyOpts := options.NewLegacyOptions()
	provider := &legacyOpts.LegacyProvider
	provider.ProviderType = "oidc"
	provider.ProviderName = "PingFederate"
	provider.ClientID = cfg.ClientID
	provider.ClientSecret = cfg.ClientSecret
	provider.OIDCIssuerURL = cfg.issuerURL
	// ID tokens are still checked against the issuer URL and the JWKS keys.
	provider.SkipOIDCDiscovery = true
	provider.LoginURL = discovery.AuthorizationEndpoint
	provider.RedeemURL = discovery.TokenEndpoint
	provider.ProfileURL = discovery.UserinfoEndpoint
	provider.OIDCJwksURL = discovery.JwksURI
	// Without discovery, oauth2-proxy would accept RS256 only.
	provider.OIDCEnabledSigningAlgs = discovery.SigningAlgs()
	provider.Scope = cfg.scopes
	provider.OIDCEmailClaim = cfg.EmailClaim
	// The session's User is the subject, oauth2-proxy's default. Its legacy
	// user ID claim option is left alone: anything but "email" also redefines
	// the email claim.
	provider.OIDCGroupsClaim = cfg.GroupsClaim
	// Set explicitly: oauth2-proxy's legacy defaults skip the nonce check.
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
	mux.HandleFunc("/obot-get-auth-groups", s.getAuthGroups)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/obot-") {
			// oauth2-proxy's sign-in page would look like a provider failure to Obot.
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

// getState identifies the user behind a request from its session cookie,
// refreshing tokens when due, and records the user's groups.
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
		// 401 for an invalid session, so Obot clears the cookie.
		state.WriteStateError(w, err)
		return
	}

	var refreshed state.SerializableState
	loaded := false
	if len(ss.SetCookies) > 0 {
		// A refreshing request's state is the pre-refresh session; the refreshed
		// one is in the cookies the refresh set.
		refreshed, loaded = s.refreshedState(req, ss.SetCookies)
	}
	checked := ss
	var (
		subject       string
		idClaims      map[string]any
		previousToken string
	)
	if !loaded {
		subject, idClaims = s.recordSession(r.Context(), &ss)
	}
	if len(ss.SetCookies) > 0 {
		// The refreshed session is the one checked and the one Obot gets: a
		// refresh that returns an ID token rebuilds the email and username. The old
		// token is not sent to userinfo, which could exceed Obot's deadline.
		if loaded {
			subject, idClaims = s.recordSession(r.Context(), &refreshed)
			checked = refreshed
			previousToken = ss.AccessToken
			ss.User = refreshed.User
			ss.Email = refreshed.Email
			ss.PreferredUsername = refreshed.PreferredUsername
			ss.AccessToken = refreshed.AccessToken
			ss.IDToken = refreshed.IDToken
			ss.ExpiresOn = refreshed.ExpiresOn
			ss.GroupInfos = refreshed.GroupInfos
		}
		ss.SetCookies = append(ss.SetCookies, expireSupersededCookies(req, ss.SetCookies)...)
	}
	switch s.checkUserinfoClaims(checked, subject, idClaims, previousToken) {
	case userinfoContradicts:
		slog.Warn("userinfo contradicts the session: it answered for another subject, or for none, or with other identity claims; refusing the session")
		http.Error(w, "the session's identity does not match userinfo", http.StatusUnauthorized)
		return
	case userinfoUnconfirmed:
		slog.Warn("could not confirm the session's identity claims with userinfo; failing the request")
		http.Error(w, "could not confirm the session's identity with userinfo", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ss); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode state: %v", err), http.StatusInternalServerError)
	}
}

// refreshedState loads the session a refresh created from the cookies it set,
// without refreshing it again, which would rotate tokens whose cookies are
// discarded here.
func (s *server) refreshedState(req *http.Request, setCookies []string) (state.SerializableState, bool) {
	header := http.Header{}
	for _, c := range setCookies {
		header.Add("Set-Cookie", c)
	}
	refreshedCookies := (&http.Response{Header: header}).Cookies()
	// Drop the old cookies of each refreshed cookie's family (name, name_0,
	// ...): a leftover unsplit cookie would win over new chunks.
	replaced := map[string]bool{}
	for _, c := range refreshedCookies {
		replaced[cookieFamily(c.Name)] = true
	}

	refreshedReq := req.Clone(req.Context())
	refreshedReq.Header.Del("Cookie")
	for _, c := range req.Cookies() {
		if !replaced[cookieFamily(c.Name)] {
			refreshedReq.AddCookie(c)
		}
	}
	for _, c := range refreshedCookies {
		if c.MaxAge >= 0 && c.Value != "" {
			refreshedReq.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}

	session, err := s.proxy.LoadCookiedSession(refreshedReq)
	if err != nil || session == nil {
		slog.Warn("could not load the refreshed session to record the user's groups", "error", err)
		return state.SerializableState{}, false
	}
	if session.IsExpired() {
		slog.Warn("the refreshed session has already expired; not recording the user's groups")
		return state.SerializableState{}, false
	}
	return state.SerializableState{
		ExpiresOn:         session.ExpiresOn,
		AccessToken:       session.AccessToken,
		IDToken:           session.IDToken,
		PreferredUsername: session.PreferredUsername,
		User:              session.User,
		Email:             session.Email,
		Groups:            session.Groups,
		GroupInfos:        state.GroupInfoList{},
	}, true
}

// expireSupersededCookies deletes the session cookies a refresh did not set
// again: a leftover unsplit cookie or chunk would corrupt the next load.
func expireSupersededCookies(req *http.Request, setCookies []string) []string {
	header := http.Header{}
	for _, c := range setCookies {
		header.Add("Set-Cookie", c)
	}
	set := map[string]bool{}
	// A deletion copies path and domain from a cookie the refresh set.
	templates := map[string]*http.Cookie{}
	for _, c := range (&http.Response{Header: header}).Cookies() {
		set[c.Name] = true
		family := cookieFamily(c.Name)
		if templates[family] == nil && c.MaxAge >= 0 && c.Value != "" {
			templates[family] = c
		}
	}

	var expired []string
	seen := map[string]bool{}
	for _, c := range req.Cookies() {
		template := templates[cookieFamily(c.Name)]
		if template == nil || set[c.Name] || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		deletion := *template
		deletion.Name = c.Name
		deletion.Value = ""
		deletion.MaxAge = -1
		deletion.Expires = time.Unix(1, 0)
		expired = append(expired, deletion.String())
	}
	return expired
}

// cookieFamily strips the _0, _1, ... suffix of a split session cookie.
func cookieFamily(name string) string {
	if i := strings.LastIndexByte(name, '_'); i > 0 && i < len(name)-1 {
		if _, err := strconv.Atoi(name[i+1:]); err == nil {
			return name[:i]
		}
	}
	return name
}

// userinfoCheck is the verdict of checkUserinfoClaims.
type userinfoCheck int

const (
	userinfoConsistent userinfoCheck = iota
	userinfoContradicts
	userinfoUnconfirmed
)

// checkUserinfoClaims checks a session against the provider's userinfo answer
// for its token. oauth2-proxy copies claims the ID token lacks (by default,
// PingFederate's email) from userinfo without comparing subjects, and Obot
// identifies users by email. Comparing the claims too catches two userinfo
// requests answered differently. With no answer, a session fails while its
// token is valid, unless userinfo confirmed the same identity for the token or
// for previousToken, the one a refresh replaced; an expired token is checked
// after the next refresh.
func (s *server) checkUserinfoClaims(ss state.SerializableState, subject string, idClaims map[string]any, previousToken string) userinfoCheck {
	if s.userinfoURL == "" || ss.AccessToken == "" || subject == "" {
		// Without a userinfo endpoint, oauth2-proxy reads no claims from it.
		return userinfoConsistent
	}
	answer, answered := s.tokenGroups.Get(ss.AccessToken)
	if answered && answer.subject != subject {
		return userinfoContradicts
	}

	// A refresh without an ID token keeps the old token's email, so an email
	// userinfo releases is compared even when the ID token has one, ignoring
	// case in case the two come from differently cased attributes.
	if answered && ss.Email != "" && answer.email != "" && !strings.EqualFold(answer.email, ss.Email) {
		slog.Warn("the session's email is not the one userinfo releases now; if the user's email did not change, release the same email attribute in the ID token and in userinfo")
		return userinfoContradicts
	}

	type claim struct{ session, answer string }
	var fromUserinfo []claim
	taken := s.takenFromUserinfo(ss, idClaims)
	if taken.email {
		fromUserinfo = append(fromUserinfo, claim{ss.Email, answer.email})
	}
	if taken.preferredUsername {
		fromUserinfo = append(fromUserinfo, claim{ss.PreferredUsername, answer.preferredUsername})
	}
	if len(fromUserinfo) == 0 {
		return userinfoConsistent
	}
	identity := sessionIdentity{subject: subject, email: ss.Email, preferredUsername: ss.PreferredUsername}
	if !answered {
		if ss.ExpiresOn != nil && ss.ExpiresOn.Before(time.Now()) {
			return userinfoConsistent
		}
		maxAge := confirmationMaxAge
		switch unusable, _ := s.unusableAnswers.Get(ss.AccessToken); unusable {
		case tokenRejected:
			// Neither its own nor an inherited confirmation passes a token
			// userinfo refused.
			return userinfoUnconfirmed
		case answerIncomplete:
			// Such an answer can also mean the user was removed from the
			// directory, so it is tolerated for less long than an outage.
			maxAge = s.incompleteAnswerTolerance
		}
		if previous, _ := s.unusableAnswers.Get(previousToken); previous == answerIncomplete {
			// So is a session whose previous token got one.
			maxAge = min(maxAge, s.incompleteAnswerTolerance)
		}
		if _, ok := s.confirmation(ss.AccessToken, identity, maxAge); ok {
			return userinfoConsistent
		}
		// A refresh that kept a confirmed identity is not failed, so its
		// cookies, which may hold a rotated refresh token, reach the browser.
		// The new token inherits the confirmation with its original time.
		if c, ok := s.confirmation(previousToken, identity, maxAge); ok {
			s.confirmedIdentities.Add(ss.AccessToken, c)
			if maxAge < confirmationMaxAge && !s.unusableAnswers.Contains(ss.AccessToken) {
				// The new token keeps the shorter tolerance.
				s.unusableAnswers.Add(ss.AccessToken, answerIncomplete)
			}
			return userinfoConsistent
		}
		return userinfoUnconfirmed
	}
	for _, c := range fromUserinfo {
		if c.session != c.answer {
			return userinfoContradicts
		}
	}
	s.confirmedIdentities.Add(ss.AccessToken, identityConfirmation{identity: identity, at: answer.observedAt})
	return userinfoConsistent
}

// sessionIdentity is a session's identity claims.
type sessionIdentity struct {
	subject, email, preferredUsername string
}

// identityConfirmation is an identity userinfo confirmed, and when.
type identityConfirmation struct {
	identity sessionIdentity
	at       time.Time
}

// confirmation returns userinfo's confirmation of identity for token, if it
// answered within maxAge.
func (s *server) confirmation(token string, identity sessionIdentity, maxAge time.Duration) (identityConfirmation, bool) {
	if token == "" {
		return identityConfirmation{}, false
	}
	c, ok := s.confirmedIdentities.Get(token)
	if !ok || c.identity != identity || time.Since(c.at) > maxAge {
		return identityConfirmation{}, false
	}
	return c, true
}

// unusableAnswer is why userinfo's answer for a token could not be used.
type unusableAnswer int

const (
	// tokenRejected is userinfo refusing the token (401 or 403).
	tokenRejected unusableAnswer = iota + 1
	// answerIncomplete is an answer without the identity claims userinfo
	// releases (see checkComplete).
	answerIncomplete
)

// sessionClaim returns a claim as oauth2-proxy stores it in a session.
func sessionClaim(claims map[string]any, name string) string {
	value := oidc.ClaimValue(claims, name)
	if value == nil {
		return ""
	}
	var coerced string
	if err := util.CoerceClaim(value, &coerced); err != nil {
		return ""
	}
	return coerced
}

// recordSession fills in a session's groups, records them under the user's
// subject, and returns the subject and the ID token's claims.
func (s *server) recordSession(ctx context.Context, ss *state.SerializableState) (string, map[string]any) {
	claims := map[string]any{}
	claimsReadable := true
	if ss.IDToken != "" {
		// oauth2-proxy verified this token.
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

	groups, observedAt, record := s.sessionGroups(ctx, ss.AccessToken, subject, claims, s.takenFromUserinfo(*ss, claims))
	ss.GroupInfos = groupInfos(groups)
	// A refreshing, expired or unreadable session says nothing current.
	if len(ss.SetCookies) > 0 || (ss.ExpiresOn != nil && ss.ExpiresOn.Before(time.Now())) || !claimsReadable {
		record = false
	}
	if record {
		s.rememberGroups(ctx, subject, groups, observedAt)
	}
	if ss.AccessToken != "" && len(claims) > 0 {
		s.idTokenClaims.Add(ss.AccessToken, claims)
	}
	return subject, claims
}

// sessionGroups returns a session's groups, when they were observed, and
// whether to record them. Groups come from userinfo when there is an endpoint:
// PingFederate does not reissue the ID token on refresh by default. A missing
// claim means no groups; a failure records nothing.
func (s *server) sessionGroups(ctx context.Context, token, subject string, idTokenClaims map[string]any, want releasedClaims) ([]string, time.Time, bool) {
	tokenGroups := oidc.StringsClaim(idTokenClaims, s.cfg.GroupsClaim, s.cfg.GroupsDelimiter)
	if subject == "" {
		return tokenGroups, time.Time{}, false
	}
	if s.userinfoURL == "" {
		issued := oidc.TimeClaim(idTokenClaims, "iat")
		return tokenGroups, issued, !issued.IsZero()
	}
	current, ok, asked := s.currentGroups(ctx, token, subject, want)
	if !ok {
		return tokenGroups, time.Time{}, false
	}
	if (want.email && current.email == "") || (want.preferredUsername && current.preferredUsername == "") {
		// An answer without a claim the session took from userinfo is
		// refused (see checkUserinfoClaims); its groups may be as partial.
		return current.groups, current.observedAt, false
	}
	if current.email == "" && current.preferredUsername == "" {
		// With no identity claim, nothing tells this answer from one with
		// only sub, which PingFederate gives when its attribute source fails.
		return current.groups, current.observedAt, false
	}
	if asked && len(current.groups) == 0 && len(tokenGroups) > 0 {
		// Groups released only in the ID token are not read.
		slog.Warn("userinfo reports no groups although the session's ID token lists some; if PingFederate releases groups only in the ID token, release them in userinfo too", "claim", s.cfg.GroupsClaim)
	}
	return current.groups, current.observedAt, true
}

// currentGroups returns the userinfo answer for a token, whether it is for
// subject, and whether userinfo was asked now. Userinfo is asked once per token;
// an answer without the claims in want is a failure (see userinfoClaims).
func (s *server) currentGroups(ctx context.Context, token, subject string, want releasedClaims) (result userinfoGroups, ok, asked bool) {
	if token == "" {
		return userinfoGroups{}, false, false
	}
	if cached, found := s.tokenGroups.Get(token); found {
		return cached, cached.subject == subject, false
	}
	failure, failedBefore := s.tokenGroupsFailed.Get(token)
	if failedBefore && time.Now().Before(failure.retryAt) {
		return userinfoGroups{}, false, false
	}
	// Not stopped by the caller giving up, which says nothing about userinfo;
	// its own timeout stops it.
	askCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.userinfoTimeout)
	defer cancel()
	claims, answeredAt, err := s.userinfoClaims(askCtx, token, want, subject)
	if err != nil {
		failure.failures++
		delay := userinfoRetryDelay(failure.failures)
		failure.retryAt = time.Now().Add(delay)
		s.tokenGroupsFailed.Add(token, failure)
		slog.Warn("could not read the user's current groups from userinfo; keeping their recorded groups", "error", err, "retryIn", delay)
		return userinfoGroups{}, false, true
	}
	s.tokenGroupsFailed.Remove(token)
	result = userinfoGroups{
		subject:           oidc.StringClaim(claims, "sub"),
		email:             sessionClaim(claims, s.cfg.EmailClaim),
		preferredUsername: sessionClaim(claims, "preferred_username"),
		observedAt:        answeredAt,
		groups:            oidc.StringsClaim(claims, s.cfg.GroupsClaim, s.cfg.GroupsDelimiter),
	}
	s.tokenGroups.Add(token, result)
	if result.subject != subject {
		// OpenID Connect requires the subjects to match.
		slog.Warn("userinfo answered for a different subject than the session's; ignoring its groups")
		return userinfoGroups{}, false, true
	}
	return result, true, true
}

// getUserInfo returns the profile for a bearer access token. Obot reads "id",
// which it looks the user's groups up by, and "name".
func (s *server) getUserInfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		http.Error(w, "missing access token", http.StatusBadRequest)
		return
	}

	var want releasedClaims
	if earlier, ok := s.tokenGroups.Get(token); ok {
		want = releasedClaims{email: earlier.email != "", preferredUsername: earlier.preferredUsername != ""}
	}
	idClaims, idClaimsKnown := s.idTokenClaims.Get(token)
	claims, answeredAt, err := s.userinfoClaims(r.Context(), token, want, oidc.StringClaim(idClaims, "sub"))
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

	// The id is used for group lookups, so userinfo must answer for the
	// session's subject. A replica that has not seen the session cannot check.
	subject := oidc.StringClaim(claims, "sub")
	if fromUserinfo {
		if subject == "" {
			slog.Warn("userinfo answered without a subject; not reporting a profile")
			http.Error(w, "the userinfo response has no subject", http.StatusBadGateway)
			return
		}
		if idClaimsKnown && oidc.StringClaim(idClaims, "sub") != subject {
			slog.Warn("userinfo answered for a different subject than the session's ID token; not reporting a profile")
			http.Error(w, "the userinfo response is for a different subject than the session", http.StatusBadGateway)
			return
		}
	}

	// PingFederate may release name attributes only in the ID token.
	profileClaims := maps.Clone(claims)
	if idClaimsKnown && subject != "" && oidc.StringClaim(idClaims, "sub") == subject {
		for _, name := range []string{s.cfg.NameClaim, "name", "given_name", "family_name", "preferred_username"} {
			if strings.TrimSpace(oidc.StringClaim(profileClaims, name)) == "" {
				if value := oidc.StringClaim(idClaims, name); value != "" {
					profileClaims[name] = value
				}
			}
		}
	}
	profile := s.profile(profileClaims)
	// Only a live answer is current; a missing claim means no groups. Every
	// session has an email, so an answer without one may be incomplete in a
	// way this replica cannot tell (see checkComplete); recording happens
	// only when the session's state is read then.
	if fromUserinfo && sessionClaim(claims, s.cfg.EmailClaim) != "" {
		groups := oidc.StringsClaim(claims, s.cfg.GroupsClaim, s.cfg.GroupsDelimiter)
		s.rememberGroups(r.Context(), subject, groups, answeredAt)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(profile); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode user info: %v", err), http.StatusInternalServerError)
	}
}

// userinfoClaims fetches userinfo for a token, through the cache if any, and
// returns when it answered. An answer without the identity claims in want, or
// that userinfo releases, is an error (see checkComplete), unless it is for
// another subject than subject, which the caller then refuses.
func (s *server) userinfoClaims(ctx context.Context, token string, want releasedClaims, subject string) (map[string]any, time.Time, error) {
	if s.userinfoURL == "" {
		return nil, time.Time{}, fmt.Errorf("no userinfo endpoint is configured")
	}
	if s.userinfo != nil {
		if answer, ok := s.userinfo.Get(token); ok {
			if err := s.checkComplete(answer.claims, want, subject); err != nil {
				s.unusableAnswers.Add(token, answerIncomplete)
				return nil, time.Time{}, err
			}
			return answer.claims, answer.at, nil
		}
	}
	claims, err := oidc.Userinfo(ctx, s.httpClient, s.userinfoURL, token)
	if err != nil {
		if errors.Is(err, oidc.ErrTokenRejected) {
			// A revoked token must not pass on an earlier answer or
			// confirmation, its own or the one a refresh replaced.
			s.unusableAnswers.Add(token, tokenRejected)
			s.confirmedIdentities.Remove(token)
			s.tokenGroups.Remove(token)
		}
		return nil, time.Time{}, err
	}
	if err := s.checkComplete(claims, want, subject); err != nil {
		s.unusableAnswers.Add(token, answerIncomplete)
		return nil, time.Time{}, err
	}
	s.unusableAnswers.Remove(token)
	at := time.Now()
	if s.userinfo != nil {
		s.userinfo.Add(token, userinfoAnswer{claims: claims, at: at})
	}
	return claims, at, nil
}

// releasedClaims names the identity claims a userinfo answer carries, or
// must carry.
type releasedClaims struct {
	email, preferredUsername bool
}

// takenFromUserinfo is the identity claims a session took from userinfo,
// which oauth2-proxy does for the claims its ID token lacks.
func (s *server) takenFromUserinfo(ss state.SerializableState, idClaims map[string]any) releasedClaims {
	return releasedClaims{
		email:             ss.Email != "" && oidc.ClaimValue(idClaims, s.cfg.EmailClaim) == nil,
		preferredUsername: ss.PreferredUsername != "" && oidc.ClaimValue(idClaims, "preferred_username") == nil,
	}
}

// errIncompleteUserinfo is a userinfo answer without any of the identity
// claims it should carry. PingFederate answers so, with only sub, when the
// OIDC policy's attribute source fails; read as an answer, it would empty the
// user's groups and refuse their session.
var errIncompleteUserinfo = errors.New("userinfo answered without the identity claims it releases; treating the answer as a failure")

// checkComplete fails an answer that carries none of the identity claims
// expected of it: those in want, and those userinfo released in its last
// complete answer for the subject. An answer missing only some of them is
// read as it is, so a claim userinfo stops releasing takes effect at once.
// It remembers what a complete answer released. An answer for another
// subject than sessionSubject, when set, passes, for the caller to refuse.
func (s *server) checkComplete(claims map[string]any, want releasedClaims, sessionSubject string) error {
	got := releasedClaims{
		email:             sessionClaim(claims, s.cfg.EmailClaim) != "",
		preferredUsername: sessionClaim(claims, "preferred_username") != "",
	}
	subject := oidc.StringClaim(claims, "sub")
	if sessionSubject != "" && subject != sessionSubject {
		// An answer for someone else is not a failure: the caller refuses it.
		return nil
	}
	expected := want
	if subject != "" {
		if before, ok := s.userinfoReleases.Get(subject); ok {
			expected.email = expected.email || before.email
			expected.preferredUsername = expected.preferredUsername || before.preferredUsername
		}
	}
	if (expected.email || expected.preferredUsername) &&
		!(expected.email && got.email) && !(expected.preferredUsername && got.preferredUsername) {
		return errIncompleteUserinfo
	}
	if subject != "" && (got.email || got.preferredUsername) {
		s.userinfoReleases.Add(subject, got)
	}
	return nil
}

// userinfoAnswer is a userinfo response and when PingFederate gave it.
type userinfoAnswer struct {
	claims map[string]any
	at     time.Time
}

// profile shapes claims into /obot-get-user-info's answer, keeping the raw
// claims.
func (s *server) profile(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims)+3)
	maps.Copy(out, claims)

	// Groups are recorded under the subject only.
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

// listUserAuthGroups returns the groups recorded for a user ID (the request
// body). An unknown ID is an error, not "no groups", which Obot would store,
// dropping the user's memberships.
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

// rememberGroups records a user's groups under their subject, which no user
// can choose. A failure is logged, not returned.
func (s *server) rememberGroups(ctx context.Context, subject string, groups []string, observedAt time.Time) {
	if subject == "" {
		return
	}
	// A future observation would outrank every later one.
	if now := time.Now(); observedAt.After(now) {
		observedAt = now
	}
	if err := s.store.recordUserGroups(ctx, subject, filterGroups(groups), observedAt); err != nil {
		slog.Warn("failed to record the user's groups", "error", err)
	}
}

// groupInfos converts group names into Obot's prefixed group IDs.
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
