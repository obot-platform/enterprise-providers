// Package client provides realm discovery and read-only Keycloak directory access.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxResponseBytes = 8 << 20

// Endpoints are derived from the configured, validated realm issuer.
type Endpoints struct {
	Issuer      string `json:"issuer"`
	TokenURL    string `json:"token_endpoint"`
	UserInfoURL string `json:"userinfo_endpoint"`
	AdminURL    string `json:"-"`
}

// CanonicalIssuer accepts syntactic whitespace/trailing slash variations only.
func CanonicalIssuer(raw string) (string, error) {
	u, issuer, err := parseBaseURL(raw)
	if err != nil {
		return "", fmt.Errorf("issuer %w", err)
	}
	path := u.EscapedPath()
	idx := strings.LastIndex(path, "/realms/")
	if idx < 0 || path[idx+len("/realms/"):] == "" || strings.Contains(path[idx+len("/realms/"):], "/") {
		return "", errors.New("issuer must end with /realms/{realm}")
	}
	return issuer, nil
}

// WithAdminBaseURL sends Admin REST reads to a separate Keycloak base URL, such as an
// internal admin hostname, keeping the configured realm. The base URL includes any
// deployment prefix such as /auth, but not /admin or /realms.
func WithAdminBaseURL(endpoints Endpoints, raw string) (Endpoints, error) {
	u, base, err := parseBaseURL(raw)
	if err != nil {
		return endpoints, fmt.Errorf("admin URL %w", err)
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		if decoded, _ := url.PathUnescape(segment); decoded == "admin" || decoded == "realms" {
			return endpoints, errors.New("admin URL must be the Keycloak base URL, without /admin or /realms")
		}
	}
	idx := strings.LastIndex(endpoints.Issuer, "/realms/")
	if idx < 0 {
		return endpoints, errors.New("issuer must end with /realms/{realm}")
	}
	endpoints.AdminURL = base + "/admin" + endpoints.Issuer[idx:]
	return endpoints, nil
}

// parseBaseURL validates an operator-supplied Keycloak URL and trims surrounding
// whitespace and a trailing slash.
func parseBaseURL(raw string) (*url.URL, string, error) {
	value := strings.TrimSuffix(strings.TrimSpace(raw), "/")
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, "", errors.New("must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	if u.Scheme == "http" && !strings.EqualFold(u.Hostname(), "localhost") && !net.ParseIP(u.Hostname()).IsLoopback() {
		return nil, "", errors.New("must use HTTPS except on a loopback host")
	}
	// Reject encoded slashes and dot segments that could change the authority's path.
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "." || decoded == ".." || strings.Contains(decoded, "/") || strings.Contains(decoded, "\\") {
			return nil, "", errors.New("contains an unsafe path segment")
		}
	}
	return u, value, nil
}

// Discover validates the exact issuer and preserves deployment prefixes such as /auth.
func Discover(ctx context.Context, issuer string, httpClient *http.Client) (Endpoints, error) {
	var endpoints Endpoints
	canonical, err := CanonicalIssuer(issuer)
	if err != nil {
		return endpoints, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canonical+"/.well-known/openid-configuration", nil)
	if err != nil {
		return endpoints, err
	}
	response, err := transport(httpClient).Do(req)
	if err != nil {
		return endpoints, fmt.Errorf("discover realm: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return endpoints, fmt.Errorf("realm discovery returned HTTP %d", response.StatusCode)
	}
	if err := Decode(response.Body, &endpoints); err != nil {
		return endpoints, fmt.Errorf("decode realm discovery: %w", err)
	}
	if endpoints.Issuer != canonical {
		return Endpoints{}, errors.New("discovery issuer does not match configured realm issuer")
	}
	origin, _ := url.Parse(canonical)
	for _, endpoint := range []string{endpoints.TokenURL, endpoints.UserInfoURL} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != origin.Scheme || u.Host != origin.Host || u.User != nil || u.Fragment != "" {
			return Endpoints{}, errors.New("discovered token and userinfo endpoints must use the issuer origin")
		}
	}
	path := origin.EscapedPath()
	idx := strings.LastIndex(path, "/realms/")
	endpoints.AdminURL = origin.Scheme + "://" + origin.Host + path[:idx] + "/admin" + path[idx:]
	return endpoints, nil
}

func transport(c *http.Client) *http.Client {
	if c == nil {
		adminTransport := http.DefaultTransport.(*http.Transport).Clone()
		adminTransport.MaxIdleConnsPerHost = 32
		adminTransport.IdleConnTimeout = 90 * time.Second
		c = &http.Client{Timeout: 15 * time.Second, Transport: adminTransport}
	}
	cloned := *c
	// Discovery and token endpoints have known URLs; never replay client secrets on redirects.
	cloned.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &cloned
}

// Decode limits both response size and trailing JSON; partial payloads are errors.
func Decode(reader io.Reader, out any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("keycloak response exceeds size limit")
	}
	return json.Unmarshal(data, out)
}

// TokenError means Keycloak refused the directory service client's token request, such as for a wrong
// secret, or a client without service accounts enabled.
type TokenError struct{ Status int }

func (e *TokenError) Error() string {
	return fmt.Sprintf("directory token request returned HTTP %d", e.Status)
}

// Client caches client-credentials tokens and performs read-only Admin REST requests.
type Client struct {
	endpoints              Endpoints
	clientID, clientSecret string
	httpClient             *http.Client
	mu                     sync.Mutex
	token                  string
	refreshAt              time.Time
	tokenFlight            chan struct{}
	tokenErr               error
	retryAt                time.Time
}

func New(endpoints Endpoints, clientID, clientSecret string, httpClient *http.Client) *Client {
	return &Client{endpoints: endpoints, clientID: clientID, clientSecret: clientSecret, httpClient: transport(httpClient)}
}

// Issuer returns the canonical realm authority discovered for this client.
func (c *Client) Issuer() string { return c.endpoints.Issuer }

// AdminURL returns the realm's Admin REST base URL that directory reads use.
func (c *Client) AdminURL() string { return c.endpoints.AdminURL }

func (c *Client) accessToken(ctx context.Context) (string, error) {
	for {
		c.mu.Lock()
		if c.token != "" && time.Now().Before(c.refreshAt) {
			token := c.token
			c.mu.Unlock()
			return token, nil
		}
		if time.Now().Before(c.retryAt) {
			err := c.tokenErr
			c.mu.Unlock()
			return "", err
		}
		if flight := c.tokenFlight; flight != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-flight:
				continue
			}
		}
		flight := make(chan struct{})
		c.tokenFlight = flight
		c.mu.Unlock()
		go c.refreshToken(context.WithoutCancel(ctx), flight)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-flight:
		}
	}
}

func (c *Client) refreshToken(ctx context.Context, flight chan struct{}) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	token, lifetime, err := c.requestToken(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.token = token
		c.refreshAt = time.Now().Add(lifetime - min(30*time.Second, lifetime/10))
	} else {
		c.tokenErr = err
		c.retryAt = time.Now().Add(2 * time.Second)
	}
	c.tokenFlight = nil
	close(flight)
}

func (c *Client) requestToken(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.clientID}, "client_secret": {c.clientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoints.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("request directory token: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", 0, &TokenError{Status: response.StatusCode}
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := Decode(response.Body, &token); err != nil {
		return "", 0, fmt.Errorf("decode directory token: %w", err)
	}
	if token.AccessToken == "" || token.ExpiresIn <= 0 || !strings.EqualFold(token.TokenType, "Bearer") {
		return "", 0, errors.New("directory token response is missing a usable bearer token or expiry")
	}
	lifetime := time.Duration(min(token.ExpiresIn, int64(24*60*60))) * time.Second
	return token.AccessToken, lifetime, nil
}

// Get retries an idempotent read once after 401, never after a permission error.
func (c *Client) Get(ctx context.Context, path string, query url.Values) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.accessToken(ctx)
		if err != nil {
			return nil, err
		}
		endpoint := c.endpoints.AdminURL + path
		if len(query) > 0 {
			endpoint += "?" + query.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		response, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusUnauthorized || attempt == 1 {
			return response, nil
		}
		_ = response.Body.Close()
		c.mu.Lock()
		if c.token == token {
			c.token = ""
			c.refreshAt = time.Time{}
		}
		c.mu.Unlock()
	}
	return nil, errors.New("directory authentication retry exhausted")
}
