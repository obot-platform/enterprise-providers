package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// AfterCursorHeader is the response header that carries OneLogin's cursor for the next page of a v2 list. It is
	// absent on the last page.
	AfterCursorHeader = "After-Cursor"

	tokenPath = "/auth/oauth2/v2/token"

	// requestTimeout bounds each call to OneLogin, body included, so that a stalled OneLogin cannot hold a directory
	// route or the role-cache refresh forever.
	requestTimeout = 30 * time.Second

	// responseHeaderTimeout bounds the wait for OneLogin to start answering, which is where a stalled OneLogin usually
	// hangs.
	responseHeaderTimeout = 15 * time.Second

	// tokenFetchTimeout bounds a shared token request. It runs detached from the callers' contexts, so that one caller
	// giving up does not fail the others, and so it needs its own limit.
	tokenFetchTimeout = 30 * time.Second

	// maxIdleConnsPerHost lets concurrent directory lookups reuse connections to OneLogin, rather than the default of
	// 2, which would close most of them after a burst.
	maxIdleConnsPerHost = 32

	// maxResponseBodyBytes caps how much of a successful response is decoded, as a defence against a runaway
	// response rather than a limit that real responses come near.
	maxResponseBodyBytes = 16 << 20

	// maxDrainBytes caps how much of an unread response is drained before closing it. A body that small is cheaper
	// to read than a new connection; a larger one is cheaper to drop.
	maxDrainBytes = 4 << 10

	// tokenExpirySkew is how long before its expiry a cached access token is replaced. OneLogin's tokens last 10 hours.
	tokenExpirySkew = 5 * time.Minute

	// defaultTokenLifetime is how long a token is cached when OneLogin's response does not say.
	defaultTokenLifetime = 10 * time.Minute

	// defaultRateLimitWait is how long the client stops calling OneLogin after a 429 that carries no Retry-After.
	// OneLogin's v2 API exposes no rate-limit headers, so there is nothing better to go on.
	defaultRateLimitWait = 30 * time.Second

	// maxRateLimitWait caps the wait a Retry-After can impose, so that a bogus value cannot stop directory lookups for
	// hours. Calling again too early costs only another 429.
	maxRateLimitWait = 15 * time.Minute

	// MaxErrorBodyBytes caps how much of an error response is kept for an error message.
	MaxErrorBodyBytes = 2048
)

// Client calls the OneLogin admin API with the credentials of an API client. It caches the access token, and after
// a 429 it fails every call fast, without calling OneLogin, until the wait OneLogin asked for has passed.
//
// Only v2 endpoints should be called through it: v2 calls don't use up the account's v1 rate limit, which other
// integrations share.
type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	now          func() time.Time

	tokenMu     sync.Mutex
	accessToken string
	tokenExpiry time.Time

	// tokenFetches shares one token request among the callers that need a token at the same time, and gives every
	// one of them its result, error included.
	tokenFetches singleflight.Group

	rateLimitMu      sync.Mutex
	rateLimitedUntil time.Time
}

// RateLimitedError is returned when OneLogin answers 429, and for every call made before the wait it asked for has
// passed.
type RateLimitedError struct {
	// RetryAfter is how long until the client calls OneLogin again. On the 429 itself, it is OneLogin's Retry-After,
	// or 30 seconds when OneLogin sent none.
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("OneLogin API rate limit reached; OneLogin directory lookups resume in %s", e.RetryAfter.Round(time.Second))
}

// StatusError is returned for a OneLogin API response with an unexpected status.
type StatusError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("OneLogin API %s %s returned status %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

// IsNotFound reports whether err is a StatusError for a 404.
func IsNotFound(err error) bool {
	return HasStatus(err, http.StatusNotFound)
}

// HasStatus reports whether err is a StatusError with the given status code.
func HasStatus(err error, statusCode int) bool {
	var statusErr *StatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == statusCode
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient makes the client send its requests through httpClient, rather than through a new one from
// NewHTTPClient.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// New returns a Client for the OneLogin admin API at baseURL, for example "https://example.onelogin.com".
func New(baseURL, clientID, clientSecret string, opts ...Option) *Client {
	c := &Client{
		baseURL:      strings.TrimSuffix(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		now:          time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.httpClient == nil {
		c.httpClient = NewHTTPClient()
	}

	return c
}

// NewHTTPClient returns an HTTP client for calls to OneLogin, with timeouts so that a stalled OneLogin fails the call
// rather than hanging it.
func NewHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = responseHeaderTimeout
	transport.MaxIdleConnsPerHost = maxIdleConnsPerHost

	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}
}

// RateLimitErr returns a RateLimitedError while the client is waiting out a 429, and nil otherwise.
func (c *Client) RateLimitErr() error {
	c.rateLimitMu.Lock()
	defer c.rateLimitMu.Unlock()

	if wait := c.rateLimitedUntil.Sub(c.now()); wait > 0 {
		return &RateLimitedError{RetryAfter: wait}
	}

	return nil
}

// doRequest performs an authenticated request to the OneLogin API.
//
// A 401 clears the cached access token and retries once with a new one. A 429 comes back as a RateLimitedError
// rather than a response, and starts the wait during which every call fails fast. It never sleeps: Obot gives a
// group refresh only 10 seconds.
func (c *Client) doRequest(ctx context.Context, method, path string, query url.Values) (*http.Response, error) {
	if err := c.RateLimitErr(); err != nil {
		return nil, err
	}

	reqURL := c.baseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	resp, token, err := c.do(ctx, method, reqURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		discard(resp)
		c.clearAccessToken(token)

		if resp, _, err = c.do(ctx, method, reqURL); err != nil {
			return nil, err
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		discard(resp)
		return nil, c.startRateLimitWait(resp.Header.Get("Retry-After"))
	}

	return resp, nil
}

// GetJSON calls GET path and decodes a 200 response's JSON body into out. It returns the response headers, which
// carry the cursors of a list. Any other status is a StatusError.
func (c *Client) GetJSON(ctx context.Context, path string, query url.Values, out any) (http.Header, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, path, query)
	if err != nil {
		return nil, err
	}
	defer discard(resp)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
		return nil, &StatusError{
			Method:     http.MethodGet,
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}

	body := &io.LimitedReader{R: resp.Body, N: maxResponseBodyBytes}
	if err := json.NewDecoder(body).Decode(out); err != nil {
		if body.N <= 0 {
			return nil, fmt.Errorf("OneLogin API response from %s is larger than %d bytes", path, maxResponseBodyBytes)
		}
		return nil, fmt.Errorf("failed to decode OneLogin API response from %s: %w", path, err)
	}

	return resp.Header, nil
}

// ListAll fetches every item of a v2 list endpoint, up to maxItems, following the After-Cursor header. A positive
// pageTimeout bounds each page request separately, so that a long listing is not cut off as a whole while a stalled
// page still fails.
//
// The first request carries query. Every later one carries only the cursor: OneLogin answers 400 when a cursor comes
// with limit or page, and the cursor already encodes them, along with any name filter.
func ListAll[T any](ctx context.Context, c *Client, path string, query url.Values, maxItems int, pageTimeout time.Duration) ([]T, error) {
	var (
		all  []T
		seen = map[string]struct{}{}
	)

	for {
		var page []T
		header, err := getPage(ctx, c, path, query, &page, pageTimeout)
		if err != nil {
			return nil, err
		}

		all = append(all, page...)
		cursor := header.Get(AfterCursorHeader)

		if len(all) >= maxItems {
			if len(all) > maxItems || cursor != "" {
				slog.Warn("Reached the maximum number of OneLogin items that can be listed; some were not loaded", "path", path, "limit", maxItems)
			}
			return all[:maxItems], nil
		}

		if cursor == "" || len(page) == 0 {
			return all, nil
		}
		if _, ok := seen[cursor]; ok {
			return nil, fmt.Errorf("OneLogin API %s returned a cursor it had already returned", path)
		}
		seen[cursor] = struct{}{}

		query = url.Values{"cursor": []string{cursor}}
	}
}

// getPage calls GetJSON, with a deadline of pageTimeout when it is positive.
func getPage(ctx context.Context, c *Client, path string, query url.Values, out any, pageTimeout time.Duration) (http.Header, error) {
	if pageTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, pageTimeout)
		defer cancel()
	}
	return c.GetJSON(ctx, path, query, out)
}

// do sends one request with the current access token, and returns the response and the token it used.
func (c *Client) do(ctx context.Context, method, reqURL string) (*http.Response, string, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to execute request: %w", err)
	}

	return resp, token, nil
}

// token returns the cached access token, or requests a new one when there is none or it is about to expire.
//
// Concurrent callers share one token request. It runs on a context of its own, so that the first caller's
// cancellation does not fail the rest, and each caller waits only as long as its own context allows.
func (c *Client) token(ctx context.Context) (string, error) {
	if token, ok := c.cachedToken(); ok {
		return token, nil
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	ch := c.tokenFetches.DoChan("token", func() (any, error) {
		// A request that finished after the check above has already cached a token.
		if token, ok := c.cachedToken(); ok {
			return token, nil
		}
		// A 429 since the caller's own check means another token request would only get another 429.
		if err := c.RateLimitErr(); err != nil {
			return "", err
		}

		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tokenFetchTimeout)
		defer cancel()

		return c.fetchToken(fetchCtx)
	})

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-ch:
		if result.Err != nil {
			return "", result.Err
		}
		return result.Val.(string), nil
	}
}

// cachedToken returns the cached access token, unless there is none or it is about to expire.
func (c *Client) cachedToken() (string, bool) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.accessToken != "" && c.now().Before(c.tokenExpiry) {
		return c.accessToken, true
	}

	return "", false
}

// fetchToken requests a new access token and caches it.
func (c *Client) fetchToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+tokenPath, strings.NewReader(`{"grant_type":"client_credentials"}`))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.SetBasicAuth(c.clientID, c.clientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute token request: %w", err)
	}
	defer discard(resp)

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", c.startRateLimitWait(resp.Header.Get("Retry-After"))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
		return "", fmt.Errorf("OneLogin token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("token response has no access_token")
	}

	lifetime := time.Duration(tokenResp.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = defaultTokenLifetime
	}
	if lifetime > 2*tokenExpirySkew {
		lifetime -= tokenExpirySkew
	}

	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = c.now().Add(lifetime)

	return c.accessToken, nil
}

// clearAccessToken drops the cached access token, unless it has already been replaced by a token other than the
// one OneLogin rejected.
func (c *Client) clearAccessToken(rejected string) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.accessToken == rejected {
		c.accessToken = ""
		c.tokenExpiry = time.Time{}
	}
}

// startRateLimitWait records a 429 and returns the RateLimitedError for it. retryAfter is the response's
// Retry-After header, which may be empty.
func (c *Client) startRateLimitWait(retryAfter string) error {
	c.rateLimitMu.Lock()
	defer c.rateLimitMu.Unlock()

	now := c.now()
	wait := min(parseRetryAfter(retryAfter, now), maxRateLimitWait)
	if wait <= 0 {
		wait = defaultRateLimitWait
	}

	if until := now.Add(wait); until.After(c.rateLimitedUntil) {
		c.rateLimitedUntil = until
	}

	return &RateLimitedError{RetryAfter: wait}
}

// parseRetryAfter returns the wait a Retry-After header asks for, given in seconds or as an HTTP date. It returns
// zero for an empty or malformed header.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		// Clamp before converting, so that a huge value cannot overflow the duration.
		return time.Duration(min(max(seconds, 0), int64(maxRateLimitWait/time.Second))) * time.Second
	}

	if at, err := http.ParseTime(value); err == nil {
		return at.Sub(now)
	}

	return 0
}

// discard drains and closes a response body, so the connection can be reused. Only a small remainder is drained;
// a connection with more left unread is dropped instead.
func discard(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
	_ = resp.Body.Close()
}
