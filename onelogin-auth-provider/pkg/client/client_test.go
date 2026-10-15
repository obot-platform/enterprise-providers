package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/internal/onelogintest"
)

// testClock is a clock a test moves by hand.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{
		now: time.Date(2026, 10, 14, 19, 30, 0, 0, time.UTC),
	}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newTestClient returns a Client for baseURL with the fake's credentials and a clock the test controls.
func newTestClient(baseURL string) (*Client, *testClock) {
	clock := newTestClock()
	c := New(baseURL, onelogintest.ClientID, onelogintest.ClientSecret)
	c.now = clock.Now
	return c, clock
}

// testRoles returns n roles with ascending IDs, named eng-<i> and ops-<i> in turn.
func testRoles(n int) []onelogintest.Role {
	roles := make([]onelogintest.Role, 0, n)
	for i := range n {
		prefix := "eng-"
		if i%2 == 1 {
			prefix = "ops-"
		}
		roles = append(roles, onelogintest.Role{
			ID:   int64(1000 + i),
			Name: prefix + strconv.Itoa(i),
		})
	}
	return roles
}

func TestTokenCaching(t *testing.T) {
	tests := []struct {
		name              string
		advance           time.Duration
		wantTokenRequests int
	}{
		{
			name:              "reused within its lifetime",
			advance:           time.Hour,
			wantTokenRequests: 1,
		},
		{
			name:              "reused until the skew before expiry",
			advance:           onelogintest.TokenLifetimeSeconds*time.Second - tokenExpirySkew - time.Second,
			wantTokenRequests: 1,
		},
		{
			name:              "replaced within the skew before expiry",
			advance:           onelogintest.TokenLifetimeSeconds*time.Second - tokenExpirySkew,
			wantTokenRequests: 2,
		},
		{
			name:              "replaced after expiry",
			advance:           onelogintest.TokenLifetimeSeconds*time.Second + time.Second,
			wantTokenRequests: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := onelogintest.New(t, testRoles(1), nil)
			c, clock := newTestClient(fake.URL)

			var roles []struct{}
			if _, err := c.GetJSON(t.Context(), "/api/2/roles", nil, &roles); err != nil {
				t.Fatalf("first GetJSON() error = %v", err)
			}
			if _, err := c.GetJSON(t.Context(), "/api/2/roles", nil, &roles); err != nil {
				t.Fatalf("second GetJSON() error = %v", err)
			}

			clock.Advance(tt.advance)
			if _, err := c.GetJSON(t.Context(), "/api/2/roles", nil, &roles); err != nil {
				t.Fatalf("GetJSON() after advancing error = %v", err)
			}

			if got := fake.TokenRequests(); got != tt.wantTokenRequests {
				t.Errorf("token requests = %d, want %d", got, tt.wantTokenRequests)
			}
		})
	}
}

func TestTokenRequestFailure(t *testing.T) {
	fake := onelogintest.New(t, nil, nil)
	c := New(fake.URL, onelogintest.ClientID, "wrong-secret")

	_, err := c.doRequest(t.Context(), http.MethodGet, "/api/2/roles", nil)
	if err == nil || !strings.Contains(err.Error(), "token endpoint returned status 401") {
		t.Fatalf("doRequest() error = %v, want a token endpoint 401", err)
	}
	if got := fake.RequestCount("/api/2/roles"); got != 0 {
		t.Errorf("API calls = %d, want 0", got)
	}
}

func TestUnauthorizedRetry(t *testing.T) {
	tests := []struct {
		name              string
		rejectTokens      []string
		wantStatus        int
		wantTokenRequests int
		wantAPICalls      int
	}{
		{
			name:              "a rejected token is replaced and the call retried",
			rejectTokens:      []string{"token-1"},
			wantStatus:        http.StatusOK,
			wantTokenRequests: 2,
			wantAPICalls:      2,
		},
		{
			name:              "only one retry",
			rejectTokens:      []string{"token-1", "token-2"},
			wantStatus:        http.StatusUnauthorized,
			wantTokenRequests: 2,
			wantAPICalls:      2,
		},
		{
			name:              "an accepted token is not replaced",
			rejectTokens:      nil,
			wantStatus:        http.StatusOK,
			wantTokenRequests: 1,
			wantAPICalls:      1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := onelogintest.New(t, testRoles(1), nil)
			for _, token := range tt.rejectTokens {
				fake.RejectToken(token)
			}
			c, _ := newTestClient(fake.URL)

			resp, err := c.doRequest(t.Context(), http.MethodGet, "/api/2/roles", nil)
			if err != nil {
				t.Fatalf("doRequest() error = %v", err)
			}
			_ = resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if got := fake.TokenRequests(); got != tt.wantTokenRequests {
				t.Errorf("token requests = %d, want %d", got, tt.wantTokenRequests)
			}
			if got := fake.RequestCount("/api/2/roles"); got != tt.wantAPICalls {
				t.Errorf("API calls = %d, want %d", got, tt.wantAPICalls)
			}
		})
	}
}

func TestRateLimited(t *testing.T) {
	tests := []struct {
		name           string
		retryAfter     string
		wantRetryAfter time.Duration
	}{
		{
			name:           "without Retry-After",
			retryAfter:     "",
			wantRetryAfter: defaultRateLimitWait,
		},
		{
			name:           "Retry-After in seconds",
			retryAfter:     "120",
			wantRetryAfter: 2 * time.Minute,
		},
		{
			name:           "Retry-After as an HTTP date",
			retryAfter:     "Wed, 14 Oct 2026 19:35:00 GMT",
			wantRetryAfter: 5 * time.Minute,
		},
		{
			name:           "Retry-After beyond the cap",
			retryAfter:     "86400",
			wantRetryAfter: maxRateLimitWait,
		},
		{
			name:           "malformed Retry-After",
			retryAfter:     "soon",
			wantRetryAfter: defaultRateLimitWait,
		},
		{
			name:           "Retry-After in the past",
			retryAfter:     "Wed, 14 Oct 2026 19:00:00 GMT",
			wantRetryAfter: defaultRateLimitWait,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := onelogintest.New(t, testRoles(1), nil)
			fake.RateLimit(tt.retryAfter)
			c, clock := newTestClient(fake.URL)

			_, err := c.doRequest(t.Context(), http.MethodGet, "/api/2/roles", nil)
			var rateLimitErr *RateLimitedError
			if !errors.As(err, &rateLimitErr) {
				t.Fatalf("doRequest() error = %v, want a RateLimitedError", err)
			}
			if rateLimitErr.RetryAfter != tt.wantRetryAfter {
				t.Errorf("RetryAfter = %s, want %s", rateLimitErr.RetryAfter, tt.wantRetryAfter)
			}

			// OneLogin stops rate limiting at once, but the client waits out the whole window without calling it.
			fake.StopRateLimiting()
			clock.Advance(tt.wantRetryAfter - time.Second)

			if err := c.RateLimitErr(); !errors.As(err, &rateLimitErr) || rateLimitErr.RetryAfter != time.Second {
				t.Errorf("RateLimitErr() = %v, want a RateLimitedError with a second left", err)
			}
			if _, err := c.doRequest(t.Context(), http.MethodGet, "/api/2/roles", nil); !errors.As(err, &rateLimitErr) {
				t.Fatalf("doRequest() in the window error = %v, want a RateLimitedError", err)
			}
			if got := fake.RequestCount("/api/2/roles"); got != 1 {
				t.Errorf("API calls in the window = %d, want 1", got)
			}

			clock.Advance(time.Second)

			if err := c.RateLimitErr(); err != nil {
				t.Errorf("RateLimitErr() after the window = %v, want nil", err)
			}
			resp, err := c.doRequest(t.Context(), http.MethodGet, "/api/2/roles", nil)
			if err != nil {
				t.Fatalf("doRequest() after the window error = %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status after the window = %d, want %d", resp.StatusCode, http.StatusOK)
			}
		})
	}
}

func TestRateLimitedTokenRequest(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c, _ := newTestClient(srv.URL)

	var rateLimitErr *RateLimitedError
	if _, err := c.doRequest(t.Context(), http.MethodGet, "/api/2/roles", nil); !errors.As(err, &rateLimitErr) || rateLimitErr.RetryAfter != time.Minute {
		t.Fatalf("doRequest() error = %v, want a RateLimitedError of a minute", err)
	}
	if _, err := c.doRequest(t.Context(), http.MethodGet, "/api/2/roles", nil); !errors.As(err, &rateLimitErr) {
		t.Fatalf("second doRequest() error = %v, want a RateLimitedError", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestGetJSONStatusError(t *testing.T) {
	fake := onelogintest.New(t, nil, nil)
	c, _ := newTestClient(fake.URL)

	var role struct{}
	_, err := c.GetJSON(t.Context(), "/api/2/roles/123", nil, &role)
	if !IsNotFound(err) {
		t.Fatalf("GetJSON() error = %v, want a 404 StatusError", err)
	}
	if HasStatus(err, http.StatusBadRequest) {
		t.Errorf("HasStatus(err, 400) = true, want false")
	}
}

type testRole struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func TestListAll(t *testing.T) {
	tests := []struct {
		name         string
		roles        int
		query        url.Values
		maxItems     int
		wantItems    int
		wantRequests int
	}{
		{
			name:         "one page",
			roles:        3,
			query:        url.Values{"limit": []string{"10"}},
			maxItems:     100,
			wantItems:    3,
			wantRequests: 1,
		},
		{
			name:         "several pages",
			roles:        7,
			query:        url.Values{"limit": []string{"2"}},
			maxItems:     100,
			wantItems:    7,
			wantRequests: 4,
		},
		{
			name:         "exact multiple of the page size",
			roles:        6,
			query:        url.Values{"limit": []string{"2"}},
			maxItems:     100,
			wantItems:    6,
			wantRequests: 3,
		},
		{
			name:         "the cap stops paging",
			roles:        10,
			query:        url.Values{"limit": []string{"2"}},
			maxItems:     5,
			wantItems:    5,
			wantRequests: 3,
		},
		{
			// OneLogin's cursor carries the name filter, so later pages keep it without sending it.
			name:         "a filter is kept on later pages",
			roles:        7,
			query:        url.Values{"limit": []string{"1"}, "name": []string{"ENG"}},
			maxItems:     100,
			wantItems:    4,
			wantRequests: 4,
		},
		{
			name:         "empty",
			roles:        0,
			query:        url.Values{"limit": []string{"2"}},
			maxItems:     100,
			wantItems:    0,
			wantRequests: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := onelogintest.New(t, testRoles(tt.roles), nil)
			c, _ := newTestClient(fake.URL)

			got, err := ListAll[testRole](t.Context(), c, "/api/2/roles", tt.query, tt.maxItems, 0)
			if err != nil {
				t.Fatalf("ListAll() error = %v", err)
			}
			if len(got) != tt.wantItems {
				t.Errorf("items = %d, want %d", len(got), tt.wantItems)
			}
			filter := strings.ToLower(tt.query.Get("name"))
			for i, role := range got {
				if i > 0 && role.ID <= got[i-1].ID {
					t.Errorf("item %d has ID %d, after %d", i, role.ID, got[i-1].ID)
				}
				if !strings.Contains(role.Name, filter) {
					t.Errorf("item %d is named %q, which does not match the filter %q", i, role.Name, filter)
				}
			}

			requests := fake.Requests()
			if len(requests) != tt.wantRequests {
				t.Fatalf("requests = %d, want %d", len(requests), tt.wantRequests)
			}
			if got := requests[0].Query(); got.Encode() != tt.query.Encode() {
				t.Errorf("first request query = %q, want %q", got.Encode(), tt.query.Encode())
			}
			for _, u := range requests[1:] {
				query := u.Query()
				if len(query) != 1 || query.Get("cursor") == "" {
					t.Errorf("later request query = %q, want only a cursor", u.RawQuery)
				}
			}
		})
	}
}

func TestListAllRepeatedCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			_, _ = io.WriteString(w, `{"access_token":"token","expires_in":36000}`)
			return
		}
		w.Header().Set(AfterCursorHeader, "c2FtZQ==")
		_, _ = io.WriteString(w, `[{"id":1,"name":"a"}]`)
	}))
	defer srv.Close()

	c, _ := newTestClient(srv.URL)
	if _, err := ListAll[testRole](t.Context(), c, "/api/2/roles", nil, 100, 0); err == nil {
		t.Fatal("ListAll() error = nil, want an error for a repeated cursor")
	}
}

func TestRequestCanceledContext(t *testing.T) {
	fake := onelogintest.New(t, nil, nil)
	c, _ := newTestClient(fake.URL)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := c.doRequest(ctx, http.MethodGet, "/api/2/roles", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("doRequest() error = %v, want context.Canceled", err)
	}
}

func TestTokenRequestShared(t *testing.T) {
	const callers = 5

	tests := []struct {
		name            string
		tokenStatus     int
		wantRateLimited bool
		wantAPICalls    int
	}{
		{
			name:            "waiting callers share the token",
			tokenStatus:     http.StatusOK,
			wantRateLimited: false,
			wantAPICalls:    callers,
		},
		{
			name:            "waiting callers share a 429",
			tokenStatus:     http.StatusTooManyRequests,
			wantRateLimited: true,
			wantAPICalls:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := onelogintest.New(t, testRoles(1), nil)

			synctest.Test(t, func(t *testing.T) {
				var (
					tokenRequests atomic.Int32
					release       = make(chan struct{})
				)
				// The token request blocks until release is closed, so that every caller is waiting on it.
				transport := onelogintest.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == onelogintest.TokenPath {
						tokenRequests.Add(1)
						select {
						case <-release:
						case <-req.Context().Done():
							return nil, req.Context().Err()
						}
						if tt.tokenStatus != http.StatusOK {
							return &http.Response{
								StatusCode: tt.tokenStatus,
								Header:     http.Header{"Retry-After": []string{"60"}},
								Body:       http.NoBody,
								Request:    req,
							}, nil
						}
					}
					return fake.Transport().RoundTrip(req)
				})
				c := New(fake.URL, onelogintest.ClientID, onelogintest.ClientSecret, WithHTTPClient(&http.Client{Transport: transport}))

				var (
					wg   sync.WaitGroup
					errs = make([]error, callers)
				)
				for i := range errs {
					wg.Go(func() {
						var roles []testRole
						_, errs[i] = c.GetJSON(t.Context(), "/api/2/roles", nil, &roles)
					})
				}

				// One more caller gives up while the token request is in flight. It returns at once, and the
				// request carries on for the others.
				ctx, cancel := context.WithCancel(t.Context())
				quitterErr := make(chan error, 1)
				go func() {
					var roles []testRole
					_, err := c.GetJSON(ctx, "/api/2/roles", nil, &roles)
					quitterErr <- err
				}()

				synctest.Wait()
				cancel()
				if err := <-quitterErr; !errors.Is(err, context.Canceled) {
					t.Errorf("GetJSON() of the caller that gave up error = %v, want context.Canceled", err)
				}

				close(release)
				wg.Wait()

				for i, err := range errs {
					if _, rateLimited := errors.AsType[*RateLimitedError](err); rateLimited != tt.wantRateLimited {
						t.Errorf("caller %d error = %v, want a RateLimitedError: %v", i, err, tt.wantRateLimited)
					}
					if !tt.wantRateLimited && err != nil {
						t.Errorf("caller %d error = %v", i, err)
					}
				}
				if got := tokenRequests.Load(); got != 1 {
					t.Errorf("token requests = %d, want 1", got)
				}
				if got := fake.RequestCount("/api/2/roles"); got != tt.wantAPICalls {
					t.Errorf("API calls = %d, want %d", got, tt.wantAPICalls)
				}
			})
		})
	}
}

func TestTokenRequestTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// OneLogin never answers the token request.
		transport := onelogintest.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		})
		c := New("https://example.onelogin.com", onelogintest.ClientID, onelogintest.ClientSecret, WithHTTPClient(&http.Client{Transport: transport}))

		start := time.Now()
		var roles []testRole
		if _, err := c.GetJSON(t.Context(), "/api/2/roles", nil, &roles); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("GetJSON() error = %v, want context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed != tokenFetchTimeout {
			t.Errorf("GetJSON() returned after %s, want %s", elapsed, tokenFetchTimeout)
		}
	})
}

func TestListAllPageTimeout(t *testing.T) {
	const (
		pageTimeout = time.Minute
		pageDelay   = 45 * time.Second
	)
	tests := []struct {
		name        string
		stalledPage int
		wantErr     error
		wantElapsed time.Duration
	}{
		{
			name:        "slow pages that each finish in time",
			stalledPage: 0,
			wantErr:     nil,
			wantElapsed: 3 * pageDelay,
		},
		{
			name:        "a stalled second page",
			stalledPage: 2,
			wantErr:     context.DeadlineExceeded,
			wantElapsed: pageDelay + pageTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport := onelogintest.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == onelogintest.TokenPath {
						return jsonResponse(req, `{"access_token":"token","expires_in":36000}`, nil), nil
					}

					page := 1
					if cursor := req.URL.Query().Get("cursor"); cursor != "" {
						page, _ = strconv.Atoi(cursor)
					}
					if page == tt.stalledPage {
						<-req.Context().Done()
						return nil, req.Context().Err()
					}
					time.Sleep(pageDelay)

					header := http.Header{}
					if page < 3 {
						header.Set(AfterCursorHeader, strconv.Itoa(page+1))
					}
					return jsonResponse(req, fmt.Sprintf(`[{"id":%d,"name":"role-%d"}]`, page, page), header), nil
				})
				c := New("https://example.onelogin.com", onelogintest.ClientID, onelogintest.ClientSecret, WithHTTPClient(&http.Client{Transport: transport}))

				start := time.Now()
				roles, err := ListAll[testRole](t.Context(), c, "/api/2/roles", nil, 100, pageTimeout)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ListAll() error = %v, want %v", err, tt.wantErr)
				}
				if elapsed := time.Since(start); elapsed != tt.wantElapsed {
					t.Errorf("ListAll() returned after %s, want %s", elapsed, tt.wantElapsed)
				}
				if tt.wantErr == nil && len(roles) != 3 {
					t.Errorf("ListAll() returned %d roles, want 3", len(roles))
				}
			})
		})
	}
}

// jsonResponse builds a 200 response with body and header, for in-memory transports.
func jsonResponse(req *http.Request, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func TestNewHTTPClient(t *testing.T) {
	httpClient := NewHTTPClient()
	if httpClient.Timeout != requestTimeout {
		t.Errorf("Timeout = %s, want %s", httpClient.Timeout, requestTimeout)
	}

	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is a %T, want an *http.Transport", httpClient.Transport)
	}
	if transport.ResponseHeaderTimeout != responseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout = %s, want %s", transport.ResponseHeaderTimeout, responseHeaderTimeout)
	}
	if transport.MaxIdleConnsPerHost != maxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", transport.MaxIdleConnsPerHost, maxIdleConnsPerHost)
	}
	if transport == http.DefaultTransport {
		t.Error("Transport is http.DefaultTransport, want a clone")
	}
}

func TestGetJSONResponseTooLarge(t *testing.T) {
	fake := onelogintest.New(t, nil, nil)
	transport := onelogintest.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == onelogintest.TokenPath {
			return fake.Transport().RoundTrip(req)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("[" + strings.Repeat("1,", maxResponseBodyBytes/2) + "1]")),
			Request:    req,
		}, nil
	})
	c := New(fake.URL, onelogintest.ClientID, onelogintest.ClientSecret, WithHTTPClient(&http.Client{Transport: transport}))

	var ids []int
	if _, err := c.GetJSON(t.Context(), "/api/2/roles", nil, &ids); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("GetJSON() error = %v, want one for a response over the cap", err)
	}
}

func TestGetJSONReusesConnections(t *testing.T) {
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			_, _ = io.WriteString(w, `{"access_token":"token","expires_in":36000}`)
			return
		}
		// Whitespace after the JSON value is left unread by the decoder, so only draining lets the connection be
		// reused. Go 1.27's transport drains a small remainder on its own, so this fails without the drain only on
		// earlier versions, such as the go.mod minimum.
		_, _ = io.WriteString(w, "[]"+strings.Repeat(" ", 2048))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	c, _ := newTestClient(srv.URL)
	for i := range 3 {
		var roles []testRole
		if _, err := c.GetJSON(t.Context(), "/api/2/roles", nil, &roles); err != nil {
			t.Fatalf("GetJSON() %d error = %v", i, err)
		}
	}

	if got := newConns.Load(); got != 1 {
		t.Errorf("connections = %d, want 1", got)
	}
}
