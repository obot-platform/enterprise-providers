package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obot-platform/enterprise-providers/onelogin-auth-provider/pkg/onelogintest"
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

	_, err := c.DoRequest(t.Context(), http.MethodGet, "/api/2/roles", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "token endpoint returned status 401") {
		t.Fatalf("DoRequest() error = %v, want a token endpoint 401", err)
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

			resp, err := c.DoRequest(t.Context(), http.MethodGet, "/api/2/roles", nil, nil)
			if err != nil {
				t.Fatalf("DoRequest() error = %v", err)
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

func TestUnauthorizedRetryReplaysBody(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
		tokens int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.URL.Path == tokenPath {
			tokens++
			_, _ = io.WriteString(w, `{"access_token":"token-`+strconv.Itoa(tokens)+`","expires_in":36000}`)
			return
		}

		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		if r.Header.Get("Authorization") == "Bearer token-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := newTestClient(srv.URL)
	resp, err := c.DoRequest(t.Context(), http.MethodPost, "/api/2/example", nil, []byte(`{"key":"value"}`))
	if err != nil {
		t.Fatalf("DoRequest() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if len(bodies) != 2 || bodies[0] != `{"key":"value"}` || bodies[1] != bodies[0] {
		t.Errorf("bodies = %q, want the same body twice", bodies)
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
			wantRetryAfter: DefaultRateLimitWait,
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
			wantRetryAfter: DefaultRateLimitWait,
		},
		{
			name:           "Retry-After in the past",
			retryAfter:     "Wed, 14 Oct 2026 19:00:00 GMT",
			wantRetryAfter: DefaultRateLimitWait,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := onelogintest.New(t, testRoles(1), nil)
			fake.SetRateLimited(true, tt.retryAfter)
			c, clock := newTestClient(fake.URL)

			_, err := c.DoRequest(t.Context(), http.MethodGet, "/api/2/roles", nil, nil)
			var rateLimitErr *RateLimitedError
			if !errors.As(err, &rateLimitErr) {
				t.Fatalf("DoRequest() error = %v, want a RateLimitedError", err)
			}
			if rateLimitErr.RetryAfter != tt.wantRetryAfter {
				t.Errorf("RetryAfter = %s, want %s", rateLimitErr.RetryAfter, tt.wantRetryAfter)
			}

			// OneLogin stops rate limiting at once, but the client waits out the whole window without calling it.
			fake.SetRateLimited(false, "")
			clock.Advance(tt.wantRetryAfter - time.Second)

			if err := c.RateLimitErr(); !errors.As(err, &rateLimitErr) || rateLimitErr.RetryAfter != time.Second {
				t.Errorf("RateLimitErr() = %v, want a RateLimitedError with a second left", err)
			}
			if _, err := c.DoRequest(t.Context(), http.MethodGet, "/api/2/roles", nil, nil); !errors.As(err, &rateLimitErr) {
				t.Fatalf("DoRequest() in the window error = %v, want a RateLimitedError", err)
			}
			if got := fake.RequestCount("/api/2/roles"); got != 1 {
				t.Errorf("API calls in the window = %d, want 1", got)
			}

			clock.Advance(time.Second)

			if err := c.RateLimitErr(); err != nil {
				t.Errorf("RateLimitErr() after the window = %v, want nil", err)
			}
			resp, err := c.DoRequest(t.Context(), http.MethodGet, "/api/2/roles", nil, nil)
			if err != nil {
				t.Fatalf("DoRequest() after the window error = %v", err)
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
	if _, err := c.DoRequest(t.Context(), http.MethodGet, "/api/2/roles", nil, nil); !errors.As(err, &rateLimitErr) || rateLimitErr.RetryAfter != time.Minute {
		t.Fatalf("DoRequest() error = %v, want a RateLimitedError of a minute", err)
	}
	if _, err := c.DoRequest(t.Context(), http.MethodGet, "/api/2/roles", nil, nil); !errors.As(err, &rateLimitErr) {
		t.Fatalf("second DoRequest() error = %v, want a RateLimitedError", err)
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

			got, err := ListAll[testRole](t.Context(), c, "/api/2/roles", tt.query, tt.maxItems)
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
	if _, err := ListAll[testRole](t.Context(), c, "/api/2/roles", nil, 100); err == nil {
		t.Fatal("ListAll() error = nil, want an error for a repeated cursor")
	}
}

func TestDoRequestCanceledContext(t *testing.T) {
	fake := onelogintest.New(t, nil, nil)
	c, _ := newTestClient(fake.URL)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := c.DoRequest(ctx, http.MethodGet, "/api/2/roles", nil, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("DoRequest() error = %v, want context.Canceled", err)
	}
}
