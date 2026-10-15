// Package onelogintest provides a fake of the parts of the OneLogin admin API that directory synchronization calls,
// for tests. It behaves as OneLogin's v2 API has been observed to: lists are bare JSON arrays sorted by ID, the role
// name filter is a case-insensitive substring match, and paging follows an After-Cursor that OneLogin rejects with
// 400 when it is sent along with limit or page.
package onelogintest

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	// ClientID and ClientSecret are the API credentials the fake accepts.
	ClientID     = "test-client-id"
	ClientSecret = "test-client-secret"

	// TokenLifetimeSeconds is the expires_in of every token the fake issues, as OneLogin's.
	TokenLifetimeSeconds = 36000

	// TokenPath is the path of OneLogin's token endpoint.
	TokenPath = "/auth/oauth2/v2/token"
)

// Role is a OneLogin role.
type Role struct {
	ID   int64
	Name string
}

// User is a OneLogin user.
type User struct {
	ID      int64
	RoleIDs []int64
	Status  int
}

// Server is a fake OneLogin admin API.
type Server struct {
	*httptest.Server

	mu            sync.Mutex
	roles         []Role
	users         map[int64]User
	tokens        int
	requests      []*url.URL
	rateLimited   bool
	retryAfter    string
	rejectedToken map[string]bool
	failingPaths  map[string]int
}

// New starts a fake with the given roles and users, and stops it when the test ends.
func New(t testing.TB, roles []Role, users []User) *Server {
	t.Helper()

	s := &Server{
		users:         make(map[int64]User, len(users)),
		rejectedToken: map[string]bool{},
		failingPaths:  map[string]int{},
	}
	s.SetRoles(roles)
	for _, u := range users {
		s.users[u.ID] = u
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+TokenPath, s.token)
	mux.HandleFunc("GET /api/2/roles", s.authenticated(s.listRoles))
	mux.HandleFunc("GET /api/2/roles/{id}", s.authenticated(s.getRole))
	mux.HandleFunc("GET /api/2/users/{id}", s.authenticated(s.getUser))

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)

	return s
}

// SetRoles replaces the account's roles.
func (s *Server) SetRoles(roles []Role) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.roles = slices.Clone(roles)
	slices.SortFunc(s.roles, func(a, b Role) int {
		return cmp.Compare(a.ID, b.ID)
	})
}

// RateLimit makes every API call answer 429, with retryAfter as its Retry-After header unless it is empty.
func (s *Server) RateLimit(retryAfter string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rateLimited = true
	s.retryAfter = retryAfter
}

// StopRateLimiting undoes RateLimit.
func (s *Server) StopRateLimiting() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rateLimited = false
	s.retryAfter = ""
}

// FailPath makes every authenticated API call whose path starts with prefix answer status, as OneLogin does when it
// fails.
func (s *Server) FailPath(prefix string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failingPaths[prefix] = status
}

// StopFailingPath undoes FailPath for prefix.
func (s *Server) StopFailingPath(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.failingPaths, prefix)
}

// Transport returns a RoundTripper that serves every request in memory with the fake's handler, whatever its host.
// Tests in a synctest bubble need it: a request over the network is not durably blocked, so while one is in flight
// the bubble's clock could not advance.
func (s *Server) Transport() http.RoundTripper {
	return RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.Context().Err(); err != nil {
			return nil, err
		}

		r := req.Clone(req.Context())
		if r.Body == nil {
			r.Body = http.NoBody
		}
		defer func() { _ = r.Body.Close() }()

		rec := httptest.NewRecorder()
		s.Config.Handler.ServeHTTP(rec, r)

		resp := rec.Result()
		resp.Request = req
		return resp, nil
	})
}

// RoundTripperFunc adapts a function to an http.RoundTripper.
type RoundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// RejectToken makes the API answer 401 to the given access token, as OneLogin does for a revoked token.
func (s *Server) RejectToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rejectedToken[token] = true
}

// TokenRequests returns how many access tokens the fake has issued.
func (s *Server) TokenRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.tokens
}

// Requests returns the URLs of the API calls the fake has received, other than token requests.
func (s *Server) Requests() []*url.URL {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Clone(s.requests)
}

// RequestCount returns how many API calls the fake has received for path.
func (s *Server) RequestCount(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	for _, u := range s.requests {
		if u.Path == path {
			count++
		}
	}

	return count
}

// token issues a new access token for valid Basic credentials and a client_credentials grant.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok || id != ClientID || secret != ClientSecret {
		writeError(w, http.StatusUnauthorized, "Unauthorized", "Authentication Failure")
		return
	}

	var body struct {
		GrantType string `json:"grant_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.GrantType != "client_credentials" {
		writeError(w, http.StatusBadRequest, "BadRequestError", "grant_type must be client_credentials")
		return
	}

	s.mu.Lock()
	s.tokens++
	token := fmt.Sprintf("token-%d", s.tokens)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  token,
		"created_at":    "2026-01-01T00:00:00.000Z",
		"expires_in":    TokenLifetimeSeconds,
		"refresh_token": "refresh-" + token,
		"token_type":    "bearer",
		"account_id":    1,
	})
}

// authenticated records the call, and answers 429 while the fake is rate limited, 401 to a token it did not issue or
// has rejected, and the status FailPath set for a failing path.
func (s *Server) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.URL)
		var (
			rateLimited = s.rateLimited
			retryAfter  = s.retryAfter
			failStatus  int
		)
		token, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		valid := hasBearer && !s.rejectedToken[token] && validToken(token, s.tokens)
		for prefix, status := range s.failingPaths {
			if strings.HasPrefix(r.URL.Path, prefix) {
				failStatus = status
			}
		}
		s.mu.Unlock()

		if rateLimited {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			writeError(w, http.StatusTooManyRequests, "TooManyRequestsError", "Too Many Requests")
			return
		}
		if !valid {
			writeError(w, http.StatusUnauthorized, "Unauthorized", "Authentication Failure")
			return
		}
		if failStatus != 0 {
			writeError(w, failStatus, http.StatusText(failStatus), http.StatusText(failStatus))
			return
		}

		next(w, r)
	}
}

// listRoles serves GET /api/2/roles.
func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Has("cursor") {
		if query.Has("limit") || query.Has("page") {
			writeError(w, http.StatusBadRequest, "BadRequestError", "Requests can only have cursor xor pagination arguments")
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(query.Get("cursor"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "BadRequestError", "Invalid cursor")
			return
		}
		if query, err = url.ParseQuery(string(decoded)); err != nil {
			writeError(w, http.StatusBadRequest, "BadRequestError", "Invalid cursor")
			return
		}
	}

	limit := 50
	if raw := query.Get("limit"); raw != "" {
		var err error
		if limit, err = strconv.Atoi(raw); err != nil || limit <= 0 {
			writeError(w, http.StatusBadRequest, "BadRequestError", "Invalid limit")
			return
		}
	}

	page := 1
	if raw := query.Get("page"); raw != "" {
		var err error
		if page, err = strconv.Atoi(raw); err != nil || page <= 0 {
			writeError(w, http.StatusBadRequest, "BadRequestError", "Invalid page")
			return
		}
	}

	var (
		name   = query.Get("name")
		fields = query.Get("fields")
	)

	s.mu.Lock()
	var matching []Role
	for _, role := range s.roles {
		if strings.Contains(strings.ToLower(role.Name), strings.ToLower(name)) {
			matching = append(matching, role)
		}
	}
	s.mu.Unlock()

	start := min((page-1)*limit, len(matching))
	end := min(start+limit, len(matching))

	if end < len(matching) {
		next := url.Values{}
		if name != "" {
			next.Set("name", name)
		}
		if fields != "" {
			next.Set("fields", fields)
		}
		next.Set("limit", strconv.Itoa(limit))
		next.Set("page", strconv.Itoa(page+1))
		w.Header().Set("After-Cursor", base64.StdEncoding.EncodeToString([]byte(next.Encode())))
	}

	body := make([]map[string]any, 0, end-start)
	for _, role := range matching[start:end] {
		body = append(body, onlyFields(roleJSON(role), fields))
	}
	writeJSON(w, http.StatusOK, body)
}

// getRole serves GET /api/2/roles/:id. Like OneLogin, it rejects the fields parameter that the role list accepts.
func (s *Server) getRole(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("fields") {
		writeError(w, http.StatusBadRequest, "BadRequestError", "Invalid key(s): fields")
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "NotFoundError", "Not Found")
		return
	}

	s.mu.Lock()
	idx := slices.IndexFunc(s.roles, func(role Role) bool {
		return role.ID == id
	})
	var role Role
	if idx >= 0 {
		role = s.roles[idx]
	}
	s.mu.Unlock()

	if idx < 0 {
		writeError(w, http.StatusNotFound, "NotFoundError", "Not Found")
		return
	}

	writeJSON(w, http.StatusOK, roleJSON(role))
}

// getUser serves GET /api/2/users/:id, with the fields OneLogin returns that directory synchronization might read.
func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "NotFoundError", "Not Found")
		return
	}

	s.mu.Lock()
	user, ok := s.users[id]
	s.mu.Unlock()

	if !ok {
		writeError(w, http.StatusNotFound, "NotFoundError", "Not Found")
		return
	}

	roleIDs := user.RoleIDs
	if roleIDs == nil {
		roleIDs = []int64{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         user.ID,
		"username":   fmt.Sprintf("user%d", user.ID),
		"email":      fmt.Sprintf("user%d@example.com", user.ID),
		"firstname":  "Test",
		"lastname":   "User",
		"role_ids":   roleIDs,
		"state":      1,
		"status":     user.Status,
		"group_id":   nil,
		"created_at": "2026-01-01T00:00:00.000Z",
	})
}

// validToken reports whether token is one the fake has issued.
func validToken(token string, issued int) bool {
	n, err := strconv.Atoi(strings.TrimPrefix(token, "token-"))
	return strings.HasPrefix(token, "token-") && err == nil && n >= 1 && n <= issued
}

func roleJSON(role Role) map[string]any {
	return map[string]any{
		"admins": []int64{},
		"apps":   []int64{},
		"id":     role.ID,
		"name":   role.Name,
		"users":  []int64{},
	}
}

// onlyFields keeps the keys of item named in fields, a comma-separated list, as OneLogin's fields parameter does. An
// empty fields keeps every key.
func onlyFields(item map[string]any, fields string) map[string]any {
	if fields == "" {
		return item
	}

	names := strings.Split(fields, ",")
	trimmed := make(map[string]any, len(names))
	for _, field := range names {
		if value, ok := item[field]; ok {
			trimmed[field] = value
		}
	}
	return trimmed
}

func writeError(w http.ResponseWriter, status int, name, description string) {
	writeJSON(w, status, map[string]any{
		"description": description,
		"error":       name,
		"status":      status,
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
