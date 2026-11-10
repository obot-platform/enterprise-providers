package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// getUserInfo serves GET /obot-get-user-info for the access token in the Authorization header. Obot reads "id", the
// key it later passes to /obot-list-user-auth-groups, and "name", the user's display name.
func (s *server) getUserInfo(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		http.Error(w, "no authorization token provided", http.StatusUnauthorized)
		return
	}

	claims, status, err := s.fetchUserInfo(r, token)
	if err != nil {
		fmt.Printf("ERROR: pingfederate-auth-provider: failed to get user info: %v\n", err)
		http.Error(w, "failed to get user info from PingFederate", status)
		return
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		http.Error(w, "PingFederate's userinfo response has no subject", http.StatusBadGateway)
		return
	}
	email, _ := claims["email"].(string)
	username, _ := claims["preferred_username"].(string)

	if err := json.NewEncoder(w).Encode(map[string]string{
		"id":                 subject,
		"name":               profileName(claims),
		"email":              email,
		"preferred_username": username,
	}); err != nil {
		http.Error(w, "failed to encode user info", http.StatusInternalServerError)
	}
}

func (s *server) fetchUserInfo(r *http.Request, token string) (map[string]any, int, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.userInfoURL, nil)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		status := http.StatusBadGateway
		if resp.StatusCode == http.StatusUnauthorized {
			status = http.StatusUnauthorized
		}
		return nil, status, fmt.Errorf("userinfo endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var claims map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("decode userinfo response: %w", err)
	}
	return claims, http.StatusOK, nil
}

// profileName picks the display name from the standard OIDC profile claims.
func profileName(claims map[string]any) string {
	if name, _ := claims["name"].(string); strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	given, _ := claims["given_name"].(string)
	family, _ := claims["family_name"].(string)
	if full := strings.TrimSpace(strings.TrimSpace(given) + " " + strings.TrimSpace(family)); full != "" {
		return full
	}
	username, _ := claims["preferred_username"].(string)
	return strings.TrimSpace(username)
}
