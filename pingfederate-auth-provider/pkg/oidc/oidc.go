// Package oidc is the OpenID Connect plumbing the provider needs besides
// oauth2-proxy: discovery, userinfo, and reading verified tokens' claims.
package oidc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// maxResponseBytes bounds a discovery or userinfo response.
const maxResponseBytes = 1 << 20

// Discovery is the subset of the OpenID Provider Metadata document we use.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	// IDTokenSigningAlgs is id_token_signing_alg_values_supported.
	IDTokenSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
}

// asymmetricSigningAlgs are verifiable with the JWKS keys, unlike none and
// HMAC, which PingFederate also advertises.
var asymmetricSigningAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

// SigningAlgs returns the advertised algorithms in asymmetricSigningAlgs.
func (d *Discovery) SigningAlgs() []string {
	var algs []string
	for _, alg := range d.IDTokenSigningAlgs {
		if asymmetricSigningAlgs[alg] {
			algs = append(algs, alg)
		}
	}
	return algs
}

// NewHTTPClient trusts the system roots plus the given PEM files. It has its
// own transport, because oauth2-proxy installs its CAs in the default one.
// It follows no redirects: Go would keep the Authorization header on a
// same-host redirect, even to plain HTTP.
func NewHTTPClient(caFiles []string) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caFiles) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		for _, caFile := range caFiles {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("read CA file %s: %w", caFile, err)
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("CA file %s contains no PEM certificates", caFile)
			}
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsConfig,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// Discover fetches <issuer>/.well-known/openid-configuration.
func Discover(ctx context.Context, client *http.Client, issuer string) (*Discovery, error) {
	url := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("fetch %s: unexpected status %d%s: %s", url, resp.StatusCode, redirectTarget(resp), strings.TrimSpace(string(body)))
	}
	var d Discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&d); err != nil {
		return nil, fmt.Errorf("decode discovery document: %w", err)
	}
	return &d, nil
}

// ErrTokenRejected is userinfo refusing the access token (401 or 403), as
// for a revoked token, rather than failing to answer.
var ErrTokenRejected = errors.New("userinfo rejected the access token")

// Userinfo returns the userinfo claims for a bearer token. A signed answer
// (application/jwt) is read without checking the signature, as oauth2-proxy
// does: it arrives over the same verified TLS as JSON.
func Userinfo(ctx context.Context, client *http.Client, userinfoURL, authorization string) (map[string]any, error) {
	if userinfoURL == "" {
		return nil, fmt.Errorf("no userinfo endpoint configured")
	}
	token := strings.TrimSpace(authorization)
	if len(token) >= 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		return nil, fmt.Errorf("missing access token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		err := fmt.Errorf("userinfo returned %d%s: %s", resp.StatusCode, redirectTarget(resp), strings.TrimSpace(string(body)))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			err = fmt.Errorf("%w: %w", ErrTokenRejected, err)
		}
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read userinfo: %w", err)
	}
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType == "application/jwt" {
		claims, err := UnverifiedClaims(strings.TrimSpace(string(body)))
		if err != nil {
			return nil, fmt.Errorf("decode signed userinfo: %w", err)
		}
		return claims, nil
	}
	var claims map[string]any
	if err := decodeClaims(body, &claims); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	return claims, nil
}

// redirectTarget names a redirect's target in an error, or is empty.
func redirectTarget(resp *http.Response) string {
	if location := resp.Header.Get("Location"); location != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Sprintf(" (a redirect to %s, which is not followed)", location)
	}
	return ""
}

// decodeClaims keeps numbers exact, as oauth2-proxy does.
func decodeClaims(data []byte, claims *map[string]any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(claims)
}

// UnverifiedClaims decodes a JWT's payload without checking its signature.
// Use it only on tokens oauth2-proxy verified.
func UnverifiedClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]any
	if err := decodeClaims(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT payload: %w", err)
	}
	return claims, nil
}

// TimeClaim returns a NumericDate claim such as iat, or the zero time.
func TimeClaim(claims map[string]any, name string) time.Time {
	switch v := claims[name].(type) {
	case float64:
		return time.Unix(0, int64(v*float64(time.Second)))
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return time.Unix(0, int64(f*float64(time.Second)))
		}
	}
	return time.Time{}
}

// ClaimValue looks a claim up as oauth2-proxy does: by name, else as a dotted
// path (profile.groups). Null is missing.
func ClaimValue(claims map[string]any, name string) any {
	if name == "" {
		return nil
	}
	if value, ok := claims[name]; ok {
		// Present, even as null: oauth2-proxy then does not try the path.
		return value
	}
	var current any = claims
	for _, part := range strings.Split(name, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}

// StringClaim returns claim as a string, or "" when absent or not a string.
func StringClaim(claims map[string]any, name string) string {
	s, _ := ClaimValue(claims, name).(string)
	return s
}

// StringsClaim returns a multi-valued claim. An array's elements are never
// split, so an LDAP DN stays whole; a string is split on delimiter if set.
func StringsClaim(claims map[string]any, name, delimiter string) []string {
	switch v := ClaimValue(claims, name).(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, SplitValues(s, "")...)
			}
		}
		return out
	case []string:
		var out []string
		for _, s := range v {
			out = append(out, SplitValues(s, "")...)
		}
		return out
	case string:
		return SplitValues(v, delimiter)
	default:
		return nil
	}
}

// SplitValues splits on delimiter, if set, dropping empty entries.
func SplitValues(value, delimiter string) []string {
	parts := []string{value}
	if delimiter != "" {
		parts = strings.Split(value, delimiter)
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// DisplayName picks a name from the standard claims, else the email.
func DisplayName(claims map[string]any, emailClaim string) string {
	if name := StringClaim(claims, "name"); name != "" {
		return name
	}
	given, family := StringClaim(claims, "given_name"), StringClaim(claims, "family_name")
	if full := strings.TrimSpace(given + " " + family); full != "" {
		return full
	}
	if name := StringClaim(claims, "preferred_username"); name != "" {
		return name
	}
	return StringClaim(claims, emailClaim)
}
