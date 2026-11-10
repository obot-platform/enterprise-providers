package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestUnverifiedEmailReason(t *testing.T) {
	token := func(claims string) string {
		return "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
	}
	for _, tc := range []struct {
		name    string
		idToken string
		want    string
	}{
		{
			name:    "verified",
			idToken: token(`{"email_verified":true}`),
			want:    "",
		},
		{
			name:    "explicitly unverified",
			idToken: token(`{"email_verified":false}`),
			want:    "email_verified is false",
		},
		{
			name:    "claim missing",
			idToken: token(`{}`),
			want:    "does not include email_verified",
		},
		{
			name:    "claim not a boolean",
			idToken: token(`{"email_verified":"true"}`),
			want:    "not a boolean",
		},
		{
			name:    "not a JWT",
			idToken: "opaque",
			want:    "could not be read",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := unverifiedEmailReason(tc.idToken)
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("reason %q, want %q", got, tc.want)
			}
		})
	}
}
