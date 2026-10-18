// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// TestExchange_PKCEAgainstFakeTokenEndpoint checks that AuthCodeURL
// sends an S256 challenge derived from the PKCE verifier, and that
// Exchange presents the matching verifier to the token endpoint
// (§3.6: oauth2.GenerateVerifier, oauth2.S256ChallengeOption,
// oauth2.VerifierOption) rather than a hand-rolled PKCE
// implementation: adopting x/oauth2's own PKCE options applies here
// because DS6.1 says the library is already linked in, and DS6.7
// rejects hand-written PKCE as no size gain and more code to get
// wrong.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestExchange_PKCEAgainstFakeTokenEndpoint(t *testing.T) {
	pkce := NewPKCE()
	if pkce.Verifier == "" {
		t.Fatalf("NewPKCE: empty verifier")
	}

	var gotVerifier string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("token endpoint: parse form: %v", err)
		}
		gotVerifier = r.Form.Get("code_verifier")
		if r.Form.Get("code") != "the-code" {
			t.Fatalf("token endpoint: code = %q, want %q", r.Form.Get("code"), "the-code")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at-1",
			"refresh_token": "rt-1",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer srv.Close()

	cfg := &oauth2.Config{
		ClientID: "client-1",
		Endpoint: oauth2.Endpoint{
			AuthURL:   srv.URL + "/authorize",
			TokenURL:  srv.URL + "/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: "http://127.0.0.1:0/callback",
	}

	authURL := AuthCodeURL(cfg, "state-1", pkce)
	if !strings.Contains(authURL, "code_challenge=") || !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Fatalf("AuthCodeURL = %q, want an S256 code_challenge", authURL)
	}
	if !strings.Contains(authURL, "state=state-1") {
		t.Fatalf("AuthCodeURL = %q, want the state carried through", authURL)
	}

	tok, err := Exchange(context.Background(), cfg, "the-code", pkce)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "at-1" {
		t.Fatalf("Exchange token = %+v, want AccessToken at-1", tok)
	}
	if gotVerifier != pkce.Verifier {
		t.Fatalf("token endpoint saw code_verifier = %q, want %q", gotVerifier, pkce.Verifier)
	}
}

// TestConstantTimeEqual_LengthAndContent checks the fast-reject path
// (different length) and the equal-length comparison both give the
// right answer; the loopback and paste tests only exercise this
// indirectly through full requests, so this test pins the helper on
// its own.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestConstantTimeEqual_LengthAndContent(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "abcd", false},
		{"", "", true},
	}
	for _, c := range cases {
		if got := constantTimeEqual(c.a, c.b); got != c.want {
			t.Errorf("constantTimeEqual(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
