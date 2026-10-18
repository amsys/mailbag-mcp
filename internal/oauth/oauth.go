// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package oauth builds and runs the authorization-code-with-PKCE flow
// that Google and Microsoft sign-in share (§3.6): a plain HTTP client
// for the fixed authorize/token endpoints, the loopback callback
// server, the --paste fallback, and a token source that persists a
// rotated refresh token. It has no dependency on internal/secrets or
// internal/config; the account-shaped pieces (which store, which
// alias, which provider's endpoint) are the caller's job.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
package oauth

import (
	"context"
	"crypto/subtle"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// httpTimeout bounds every call this package makes to an authorize or
// token endpoint. Those endpoints are fixed constants
// (login.microsoftonline.com, accounts.google.com, ...), never a URL
// that came from mail or from the model, so the SSRF guard
// (internal/guard) does not apply and a plain client is correct
// (DS6.2).
const httpTimeout = 30 * time.Second

// Client returns the plain HTTP client every call in this package
// uses for the authorize and token endpoints (DS6.2).
func Client() *http.Client {
	return &http.Client{Timeout: httpTimeout}
}

// withClient attaches Client() to ctx the way golang.org/x/oauth2
// expects to find an HTTP client override (oauth2.HTTPClient).
func withClient(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, Client())
}

// PKCE holds one authorization-code flow's verifier, so the same
// value reaches both the authorize URL (as an S256 challenge) and the
// token exchange (§3.6: oauth2.GenerateVerifier,
// oauth2.S256ChallengeOption, oauth2.VerifierOption).
type PKCE struct {
	Verifier string
}

// NewPKCE generates a fresh PKCE verifier for one sign-in attempt.
func NewPKCE() PKCE {
	return PKCE{Verifier: oauth2.GenerateVerifier()}
}

// AuthCodeURL builds the authorization URL for one sign-in attempt,
// carrying the state and the S256 PKCE challenge derived from pkce
// (§3.6). Provider-specific parameters (login_hint, prompt, ...) are
// passed through opts.
func AuthCodeURL(cfg *oauth2.Config, state string, pkce PKCE, opts ...oauth2.AuthCodeOption) string {
	all := make([]oauth2.AuthCodeOption, 0, len(opts)+1)
	all = append(all, opts...)
	all = append(all, oauth2.S256ChallengeOption(pkce.Verifier))
	return cfg.AuthCodeURL(state, all...)
}

// Exchange trades an authorization code for a token, presenting the
// PKCE verifier that matches the challenge AuthCodeURL sent (§3.6).
func Exchange(ctx context.Context, cfg *oauth2.Config, code string, pkce PKCE) (*oauth2.Token, error) {
	return cfg.Exchange(withClient(ctx), code, oauth2.VerifierOption(pkce.Verifier))
}

// constantTimeEqual reports whether a and b hold the same bytes,
// without leaking their length difference through timing (§3.6: state
// compared in constant time). Two different-length strings differ, so
// comparing len() first before the constant-time comparison of equal-
// length strings leaks nothing an attacker does not already have:
// the state length is fixed and public (32 bytes, base64url-encoded).
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
