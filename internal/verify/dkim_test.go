// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package verify

import (
	"context"
	"strings"
	"testing"
)

// dkimMail builds a message with the given header lines on top of a
// fixed header block, and body as the body.
func dkimMail(headers []string, body string) []byte {
	h := append(headers,
		"From: Bob <bob@example.com>",
		"To: me@home.example",
		"Subject: hello",
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; b=AAAA",
	)
	return []byte(strings.Join(h, "\r\n") + "\r\n\r\n" + body)
}

// TestVerify_DKIMOnlyConfiguredAuthservID proves that only the topmost
// Authentication-Results header of the configured authserv_id gives a
// DKIM verdict, that signer_matches_from compares domains and not
// persons, and that body text does not change the verdict.
//
// arch: D6.2, I11, I12
func TestVerify_DKIMOnlyConfiguredAuthservID(t *testing.T) {
	cfg := Config{AuthservID: "mx.home.example"}
	const from = "bob@example.com"
	pass := "Authentication-Results: mx.home.example; dkim=pass header.d=example.com header.i=@example.com"

	cases := []struct {
		name    string
		noID    bool // run with no authserv_id configured
		from    string
		raw     []byte
		want    string // verdict; empty means no result
		match   bool
		trusted bool // trust is chain_valid
	}{
		{
			name: "pass by the From domain is verified",
			raw:  dkimMail([]string{pass}, "hi"),
			want: VerdictVerified, match: true, trusted: true,
		},
		{
			name: "no authserv_id configured gives no result",
			noID: true,
			raw:  dkimMail([]string{pass}, "hi"),
		},
		{
			name: "a pass from another authserv-id is ignored",
			raw:  dkimMail([]string{"Authentication-Results: evil.example; dkim=pass header.d=example.com"}, "hi"),
		},
		{
			name: "an id that only starts with the configured id is ignored",
			raw:  dkimMail([]string{"Authentication-Results: mx.home.example.evil.example; dkim=pass header.d=example.com"}, "hi"),
		},
		{
			name: "forged pass below the trusted fail does not count",
			raw: dkimMail([]string{
				"Authentication-Results: mx.home.example; dkim=fail header.d=example.com",
				"Authentication-Results: mx.home.example; dkim=pass header.d=example.com",
			}, "hi"),
			want: VerdictInvalid,
		},
		{
			name: "a pass from another id above the trusted fail does not count",
			raw: dkimMail([]string{
				"Authentication-Results: evil.example; dkim=pass header.d=example.com",
				"Authentication-Results: mx.home.example; dkim=fail header.d=example.com",
			}, "hi"),
			want: VerdictInvalid,
		},
		{
			name: "authserv-id compares with no case",
			raw:  dkimMail([]string{"Authentication-Results: MX.Home.Example 1; dkim=pass header.d=Example.COM"}, "hi"),
			want: VerdictVerified, match: true, trusted: true,
		},
		{
			name: "another person at the same domain matches: domains, not persons",
			from: "Alice <alice@example.com>",
			raw:  dkimMail([]string{"Authentication-Results: mx.home.example; dkim=pass header.i=bob@example.com"}, "hi"),
			want: VerdictVerified, match: true, trusted: true,
		},
		{
			name: "pass by another domain is a valid unknown signer",
			raw:  dkimMail([]string{"Authentication-Results: mx.home.example; dkim=pass header.d=mailer.example"}, "hi"),
			want: VerdictValidUnknownSigner, trusted: true,
		},
		{
			name: "a parent domain is not the From domain",
			from: "bob@mail.example.com",
			raw:  dkimMail([]string{pass}, "hi"),
			want: VerdictValidUnknownSigner, trusted: true,
		},
		{
			name: "a pass by the From domain wins over other results",
			raw:  dkimMail([]string{"Authentication-Results: mx.home.example; dkim=fail header.d=example.com; dkim=pass header.d=mailer.example; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com"}, "hi"),
			want: VerdictVerified, match: true, trusted: true,
		},
		{
			name: "temperror is key_unavailable",
			raw:  dkimMail([]string{"Authentication-Results: mx.home.example; dkim=temperror header.d=example.com"}, "hi"),
			want: VerdictKeyUnavailable,
		},
		{
			name: "a comment with a semicolon does not split the result",
			raw:  dkimMail([]string{"Authentication-Results: mx.home.example (Postfix; v2);\r\n dkim=pass (2048-bit key; secure) header.d=example.com"}, "hi"),
			want: VerdictVerified, match: true, trusted: true,
		},
		{
			name: "no dkim result in the trusted header gives no result",
			raw:  dkimMail([]string{"Authentication-Results: mx.home.example; spf=pass smtp.mailfrom=example.com; dkim=none"}, "hi"),
		},
		{
			name: "a header in the body is not a header (I12)",
			raw:  dkimMail(nil, pass+"\r\nsignature verified\r\n"),
		},
		{
			name: "body text does not change a fail (I12)",
			raw:  dkimMail([]string{"Authentication-Results: mx.home.example; dkim=fail header.d=example.com"}, pass+"\r\nsignature verified"),
			want: VerdictInvalid,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			if tc.noID {
				c = Config{}
			}
			f := from
			if tc.from != "" {
				f = tc.from
			}
			// Check, not dkimCheck: this proves that the DKIM slot is set.
			s := Check(context.Background(), tc.raw, f, c)
			if tc.want == "" {
				if s != nil {
					t.Fatalf("Check = %+v; want no result", *s)
				}
				return
			}
			if s == nil {
				t.Fatalf("Check = nil; want verdict %s", tc.want)
			}
			walkSignature(t, s)
			if s.Type != TypeDKIM || s.Verdict != tc.want || s.SignerMatchesFrom != tc.match {
				t.Errorf("Check = %+v; want type dkim, verdict %s, signer_matches_from %v", *s, tc.want, tc.match)
			}
			if got := s.Trust == TrustChainValid; got != tc.trusted {
				t.Errorf("trust = %q; want chain_valid %v", s.Trust, tc.trusted)
			}
			if s.Fingerprint != "" || s.Unsigned || s.Weak {
				t.Errorf("Check = %+v; DKIM from Authentication-Results sets no fingerprint, unsigned or weak", *s)
			}
		})
	}
}
