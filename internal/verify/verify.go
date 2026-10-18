// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package verify gives the signature result that read shows (D6.1).
// The result holds only enum words, hex and booleans. A key user ID,
// a certificate subject or any other sender text never goes into it,
// because it sits outside the fence (I11).
//
// arch: D6.1, D6.2, D10.3, DRV.18
package verify

import (
	"context"
	"strings"
	"time"
)

// Signature is the result of one signature check (D6.1). No field holds
// sender text. Check passes each result through clean before it returns
// it, so a checker that puts sender text in a field loses that field.
//
// arch: D6.1, I11
type Signature struct {
	Type              string `json:"type"`                  // one of the Type* words
	Verdict           string `json:"verdict"`               // one of the Verdict* words
	Fingerprint       string `json:"fingerprint,omitempty"` // lowercase hex only
	SignerMatchesFrom bool   `json:"signer_matches_from"`
	Trust             string `json:"trust,omitempty"` // one of the Trust* words
	Unsigned          bool   `json:"unsigned_parts_present,omitempty"`
	Weak              bool   `json:"weak_algorithm,omitempty"`
}

// The words of Signature.Type (D6.1).
const (
	TypeDKIM    = "dkim"
	TypeOpenPGP = "openpgp"
	TypeSMIME   = "smime"
)

// The words of Signature.Verdict (D6.1). VerdictVerified needs all
// four: a correct signature, a signer equal to From, trust pinned or
// chain_valid (chain_valid_no_crl counts as a chain), and no unsigned
// content part. VerdictBad is a signature that checks out but whose
// signer is revoked or expired (DRV.18): trust revoked or expired
// always gives it, ahead of every other condition.
const (
	VerdictVerified           = "verified"
	VerdictValidUnknownSigner = "valid_unknown_signer"
	VerdictPartial            = "partial"
	VerdictBad                = "bad"
	VerdictInvalid            = "invalid"
	VerdictKeyUnavailable     = "key_unavailable"
	VerdictUnsupported        = "unsupported"
)

// The words of Signature.Trust (D6.1). TrustChainValidNoCRL is
// TrustChainValid with the revocation check off: the chain to
// smime_ca_file passed, but no CRL was checked, so the result says so
// instead of calling it chain_valid (DRV.18).
const (
	TrustPinned          = "pinned"
	TrustChainValid      = "chain_valid"
	TrustChainValidNoCRL = "chain_valid_no_crl"
	TrustUnknown         = "unknown"
	TrustExpired         = "expired"
	TrustRevoked         = "revoked"
)

// Types, Verdicts and Trusts are the only values the enum fields can
// hold. clean and the field walk test read these sets.
var (
	Types    = []string{TypeDKIM, TypeOpenPGP, TypeSMIME}
	Verdicts = []string{VerdictVerified, VerdictValidUnknownSigner, VerdictPartial, VerdictBad, VerdictInvalid, VerdictKeyUnavailable, VerdictUnsupported}
	Trusts   = []string{TrustPinned, TrustChainValid, TrustChainValidNoCRL, TrustUnknown, TrustExpired, TrustRevoked}
)

// MaxFingerprintHex is the longest fingerprint that clean keeps: 128
// hex characters, the size of a SHA-512 digest.
const MaxFingerprintHex = 128

// The D6.2 limits. A breach of one gives VerdictUnsupported, never
// VerdictInvalid, because the server did not check the signature
// (D10.3).
const (
	MaxInput = 25 << 20
	MaxDepth = 10
	Timeout  = 5 * time.Second
)

// Config holds the [verify] keys of accounts.toml (D6.2). The config
// package fills it.
type Config struct {
	AuthservID    string // DKIM: the only Authentication-Results authority to trust
	PGPKeysDir    string // OpenPGP: directory of public keys the human controls
	SMIMECAFile   string // S/MIME: CA bundle; empty gives trust unknown
	SMIMECRLCheck bool   // S/MIME: add -crl_check to pass B
	OpensslPath   string // S/MIME: openssl binary; empty means PATH
}

// checker is one verification path. It returns nil when the message
// has no signature of its kind. ctx carries the D6.2 5-second limit
// (F-D6); a checker whose walk reads more than one MIME part checks
// ctx.Err() between parts and stops early, the same as a structure
// error, instead of reading the full tree after the deadline.
type checker func(ctx context.Context, raw []byte, from string, cfg Config) *Signature

// The three paths of D6.2. dkim.go, openpgp.go and smime.go set them
// in an init function. A nil slot is a path that is not built.
var (
	checkDKIM    checker
	checkOpenPGP checker
	checkSMIME   checker
)

// Check gives the signature result of raw, the full message, for the
// sender address from. It returns nil when the message has no signed
// structure, no inline block and no DKIM result from the configured
// authserv_id, so an unsigned message costs no bytes (D6.1). read
// calls it for each message, so Check alone decides the type (F-D1).
//
// ctx carries the D6.2 5-second limit. Check stops at ctx and gives no
// result, the same as when no path applies, once the deadline has
// passed between two checkers; each checker's own walk stops the same
// way between the MIME parts it reads (F-D6). When ctx ends after a
// checker returns but before markUnsigned finishes its own walk, Check
// gives unsupported of that type instead of the verdict the checker
// found: the server did not finish reading the message, so it is
// never invalid (D10.3).
//
// A signature on the message content (OpenPGP, then S/MIME) comes
// before DKIM. DKIM states only the domain, so it must not hide the
// result of a signature that covers the person.
//
// Each OpenPGP and S/MIME result goes through markUnsigned, the one
// place of the unsigned_parts_present rule (D6.2, I17).
func Check(ctx context.Context, raw []byte, from string, cfg Config) *Signature {
	for _, c := range []checker{checkOpenPGP, checkSMIME, checkDKIM} {
		if c == nil || ctx.Err() != nil {
			continue
		}
		if s := c(ctx, raw, from, cfg); s != nil {
			s = markUnsigned(ctx, s, raw)
			if ctx.Err() != nil {
				// The walk that markUnsigned ran may have stopped
				// partway through, so the verdict it built is not
				// proven. Give unsupported of the same type instead
				// of a partial result the server did not finish
				// computing (D10.3).
				s = &Signature{Type: s.Type, Verdict: VerdictUnsupported}
			}
			return clean(s)
		}
	}
	return nil
}

// TypeHint gives the signature type that the bytes of raw name, or ""
// for none. It reads no structure, so it is only the type of an
// unsupported result when a D6.2 limit stops Check (D10.3). It never
// gives a verdict.
//
// arch: D10.3
func TypeHint(raw []byte) string {
	if unsupportedIfPGP(raw) != nil {
		return TypeOpenPGP
	}
	if unsupportedIfSMIME(raw) != nil {
		return TypeSMIME
	}
	return ""
}

// clean enforces I11 on s. A Type that is not a known word drops the
// result. A Verdict that is not a known word becomes unsupported. A
// Fingerprint that is not hex, or a Trust that is not a known word,
// becomes empty. The result can only hold enum words, hex and booleans.
func clean(s *Signature) *Signature {
	if s == nil || !oneOf(s.Type, Types) {
		return nil
	}
	out := *s
	if !oneOf(out.Verdict, Verdicts) {
		out.Verdict = VerdictUnsupported
	}
	out.Fingerprint = strings.ToLower(out.Fingerprint)
	if !isHex(out.Fingerprint) {
		out.Fingerprint = ""
	}
	if out.Trust != "" && !oneOf(out.Trust, Trusts) {
		out.Trust = ""
	}
	return &out
}

func oneOf(v string, set []string) bool {
	for _, w := range set {
		if v == w {
			return true
		}
	}
	return false
}

// isHex is true for a lowercase hex string of at most
// MaxFingerprintHex characters. An empty string is not hex.
func isHex(v string) bool {
	if v == "" || len(v) > MaxFingerprintHex {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
