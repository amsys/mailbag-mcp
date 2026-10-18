// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"context"
	"net/mail"
	"strings"

	"github.com/emersion/go-msgauth/authres"
)

func init() { checkDKIM = dkimCheck }

// dkimCheck gives the DKIM result from the Authentication-Results
// header that the configured [verify] authserv_id wrote (D6.2). It
// reads only the message header, so body text cannot change the
// verdict (I12).
//
// Only the topmost Authentication-Results header with the configured
// authserv-id counts. The receiving server adds its header on top. A
// header below it with the same id came from an earlier hop or from
// the sender, so it can be forged. A header from any other id is
// ignored. With no authserv_id set, no header counts and the result
// is nil.
//
// DKIM proves the domain, not the person. SignerMatchesFrom is true
// when the signing domain (header.d) is equal to the domain of from.
// A subdomain is not equal.
//
// dkimCheck takes ctx only to match the checker type (F-D6); it reads
// one bounded header, not a MIME tree, so it has no parts to check ctx
// between.
//
// arch: D6.2, I11, I12
func dkimCheck(_ context.Context, raw []byte, from string, cfg Config) *Signature {
	want := strings.ToLower(strings.TrimSpace(cfg.AuthservID))
	if want == "" {
		return nil
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	for _, v := range msg.Header["Authentication-Results"] {
		v = stripComments(v)
		id, rest, _ := strings.Cut(v, ";")
		if authservID(id) != want {
			continue
		}
		return dkimVerdict(dkimResults(rest), domainOf(fromAddress(from)))
	}
	return nil
}

// authservID gives the authserv-id of the text before the first ";"
// of an Authentication-Results value, in lowercase. A version number
// after the id is dropped.
func authservID(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return strings.ToLower(f[0])
}

// dkimResults parses each result of rest, the text after the
// authserv-id. It parses one result at a time, so a result that the
// library cannot read does not remove the DKIM results next to it.
func dkimResults(rest string) []*authres.DKIMResult {
	var out []*authres.DKIMResult
	for _, part := range strings.Split(rest, ";") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		_, rs, err := authres.Parse("x; " + part)
		if err != nil {
			continue
		}
		for _, r := range rs {
			if d, ok := r.(*authres.DKIMResult); ok {
				out = append(out, d)
			}
		}
	}
	return out
}

// dkimVerdict picks the best DKIM result. A pass by the From domain
// comes first, then any pass, then a temporary error, then a failure.
// It gives nil when no DKIM result is present or each one is "none".
func dkimVerdict(rs []*authres.DKIMResult, fromDomain string) *Signature {
	var best *Signature
	rank := 0
	for _, r := range rs {
		s, n := dkimOne(r, fromDomain)
		if n > rank {
			best, rank = s, n
		}
	}
	return best
}

// dkimOne maps one DKIM result to a Signature and a rank. A higher
// rank is a better result. Rank 0 is no result. Only a pass can set
// SignerMatchesFrom, because the domain of a failed signature is
// sender text that nobody checked.
func dkimOne(r *authres.DKIMResult, fromDomain string) (*Signature, int) {
	d := cleanDomain(r.Domain)
	if d == "" {
		d = domainOf(r.Identifier)
	}
	match := d != "" && d == fromDomain
	s := &Signature{Type: TypeDKIM}
	switch r.Value {
	case authres.ResultNone, "":
		return nil, 0
	case authres.ResultPass:
		s.Trust = TrustChainValid
		if match {
			s.Verdict, s.SignerMatchesFrom = VerdictVerified, true
			return s, 4
		}
		s.Verdict = VerdictValidUnknownSigner
		return s, 3
	case authres.ResultTempError:
		s.Verdict = VerdictKeyUnavailable
		return s, 2
	default:
		s.Verdict = VerdictInvalid
		return s, 1
	}
}

// fromAddress gives the bare address of from. A caller can pass a
// bare address or a full "Name <address>" value.
func fromAddress(from string) string {
	if a, err := mail.ParseAddress(from); err == nil {
		return a.Address
	}
	return from
}

// domainOf gives the domain after the last "@" of addr, clean.
func domainOf(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return ""
	}
	return cleanDomain(addr[i+1:])
}

// cleanDomain removes quotes, space and a final dot, and gives
// lowercase.
func cleanDomain(d string) string {
	d = strings.Trim(strings.TrimSpace(d), `"`)
	return strings.TrimSuffix(strings.ToLower(d), ".")
}

// stripComments removes RFC 5322 comments, "(...)" with nesting and
// quoted pairs. The authres parser does not remove them, and a ";" in
// a comment would split a result in two.
func stripComments(s string) string {
	var b strings.Builder
	depth := 0
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case depth > 0 && c == '\\':
			i++
		case !quoted && c == '(':
			depth++
		case depth > 0 && c == ')':
			depth--
		case depth > 0:
		default:
			if c == '"' {
				quoted = !quoted
			} else if quoted && c == '\\' && i+1 < len(s) {
				b.WriteByte(c)
				i++
				c = s[i]
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}
