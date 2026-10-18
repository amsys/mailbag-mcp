// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"regexp"
	"strings"
)

// markerRe finds an open or close fence marker, in any case, using
// either the ASCII bracket or its full-width look-alike U+FF3B, so
// both forms are escaped before the real fence is added around them
// (§3.15, G2). Group 1 holds the marker text without the bracket.
var markerRe = regexp.MustCompile(`(?i)[\[\x{FF3B}](/?UNTRUSTED_)`)

// escapeMarkers replaces the bracket of a `[UNTRUSTED_` or
// `[/UNTRUSTED_` prefix found in content, ASCII or full-width, with
// U+27E6, no regard to case, so content cannot forge a fence marker
// (§3.15, G2).
//
// arch: T2.1, §3.15, G2, G4, §10.4
func escapeMarkers(s string) string {
	return markerRe.ReplaceAllString(s, "⟦$1")
}

// StripFenceMarkers deletes a `[UNTRUSTED_` or `[/UNTRUSTED_` prefix
// found in s, bracket and all, ASCII or full-width, no regard to case,
// so s cannot contain a working fence marker (§3.14, M14). This
// is for outgoing sender-visible text (a reply subject or body): the
// marker must go, not just get escaped, because the receiving side is
// another mail reader, not the guard's own fence parser. Use Fence,
// not this function, on inbound sender-controlled text.
//
// It runs StripInvisible first: a hidden character placed inside the
// marker word (for example a zero-width character splitting
// "UNTRUSTED_") keeps this call's own regexp from seeing the marker,
// and a later, separate StripInvisible call by some other caller
// would then join the halves back into a working one. Doing the
// strip here, first, means no caller order can revive a marker
// (IRV.7).
//
// It then removes markers in a loop until the text stops changing,
// because removing one marker's bracket and prefix can complete
// another: "[UN[UNTRUSTED_TRUSTED_EMAIL]" loses its inner
// "[UNTRUSTED_" on the first pass and becomes "[UNTRUSTED_EMAIL]", a
// working marker. Each pass deletes at least 11 characters, so the
// loop ends.
//
// arch: DRV.9, IRV.7, §3.14, M14
func StripFenceMarkers(s string) string {
	out, _ := StripInvisible(s)
	for {
		next := markerRe.ReplaceAllString(out, "")
		if next == out {
			return out
		}
		out = next
	}
}

// Fence wraps body in `[UNTRUSTED_<KIND>]` ... `[/UNTRUSTED_<KIND>]`
// markers. It is the one entry point for fencing sender-controlled
// text: it runs Sanitize on body (NFKC, hidden characters removed,
// markers and chat template tokens escaped, D4.1), so a caller cannot
// break the fence by doing the steps in the wrong order (a hidden
// character placed inside a forged marker would otherwise survive
// escaping and turn real once something strips it later). kind is
// upper-cased. Server-controlled fields never go through Fence
// (§3.15): only a sender-controlled field does.
//
// arch: T2.1, §3.15, G2, G4, §10.4, D4.1
func Fence(kind, body string) string {
	k := strings.ToUpper(kind)
	var b strings.Builder
	b.WriteString("[UNTRUSTED_")
	b.WriteString(k)
	b.WriteString("]\n")
	b.WriteString(Sanitize(body))
	b.WriteString("\n[/UNTRUSTED_")
	b.WriteString(k)
	b.WriteString("]")
	return b.String()
}
