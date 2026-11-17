// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"regexp"
	"strings"
)

// markerFoldRe finds an open or close fence marker in a foldCopy
// result, in any case, with the ASCII bracket or its full-width form
// U+FF3B. The separator after the word is optional and can be `_`, a
// space or `-`, so that a form that a human reads as a marker also
// matches. The match covers the bracket through the separator.
//
// arch: DH2.2, DH2.3
var markerFoldRe = regexp.MustCompile(`(?i)[\[\x{FF3B}]/?UNTRUSTED[_ \-]?`)

// escapeMarkers replaces the bracket of each fence marker in s with
// U+27E6, so content cannot forge a marker (§3.15, G2). A marker can
// use confusable letters or a confusable slash, a separator that is
// `_`, a space or `-`, or no separator, and a rune that shows no glyph
// (skipInFold) can sit inside it. Only the bracket changes: all
// other bytes of s stay as they are, so a Cyrillic letter stays
// visible to the reader. The fold runs with no NFKC, because Sanitize
// has already run NFKC on s.
//
// arch: T2.1, §3.15, G2, G4, §10.4, DH2.2
func escapeMarkers(s string) string {
	folded, off := foldCopy(s, false)
	locs := markerFoldRe.FindAllStringIndex(folded, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 2*len(locs))
	last := 0
	for _, loc := range locs {
		start := off[loc[0]]
		b.WriteString(s[last:start])
		b.WriteRune('\u27E6')
		last = runeEnd(s, off, loc[0])
	}
	b.WriteString(s[last:])
	return b.String()
}

// removeMarkers deletes each fence marker in s, for one pass of
// StripFenceMarkers. The fold runs with NFKC, because s has had no
// NFKC, but the NFKC form never goes into the result: the result holds
// only original bytes of s. A deleted span starts at the bracket rune
// and ends at the end of the original rune that produced the last
// matched byte, so an NFKC expansion is never cut in half.
//
// arch: DH2.3
func removeMarkers(s string) string {
	folded, off := foldCopy(s, true)
	locs := markerFoldRe.FindAllStringIndex(folded, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, loc := range locs {
		// No NFKC form holds a bracket with other runes today, so
		// spans do not overlap. A later Unicode table can change
		// this, and a bad slice would panic on mail text.
		b.WriteString(s[last:max(off[loc[0]], last)])
		last = runeEnd(s, off, loc[1]-1)
	}
	b.WriteString(s[last:])
	return b.String()
}

// StripFenceMarkers deletes each fence marker found in s, bracket and
// all, with the forms that markerFoldRe and the fold accept: ASCII or
// full-width bracket, confusable letters or slash, any case, and a
// separator that is `_`, a space, `-` or absent (§3.14, M14). This is
// for outgoing sender-visible text (a reply subject or body): the
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
// working marker. Each pass that changes the text deletes at least
// the bracket rune, so the loop ends.
//
// The loop has a limit of stripPasses passes. Each nested level costs
// one pass over the whole text, so text with thousands of levels
// would cost quadratic time, and any sender can write such a body.
// Text that still holds a marker after the last pass loses every
// square bracket: with no bracket there is no marker. Only text built
// for this attack has that many levels.
//
// arch: DRV.9, IRV.7, §3.14, M14, DH2.3
func StripFenceMarkers(s string) string {
	out, _ := StripInvisible(s)
	for range stripPasses {
		next := removeMarkers(out)
		if next == out {
			return out
		}
		out = next
	}
	return removeBrackets(out)
}

// stripPasses is the most passes of removeMarkers that
// StripFenceMarkers makes before it removes every bracket.
const stripPasses = 16

// removeBrackets deletes each rune of s that the fold reads as the
// bracket of a marker: `[`, and a rune whose NFKC form is `[`, such as
// U+FF3B. All other bytes stay.
func removeBrackets(s string) string {
	folded, off := foldCopy(s, true)
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for i := 0; i < len(folded); i++ {
		if folded[i] != '[' {
			continue
		}
		b.WriteString(s[last:max(off[i], last)])
		last = runeEnd(s, off, i)
	}
	b.WriteString(s[last:])
	return b.String()
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
