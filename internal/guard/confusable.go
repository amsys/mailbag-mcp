// SPDX-License-Identifier: MIT

// This file holds the fold table of the fence marker checks. A forged
// fence marker can use letters of another script that look like the
// letters of UNTRUSTED, or a character that looks like a slash. The
// fold turns those characters into ASCII, so one pattern finds every
// form of a marker.

package guard

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// foldRunes maps a rune that looks like a letter of UNTRUSTED, or a
// slash, to its ASCII form. The base table holds the runes that NFKC
// does not change and that Unicode 18.0.0 confusables.txt lists for
// each letter, written as escapes. Letters are upper case, because the
// marker pattern ignores case. Runes that NFKC changes need no entry:
// NFKC gives the ASCII letter or a rune of this table.
//
// arch: DH2.1
var foldRunes = addCaseForms(map[rune]byte{
	// letter U
	'\u222A': 'U', '\u22C3': 'U', '\u054D': 'U', '\u1200': 'U', '\U000104CE': 'U',
	'\u144C': 'U', '\uA4F4': 'U', '\U00016F42': 'U', '\U000118B8': 'U', '\uA79F': 'U',
	'\u1D1C': 'U', '\uAB4E': 'U', '\uAB52': 'U', '\u028B': 'U', '\u03C5': 'U',
	'\u057D': 'U', '\U000104F6': 'U', '\U000118D8': 'U',
	// letter N
	'\u039D': 'N', '\u2C9A': 'N', '\U00011ABE': 'N', '\uA4E0': 'N', '\U00010513': 'N',
	'\u0578': 'N', '\u057C': 'N',
	// letter T
	'\u22A4': 'T', '\u27D9': 'T', '\U0001F768': 'T', '\U0001D373': 'T', '\u03A4': 'T',
	'\u2CA6': 'T', '\u0422': 'T', '\u07E0': 'T', '\u13A2': 'T', '\uA50B': 'T',
	'\u3112': 'T', '\uA4D4': 'T', '\U00016F0A': 'T', '\U000118BC': 'T', '\U00010297': 'T',
	'\U000102B1': 'T', '\U00010315': 'T', '\u4E05': 'T',
	// letter R
	'\U0001D216': 'R', '\u01A6': 'R', '\u024C': 'R', '\u13A1': 'R', '\u13D2': 'R',
	'\U000104B4': 'R', '\u1587': 'R', '\uA4E3': 'R', '\U00016F35': 'R', '\uAB47': 'R',
	'\uAB48': 'R', '\u1D26': 'R', '\u2C85': 'R', '\u0433': 'R', '\uAB81': 'R',
	'\U00016A19': 'R',
	// letter S
	'\u0405': 'S', '\u10BD': 'S', '\u10FD': 'S', '\u1CBD': 'S', '\u054F': 'S',
	'\u13D5': 'S', '\u13DA': 'S', '\uA576': 'S', '\U00016AD6': 'S', '\uA4E2': 'S',
	'\U00016F3A': 'S', '\U00010296': 'S', '\U00010420': 'S', '\uA731': 'S', '\u01BD': 'S',
	'\u0455': 'S', '\u0D1F': 'S', '\uABAA': 'S', '\U000118C1': 'S', '\U00010448': 'S',
	// letter E
	'\u22FF': 'E', '\U0001DF81': 'E', '\u0395': 'E', '\u0415': 'E', '\u2D39': 'E',
	'\u13AC': 'E', '\uA5CB': 'E', '\uA4F0': 'E', '\U000118A6': 'E', '\U000118AE': 'E',
	'\U00010286': 'E', '\u212E': 'E', '\uAB32': 'E', '\u0435': 'E', '\u04BD': 'E',
	// letter D
	'\u13A0': 'D', '\u15DE': 'D', '\u15EA': 'D', '\uA4D3': 'D', '\U0001018B': 'D',
	'\u0501': 'D', '\u13E7': 'D', '\u146F': 'D', '\uA4D2': 'D',
	// slash
	'\u1735': '/', '\u2041': '/', '\u2215': '/', '\u2044': '/', '\u2571': '/',
	'\u27CB': '/', '\u29F8': '/', '\U0001D23A': '/', '\u31D2': '/', '\u31D3': '/',
	'\u3033': '/', '\u2CC6': '/', '\u2CC7': '/', '\u30CE': '/', '\u4E3F': '/',
})

// addCaseForms returns a copy of base that also holds each rune of the
// unicode.SimpleFold orbit of each entry, with the ASCII form of that
// entry. The table of confusables leaves out many case forms, for
// example U+0442. An entry of base is never replaced.
//
// arch: DH2.1
func addCaseForms(base map[rune]byte) map[rune]byte {
	all := make(map[rune]byte, 2*len(base))
	for r, ascii := range base {
		all[r] = ascii
		for o := unicode.SimpleFold(r); o != r; o = unicode.SimpleFold(o) {
			if _, ok := base[o]; !ok {
				all[o] = ascii
			}
		}
	}
	return all
}

// foldCopy returns a copy of s with each rune of foldRunes changed to
// its ASCII form, and the map back to s. With nfkc true, any other
// rune gives its NFKC form, taken for that rune alone, and each rune
// of the form then goes through the table. A rune that has no fold
// and no NFKC change stays as it is. An invalid UTF-8 byte stays as
// one byte.
//
// off[i] is the byte offset in s of the rune that produced byte i of
// folded. off[len(folded)] is len(s), so off holds len(folded)+1
// items. The offsets do not decrease. All the bytes of one NFKC form
// have the same offset.
//
// A rune that skipInFold names is not in the copy: a reader sees
// "UNTRUSTED" through a soft hyphen or a variation selector, so the
// pattern must see it too. Such a rune has no item in off. A match in
// folded still maps back to original bytes, and a skipped rune inside
// the match lies between the offsets of the match.
//
// arch: DH2.1
func foldCopy(s string, nfkc bool) (folded string, off []int) {
	var b strings.Builder
	b.Grow(len(s))
	off = make([]int, 0, len(s)+1)
	for i := 0; i < len(s); {
		if s[i] < utf8.RuneSelf {
			b.WriteByte(s[i])
			off = append(off, i)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteByte(s[i])
			off = append(off, i)
			i++
			continue
		}
		if ascii, ok := foldRunes[r]; ok {
			b.WriteByte(ascii)
			off = append(off, i)
			i += size
			continue
		}
		if skipInFold(r) {
			i += size
			continue
		}
		form := s[i : i+size]
		if nfkc {
			form = norm.NFKC.String(form)
		}
		for _, fr := range form {
			if ascii, ok := foldRunes[fr]; ok {
				b.WriteByte(ascii)
				off = append(off, i)
				continue
			}
			if skipInFold(fr) {
				continue
			}
			for n := utf8.RuneLen(fr); n > 0; n-- {
				off = append(off, i)
			}
			b.WriteRune(fr)
		}
		i += size
	}
	return b.String(), append(off, len(s))
}

// skipInFold is true for a rune that shows no glyph of its own between
// two letters: a nonspacing or enclosing mark (Mn, Me: variation
// selectors, the combining grapheme joiner, accents), a format
// character (Cf: the soft hyphen, the invisible operators) and the
// Hangul fillers, which are letters with an empty glyph. foldCopy
// leaves such a rune out, so it cannot split a marker word. The rune
// stays in the text. A rune of foldRunes is never skipped: the table
// is read first.
//
// arch: DH2.1, G4
func skipInFold(r rune) bool {
	switch r {
	case 0x115F, 0x1160, 0x3164, 0xFFA0:
		return true // Hangul fillers
	}
	return unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf)
}

// runeEnd returns the offset in the original text s of the end of the
// rune that produced byte i of the folded copy. off is the map that
// foldCopy returned for s, and i is less than the length of the copy.
// It reads the rune in s, so a rune that the fold skipped after it is
// not part of the span.
//
// arch: DH2.3
func runeEnd(s string, off []int, i int) int {
	_, size := utf8.DecodeRuneInString(s[off[i]:])
	return off[i] + size
}
