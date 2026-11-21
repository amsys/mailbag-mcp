// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Fencer makes the per-response nonce and the fence markers that carry
// it, and checks that a string is one whole fence of that nonce.
//
// arch: DU1.1, DU9.1

package guard

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"strings"
)

// zeroFencerPanic is the fixed panic text of Wrap on a zero Fencer.
const zeroFencerPanic = "guard: Wrap on a zero Fencer"

// nonceBytes is the size of the nonce: 64 bits (owner ruling).
const nonceBytes = 8

// Fencer holds the nonce of one response. The zero value is not usable:
// Wrap panics on it, so no code path can write a marker with no nonce.
//
// arch: DU1.1, DU9.1
type Fencer struct {
	nonce string
	// nonceRe finds the nonce text in any case.
	nonceRe *regexp.Regexp
}

// NewFencer returns a Fencer with a nonce of 8 bytes from crypto/rand.
//
// arch: DU1.1
func NewFencer() (Fencer, error) {
	return NewFencerFrom(rand.Reader)
}

// NewFencerFrom returns a Fencer with a nonce of 8 bytes read from r.
// Only tests call it with a fixed reader.
//
// arch: DU1.1
func NewFencerFrom(r io.Reader) (Fencer, error) {
	if r == nil {
		return Fencer{}, errors.New("guard: no nonce source")
	}
	var b [nonceBytes]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Fencer{}, err
	}
	n := hex.EncodeToString(b[:])
	return Fencer{nonce: n, nonceRe: regexp.MustCompile(`(?i)` + n)}, nil
}

// Nonce returns the nonce: 16 lowercase hex characters. It is empty
// for a zero Fencer.
func (f Fencer) Nonce() string { return f.nonce }

// Wrap returns body in the open and close markers of the nonce. The
// body goes through Sanitize, then each occurrence of the nonce text,
// in any case, becomes 16 `*` characters, so content cannot close the
// fence. Wrap panics on a zero Fencer.
//
// arch: DU1.1, DU9.1
func (f Fencer) Wrap(body string) string {
	if f.nonce == "" {
		panic(zeroFencerPanic)
	}
	body2 := f.nonceRe.ReplaceAllLiteralString(Sanitize(body), strings.Repeat("*", len(f.nonce)))
	var b strings.Builder
	b.Grow(len(body2) + 2*len(f.nonce) + 28)
	b.WriteString(f.open())
	b.WriteString(body2)
	b.WriteString(f.close())
	return b.String()
}

// Holds reports whether s is one whole fence of this nonce: it starts
// with the open marker and a line feed, ends with a line feed and the
// close marker, and the text between them has no marker on its fold
// copy and no nonce text. It is false for a zero Fencer.
//
// arch: DU1.1, DU9.1
func (f Fencer) Holds(s string) bool {
	if f.nonce == "" {
		return false
	}
	open, closing := f.open(), f.close()
	if len(s) < len(open)+len(closing) || !strings.HasPrefix(s, open) || !strings.HasSuffix(s, closing) {
		return false
	}
	inner := s[len(open) : len(s)-len(closing)]
	folded, _ := foldCopy(inner, false)
	if markerFoldRe.MatchString(folded) {
		return false
	}
	return !f.nonceRe.MatchString(inner)
}

// open is the open marker and its line feed.
func (f Fencer) open() string { return "[UNTRUSTED_" + f.nonce + "]\n" }

// close is the line feed and the close marker.
func (f Fencer) close() string { return "\n[/UNTRUSTED_" + f.nonce + "]" }
