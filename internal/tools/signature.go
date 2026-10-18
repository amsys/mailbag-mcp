// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools holds, in signature.go, the signature step of the draft tool
// for an account in identity mode (DI3): the check of the caller's own
// text for a typed signature, the layout of the text part and the
// build of the HTML part.
package tools

import (
	"errors"
	"strings"
	"unicode"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// errSignatureInBody is the refusal of an own text that holds a near
// copy of the identity signature or a "-- " line (DI0 R7, DI3.2).
var errSignatureInBody = errors.New("the body holds a signature or a \"-- \" line; leave it out, the draft tool adds the signature of the identity")

// errComposedHTML is the refusal of an HTML part that the signature
// step built and that does not pass the HTML check of the send
// confirmation (DI3.5). The load check of signature_html makes this
// rare; the draft tool fails closed when it occurs.
var errComposedHTML = errors.New("the html part with the signature does not pass the html check of the send confirmation; nothing was saved")

// sigDelimiter is the line that starts a signature block (DI3.3).
const sigDelimiter = "-- \n"

// htmlDelimiter is the HTML form of the delimiter line (DI3.5).
const htmlDelimiter = "<p>-- </p>"

// htmlEscaper escapes the three characters that [mime.AllowHTML]
// escapes in text, so a part that textToHTML builds passes that
// function unchanged.
var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// cleanOwn applies the own-text checks of DI3.2 to the caller's own
// text, before any quote or forward block joins it (I10).
//
//  1. CRLF becomes LF.
//  2. When the text, with trailing white space cut, ends with
//     "-- \n" + sig or with sig at the start of a line, that copy and
//     the blank lines above it are cut (the exact copy, DI0 R7).
//  3. The rest is refused with [errSignatureInBody] when it has a line
//     whose right-trimmed form is "--", or when it holds the squashed
//     signature (a near copy, I5).
//
// A copy that does not start at a line start is not cut; step 3 then
// refuses it.
//
// arch: DI3.2, I5
func cleanOwn(own, sig string) (string, error) {
	own = strings.ReplaceAll(own, "\r\n", "\n")
	if rest, ok := cutCopy(own, sig); ok {
		own = rest
	}
	if err := checkOwn(own, sig); err != nil {
		return "", err
	}
	return own, nil
}

// cutCopy finds an exact copy of sig at the end of own (own has LF
// line ends). It gives the text without that copy and the blank lines
// above it, and true. It gives own and false when there is no copy.
func cutCopy(own, sig string) (string, bool) {
	trimmed := strings.TrimRightFunc(own, unicode.IsSpace)
	want := strings.TrimRightFunc(sig, unicode.IsSpace)
	if want == "" {
		return own, false
	}
	for _, suffix := range []string{sigDelimiter + want, want} {
		rest, ok := strings.CutSuffix(trimmed, suffix)
		if ok && (rest == "" || strings.HasSuffix(rest, "\n")) {
			return trimBlankLines(rest), true
		}
	}
	return own, false
}

// checkOwn is step 3 of DI3.2. It refuses text that has a delimiter
// line, or that holds the signature when white space is folded. The
// draft tool runs it alone on the text view of caller HTML, so a copy
// in HTML is refused and never cut.
//
// arch: DI3.2, I5
func checkOwn(text, sig string) error {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimRightFunc(line, unicode.IsSpace) == "--" {
			return errSignatureInBody
		}
	}
	s := squash(sig)
	if s == "" {
		return nil
	}
	// A one-line signature is a near copy only at the end of the text
	// and at the start of a word, so a short name inside a sentence or
	// inside a word is not refused (L2).
	if fewLines(sig) {
		st := squash(text)
		if strings.HasSuffix(st, s) && (len(st) == len(s) || st[len(st)-len(s)-1] == ' ') {
			return errSignatureInBody
		}
		return nil
	}
	if strings.Contains(squash(text), s) {
		return errSignatureInBody
	}
	return nil
}

// fewLines tells whether sig has fewer than two lines with text.
func fewLines(sig string) bool {
	n := 0
	for _, line := range strings.Split(sig, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n < 2
}

// squash folds each run of white space, newlines included, into one
// space and cuts white space at both ends (DI3.2).
func squash(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// trimBlankLines cuts the lines at the end of s that are empty or hold
// only white space. The last line with text keeps its own bytes.
func trimBlankLines(s string) string {
	lines := strings.Split(s, "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

// joinParts joins the parts that are not empty with one empty line
// between them (DI3.3).
func joinParts(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "\n\n")
}

// textToHTML turns plain text into HTML that [mime.AllowHTML] leaves
// unchanged (DI3.5). It escapes &, < and >. A run of empty lines
// starts a new p element, and a single newline becomes br.
//
// arch: DI3.5
func textToHTML(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var b strings.Builder
	var para []string
	flush := func() {
		if len(para) == 0 {
			return
		}
		b.WriteString("<p>")
		b.WriteString(strings.Join(para, "<br>"))
		b.WriteString("</p>")
		para = nil
	}
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			flush()
			continue
		}
		para = append(para, htmlEscaper.Replace(line))
	}
	flush()
	return b.String()
}

// sigFlag tells whether the identity adds its signature to this kind
// of draft (DI3.1): OnReply for a reply, OnForward for a forward, and
// OnNew for a new draft, templates included.
func sigFlag(id config.Identity, in DraftIn) bool {
	switch {
	case in.ReplyToID != "":
		return id.OnReply
	case in.ForwardID != "":
		return id.OnForward
	default:
		return id.OnNew
	}
}

// ownBody is the caller's own content after the checks of DI3.2 and
// DI3.4.
type ownBody struct {
	text    string // O of DI3.3
	hasBody bool   // the caller gave a body (DI3.5)
	add     bool   // the signature is added (DI3.1)
}

// prepareOwn runs the checks of DI3.2 on the own text and the caller
// HTML of m, and gives O. With no body and an html field, O is the
// text view of that HTML (DI3.4). The exact-copy cut never runs on
// text from HTML, so the text and HTML parts agree.
//
// arch: DI3.1, DI3.2, DI3.4
func prepareOwn(m *mail.Outgoing, id config.Identity, in DraftIn) (ownBody, error) {
	sig := id.Signature
	out := ownBody{text: m.Text, hasBody: m.Text != "", add: sig != "" && sigFlag(id, in)}
	if sig != "" && m.HTML != "" {
		if err := checkOwn(mime.HTMLToText(m.HTML), sig); err != nil {
			return ownBody{}, err
		}
	}
	if out.hasBody {
		if sig != "" {
			// With no signature to add, a cut would drop model text
			// with no sign. The exact copy is refused instead (L1).
			if _, copied := cutCopy(strings.ReplaceAll(out.text, "\r\n", "\n"), sig); copied && !out.add {
				return ownBody{}, errSignatureInBody
			}
			text, err := cleanOwn(out.text, sig)
			if err != nil {
				return ownBody{}, err
			}
			out.text = text
		}
	} else if m.HTML != "" {
		out.text = mime.HTMLToText(m.HTML)
	}
	return out, nil
}

// placeSignature sets the text part and the HTML part of m in identity
// mode. block is the quote of a reply ("" when the quote is off) or
// the forward block (DI3.3). The text part:
//
//	new, reply with the quote off:      O, S
//	reply, ReplyAboveQuote, !SigBelow:  O, S, Q
//	reply, ReplyAboveQuote, SigBelow:   O, Q, S
//	reply, !ReplyAboveQuote:            Q, O, S
//	forward:                            O, S, F
//
// S is "-- \n" + Signature when own.add is true. An HTML part exists
// when the caller gave html, or when ComposeHTML is true and the
// caller gave a body. It is the caller HTML, or O as HTML, plus the
// HTML signature. It has no quote and no forward block (DI3.5).
//
// arch: DI3.3, DI3.5, I1, I10
func placeSignature(m *mail.Outgoing, id config.Identity, in DraftIn, own ownBody, block string) error {
	s := ""
	if own.add {
		s = sigDelimiter + id.Signature
	}
	o := own.text
	switch {
	case in.ReplyToID != "" && block != "" && !id.ReplyAboveQuote:
		m.Text = joinParts(block, o, s)
	case in.ReplyToID != "" && block != "" && id.SignatureBelowQuote:
		m.Text = joinParts(o, block, s)
	default:
		m.Text = joinParts(o, s, block)
	}

	if m.HTML == "" && (!id.ComposeHTML || !own.hasBody) {
		return nil
	}
	h := m.HTML
	if h == "" {
		h = textToHTML(o)
	}
	if own.add {
		sh := id.SignatureHTML
		if sh == "" {
			sh = textToHTML(id.Signature)
		}
		h += htmlDelimiter + sh
	}
	if clean, _ := mime.AllowHTML(h); clean != h {
		return errComposedHTML
	}
	if _, nested := mime.HTMLToTextCount(h); nested > 0 {
		return errComposedHTML
	}
	m.HTML = h
	return nil
}
