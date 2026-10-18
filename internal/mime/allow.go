// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

// allowTags names the elements that stay in the output of
// [AllowHTML] (D5.5 rule 1).
var allowTags = map[string]bool{
	"p": true, "br": true, "b": true, "strong": true, "i": true,
	"em": true, "u": true, "ul": true, "ol": true, "li": true,
	"blockquote": true, "a": true,
}

// dropTags names the elements that [AllowHTML] removes with their
// content (D5.5 rule 3).
var dropTags = map[string]bool{
	"script": true, "style": true, "head": true, "title": true,
	"template": true, "iframe": true, "object": true, "embed": true,
	"svg": true, "math": true, "noscript": true,
}

// hrefSchemes names the schemes that an href of an a element can
// have (D5.5 rule 2).
var hrefSchemes = map[string]bool{"http": true, "https": true, "mailto": true}

// textEscaper escapes the three characters that can start markup or
// a character reference in text.
var textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// AllowHTML returns src cut to the allowlist and the count of elements
// and attributes that it removed (D5.5). The rules:
//
//  1. The elements p, br, b, strong, i, em, u, ul, ol, li, blockquote
//     and a stay.
//  2. The only attribute that stays is href on a, with the scheme http,
//     https or mailto. An a with a different href keeps its text and
//     loses the href.
//  3. script, style, head, title, template, iframe, object, embed,
//     svg, math and noscript go with their content.
//  4. Every other element goes, and its text stays.
//  5. Comments go.
//
// A doctype also goes and counts as removed. A removed element counts
// once, with its attributes and its content. The output holds no
// style and no URL other than an href, so a text view of the output
// shows all of its content. That is the rule that the send
// confirmation needs (I8).
//
// The output is safe whatever the input is: every tag in it is one
// that this function wrote. A parse of the input that is different
// from the parse of a browser can only change which text stays.
//
// A second pass over the output removes nothing.
//
// arch: D5.5, D5.2
func AllowHTML(src string) (clean string, removed int) {
	z := html.NewTokenizer(strings.NewReader(src))
	var b strings.Builder
	skip := 0 // depth inside elements of rule 3
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return b.String(), removed

		case html.CommentToken, html.DoctypeToken:
			removed++

		case html.TextToken:
			if skip == 0 {
				b.WriteString(textEscaper.Replace(string(z.Text())))
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			tag := tok.Data
			if dropTags[tag] {
				if skip == 0 {
					removed++
				}
				// embed is a void element: it has no end tag.
				if tt == html.StartTagToken && tag != "embed" {
					skip++
				}
				continue
			}
			if skip > 0 {
				continue
			}
			if !allowTags[tag] {
				removed++
				continue
			}
			b.WriteByte('<')
			b.WriteString(tag)
			kept := false // a browser reads the first href only
			for _, a := range tok.Attr {
				if tag == "a" && !kept && a.Key == "href" && allowedHref(a.Val) {
					kept = true
					b.WriteString(` href="`)
					b.WriteString(html.EscapeString(a.Val))
					b.WriteByte('"')
					continue
				}
				removed++
			}
			b.WriteByte('>')

		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if dropTags[tag] {
				if skip > 0 {
					skip--
				}
				continue
			}
			if skip > 0 || !allowTags[tag] {
				continue
			}
			if tag == "br" {
				// A browser reads </br> as <br>.
				b.WriteString("<br>")
				continue
			}
			b.WriteString("</" + tag + ">")
		}
	}
}

// allowedHref reports whether v is an href that rule 2 of D5.5 keeps:
// the scheme is http, https or mailto. A value with a control
// character or with space at an end is refused, because a browser
// removes those characters before it reads the scheme, so the value
// that the summary shows is not the target. A value with a bidi
// control character or a zero-width character is refused too (DRV.13):
// either can make the text of a link read as one target while a
// browser opens another.
func allowedHref(v string) bool {
	if v == "" || strings.TrimSpace(v) != v {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f || isBidiOrZeroWidth(r) {
			return false
		}
	}
	i := strings.IndexByte(v, ':')
	if i <= 0 {
		return false
	}
	return hrefSchemes[strings.ToLower(v[:i])]
}

// isBidiOrZeroWidth reports whether r is a Unicode bidi control
// character or a zero-width character (DRV.13). It refuses each rune
// of the Unicode format class (Cf). That class holds every bidi control
// (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) and the
// zero-width and invisible characters (U+00AD, U+180E, U+200B to
// U+200D, U+2060 to U+2064, U+FEFF). A short list of code points misses
// some of them.
func isBidiOrZeroWidth(r rune) bool {
	return unicode.Is(unicode.Cf, r)
}

// HTMLLinks gives the href of each a element in src, in source order.
// The send confirmation lists them (D5.5). src is the output of
// [AllowHTML], so each href is a target that the recipient can open.
//
// arch: D5.5, D5.2
func HTMLLinks(src string) []string {
	z := html.NewTokenizer(strings.NewReader(src))
	var out []string
	for {
		switch z.Next() {
		case html.ErrorToken:
			return out
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			if tok.Data != "a" {
				continue
			}
			for _, a := range tok.Attr {
				if a.Key == "href" {
					out = append(out, a.Val)
				}
			}
		}
	}
}
