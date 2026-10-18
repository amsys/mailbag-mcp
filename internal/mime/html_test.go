// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

// TestHTMLToText_DropsHiddenText: a sender can put text in HTML that
// the human never sees. display:none, the hidden attribute,
// visibility:hidden, font size 0, text in the color of its background
// and comments hide it. HTMLToText must drop that text, because the
// model reads it and the human does not. Text that the human can see
// must stay: white text on a dark cell, a font-size:0 wrapper whose
// child sets a size again, and visibility:visible inside a hidden
// parent.
//
// arch: D4.1
func TestHTMLToText_DropsHiddenText(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"display none", `<p>Hi</p><div style="display:none">SECRET</div><p>Bye</p>`, "Hi\nBye"},
		{"display none spaced upper case", `<span style="DISPLAY : None !important">SECRET</span>ok`, "ok"},
		{"display none nested", `<div style="display:none"><p>SECRET <b>MORE</b></p></div>ok`, "ok"},
		{"display none child cannot undo", `<div style="display:none"><span style="display:block">SECRET</span></div>ok`, "ok"},
		{"hidden attribute", `<span hidden>SECRET</span>ok`, "ok"},
		{"visibility hidden", `<span style="visibility:hidden">SECRET</span>ok`, "ok"},
		{"visibility restored", `<div style="visibility:hidden">SECRET<span style="visibility:visible">shown</span></div>`, "shown"},
		{"font size 0", `<span style="font-size:0">SECRET</span>ok`, "ok"},
		{"font size 0px", `<span style="font-size: 0px">SECRET</span>ok`, "ok"},
		{"font size 0 em child", `<div style="font-size:0pt"><span style="font-size:2em">SECRET</span></div>ok`, "ok"},
		{"font size 0 wrapper resized", `<div style="font-size:0"><span style="font-size:14px">shown</span></div>`, "shown"},
		{"white on default", `<span style="color:#ffffff">SECRET</span>ok`, "ok"},
		{"white named", `<span style="color:White">SECRET</span>ok`, "ok"},
		{"white short hex", `<span style="color:#fff">SECRET</span>ok`, "ok"},
		{"white rgb", `<span style="color:rgb(255, 255, 255)">SECRET</span>ok`, "ok"},
		{"near white", `<span style="color:#fefefe">SECRET</span>ok`, "ok"},
		{"white on white bg", `<td bgcolor="#FFFFFF"><font color="white">SECRET</font></td>ok`, "ok"},
		{"black on black", `<div style="background-color:#000"><span style="color:black">SECRET</span></div>ok`, "ok"},
		{"white on dark cell", `<table><tr><td bgcolor="#003366"><a href="https://x.test/" style="color:#ffffff">Click</a></td></tr></table>`, "Click <https://x.test/>"},
		{"white on dark shorthand", `<div style="background:#123456 url(x.png)"><span style="color:#fff">shown</span></div>`, "shown"},
		{"hidden link drops url", `<div style="display:none"><a href="https://evil.test/">SECRET</a></div>ok`, "ok"},
		{"comment", `ok<!-- SECRET -->`, "ok"},
		{"conditional comment", `<!--[if mso]>SECRET<![endif]-->ok`, "ok"},

		// The probes of FAIL-T79.md: valid CSS forms of the rules above.
		{"css comment before property", `<span style="/*x*/display:none">SECRET</span>ok`, "ok"},
		{"css comment in value", `<span style="display:/**/none">SECRET</span>ok`, "ok"},
		{"css open comment", `<span style="color:red;display:none/* x">SECRET</span>ok`, "ok"},
		{"css escape in property", `<span style="disp\lay:none">SECRET</span>ok`, "ok"},
		{"css escape in color", `<span style="color:w\hite">SECRET</span>ok`, "ok"},
		{"css hex escape", `<span style="\64 isplay:\6e one">SECRET</span>ok`, "ok"},
		{"important with space", `<span style="display:none ! important">SECRET</span>ok`, "ok"},
		{"important wins over later", `<span style="color:white !important;color:black">SECRET</span>ok`, "ok"},
		{"font shorthand 0", `<span style="font:0/0 a">SECRET</span>ok`, "ok"},
		{"font shorthand weight then 0", `<span style="font:italic bold 0px Arial,sans-serif">SECRET</span>ok`, "ok"},
		{"font size calc 0", `<span style="font-size:calc(0px)">SECRET</span>ok`, "ok"},
		{"font size calc to 0", `<span style="font-size:calc(10px * 0 + 1px - 1px)">SECRET</span>ok`, "ok"},
		{"font size inherit in 0", `<div style="font-size:0"><span style="font-size:inherit">SECRET</span></div>ok`, "ok"},
		{"font size larger in 0", `<div style="font-size:0"><span style="font-size:larger">SECRET</span></div>ok`, "ok"},
		{"white rgb percent", `<span style="color:rgb(100%,100%,100%)">SECRET</span>ok`, "ok"},
		{"white hsl", `<span style="color:hsl(0,0%,100%)">SECRET</span>ok`, "ok"},
		{"white hsl turn", `<span style="color:hsl(0.5turn 0% 100%)">SECRET</span>ok`, "ok"},
		{"near white snow", `<span style="color:snow">SECRET</span>ok`, "ok"},
		{"near white ghostwhite", `<span style="color:ghostwhite">SECRET</span>ok`, "ok"},
		{"low alpha", `<span style="color:rgba(0,0,0,0.01)">SECRET</span>ok`, "ok"},
		{"low alpha percent", `<span style="color:rgb(0 0 0 / 5%)">SECRET</span>ok`, "ok"},
		{"low alpha hex", `<span style="color:#00000008">SECRET</span>ok`, "ok"},
		{"body text attribute", `<body text="white">SECRET</body>`, ""},
		{"body text on bgcolor", `<body text="#000000" bgcolor="black">SECRET</body>`, ""},

		// A browser drops a declaration that is not valid and keeps the
		// earlier value. The check must not reset it.
		{"empty font size keeps 0", `<span style="font-size:0;font-size:">SECRET</span>ok`, "ok"},
		{"font shorthand with no size keeps 0", `<span style="font-size:0;font:bold">SECRET</span>ok`, "ok"},
		{"font shorthand with no family keeps 0", `<div style="font-size:0"><span style="font:14px">SECRET</span></div>ok`, "ok"},
		{"font shorthand line height no family", `<div style="font-size:0"><span style="font:14px / 1.2">SECRET</span></div>ok`, "ok"},
		{"empty color keeps white", `<span style="color:white;color:">SECRET</span>ok`, "ok"},
		{"empty important color keeps white", `<span style="color:white;color:!important">SECRET</span>ok`, "ok"},
		{"empty important color does not block", `<span style="color:white;color:!important;color:black">shown</span>`, "shown"},
		{"empty background keeps black", `<div style="color:#000;background-color:#000;background-color:">SECRET</div>ok`, "ok"},
		{"bad background shorthand", `<div style="color:#000;background:#000;background:foo">SECRET</div>ok`, "ok"},
		{"bad background color", `<div style="color:#000;background-color:#000;background-color:bar">SECRET</div>ok`, "ok"},
		{"background variable", `<div style="--bg:#000;background-color:var(--bg);color:#000">SECRET</div>ok`, "ok"},
		{"display variable", `<div style="--d:none;display:var(--d)">SECRET</div>ok`, "ok"},
		{"visibility env", `<div style="visibility:env(x, hidden)">SECRET</div>ok`, "ok"},

		// Lengths that CSS does not accept do not undo font-size:0.
		{"calc of number", `<div style="font-size:0"><span style="font-size:calc(14)">SECRET</span></div>ok`, "ok"},
		{"calc length plus number", `<div style="font-size:0"><span style="font-size:calc(14px + 0)">SECRET</span></div>ok`, "ok"},
		{"calc plus with no space", `<div style="font-size:0"><span style="font-size:calc(14px+0px)">SECRET</span></div>ok`, "ok"},
		{"calc length times length", `<div style="font-size:0"><span style="font-size:calc(2px * 7px)">SECRET</span></div>ok`, "ok"},
		{"sum outside calc", `<div style="font-size:0"><span style="font-size:7px + 7px">SECRET</span></div>ok`, "ok"},
		{"brackets outside calc", `<div style="font-size:0"><span style="font-size:(14px)">SECRET</span></div>ok`, "ok"},
		{"dot with no fraction", `<div style="font-size:0"><span style="font-size:14.px">SECRET</span></div>ok`, "ok"},
		{"no unit in standards mode", `<!DOCTYPE html><div style="font-size:0"><span style="font-size:14">SECRET</span></div>ok`, "ok"},
		{"tiny font size", `<span style="font-size:0.01px">SECRET</span>ok`, "ok"},
		{"tiny relative font size", `<span style="font-size:0.01em">SECRET</span>ok`, "ok"},

		// Color forms that CSS does not accept.
		{"hashless hex in standards mode", `<!DOCTYPE html><div style="color:#fff"><span style="color:000000">SECRET</span></div>ok`, "ok"},
		{"rgb empty part", `<div style="color:#fff"><span style="color:rgb(0,,0,0)">SECRET</span></div>ok`, "ok"},
		{"rgb space form 4 parts", `<div style="color:#fff"><span style="color:rgb(0 0 0 1)">SECRET</span></div>ok`, "ok"},
		{"rgb mixed separators", `<div style="color:#fff"><span style="color:rgb(0 0, 0)">SECRET</span></div>ok`, "ok"},
		{"rgb comma form mixed percent", `<div style="color:#fff"><span style="color:rgb(0%,0,0)">SECRET</span></div>ok`, "ok"},
		{"hsl comma form no percent", `<div style="color:#fff"><span style="color:hsl(0,0,0)">SECRET</span></div>ok`, "ok"},
		{"rgb hex float", `<div style="color:#fff"><span style="color:rgb(0x0p0 0 0)">SECRET</span></div>ok`, "ok"},
		{"preheader", `<body><div style="display:none;max-height:0">SECRET preheader</div><p>Body</p></body>`, "Body"},
		{"hidden ends at close", `<span style="display:none">SECRET</span><span>after</span>`, "after"},
		{"sibling p not hidden", `<p style="display:none">SECRET<p>after`, "after"},
		{"void inside hidden", `<div style="display:none">SECRET<br><img src="x">MORE</div>ok`, "ok"},
		{"kept format tag leaves hidden parent", `<span style="display:none"><b>SECRET</span>after</b>`, "after"},
		{"transparent text", `<span style="color:transparent">SECRET</span>ok`, "ok"},
		{"alpha 0 text", `<span style="color:rgba(0,0,0,0)">SECRET</span>ok`, "ok"},
		{"template content", `<template>SECRET</template>ok`, "ok"},
		{"self-closing div still opens", `<div style="display:none"/>SECRET</div>ok`, "ok"},

		// The stack must repair malformed markup as a browser does. Each
		// input below gave SECRET before the fix: the check closed or
		// kept an element that the browser does not.
		{"stray end tag stops at special", `<span style="display:none"><div></span>SECRET</div>`, ""},
		{"formatting end tag stops at cell", `<b style="display:none"><table><td></b>SECRET`, ""},
		{"formatting in cell not reopened after table", `<div style="color:#fff"><table><tr><td><b style="color:#000"></td></tr></table>SECRET</div>`, ""},
		{"li does not close past section", `<li style="display:none"><section><li>SECRET`, ""},
		{"text in table is foster-parented", `<div style="color:#fff"><table style="background:#000">SECRET</table></div>`, ""},
		{"end body does not close", `<body><div style="display:none"></body>SECRET`, ""},
		{"cell with no table is ignored", `<div style="color:#fff"><td bgcolor="#000">SECRET</td></div>`, ""},
		{"formatting end tag with no block pops span", `<div style="color:#fff"><b><span style="color:#000"></b>SECRET</span></div>`, ""},
		{"formatting reopened after table", `<table><b style="display:none"><tr><td>x</td></tr></table>SECRET`, "x"},
		{"later body style applies", `<body><body style="color:#fff">SECRET`, ""},
		{"heading closes heading", `<div style="color:#fff"><h1 style="color:#000"><h2>SECRET</h2></div>`, ""},
		{"late body style applies to text before it", `SECRET<body style="color:#fff">`, ""},
		{"end tag moves text under a later formatting copy", `<span style="color:#fff"><font color="white"><em style="color:#000"><p>SECRET</font></p></em></span>`, ""},
		{"end form leaves inner elements open", `<form><span style="display:none"></form>SECRET`, ""},
		{"end table keeps object marker", `<div style="color:#fff"><table><b style="color:#000"><object></table>SECRET</div>`, ""},
		{"caption close opens formatting again", `<table><b style="display:none"><caption>x</caption><tbody>SECRET`, "x"},
		{"late doctype keeps quirks", `<p style="display:none"><!DOCTYPE html><table><tr><td>SECRET</td></tr></table>`, ""},
		{"implied tr closes cell", `<div style="color:#fff"><table><td bgcolor="#000"></tr><span>SECRET</span></table></div>`, ""},

		// Repair that shows text must show it too.
		{"formatting end tag moves block out", `<b style="display:none">SECRET<div></b>shown</div>`, "shown"},
		{"formatting end tag with no block", `<span style="display:none"><b></span>shown</b>`, "shown"},
		{"end div closes hidden span", `<div><span style="display:none">SECRET</div>shown`, "shown"},
		{"new li closes hidden li", `<ul><li style="display:none">SECRET<li>shown</ul>`, "shown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HTMLToText(c.in); got != c.want {
				t.Errorf("HTMLToText(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestHTMLToText_UnparsedColorFailsClosed: a text color that the check
// cannot read could be any color, white on white too. The owner chose
// fail closed: the text counts as hidden. A font size that the check
// cannot compute is hidden for the same reason.
//
// arch: D4.1
func TestHTMLToText_UnparsedColorFailsClosed(t *testing.T) {
	cases := []struct{ name, style string }{
		{"unknown name", "color:whiteish"},
		{"css variable", "color:var(--fg)"},
		{"bad hex", "color:#12345"},
		{"short rgb", "color:rgb(1,2)"},
		{"lab", "color:lab(100 0 0)"},
		{"oklch", "color:oklch(1 0 0)"},
		{"color-mix", "color:color-mix(in srgb, white 90%, black)"},
		{"font size variable", "font-size:var(--s)"},
		{"font size bad unit", "font-size:12foo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := `<span style="` + c.style + `">SECRET</span>ok`
			if got := HTMLToText(in); got != "ok" {
				t.Errorf("HTMLToText(%q) = %q, want %q", in, got, "ok")
			}
		})
	}
}

// TestHTMLToText_NamedColorsStayVisible: fail closed must not hide text
// that the human can see. Every named color, the percent and hsl forms
// and the legacy color attributes are read, so dark text on the white
// page stays.
//
// arch: D4.1
func TestHTMLToText_NamedColorsStayVisible(t *testing.T) {
	cases := []struct{ name, in string }{
		{"navy", `<span style="color:navy">shown</span>`},
		{"navy upper case important", `<span style="COLOR: Navy ! important">shown</span>`},
		{"rebeccapurple", `<span style="color:rebeccapurple">shown</span>`},
		{"darkslategrey", `<span style="color:darkslategrey">shown</span>`},
		{"rgb percent", `<span style="color:rgb(0%, 0%, 50%)">shown</span>`},
		{"hsl", `<span style="color:hsl(240deg 100% 25%)">shown</span>`},
		{"hsla", `<span style="color:hsla(0, 100%, 40%, 0.9)">shown</span>`},
		{"hashless hex", `<span style="color:333333">shown</span>`},
		{"initial", `<div style="color:white"><span style="color:initial">shown</span></div>`},
		{"inherit navy", `<div style="color:navy"><span style="color:inherit">shown</span></div>`},
		{"white on navy", `<div style="background-color:navy"><span style="color:white">shown</span></div>`},
		{"font color hashless", `<font color="0000ff">shown</font>`},
		{"font color legacy word", `<font color="chucknorris">shown</font>`},
		{"body text navy", `<body text="navy">shown</body>`},
		{"font shorthand", `<div style="font-size:0"><span style="font:bold 14px/1.4 Arial">shown</span></div>`},
		{"font size clamp", `<span style="font-size:clamp(12px, 2vw, 18px)">shown</span>`},
		{"no unit in quirks mode", `<div style="font-size:0"><span style="font-size:14">shown</span></div>`},
		{"font shorthand spaced line height", `<div style="font-size:0"><span style="font:14px / 1.2 Arial">shown</span></div>`},
		{"calc em plus px", `<div style="font-size:0"><span style="font-size:calc(1rem + 2px)">shown</span></div>`},
		{"calc with brackets", `<div style="font-size:0"><span style="font-size:calc((7px + 7px) * 1)">shown</span></div>`},
		{"exponent", `<div style="font-size:0"><span style="font-size:1.4e1px">shown</span></div>`},
		{"empty color keeps navy", `<span style="color:navy;color:">shown</span>`},
		{"rgb space form alpha", `<span style="color:rgb(0 0 128 / 0.9)">shown</span>`},
		{"rgb none", `<span style="color:rgb(none 0 128)">shown</span>`},
		{"background shorthand words", `<div style="background:#fff no-repeat center / cover"><span style="color:#000">shown</span></div>`},
		{"background none", `<div style="background-color:#000"><div style="background:none"><span style="color:#000">x</span></div><span style="color:#fff">shown</span></div>`},
		{"escaped semicolon in string", `<span style="font-family:'a;display:none'">shown</span>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HTMLToText(c.in); got != "shown" {
				t.Errorf("HTMLToText(%q) = %q, want %q", c.in, got, "shown")
			}
		})
	}
}

// TestHTMLToText_DeepNestingBounded: any sender controls the markup, so
// the hidden-text check must not let a body cost more than linear
// time. A stack of open elements with stray end tags made each tag
// scan the whole stack. Past maxStackDepth open elements the rest of
// the body counts as hidden, so that a deep stack never hides a
// visible style from the check.
//
// arch: D4.1
func TestHTMLToText_DeepNestingBounded(t *testing.T) {
	t.Run("fails closed past the limit", func(t *testing.T) {
		in := "before" + strings.Repeat("<div>", maxStackDepth+1) + "SECRET"
		if got := HTMLToText(in); got != "before" {
			t.Errorf("HTMLToText(deep) = %q, want %q", got, "before")
		}
	})
	t.Run("at the limit text stays", func(t *testing.T) {
		in := strings.Repeat("<div>", maxStackDepth) + "shown"
		if got := HTMLToText(in); got != "shown" {
			t.Errorf("HTMLToText(at limit) = %q, want %q", got, "shown")
		}
	})
	t.Run("many closed formatting elements is fast", func(t *testing.T) {
		// The list of active formatting elements can grow with no
		// growth of the stack. Each end tag of a formatting element
		// reads the list, so the list has the same limit.
		in := strings.Repeat("<div><b></div>", 40000) + strings.Repeat("</i>", 100000)
		start := time.Now()
		HTMLToText(in)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("HTMLToText(formatting list) took %v, want under 5s", d)
		}
	})
	t.Run("1 MB of stray end tags is fast", func(t *testing.T) {
		// Before the fix, 640 KB of this shape took 24 s. Now 1 MB
		// takes well under 1 s. The bound is loose for slow runners.
		// raceFactor widens it under -race, where the detector adds
		// overhead that can push a plain-run pass past 5s. arch: DRV.20.2
		// With -race, go test counts coverage with atomic adds, and the
		// detector checks each one. On 2026-10-14 this case took 4.4 s
		// with -race and 24.6 s with -race -coverprofile (CI runs the
		// second, T285). The quadratic shape is still far above 160 s.
		in := strings.Repeat("<b>", maxStackDepth-1) + strings.Repeat("</i>x", 200000)
		start := time.Now()
		HTMLToText(in)
		bound := 5 * time.Second * raceFactor
		if raceFactor > 1 && testing.CoverMode() == "atomic" {
			bound *= 8
		}
		if d := time.Since(start); d > bound {
			t.Errorf("HTMLToText(1 MB) took %v, want under %v", d, bound)
		}
	})
}

// TestHTMLToText_NoLeakAgainstTreeBuilder: the hidden-text check builds
// the document tree itself (html.Parse is quadratic on some bodies). A
// sender can use any rule of the HTML5 tree builder that the check
// does not copy, and make text that the human does not see reach the
// model. This test builds random malformed bodies and compares the
// check with html.Parse, with the same style rules on its tree. No word
// that is hidden in the html.Parse tree may reach the output. The
// check can hide more (fail closed). <th> is not in the vocabulary:
// html.Parse keeps a <th> in a <caption>, but the HTML5 rule closes
// the caption, as the check does.
//
// arch: D4.1
func TestHTMLToText_NoLeakAgainstTreeBuilder(t *testing.T) {
	voc := []string{
		"<b>", "</b>", `<i style="display:none">`, "</i>", "<a href=x>", "</a>",
		"<div>", "</div>", "<p>", "</p>", `<span style="color:#fff">`, "</span>",
		"<table>", "</table>", "<tr>", "</tr>", "<td bgcolor=#000>", "</td>",
		"<tbody>", "</tbody>", "<caption>", "</caption>", "<li>", "</li>",
		"<ul>", "</ul>", "<dd>", "<dt>", "<h1>", "</h2>",
		`<body style="color:#fff">`, "</body>", "<nobr>", "</nobr>",
		"<button>", "</button>", "<object>", "</object>", "<div/>", "<br>",
		"</br>", "<hr>", "<font color=white>", "</font>", "<section>",
		`<u style="background:#fff">`, "</u>", `<em style="color:#000">`, "</em>",
		`<div style="display:none">`, `<span style="visibility:hidden">`,
		`<s style="visibility:visible">`, "<!DOCTYPE html>", "<select>",
		"</select>", "<option>", "<template>", "</template>", "<applet>",
		"</applet>", "<marquee>", "</marquee>", `<h3 style="font-size:0">`,
		"</h3>", "<form>", "</form>", "<thead>", "</thead>", "<center>",
	}
	r := rand.New(rand.NewSource(79)) //nolint:gosec // G404: a fixed seed makes the test repeat the same input
	for n := 0; n < 20000; n++ {
		var b strings.Builder
		w := 0
		for j := r.Intn(25); j >= 0; j-- {
			if r.Intn(3) == 0 {
				fmt.Fprintf(&b, " W%d ", w)
				w++
			} else {
				b.WriteString(voc[r.Intn(len(voc))])
			}
		}
		fmt.Fprintf(&b, " W%d ", w)
		src := b.String()
		visible := treeBuilderVisible(t, src)
		for _, word := range strings.Fields(HTMLToText(src)) {
			if strings.HasPrefix(word, "W") && !visible[word] {
				t.Fatalf("HTMLToText(%q) shows %s, hidden in the html.Parse tree", src, word)
			}
		}
	}
}

// treeBuilderVisible gives the words of src that are visible in the
// tree of html.Parse, with the style rules of HTMLToText.
func treeBuilderVisible(t *testing.T, src string) map[string]bool {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("html.Parse(%q): %v", src, err)
	}
	out := map[string]bool{}
	var walk func(n *html.Node, st state)
	walk = func(n *html.Node, st state) {
		switch n.Type {
		case html.ElementNode:
			if skipTags[n.Data] || n.Data == "head" {
				return
			}
			f := parseFrame(n.Data, n.Attr, true)
			st = f.apply(st)
		case html.TextNode:
			if !st.hides() {
				for _, w := range strings.Fields(n.Data) {
					out[w] = true
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, st)
		}
	}
	walk(doc, rootState)
	return out
}

// TestHTMLToText_SystemColorsAndBackgroundImageVisible is R1D-judge.md
// finding 2: the check removed text that the human sees. A CSS system
// color such as windowtext (Outlook writes it) is the page text color,
// so the text stays. A background image makes the background unknown,
// so white text on it stays. A text color that the check cannot read
// still hides the text (owner decision).
//
// arch: D4.1, D4.2
func TestHTMLToText_SystemColorsAndBackgroundImageVisible(t *testing.T) {
	visible := []struct{ name, in string }{
		{"windowtext", `<span style="font-size:11pt;color:windowtext">shown</span>`},
		{"canvastext", `<span style="color:CanvasText">shown</span>`},
		{"linktext important", `<span style="color:linktext !important">shown</span>`},
		{"graytext", `<span style="color:graytext">shown</span>`},
		{"windowtext under white text", `<div style="color:white"><span style="color:windowtext">shown</span></div>`},
		{"background color window", `<div style="background-color:window"><span style="color:#fff">shown</span></div>`},
		{"background shorthand window", `<div style="background:window"><span style="color:#fff">shown</span></div>`},
		{"background image url", `<div style="background-image:url(dark.png)"><span style="color:#fff">shown</span></div>`},
		{"background image over white color", `<div style="background-color:#fff;background-image:url(dark.png)"><span style="color:#fff">shown</span></div>`},
		{"background image before white color", `<div style="background-image:url(dark.png);background-color:#fff"><span style="color:#fff">shown</span></div>`},
		{"background image gradient", `<table><tr><td style="background-image:linear-gradient(#000,#333)"><span style="color:white">shown</span></td></tr></table>`},
	}
	for _, c := range visible {
		t.Run(c.name, func(t *testing.T) {
			if got := HTMLToText(c.in); got != "shown" {
				t.Errorf("HTMLToText(%q) = %q, want %q", c.in, got, "shown")
			}
		})
	}

	hidden := []struct{ name, in string }{
		{"background image none", `<div style="background-image:none"><span style="color:#fff">SECRET</span></div>ok`},
		{"shorthand resets image", `<div style="background-image:url(x.png);background:#fff"><span style="color:#fff">SECRET</span></div>ok`},
		{"child white background over image", `<div style="background-image:url(x.png)"><div style="background-color:#fff"><span style="color:#fff">SECRET</span></div></div>ok`},
		{"unparsed text color", `<span style="color:-webkit-link">SECRET</span>ok`},
		{"invalid hex", `<span style="color:#12345">SECRET</span>ok`},
	}
	for _, c := range hidden {
		t.Run(c.name, func(t *testing.T) {
			if got := HTMLToText(c.in); got != "ok" {
				t.Errorf("HTMLToText(%q) = %q, want %q", c.in, got, "ok")
			}
		})
	}
}

// TestHTMLToText_OpacityAndMsoHide is R1D-judge.md finding 4:
// opacity:0 and mso-hide:all hide text from the human, so the model
// must not get it. A child cannot show text again under opacity:0. A
// child with mso-hide:none shows text again. Opacity that is not 0
// keeps the text.
//
// arch: D4.1, D4.2
func TestHTMLToText_OpacityAndMsoHide(t *testing.T) {
	hidden := []struct{ name, in string }{
		{"opacity 0", `<span style="opacity:0">SECRET</span>ok`},
		{"opacity 0.0 spaced", `<span style="opacity : 0.0">SECRET</span>ok`},
		{"opacity percent", `<span style="opacity:0%">SECRET</span>ok`},
		{"opacity negative", `<span style="opacity:-1">SECRET</span>ok`},
		{"opacity small", `<span style="opacity:.05">SECRET</span>ok`},
		{"opacity product", `<div style="opacity:.3"><span style="opacity:.3">SECRET</span></div>ok`},
		{"opacity 0 child opacity 1", `<div style="opacity:0"><span style="opacity:1">SECRET</span></div>ok`},
		{"opacity important wins", `<span style="opacity:0 !important;opacity:1">SECRET</span>ok`},
		{"mso-hide all", `<div style="mso-hide:all">SECRET</div>ok`},
		{"mso-hide all upper case", `<div style="MSO-HIDE: ALL">SECRET</div>ok`},
		{"mso-hide all inherited", `<table style="mso-hide:all"><tr><td><span>SECRET</span></td></tr></table>ok`},
	}
	for _, c := range hidden {
		t.Run(c.name, func(t *testing.T) {
			if got := HTMLToText(c.in); got != "ok" {
				t.Errorf("HTMLToText(%q) = %q, want %q", c.in, got, "ok")
			}
		})
	}

	visible := []struct{ name, in string }{
		{"opacity 1", `<span style="opacity:1">shown</span>`},
		{"opacity half", `<span style="opacity:0.5">shown</span>`},
		{"opacity 0 then 1", `<span style="opacity:0;opacity:1">shown</span>`},
		{"opacity not valid", `<span style="opacity:abc">shown</span>`},
		{"mso-hide none", `<span style="mso-hide:none">shown</span>`},
		{"mso-hide none in all", `<div style="mso-hide:all"><span style="mso-hide:none">shown</span></div>`},
	}
	for _, c := range visible {
		t.Run(c.name, func(t *testing.T) {
			if got := HTMLToText(c.in); got != "shown" {
				t.Errorf("HTMLToText(%q) = %q, want %q", c.in, got, "shown")
			}
		})
	}
}

// TestHTMLToText_Noscript: the tokenizer reads noscript as raw text,
// the same as script and style, so a sender can carry a payload inside
// it that no browser ever shows. neverRendered must drop it, the same
// as title.
//
// arch: DRV.13
func TestHTMLToText_Noscript(t *testing.T) {
	cases := []struct{ name, in string }{
		{"plain text", `<noscript>SECRET</noscript>ok`},
		{"markup-like text", `<noscript><img src="https://evil.example/p.gif">SECRET</noscript>ok`},
		{"in head", `<head><noscript>SECRET</noscript></head><body>ok</body>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HTMLToText(c.in); got != "ok" {
				t.Errorf("HTMLToText(%q) = %q, want %q", c.in, got, "ok")
			}
		})
	}
}

// TestHTMLToText_TextInOpenHead: the first character of text that is
// not a space ends the head, even with no closing tag and no other
// tag to end it, the way an HTML5 browser reprocesses it in the body.
// Text inside a head element (title, noscript, style, script) is that
// element's own content, not loose head text, so it stays out.
//
// arch: DRV.13
func TestHTMLToText_TextInOpenHead(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"loose text after meta", `<head><meta charset="utf-8">leaked text</head><body><p>ok</p></body>`, "leaked text\nok"},
		{"title text stays out", `<head><title>SECRET</title><meta charset="utf-8"></head><body><p>ok</p></body>`, "ok"},
		{"noscript text stays out", `<head><noscript>SECRET</noscript>leaked<meta></head><body><p>ok</p></body>`, "leaked\nok"},
		{"style text stays out", `<head><style>.a{color:red}</style>leaked</head><body><p>ok</p></body>`, "leaked\nok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HTMLToText(c.in); got != c.want {
				t.Errorf("HTMLToText(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestHTMLToText_HiddenStyles: DRV.13 adds content-visibility:hidden,
// -webkit-text-fill-color:transparent, filter:opacity(0), a font size
// of 1px or less, and a zero-size svg to the hidden-text check of
// D4.1. Each hides text that would otherwise reach the model, and a
// value just past the hiding threshold stays visible.
//
// arch: D4.1, DRV.13
func TestHTMLToText_HiddenStyles(t *testing.T) {
	hidden := []struct{ name, in string }{
		{"content-visibility hidden", `<span style="content-visibility:hidden">SECRET</span>ok`},
		{"webkit fill transparent over a visible color", `<span style="color:red;-webkit-text-fill-color:transparent">SECRET</span>ok`},
		{"filter opacity 0", `<span style="filter:opacity(0)">SECRET</span>ok`},
		{"filter opacity 0 percent", `<span style="filter:opacity(0%)">SECRET</span>ok`},
		{"opacity property then filter opacity compose to hidden", `<span style="opacity:0;filter:opacity(1)">SECRET</span>ok`},
		{"filter opacity then opacity property compose to hidden", `<span style="filter:opacity(1);opacity:0">SECRET</span>ok`},
		{"font size 1px", `<span style="font-size:1px">SECRET</span>ok`},
		{"svg width 0", `<svg width="0" height="50"><text>SECRET</text></svg>ok`},
		{"svg height 0", `<svg width="50" height="0"><text>SECRET</text></svg>ok`},
		{"svg width 0 percent", `<svg width="0%"><text>SECRET</text></svg>ok`},
		{"svg width 0em", `<svg width="0em"><text>SECRET</text></svg>ok`},
		{"svg style width 0", `<svg style="width:0"><text>SECRET</text></svg>ok`},
		{"webkit fill rgba alpha 0", `<span style="-webkit-text-fill-color:rgba(0,0,0,0)">SECRET</span>ok`},
		{"webkit fill hex alpha 0", `<span style="-webkit-text-fill-color:#0000">SECRET</span>ok`},
		{"webkit fill in the background color", `<div style="background-color:#fff"><span style="color:#000;-webkit-text-fill-color:#fff">SECRET</span></div>ok`},
		{"filter opacity 0 after opacity 1 in one list", `<span style="filter:opacity(1) opacity(0)">SECRET</span>ok`},
		{"filter opacity 0 survives an invalid later filter", `<span style="filter:opacity(0);filter:x">SECRET</span>ok`},
		{"filter opacity 0 survives an unknown filter function name", `<span style="filter:opacity(0);filter:foo(1)">SECRET</span>ok`},
		{"filter opacity 0 survives a non-function later filter", `<span style="filter:opacity(0);filter:1px">SECRET</span>ok`},
		{"webkit fill revert stays hidden under transparent", `<span style="-webkit-text-fill-color:transparent"><b style="-webkit-text-fill-color:revert">SECRET</b></span>ok`},
		{"webkit fill revert-layer stays hidden under transparent", `<span style="-webkit-text-fill-color:transparent"><b style="-webkit-text-fill-color:revert-layer">SECRET</b></span>ok`},
	}
	for _, c := range hidden {
		t.Run(c.name, func(t *testing.T) {
			if got, removed := HTMLToTextCount(c.in); got != "ok" || removed != 1 {
				t.Errorf("HTMLToTextCount(%q) = %q, %d; want %q, 1", c.in, got, removed, "ok")
			}
		})
	}

	visible := []struct{ name, in string }{
		{"content-visibility visible", `<span style="content-visibility:visible">shown</span>`},
		{"webkit fill not transparent", `<span style="-webkit-text-fill-color:blue">shown</span>`},
		{"filter opacity 1", `<span style="filter:opacity(1)">shown</span>`},
		{"opacity property and filter opacity both 1", `<span style="opacity:1;filter:opacity(1)">shown</span>`},
		{"filter blur only", `<span style="filter:blur(2px)">shown</span>`},
		{"font size 2px", `<span style="font-size:2px">shown</span>`},
		{"font size 1.5px", `<span style="font-size:1.5px">shown</span>`},
		{"a later filter with no opacity replaces filter opacity 0", `<span style="filter:opacity(0);filter:blur(1px)">shown</span>`},
		{"an invalid filter alone does not hide", `<span style="filter:not-a-function(1)">shown</span>`},
		{"webkit fill currentcolor after transparent", `<span style="-webkit-text-fill-color:transparent"><b style="-webkit-text-fill-color:currentcolor">shown</b></span>`},
		{"svg width 0 on a div", `<div width="0">shown</div>`},
		{"width 0 style on a span", `<span style="width:0">shown</span>`},
		{"svg no zero size", `<svg width="50" height="50"><text>shown</text></svg>`},
	}
	for _, c := range visible {
		t.Run(c.name, func(t *testing.T) {
			if got := HTMLToText(c.in); got != "shown" {
				t.Errorf("HTMLToText(%q) = %q, want %q", c.in, got, "shown")
			}
		})
	}
}

// TestHTMLToTextCount_CountsRemovedRuns: the model must know that part
// of a mail was not shown (D4.2). HTMLToTextCount gives the text of
// HTMLToText and the count of hidden text runs that it removed. A run
// of spaces only, a comment, script, style and head content do not
// count.
//
// arch: D4.1, D4.2
func TestHTMLToTextCount_CountsRemovedRuns(t *testing.T) {
	cases := []struct {
		name, in, want string
		removed        int
	}{
		{"none removed", `<p>Hi</p><p>Bye</p>`, "Hi\nBye", 0},
		{"one hidden", `<p>Hi</p><div style="display:none">SECRET</div>`, "Hi", 1},
		{"three runs in one element", `<div hidden>a<b>b</b>c</div>ok`, "ok", 3},
		{"each form", `<span style="opacity:0">1</span><span style="mso-hide:all">2</span>` +
			`<span style="color:#fff">3</span><span style="font-size:0">4</span>` +
			`<span style="color:oklch(1 0 0)">5</span>ok`, "ok", 5},
		{"spaces only not counted", `<div style="display:none">  <p> </p>
</div>ok`, "ok", 0},
		{"comment script style head not counted", `<head><title>T</title><style>.a{}</style></head>` +
			`<body><!-- SECRET --><script>x()</script>ok</body>`, "ok", 0},
		{"hidden link", `<a href="https://x.test" style="display:none">click</a>ok`, "ok", 1},
		{"visible system color", `<span style="color:windowtext">shown</span>`, "shown", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, removed := HTMLToTextCount(c.in)
			if got != c.want || removed != c.removed {
				t.Errorf("HTMLToTextCount(%q) = %q, %d; want %q, %d", c.in, got, removed, c.want, c.removed)
			}
			if plain := HTMLToText(c.in); plain != got {
				t.Errorf("HTMLToText(%q) = %q, HTMLToTextCount text = %q", c.in, plain, got)
			}
		})
	}
}

// TestHTMLToText_BgcolorOnSpanIgnored: a browser reads the bgcolor
// attribute only on body, table, thead, tbody, tfoot, tr, td, th and
// marquee. On another tag the attribute has no effect, so black text in
// a span with bgcolor=white on a black body is hidden. The text must
// not reach the model, and HTMLToTextCount must count it as removed. A
// td with bgcolor=white keeps the same text visible.
//
// arch: REVIEW-2026-10-12 H4, D4.1
func TestHTMLToText_BgcolorOnSpanIgnored(t *testing.T) {
	for _, tag := range []string{"span", "div", "p", "font"} {
		t.Run(tag, func(t *testing.T) {
			in := `<body bgcolor="black"><` + tag + ` bgcolor="white"><font color="black">SECRET</font></` +
				tag + `></body>`
			got, removed := HTMLToTextCount(in)
			if strings.Contains(got, "SECRET") || removed == 0 {
				t.Errorf("HTMLToTextCount(%q) = %q, %d; want no SECRET and removed > 0", in, got, removed)
			}
		})
	}
	t.Run("td keeps text visible", func(t *testing.T) {
		in := `<body bgcolor="black"><table><tr><td bgcolor="white"><font color="black">SECRET</font>` +
			`</td></tr></table></body>`
		got, removed := HTMLToTextCount(in)
		if got != "SECRET" || removed != 0 {
			t.Errorf("HTMLToTextCount(%q) = %q, %d; want %q, 0", in, got, removed, "SECRET")
		}
	})
}

// TestHTMLToText_NestedRelativeFontHidden: a relative font size (em,
// %, ex, ch, larger, smaller) is computed from the font size of the
// parent, so nested relative sizes multiply. Text at 1px or less is
// hidden: it must not reach the model, and HTMLToTextCount must count
// it as removed. A relative size that stays above 1px keeps the text
// visible.
//
// arch: REVIEW-2026-10-12 H5, D4.1, DRV.13
func TestHTMLToText_NestedRelativeFontHidden(t *testing.T) {
	for _, tc := range []struct{ name, in, secret string }{
		{"10% in 10%", `<span style="font-size:10%"><span style="font-size:10%">SECRET</span></span>`, "SECRET"},
		{"0.4em in 2px", `<div style="font-size:2px"><span style="font-size:0.4em">X</span></div>`, "X"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, removed := HTMLToTextCount(tc.in)
			if strings.Contains(got, tc.secret) || removed == 0 {
				t.Errorf("HTMLToTextCount(%q) = %q, %d; want no %s and removed > 0", tc.in, got, removed, tc.secret)
			}
		})
	}
	t.Run("2em in 16px stays visible", func(t *testing.T) {
		in := `<div style="font-size:16px"><span style="font-size:2em">SECRET</span></div>`
		got, removed := HTMLToTextCount(in)
		if got != "SECRET" || removed != 0 {
			t.Errorf("HTMLToTextCount(%q) = %q, %d; want %q, 0", in, got, removed, "SECRET")
		}
	})
}
