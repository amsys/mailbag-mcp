// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// skipTags names elements whose text content never reaches the
// output: script is code, style is CSS. Neither holds text a reader
// should see (§3.14). head is tracked on its own below (inHead),
// because HTML5 leaves the "in head" state at the first flow element,
// not only at a closing tag.
var skipTags = map[string]bool{"script": true, "style": true}

// headTags names the only elements real mail keeps inside <head>. The
// first start tag that is not one of these ends the head, whether or
// not </head> ever appears (§3.14, trap C20).
var headTags = map[string]bool{
	"head": true, "meta": true, "title": true, "link": true,
	"base": true, "style": true, "script": true, "noscript": true,
}

// rawTextTags names the head elements, apart from script and style
// (skipTags), whose content the tokenizer reads as one raw text token
// with no nested tags. Text inside one of these never ends the head on
// its own (DRV.13): it is the element's own content, not loose text a
// human reads next to it.
var rawTextTags = map[string]bool{"title": true, "noscript": true}

// blockTags names elements that start a new line before their content
// and after it ends (§3.14). br is handled on its own below: it is a
// void element, so the tokenizer never reports a matching end tag.
var blockTags = map[string]bool{
	"p": true, "div": true, "li": true, "tr": true, "td": true, "th": true, "table": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"blockquote": true, "hr": true, "section": true, "article": true,
	"header": true, "footer": true, "ul": true, "ol": true, "pre": true,
}

// event is one piece of output, kept until the whole body is read.
type event struct {
	kind int    // evText, evNewline, evLinkOpen or evLinkClose
	text string // the text, or the href of a link
	node *node  // the parent of the text, or the <a> element
}

const (
	evText = iota
	evNewline
	evLinkOpen
	evLinkClose
)

// HTMLToText turns html into plain text with the tokenizer of
// golang.org/x/net/html (§3.14). script, style, noscript and head are
// skipped. The head ends at its close tag, at the first tag that is
// not head content, or at the first character of text that is not a
// space, whichever comes first, as an HTML5 browser reads it (DRV.13).
// Block elements and <br> start a new line. A link becomes
// "text <url>".
//
// Text that the human does not see is removed (D4.1, DRV.13): text
// under display:none, content-visibility:hidden or the hidden
// attribute, text with visibility:hidden, text with a font size of
// 1px or less, text under opacity:0, filter:opacity(0) or
// mso-hide:all, transparent text, text in the color of its
// background (for color and for -webkit-text-fill-color), and an
// <svg> with width or height 0. Comments
// never reach the output. A hidden link gives
// no URL. The check reads the style of each text run only after the
// last token, because a later tag can move text that came before it
// (see tree).
//
// Malformed markup never fails this function: the tokenizer stops at
// the first error, and whatever text was already collected is
// returned as-is (§3.10: "any failure gives an empty preview and
// never fails the search" — this is the piece a caller builds that
// rule on).
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15, D4.1
func HTMLToText(src string) string {
	text, _ := HTMLToTextCount(src)
	return text
}

// HTMLToTextCount is HTMLToText plus the count of runs it removed. A
// run is one text token of the HTML that holds a character that is not
// a space, and that the hidden-text check removes (D4.1). Comments,
// script, style and head content are not runs. The caller shows the
// count to the model outside the fence (D4.2).
//
// arch: D4.1, D4.2
func HTMLToTextCount(src string) (text string, removed int) {
	z := html.NewTokenizer(strings.NewReader(src))
	t := newTree()
	var ev []event
	// skipping is true inside script or style. The tokenizer reads
	// their content as raw text up to the end tag, so they never nest.
	skipping := false
	inHead := false
	rawTextDepth := 0 // depth inside title or noscript (see rawTextTags)

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return render(ev)

		case html.DoctypeToken:
			t.doctype(z.Token().Data)

		case html.TextToken:
			text := z.Text()
			if inHead && !skipping && rawTextDepth == 0 && strings.TrimSpace(string(text)) != "" {
				// The first character that is not white space ends
				// the head, even with no closing tag, as an HTML5
				// browser reprocesses it in the body (DRV.13). Text
				// inside title or noscript is their own content, not
				// loose head text, so it never ends the head.
				inHead = false
			}
			if !skipping && !inHead {
				parent := t.text(text)
				ev = append(ev, event{kind: evText, text: string(text), node: parent})
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			tag := tok.Data

			if inHead && !headTags[tag] {
				// The first tag that is not head content ends the
				// head, even with no </head> (§3.14, trap C20).
				inHead = false
			}

			var n *node
			if !skipTags[tag] && tag != "head" {
				n = t.start(tag, tok.Attr, tt == html.SelfClosingTagToken)
			}

			switch {
			case tag == "body":
				// Real mail often leaves <head> open. <body> ends the
				// head.
				inHead = false
			case tag == "head":
				inHead = true
			case skipTags[tag]:
				skipping = true
				continue
			case rawTextTags[tag]:
				rawTextDepth++
			case tag == "br":
				ev = append(ev, event{kind: evNewline})
				continue
			case blockTags[tag]:
				ev = append(ev, event{kind: evNewline})
			}

			if tag == "a" {
				href := ""
				for _, a := range tok.Attr {
					if a.Key == "href" {
						href = a.Val
					}
				}
				ev = append(ev, event{kind: evLinkOpen, text: href, node: n})
			}

		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)

			if tag == "head" {
				inHead = false
				continue
			}
			if skipTags[tag] {
				skipping = false
				continue
			}
			if rawTextTags[tag] && rawTextDepth > 0 {
				rawTextDepth--
			}
			t.end(tag)
			if tag == "a" {
				ev = append(ev, event{kind: evLinkClose})
			}
			if blockTags[tag] {
				ev = append(ev, event{kind: evNewline})
			}
		}
	}
}

// render builds the output from the events, after the tree is final.
// It drops each text run whose parent is hidden (D4.1), and counts the
// dropped runs that are not only spaces (D4.2).
func render(ev []event) (string, int) {
	removed := 0
	var b strings.Builder
	var href string
	var linkHasText bool
	memo := map[*node]state{}
	for _, e := range ev {
		switch e.kind {
		case evText:
			if hidden(e.node, memo) {
				if strings.TrimSpace(e.text) != "" {
					removed++
				}
				continue
			}
			if href != "" && len(strings.TrimSpace(e.text)) > 0 {
				linkHasText = true
			}
			b.WriteString(e.text)
		case evNewline:
			if s := b.String(); len(s) > 0 && !strings.HasSuffix(s, "\n") {
				b.WriteByte('\n')
			}
		case evLinkOpen:
			href, linkHasText = "", false
			if !hidden(e.node, memo) {
				href = e.text
			}
		case evLinkClose:
			if href != "" {
				if linkHasText {
					b.WriteByte(' ')
				}
				b.WriteByte('<')
				b.WriteString(href)
				b.WriteByte('>')
			}
			href, linkHasText = "", false
		}
	}
	return strings.TrimSpace(b.String()), removed
}

// The hidden-text check (D4.1) needs the style of each text run, so it
// needs the parent of each element. Real mail is often malformed, and
// a browser repairs it with the HTML5 tree construction rules. The
// check must repair it the same way: if the check puts an element under
// a different parent than the browser, a sender can make text look
// visible to the check and hidden to the human. html.Parse is not used:
// it joins adjacent text with string concatenation, so a body of text
// that stray end tags split costs quadratic time.
//
// tree keeps the two structures of the HTML5 tree builder: the stack
// of open elements and the list of active formatting elements. It
// follows these rules of the "in body" and table insertion modes:
// scopes, implied end tags, the adoption agency algorithm, the
// reconstruction of formatting elements, implied <tbody> and <tr>, and
// foster parenting. It leaves out the rules that do not move an element
// to a different parent: the Noah's Ark clause, and foreign content
// (SVG, MathML), apart from self-closing tags.

// voidTags names elements that never have content. They never go on
// the stack.
var voidTags = map[string]bool{
	"area": true, "base": true, "basefont": true, "bgsound": true,
	"br": true, "col": true, "embed": true, "frame": true, "hr": true,
	"img": true, "image": true, "input": true, "keygen": true,
	"link": true, "meta": true, "param": true, "source": true,
	"track": true, "wbr": true,
}

// formattingTags names the HTML5 formatting elements. They go on the
// list of active formatting elements, and the browser opens a copy of
// them again after an unrelated end tag closes them.
var formattingTags = map[string]bool{
	"a": true, "b": true, "big": true, "code": true, "em": true,
	"font": true, "i": true, "nobr": true, "s": true, "small": true,
	"strike": true, "strong": true, "tt": true, "u": true,
}

// specialTags names the HTML5 "special" elements.
var specialTags = map[string]bool{
	"address": true, "applet": true, "area": true, "article": true,
	"aside": true, "base": true, "basefont": true, "bgsound": true,
	"blockquote": true, "body": true, "br": true, "button": true,
	"caption": true, "center": true, "col": true, "colgroup": true,
	"dd": true, "details": true, "dialog": true, "dir": true, "div": true,
	"dl": true, "dt": true, "embed": true, "fieldset": true,
	"figcaption": true, "figure": true, "footer": true, "form": true,
	"frame": true, "frameset": true, "h1": true, "h2": true, "h3": true,
	"h4": true, "h5": true, "h6": true, "head": true, "header": true,
	"hgroup": true, "hr": true, "html": true, "iframe": true, "img": true,
	"input": true, "keygen": true, "li": true, "link": true,
	"listing": true, "main": true, "marquee": true, "menu": true,
	"meta": true, "nav": true, "noembed": true, "noframes": true,
	"noscript": true, "object": true, "ol": true, "p": true, "param": true,
	"plaintext": true, "pre": true, "script": true, "search": true,
	"section": true, "select": true, "source": true, "style": true,
	"summary": true, "table": true, "tbody": true, "td": true,
	"template": true, "textarea": true, "tfoot": true, "th": true,
	"thead": true, "title": true, "tr": true, "track": true, "ul": true,
	"wbr": true, "xmp": true,
}

// pClosers names the start tags that close an open <p> in button
// scope before they open. table is handled on its own: it closes a <p>
// only when the page is not in quirks mode.
var pClosers = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true,
	"center": true, "details": true, "dialog": true, "dir": true,
	"div": true, "dl": true, "fieldset": true, "figcaption": true,
	"figure": true, "footer": true, "form": true, "header": true,
	"hgroup": true, "hr": true, "listing": true, "main": true,
	"menu": true, "nav": true, "ol": true, "p": true, "plaintext": true,
	"pre": true, "search": true, "section": true, "summary": true,
	"ul": true, "xmp": true, "li": true, "dd": true, "dt": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
}

// headingTags names h1 to h6. Any of them closes any other.
var headingTags = map[string]bool{
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
}

// The HTML5 scopes. A search for an open element stops at an element
// in the scope set.
var (
	defaultScope = map[string]bool{
		"applet": true, "caption": true, "html": true, "table": true,
		"td": true, "th": true, "marquee": true, "object": true,
		"template": true, "select": true,
	}
	buttonScope = union(defaultScope, "button")
	listScope   = union(defaultScope, "ol", "ul")
	tableScope  = map[string]bool{"html": true, "table": true, "template": true}
)

// markerTags push a marker on the list of active formatting elements.
// Formatting elements opened before the marker are not opened again
// inside the element. Closing the element clears the list back to the
// marker.
var markerTags = map[string]bool{
	"applet": true, "caption": true, "marquee": true, "object": true,
	"td": true, "template": true, "th": true,
}

// cellTags names the elements that "close the cell" (or the caption)
// closes. Closing them clears the active formatting elements back to
// the last marker. An <object> that a </table> closes does not.
var cellTags = map[string]bool{"td": true, "th": true, "caption": true}

// tableCtx names the elements that put the parser in a table mode. An
// element or text that is not table structure and opens in one of
// them is foster-parented: its parent is the parent of the table.
var tableCtx = map[string]bool{
	"table": true, "tbody": true, "thead": true, "tfoot": true, "tr": true,
}

// tableStruct names the elements that belong inside a table.
var tableStruct = map[string]bool{
	"table": true, "tbody": true, "thead": true, "tfoot": true, "tr": true,
	"td": true, "th": true, "caption": true, "col": true, "colgroup": true,
}

// reconstructs names the special start tags that open the active
// formatting elements again before they open. All start tags that are
// not special do this too.
var reconstructs = map[string]bool{
	"applet": true, "area": true, "br": true, "button": true, "embed": true,
	"img": true, "image": true, "input": true, "keygen": true,
	"marquee": true, "object": true, "select": true, "wbr": true,
}

func union(m map[string]bool, tags ...string) map[string]bool {
	out := make(map[string]bool, len(m)+len(tags))
	for k := range m {
		out[k] = true
	}
	for _, t := range tags {
		out[t] = true
	}
	return out
}

// rgb is a color. ok false means the color is not known: a color that
// the parser does not read, or a background image. clear means a
// transparent color: text in it is not seen. bad marks a background
// color that the parser does not read: text on it counts as hidden
// (fail closed).
type rgb struct {
	r, g, b int
	ok      bool
	clear   bool
	bad     bool
}

// frame is the tag of an element and the styles it declares. A field
// that the element does not declare is left unset, and the element
// takes the value of its parent.
type frame struct {
	tag   string
	attrs []html.Attribute
	none  bool // display:none, the hidden attribute, or never rendered
	vis   int  // 0 inherit, 1 visible, 2 hidden
	font  int  // 0 inherit, 1 a size in fontVal, 2 size 0 or not read
	// fontVal is the font-size value when font is 1. apply computes
	// its size in px from the size of the parent (REVIEW-2026-10-12
	// H5). fontQuirks tells that a number with no unit in it is in px.
	fontVal    string
	fontQuirks bool
	color      *rgb // nil inherits
	bg         *rgb // nil inherits
	// alpha is the opacity property of the element. nil means opacity 1.
	alpha *float64
	// filterAlpha is the opacity() function inside the filter property
	// (DRV.13). It is a separate property from opacity and composes
	// with it by multiplication (frame.apply): a sender cannot cancel
	// opacity:0 by adding filter:opacity(1) after it in the same style
	// attribute. nil means no filter opacity effect (1).
	filterAlpha *float64
	// bgImage marks a background image: the background is unknown.
	bgImage bool
	mso     int // mso-hide: 0 inherit, 1 none, 2 all
	// fill is -webkit-text-fill-color (DRV.13): 0 inherit, 1
	// currentcolor (the glyphs take the text color again), 2 the color
	// in fillColor. A browser paints the glyphs in this color, not in
	// color, so a fill that is transparent or in the color of the
	// background hides the text.
	fill      int
	fillColor rgb
}

// node is one element of the document tree. Only the parent link is
// kept: the style of a text run comes from its chain of parents.
type node struct {
	parent *node
	f      frame
}

// state is the style that applies to text at one point in the page.
type state struct {
	none, hiddenVis, fontZero, msoHidden bool
	color, bg                            rgb
	// fontPx is the computed font size in px. A relative size of a
	// child is computed from it, so nested relative sizes multiply.
	// fontZero is true when fontPx is maxHiddenFontPx or less.
	fontPx float64
	// fillSet tells that a -webkit-text-fill-color applies, and fill is
	// that color (DRV.13).
	fillSet bool
	fill    rgb
	// alpha is the product of the opacity of each element in the chain.
	alpha float64
}

// rootState is the page before any element: black text on white, at
// full opacity, in the default font size of 16px.
var rootState = state{color: rgb{ok: true}, bg: rgb{r: 255, g: 255, b: 255, ok: true}, alpha: 1, fontPx: 16}

// maxStackDepth limits the open elements that the stack holds, and the
// entries of the list of active formatting elements. Each token costs
// at most a few passes over them, so the limit keeps the time for a
// body linear in its size. Real mail stays far below it.
const maxStackDepth = 256

// afeEntry is one entry of the list of active formatting elements:
// either a marker, or a formatting element. When the element is
// closed, the entry stays, and its frame gives the element to open
// again.
type afeEntry struct {
	marker bool
	n      *node
}

// tree builds the document tree as the tokens come. When a body opens
// more than maxStackDepth elements, the tree stops and all text after
// that point counts as hidden (fail closed, D4.1).
type tree struct {
	html, body *node
	stack      []*node
	afe        []afeEntry
	noQuirks   bool
	started    bool  // a tag or text came, so a doctype is too late
	form       *node // the form element pointer
	overflow   bool
}

func newTree() *tree {
	h := &node{f: frame{tag: "html"}}
	return &tree{html: h, body: &node{parent: h, f: frame{tag: "body"}}}
}

// doctype records the document type. With no doctype, or with an old
// one, the page is in quirks mode, and a <table> does not close an
// open <p>.
func (t *tree) doctype(d string) {
	if t.started {
		return // a browser ignores a doctype after the first tag or text
	}
	d = strings.ToLower(strings.TrimSpace(d))
	switch {
	case d == "html", strings.Contains(d, "xhtml"):
		t.noQuirks = true
	case strings.Contains(d, "html 4.01"):
		loose := strings.Contains(d, "transitional") || strings.Contains(d, "frameset")
		hasSystemID := strings.Count(d, `"`) >= 4
		t.noQuirks = !loose || hasSystemID
	}
}

// fail makes the check fail closed: all text after this point is
// hidden.
func (t *tree) fail() {
	t.overflow, t.stack, t.afe = true, nil, nil
}

// text runs the rules for a text token and gives the parent of the
// text, or nil when the check failed closed. Text that is not only
// white space, and all text outside a table, opens the active
// formatting elements again.
func (t *tree) text(b []byte) *node {
	if t.overflow {
		return nil
	}
	nonSpace := len(strings.TrimSpace(string(b))) > 0
	if nonSpace {
		t.started = true
	}
	if nonSpace || !t.inTableMode() {
		t.reconstruct()
	}
	if t.overflow {
		return nil
	}
	return t.place("")
}

// start handles a start tag. It gives the new element, or nil when the
// tag opens no element.
func (t *tree) start(tag string, attrs []html.Attribute, selfClosing bool) *node {
	t.started = true
	if t.overflow {
		return nil
	}
	switch tag {
	case "form":
		if t.form != nil && !t.inTemplate() {
			return nil // a form in a form is ignored
		}
		if t.inTableMode() {
			// In a table, the form is inserted and closed at once.
			if t.inTemplate() {
				return nil
			}
			n := t.push(parseFrame(tag, attrs, !t.noQuirks))
			if n != nil {
				t.popTo(len(t.stack) - 1)
				t.form = n
			}
			return n
		}
		t.closeP()
		n := t.push(parseFrame(tag, attrs, !t.noQuirks))
		if !t.inTemplate() {
			t.form = n
		}
		return n
	case "html", "body":
		if t.inTemplate() {
			return nil // ignored in a template
		}
		// The browser has one of each. A later tag adds the attributes
		// that the element does not have yet. They apply to the whole
		// page, also to text before the tag.
		n := t.body
		if tag == "html" {
			n = t.html
		}
		all := append([]html.Attribute(nil), n.f.attrs...)
		for _, a := range attrs {
			if !hasAttr(all, a.Key) {
				all = append(all, a)
			}
		}
		n.f = parseFrame(tag, all, !t.noQuirks)
		return n
	case "frameset", "caption", "col", "colgroup", "tbody", "td", "tfoot", "th", "thead", "tr":
		if tag == "frameset" || t.inScope(tableScope, "table") < 0 {
			return nil // ignored outside a table
		}
		return t.tableStart(tag, attrs)
	case "table":
		if t.inTableMode() {
			// A table in a table closes the first one.
			t.popTo(t.inScope(tableScope, "table"))
		} else if t.noQuirks {
			t.closeP()
		}
		return t.push(parseFrame(tag, attrs, !t.noQuirks))
	case "li", "dd", "dt":
		t.closeListItem(tag)
	case "a":
		if i := t.afeFind("a"); i >= 0 {
			old := t.afe[i].n
			t.adoption("a")
			t.afeRemove(old)
			if j := t.stackIndex(old); j >= 0 {
				t.stack = append(t.stack[:j], t.stack[j+1:]...)
			}
		}
	case "nobr":
		if t.inScope(defaultScope, "nobr") >= 0 {
			t.adoption("nobr")
		}
	case "button":
		t.popTo(t.inScope(defaultScope, "button"))
	case "select":
		if i := t.inScope(defaultScope, "select"); i >= 0 {
			t.popTo(i) // a select in a select closes it
			return nil
		}
	case "option", "optgroup", "hr":
		if t.inScope(defaultScope, "select") >= 0 {
			t.impliedEnd(tag == "option")
		} else if n := len(t.stack); tag != "hr" && n > 0 && t.stack[n-1].f.tag == "option" {
			t.popTo(n - 1)
		}
	case "input":
		t.popTo(t.inScope(defaultScope, "select"))
	}
	if pClosers[tag] {
		t.closeP()
	}
	if headingTags[tag] {
		if n := len(t.stack); n > 0 && headingTags[t.stack[n-1].f.tag] {
			t.popTo(n - 1)
		}
	}
	if !specialTags[tag] || reconstructs[tag] || formattingTags[tag] {
		t.reconstruct()
	}
	if t.overflow || voidTags[tag] {
		return nil
	}
	if selfClosing && (tag == "svg" || tag == "math" || t.inForeign()) {
		return nil // only foreign content honors a self-closing tag
	}
	n := t.push(parseFrame(tag, attrs, !t.noQuirks))
	if n != nil && formattingTags[tag] {
		t.addAfe(afeEntry{n: n})
	}
	if n != nil && markerTags[tag] {
		t.addAfe(afeEntry{marker: true})
	}
	return n
}

func hasAttr(attrs []html.Attribute, key string) bool {
	for _, a := range attrs {
		if a.Key == key {
			return true
		}
	}
	return false
}

// tableStart handles a table structure start tag inside a table. It
// closes an open cell or caption, clears the stack back to the right
// table context, adds the implied <tbody> and <tr>, and opens the
// element.
func (t *tree) tableStart(tag string, attrs []html.Attribute) *node {
	if i := t.inScope(tableScope, "td", "th", "caption"); i >= 0 {
		t.popToClear(i, cellTags) // close the open cell or caption
	}
	var ctx []string
	switch tag {
	case "td", "th", "tr":
		ctx = []string{"tr", "tbody", "thead", "tfoot", "table"}
	case "tbody", "thead", "tfoot":
		ctx = []string{"tbody", "thead", "tfoot", "table"}
	default: // caption, col, colgroup
		ctx = []string{"table"}
	}
	k := t.inScope(tableScope, ctx...)
	if k < 0 {
		return nil
	}
	t.popTo(k + 1)
	top := t.stack[k].f.tag
	switch tag {
	case "tr":
		if top == "tr" {
			t.popTo(k)
			if k == 0 {
				return nil
			}
			top = t.stack[k-1].f.tag
		}
		if top == "table" && t.push(frame{tag: "tbody"}) == nil {
			return nil
		}
	case "td", "th":
		if top == "table" {
			if t.push(frame{tag: "tbody"}) == nil {
				return nil
			}
			top = "tbody"
		}
		if top != "tr" && t.push(frame{tag: "tr"}) == nil {
			return nil
		}
	case "tbody", "thead", "tfoot":
		if top != "table" {
			t.popTo(k)
		}
	case "col", "colgroup":
		return nil // no text content
	}
	n := t.push(parseFrame(tag, attrs, !t.noQuirks))
	if n != nil && markerTags[tag] {
		t.addAfe(afeEntry{marker: true})
	}
	return n
}

// closeListItem closes an open li (or dd, dt) before a new one opens.
// The search stops at a special element other than address, div and p.
func (t *tree) closeListItem(tag string) {
	match := []string{"li"}
	if tag != "li" {
		match = []string{"dd", "dt"}
	}
	for i := len(t.stack) - 1; i >= 0; i-- {
		name := t.stack[i].f.tag
		if contains(match, name) {
			t.popTo(i)
			return
		}
		if specialTags[name] && name != "address" && name != "div" && name != "p" {
			return
		}
	}
}

// impliedEnd closes the elements that an end tag can leave implied:
// dd, dt, li, optgroup, option, p and the ruby elements. keepOptgroup
// leaves an optgroup open.
func (t *tree) impliedEnd(keepOptgroup bool) {
	for n := len(t.stack); n > 0; n-- {
		switch t.stack[n-1].f.tag {
		case "dd", "dt", "li", "option", "p", "rb", "rp", "rt", "rtc":
		case "optgroup":
			if keepOptgroup {
				return
			}
		default:
			return
		}
		t.popTo(n - 1)
	}
}

// closeP closes an open <p> in button scope.
func (t *tree) closeP() {
	t.popTo(t.inScope(buttonScope, "p"))
}

// end handles an end tag.
func (t *tree) end(tag string) {
	if t.overflow {
		return
	}
	switch {
	case tag == "form":
		// </form> takes the form element out of the stack. The
		// elements above it stay open.
		n := t.form
		t.form = nil
		if n == nil || t.inTemplate() {
			if t.inTemplate() {
				t.popTo(t.inScope(defaultScope, "form"))
			}
			return
		}
		for i := len(t.stack) - 1; i >= 0; i-- {
			if t.stack[i] == n {
				t.impliedEnd(false) // this closes an open <p> first
				if j := t.stackIndex(n); j >= 0 {
					t.stack = append(t.stack[:j], t.stack[j+1:]...)
				}
				return
			}
			if defaultScope[t.stack[i].f.tag] {
				return // not in scope: ignore the tag
			}
		}
	case tag == "template":
		// </template> closes the nearest template, with no scope.
		for i := len(t.stack) - 1; i >= 0; i-- {
			if t.stack[i].f.tag == "template" {
				t.popToClear(i, markerTags)
				return
			}
		}
	case tag == "html" || tag == "body" || voidTags[tag]:
		// </body> and </html> close nothing that text after them
		// leaves. </br> acts as <br>.
		return
	case formattingTags[tag]:
		t.adoption(tag)
	case tag == "p":
		t.popTo(t.inScope(buttonScope, "p"))
	case tag == "li":
		t.popTo(t.inScope(listScope, "li"))
	case headingTags[tag]:
		t.popTo(t.inScope(defaultScope, "h1", "h2", "h3", "h4", "h5", "h6"))
	case tableStruct[tag]:
		// A cell or caption between the top and the element closes
		// first.
		t.popToClear(t.inScope(tableScope, tag), cellTags)
	case markerTags[tag]:
		t.popToClear(t.inScope(defaultScope, tag), markerTags)
	case specialTags[tag]:
		t.popTo(t.inScope(defaultScope, tag))
	default:
		t.endOther(tag)
	}
}

// endOther is the rule for "any other end tag": close the nearest open
// element of that name, but stop at a special element.
func (t *tree) endOther(tag string) {
	for i := len(t.stack) - 1; i >= 0; i-- {
		name := t.stack[i].f.tag
		if name == tag {
			t.popTo(i)
			return
		}
		if specialTags[name] {
			return
		}
	}
}

// adoption runs the adoption agency algorithm for the end tag of a
// formatting element. It moves elements, and the text in them, to the
// parents that a browser gives them. This can change the style of text
// that came before the tag, so the style is read only at the end.
func (t *tree) adoption(tag string) {
	for outer := 0; outer < 8; outer++ {
		n := len(t.stack)
		if n > 0 && t.stack[n-1].f.tag == tag && t.afeIndex(t.stack[n-1]) < 0 {
			t.popTo(n - 1)
			return
		}
		fi := t.afeFind(tag)
		if fi < 0 {
			t.endOther(tag)
			return
		}
		fe := t.afe[fi].n
		si := t.stackIndex(fe)
		if si < 0 {
			t.afe = append(t.afe[:fi], t.afe[fi+1:]...)
			return
		}
		for j := n - 1; j > si; j-- {
			if defaultScope[t.stack[j].f.tag] {
				return // not in scope: ignore the tag
			}
		}
		fb := -1
		for j := si + 1; j < n; j++ {
			if specialTags[t.stack[j].f.tag] {
				fb = j
				break
			}
		}
		if fb < 0 {
			t.popTo(si)
			t.afeRemove(fe)
			return
		}
		common := t.body
		if si > 0 {
			common = t.stack[si-1]
		}
		// The furthest block keeps its children, but they get a new
		// copy of the formatting element as parent. The old node
		// object becomes that copy, so that each child and text run
		// that points to it follows with no list of children.
		oldFB := t.stack[fb]
		newFB := &node{f: oldFB.f}
		oldFB.f = fe.f
		oldFB.parent = newFB
		t.afe[fi].n = oldFB
		// The elements between the formatting element and the
		// furthest block: the three nearest to the block that are
		// active formatting elements get a copy that wraps the block.
		// All others leave the stack.
		var kept []*node
		last := newFB
		count := 0
		for j := fb - 1; j > si; j-- {
			el := t.stack[j]
			ai := t.afeIndex(el)
			count++
			if ai >= 0 && count > 3 {
				t.afe = append(t.afe[:ai], t.afe[ai+1:]...)
				ai = -1
			}
			if ai < 0 {
				continue
			}
			c := &node{f: el.f}
			t.afe[ai].n = c
			last.parent = c
			last = c
			kept = append([]*node{c}, kept...)
		}
		if tableCtx[common.f.tag] {
			last.parent = t.fosterParent()
		} else {
			last.parent = common
		}
		out := append([]*node(nil), t.stack[:si]...)
		out = append(out, kept...)
		out = append(out, newFB, oldFB)
		out = append(out, t.stack[fb+1:]...)
		t.stack = out
	}
}

// reconstruct opens again the active formatting elements after the
// last marker that are no longer on the stack.
func (t *tree) reconstruct() {
	if t.overflow || len(t.afe) == 0 {
		return
	}
	last := len(t.afe) - 1
	if t.afe[last].marker || t.stackIndex(t.afe[last].n) >= 0 {
		return
	}
	i := last
	for i > 0 && !t.afe[i-1].marker && t.stackIndex(t.afe[i-1].n) < 0 {
		i--
	}
	for ; i <= last; i++ {
		n := t.push(t.afe[i].n.f)
		if n == nil {
			return
		}
		t.afe[i].n = n
	}
}

// place gives the parent for a new element with tag (or for text, with
// tag ""). An element that is not table structure, or text, in a table
// mode is foster-parented: its parent is the parent of the table.
func (t *tree) place(tag string) *node {
	n := len(t.stack)
	if n == 0 {
		return t.body
	}
	if top := t.stack[n-1]; !tableCtx[top.f.tag] || tableStruct[tag] {
		return top
	}
	return t.fosterParent()
}

// fosterParent gives the parent of the last open table.
func (t *tree) fosterParent() *node {
	for k := len(t.stack) - 1; k >= 0; k-- {
		if t.stack[k].f.tag == "table" {
			return t.stack[k].parent
		}
	}
	return t.body
}

// push opens a new element on top of the stack. It gives nil when the
// stack is full: then the check fails closed.
func (t *tree) push(f frame) *node {
	if t.overflow {
		return nil
	}
	if len(t.stack) >= maxStackDepth {
		t.fail()
		return nil
	}
	n := &node{parent: t.place(f.tag), f: f}
	t.stack = append(t.stack, n)
	return n
}

// addAfe adds e to the list of active formatting elements. A body can
// grow the list with no growth of the stack, and each end tag of a
// formatting element reads the list. Past maxStackDepth entries the
// check fails closed, as for a deep stack.
func (t *tree) addAfe(e afeEntry) {
	if len(t.afe) >= maxStackDepth {
		t.fail()
		return
	}
	t.afe = append(t.afe, e)
}

// popTo closes the element at i and all elements above it. The active
// formatting elements stay: only an explicit step clears them (see
// popToClear). i < 0 does nothing.
func (t *tree) popTo(i int) {
	if i >= 0 {
		t.stack = t.stack[:i]
	}
}

// popToClear closes the element at i and all elements above it. When
// one of them is in clearOn, it also clears the active formatting
// elements back to the last marker, once. This is the step for "close
// the cell" (clearOn cellTags) and for the end tag of a marker element
// (clearOn markerTags).
func (t *tree) popToClear(i int, clearOn map[string]bool) {
	if i < 0 {
		return
	}
	for j := len(t.stack) - 1; j >= i; j-- {
		if clearOn[t.stack[j].f.tag] {
			for len(t.afe) > 0 {
				e := t.afe[len(t.afe)-1]
				t.afe = t.afe[:len(t.afe)-1]
				if e.marker {
					break
				}
			}
			break
		}
	}
	t.stack = t.stack[:i]
}

// inScope gives the index of the nearest open element named in tags,
// or -1 when an element of the scope set comes first.
func (t *tree) inScope(scope map[string]bool, tags ...string) int {
	for i := len(t.stack) - 1; i >= 0; i-- {
		name := t.stack[i].f.tag
		if contains(tags, name) {
			return i
		}
		if scope[name] {
			return -1
		}
	}
	return -1
}

// inTableMode reports whether the parser is in a table mode and not in
// a cell or a caption.
func (t *tree) inTableMode() bool {
	for i := len(t.stack) - 1; i >= 0; i-- {
		name := t.stack[i].f.tag
		switch {
		case tableCtx[name]:
			return true
		case name == "td" || name == "th" || name == "caption" || name == "template":
			return false
		}
	}
	return false
}

// inTemplate reports whether a template element is open.
func (t *tree) inTemplate() bool {
	for i := len(t.stack) - 1; i >= 0; i-- {
		if t.stack[i].f.tag == "template" {
			return true
		}
	}
	return false
}

// inForeign reports whether an SVG or MathML element is open.
func (t *tree) inForeign() bool {
	for i := len(t.stack) - 1; i >= 0; i-- {
		if name := t.stack[i].f.tag; name == "svg" || name == "math" {
			return true
		}
	}
	return false
}

// afeFind gives the index of the last active formatting element named
// tag after the last marker, or -1.
func (t *tree) afeFind(tag string) int {
	for i := len(t.afe) - 1; i >= 0; i-- {
		if t.afe[i].marker {
			return -1
		}
		if t.afe[i].n.f.tag == tag {
			return i
		}
	}
	return -1
}

func (t *tree) afeIndex(n *node) int {
	for i := len(t.afe) - 1; i >= 0; i-- {
		if !t.afe[i].marker && t.afe[i].n == n {
			return i
		}
	}
	return -1
}

func (t *tree) afeRemove(n *node) {
	if i := t.afeIndex(n); i >= 0 {
		t.afe = append(t.afe[:i], t.afe[i+1:]...)
	}
}

func (t *tree) stackIndex(n *node) int {
	for i := len(t.stack) - 1; i >= 0; i-- {
		if t.stack[i] == n {
			return i
		}
	}
	return -1
}

// maxChain limits the chain of parents that styleOf reads. The stack
// limit keeps a real chain far below it.
const maxChain = 8 * maxStackDepth

// styleOf gives the state inside n, from its chain of parents. memo
// holds the states found before, so that the time for all text runs
// stays linear.
func styleOf(n *node, memo map[*node]state) state {
	var chain []*node
	p := rootState
	for c := n; c != nil; c = c.parent {
		if s, ok := memo[c]; ok {
			p = s
			break
		}
		if len(chain) > maxChain {
			// A chain this long is not a real page, and could be a
			// loop of parents: fail closed.
			return state{none: true}
		}
		chain = append(chain, c)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		p = chain[i].f.apply(p)
		memo[chain[i]] = p
	}
	return p
}

// hidden reports whether text with parent n is hidden from the human
// (D4.1). A nil parent means the check failed closed.
func hidden(n *node, memo map[*node]state) bool {
	if n == nil {
		return true
	}
	return styleOf(n, memo).hides()
}

// hides reports whether text in state s is hidden from the human. A
// text color that the parser cannot read counts as hidden: the check
// fails closed (D4.1). An unknown background, such as an image, does
// not hide text, but a background color that the parser cannot read
// does. Opacity below minAlpha hides text; the opacity property and a
// filter:opacity() function (DRV.13) each contribute their own factor
// and compose by multiplication (frame.apply), so one cannot cancel
// the other. mso-hide:all also hides text. A -webkit-text-fill-color
// (DRV.13) gets the same color checks as color. Text is hidden when
// either color hides it, because a mail program that does not read
// the fill paints the glyphs in color (fail closed).
func (s state) hides() bool {
	if s.none || s.hiddenVis || s.fontZero || s.msoHidden || s.alpha < minAlpha ||
		s.bg.bad || colorHides(s.color, s.bg) {
		return true
	}
	return s.fillSet && colorHides(s.fill, s.bg)
}

// colorHides reports whether text in color c on background bg is not
// seen: c is transparent, c is not read (fail closed), or c is too
// near a known bg.
func colorHides(c, bg rgb) bool {
	return c.clear || !c.ok || bg.ok && nearColor(c, bg)
}

// apply gives the state inside f, from the state of its parent.
func (f *frame) apply(p state) state {
	if f.none {
		p.none = true
	}
	switch f.vis {
	case 1:
		p.hiddenVis = false
	case 2:
		p.hiddenVis = true
	}
	switch f.font {
	case 1:
		p.fontPx = fontSizePx(f.fontVal, f.fontQuirks, p.fontPx)
		p.fontZero = p.fontPx <= maxHiddenFontPx+fontEps
	case 2:
		p.fontPx, p.fontZero = 0, true
	}
	if f.color != nil {
		p.color = *f.color
	}
	if f.bg != nil {
		p.bg = *f.bg
	}
	if f.bgImage {
		// The image paints over the background color: unknown.
		p.bg = rgb{}
	}
	if f.alpha != nil {
		p.alpha *= *f.alpha
	}
	if f.filterAlpha != nil {
		p.alpha *= *f.filterAlpha
	}
	switch f.mso {
	case 1:
		p.msoHidden = false
	case 2:
		p.msoHidden = true
	}
	switch f.fill {
	case 1:
		p.fillSet = false
	case 2:
		p.fillSet, p.fill = true, f.fillColor
	}
	return p
}

// nearColor reports whether a and b are too close to tell apart.
func nearColor(a, b rgb) bool {
	const d = 16
	return abs(a.r-b.r) <= d && abs(a.g-b.g) <= d && abs(a.b-b.b) <= d
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// neverRendered names elements whose text a browser never shows.
// noscript is here because the tokenizer reads it as raw text the same
// way it reads script and style (proven trap, DRV.13): a sender can
// carry payload text inside it that must not reach the model.
var neverRendered = map[string]bool{
	"template": true, "title": true, "noembed": true, "noframes": true,
	"iframe": true, "noscript": true,
}

// bgcolorTags names the elements on which a browser uses the bgcolor
// attribute. On another element bgcolor does not change the background.
var bgcolorTags = map[string]bool{
	"body": true, "table": true, "thead": true, "tbody": true, "tfoot": true,
	"tr": true, "td": true, "th": true, "marquee": true,
}

// parseFrame reads the attributes of an element into a frame. The
// style attribute wins over the old color attributes. The text
// attribute of <body> is the text color of the page. quirks tells
// whether the page is in quirks mode.
func parseFrame(tag string, attrs []html.Attribute, quirks bool) frame {
	f := frame{tag: tag, attrs: attrs, none: neverRendered[tag]}
	for _, a := range attrs {
		switch a.Key {
		case "hidden":
			f.none = true
		case "bgcolor":
			// A browser maps bgcolor only on these tags. On any
			// other tag it has no effect (REVIEW-2026-10-12 H4).
			if bgcolorTags[tag] {
				f.bg = legacyColor(a.Val)
			}
		case "color":
			if tag == "font" {
				f.color = legacyColor(a.Val)
			}
		case "text":
			if tag == "body" {
				f.color = legacyColor(a.Val)
			}
		case "width", "height":
			// A zero-size svg is not shown (DRV.13). The SVG rules
			// say that a width or height of 0 disables rendering.
			if tag == "svg" && isZeroLength(a.Val) {
				f.none = true
			}
		}
	}
	for _, a := range attrs {
		if a.Key == "style" {
			applyStyle(&f, a.Val, quirks)
		}
	}
	return f
}

// isZeroLength reports whether v, a width or height value, is zero.
// It reads a number with no unit, or with a unit of letters or "%"
// (0, 0px, 0%, 0em, 0.0). Zero in any unit is zero. A value that it
// cannot read is not zero.
func isZeroLength(v string) bool {
	v = strings.TrimRight(strings.ToLower(strings.TrimSpace(v)), "abcdefghijklmnopqrstuvwxyz%")
	n, err := strconv.ParseFloat(v, 64)
	return err == nil && n == 0
}

// dynamicValues are the CSS functions whose value is known only when
// the page shows.
var dynamicValues = []string{"var(", "env(", "attr("}

// applyStyle reads the CSS declarations in style into f. A later
// declaration wins over an earlier one, but not over an earlier
// !important one. Comments and escapes are removed before the match,
// so that disp\lay:/**/none is display:none. A browser drops a
// declaration that is not valid, so an empty value or a font
// shorthand with no size or no family keeps the earlier value. A value
// that the parser cannot read hides the text (fail closed, D4.1).
func applyStyle(f *frame, style string, quirks bool) {
	important := map[string]bool{}
	for _, decl := range splitDecls(style) {
		k, v, ok := strings.Cut(unescapeCSS(decl), ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v, imp := cutImportant(strings.ToLower(v))
		group := k
		switch k {
		case "font":
			group = "font-size"
		case "background":
			group = "background-color"
		}
		if important[group] && !imp {
			continue
		}
		switch k {
		case "display", "visibility", "font-size", "font", "color", "background-color", "background",
			"background-image", "opacity", "mso-hide", "content-visibility", "-webkit-text-fill-color",
			"filter":
		case "width", "height":
			if f.tag != "svg" {
				continue // read only for a zero-size svg (DRV.13)
			}
		default:
			continue
		}
		if v == "" {
			continue // not valid: the browser drops it
		}
		dynamic := false
		for _, d := range dynamicValues {
			dynamic = dynamic || strings.Contains(v, d)
		}
		if dynamic {
			// The value is known only when the page shows: fail closed.
			f.none = true
			continue
		}
		switch k {
		case "display":
			if v == "none" {
				f.none = true
			}
		case "visibility":
			switch v {
			case "hidden", "collapse":
				f.vis = 2
			case "visible":
				f.vis = 1
			}
		case "font-size":
			f.font, f.fontVal, f.fontQuirks = parseFontSize(v, quirks), v, quirks
		case "font":
			size, sz, valid := parseFontShorthand(v)
			if !valid {
				continue
			}
			// The unitless length quirk does not apply to the shorthand.
			f.font, f.fontVal, f.fontQuirks = size, sz, false
		case "color":
			f.color = parseColorValue(v, quirks)
		case "background-color":
			f.bg = bgColor(v, quirks)
		case "background":
			f.bg = parseBackground(v, quirks)
			if !important["background-image"] {
				// The shorthand sets the image too. An image in it
				// already gives an unknown background.
				f.bgImage = false
			}
		case "background-image":
			switch {
			case v == "none" || v == "initial" || v == "unset":
				f.bgImage = false
			case hasBackgroundImage(v):
				f.bgImage = true
			default:
				continue // not read: taken as not valid, the browser drops it
			}
		case "opacity":
			a, ok := parseOpacity(v)
			if !ok {
				continue // not valid: the browser drops it
			}
			f.alpha = &a
		case "mso-hide":
			switch v {
			case "all":
				f.mso = 2
			case "none":
				f.mso = 1
			}
		case "content-visibility":
			// hidden removes the element the same way display:none
			// does (DRV.13). auto and visible keep it shown.
			if v == "hidden" {
				f.none = true
			}
		case "-webkit-text-fill-color":
			switch v {
			case "inherit", "unset", "revert", "revert-layer":
				// The property inherits, and there is no UA rule for
				// it, so revert and revert-layer act as inherit too
				// (parseColorValue does the same): keep the parent.
				f.fill = 0
			case "currentcolor", "initial":
				f.fill = 1
			default:
				f.fill = 2
				if c := parseColorValue(v, quirks); c != nil {
					f.fillColor = *c
				} else {
					f.fillColor = rgb{} // not read: fail closed
				}
			}
		case "filter":
			a, ok := filterOpacity(v)
			if !ok {
				continue // not valid: the browser drops it
			}
			// Each filter declaration replaces the one before it,
			// also when it holds no opacity() (a is then 1).
			f.filterAlpha = &a
		case "width", "height":
			if isZeroLength(v) {
				f.none = true
			}
		}
		if imp {
			important[group] = true
			if k == "background" {
				important["background-image"] = true
			}
		}
	}
}

// splitDecls splits a style attribute into its declarations. Each
// comment becomes a space, as in CSS. A semicolon in a string, in
// brackets or after a backslash does not split.
func splitDecls(style string) []string {
	var out []string
	var b strings.Builder
	depth := 0
	var quote byte
	for i := 0; i < len(style); i++ {
		c := style[i]
		switch {
		case c == '\\' && i+1 < len(style):
			b.WriteByte(c)
			i++
			b.WriteByte(style[i])
			continue
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '/' && i+1 < len(style) && style[i+1] == '*':
			// An open comment runs to the end of the style.
			if end := strings.Index(style[i+2:], "*/"); end < 0 {
				i = len(style)
			} else {
				i += end + 3
			}
			b.WriteByte(' ')
			continue
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth > 0 {
				depth--
			}
		case c == ';' && depth == 0:
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	return append(out, b.String())
}

// unescapeCSS decodes the CSS escapes in s: a backslash and 1 to 6 hex
// digits (and one space after them) give that code point, and a
// backslash before any other character gives that character.
func unescapeCSS(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i >= len(s) {
			b.WriteRune(utf8.RuneError)
			break
		}
		j := i
		for j < len(s) && j-i < 6 && isHex(rune(s[j])) {
			j++
		}
		if j == i {
			if s[i] == '\n' || s[i] == '\r' || s[i] == '\f' {
				continue // an escaped newline is removed
			}
			r, size := utf8.DecodeRuneInString(s[i:])
			b.WriteRune(r)
			i += size - 1
			continue
		}
		n, _ := strconv.ParseUint(s[i:j], 16, 32)
		if n == 0 || n > unicode.MaxRune || n >= 0xd800 && n <= 0xdfff {
			n = utf8.RuneError
		}
		b.WriteRune(rune(n)) //nolint:gosec // G115: n is at most unicode.MaxRune after the check above
		i = j
		switch {
		case i < len(s) && s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n':
			i++
		case i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\f'):
		default:
			i-- // no space to remove after the escape
		}
	}
	return b.String()
}

func isHex(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
}

// cutImportant removes "!important" from the end of a value. CSS
// allows space between the "!" and "important".
func cutImportant(v string) (string, bool) {
	v = strings.TrimSpace(v)
	rest, ok := strings.CutSuffix(v, "important")
	if !ok {
		return v, false
	}
	rest, ok = strings.CutSuffix(strings.TrimSpace(rest), "!")
	if !ok {
		return v, false
	}
	return strings.TrimSpace(rest), true
}

// cssFields splits a value at the spaces that are not in brackets, so
// that rgb(1, 2, 3) and calc(1px + 2px) stay one field.
func cssFields(v string) []string {
	var out []string
	var b strings.Builder
	depth := 0
	for _, r := range v {
		switch {
		case r == '(':
			depth++
		case r == ')' && depth > 0:
			depth--
		case unicode.IsSpace(r) && depth == 0:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// fontSizeKeywords gives the size in px of each absolute font-size
// keyword. All of them give a size not 0.
var fontSizeKeywords = map[string]float64{
	"xx-small": 9, "x-small": 10, "small": 13, "medium": 16,
	"large": 18, "x-large": 24, "xx-large": 32, "xxx-large": 48,
	"initial": 16,
}

// fontScale is the ratio between two steps of the font-size keywords:
// larger multiplies the size of the parent by it, and smaller divides.
const fontScale = 1.2

// maxHiddenFontPx is the largest font size in px that does not show
// text. A size of 1px or less cannot be read, so it counts as size 0
// (DRV.13). fontEps absorbs the rounding of a unit change, so that
// 0.75pt is 1px.
const (
	maxHiddenFontPx = 1
	fontEps         = 1e-9
)

// parseFontSize gives 0 to take the size of the parent, 1 for a size
// that apply computes with fontSizePx, and 2 for a value that it cannot
// read: the text counts as hidden (fail closed). A calc(), min(), max()
// or clamp() is a size. A number with no unit is a size only in quirks
// mode.
func parseFontSize(v string, quirks bool) int {
	switch v {
	case "inherit", "unset", "revert", "revert-layer":
		return 0
	case "larger", "smaller", "math":
		return 1
	}
	if fontSizeKeywords[v] > 0 {
		return 1
	}
	if _, ok := evalLength(v, 16, quirks); !ok {
		return 2
	}
	return 1
}

// fontSizePx computes the font size in px of the value v, which
// parseFontSize reads as 1, in a parent of font size parent px. em, %,
// ex, ch, larger and smaller are relative to the parent (REVIEW-2026-10-12
// H5). math keeps the size of the parent. A negative result gives 0, as
// a browser clamps a calc() to the range of the property. A value that
// it cannot read gives 0: the text counts as hidden (fail closed).
func fontSizePx(v string, quirks bool, parent float64) float64 {
	switch v {
	case "larger":
		return parent * fontScale
	case "smaller":
		return parent / fontScale
	case "math":
		return parent
	}
	if px := fontSizeKeywords[v]; px > 0 {
		return px
	}
	px, ok := evalLength(v, parent, quirks)
	if !ok || px < 0 {
		return 0
	}
	return px
}

// parseFontShorthand gives the font size in the font shorthand, with
// the values of parseFontSize, and the size value val. The size is the first field that is not
// a style, variant or weight keyword, or a weight number. A system font
// such as caption gives a size not 0. valid false means that the
// value has no size or no family after the size: the browser drops
// the declaration.
func parseFontShorthand(v string) (size int, val string, valid bool) {
	switch v {
	case "inherit", "unset", "revert", "revert-layer":
		return 0, "", true
	case "initial", "caption", "icon", "menu", "message-box", "small-caption", "status-bar":
		// A system font: take the default size.
		return 1, "medium", true
	}
	fields := cssFields(v)
	for i, field := range fields {
		sz, lh, slash := strings.Cut(field, "/")
		if sz == "" {
			return 0, "", false // a line height with no size before it
		}
		isSize := fontSizeKeywords[sz] > 0 || sz == "larger" || sz == "smaller"
		if !isSize {
			if n, err := strconv.ParseFloat(sz, 64); err == nil && n != 0 {
				continue // a weight such as 700
			}
			c := sz[0]
			isSize = c >= '0' && c <= '9' || c == '.' || c == '+' || c == '-' || strings.Contains(sz, "(")
		}
		if !isSize {
			continue
		}
		// Skip the line height: "14px/1.2", "14px/ 1.2", "14px /1.2"
		// or "14px / 1.2". A family must come after it.
		rest := fields[i+1:]
		switch {
		case slash && lh == "":
			if len(rest) == 0 {
				return 0, "", false
			}
			rest = rest[1:]
		case !slash && len(rest) > 0 && rest[0] == "/":
			if len(rest) < 2 {
				return 0, "", false
			}
			rest = rest[2:]
		case !slash && len(rest) > 0 && strings.HasPrefix(rest[0], "/"):
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return 0, "", false
		}
		// The unitless length quirk does not apply to the shorthand.
		return parseFontSize(sz, false), sz, true
	}
	return 0, "", false
}

// evalLength computes a CSS length in px. em is the size of 1em (the
// font size of the parent). It reads a number with a unit, and calc(),
// min(), max() and clamp() of them. A number with no unit is a length
// only when it is 0, or in quirks mode, and only outside a function.
// ok false means that the value is not a valid length.
func evalLength(v string, em float64, quirks bool) (float64, bool) {
	p := calcParser{s: v, em: em}
	q, ok := p.factor()
	if !ok || p.i != len(p.s) {
		return 0, false
	}
	if !q.length && (strings.Contains(v, "(") || q.v != 0 && !quirks) {
		return 0, false
	}
	return q.v, true
}

// calcParser reads a CSS math expression.
type calcParser struct {
	s     string
	i     int
	em    float64
	depth int
}

// quantity is a value of a math expression: a length in px, or a
// number with no unit.
type quantity struct {
	v      float64
	length bool
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *calcParser) space() {
	for p.i < len(p.s) && isSpace(p.s[p.i]) {
		p.i++
	}
}

// sum reads terms joined by + or -. CSS needs white space on both
// sides of the operator, and both terms must be of one type.
func (p *calcParser) sum() (quantity, bool) {
	n, ok := p.product()
	for ok {
		before := p.i
		p.space()
		if p.i == before || p.i+1 >= len(p.s) || p.s[p.i] != '+' && p.s[p.i] != '-' || !isSpace(p.s[p.i+1]) {
			p.i = before
			break
		}
		op := p.s[p.i]
		p.i++
		var m quantity
		m, ok = p.product()
		if m.length != n.length {
			return quantity{}, false
		}
		if op == '+' {
			n.v += m.v
		} else {
			n.v -= m.v
		}
	}
	return n, ok
}

// product reads factors joined by * or /. A length times a length and
// a division by a length or by 0 are not valid.
func (p *calcParser) product() (quantity, bool) {
	n, ok := p.factor()
	for ok {
		before := p.i
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != '*' && p.s[p.i] != '/' {
			p.i = before
			break
		}
		op := p.s[p.i]
		p.i++
		var m quantity
		m, ok = p.factor()
		switch {
		case !ok:
		case op == '*' && (!n.length || !m.length):
			n = quantity{n.v * m.v, n.length || m.length}
		case op == '/' && !m.length && m.v != 0:
			n.v /= m.v
		default:
			ok = false
		}
	}
	return n, ok
}

// lengthUnits gives the size in px of one unit. A unit relative to
// the font of the parent is a multiple of em (-1 means 1em, -0.5 half
// of it, -0.01 1%).
var lengthUnits = map[string]float64{
	"px": 1, "pt": 4.0 / 3, "pc": 16, "in": 96, "cm": 96 / 2.54,
	"mm": 96 / 25.4, "q": 96 / 101.6, "rem": 16,
	"vw": 6, "vh": 6, "vmin": 6, "vmax": 6,
	"em": -1, "lh": -1, "ex": -0.5, "ch": -0.5, "cap": -0.5, "ic": -1, "%": -0.01,
}

// number reads a CSS number at p.i: an optional sign, digits with an
// optional fraction, and an optional exponent. It gives false and
// leaves p.i when there is no number.
func (p *calcParser) number() (float64, bool) {
	s, i := p.s, p.i
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	digits := 0
	for i < len(s) && isDigit(s[i]) {
		i++
		digits++
	}
	if i+1 < len(s) && s[i] == '.' && isDigit(s[i+1]) {
		i++
		for i < len(s) && isDigit(s[i]) {
			i++
			digits++
		}
	}
	if digits == 0 {
		return 0, false
	}
	if i < len(s) && s[i] == 'e' {
		j := i + 1
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		if j < len(s) && isDigit(s[j]) {
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			i = j
		}
	}
	n, err := strconv.ParseFloat(s[p.i:i], 64)
	if err != nil || math.IsInf(n, 0) {
		return 0, false
	}
	p.i = i
	return n, true
}

func (p *calcParser) factor() (quantity, bool) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 32 {
		return quantity{}, false
	}
	p.space()
	if p.i >= len(p.s) {
		return quantity{}, false
	}
	if n, ok := p.number(); ok {
		u := p.i
		for p.i < len(p.s) && (p.s[p.i] >= 'a' && p.s[p.i] <= 'z' || p.s[p.i] == '%') {
			p.i++
		}
		if u == p.i {
			return quantity{v: n}, true
		}
		f, ok := lengthUnits[p.s[u:p.i]]
		if !ok {
			return quantity{}, false
		}
		if f < 0 {
			f = -f * p.em
		}
		return quantity{n * f, true}, true
	}
	name := p.i
	for p.i < len(p.s) && (p.s[p.i] >= 'a' && p.s[p.i] <= 'z' || p.s[p.i] == '-') {
		p.i++
	}
	fn := p.s[name:p.i]
	if p.i >= len(p.s) || p.s[p.i] != '(' {
		return quantity{}, false
	}
	p.i++
	var args []quantity
	for {
		n, ok := p.sum()
		if !ok || len(args) > 0 && n.length != args[0].length {
			return quantity{}, false
		}
		args = append(args, n)
		p.space()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.s) && p.s[p.i] == ')' {
			p.i++
			break
		}
		return quantity{}, false
	}
	a := args[0]
	switch {
	case fn == "calc" && len(args) == 1:
		return a, true
	case fn == "" && len(args) == 1 && p.depth > 1:
		// Brackets group terms only inside a math function.
		return a, true
	case fn == "min" || fn == "max":
		for _, b := range args[1:] {
			if fn == "min" && b.v < a.v || fn == "max" && b.v > a.v {
				a.v = b.v
			}
		}
		return a, true
	case fn == "clamp" && len(args) == 3:
		a.v = max(args[0].v, min(args[1].v, args[2].v))
		return a, true
	}
	return quantity{}, false
}

// parseColorValue reads a CSS color. inherit, currentcolor and the
// other keywords that take the parent value give nil. A CSS system
// color gives the page text color (D4.1). A color that it cannot read
// gives an unknown color. As a text color, an unknown color hides the
// text (fail closed).
func parseColorValue(v string, quirks bool) *rgb {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", "inherit", "currentcolor", "unset", "revert", "revert-layer":
		return nil
	case "initial":
		return &rgb{ok: true}
	}
	if systemColors[v] {
		return &rgb{ok: true}
	}
	c := parseColor(v, quirks)
	return &c
}

// bgColor reads a background color. A transparent background shows
// the background of the parent, so it gives nil. A color that it
// cannot read is bad: text on it counts as hidden (fail closed).
func bgColor(v string, quirks bool) *rgb {
	if v == "initial" {
		return nil
	}
	if systemColors[strings.TrimSpace(v)] {
		// The value depends on the mail program: unknown.
		return &rgb{}
	}
	c := parseColorValue(v, quirks)
	switch {
	case c == nil || c.clear:
		return nil
	case !c.ok:
		return &rgb{bad: true}
	}
	return c
}

// legacyColor reads a color attribute (color, bgcolor, text) with the
// HTML rules for a legacy color value. These rules give a color for
// almost any text, for example 0000ff or chucknorris. nil means that
// the attribute has no effect.
func legacyColor(v string) *rgb {
	v = strings.Trim(v, " \t\n\f\r")
	if v == "" || strings.EqualFold(v, "transparent") {
		return nil
	}
	if n, ok := namedColors[strings.ToLower(v)]; ok {
		return &rgb{r: int(n >> 16), g: int(n >> 8 & 0xff), b: int(n & 0xff), ok: true}
	}
	if len(v) == 4 && v[0] == '#' && isHex(rune(v[1])) && isHex(rune(v[2])) && isHex(rune(v[3])) {
		c := parseColor(strings.ToLower(v), false)
		return &c
	}
	var rs []rune
	for _, r := range v {
		if r > 0xffff {
			rs = append(rs, '0', '0')
		} else {
			rs = append(rs, r)
		}
	}
	if len(rs) > 128 {
		rs = rs[:128]
	}
	if rs[0] == '#' {
		rs = rs[1:]
	}
	for i, r := range rs {
		if !isHex(r) {
			rs[i] = '0'
		}
	}
	for len(rs) == 0 || len(rs)%3 != 0 {
		rs = append(rs, '0')
	}
	n := len(rs) / 3
	comp := [3]string{string(rs[:n]), string(rs[n : 2*n]), string(rs[2*n:])}
	if n > 8 {
		for i := range comp {
			comp[i] = comp[i][n-8:]
		}
		n = 8
	}
	for n > 2 && comp[0][0] == '0' && comp[1][0] == '0' && comp[2][0] == '0' {
		for i := range comp {
			comp[i] = comp[i][1:]
		}
		n--
	}
	var c [3]int
	for i := range comp {
		if n > 2 {
			comp[i] = comp[i][:2]
		}
		x, _ := strconv.ParseUint(comp[i], 16, 8)
		c[i] = int(x)
	}
	return &rgb{r: c[0], g: c[1], b: c[2], ok: true}
}

// backgroundImages are the CSS functions that give a background image.
var backgroundImages = []string{"url(", "gradient(", "image-set(", "image(", "element(", "cross-fade(", "paint("}

// backgroundWords are the keywords of the background shorthand that
// are not a color or an image.
var backgroundWords = map[string]bool{
	"none": true, "repeat": true, "repeat-x": true, "repeat-y": true,
	"no-repeat": true, "space": true, "round": true, "scroll": true,
	"fixed": true, "local": true, "left": true, "right": true, "top": true,
	"bottom": true, "center": true, "cover": true, "contain": true,
	"auto": true, "border-box": true, "padding-box": true,
	"content-box": true, "text": true, "border-area": true,
}

// parseBackground reads the background shorthand. An image makes the
// background unknown. With no color, the element takes the background
// of its parent. A field that it cannot read makes the background
// bad: text on it counts as hidden (fail closed).
func parseBackground(v string, quirks bool) *rgb {
	switch v {
	case "inherit", "initial", "unset", "revert", "revert-layer":
		return nil
	}
	if hasBackgroundImage(v) {
		return &rgb{}
	}
	var color *rgb
	system := false
	for _, field := range cssFields(v) {
		for _, part := range strings.Split(field, "/") {
			if part == "" || backgroundWords[part] {
				continue
			}
			if systemColors[part] && color == nil && !system {
				system = true
				continue
			}
			if _, ok := evalLength(part, 16, false); ok {
				continue
			}
			c := parseColor(part, quirks)
			switch {
			case c.clear:
				continue
			case c.ok && color == nil:
				color = &c
				continue
			}
			return &rgb{bad: true}
		}
	}
	if system {
		// A system color depends on the mail program: unknown.
		return &rgb{}
	}
	return color
}

// hasBackgroundImage reports whether a background value holds an
// image.
func hasBackgroundImage(v string) bool {
	for _, img := range backgroundImages {
		if strings.Contains(v, img) {
			return true
		}
	}
	return false
}

// parseOpacity reads an opacity: a number or a percentage, clamped to
// 0 to 1. ok is false for a value that is not valid.
func parseOpacity(v string) (float64, bool) {
	if v == "none" {
		return 0, false
	}
	a, ok := cssNumber(v, 1)
	if !ok {
		return 0, false
	}
	return max(0, min(1, a)), true
}

// filterFuncs are the CSS filter functions a browser accepts in a
// filter value, other than "none" (DRV.13). A value that is not one of
// these, in a space-separated list, is not valid CSS: the browser
// drops the whole declaration and keeps the property's earlier value.
var filterFuncs = []string{
	"blur(", "brightness(", "contrast(", "drop-shadow(", "grayscale(",
	"hue-rotate(", "invert(", "opacity(", "saturate(", "sepia(", "url(",
}

// filterOpacity gives the product of the arguments of each opacity()
// function in a filter value, with the rules of [parseOpacity]
// (DRV.13). A filter list applies each function in turn, so
// "opacity(1) opacity(0)" hides the text. A value with no opacity()
// gives 1. ok is false when the value is not "none" and not a
// space-separated list of known filter functions, when an opacity()
// argument is not valid, or when a function never closes: the browser
// then drops the whole declaration and the caller must keep the
// previous filter state rather than replace it with 1.
func filterOpacity(v string) (float64, bool) {
	v = strings.TrimSpace(v)
	if v == "none" {
		return 1, true
	}
	alpha := 1.0
	for {
		v = strings.TrimSpace(v)
		if v == "" {
			return alpha, true
		}
		name := matchFilterFunc(v)
		if name == "" {
			return 0, false // not a known filter function: not valid
		}
		start := len(name)
		depth := 1
		j := start
		for j < len(v) && depth > 0 {
			switch v[j] {
			case '(':
				depth++
			case ')':
				depth--
			}
			j++
		}
		if depth != 0 {
			return 0, false // the function never closes: not valid
		}
		if name == "opacity(" {
			a, ok := parseOpacity(strings.TrimSpace(v[start : j-1]))
			if !ok {
				return 0, false
			}
			alpha *= a
		}
		v = v[j:]
	}
}

// matchFilterFunc gives the filterFuncs entry v starts with, or "" if
// v starts with none of them.
func matchFilterFunc(v string) string {
	for _, fn := range filterFuncs {
		if strings.HasPrefix(v, fn) {
			return fn
		}
	}
	return ""
}

// systemColors are the CSS system color keywords, with the deprecated
// ones. The mail program gives their value. As a text color, each one
// is the page text color and stays visible (D4.1). As a background,
// each one is unknown.
var systemColors = map[string]bool{
	"accentcolor": true, "accentcolortext": true, "activetext": true,
	"buttonborder": true, "buttonface": true, "buttontext": true,
	"canvas": true, "canvastext": true, "field": true, "fieldtext": true,
	"graytext": true, "highlight": true, "highlighttext": true,
	"linktext": true, "mark": true, "marktext": true,
	"selecteditem": true, "selecteditemtext": true, "visitedtext": true,
	"activeborder": true, "activecaption": true, "appworkspace": true,
	"background": true, "buttonhighlight": true, "buttonshadow": true,
	"captiontext": true, "inactiveborder": true, "inactivecaption": true,
	"inactivecaptiontext": true, "infobackground": true, "infotext": true,
	"menu": true, "menutext": true, "scrollbar": true,
	"threeddarkshadow": true, "threedface": true, "threedhighlight": true,
	"threedlightshadow": true, "threedshadow": true, "window": true,
	"windowframe": true, "windowtext": true,
}

// minAlpha is the lowest alpha that shows text. Text with less alpha
// counts as transparent.
const minAlpha = 0.1

// parseColor reads a CSS color: a named color, transparent, #rgb,
// #rrggbb (and the forms with alpha), rgb()/rgba() with numbers or
// percentages, and hsl()/hsla(). A hex value with no # is read only
// in quirks mode, as browsers do. Any other value gives an unknown
// color.
func parseColor(v string, quirks bool) rgb {
	if v == "transparent" {
		return rgb{clear: true}
	}
	if n, ok := namedColors[v]; ok {
		return rgb{r: int(n >> 16), g: int(n >> 8 & 0xff), b: int(n & 0xff), ok: true}
	}
	if quirks && (len(v) == 3 || len(v) == 6) && strings.IndexFunc(v, func(r rune) bool { return !isHex(r) }) < 0 {
		v = "#" + v
	}
	if strings.HasPrefix(v, "#") {
		h := v[1:]
		alpha := "ff"
		switch len(h) {
		case 4:
			alpha = h[3:] + h[3:]
			h = h[:3]
			fallthrough
		case 3:
			h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
		case 8:
			alpha = h[6:]
			h = h[:6]
		case 6:
		default:
			return rgb{}
		}
		n, err := strconv.ParseUint(h, 16, 32)
		a, errA := strconv.ParseUint(alpha, 16, 8)
		if err != nil || errA != nil {
			return rgb{}
		}
		if float64(a)/255 < minAlpha {
			return rgb{clear: true}
		}
		return rgb{r: int(n >> 16 & 0xff), g: int(n >> 8 & 0xff), b: int(n & 0xff), ok: true}
	}
	fn, in, ok := strings.Cut(v, "(")
	if !ok || !strings.HasSuffix(in, ")") {
		return rgb{}
	}
	parts, legacy := colorArgs(strings.TrimSuffix(in, ")"))
	if parts == nil {
		return rgb{}
	}
	if legacy && contains(parts, "none") {
		return rgb{}
	}
	if len(parts) == 4 {
		a, ok := cssNumber(parts[3], 1)
		if !ok {
			return rgb{}
		}
		if a < minAlpha {
			return rgb{clear: true}
		}
	}
	var c [3]float64
	switch fn {
	case "rgb", "rgba":
		if legacy && (strings.HasSuffix(parts[0], "%") != strings.HasSuffix(parts[1], "%") ||
			strings.HasSuffix(parts[0], "%") != strings.HasSuffix(parts[2], "%")) {
			return rgb{} // the comma form does not mix numbers and percentages
		}
		for i := range c {
			n, ok := cssNumber(parts[i], 255)
			if !ok {
				return rgb{}
			}
			c[i] = n
		}
	case "hsl", "hsla":
		if legacy && (!strings.HasSuffix(parts[1], "%") || !strings.HasSuffix(parts[2], "%")) {
			return rgb{} // the comma form needs percentages
		}
		h, okH := cssHue(parts[0])
		s, okS := cssNumber(strings.TrimSuffix(parts[1], "%"), 1)
		l, okL := cssNumber(strings.TrimSuffix(parts[2], "%"), 1)
		if !okH || !okS || !okL {
			return rgb{}
		}
		c = hslToRGB(h, s/100, l/100)
	default:
		return rgb{}
	}
	for i := range c {
		c[i] = math.Round(min(255, max(0, c[i])))
	}
	return rgb{r: int(c[0]), g: int(c[1]), b: int(c[2]), ok: true}
}

// colorArgs splits the arguments of rgb() or hsl() into 3 or 4 parts.
// The comma form (legacy true) has 3 or 4 parts with commas between
// them. The space form has 3 parts, then an optional "/" and the
// alpha. nil means that the arguments are not valid.
func colorArgs(in string) (parts []string, legacy bool) {
	if strings.Contains(in, ",") {
		parts = strings.Split(in, ",")
		for i, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" || strings.ContainsAny(p, " \t\n\r\f/") {
				return nil, true
			}
			parts[i] = p
		}
		if len(parts) != 3 && len(parts) != 4 {
			return nil, true
		}
		return parts, true
	}
	main, alpha, slash := strings.Cut(in, "/")
	parts = strings.Fields(main)
	if len(parts) != 3 {
		return nil, false
	}
	if slash {
		a := strings.Fields(alpha)
		if len(a) != 1 || strings.Contains(a[0], "/") {
			return nil, false
		}
		parts = append(parts, a[0])
	}
	return parts, false
}

// cssNumber reads a number, or a percentage of full. none is 0.
func cssNumber(s string, full float64) (float64, bool) {
	if s == "none" {
		return 0, true
	}
	pct := strings.HasSuffix(s, "%")
	p := calcParser{s: strings.TrimSuffix(s, "%")}
	n, ok := p.number()
	if !ok || p.i != len(p.s) {
		return 0, false
	}
	if pct {
		n = n / 100 * full
	}
	return n, true
}

// cssHue reads a hue in degrees. The units deg, grad, rad and turn are
// read.
func cssHue(s string) (float64, bool) {
	units := []struct {
		suffix string
		deg    float64
	}{{"deg", 1}, {"grad", 0.9}, {"rad", 180 / math.Pi}, {"turn", 360}}
	f := 1.0
	for _, u := range units {
		if rest, ok := strings.CutSuffix(s, u.suffix); ok {
			s, f = rest, u.deg
			break
		}
	}
	n, ok := cssNumber(s, 0)
	if !ok || strings.HasSuffix(s, "%") {
		return 0, false
	}
	return n * f, true
}

// hslToRGB gives the rgb values (0 to 255) of a hue in degrees and a
// saturation and lightness from 0 to 1.
func hslToRGB(h, s, l float64) [3]float64 {
	s = min(1, max(0, s))
	l = min(1, max(0, l))
	h = math.Mod(h, 360)
	if h < 0 {
		h += 360
	}
	a := s * min(l, 1-l)
	f := func(n float64) float64 {
		k := math.Mod(n+h/30, 12)
		return 255 * (l - a*max(-1, min(k-3, 9-k, 1)))
	}
	return [3]float64{f(0), f(8), f(4)}
}

// namedColors is the CSS table of named colors, as 0xrrggbb.
var namedColors = map[string]uint32{
	"aliceblue": 0xf0f8ff, "antiquewhite": 0xfaebd7, "aqua": 0x00ffff,
	"aquamarine": 0x7fffd4, "azure": 0xf0ffff, "beige": 0xf5f5dc,
	"bisque": 0xffe4c4, "black": 0x000000, "blanchedalmond": 0xffebcd,
	"blue": 0x0000ff, "blueviolet": 0x8a2be2, "brown": 0xa52a2a,
	"burlywood": 0xdeb887, "cadetblue": 0x5f9ea0, "chartreuse": 0x7fff00,
	"chocolate": 0xd2691e, "coral": 0xff7f50, "cornflowerblue": 0x6495ed,
	"cornsilk": 0xfff8dc, "crimson": 0xdc143c, "cyan": 0x00ffff,
	"darkblue": 0x00008b, "darkcyan": 0x008b8b, "darkgoldenrod": 0xb8860b,
	"darkgray": 0xa9a9a9, "darkgreen": 0x006400, "darkgrey": 0xa9a9a9,
	"darkkhaki": 0xbdb76b, "darkmagenta": 0x8b008b, "darkolivegreen": 0x556b2f,
	"darkorange": 0xff8c00, "darkorchid": 0x9932cc, "darkred": 0x8b0000,
	"darksalmon": 0xe9967a, "darkseagreen": 0x8fbc8f, "darkslateblue": 0x483d8b,
	"darkslategray": 0x2f4f4f, "darkslategrey": 0x2f4f4f, "darkturquoise": 0x00ced1,
	"darkviolet": 0x9400d3, "deeppink": 0xff1493, "deepskyblue": 0x00bfff,
	"dimgray": 0x696969, "dimgrey": 0x696969, "dodgerblue": 0x1e90ff,
	"firebrick": 0xb22222, "floralwhite": 0xfffaf0, "forestgreen": 0x228b22,
	"fuchsia": 0xff00ff, "gainsboro": 0xdcdcdc, "ghostwhite": 0xf8f8ff,
	"gold": 0xffd700, "goldenrod": 0xdaa520, "gray": 0x808080,
	"green": 0x008000, "greenyellow": 0xadff2f, "grey": 0x808080,
	"honeydew": 0xf0fff0, "hotpink": 0xff69b4, "indianred": 0xcd5c5c,
	"indigo": 0x4b0082, "ivory": 0xfffff0, "khaki": 0xf0e68c,
	"lavender": 0xe6e6fa, "lavenderblush": 0xfff0f5, "lawngreen": 0x7cfc00,
	"lemonchiffon": 0xfffacd, "lightblue": 0xadd8e6, "lightcoral": 0xf08080,
	"lightcyan": 0xe0ffff, "lightgoldenrodyellow": 0xfafad2, "lightgray": 0xd3d3d3,
	"lightgreen": 0x90ee90, "lightgrey": 0xd3d3d3, "lightpink": 0xffb6c1,
	"lightsalmon": 0xffa07a, "lightseagreen": 0x20b2aa, "lightskyblue": 0x87cefa,
	"lightslategray": 0x778899, "lightslategrey": 0x778899, "lightsteelblue": 0xb0c4de,
	"lightyellow": 0xffffe0, "lime": 0x00ff00, "limegreen": 0x32cd32,
	"linen": 0xfaf0e6, "magenta": 0xff00ff, "maroon": 0x800000,
	"mediumaquamarine": 0x66cdaa, "mediumblue": 0x0000cd, "mediumorchid": 0xba55d3,
	"mediumpurple": 0x9370db, "mediumseagreen": 0x3cb371, "mediumslateblue": 0x7b68ee,
	"mediumspringgreen": 0x00fa9a, "mediumturquoise": 0x48d1cc, "mediumvioletred": 0xc71585,
	"midnightblue": 0x191970, "mintcream": 0xf5fffa, "mistyrose": 0xffe4e1,
	"moccasin": 0xffe4b5, "navajowhite": 0xffdead, "navy": 0x000080,
	"oldlace": 0xfdf5e6, "olive": 0x808000, "olivedrab": 0x6b8e23,
	"orange": 0xffa500, "orangered": 0xff4500, "orchid": 0xda70d6,
	"palegoldenrod": 0xeee8aa, "palegreen": 0x98fb98, "paleturquoise": 0xafeeee,
	"palevioletred": 0xdb7093, "papayawhip": 0xffefd5, "peachpuff": 0xffdab9,
	"peru": 0xcd853f, "pink": 0xffc0cb, "plum": 0xdda0dd,
	"powderblue": 0xb0e0e6, "purple": 0x800080, "rebeccapurple": 0x663399,
	"red": 0xff0000, "rosybrown": 0xbc8f8f, "royalblue": 0x4169e1,
	"saddlebrown": 0x8b4513, "salmon": 0xfa8072, "sandybrown": 0xf4a460,
	"seagreen": 0x2e8b57, "seashell": 0xfff5ee, "sienna": 0xa0522d,
	"silver": 0xc0c0c0, "skyblue": 0x87ceeb, "slateblue": 0x6a5acd,
	"slategray": 0x708090, "slategrey": 0x708090, "snow": 0xfffafa,
	"springgreen": 0x00ff7f, "steelblue": 0x4682b4, "tan": 0xd2b48c,
	"teal": 0x008080, "thistle": 0xd8bfd8, "tomato": 0xff6347,
	"turquoise": 0x40e0d0, "violet": 0xee82ee, "wheat": 0xf5deb3,
	"white": 0xffffff, "whitesmoke": 0xf5f5f5, "yellow": 0xffff00,
	"yellowgreen": 0x9acd32,
}
