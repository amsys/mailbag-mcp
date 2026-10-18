// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the templates tool (DS9.6): the store under the config
// directory, the link rules of IS9.5, the {{key}} fill and the levels
// of G22.

package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// templatesHome points config.ConfigDir at a new temporary directory
// and gives the templates directory under it. Nothing is made there.
func templatesHome(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Setenv("MAILBAG_CONFIG_DIR", base)
	return filepath.Join(base, templatesDirName)
}

// templatesFixture gives a templates tool over the send-test fake
// writer at level send, and the templates directory.
func templatesFixture(t *testing.T) (*templatesTool, *writeProvider, string) {
	t.Helper()
	dir := templatesHome(t)
	h, prov := sendFixture(t, nil)
	return &templatesTool{mail: h.mail}, prov, dir
}

// symlinkOrSkip makes a link, or skips the test where the system
// cannot make one.
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
}

// TestTemplates_SaveReplacesSameName holds the rename rule of DS9.6:
// a second save of one name replaces the first, list shows one row
// with the new subject, a draft gets the new text, and no temporary
// file stays in the directory.
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_SaveReplacesSameName(t *testing.T) {
	h, prov, dir := templatesFixture(t)
	ctx := context.Background()
	for _, s := range []struct{ subject, body string }{
		{"First subject", "first body"},
		{"Second subject", "second body"},
	} {
		if _, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "save", Name: "ooo", Subject: s.subject, Body: s.body}); err != nil {
			t.Fatalf("save %q: %v", s.subject, err)
		}
	}

	out, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "list"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out.Templates) != 1 || out.Templates[0].Name != "ooo" {
		t.Fatalf("list = %+v, want one row ooo", out.Templates)
	}
	if !strings.Contains(out.Templates[0].Subject, "Second subject") || strings.Contains(out.Templates[0].Subject, "First") {
		t.Errorf("subject = %q, want the second save", out.Templates[0].Subject)
	}

	if _, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "draft", Name: "ooo", To: []string{"ann@example.test"}}); err != nil {
		t.Fatalf("draft: %v", err)
	}
	if len(prov.drafts) != 1 || prov.drafts[0].Text != "second body" || prov.drafts[0].Subject != "Second subject" {
		t.Fatalf("drafts = %+v, want one draft with the second text", prov.drafts)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"ooo.md"}) {
		t.Errorf("directory holds %v, want only ooo.md (no temporary file)", names)
	}
}

// TestTemplates_LinkOutOfRootRefused holds IS9.5 on the read side: a
// link in the templates directory that points out of it is never
// read. draft refuses it and saves nothing, and list does not show
// the text of the file outside.
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_LinkOutOfRootRefused(t *testing.T) {
	h, prov, dir := templatesFixture(t)
	ctx := context.Background()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.md")
	if err := os.WriteFile(outside, []byte("Subject: OUTSIDE-SECRET\n\nsecret body"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, outside, filepath.Join(dir, "evil.md"))

	_, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "draft", Name: "evil", To: []string{"ann@example.test"}})
	if err == nil {
		t.Fatal("draft through a link out of the directory: no error")
	}
	if strings.Contains(err.Error(), "OUTSIDE-SECRET") {
		t.Errorf("error %q holds text of the file outside", err)
	}
	if len(prov.drafts) != 0 {
		t.Errorf("SaveDraft ran %d times through a link out of the directory", len(prov.drafts))
	}

	out, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "list"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, r := range out.Templates {
		if strings.Contains(r.Subject, "OUTSIDE-SECRET") {
			t.Errorf("list row %+v holds the subject of the file outside", r)
		}
	}
	if len(out.Templates) != 0 {
		t.Errorf("list = %+v, want no row for the link", out.Templates)
	}
	if !strings.Contains(out.Note, "1 templates could not be read") {
		t.Errorf("note = %q, want the count of skipped files", out.Note)
	}
}

// TestTemplates_SaveDoesNotFollowLink holds IS9.5 on the write side:
// a save over a planted link replaces the link with a regular file
// and never writes into the file the link points to.
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_SaveDoesNotFollowLink(t *testing.T) {
	h, _, dir := templatesFixture(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o644); err != nil { //nolint:gosec // G306: a fixture file in the test temp dir holds no secret
		t.Fatal(err)
	}
	link := filepath.Join(dir, "x.md")
	symlinkOrSkip(t, victim, link)

	if _, err := h.handle(context.Background(), TemplatesIn{Account: "work", Action: "save", Name: "x", Subject: "s", Body: "new body"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := os.ReadFile(victim) //nolint:gosec // G304: test code; the path is built by the test
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Errorf("the link target now holds %q; the save wrote through the link", got)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("x.md mode = %v, want a regular file in place of the link", fi.Mode())
	}
	data, err := os.ReadFile(link) //nolint:gosec // G304: test code; the path is built by the test
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "Subject: s\n\nnew body" {
		t.Errorf("x.md = %q, want the saved template", data)
	}
}

// TestTemplates_Mode0600 holds the modes of IS9.5: the first save
// makes the directory 0700 and every template file is 0600.
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_Mode0600(t *testing.T) {
	h, _, dir := templatesFixture(t)
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("templates directory exists before the first save: %v", err)
	}
	ctx := context.Background()
	for _, name := range []string{"a", "b"} {
		if _, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "save", Name: name, Subject: "s", Body: "b"}); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %o, want 0700", di.Mode().Perm())
	}
	for _, name := range []string{"a.md", "b.md"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 0600", name, fi.Mode().Perm())
		}
	}
}

// TestTemplates_NameMustMatchAlias holds the name rule of DS9.6: a
// name passes config.ValidAlias, so no name holds "/", "." or "..",
// and a refused name writes, reads and removes nothing.
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_NameMustMatchAlias(t *testing.T) {
	h, prov, dir := templatesFixture(t)
	ctx := context.Background()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A file one level up that a "../" name would reach.
	up := filepath.Join(filepath.Dir(dir), "up.md")
	if err := os.WriteFile(up, []byte("Subject: up\n\nup"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".", "..", "../up", "a/b", "a.b", "a b", "ä"} {
		for _, action := range []string{"save", "delete", "draft"} {
			_, err := h.handle(ctx, TemplatesIn{Account: "work", Action: action, Name: name, Subject: "s", Body: "b", To: []string{"ann@example.test"}})
			if err == nil || !strings.Contains(err.Error(), "needs a name") {
				t.Errorf("%s name %q: err = %v, want the name rule", action, name, err)
			}
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("refused names left %d entries in the directory", len(entries))
	}
	if _, err := os.Stat(up); err != nil {
		t.Errorf("a refused delete removed the file above: %v", err)
	}
	if len(prov.drafts) != 0 {
		t.Errorf("a refused name saved %d drafts", len(prov.drafts))
	}
	for _, name := range []string{"ooo", "Out-of_office2"} {
		if _, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "save", Name: name, Subject: "s"}); err != nil {
			t.Errorf("save %q: %v", name, err)
		}
	}
}

// TestTemplates_DraftFillsVars holds DS9.6 and IS9.6 for draft: each
// {{key}} gets its value by literal replacement, a value is not read
// again for keys, the draft tool saves exactly one draft, and nothing
// is sent (S9-GAP9).
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_DraftFillsVars(t *testing.T) {
	h, prov, _ := templatesFixture(t)
	ctx := context.Background()
	if _, err := h.handle(ctx, TemplatesIn{
		Account: "work", Action: "save", Name: "ooo",
		Subject: "Out of office until {{date}}",
		Body:    "Back on {{date}}. Ask {{who}}. {{date}}",
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := h.handle(ctx, TemplatesIn{
		Account: "work", Action: "draft", Name: "ooo",
		To:   []string{"ann@example.test"},
		Cc:   []string{"bob@example.test"},
		Vars: map[string]string{"date": "Monday", "who": "{{date}} $1 Bob"},
	})
	if err != nil {
		t.Fatalf("draft: %v", err)
	}
	if len(prov.sentDrafts) != 0 || len(prov.sent) != 0 {
		t.Fatalf("the templates tool sent mail: SendDraft ran %d times", len(prov.sentDrafts))
	}
	if len(prov.drafts) != 1 {
		t.Fatalf("SaveDraft ran %d times, want 1", len(prov.drafts))
	}
	m := prov.drafts[0]
	if m.Subject != "Out of office until Monday" {
		t.Errorf("subject = %q", m.Subject)
	}
	if want := "Back on Monday. Ask {{date}} $1 Bob. Monday"; m.Text != want {
		t.Errorf("body = %q, want %q", m.Text, want)
	}
	if !slices.Equal(m.To, []string{"ann@example.test"}) || !slices.Equal(m.Cc, []string{"bob@example.test"}) {
		t.Errorf("to = %v, cc = %v, want the caller's recipients", m.To, m.Cc)
	}
	if out.DraftID != prov.draftID {
		t.Errorf("draft_id = %q, want %q", out.DraftID, prov.draftID)
	}
}

// TestTemplates_MissingVarListed holds DS9.6: a {{key}} with no value
// fails the call with every missing key, and no draft is saved.
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_MissingVarListed(t *testing.T) {
	h, prov, _ := templatesFixture(t)
	ctx := context.Background()
	if _, err := h.handle(ctx, TemplatesIn{
		Account: "work", Action: "save", Name: "t",
		Subject: "Hi {{name}}", Body: "On {{date}} at {{time}}, {{name}}.",
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	_, err := h.handle(ctx, TemplatesIn{
		Account: "work", Action: "draft", Name: "t",
		To: []string{"ann@example.test"}, Vars: map[string]string{"time": "10:00"},
	})
	if err == nil {
		t.Fatal("draft with missing vars: no error")
	}
	if !strings.Contains(err.Error(), `"date", "name"`) {
		t.Errorf("err = %q, want the sorted missing keys date and name once each", err)
	}
	if strings.Contains(err.Error(), `"time"`) {
		t.Errorf("err = %q names a key that has a value", err)
	}
	if len(prov.drafts) != 0 {
		t.Errorf("SaveDraft ran %d times with missing vars", len(prov.drafts))
	}
}

// TestTemplates_ListReadsSubjectOnly holds the list rule of DS9.6:
// each row gives the name, the fenced line 1 and the size, sorted by
// name; no body text is in the result; at most 200 rows come back;
// a missing directory is an empty list.
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_ListReadsSubjectOnly(t *testing.T) {
	h, _, dir := templatesFixture(t)
	ctx := context.Background()

	out, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "list"})
	if err != nil || len(out.Templates) != 0 {
		t.Fatalf("list before the first save = %+v, %v; want an empty list", out, err)
	}

	for _, s := range []struct{ name, subject, body string }{
		{"zeta", "Zeta subject", "ZETA-BODY-TEXT"},
		{"alpha", "Alpha subject", "ALPHA-BODY-TEXT\nmore"},
	} {
		if _, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "save", Name: s.name, Subject: s.subject, Body: s.body}); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	// A file that is no template is not listed.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = h.handle(ctx, TemplatesIn{Account: "work", Action: "list"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out.Templates) != 2 || out.Templates[0].Name != "alpha" || out.Templates[1].Name != "zeta" {
		t.Fatalf("list = %+v, want alpha then zeta", out.Templates)
	}
	a := out.Templates[0]
	if a.Subject != guard.Fence("TEMPLATE", "Alpha subject") {
		t.Errorf("subject = %q, want the fenced line 1", a.Subject)
	}
	if want := len("Subject: Alpha subject\n\nALPHA-BODY-TEXT\nmore"); a.Size != want {
		t.Errorf("size = %d, want %d", a.Size, want)
	}
	if s := fmt.Sprintf("%+v", out); strings.Contains(s, "BODY-TEXT") {
		t.Errorf("list result holds body text: %s", s)
	}

	for i := range templatesListMax {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("n%03d.md", i)), []byte("Subject: n\n\nb"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err = h.handle(ctx, TemplatesIn{Account: "work", Action: "list"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out.Templates) != templatesListMax {
		t.Errorf("list gave %d rows, want %d", len(out.Templates), templatesListMax)
	}
	if !strings.Contains(out.Note, "200 of 202 templates shown") {
		t.Errorf("note = %q, want the cut named", out.Note)
	}
}

// TestTemplates_SizeCap holds the 64 KiB cap of DS9.6: a save over
// the cap writes nothing, a save at the cap works, and a larger file
// put in the directory by hand is refused by draft.
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_SizeCap(t *testing.T) {
	h, prov, dir := templatesFixture(t)
	ctx := context.Background()
	head := len("Subject: s\n\n")

	_, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "save", Name: "big", Subject: "s", Body: strings.Repeat("x", templateMaxBytes-head+1)})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("save over the cap: err = %v, want the size refusal", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "big.md")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused save left big.md: %v", err)
	}
	if _, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "save", Name: "full", Subject: "s", Body: strings.Repeat("x", templateMaxBytes-head)}); err != nil {
		t.Fatalf("save at the cap: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "hand.md"), []byte("Subject: s\n\n"+strings.Repeat("y", templateMaxBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = h.handle(ctx, TemplatesIn{Account: "work", Action: "draft", Name: "hand", To: []string{"ann@example.test"}})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("draft of a file over the cap: err = %v, want the size refusal", err)
	}
	if len(prov.drafts) != 0 {
		t.Errorf("SaveDraft ran %d times for a file over the cap", len(prov.drafts))
	}
}

// TestTemplates_Levels holds G22 and G10: list works at read; save,
// delete and draft need draft. A refused call reads, writes and
// removes no template and calls no provider method. An unknown alias
// fails with ErrUnknownAccount before any file work, and delete of a
// missing template names it.
//
// arch: DS9.6, DS9.11, DS9.12, IS9.5, IS9.6
func TestTemplates_Levels(t *testing.T) {
	needDraft := map[string]bool{"list": false, "save": true, "delete": true, "draft": true}
	for _, level := range []guard.Level{guard.LevelRead, guard.LevelDraft, guard.LevelSend} {
		for _, action := range []string{"list", "save", "delete", "draft"} {
			t.Run(string(level)+"/"+action, func(t *testing.T) {
				dir := templatesHome(t)
				if err := saveTemplate(dir, "keep", "Hello {{n}}", "body {{n}}"); err != nil {
					t.Fatal(err)
				}
				fx := newAccessFixture(t, level)
				h := &templatesTool{mail: fx.mail}
				_, err := h.handle(context.Background(), TemplatesIn{
					Account: "work", Action: action, Name: "keep",
					Subject: "changed", To: []string{"ann@example.test"},
					Vars: map[string]string{"n": "1"},
				})
				data, readErr := os.ReadFile(filepath.Join(dir, "keep.md")) //nolint:gosec // G304: test code; the path is built by the test
				denied := level == guard.LevelRead && needDraft[action]
				if denied {
					if !errors.Is(err, guard.ErrAccessDenied) {
						t.Fatalf("err = %v, want ErrAccessDenied", err)
					}
					if readErr != nil || string(data) != "Subject: Hello {{n}}\n\nbody {{n}}" {
						t.Errorf("a refused %s changed the template: %q, %v", action, data, readErr)
					}
					if fx.prov.drafts+fx.prov.sent+fx.prov.mods != 0 {
						t.Errorf("a refused %s reached the provider", action)
					}
					return
				}
				if err != nil {
					t.Fatalf("err = %v, want success", err)
				}
				if fx.prov.sent != 0 {
					t.Errorf("%s sent mail", action)
				}
				switch action {
				case "draft":
					if fx.prov.drafts != 1 {
						t.Errorf("SaveDraft ran %d times, want 1", fx.prov.drafts)
					}
				case "save":
					if string(data) != "Subject: changed\n\n" {
						t.Errorf("saved template = %q", data)
					}
				case "delete":
					if !errors.Is(readErr, os.ErrNotExist) {
						t.Errorf("template still there after delete: %v", readErr)
					}
				}
			})
		}
	}

	t.Run("unknown alias", func(t *testing.T) {
		dir := templatesHome(t)
		fx := newAccessFixture(t, guard.LevelSend)
		h := &templatesTool{mail: fx.mail}
		_, err := h.handle(context.Background(), TemplatesIn{Account: "nobody", Action: "save", Name: "x", Subject: "s"})
		if !errors.Is(err, ErrUnknownAccount) {
			t.Fatalf("err = %v, want ErrUnknownAccount", err)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("an unknown alias made the templates directory: %v", err)
		}
	})

	t.Run("delete missing", func(t *testing.T) {
		templatesHome(t)
		fx := newAccessFixture(t, guard.LevelDraft)
		h := &templatesTool{mail: fx.mail}
		_, err := h.handle(context.Background(), TemplatesIn{Account: "work", Action: "delete", Name: "gone"})
		if err == nil || !strings.Contains(err.Error(), `template "gone" does not exist`) {
			t.Errorf("err = %v, want the missing template named", err)
		}
	})
}
