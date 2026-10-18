// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// TestExport_ThreadSkippedNote holds DR1G.4 and DR1G.18.10: export
// moved to mail.ThreadResult the same way read did, and gives the
// same count-only note when the thread search could not check every
// folder. The note never names a folder (I14).
//
// arch: DR1G.4, DR1G.5, DR1G.18
func TestExport_ThreadSkippedNote(t *testing.T) {
	dir := t.TempDir()
	m := &mail.Message{ID: "1700000000.4211.INBOX", Folder: "INBOX",
		From: mail.Address{Address: "ann@example.test"}, Subject: "report", Body: "body text"}
	prov := &readProvider{
		msg:           m,
		raw:           []byte("From: ann\r\n\r\nbody\r\n"),
		thread:        []*mail.Message{m},
		threadSkipped: 2,
	}
	fm := &readMail{alias: "work", prov: prov, dirs: []string{dir}}
	h := &exportTool{mail: fm}

	out, err := h.handle(context.Background(), ExportIn{Account: "work", ID: m.ID, Thread: true, SaveDir: dir})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	const want = "2 folder(s) could not be searched; the conversation may be incomplete"
	if !strings.Contains(out.Note, want) {
		t.Errorf("Note = %q, want it to hold %q", out.Note, want)
	}
	if len(out.Files) != 1 {
		t.Fatalf("Files = %v, want one entry", out.Files)
	}
}

// TestExport_NoPreviewsNote checks that export gives no "previews are
// missing" note. Export writes each message in full and shows no
// preview, so the note would name data that export never holds. read
// keeps the note, because its thread rows show the previews.
//
// arch: DR1G.18.3, R16-M7
func TestExport_NoPreviewsNote(t *testing.T) {
	dir := t.TempDir()
	m := &mail.Message{ID: "1700000000.4211.INBOX", Folder: "INBOX",
		From: mail.Address{Address: "ann@example.test"}, Subject: "report", Body: "body text"}
	prov := &readProvider{
		msg:                   m,
		raw:                   []byte("From: ann\r\n\r\nbody\r\n"),
		thread:                []*mail.Message{m},
		threadPreviewsMissing: 3,
	}
	fm := &readMail{alias: "work", prov: prov, dirs: []string{dir}}
	h := &exportTool{mail: fm}

	out, err := h.handle(context.Background(), ExportIn{Account: "work", ID: m.ID, Thread: true, SaveDir: dir})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if strings.Contains(out.Note, "preview") {
		t.Errorf("Note = %q, want no previews note", out.Note)
	}
}
