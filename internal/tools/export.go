// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// threadCutAt is the conversation size the IMAP provider's own thread
// search caps at (§3.10, internal/imap/thread.go maxThread). Neither
// read nor export can see whether a longer conversation was really
// cut to this size or happened to have exactly this many messages, so
// both give a note on that size, best effort (DRV.16d).
const threadCutAt = 50

// ExportIn is the input of the export tool (App B).
type ExportIn struct {
	Account string `json:"account"`
	ID      string `json:"id"`
	Thread  bool   `json:"thread,omitempty"`
	Format  string `json:"format,omitempty" jsonschema:"eml (default) or md"`
	SaveDir string `json:"save_dir,omitempty" jsonschema:"default ~/Downloads/mailbag-mcp"`
}

// SavedFile is one file an export wrote. Dir is outside: the save
// root (kind owner). The file name is built from the message id, and
// a provider can give any id text, so it is under Untrusted in one
// fence (DU5.6, G3, §3.15).
//
// arch: DU5.1, DU5.6
type SavedFile struct {
	Dir       string              `json:"dir" strict:"owner"`
	Size      int64               `json:"size"`
	Untrusted AttachmentUntrusted `json:"untrusted"`
}

// ExportOut is the export tool result: save directories, file names
// and sizes, never the content (§3.15). Note is text this server
// wrote, checked against the note registry. The error text of a
// thread that could not be read is in Untrusted.Detail (DU3.5).
//
// arch: DU5.1, DU5.6
type ExportOut struct {
	Head
	Account   string      `json:"account" strict:"alias"`
	Files     []SavedFile `json:"files"`
	Note      string      `json:"note,omitempty" strict:"note"`
	Untrusted *Detail     `json:"untrusted,omitempty"`
}

// AddExport adds the "export" tool to srv (§3.16): read level, one
// message or one conversation, written to a permitted save root.
//
// Like attachment, this tool writes a file and claims no annotation.
// See AddAttachment for the reason (§3.16, §9 U7).
//
// The format list stays on the format property and leaves the tool
// text, which said it twice.
//
// arch: T4.5, T5.4, §3.16, §3.15, §9 U7, App B, G3, G6, §10.9
func AddExport(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &exportTool{mail: m}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "export",
		Description: "Save a message or conversation to disk.",
	}, Wrap(logger, "export", LongTimeout, h.handle))
}

type exportTool struct{ mail Mail }

// handle writes one file for each message of the export.
//
// Every file is created through [guard.CreateSaveFile] under a
// permitted root (G6), and the result gives the path and the size
// only, never the content (§3.15).
//
// arch: T4.5, §3.16, §3.15, App B, G3, G6, §10.9, DU5.1, DU5.6, DU3.2
func (t *exportTool) handle(ctx context.Context, in ExportIn) (ExportOut, error) {
	f := fencer(ctx)
	p, acct, err := t.mail.Open(ctx, in.Account)
	if err != nil {
		return ExportOut{}, err
	}
	if in.ID == "" {
		return ExportOut{}, public("invalid_input", "id is required; take one from a search row")
	}
	if _, ok := normalizeID(acct.Provider, in.ID); !ok {
		return ExportOut{}, public("invalid_input", "id is not a valid message id; take one from a search row")
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "eml"
	}
	if format != "eml" && format != "md" {
		return ExportOut{}, publicDetail("invalid_input", "format is not known; use eml or md", in.Format)
	}

	out := ExportOut{Account: in.Account, Files: []SavedFile{}}
	ids := []string{in.ID}
	var details []string
	if in.Thread {
		tr, terr := p.Thread(ctx, in.ID)
		if terr != nil {
			// The note gives the class word; the error text goes
			// to the detail (DU3.5).
			out.Note = joinNote(out.Note, "the conversation could not be read")
			out.Note = joinNote(out.Note, "only the message itself is exported: "+classOf(terr))
			details = append(details, "conversation: "+terr.Error())
		} else {
			ids = threadIDs(acct.Provider, tr.Messages, in.ID)
			if len(tr.Messages) >= threadCutAt {
				out.Note = joinNote(out.Note, "the conversation may be longer than "+strconv.Itoa(threadCutAt)+" messages")
				out.Note = joinNote(out.Note, "only the newest "+strconv.Itoa(threadCutAt)+" were exported")
			}
			// The same count-only folder note as read gives (DR1G.4,
			// I14). Export writes each message in full and shows no
			// preview, so it gives no previews note (DR1G.18.3).
			if tr.Skipped > 0 {
				out.Note = joinNote(out.Note, skippedFoldersNote(tr.Skipped))
			}
		}
	}

	dir, roots, err := saveTarget(in.SaveDir, t.mail.DownloadDirs()...)
	if err != nil {
		return ExportOut{}, err
	}
	for _, id := range ids {
		data, err := renderExport(ctx, p, id, format)
		if err != nil {
			return ExportOut{}, err
		}
		name := "message." + format
		if norm, ok := normalizeID(acct.Provider, id); ok {
			name = fileNameOf(norm, format)
		}
		path, err := writeSaved(dir, roots, name, data)
		if err != nil {
			return ExportOut{}, err
		}
		out.Files = append(out.Files, SavedFile{
			Dir:       dir,
			Size:      int64(len(data)),
			Untrusted: AttachmentUntrusted{Name: f.Wrap(filepath.Base(path))},
		})
	}
	out.Untrusted = noteDetail(f, details)
	return out, nil
}

// threadIDs lists the ids of a conversation, with the message the
// caller named always in it.
//
// An id of the same message in the old and the new form counts once
// (DU3.2). An id that does not pass normalizeID is kept, and its file
// gets the fixed name.
func threadIDs(kind string, list []*mail.Message, id string) []string {
	ids := make([]string, 0, len(list)+1)
	found := false
	want, wantOK := normalizeID(kind, id)
	for _, m := range list {
		if m == nil || m.ID == "" {
			continue
		}
		got, ok := normalizeID(kind, m.ID)
		if m.ID == id || (ok && wantOK && got == want) {
			if found {
				continue
			}
			found = true
			ids = append(ids, id)
			continue
		}
		ids = append(ids, m.ID)
	}
	if !found {
		ids = append(ids, id)
	}
	return ids
}

// renderExport builds the bytes of one exported file. "eml" is the
// RFC 822 source as the server holds it; "md" is a short markdown
// page for a person to read.
func renderExport(ctx context.Context, p Reader, id, format string) ([]byte, error) {
	if format == "eml" {
		return p.Raw(ctx, id)
	}
	m, err := p.Read(ctx, id, mail.ReadOpts{})
	if err != nil {
		return nil, err
	}
	return []byte(markdownOf(*m)), nil
}

// markdownOf writes one message as markdown.
//
// The text is not fenced: a fence belongs to a tool result that a
// model reads (§3.15), and this text goes to a file for a person. The
// hidden characters still go, because a file is pasted back into a
// chat more often than anybody plans.
func markdownOf(m mail.Message) string {
	var b strings.Builder
	b.WriteString("# " + oneLine(m.Subject) + "\n\n")
	b.WriteString("- from: " + oneLine(addressText(m.From)) + "\n")
	if len(m.To) > 0 {
		b.WriteString("- to: " + oneLine(addressListText(m.To)) + "\n")
	}
	if len(m.Cc) > 0 {
		b.WriteString("- cc: " + oneLine(addressListText(m.Cc)) + "\n")
	}
	b.WriteString("- date: " + m.Date.UTC().Format(time.RFC3339) + "\n")
	b.WriteString("- id: " + oneLine(m.ID) + "\n")
	for _, a := range m.Attachments {
		b.WriteString("- attachment: " + oneLine(a.Filename) + " (" + oneLine(a.ContentType) + ", " + strconv.FormatInt(a.Size, 10) + " bytes)\n")
	}
	b.WriteString("\n" + m.Body + "\n")
	clean, _ := guard.StripInvisible(b.String())
	return clean
}

// oneLine puts a value on one line, so a subject with a line break
// cannot make a second markdown heading.
func oneLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// fileNameOf builds the file name of one exported message. It comes
// from the message id, not from the subject, so no sender text picks
// a name on disk. The separators go first, because the id carries a
// folder name and path.Base inside guard.SaveName would otherwise
// keep the last part of it alone.
func fileNameOf(id, format string) string {
	flat := strings.NewReplacer("/", "_", `\`, "_").Replace(id)
	name, err := guard.SaveName(flat + "." + format)
	if err != nil {
		return "message." + format
	}
	return name
}

// writeSaved creates name under dir and writes data to it.
func writeSaved(dir string, roots []string, name string, data []byte) (string, error) {
	f, path, err := guard.CreateSaveFile(dir, name, roots)
	if err != nil {
		return "", err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", errors.Join(writeErr, closeErr)
	}
	return path, nil
}
