// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
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

// SavedFile is one file an export wrote. Path is fenced: the file
// name is built from the message id, and a caller can hand this tool
// any id text, so the value is not server data (G3, §3.15).
type SavedFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// ExportOut is the export tool result: paths and sizes, never the
// content (§3.15).
type ExportOut struct {
	Account string      `json:"account"`
	Files   []SavedFile `json:"files"`
	// Note is text this server wrote, never sender text.
	Note string `json:"note,omitempty"`
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
// arch: T4.5, §3.16, §3.15, App B, G3, G6, §10.9
func (t *exportTool) handle(ctx context.Context, in ExportIn) (ExportOut, error) {
	p, _, err := t.mail.Open(ctx, in.Account)
	if err != nil {
		return ExportOut{}, err
	}
	if in.ID == "" {
		return ExportOut{}, errors.New("id is required; take one from a search row")
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "eml"
	}
	if format != "eml" && format != "md" {
		return ExportOut{}, fmt.Errorf("format %q is not known; use eml or md", in.Format)
	}

	out := ExportOut{Account: in.Account, Files: []SavedFile{}}
	ids := []string{in.ID}
	if in.Thread {
		tr, terr := p.Thread(ctx, in.ID)
		if terr != nil {
			out.Note = addNote(out.Note, "the conversation could not be read; only the message itself is exported: "+guard.Redact(terr.Error()))
		} else {
			ids = threadIDs(tr.Messages, in.ID)
			if len(tr.Messages) >= threadCutAt {
				out.Note = addNote(out.Note, "the conversation may be longer than "+strconv.Itoa(threadCutAt)+" messages; only the newest "+strconv.Itoa(threadCutAt)+" were exported")
			}
			// The same count-only folder note as read gives (DR1G.4,
			// I14). Export writes each message in full and shows no
			// preview, so it gives no previews note (DR1G.18.3).
			if tr.Skipped > 0 {
				out.Note = addNote(out.Note, skippedFoldersNote(tr.Skipped))
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
		path, err := writeSaved(dir, roots, fileNameOf(id, format), data)
		if err != nil {
			return ExportOut{}, err
		}
		out.Files = append(out.Files, SavedFile{Path: guard.Fence("PATH", path), Size: int64(len(data))})
	}
	return out, nil
}

// threadIDs lists the ids of a conversation, with the message the
// caller named always in it.
func threadIDs(list []*mail.Message, id string) []string {
	ids := make([]string, 0, len(list)+1)
	found := false
	for _, m := range list {
		if m == nil || m.ID == "" {
			continue
		}
		if m.ID == id {
			found = true
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
