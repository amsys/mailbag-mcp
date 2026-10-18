// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// AttachmentIn is the input of the attachment tool (App B).
type AttachmentIn struct {
	Account string `json:"account"`
	ID      string `json:"id"`
	Ref     string `json:"ref" jsonschema:"file name or part id from read"`
	SaveDir string `json:"save_dir,omitempty" jsonschema:"default ~/Downloads/mailbag-mcp"`
}

// AttachmentOut is the attachment tool result: the path and the size,
// never the content (§3.15).
//
// Path is fenced. §3.15 lists an attachment file name as
// sender-controlled, and the file name is the last part of this path,
// so the whole value is sender-influenced text (G3).
type AttachmentOut struct {
	Account string `json:"account"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
}

// AddAttachment adds the "attachment" tool to srv (§3.16): read
// level, one part of one message, written to a permitted save root.
//
// The tool claims no annotation. §3.16 names ReadOnlyHint for
// accounts, search and read, and DestructiveHint for modify. This
// tool is neither, and the JSON of every hint counts against the 8 KB
// budget of §9 U7: the SDK writes readOnlyHint and idempotentHint in
// full as soon as one annotation is set. A client that asks before a
// write is the safe answer here, because this tool does write a file.
//
// It gets LongTimeout, because a download can outrun the default
// deadline (§3.1).
//
// arch: T4.5, T5.4, §3.16, §3.15, §9 U7, App B, G3, G6, §10.9
func AddAttachment(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &attachmentTool{mail: m}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "attachment",
		Description: "Save one attachment to disk, never its content.",
	}, Wrap(logger, "attachment", LongTimeout, h.handle))
}

type attachmentTool struct{ mail Mail }

// handle downloads one attachment and writes it into a permitted save
// root.
//
// The file name comes from the sender, so it goes through
// [guard.SaveName] and the file is created through
// [guard.CreateSaveFile], which opens it under an os.Root and refuses
// a symbolic link on every path component (G6). The caller's save_dir
// never reaches os.Open on its own.
//
// The copy stops at [guard.MaxAttachBytes]. The IMAP provider already
// caps its own fetch, but this tool must not trust a provider to have
// done so before it writes bytes to a disk.
//
// arch: T4.5, §3.16, §3.15, App B, G3, G6, §10.9
func (t *attachmentTool) handle(ctx context.Context, in AttachmentIn) (AttachmentOut, error) {
	p, _, err := t.mail.Open(ctx, in.Account)
	if err != nil {
		return AttachmentOut{}, err
	}
	if in.ID == "" || in.Ref == "" {
		return AttachmentOut{}, errors.New("id and ref are required; take both from a read result")
	}
	dir, roots, err := saveTarget(in.SaveDir, t.mail.DownloadDirs()...)
	if err != nil {
		return AttachmentOut{}, err
	}

	rc, info, err := p.Attachment(ctx, in.ID, in.Ref)
	if err != nil {
		return AttachmentOut{}, fencedErr{kind: "ATTACHMENT", err: err}
	}
	defer func() { _ = rc.Close() }()

	name := info.Filename
	if name == "" {
		name = "attachment"
	}
	// A name that the cleanup empties ("..", or hidden characters
	// only) gets the fixed name, as export does (R16-L9).
	safe, err := guard.SaveName(name)
	if err != nil {
		safe = "attachment"
	}
	f, path, err := guard.CreateSaveFile(dir, safe, roots)
	if err != nil {
		return AttachmentOut{}, err
	}

	n, copyErr := io.Copy(f, io.LimitReader(rc, guard.MaxAttachBytes+1))
	closeErr := f.Close()
	switch {
	case copyErr != nil:
		_ = os.Remove(path)
		return AttachmentOut{}, copyErr
	case closeErr != nil:
		_ = os.Remove(path)
		return AttachmentOut{}, closeErr
	case n > guard.MaxAttachBytes:
		_ = os.Remove(path)
		return AttachmentOut{}, fmt.Errorf("this attachment is larger than the limit of %d MB", guard.MaxAttachBytes>>20)
	}
	return AttachmentOut{Account: in.Account, Path: guard.Fence("PATH", path), Size: n}, nil
}

// saveTarget resolves the directory a save tool writes into and gives
// back the permitted roots with it (§3.15). An empty dir means
// "~/Downloads/mailbag-mcp", which this function creates when it is
// not there yet.
//
// extraRoots are the download_dirs of accounts.toml. A caller reads
// them from [Mail.DownloadDirs]; a caller that passes none gets the
// two default roots. Both attachment and export pass
// `t.mail.DownloadDirs()...` here (DRV.14b).
//
// arch: T4.5, §3.15, G6, §10.9
func saveTarget(dir string, extraRoots ...string) (string, []string, error) {
	roots, err := guard.DefaultRoots(extraRoots)
	if err != nil {
		return "", nil, err
	}
	if dir == "" {
		dir = roots[0]
	}
	cdir, err := guard.ResolveSaveDir(dir, roots)
	if err != nil {
		return "", nil, err
	}
	// The path is canonical and inside a permitted root by now.
	// CreateSaveFile checks it again and opens under an os.Root, so a
	// component swapped after this line still cannot walk the write
	// out of the root (G6).
	if err := os.MkdirAll(cdir, 0o700); err != nil {
		return "", nil, fmt.Errorf("save dir: %w", err)
	}
	return cdir, roots, nil
}

// fencedErr gives the text of err inside a fence and keeps err for
// errors.Is and errors.As.
//
// A provider error can quote sender text. The IMAP provider names the
// attachments of the message when a ref is not found, and a sender
// chooses those names (§3.15). Only internal/tools fences, so the
// whole error text goes in the fence here, the same as
// AttachmentOut.Path (G3, I10).
//
// arch: D4.1, §3.15, G3, I10
type fencedErr struct {
	kind string
	err  error
}

func (e fencedErr) Error() string { return guard.Fence(e.kind, e.err.Error()) }

func (e fencedErr) Unwrap() error { return e.err }
