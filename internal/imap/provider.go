// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/amsys/mailbag-mcp/internal/mime"
)

// Limits of the read path.
const (
	// maxPartBytes caps every part fetch, before the bytes leave the
	// socket. The value is mime.MaxPartBytes, so the read tool caps a
	// part of the signed entity at the same size (§3.10, DRV.3).
	maxPartBytes = mime.MaxPartBytes

	// previewPlainBytes is the preview window of §3.10 for a
	// text/plain part.
	previewPlainBytes int64 = 2048

	// previewHTMLBytes is the preview window for a message that has
	// an HTML part only. An HTML newsletter starts with a <style>
	// head that is often longer than 2048 bytes, and a 2048-byte
	// window then decodes to an empty preview. 16 KB reaches the
	// first words of the body text. A text/plain part keeps the
	// smaller window, because its first bytes are already the text.
	previewHTMLBytes int64 = 16384

	// previewRows is how many of the newest rows get a preview
	// (§3.10).
	previewRows = 10

	// statusBatch is how many STATUS commands go out together when
	// the server has no LIST-STATUS (C23).
	statusBatch = 8

	// defaultLimit and maxLimit bound one search page (§3.16).
	defaultLimit = 20
	maxLimit     = 100

	// candidateLimit is how many rows a search fetches when a filter
	// runs in the client (has:attachment, an exact since time). The
	// server cannot apply those, so the page comes out of a larger
	// window (§3.9, §3.10).
	candidateLimit = 500

	// scanLimit is how many envelopes the non-ASCII fallback reads
	// (§3.9, C7).
	scanLimit = 1000
)

// ErrStaleID is the error of C4: the server built the folder again,
// so every id that holds the old UIDVALIDITY points at nothing.
var ErrStaleID = errors.New("stale id: the server rebuilt this folder; search again")

// Provider reads one IMAP account through the pool. Every command
// runs inside Pool.WithRead or Pool.WithWrite, so the folder state of
// the connection stays in step with the commands (§3.10).
//
// arch: T4.3, §3.7, §3.10
type Provider struct {
	alias string
	pool  *Pool
}

// New makes a provider for one account alias.
//
// arch: T4.3, §3.7, §3.10
func New(alias string, pool *Pool) *Provider {
	return &Provider{alias: alias, pool: pool}
}

// Close returns nil. The pool owns the connections and closes them at
// shutdown (§3.1 step 7).
func (p *Provider) Close() error { return nil }

// examine opens folder read only. C3: SELECT can set \Recent and
// change server state, so every read uses EXAMINE.
//
// It sends the command each time, also when the folder is already
// open. The answer carries UIDVALIDITY, and every read compares that
// number against the id it was given (C4). One round trip is a small
// price for a check that stops a read of the wrong message.
//
// arch: T4.3, §3.10, C3, C4
func examine(c *Conn, folder string) (*imap.SelectData, error) {
	data, err := c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		c.Selected = ""
		return nil, fmt.Errorf("imap: examine %q: %w", folder, err)
	}
	c.Selected = folder
	return data, nil
}

// checkUIDValidity compares the UIDVALIDITY of an id against the open
// folder (C4).
//
// arch: T4.3, §3.8, C4
func checkUIDValidity(sel *imap.SelectData, want uint32) error {
	if sel.UIDValidity != want {
		return ErrStaleID
	}
	return nil
}

// listOptions builds the LIST options the server can answer. A server
// without LIST-EXTENDED refuses the whole RETURN part, so every
// option goes in only after a capability check (§3.10, C23).
func listOptions(c *Conn, wantStatus bool) *imap.ListOptions {
	caps := c.Caps()
	opts := &imap.ListOptions{}
	if !caps.Has(imap.CapListExtended) {
		return opts
	}
	opts.ReturnSpecialUse = caps.Has(imap.CapSpecialUse)
	if wantStatus && caps.Has(imap.CapListStatus) {
		opts.ReturnStatus = &imap.StatusOptions{NumMessages: true, NumUnseen: true}
	}
	return opts
}

// listMailboxes runs one LIST over the whole personal namespace.
func listMailboxes(c *Conn, opts *imap.ListOptions) ([]*imap.ListData, error) {
	list, err := c.List("", "*", opts).Collect()
	if err != nil {
		return nil, fmt.Errorf("imap: list folders: %w", err)
	}
	return list, nil
}

// resolveFolder checks name against the folder list the server gives
// now, and returns the name as the server spells it.
//
// The folder part of a message id is text that the caller sent
// (mail.ParseIMAPID splits on dots and keeps the rest), and a folder
// argument comes from a tool call. Neither is trusted. The check runs
// before EXAMINE, so a name that no folder carries never reaches a
// command (§3.8).
//
// arch: T4.3, §3.8, §3.10
func resolveFolder(c *Conn, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("imap: no folder name")
	}
	// ponytail: one LIST for each call. Add a cache with the role map
	// of T4.4 if the round trip shows up in a measurement.
	list, err := listMailboxes(c, nil)
	if err != nil {
		return "", err
	}
	if got, ok := findFolder(list, name); ok {
		return got, nil
	}
	return "", fmt.Errorf("imap: the account has no folder %q", name)
}

// partialFetch builds a BODY.PEEK[<part>]<0.size> item. It always
// peeks (C2: BODY[] sets \Seen) and it never asks for more than
// maxPartBytes.
//
// arch: T4.3, §3.10, C2
func partialFetch(part []int, size int64) *imap.FetchItemBodySection {
	if size <= 0 || size > maxPartBytes {
		size = maxPartBytes
	}
	return &imap.FetchItemBodySection{
		Part:    part,
		Partial: &imap.SectionPartial{Offset: 0, Size: size},
		Peek:    true,
	}
}

// hasAttr reports whether the folder carries one mailbox attribute.
func hasAttr(attrs []imap.MailboxAttr, want imap.MailboxAttr) bool {
	for _, a := range attrs {
		if a == want {
			return true
		}
	}
	return false
}
