// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"errors"
	"fmt"

	"github.com/emersion/go-imap/v2"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// draftFlags are the flags of a stored draft. \Seen keeps the draft
// out of the unread count of the person (§3.10).
var draftFlags = []imap.Flag{imap.FlagDraft, imap.FlagSeen}

// SaveDraft stores one message in the Drafts folder and gives its id
// (§3.10).
//
// The id is the id every other tool takes, so a person can read the
// draft again, send it, or replace it. It comes from APPENDUID, and
// from a search for the Message-ID when the server has no UIDPLUS
// (C15).
//
// replaceID is the draft this one takes the place of, or "". IMAP has
// no command that changes a stored message, so an update appends the
// new text first and removes the old draft after it. When the removal
// fails, the error names the id of the new draft, or says that id is
// unknown when the APPEND id search missed: the text is saved, and
// the person must know that the older one is still there.
//
// The APPEND can also store the new text on a server that then fails
// to find it again by its Message-ID (no UIDPLUS, and the search
// itself finds nothing). The text is saved all the same, so that
// miss is not an error: SaveDraft gives an empty id instead of one it
// does not have, and still goes on to replace an older draft. This
// signature carries no warning field of its own (it is the
// tools.Writer contract), so the miss goes out as a line on the
// pool's logger instead (DRV.19.2).
//
// When m answers a message, m.ReplyToID goes into the draft as the
// header mime.ReplyIDHeader (build sets mime.Input.ReplyID). A replace
// builds the new draft from m alone, so the header follows the
// reply_to_id of this call, as In-Reply-To does. SendDraft reads the
// header and removes it before the send (DR1G.8, DR1G.18.6).
//
// arch: T5.2, §3.10, §3.14, C15, DRV.19.2, DR1G.8, DR1G.18
func (w *WriteProvider) SaveDraft(ctx context.Context, m *mail.Outgoing, replaceID string) (string, error) {
	if m == nil {
		return "", errors.New("imap: save draft: no message")
	}
	from, err := w.envelopeFrom(m.From)
	if err != nil {
		return "", err
	}
	raw, err := w.build(m, w.headerFrom(m.From, from))
	if err != nil {
		return "", err
	}

	var id string
	err = w.pool.WithWrite(ctx, w.alias, func(c *Conn) error {
		folders, err := w.roleFolders(c)
		if err != nil {
			return err
		}
		id, err = w.appendToRole(c, folders, "drafts", raw, draftFlags)
		var miss *storedIDMissError
		if err != nil {
			if !errors.As(err, &miss) {
				return err
			}
			// The draft is stored; only its id is unknown. SaveDraft
			// has no field of its own for a warning (its signature
			// is the tools.Writer contract), so the pool's logger
			// carries the word out instead, the way thread.go
			// already does for its own per-folder miss (DRV.19.2).
			w.pool.log.Warn("imap: draft stored but not found again by its Message-ID", "folder", miss.folder)
		}
		if replaceID == "" {
			return nil
		}
		if err := removeDraft(c, replaceID); err != nil {
			if id == "" {
				return fmt.Errorf("imap: the draft is saved, but the server did not find it again, so its id is unknown; the older draft %s did not go away: %w", replaceID, err)
			}
			return fmt.Errorf("imap: the draft is saved as %s, but the older draft %s did not go away: %w", id, replaceID, err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// draftSource reads the stored text of one draft.
//
// It refuses a message that does not carry \Draft. The id comes from
// a tool call, so nothing stops a caller from naming a message of the
// inbox, and a send of that message, or a removal of it, is not what
// "draft" means (§3.8, §3.15).
//
// arch: T5.2, §3.10, §3.8, C2, C4
func (w *WriteProvider) draftSource(ctx context.Context, id string) ([]byte, error) {
	var raw []byte
	err := w.pool.WithRead(ctx, w.alias, func(c *Conn) error {
		uid, _, _, err := locate(c, id)
		if err != nil {
			return err
		}
		sec := &imap.FetchItemBodySection{
			Peek:    true,
			Partial: &imap.SectionPartial{Offset: 0, Size: maxRawBytes + 1},
		}
		opts := &imap.FetchOptions{
			UID:         true,
			Flags:       true,
			BodySection: []*imap.FetchItemBodySection{sec},
		}
		row, err := fetchOne(c, uid, opts)
		if err != nil {
			return err
		}
		if !carriesFlag(row.Flags, imap.FlagDraft) {
			return fmt.Errorf("imap: message %s is not a draft", id)
		}
		body := row.FindBodySection(sec)
		if int64(len(body)) > maxRawBytes {
			return fmt.Errorf("imap: this draft is larger than the limit of %d MB", maxRawBytes>>20)
		}
		if len(body) == 0 {
			return fmt.Errorf("imap: draft %s holds no text", id)
		}
		raw = body
		return nil
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// dropDraft removes one draft on its own connection. SendDraft calls
// it after the mail left.
//
// arch: T5.2, §3.10
func (w *WriteProvider) dropDraft(ctx context.Context, id string) error {
	return w.pool.WithWrite(ctx, w.alias, func(c *Conn) error {
		return removeDraft(c, id)
	})
}

// removeDraft takes one draft out of its folder.
//
// It marks the message \Deleted and then expunges that UID alone. A
// server with no UIDPLUS gets no expunge at all: a plain EXPUNGE
// removes every message that carries \Deleted, also the ones another
// client marked, and no message of this server is ever removed for
// good by us (§10.6). The draft then stays with the flag, and every
// mail client shows it as deleted.
//
// It refuses a message that does not carry \Draft, for the reason
// draftSource gives: the id comes from a tool call.
//
// arch: T5.2, §3.10, §3.8, §10.6, C4
func removeDraft(c *Conn, id string) error {
	uid, folder, uidValidity, err := locate(c, id)
	if err != nil {
		return err
	}
	row, err := fetchOne(c, uid, &imap.FetchOptions{UID: true, Flags: true})
	if err != nil {
		return err
	}
	if !carriesFlag(row.Flags, imap.FlagDraft) {
		return fmt.Errorf("imap: message %s is not a draft", id)
	}

	sel, err := selectWrite(c, folder)
	if err != nil {
		return err
	}
	if err := checkUIDValidity(sel, uidValidity); err != nil {
		return err
	}
	set := imap.UIDSetNum(uid)
	op := &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}, Silent: true}
	if err := c.Store(set, op, nil).Close(); err != nil {
		return fmt.Errorf("imap: mark draft %s deleted: %w", id, err)
	}
	if !c.Caps().Has(imap.CapUIDPlus) {
		return nil
	}
	if err := c.UIDExpunge(set).Close(); err != nil {
		return fmt.Errorf("imap: expunge draft %s: %w", id, err)
	}
	return nil
}

// carriesFlag reports whether a message carries one flag.
func carriesFlag(flags []imap.Flag, want imap.Flag) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
