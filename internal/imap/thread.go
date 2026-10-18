// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"cmp"
	"context"
	"log/slog"
	"slices"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// maxThread is how many messages one conversation gives back (§3.10).
const maxThread = 50

// Thread gives the conversation of one message, oldest first.
//
// IMAP has no thread id, so the group comes from the headers: the
// root is the first entry of References, or the Message-ID of the
// message itself. The search then asks for every message that holds
// that id in Message-ID or in References. It runs in the folder of
// the message and in the Sent and Archive folders, because a reply
// that this account sent lives in Sent (§3.10).
//
// The grouping is best effort. A sender that writes no References
// header leaves a message alone in its own thread, and no client can
// do better with the headers it gets.
//
// arch: T4.3, §3.10, §3.8, C2, C3, C4, DR1G.4
func (p *Provider) Thread(ctx context.Context, id string) (mail.ThreadResult, error) {
	var out mail.ThreadResult
	err := p.pool.WithRead(ctx, p.alias, func(c *Conn) error {
		uid, folder, uidValidity, err := locate(c, id)
		if err != nil {
			return err
		}
		row, err := fetchOne(c, uid, readFetch)
		if err != nil {
			return err
		}
		self := rowToMessage(row, folder, uidValidity)
		self.References = parseReferences(row.FindBodySection(refsSection))

		root := self.MessageID
		if len(self.References) > 0 {
			root = self.References[0]
		}
		if root == "" {
			// No usable header: the message is its own thread.
			out = mail.ThreadResult{Messages: []*mail.Message{&self}}
			return nil
		}

		crit := imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{
			{Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: root}}},
			{Header: []imap.SearchCriteriaHeaderField{{Key: "References", Value: root}}},
		}}}

		found, skipped, previewsMissing, err := threadSearchFolders(ctx, c, threadFolders(c, folder), &crit, p.pool.log)
		if err != nil {
			return err
		}
		out = mail.ThreadResult{
			Messages:        sortThread(found, self),
			Skipped:         skipped,
			PreviewsMissing: previewsMissing,
		}
		return nil
	})
	if err != nil {
		return mail.ThreadResult{}, err
	}
	return out, nil
}

// threadSearchFolders runs threadIn over every folder in order and
// merges what it finds. A threadIn error with connBroken false skips
// that one folder only: the account may hide Archive from this user,
// and the caller counts it instead of failing the whole search
// (DR1G.4). A connBroken error stops the loop and comes back as an
// error, so the pool can dial again and run the search once more
// (DRV.10); it is never counted as a skip.
//
// Split out of Thread so the skip-and-count path can be tested
// against a folder list this function is handed directly: a folder
// name that a real LIST would never return (because it genuinely does
// not exist) still gives a true "no such mailbox" answer from the
// server, with no need to race a real client against it.
//
// arch: DR1G.4, DR1G.5, DR1G.18, IR1G.12
func threadSearchFolders(ctx context.Context, c *Conn, folders []string, crit *imap.SearchCriteria, log *slog.Logger) (found []mail.Message, skipped, previewsMissing int, err error) {
	for _, name := range folders {
		if err := ctx.Err(); err != nil {
			return found, skipped, previewsMissing, err
		}
		part, missing, ierr := threadIn(c, name, crit)
		if connBroken(c, ierr) {
			return found, skipped, previewsMissing, ierr
		}
		if ierr != nil {
			log.Warn("thread: folder skipped", "folder", name, "error", ierr)
			skipped++
			continue
		}
		found = append(found, part...)
		previewsMissing += missing
	}
	return found, skipped, previewsMissing, nil
}

// threadIn searches one folder and builds its rows, with a preview.
// The second result is the count of rows a local preview-fetch error
// left with no preview (DR1G.5, DR1G.18.3).
func threadIn(c *Conn, folder string, crit *imap.SearchCriteria) ([]mail.Message, int, error) {
	sel, err := examine(c, folder)
	if err != nil {
		return nil, 0, err
	}
	uids, err := uidSearch(c, crit)
	if err != nil {
		return nil, 0, err
	}
	if len(uids) == 0 {
		return nil, 0, nil
	}
	slices.SortFunc(uids, func(a, b imap.UID) int { return cmp.Compare(b, a) })
	if len(uids) > maxThread {
		uids = uids[:maxThread]
	}
	rows, err := fetchRows(c, uids)
	if err != nil {
		return nil, 0, err
	}
	msgs := make([]mail.Message, 0, len(rows))
	kept := make([]*imapclient.FetchMessageBuffer, 0, len(rows))
	for _, r := range rows {
		msgs = append(msgs, rowToMessage(r, folder, sel.UIDValidity))
		kept = append(kept, r)
	}
	// The preview fetch must run while this folder is open: the next
	// turn of the loop opens another one and the same UID would then
	// name another message.
	missing, err := addPreviews(c, msgs, kept)
	if err != nil {
		return nil, 0, err
	}
	return msgs, missing, nil
}

// sortThread puts the conversation in date order, drops the copies
// and keeps the newest maxThread messages. self is always in the
// result, also when the search found nothing.
func sortThread(found []mail.Message, self mail.Message) []*mail.Message {
	all := append([]mail.Message{self}, found...)
	seen := make(map[string]bool, len(all))
	out := make([]*mail.Message, 0, len(all))
	for i := range all {
		// A message that this account sent lies in Sent and in the
		// folder of the thread. The Message-ID tells the two copies
		// apart; with no Message-ID the id has to do.
		key := all[i].MessageID
		if key == "" {
			key = all[i].ID
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, &all[i])
	}
	slices.SortStableFunc(out, func(a, b *mail.Message) int { return a.Date.Compare(b.Date) })
	if len(out) > maxThread {
		out = out[len(out)-maxThread:]
	}
	return out
}

// threadFolders gives the folders a thread search reads: the folder
// of the message, then Sent and Archive. When an \All folder exists,
// it reads that folder alone, because \All already holds every
// message (RFC 6154).
//
// It uses the role map of roles.go (T4.4): the special-use attribute
// first, then the name table for a server that gives none. The
// account's own [accounts.<alias>.folders] table is config, not
// server state, and does not reach this search (§3.10); a thread that
// misses one folder gives fewer messages, which is what "best effort"
// means here, while a wrong name would open the wrong folder.
//
// arch: T4.3, §3.10, C10, DRV.19.5
func threadFolders(c *Conn, folder string) []string {
	list, err := listMailboxes(c, listOptions(c, false))
	if err != nil {
		return []string{folder}
	}
	return threadFolderNames(list, folder)
}

// threadFolderNames picks the folders out of one LIST answer.
//
// arch: DRV.19.5
func threadFolderNames(list []*imap.ListData, folder string) []string {
	roles := listRoles(list)
	for i, d := range list {
		if hasAttr(d.Attrs, imap.MailboxAttrNoSelect) {
			continue
		}
		if roles[i] == "all" {
			return []string{d.Mailbox}
		}
	}
	out := []string{folder}
	for i, d := range list {
		if d.Mailbox == folder || hasAttr(d.Attrs, imap.MailboxAttrNoSelect) {
			continue
		}
		switch roles[i] {
		case "sent", "archive":
			out = append(out, d.Mailbox)
		}
	}
	return out
}
