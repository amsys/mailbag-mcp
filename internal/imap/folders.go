// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// Folders lists every folder the account can select, with a total and
// an unread count.
//
// Counts never come from the EXAMINE answer. C9: those numbers go
// stale as soon as another client changes the mailbox. The counts
// come from LIST-STATUS when the server has it, from STATUS in
// batches of statusBatch when it does not (C23), and from a live
// UID SEARCH for the folder that is open on this connection, because
// a server may answer STATUS on the selected mailbox from the same
// stale state.
//
// arch: T4.3, §3.10, C9, C23
func (p *Provider) Folders(ctx context.Context) ([]mail.Folder, error) {
	var out []mail.Folder
	err := p.pool.WithRead(ctx, p.alias, func(c *Conn) error {
		list, err := listMailboxes(c, listOptions(c, true))
		if err != nil {
			return err
		}
		out = make([]mail.Folder, 0, len(list))
		var need []string
		roles := listRoles(list)
		for i, d := range list {
			if hasAttr(d.Attrs, imap.MailboxAttrNoSelect) || hasAttr(d.Attrs, imap.MailboxAttrNonExistent) {
				continue
			}
			f := mail.Folder{Name: d.Mailbox, Role: roles[i]}
			if d.Status != nil && d.Mailbox != c.Selected {
				applyStatus(&f, d.Status)
			} else {
				need = append(need, d.Mailbox)
			}
			out = append(out, f)
		}
		return fillCounts(c, out, need)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// applyStatus copies a STATUS answer into a folder row.
func applyStatus(f *mail.Folder, d *imap.StatusData) {
	if d == nil {
		return
	}
	if d.NumMessages != nil {
		f.Total = int(*d.NumMessages)
	}
	if d.NumUnseen != nil {
		f.Unread = int(*d.NumUnseen)
	}
}

// fillCounts asks for the counts that LIST did not carry. The open
// folder gets a live UID SEARCH; every other folder gets a STATUS,
// statusBatch commands at a time (C9, C23).
func fillCounts(c *Conn, folders []mail.Folder, need []string) error {
	if len(need) == 0 {
		return nil
	}
	at := make(map[string]int, len(folders))
	for i := range folders {
		at[folders[i].Name] = i
	}
	batch := make([]string, 0, statusBatch)
	for _, name := range need {
		if name == c.Selected {
			total, unread, err := liveCounts(c)
			if err != nil {
				return err
			}
			folders[at[name]].Total = total
			folders[at[name]].Unread = unread
			continue
		}
		batch = append(batch, name)
		if len(batch) == statusBatch {
			if err := runStatusBatch(c, folders, at, batch); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		return runStatusBatch(c, folders, at, batch)
	}
	return nil
}

// runStatusBatch sends one group of STATUS commands together and then
// reads the answers. Servers slow down or refuse a long run of STATUS
// commands, so a group never grows past statusBatch (C23).
//
// It reads every answer, also after a failure, because an unread
// command would leave the connection out of step.
func runStatusBatch(c *Conn, folders []mail.Folder, at map[string]int, names []string) error {
	opts := &imap.StatusOptions{NumMessages: true, NumUnseen: true}
	cmds := make([]*imapclient.StatusCommand, len(names))
	for i, name := range names {
		cmds[i] = c.Status(name, opts)
	}
	var firstErr error
	for i, cmd := range cmds {
		data, err := cmd.Wait()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("imap: status %q: %w", names[i], err)
			}
			continue
		}
		applyStatus(&folders[at[names[i]]], data)
	}
	return firstErr
}

// liveCounts counts the open folder with two UID SEARCH commands.
// C9: the numbers that came with EXAMINE are a snapshot, and a
// STATUS on the selected mailbox may answer from that same snapshot.
// A search runs against the mailbox as it is now.
//
// arch: T4.3, §3.10, C1, C9
func liveCounts(c *Conn) (total, unread int, err error) {
	all, err := uidSearch(c, &imap.SearchCriteria{})
	if err != nil {
		return 0, 0, err
	}
	unseen, err := uidSearch(c, &imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}})
	if err != nil {
		return 0, 0, err
	}
	return len(all), len(unseen), nil
}

// --- folder writes (T5.5) ------------------------------------------

// CreateFolder makes one folder (§3.10, §3.16).
//
// The name the caller gives is not the name that goes on the wire.
// Two server facts change it (C11):
//
//   - The hierarchy delimiter is the one the server reports. It can
//     be ".", so a "/" in the name becomes that delimiter.
//   - When NAMESPACE reports a personal prefix, such as "INBOX.",
//     the new folder goes below that prefix. A server with such a
//     prefix refuses a folder outside it.
//
// The call runs on the write path of the pool, so it never runs a
// second time on its own.
//
// arch: T5.5, §3.10, §3.16, C10, C11
func (w *WriteProvider) CreateFolder(ctx context.Context, name string) error {
	return w.pool.WithWrite(ctx, w.alias, func(c *Conn) error {
		list, err := listMailboxes(c, nil)
		if err != nil {
			return err
		}
		path, err := folderPath(c, list, name)
		if err != nil {
			return err
		}
		if _, ok := findFolder(list, path); ok {
			return fmt.Errorf("imap: the account already has a folder %q", path)
		}
		if err := c.Create(path, nil).Wait(); err != nil {
			return fmt.Errorf("imap: create %q: %w", path, err)
		}
		clearFolderState(c)
		return nil
	})
}

// RenameFolder gives one folder a new name (§3.10, §3.16). The new
// name follows the delimiter and the prefix rules of CreateFolder
// (C11).
//
// It refuses INBOX. RFC 3501 gives RENAME INBOX its own meaning: the
// server moves the messages into a new folder and keeps INBOX in
// place. That is not what a caller who asks to rename a folder means.
//
// arch: T5.5, §3.10, §3.16, C10, C11
func (w *WriteProvider) RenameFolder(ctx context.Context, from, to string) error {
	return w.pool.WithWrite(ctx, w.alias, func(c *Conn) error {
		list, err := listMailboxes(c, nil)
		if err != nil {
			return err
		}
		src, err := existingFolder(c, list, from)
		if err != nil {
			return err
		}
		if isInbox(src) {
			return errors.New("imap: INBOX cannot be renamed; RENAME INBOX moves the messages and keeps INBOX, which is not a rename")
		}
		dst, err := folderPath(c, list, to)
		if err != nil {
			return err
		}
		if _, ok := findFolder(list, dst); ok {
			return fmt.Errorf("imap: the account already has a folder %q", dst)
		}
		if err := c.Rename(src, dst, nil).Wait(); err != nil {
			return fmt.Errorf("imap: rename %q to %q: %w", src, dst, err)
		}
		clearFolderState(c)
		return nil
	})
}

// DeleteFolder removes one empty folder (§3.10, §3.16).
//
// It refuses three folders, because a delete cannot be undone:
// INBOX, a folder that carries a role, and a folder that holds
// messages. A role folder is the Sent, Drafts, Trash, Junk or
// Archive folder of the account, and the send and modify tools write
// into it.
//
// The LIST asks for the special-use attributes (C11). RFC 6154 lets
// a server give them only when the LIST carries RETURN (SPECIAL-USE).
// Without them a role folder with a name the T4.4 name table does not
// know reads as plain, and the role check lets it go.
//
// arch: T5.5, §3.10, §3.16, C10, C11
func (w *WriteProvider) DeleteFolder(ctx context.Context, name string) error {
	return w.pool.WithWrite(ctx, w.alias, func(c *Conn) error {
		list, err := listMailboxes(c, listOptions(c, false))
		if err != nil {
			return err
		}
		target, err := existingFolder(c, list, name)
		if err != nil {
			return err
		}
		if isInbox(target) {
			return errors.New("imap: INBOX cannot be deleted")
		}
		if role := roleOf(folderRows(list, w.acct.Folders), target); role != "" {
			return fmt.Errorf("imap: %q is the %s folder of this account; the send and modify tools write into it. Point %s at another folder in accounts.toml first",
				target, role, "[accounts."+w.alias+".folders]")
		}
		total, err := messageCount(c, target)
		if err != nil {
			return err
		}
		if total > 0 {
			return fmt.Errorf("imap: %q holds %d messages; move them out first, because a delete cannot be undone", target, total)
		}
		if err := c.Delete(target).Wait(); err != nil {
			return fmt.Errorf("imap: delete %q: %w", target, err)
		}
		clearFolderState(c)
		return nil
	})
}

// clearFolderState drops what this connection remembers about the
// folder tree after a create, a rename or a delete (C10).
//
// Conn.Selected is that memory. After a rename or a delete it can
// name a folder that is gone, and a server closes the selected
// mailbox when that mailbox is deleted, so the two sides would no
// longer agree. Every command that needs a folder sends SELECT or
// EXAMINE itself, so the next call opens the folder again.
//
// The role of a folder is read from LIST at each call and is not kept
// between calls, so there is no role map to clear here. If a later
// task adds one, its clear belongs in this function.
//
// arch: T5.5, §3.10, C10
func clearFolderState(c *Conn) {
	c.Selected = ""
}

// folderPath turns the name a caller gave into the name that goes on
// the wire (C11): the delimiter of the server, and the personal
// NAMESPACE prefix when the server has one.
//
// arch: T5.5, §3.10, C11
func folderPath(c *Conn, list []*imap.ListData, name string) (string, error) {
	prefix, delim := folderLayout(c, list)
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("imap: no folder name")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("imap: the folder name %q holds a control character", name)
		}
	}
	if delim != 0 && delim != '/' {
		// A caller writes a folder below another with "/". The
		// server may spell the same tree with "." (C11).
		name = strings.ReplaceAll(name, "/", string(delim))
	}
	if delim != 0 {
		name = strings.Trim(name, string(delim))
		if name == "" {
			return "", errors.New("imap: the folder name is only delimiters")
		}
	}
	if prefix != "" && !strings.HasPrefix(name, prefix) && !isInbox(name) {
		name = prefix + name
	}
	return name, nil
}

// folderLayout gives the personal prefix and the hierarchy delimiter
// of the account (C11).
//
// The delimiter comes from LIST, which every server answers. The
// prefix comes from NAMESPACE, and so does the delimiter that belongs
// to that prefix: the two travel together on a server that has a
// prefix, and the prefix rule is useless with the delimiter of a
// different namespace. A server without NAMESPACE, or one that fails
// the command, leaves the prefix empty and keeps the LIST delimiter.
//
// arch: T5.5, §3.10, C11
func folderLayout(c *Conn, list []*imap.ListData) (prefix string, delim rune) {
	delim = listDelim(list)
	if !c.Caps().Has(imap.CapNamespace) {
		return "", delim
	}
	data, err := c.Namespace().Wait()
	if err != nil || data == nil || len(data.Personal) == 0 {
		return "", delim
	}
	p := data.Personal[0]
	if p.Delim != 0 {
		delim = p.Delim
	}
	return p.Prefix, delim
}

// listDelim reads the hierarchy delimiter out of a LIST answer. The
// INBOX row answers for the whole personal tree; any row answers when
// the list holds no INBOX.
func listDelim(list []*imap.ListData) rune {
	var first rune
	for _, d := range list {
		if d.Delim == 0 {
			continue
		}
		if isInbox(d.Mailbox) {
			return d.Delim
		}
		if first == 0 {
			first = d.Delim
		}
	}
	return first
}

// existingFolder finds the folder a caller named, and gives back the
// name as the server spells it. It tries the name as it came and then
// the name with the prefix and the delimiter rules of folderPath, so
// "Projects" finds "INBOX.Projects" on a server with a prefix (C11).
func existingFolder(c *Conn, list []*imap.ListData, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("imap: no folder name")
	}
	if got, ok := findFolder(list, strings.TrimSpace(name)); ok {
		return got, nil
	}
	path, err := folderPath(c, list, name)
	if err != nil {
		return "", err
	}
	if got, ok := findFolder(list, path); ok {
		return got, nil
	}
	return "", fmt.Errorf("imap: the account has no folder %q", strings.TrimSpace(name))
}

// findFolder looks one name up in a LIST answer. INBOX is the one
// name RFC 3501 makes case insensitive.
func findFolder(list []*imap.ListData, name string) (string, bool) {
	for _, d := range list {
		if d.Mailbox == name {
			return d.Mailbox, true
		}
	}
	if isInbox(name) {
		for _, d := range list {
			if isInbox(d.Mailbox) {
				return d.Mailbox, true
			}
		}
	}
	return "", false
}

// isInbox reports whether name is the INBOX of the account.
func isInbox(name string) bool { return strings.EqualFold(name, "INBOX") }

// folderRows turns a LIST answer into folder rows with their roles,
// with the [accounts.<alias>.folders] table applied over what the
// server said (C10).
func folderRows(list []*imap.ListData, table map[string]string) []mail.Folder {
	out := make([]mail.Folder, 0, len(list))
	roles := listRoles(list)
	for i, d := range list {
		out = append(out, mail.Folder{Name: d.Mailbox, Role: roles[i]})
	}
	ApplyRoleOverrides(out, table)
	return out
}

// roleOf gives the role of one folder, or "" when it carries none.
func roleOf(folders []mail.Folder, name string) string {
	for _, f := range folders {
		if f.Name == name {
			return f.Role
		}
	}
	return ""
}

// messageCount gives the number of messages in one folder.
//
// C9: a server may answer STATUS on the selected mailbox from the
// state that SELECT reported, which can be old. A delete reads this
// number to refuse a folder that still holds mail, so the folder that
// is open gets a live count instead. Opening INBOX first also takes
// the connection off the folder that is about to go.
func messageCount(c *Conn, folder string) (int, error) {
	if folder == c.Selected {
		if _, err := examine(c, "INBOX"); err != nil {
			return 0, err
		}
	}
	data, err := c.Status(folder, &imap.StatusOptions{NumMessages: true}).Wait()
	if err != nil {
		return 0, fmt.Errorf("imap: status %q: %w", folder, err)
	}
	if data == nil || data.NumMessages == nil {
		return 0, fmt.Errorf("imap: %q gave no message count", folder)
	}
	return int(*data.NumMessages), nil
}
