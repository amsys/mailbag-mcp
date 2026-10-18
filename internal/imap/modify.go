// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// This file is the IMAP write path for flags, keywords and moves
// (§3.10 "Write path"). Three rules shape it:
//
//   - C17: a keyword goes on a message only when the open folder
//     answers PERMANENTFLAGS with \*. If not, the error names
//     move_to, because a folder is the only place left to put the
//     message.
//   - C12 and invariant 6: no message is removed for good. Trash and
//     archive are moves. The code never sends a plain EXPUNGE, which
//     would remove every message that carries \Deleted in the folder,
//     also the ones another client marked.
//   - C5: a move changes the id. The new id comes from COPYUID, and
//     the undo journal of §3.18 reads it.
//
// arch: T5.3, §3.10, §3.8, C5, C12, C17, §10.6

// ErrKeywordNotPermitted is the error of C17: the folder does not
// take a keyword, so the caller must use move_to instead.
var ErrKeywordNotPermitted = errors.New("imap: this folder does not keep labels")

// ErrFolderGone is the error of an id whose folder is not in the
// folder list now: another client deleted or renamed it. Undo treats
// it like ErrStaleID and skips the ids of that folder (R16-M6).
var ErrFolderGone = errors.New("imap: the account has no folder")

// Modify applies one change to a set of messages and reports what it
// did, one row per message, for the undo journal (§3.18).
//
// It is the [tools.Writer] method. It gives the rows of
// [WriteProvider.ModifyDetail], and each row carries the
// ExpungePending answer of the call (§3.10). A message that is gone
// gets no row; [WriteProvider.ModifyDetail] names it (D5.4). With an
// error, the rows are the messages that changed before the error.
//
// arch: T5.3, §3.10, §3.8, C5, C12, C17, §10.6, DRV.11, DRV.16a
func (w *WriteProvider) Modify(ctx context.Context, ids []string, ch mail.Change) ([]mail.Applied, error) {
	res, err := w.ModifyDetail(ctx, ids, ch)
	return res.Applied, err
}

// ModifyDetail applies one change and gives the full IMAP answer.
//
// The order is flags first, then the move: the flags must travel with
// the message, and a moved message is gone from the source folder.
//
// The whole call runs inside one Pool.WithWrite, so it never runs a
// second time after a broken socket. A repeated COPY makes a second
// copy in the target folder (§3.10).
//
// The folders change one after the other. When a later folder fails,
// the earlier folders changed already, so the result holds their rows
// together with the error. The undo journal then records them
// (IRV.9). A folder that fails gives no rows of its own.
//
// arch: T5.3, §3.10, §3.8, C5, C12, C17, §10.6, DRV.11
func (w *WriteProvider) ModifyDetail(ctx context.Context, ids []string, ch mail.Change) (mail.ModifyResult, error) {
	if len(ids) == 0 {
		return mail.ModifyResult{}, errors.New("imap: modify needs at least one message id")
	}
	if err := checkChange(ch); err != nil {
		return mail.ModifyResult{}, err
	}
	order, groups, err := groupIDs(ids)
	if err != nil {
		return mail.ModifyResult{}, err
	}

	var res mail.ModifyResult
	err = w.pool.WithWrite(ctx, w.alias, func(c *Conn) error {
		res = mail.ModifyResult{}
		dest, err := w.moveTarget(c, ch)
		if err != nil {
			return err
		}
		jf, err := w.junkFoldersOf(c, ch, dest)
		if err != nil {
			return err
		}
		list, err := listMailboxes(c, nil)
		if err != nil {
			return err
		}
		for _, folder := range order {
			// The folder of an id is text the caller sent (§3.8); it
			// must be in the folder list the server gives now, and
			// applyInFolder needs the server's own spelling so its
			// same-folder check (DRV.19.3) compares like with like,
			// not "inbox" against "INBOX". A folder that is not in the
			// list gives ErrFolderGone, so undo can skip its ids
			// (R16-M6).
			realName, ok := findFolder(list, folder)
			if !ok {
				return fmt.Errorf("%w %q", ErrFolderGone, folder)
			}
			rows, gone, pending, err := applyInFolder(c, realName, groups[folder], ch, dest, jf)
			if err != nil {
				return err
			}
			res.Applied = append(res.Applied, rows...)
			res.Gone = append(res.Gone, gone...)
			res.ExpungePending = res.ExpungePending || pending
		}
		return nil
	})
	return res, err
}

// idRef is one message id, split into the parts the commands need
// (§3.8).
type idRef struct {
	id     string
	uid    imap.UID
	uidVal uint32
}

// groupIDs splits every id and groups the ids by folder. It gives the
// folder names in the order the ids named them, so the result rows
// keep a stable order.
//
// arch: T5.3, §3.8
func groupIDs(ids []string) ([]string, map[string][]idRef, error) {
	order := make([]string, 0, 4)
	groups := make(map[string][]idRef, 4)
	for _, id := range ids {
		uidVal, uid, folder, err := mail.ParseIMAPID(id)
		if err != nil {
			return nil, nil, fmt.Errorf("imap: modify: %w", err)
		}
		if uid == 0 {
			return nil, nil, fmt.Errorf("%w: %q", mail.ErrInvalidID, id)
		}
		if _, seen := groups[folder]; !seen {
			order = append(order, folder)
		}
		groups[folder] = append(groups[folder], idRef{id: id, uid: imap.UID(uid), uidVal: uidVal})
	}
	return order, groups, nil
}

// checkChange refuses a change that names more than one target. The
// tool layer of Appendix B checks this too; the provider checks it
// again, because a silent choice between two targets would move mail
// to a folder nobody asked for.
//
// arch: T5.3, §3.10
func checkChange(ch mail.Change) error {
	n := 0
	if ch.MoveTo != "" {
		n++
	}
	if ch.Archive {
		n++
	}
	if ch.Trash {
		n++
	}
	if n > 1 {
		return errors.New("imap: modify takes one of move_to, archive or trash, not more")
	}
	for _, label := range append(append([]string(nil), ch.AddLabels...), ch.RemoveLabels...) {
		if err := checkKeyword(label); err != nil {
			return err
		}
	}
	return nil
}

// checkKeyword refuses a label that is not an IMAP atom. A flag goes
// on the wire without quotes, so a space or a bracket in the text
// would end the flag list and let the rest of the string act as a
// command.
//
// arch: T5.3, §3.10, §3.15
func checkKeyword(label string) error {
	if label == "" {
		return errors.New("imap: a label must have a name")
	}
	if strings.HasPrefix(label, `\`) {
		return fmt.Errorf("imap: %q starts with a backslash, which belongs to the system flags", label)
	}
	for _, r := range label {
		if r <= ' ' || r > '~' || strings.ContainsRune(`(){%*"\]`, r) {
			return fmt.Errorf("imap: the label %q holds a character that a server does not take", label)
		}
	}
	return nil
}

// moveTarget gives the folder a move goes to, or "" when the change
// moves nothing. Trash and archive are moves to the folder that
// carries the role (§3.10, invariant 6). With no such folder the
// error names the setting that fixes it.
//
// arch: T5.3, §3.10, §10.6
func (w *WriteProvider) moveTarget(c *Conn, ch mail.Change) (string, error) {
	switch {
	case ch.Trash:
		return w.roleFolder(c, "trash", "folders.trash")
	case ch.Archive:
		return w.roleFolder(c, "archive", "folders.archive")
	case ch.MoveTo != "":
		return resolveFolder(c, ch.MoveTo)
	}
	return "", nil
}

// roleFolder gives the name of the folder that carries role.
func (w *WriteProvider) roleFolder(c *Conn, role, setting string) (string, error) {
	folders, err := w.roleFolders(c)
	if err != nil {
		return "", err
	}
	name, ok := folderNamed(folders, role)
	if !ok {
		return "", fmt.Errorf("imap: the account has no %s folder; name one with %s in accounts.toml", role, setting)
	}
	return name, nil
}

// IMAP keywords of the junk verdict (DS8.2d), in the spelling of the
// IANA keyword registry (RFC 5788). A server compares keywords with
// no regard to case, so they match mail.KeywordJunk and
// mail.KeywordNotJunk.
const (
	keywordJunk    = "$Junk"
	keywordNotJunk = "$NotJunk"
)

// junkFolders names the folders with the role junk and trash, for the
// junk rule of a move (DS8.2d). A zero value turns the rule off.
type junkFolders struct {
	junk, trash string
}

// junkFoldersOf gives the junk and trash folders when the junk rule
// can touch a message of the move to dest. It gives the zero value,
// with no LIST, for a change that does not move, and for a change that
// mail.JunkRule leaves alone for any source (an undo, or a call that
// names a junk keyword). With no junk folder, the rule is off.
//
// arch: DS8.2d
func (w *WriteProvider) junkFoldersOf(c *Conn, ch mail.Change, dest string) (junkFolders, error) {
	if dest == "" {
		return junkFolders{}, nil
	}
	if _, a := mail.JunkRule(ch, true, false, false); !a {
		if _, b := mail.JunkRule(ch, false, true, false); !b {
			return junkFolders{}, nil
		}
	}
	folders, err := w.roleFolders(c)
	if err != nil {
		return junkFolders{}, err
	}
	var jf junkFolders
	if name, ok := folderNamed(folders, "junk"); ok {
		jf.junk = name
		jf.trash, _ = folderNamed(folders, "trash")
	}
	return jf, nil
}

// withJunk gives ch with the junk keywords of the verdict added to its
// labels: junk true adds $Junk and removes $NotJunk, junk false does
// the reverse (DS8.2d). It copies the label lists, so the caller's
// change stays as it was.
func withJunk(ch mail.Change, junk bool) mail.Change {
	on, off := keywordJunk, keywordNotJunk
	if !junk {
		on, off = off, on
	}
	ch.AddLabels = append(append([]string(nil), ch.AddLabels...), on)
	ch.RemoveLabels = append(append([]string(nil), ch.RemoveLabels...), off)
	return ch
}

// applyInFolder runs the change on the messages of one folder. It
// gives the rows of the messages it changed and the ids of the
// messages that are gone.
//
// folder is already the caller's folder resolved against the folder
// list (ModifyDetail does this with resolveFolder), so it carries the
// server's own spelling, the same spelling dest carries. The
// same-folder check below (DRV.19.3) depends on that: comparing the
// raw text of an id against dest would treat "inbox" and "INBOX" as
// different folders.
//
// jf turns on the junk rule (DS8.2d). A move out of the junk folder or
// into it adds the junk keywords to the STORE of the change, before
// the move, so the keywords travel with the message. The rule acts
// only when the folder takes keywords (C17); else the move goes on
// with no keyword change and no error.
//
// The FETCH of the flags runs before each change, and it is the
// presence check of D5.4: a UID with no FETCH answer is absent. A
// SILENT STORE and a plain MOVE answer OK for a UID that does not
// exist, so no later command can see it. An absent UID gets no row
// and no command.
//
// arch: T5.3, §3.10, §3.8, C5, C12, C17, D5.4, DRV.19.3
func applyInFolder(c *Conn, folder string, refs []idRef, ch mail.Change, dest string, jf junkFolders) ([]mail.Applied, []string, bool, error) {
	sel, err := selectWrite(c, folder)
	if err != nil {
		return nil, nil, false, err
	}
	uids := make([]imap.UID, 0, len(refs))
	for _, r := range refs {
		if err := checkUIDValidity(sel, r.uidVal); err != nil {
			return nil, nil, false, err
		}
		uids = append(uids, r.uid)
	}
	if wantsKeywords(ch) && !permitsKeywords(sel) {
		return nil, nil, false, fmt.Errorf("%w: %q answers PERMANENTFLAGS with no \\*; use move_to to sort the message into a folder instead",
			ErrKeywordNotPermitted, folder)
	}
	if jf.junk != "" && dest != "" && dest != folder && permitsKeywords(sel) {
		if junk, set := mail.JunkRule(ch, folder == jf.junk, dest == jf.junk, dest == jf.trash); set {
			ch = withJunk(ch, junk)
		}
	}

	before, err := fetchFlags(c, uids)
	if err != nil {
		return nil, nil, false, err
	}
	present := presentUIDs(uids, before)
	if len(present) == 0 {
		return nil, goneIDs(refs, before, nil), false, nil
	}
	if err := storeChange(c, present, ch); err != nil {
		return nil, nil, false, err
	}

	// A move to the folder the message is already in does nothing.
	// The server refuses a copy onto itself, and trash on a message
	// in Trash is a call a person makes.
	moving := dest != "" && dest != folder
	var pairs map[imap.UID]imap.UID
	var lost map[imap.UID]bool
	var destVal uint32
	pending := false
	if moving {
		// §3.18 needs the new id of a moved message. A server with no
		// UIDPLUS sends no COPYUID, so the new id comes from a search
		// for the Message-ID in the target folder (C15). Read the
		// header now: after the move the message is no longer here.
		var msgIDs map[imap.UID]string
		if !c.Caps().Has(imap.CapUIDPlus) {
			if msgIDs, err = fetchMessageIDs(c, present); err != nil {
				return nil, nil, false, err
			}
		}
		pairs, lost, destVal, pending, err = moveUIDs(c, present, dest, msgIDs)
		if err != nil {
			return nil, nil, false, err
		}
	}

	rows := make([]mail.Applied, 0, len(refs))
	for _, r := range refs {
		if _, ok := before[r.uid]; !ok || lost[r.uid] {
			continue
		}
		row := mail.Applied{ID: r.id, Before: before[r.uid], ExpungePending: pending}
		row.After = computeAfter(row.Before, ch)
		if newUID, ok := pairs[r.uid]; ok {
			row.NewID = mail.FormatIMAPID(destVal, uint32(newUID), dest)
		} else if dest != "" && !moving {
			// The message is in the target folder already, so it did
			// not move and keeps its id. NewID = ID tells the tool
			// layer that the row has nothing to reverse. An empty
			// NewID means a move whose new id did not come back
			// (R16-M5).
			row.NewID = r.id
		}
		rows = append(rows, row)
	}
	return rows, goneIDs(refs, before, lost), pending, nil
}

// presentUIDs gives the uids that have a FETCH answer, in the order
// of the call. A uid with no answer is gone (D5.4).
//
// arch: D5.4
func presentUIDs(uids []imap.UID, before map[imap.UID]mail.Flags) []imap.UID {
	out := make([]imap.UID, 0, len(uids))
	for _, u := range uids {
		if _, ok := before[u]; ok {
			out = append(out, u)
		}
	}
	return out
}

// goneIDs gives the ids of the refs that had no FETCH answer, or that
// the COPYUID answer of the move did not name. The ids keep the order
// of the call.
//
// arch: D5.4
func goneIDs(refs []idRef, before map[imap.UID]mail.Flags, lost map[imap.UID]bool) []string {
	var out []string
	for _, r := range refs {
		if _, ok := before[r.uid]; !ok || lost[r.uid] {
			out = append(out, r.id)
		}
	}
	return out
}

// wantsKeywords reports whether the change touches a label.
func wantsKeywords(ch mail.Change) bool {
	return len(ch.AddLabels) > 0 || len(ch.RemoveLabels) > 0
}

// permitsKeywords reads the PERMANENTFLAGS answer of the open folder.
// \* means the folder takes a keyword the client invents (C17).
//
// arch: T5.3, §3.10, C17
func permitsKeywords(sel *imap.SelectData) bool {
	if sel == nil {
		return false
	}
	for _, f := range sel.PermanentFlags {
		if f == imap.FlagWildcard {
			return true
		}
	}
	return false
}

// fetchFlags reads the flags of every uid before the change, so the
// undo journal knows the state to go back to (§3.18). A uid that is
// not in the map got no FETCH answer: the message is gone (D5.4).
func fetchFlags(c *Conn, uids []imap.UID) (map[imap.UID]mail.Flags, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	rows, err := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{UID: true, Flags: true}).Collect()
	if err != nil {
		return nil, fmt.Errorf("imap: read the flags: %w", err)
	}
	out := make(map[imap.UID]mail.Flags, len(rows))
	for _, r := range rows {
		out[r.UID] = toFlags(r.Flags)
	}
	return out, nil
}

// storeChange sends the STORE commands of one change: one to add
// flags and one to remove them.
//
// arch: T5.3, §3.10
func storeChange(c *Conn, uids []imap.UID, ch mail.Change) error {
	add, del := flagOps(ch)
	if err := storeFlags(c, uids, imap.StoreFlagsAdd, add); err != nil {
		return err
	}
	return storeFlags(c, uids, imap.StoreFlagsDel, del)
}

// flagOps turns a change into the flags to add and the flags to
// remove. read is \Seen and starred is \Flagged (§3.10); a label
// becomes a keyword of the same name.
func flagOps(ch mail.Change) (add, del []imap.Flag) {
	if ch.Read != nil {
		if *ch.Read {
			add = append(add, imap.FlagSeen)
		} else {
			del = append(del, imap.FlagSeen)
		}
	}
	if ch.Starred != nil {
		if *ch.Starred {
			add = append(add, imap.FlagFlagged)
		} else {
			del = append(del, imap.FlagFlagged)
		}
	}
	for _, l := range ch.AddLabels {
		add = append(add, imap.Flag(l))
	}
	for _, l := range ch.RemoveLabels {
		del = append(del, imap.Flag(l))
	}
	return add, del
}

// storeFlags sends one UID STORE. It asks for no answer (SILENT),
// because the caller builds the new flag state itself.
func storeFlags(c *Conn, uids []imap.UID, op imap.StoreFlagsOp, flags []imap.Flag) error {
	if len(flags) == 0 || len(uids) == 0 {
		return nil
	}
	st := &imap.StoreFlags{Op: op, Flags: flags, Silent: true}
	if err := c.Store(imap.UIDSetNum(uids...), st, nil).Close(); err != nil {
		return fmt.Errorf("imap: change the flags: %w", err)
	}
	return nil
}

// computeAfter gives the flag state the change leaves behind. The
// server sends no answer to a SILENT store, and a moved message is
// gone from the folder, so a second FETCH is not possible.
func computeAfter(before mail.Flags, ch mail.Change) mail.Flags {
	after := before
	after.Labels = append([]string(nil), before.Labels...)
	if ch.Read != nil {
		after.Seen = *ch.Read
	}
	if ch.Starred != nil {
		after.Flagged = *ch.Starred
	}
	for _, l := range ch.AddLabels {
		if indexFold(after.Labels, l) < 0 {
			after.Labels = append(after.Labels, l)
		}
	}
	for _, l := range ch.RemoveLabels {
		if at := indexFold(after.Labels, l); at >= 0 {
			after.Labels = append(after.Labels[:at], after.Labels[at+1:]...)
		}
	}
	return after
}

// indexFold finds a label, ignoring case. An IMAP keyword is case
// insensitive.
func indexFold(list []string, want string) int {
	for i, s := range list {
		if strings.EqualFold(s, want) {
			return i
		}
	}
	return -1
}

// moveUIDs moves the messages to dest and gives the new uid of each
// one, the UIDVALIDITY of dest, and whether the old copies are gone.
//
// UID MOVE does the whole job in one command. A server without MOVE
// gets the fallback of §3.10: UID COPY, UID STORE +FLAGS (\Deleted),
// UID EXPUNGE. With no UIDPLUS the fallback stops after the STORE and
// reports ExpungePending, because the only command left would be a
// plain EXPUNGE, and that removes every \Deleted message in the
// folder, also messages another client marked (C12, invariant 6).
//
// imapclient.Client.Move has a fallback of its own, and that fallback
// sends the plain EXPUNGE. The code below therefore calls Move only
// when the server has the MOVE extension (U2).
//
// msgIDs holds the Message-ID of each uid, read before the move. It
// is the fallback of §3.18 for a server that sends no COPYUID; an
// empty map leaves the new id empty, as before.
//
// lost holds the uids that a COPYUID answer did not name: the server
// moved no such message, because another client removed it after the
// FETCH (D5.4). With no COPYUID answer the code cannot tell, so lost
// stays empty and the Message-ID search gives the new id.
//
// arch: T5.3, §3.10, §3.18, C5, C12, C15, §10.6, D5.4
func moveUIDs(c *Conn, uids []imap.UID, dest string, msgIDs map[imap.UID]string) (pairs map[imap.UID]imap.UID, lost map[imap.UID]bool, destVal uint32, pending bool, err error) {
	set := imap.UIDSetNum(uids...)
	if c.Caps().Has(imap.CapMove) {
		data, err := c.Move(set, dest).Wait()
		if err != nil {
			return nil, nil, 0, false, fmt.Errorf("imap: move to %q: %w", dest, err)
		}
		if data != nil {
			pairs, lost, destVal = readCopyUID(data.SourceUIDs, data.DestUIDs, data.UIDValidity, uids)
		}
		if pairs == nil {
			pairs, destVal, err = fillFromMessageIDs(c, dest, uids, msgIDs)
			if err != nil {
				return nil, nil, 0, false, err
			}
		}
		return pairs, lost, destVal, false, nil
	}

	data, err := c.Copy(set, dest).Wait()
	if err != nil {
		return nil, nil, 0, false, fmt.Errorf("imap: copy to %q: %w", dest, err)
	}
	if err := storeFlags(c, uids, imap.StoreFlagsAdd, []imap.Flag{imap.FlagDeleted}); err != nil {
		return nil, nil, 0, false, err
	}
	if data != nil {
		pairs, lost, destVal = readCopyUID(data.SourceUIDs, data.DestUIDs, data.UIDValidity, uids)
	}
	if !c.Caps().Has(imap.CapUIDPlus) {
		// The search reads the target folder, so it runs last: no
		// command after it needs the source folder.
		if pairs == nil {
			pairs, destVal, err = fillFromMessageIDs(c, dest, uids, msgIDs)
			if err != nil {
				return nil, nil, 0, false, err
			}
		}
		return pairs, lost, destVal, true, nil
	}
	if err := c.UIDExpunge(set).Close(); err != nil {
		return nil, nil, 0, false, fmt.Errorf("imap: remove the old copy from %q: %w", c.Selected, err)
	}
	return pairs, lost, destVal, false, nil
}

// readCopyUID reads the COPYUID answer of a MOVE or a COPY. It gives
// the uid pairs, the uids the answer did not name, and the
// UIDVALIDITY of the target folder. With no answer that pairs, the
// pairs and the lost uids are empty: the caller then cannot tell
// which message moved.
//
// arch: C5, D5.4
func readCopyUID(src, dst imap.NumSet, uidVal uint32, uids []imap.UID) (map[imap.UID]imap.UID, map[imap.UID]bool, uint32) {
	pairs := pairUIDs(src, dst)
	if pairs == nil {
		return nil, nil, uidVal
	}
	var lost map[imap.UID]bool
	for _, u := range uids {
		if _, ok := pairs[u]; ok {
			continue
		}
		if lost == nil {
			lost = make(map[imap.UID]bool)
		}
		lost[u] = true
	}
	return pairs, lost, uidVal
}

// fetchMessageIDs reads the Message-ID of every uid in the open
// folder. A message with no such header is left out of the map.
//
// arch: T5.3, §3.18, C15
func fetchMessageIDs(c *Conn, uids []imap.UID) (map[imap.UID]string, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	rows, err := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil {
		return nil, fmt.Errorf("imap: read the Message-ID: %w", err)
	}
	out := make(map[imap.UID]string, len(rows))
	for _, r := range rows {
		if r.Envelope == nil {
			continue
		}
		if id := angled(r.Envelope.MessageID); id != "" {
			out[r.UID] = id
		}
	}
	return out, nil
}

// fillFromMessageIDs gives the new uid of each moved message when the
// server sent no COPYUID answer that pairs. It is the fallback of
// §3.18: the server has no UIDPLUS, so the only way to the new id is a
// UID SEARCH for the Message-ID in the target folder (C15). Without it
// the undo journal records no new_id, and the undo of the move cannot
// find the message.
//
// It reads the target folder, so the caller runs it after the move.
// A message the search does not find keeps an empty new id.
//
// arch: T5.3, §3.18, §3.8, C5, C15
func fillFromMessageIDs(c *Conn, dest string, uids []imap.UID, msgIDs map[imap.UID]string) (map[imap.UID]imap.UID, uint32, error) {
	want := make([]imap.UID, 0, len(uids))
	for _, u := range uids {
		if msgIDs[u] != "" {
			want = append(want, u)
		}
	}
	if len(want) == 0 {
		return nil, 0, nil
	}

	sel, err := examine(c, dest)
	if err != nil {
		return nil, 0, err
	}
	pairs := make(map[imap.UID]imap.UID, len(want))
	for _, u := range want {
		crit := &imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: msgIDs[u]}},
		}
		found, err := uidSearch(c, crit)
		if err != nil {
			return nil, 0, err
		}
		if newest, ok := newestUID(found); ok {
			pairs[u] = newest
		}
	}
	return pairs, sel.UIDValidity, nil
}

// newestUID gives the largest uid of the list. The second value is
// false for an empty list. A folder can hold more than one copy of one
// Message-ID, and the copy the move just made is the newest one.
func newestUID(uids []imap.UID) (imap.UID, bool) {
	if len(uids) == 0 {
		return 0, false
	}
	newest := uids[0]
	for _, u := range uids {
		if u > newest {
			newest = u
		}
	}
	return newest, true
}

// pairUIDs reads a COPYUID answer: the source set and the target set
// name the same messages in the same order (RFC 4315), so the entry
// at one position of the first set belongs to the entry at that
// position of the second (C5).
//
// arch: T5.3, §3.8, C5
func pairUIDs(src, dst imap.NumSet) map[imap.UID]imap.UID {
	from, okFrom := uidNums(src)
	to, okTo := uidNums(dst)
	if !okFrom || !okTo || len(from) == 0 || len(from) != len(to) {
		return nil
	}
	out := make(map[imap.UID]imap.UID, len(from))
	for i := range from {
		out[from[i]] = to[i]
	}
	return out
}

// uidNums reads the numbers of a uid set. A set that holds "*" has no
// known numbers, and the second value is then false.
func uidNums(n imap.NumSet) ([]imap.UID, bool) {
	set, ok := n.(imap.UIDSet)
	if !ok {
		return nil, false
	}
	return set.Nums()
}
