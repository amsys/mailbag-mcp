// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/undo"
)

// MaxModifyIDs is the id limit of one modify call (§3.16, App B). A
// larger set belongs to the bulk tool, which asks for a confirmation
// first.
const MaxModifyIDs = 500

// undoListWord is the value of the undo field that asks for the list
// of the last operations instead of a reversal (§3.16).
const undoListWord = "list"

// ModifyIn is the input of the modify tool (App B).
//
// Account has no omitempty, so the schema makes it required (A12,
// G10). Read and Starred are *bool, so "not given" differs from
// false.
type ModifyIn struct {
	Account      string   `json:"account"`
	IDs          []string `json:"ids,omitempty" jsonschema:"max 500"`
	Read         *bool    `json:"read,omitempty"`
	Starred      *bool    `json:"starred,omitempty"`
	AddLabels    []string `json:"add_labels,omitempty"`
	RemoveLabels []string `json:"remove_labels,omitempty"`
	MoveTo       string   `json:"move_to,omitempty"`
	Archive      bool     `json:"archive,omitempty"`
	Trash        bool     `json:"trash,omitempty"`
	Undo         string   `json:"undo,omitempty" jsonschema:"token, or list"`
}

// The fixed state words of a [ModifyRow] (D5.4).
const (
	// stateApplied is a message the call changed.
	stateApplied = "applied"
	// stateGone is a message that was not there when the call acted:
	// another client expunged or moved it. The call changed nothing
	// on it, and the undo journal does not record it (I16).
	stateGone = "gone"
)

// ModifyRow is one message of the call: the id it had, the id it has
// now when a move gave it a new one (C5), and the fixed state word
// "applied" or "gone" (D5.4).
type ModifyRow struct {
	ID    string `json:"id"`
	NewID string `json:"new_id,omitempty"`
	State string `json:"state"`
}

// UndoRow is one line of the undo list (§3.18). Summary is text this
// tool wrote when it recorded the operation; see modifySummary.
type UndoRow struct {
	ID       string `json:"id"`
	At       string `json:"at"`
	Tool     string `json:"tool"`
	Summary  string `json:"summary"`
	Count    int    `json:"count"`
	Reversed bool   `json:"reversed,omitempty"`
}

// ModifyOut is the modify tool result (§3.16): the new ids and the
// undo token, or the list of the last operations.
//
// No field of this struct carries sender-controlled text, so nothing
// here is fenced (§3.15). The ids come from the server, the alias
// comes from accounts.toml, and Summary and Note are text this tool
// wrote. A folder name that reaches Summary loses its hidden
// characters and its fence markers first, the same way
// [FolderRow.Name] does. TestModify_ResultCarriesNoSenderText holds
// that rule the way the fence walk holds it for the read results
// (G3).
type ModifyOut struct {
	Account string `json:"account"`
	// Applied holds one row for each message of the call. A row with
	// the state "gone" names a message the call did not find (D5.4).
	Applied []ModifyRow `json:"applied,omitempty"`
	// Undo is the token that reverses this operation. It is empty
	// when the operation could not be recorded, or when an IMAP move
	// gave no new id for at least one message; Note then says so
	// (§3.18, DS78.5). A message that the change left as it was does
	// not empty it (R16-M5).
	Undo string `json:"undo,omitempty"`
	// ExpungePending says a move copied the messages and flagged the
	// old copies deleted, but the server could not remove them
	// (§3.10, C12). The caller must know: the message is in two
	// folders until another client removes the old copy.
	ExpungePending bool `json:"expunge_pending,omitempty" jsonschema:"the old copy stayed; the message is in two folders"`
	// Operations answers undo: "list", newest first.
	Operations []UndoRow `json:"operations,omitempty"`
	// Skipped answers an undo: the ids of the messages that changed
	// or went away since the operation. Undo left them as they are
	// and reversed the rest (DS9.5, G17). The ids come from the
	// journal, so they carry no fence (§3.15).
	Skipped []string `json:"skipped,omitempty"`
	// Note is text this tool wrote: a step that failed after the
	// mailbox already changed, or why an option did nothing.
	Note string `json:"note,omitempty"`
}

// AddModify adds the "modify" tool to srv (§3.16): draft level, one
// change over at most 500 messages, plus the undo of one earlier
// operation.
//
// DestructiveHint is false because the journal can reverse the
// operation (§3.16) and because no message is removed for good: trash
// and archive are moves (C12, invariant 6).
//
// arch: T5.3, §3.16, §3.18, App B, C12, C18, H3
func AddModify(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &modifyTool{mail: m, journal: undo.Open, logger: logger}
	no := false
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "modify",
		Description: "Change flags, labels or folder, or undo a change. A move out of junk marks the messages not junk.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &no},
	}, Wrap(logger, "modify", DefaultTimeout, h.handle))
}

// modifyTool is the modify handler. journal gives the undo directory;
// a test supplies its own. logger takes the warn line of a journal
// write that failed; nil means slog.Default().
type modifyTool struct {
	mail    Mail
	journal func() (*undo.Journal, error)
	logger  *slog.Logger
}

// handle runs one of the three shapes of a modify call (§3.16):
//
//   - undo: "list": the last operations of the account.
//   - undo: "<token>": the reversal of that one operation.
//   - anything else: one change over the ids.
//
// The alias is checked first, so an unknown one fails here and never
// reaches a network call (G10). The access check of §3.17 belongs on
// the next line, above every branch.
//
// arch: T5.3, §3.16, §3.18, App B, C18, H3, G10
func (t *modifyTool) handle(ctx context.Context, in ModifyIn) (ModifyOut, error) {
	p, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return ModifyOut{}, err
	}
	// §3.17: draft level, above every branch. An undo is a change of
	// the mailbox as well, and undo: "list" reads the journal of the
	// changes, so the whole tool sits at one level (§3.16).
	if err := guard.Require(acct, guard.LevelDraft); err != nil {
		return ModifyOut{}, err
	}

	token := strings.TrimSpace(in.Undo)
	if token == "" {
		return t.applyChange(ctx, p, in)
	}
	if in.hasChange() {
		return ModifyOut{}, errors.New("undo takes the call on its own; send the change in a second call")
	}
	if strings.EqualFold(token, undoListWord) {
		ops, err := undoList(t.journal, in.Account)
		if err != nil {
			return ModifyOut{}, err
		}
		out := ModifyOut{Account: in.Account, Operations: ops}
		if len(ops) == 0 {
			out.Note = "this account has no recorded operation"
		}
		return out, nil
	}
	return t.reverse(ctx, p, in.Account, token)
}

// hasChange reports whether the call asks for a change of its own.
// An undo call must name none, because a reversal takes its ids and
// its flags from the journal alone (§3.18).
func (in ModifyIn) hasChange() bool {
	return len(in.IDs) > 0 || in.Read != nil || in.Starred != nil ||
		len(in.AddLabels) > 0 || len(in.RemoveLabels) > 0 ||
		in.MoveTo != "" || in.Archive || in.Trash
}

// applyChange runs one change over the ids and records it in the undo
// journal (§3.18).
//
// The journal write happens after the change succeeded and before the
// tool returns. A journal that cannot be written does not fail the
// call: the mailbox already changed, and a failure here would tell
// the model that nothing happened. The result says instead that this
// operation has no undo token (C14 applied to the journal), and the
// error goes to the log at warn level.
//
// A provider that fails part of the way gives the rows it changed
// together with the error. Those messages changed, so the tool
// journals them, returns the undo token, and puts the error in the
// note (IRV.9). An error with no row fails the call as before.
//
// The provider call runs on a detached context (DS11.9): a client
// that goes away during the change does not stop it, and the journal
// row is written, so undo can find the change from a new session.
//
// arch: T5.3, §3.16, §3.18, App B, C18, DRV.11, DS11.9
func (t *modifyTool) applyChange(ctx context.Context, p Writer, in ModifyIn) (ModifyOut, error) {
	if len(in.IDs) == 0 {
		return ModifyOut{}, errors.New("ids: name at least one message; the search tool gives the ids")
	}
	if len(in.IDs) > MaxModifyIDs {
		return ModifyOut{}, fmt.Errorf("ids: %d ids, and one call takes %d at most; the bulk tool handles a larger set", len(in.IDs), MaxModifyIDs)
	}
	ch, err := changeOf(in)
	if err != nil {
		return ModifyOut{}, err
	}

	// DS11.9: the provider call is the point of no return. The change
	// and its journal row complete on a context that the end of the
	// session does not cancel; it keeps the tool deadline of ctx.
	ctx, cancel := detach(ctx, DefaultTimeout)
	defer cancel()
	applied, gone, err := modifyDetail(ctx, p, in.IDs, ch)
	if err != nil && len(applied) == 0 {
		return ModifyOut{}, err
	}
	unresolved := unresolvedMove(ch, applied)
	clearUnmoved(applied)

	out := ModifyOut{
		Account:        in.Account,
		Applied:        append(rowsOf(applied), goneRows(gone)...),
		ExpungePending: expungePending(applied),
	}
	if err != nil {
		// The call stopped part of the way. The note names the error,
		// and the steps below journal the messages that changed.
		out.Note = fmt.Sprintf("the change stopped part of the way: %s; only the messages in applied changed",
			guard.Redact(err.Error()))
	}
	if len(applied) == 0 {
		out.Note = "no message changed; every id is gone, because another client expunged or moved the message"
		return out, nil
	}
	if unresolved {
		out.Note = addNote(out.Note, "the change is done; this operation has no undo token, because the server gave no new id for the move, and undo cannot find the message again by its old id")
		return out, nil
	}
	rec, ok := recordChange(t.journal, t.logger, in.Account, modifySummary(ch, len(applied)), applied)
	if !ok {
		out.Note = addNote(out.Note, "the change is done; this operation has no undo token, because the journal could not be written")
		return out, nil
	}
	out.Undo = rec.ID
	return out, nil
}

// modifyDetail runs one change. It gives the rows of the messages
// the provider changed and the ids of the messages that were gone.
// Only the changed rows go to the undo journal (D5.4, I16).
//
// ModifyDetail is part of [Writer], so each provider must name the
// gone messages. A provider that is wrapped or replaced cannot drop
// the gone rows in silence (finding 3 of R1C-judge.md).
//
// With an error, the rows are the messages that changed before the
// error (DRV.11).
//
// arch: D5.4, DRV.11
func modifyDetail(ctx context.Context, p Writer, ids []string, ch mail.Change) ([]mail.Applied, []string, error) {
	res, err := p.ModifyDetail(ctx, ids, ch)
	return res.Applied, res.Gone, err
}

// isMove reports whether ch asks to put a message in a different
// folder (§3.16): a plain move, or trash and archive, which are moves
// too (invariant 6).
func isMove(ch mail.Change) bool {
	return ch.MoveTo != "" || ch.Archive || ch.Trash
}

// unresolvedMove reports whether ch moved messages but at least one
// row gives undo nothing to restore (DS78.5, gap G2 of
// 03-design-S7S8.md). Only an IMAP row with no NewID is such a row:
//
//   - NewID is set: an IMAP move gave a new id, and the first id
//     names the folder to go back to (§3.8, C5). A NewID equal to the
//     id marks a message that was in the target folder already; it
//     did not move, and clearUnmoved removes the mark (R16-M5).
//   - The id is not an IMAP id: a JMAP or Gmail move keeps the id.
//     Undo sets the mailbox list back to FoldersBefore (JMAP), or
//     reverses the label difference (Gmail, DS7.4b). A row whose
//     mailboxes and labels did not change has nothing to reverse, and
//     its undo does nothing. It does not block the undo of the other
//     rows (R16-M5).
//
// An IMAP move whose new id never comes back (no UIDPLUS, and the
// Message-ID search after the move found nothing) is unresolved, also
// when the same call added or removed a label. The old id already
// names a message that left the folder, so a later undo would either
// act on the wrong message or find nothing and report the operation
// reversed while the message stays where the move put it. A label
// difference does not help here: the keyword STORE runs before the
// move, so the label is in After, but its reverse acts on the old
// copy and leaves the message in the target folder. This function
// catches that case before the record is written, so the operation
// reports plainly that it has no undo token instead of promising one
// it cannot honor (finding 2 of docs/features/mailbag/S5-judge.md).
// A Gmail id and a JMAP id hold no dot, so they never parse as an
// IMAP id (§3.8).
//
// arch: T5.3, §3.18, §3.8, C5, DS78.5, R16-M5
func unresolvedMove(ch mail.Change, applied []mail.Applied) bool {
	if !isMove(ch) {
		return false
	}
	for _, a := range applied {
		if a.NewID != "" {
			continue
		}
		if _, _, _, err := mail.ParseIMAPID(a.ID); err == nil {
			return true
		}
	}
	return false
}

// clearUnmoved removes a NewID that equals the id. The IMAP provider
// sets it for a message that a move left in place, because the
// message was in the target folder already. After unresolvedMove has
// read the mark, the journal and the result see a row with no NewID:
// a row that did not move, whose undo moves nothing (R16-M5).
func clearUnmoved(applied []mail.Applied) {
	for i := range applied {
		if applied[i].NewID == applied[i].ID {
			applied[i].NewID = ""
		}
	}
}

// recordChange writes one journal entry of the tool "modify" for the
// messages a call changed. The read tool uses it for mark_read too, so
// both write the same entry (DRV.11). open nil means undo.Open.
//
// A write that fails does not fail the call (C14). The second value is
// then false, and the error goes to the log at warn level with the
// alias and the error only, never message content.
//
// arch: T5.3, §3.18, C14, DRV.11
func recordChange(open func() (*undo.Journal, error), logger *slog.Logger, account, summary string, applied []mail.Applied) (undo.Record, bool) {
	if open == nil {
		open = undo.Open
	}
	j, err := open()
	var rec undo.Record
	if err == nil {
		rec, err = j.Append(account, "modify", summary, applied)
	}
	if err != nil {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("undo journal write failed", "account", account, "err", err)
		return undo.Record{}, false
	}
	return rec, true
}

// undoChunk is the id count of one provider call of an undo: one state
// read and one reverse step. It equals MaxModifyIDs, so a record of any
// size reads and reverses in calls that a provider takes (DS9.5,
// S9-GAP5).
const undoChunk = MaxModifyIDs

// undoList answers undo: "list" with the last operations of one
// account, newest first (§3.16, §3.18). modify and bulk share it, and
// it lists the records of both tools. open nil means undo.Open.
//
// arch: T5.3, §3.16, §3.18, DS9.5
func undoList(open func() (*undo.Journal, error), account string) ([]UndoRow, error) {
	if open == nil {
		open = undo.Open
	}
	j, err := open()
	if err != nil {
		return nil, err
	}
	recs, err := j.List(account, 0)
	if err != nil {
		return nil, err
	}
	rows := make([]UndoRow, 0, len(recs))
	for _, rec := range recs {
		rows = append(rows, UndoRow{
			ID:       rec.ID,
			At:       rec.TS.UTC().Format(time.RFC3339),
			Tool:     rec.Tool,
			Summary:  serverText(rec.Summary),
			Count:    len(rec.Changes),
			Reversed: rec.Reversed(),
		})
	}
	return rows, nil
}

// reverse puts one recorded operation back (§3.18) through
// reverseRecord and turns the result into the modify result.
//
// arch: T5.3, §3.18, C5, H3, DRV.11, DS9.5
func (t *modifyTool) reverse(ctx context.Context, p Writer, account, token string) (ModifyOut, error) {
	r, err := reverseRecord(ctx, t.journal, p, account, token, t.logger)
	if err != nil {
		return ModifyOut{}, err
	}
	out := ModifyOut{Account: account, Applied: r.Rows, ExpungePending: r.ExpungePending, Skipped: r.Skipped}
	if r.Unchanged > 0 {
		out.Note = fmt.Sprintf("%d of the %d messages needed no change to go back", r.Unchanged, r.Total)
	}
	if len(r.Rows) == 0 {
		out.Note = "the operation is marked reversed; no message needed a change to go back"
	}
	if len(r.Skipped) > 0 {
		out.Note = addNote(out.Note, fmt.Sprintf("%d messages changed or gone since the operation were left as they are", len(r.Skipped)))
	}
	return out, nil
}

// reversal is the result of reverseRecord.
type reversal struct {
	// Rows are the messages the reverse changes reached.
	Rows []ModifyRow
	// Skipped are the current ids of the messages that changed or
	// went away since the operation. Undo did not touch them.
	Skipped []string
	// Unchanged counts the messages that needed no change to go back.
	Unchanged int
	// Total is the row count of the record.
	Total int
	// ExpungePending says a move back left an old copy (§3.10, C12).
	ExpungePending bool
}

// reverseRecord undoes the record token of account (§3.18, DS9.5,
// G17). It reads the current state, reverses the ok rows in steps,
// marks them Undone and the record reversed, and lists the skipped
// ids. When no row can be reversed the record stays open and the error
// is "undo: every message changed or gone since the operation". A
// second undo of a reversed record is refused (H3). modify and bulk
// call it, and either tool reverses the records of both. open nil
// means undo.Open.
//
// The journal claims the record, this function applies the reverse
// change, and the journal marks the record reversed only after that.
// The ids come from the record and nothing searches the mailbox again.
// A message that a move gave a new id is reached by that new id (C5),
// and it goes back to the folder its first id names.
//
// The reversal runs in steps, and the journal records each step that
// is done. When a later step fails, the record stays open, and a retry
// of the same token reverses only the rest (IRV.9). A row that an
// earlier undo reversed already is not counted as changed: when such a
// row exists and every other row changed, the record is marked
// reversed and the changed rows are listed.
//
// arch: T5.3, §3.18, C5, H3, DRV.11, DS9.5, DS9.12, G17
func reverseRecord(ctx context.Context, open func() (*undo.Journal, error), p Writer, account, token string, logger *slog.Logger) (reversal, error) {
	if open == nil {
		open = undo.Open
	}
	j, err := open()
	if err != nil {
		return reversal{}, err
	}

	var res reversal
	_, rerr := j.ReverseInSteps(token, func(rec undo.Record, progress undo.Progress) error {
		if rec.Account != account {
			return fmt.Errorf("%w: that operation belongs to another account", undo.ErrUnknown)
		}
		ok, skipped, err := partitionCurrent(ctx, p, rec)
		if err != nil {
			return err
		}
		if len(ok) == 0 && len(skipped) > 0 && !anyUndone(rec) {
			// Every message changed: change nothing, keep the record
			// open (D5.4, I16).
			return undo.ErrChangedOrGone
		}
		res = reversal{Total: len(rec.Changes)}
		for _, i := range skipped {
			res.Skipped = append(res.Skipped, currentID(rec.Changes[i]))
		}
		rows, unchanged, pending, err := applyReverse(ctx, p, rec, ok, progress)
		res.Rows, res.Unchanged, res.ExpungePending = rows, unchanged, pending
		return err
	})
	switch {
	case errors.Is(rerr, undo.ErrUnknown):
		return reversal{}, errors.New("no operation of this account has that undo token; call modify with undo: \"list\" for the tokens that are left")
	case errors.Is(rerr, undo.ErrAlreadyReversed):
		return reversal{}, errors.New("that operation was reversed already; a second undo would put the change back")
	case rerr != nil:
		return reversal{}, rerr
	}
	if len(res.Skipped) > 0 {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Info("undo left changed messages as they are", "account", account, "skipped", len(res.Skipped))
	}
	return res, nil
}

// anyUndone reports whether an earlier undo of rec reversed a row
// already (DRV.11).
func anyUndone(rec undo.Record) bool {
	for _, c := range rec.Changes {
		if c.Undone {
			return true
		}
	}
	return false
}

// partitionCurrent reads the state of each message of rec now and
// splits the rows with undo.Record.Partition (D5.4, G17): ok rows are
// in the state the operation left, skipped rows changed or went away.
//
// The read is a ModifyDetail with an empty change: the IMAP write
// path reads the flags of each id first and names each absent id
// gone, and an empty change sends no STORE and no move. It runs one
// folder at a time, in chunks of undoChunk ids (S9-GAP5). A folder
// whose UIDVALIDITY changed holds none of the recorded messages, and
// a folder that another client deleted holds none either. So
// imap.ErrStaleID or imap.ErrFolderGone on a chunk leaves each id of
// that chunk with no entry: skipped. The rows the chunk gave before
// the error stay, and the other folders are still read (R16-M6).
//
// The read fails closed. ModifyDetail is part of [Writer], so no
// provider can skip it. A provider that cannot read the current state
// returns an error, and undo then changes nothing. An id with no row
// counts as changed or gone (finding 3 of R1C-judge.md).
//
// A change that an earlier undo reversed already is not read: its
// message is back in the Before state, and a move back gave it an id
// the record does not know (DRV.11).
//
// A provider with mailbox lists (JMAP) gives the current mailboxes of
// each message in Applied.FoldersAfter of the same read. A JMAP move
// keeps the id, so the journal compares these mailboxes with the ones
// the operation left, and a message that another client moved since
// then is skipped, not moved back (DS78.5, gap G3).
//
// arch: D5.4, DRV.11, DS78.5, DS9.5, G17, R16-M6
func partitionCurrent(ctx context.Context, p Writer, rec undo.Record) (ok, skipped []int, err error) {
	// An id that is not an IMAP id (Gmail, JMAP) has no folder part;
	// those ids form the group "".
	var order []string
	groups := make(map[string][]string)
	for _, c := range rec.Changes {
		if c.Undone {
			continue
		}
		id := currentID(c)
		_, _, folder, _ := mail.ParseIMAPID(id)
		if _, seen := groups[folder]; !seen {
			order = append(order, folder)
		}
		groups[folder] = append(groups[folder], id)
	}
	current := make(map[string]undo.Current, len(rec.Changes))
	for _, folder := range order {
		ids := groups[folder]
		for start := 0; start < len(ids); start += undoChunk {
			chunk := ids[start:min(start+undoChunk, len(ids))]
			res, err := p.ModifyDetail(ctx, chunk, mail.Change{})
			if err != nil && !errors.Is(err, imap.ErrStaleID) && !errors.Is(err, imap.ErrFolderGone) {
				return nil, nil, err
			}
			for _, a := range res.Applied {
				current[a.ID] = undo.Current{Flags: a.Before, Folders: a.FoldersAfter}
			}
		}
	}
	ok, skipped = rec.Partition(current)
	return ok, skipped, nil
}

// applyReverse sends the reverse of the rows of rec at the indexes
// only to the provider. It gives the rows it changed and the number of
// messages that needed no change at all.
//
// One Modify call carries one change, and two messages of the same
// operation can need two different reversals: an operation that set
// read on a set where one message was unread must clear read on that
// one message alone. The ids are therefore grouped by the reverse
// change they need, and each group goes in its own calls of at most
// undoChunk ids (S9-GAP5).
//
// After each call, progress records the changes of the rows the call
// gave, also when the call failed part of the way. So a retry after a
// failed step reverses only the rest (DRV.11, IRV.9). A progress write
// that fails stops the reversal: the journal must know each change
// undo makes.
//
// arch: T5.3, §3.18, C5, DRV.11, DS9.5
func applyReverse(ctx context.Context, p Writer, rec undo.Record, only []int, progress undo.Progress) ([]ModifyRow, int, bool, error) {
	order := make([]string, 0, 4)
	changes := make(map[string]mail.Change, 4)
	ids := make(map[string][]string, 4)
	index := make(map[string]int, len(only))
	unchanged := 0

	for _, i := range only {
		c := rec.Changes[i]
		back, ok := reverseChange(c)
		if !ok {
			unchanged++
			continue
		}
		key := changeKey(back)
		if _, seen := changes[key]; !seen {
			order = append(order, key)
			changes[key] = back
		}
		ids[key] = append(ids[key], currentID(c))
		index[currentID(c)] = i
	}

	var rows []ModifyRow
	pending := false
	for _, key := range order {
		group := ids[key]
		for start := 0; start < len(group); start += undoChunk {
			applied, err := p.Modify(ctx, group[start:min(start+undoChunk, len(group))], changes[key])
			rows = append(rows, rowsOf(applied)...)
			pending = pending || expungePending(applied)
			if len(applied) > 0 && progress != nil {
				done := make([]int, 0, len(applied))
				for _, a := range applied {
					if i, ok := index[a.ID]; ok {
						done = append(done, i)
					}
				}
				if perr := progress(done); perr != nil && err == nil {
					err = perr
				}
			}
			if err != nil {
				return rows, unchanged, pending, err
			}
		}
	}
	return rows, unchanged, pending, nil
}

// expungePending reports whether one move left an old copy behind
// (§3.10, C12). One bool answers for the whole operation: the cause is
// a missing server extension, so it holds for every message of the
// call.
func expungePending(applied []mail.Applied) bool {
	for _, a := range applied {
		if a.ExpungePending {
			return true
		}
	}
	return false
}

// currentID gives the id the message has now: the new id when a move
// changed it, the first id when it did not (C5).
func currentID(c undo.Change) string {
	if c.NewID != "" {
		return c.NewID
	}
	return c.ID
}

// reverseChange builds the change that puts one message back. The
// second value is false when the message needs no change at all.
//
// The flags go from After back to Before. The labels go back by set
// difference, which also reverses a Gmail move: there a folder is a
// label (DS7.4b). When FoldersBefore and FoldersAfter differ, the
// message goes back to the mailboxes of FoldersBefore through
// RestoreFolders, which reverses a JMAP move (DS78.5). A message that
// an IMAP move gave a new id goes back to the folder its first id
// names: §3.8 puts the folder in the id, so the journal needs no field
// of its own for it. An id that does not parse leaves the move out;
// the flags still go back.
//
// A reverse that moves sets KeepJunkKeywords: the provider then does
// not change the junk keywords on the move back (DS8.2d).
//
// applyChange never records a move that has nothing to restore for
// one of its messages (see unresolvedMove). So an IMAP row with an
// empty NewID here is a row that did not move.
//
// arch: T5.3, §3.18, §3.8, C5, DS78.5, DS8.2d
func reverseChange(c undo.Change) (mail.Change, bool) {
	var back mail.Change
	changed := false

	if c.Before.Seen != c.After.Seen {
		seen := c.Before.Seen
		back.Read = &seen
		changed = true
	}
	if c.Before.Flagged != c.After.Flagged {
		flagged := c.Before.Flagged
		back.Starred = &flagged
		changed = true
	}
	for _, l := range c.Before.Labels {
		if !hasLabel(c.After.Labels, l) {
			back.AddLabels = append(back.AddLabels, l)
			changed = true
		}
	}
	for _, l := range c.After.Labels {
		if !hasLabel(c.Before.Labels, l) {
			back.RemoveLabels = append(back.RemoveLabels, l)
			changed = true
		}
	}
	// An empty FoldersBefore has nothing to restore: a JMAP message is
	// in one mailbox at least (IS8.2).
	if len(c.FoldersBefore) > 0 && !undo.SameFolders(c.FoldersBefore, c.FoldersAfter) {
		back.RestoreFolders = append([]string(nil), c.FoldersBefore...)
		changed = true
	}
	if c.NewID != "" {
		if _, _, folder, err := mail.ParseIMAPID(c.ID); err == nil && folder != "" {
			back.MoveTo = folder
			changed = true
		}
	}
	// The labels above give the junk keywords back exactly, so the
	// move back must not apply the junk rule again (DS8.2d).
	back.KeepJunkKeywords = back.MoveTo != "" || len(back.RestoreFolders) > 0
	return back, changed
}

// hasLabel reports whether list holds want. An IMAP keyword and a
// Gmail label are both case insensitive.
func hasLabel(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// changeKey is the grouping key of applyReverse: two changes with the
// same key are the same change.
func changeKey(ch mail.Change) string {
	var b strings.Builder
	b.WriteString(boolKey(ch.Read))
	b.WriteString(boolKey(ch.Starred))
	b.WriteString(strings.Join(sortedCopy(ch.AddLabels), "\x00"))
	b.WriteString("|")
	b.WriteString(strings.Join(sortedCopy(ch.RemoveLabels), "\x00"))
	b.WriteString("|")
	b.WriteString(ch.MoveTo)
	// Two JMAP messages that came from different mailboxes need two
	// calls, so the mailbox list is part of the key (DS78.5).
	b.WriteString("|")
	b.WriteString(strings.Join(sortedCopy(ch.RestoreFolders), "\x00"))
	return b.String()
}

func boolKey(v *bool) string {
	switch {
	case v == nil:
		return "-"
	case *v:
		return "1"
	default:
		return "0"
	}
}

func sortedCopy(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}

// rowsOf turns the provider answer into result rows. The ids come
// from the server, so they carry no fence (§3.15).
func rowsOf(applied []mail.Applied) []ModifyRow {
	rows := make([]ModifyRow, 0, len(applied))
	for _, a := range applied {
		rows = append(rows, ModifyRow{ID: a.ID, NewID: a.NewID, State: stateApplied})
	}
	return rows
}

// goneRows gives one result row with the state "gone" for each id the
// provider did not find (D5.4). The ids come from the call.
func goneRows(ids []string) []ModifyRow {
	rows := make([]ModifyRow, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, ModifyRow{ID: id, State: stateGone})
	}
	return rows
}

// changeOf turns one tool input into the provider change (App B). It
// maps the pseudo labels of §3.16 and refuses a call that names two
// targets.
//
// arch: T5.3, §3.16, App B, C18
func changeOf(in ModifyIn) (mail.Change, error) {
	ch := mail.Change{
		Read:    in.Read,
		Starred: in.Starred,
		MoveTo:  in.MoveTo,
		Archive: in.Archive,
		Trash:   in.Trash,
	}
	if err := mapPseudoLabels(&ch, in.AddLabels, true); err != nil {
		return mail.Change{}, err
	}
	if err := mapPseudoLabels(&ch, in.RemoveLabels, false); err != nil {
		return mail.Change{}, err
	}
	if err := checkTargets(ch); err != nil {
		return mail.Change{}, err
	}
	if ch.Read == nil && ch.Starred == nil && len(ch.AddLabels) == 0 &&
		len(ch.RemoveLabels) == 0 && ch.MoveTo == "" && !ch.Archive && !ch.Trash {
		return mail.Change{}, errors.New("name at least one change: read, starred, add_labels, remove_labels, move_to, archive or trash")
	}
	return ch, nil
}

// mapPseudoLabels moves the four pseudo labels of §3.16 out of a
// label list and onto the verbs of the change (C18). Every other
// label stays a label.
//
// add is true for add_labels and false for remove_labels, and the
// meaning of each pseudo label turns with it:
//
//	UNREAD  added -> read: false        removed -> read: true
//	STARRED added -> starred: true      removed -> starred: false
//	INBOX   added -> move to INBOX      removed -> archive
//	TRASH   added -> trash              removed -> move to INBOX
//
// Models that know Gmail send these names, where the same four labels
// carry the same four meanings. UNREAD is the opposite of \Seen and
// STARRED is \Flagged (C18), so the mapping lives here, in the tool
// layer, once for every provider.
//
// A list that names both sides of one verb is refused. A silent
// choice between "read" and "unread" would leave the mailbox in a
// state nobody asked for.
//
// arch: T5.3, §3.16, App B, C18
func mapPseudoLabels(ch *mail.Change, labels []string, add bool) error {
	for _, raw := range labels {
		label := strings.TrimSpace(raw)
		if label == "" {
			return errors.New("a label must have a name")
		}
		switch strings.ToUpper(label) {
		case "UNREAD":
			if err := setBool(&ch.Read, !add, "read"); err != nil {
				return err
			}
		case "STARRED":
			if err := setBool(&ch.Starred, add, "starred"); err != nil {
				return err
			}
		case "INBOX":
			var err error
			if add {
				err = setMoveTarget(ch, "INBOX", false, false)
			} else {
				err = setMoveTarget(ch, "", true, false)
			}
			if err != nil {
				return err
			}
		case "TRASH":
			var err error
			if add {
				err = setMoveTarget(ch, "", false, true)
			} else {
				err = setMoveTarget(ch, "INBOX", false, false)
			}
			if err != nil {
				return err
			}
		default:
			if add {
				ch.AddLabels = append(ch.AddLabels, label)
			} else {
				ch.RemoveLabels = append(ch.RemoveLabels, label)
			}
		}
	}
	return nil
}

// setBool writes one *bool field of the change, and refuses a second
// value that says the opposite of the first.
func setBool(field **bool, value bool, name string) error {
	if *field != nil && **field != value {
		return fmt.Errorf("the call asks for %s and for its opposite at the same time", name)
	}
	v := value
	*field = &v
	return nil
}

// setMoveTarget writes the move target of the change, and refuses a
// second target that says something else. A pseudo label must never
// take the place of the move_to the caller gave: a silent choice
// between two folders moves mail to a folder nobody asked for.
//
// The same target twice is not an error. add_labels ["TRASH",
// "TRASH"] asks for one thing, once.
//
// arch: T5.3, §3.16, App B, C18
func setMoveTarget(ch *mail.Change, moveTo string, archive, trash bool) error {
	if ch.MoveTo == "" && !ch.Archive && !ch.Trash {
		ch.MoveTo, ch.Archive, ch.Trash = moveTo, archive, trash
		return nil
	}
	if ch.MoveTo == moveTo && ch.Archive == archive && ch.Trash == trash {
		return nil
	}
	return errors.New("name one of move_to, archive and trash; the INBOX and TRASH pseudo labels reach the same three fields")
}

// checkTargets holds the rule of Appendix B: one call names one of
// move_to, archive and trash. The pseudo labels reach the same three
// fields, so the check runs after the mapping.
//
// arch: T5.3, §3.16, App B
func checkTargets(ch mail.Change) error {
	n := 0
	for _, set := range []bool{ch.MoveTo != "", ch.Archive, ch.Trash} {
		if set {
			n++
		}
	}
	if n > 1 {
		return errors.New("name one of move_to, archive and trash; the INBOX and TRASH pseudo labels reach the same three fields")
	}
	return nil
}

// modifySummary is the one-line summary the journal keeps for an
// operation, and the line the undo list shows (§3.18).
//
// A label name and a folder name go through serverText, so a hidden
// character or a forged fence marker in one of them never reaches the
// model through this line (§3.15, G2).
//
// arch: T5.3, §3.18, §3.15, G2
func modifySummary(ch mail.Change, count int) string {
	return fmt.Sprintf("%s on %s", changeWords(ch), plural(count, "message"))
}

// changeWords gives the words of one change for a summary, for
// example "read, +Label, archive". modifySummary and the bulk summary
// use it.
func changeWords(ch mail.Change) string {
	parts := make([]string, 0, 4)
	if ch.Read != nil {
		parts = append(parts, pick(*ch.Read, "read", "unread"))
	}
	if ch.Starred != nil {
		parts = append(parts, pick(*ch.Starred, "starred", "not starred"))
	}
	for _, l := range ch.AddLabels {
		parts = append(parts, "+"+serverText(l))
	}
	for _, l := range ch.RemoveLabels {
		parts = append(parts, "-"+serverText(l))
	}
	switch {
	case ch.Trash:
		parts = append(parts, "trash")
	case ch.Archive:
		parts = append(parts, "archive")
	case ch.MoveTo != "":
		parts = append(parts, "move to "+serverText(ch.MoveTo))
	}
	return strings.Join(parts, ", ")
}

// serverText makes one name safe to show outside a fence: no hidden
// character, and no text that looks like a fence marker. A folder
// name and a label name are not sender-controlled, so §3.15 keeps
// them outside every fence, the same as [FolderRow.Name].
func serverText(s string) string {
	clean, _ := guard.StripInvisible(s)
	return guard.StripFenceMarkers(clean)
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
