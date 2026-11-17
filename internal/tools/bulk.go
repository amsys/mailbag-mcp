// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools holds the bulk tool in bulk.go (DS9.4). It changes every
// message that matches a query, up to max, after the human accepts the
// exact count and a sample. One bulk is one undo record (DS9.5).
package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
	"github.com/amsys/mailbag-mcp/internal/undo"
)

// MaxBulkIDs is the largest id set of one bulk call (DS9.4).
const MaxBulkIDs = 5000

// DefaultBulkMax is the id set of a bulk call with no max.
const DefaultBulkMax = 500

// bulkChunk is the id count of one ModifyDetail call. It equals
// MaxModifyIDs, so each chunk is a call that every provider takes.
const bulkChunk = MaxModifyIDs

// bulkSampleRows is the count of rows the question shows (DS9.4).
const bulkSampleRows = 5

// bulkDryRunSample is the most rows a dry run shows (DS14.14).
const bulkDryRunSample = 50

// bulkDryRunNote is the note of a dry run (DS14.14).
const bulkDryRunNote = "dry run: nothing changed"

// bulkPage is the id count of one search page. IMAP caps a page at
// 100 (internal/imap maxLimit), so a larger value gives nothing more.
const bulkPage = searchMaxLimit

// BulkIn is the input of the bulk tool (DS9.4). Account has no
// omitempty, so the schema makes it required (G10).
type BulkIn struct {
	Account string `json:"account"`
	Query   string `json:"query,omitempty"`
	Folder  string `json:"folder,omitempty" jsonschema:"name or folder_ref"`
	Action  string `json:"action,omitempty" jsonschema:"read unread star unstar archive trash move"`
	MoveTo  string `json:"move_to,omitempty" jsonschema:"name or folder_ref"`
	Max     int    `json:"max,omitempty" jsonschema:"default 500, at most 5000"`
	Undo    string `json:"undo,omitempty" jsonschema:"token, or list"`
	DryRun  bool   `json:"dry_run,omitempty" jsonschema:"count and up to 50 matching rows; changes nothing"`
}

// BulkRow is one sample row (DU5.4). The id and the date are outside:
// the id passed normalizeID for the provider kind (DU3.2), and the
// date is the server date in RFC 3339, UTC. An id that does not pass
// is left out of the row. The from line and the subject are sender
// text, so each sits in its own fence under Untrusted (DU5.1).
type BulkRow struct {
	ID string `json:"id,omitempty" strict:"id"`
	// Date is the server date of the message (DS14.14). A zero time
	// is left out.
	Date string `json:"date,omitempty" strict:"date"`
	// Untrusted holds the fenced sender text of the row (DU5.1).
	Untrusted BulkUntrusted `json:"untrusted"`
}

// BulkUntrusted is the untrusted zone of one sample row. Each field is
// one fence of the nonce of the response.
type BulkUntrusted struct {
	From    string `json:"from,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// BulkOut is the bulk tool result (DS9.4, DU5.4).
//
// Head gives the nonce first. Outside: the counts, the undo token, the
// skipped ids after normalizeID (DU3.2), the undo list and a note of
// the registry (DU3.5). Each sample row and each undo list row has its
// own untrusted zone. Untrusted.Detail holds the provider error text
// of a change that stopped part of the way; the note ends with its
// class word (DU6.2).
type BulkOut struct {
	Head
	// Count is the count of ids that matched, at most max.
	Count int `json:"count"`
	// Applied is the count of ids that changed. After an undo it is
	// the count of messages that the reversal reached.
	Applied int `json:"applied"`
	// Gone is the count of ids that another client removed between
	// the question and the change.
	Gone   int       `json:"gone,omitempty"`
	Sample []BulkRow `json:"sample,omitempty"`
	// Undo is the journal record id that reverses this bulk.
	Undo string `json:"undo,omitempty" strict:"id"`
	// Skipped answers an undo: the ids that changed or went away since
	// the operation. Undo left them as they are (DS9.5, G17). The ids
	// come from the journal and pass normalizeID (DU3.2).
	Skipped []string `json:"skipped,omitempty" strict:"id"`
	// Records answers undo: "list", newest first.
	Records []UndoRow `json:"records,omitempty"`
	// Note is text this tool wrote: a text of the note registry
	// (DU3.5).
	Note string `json:"note,omitempty" strict:"note"`
	// Untrusted holds the provider error text that the note names by
	// its class word (DU3.5, DU6.2).
	Untrusted *Detail `json:"untrusted,omitempty"`
}

// The fixed notes of the bulk tool.
const (
	bulkNothingNote  = "nothing matches; no change"
	bulkDeclinedNote = "declined; nothing changed"
	// bulkGrantGivenNote is the note of the call whose accept gave
	// the session grant (DS14.11).
	bulkGrantGivenNote = "the human allowed later bulk changes on this account with no question until the client reconnects"
	// bulkGrantUsedNote is the note of a call that ran under the
	// session grant and asked nobody (DS14.11).
	bulkGrantUsedNote = "no question: the human allowed bulk changes on this account until the client reconnects"
)

// The confirm outcomes of the session grant (DS14.11). The other
// outcomes are in send.go.
const (
	// confirmAcceptSession is an accept with remember true. It
	// changes mail as [confirmAccept] does and gives the grant.
	confirmAcceptSession = "elicit_accept_session"
	// confirmGranted is a call that a grant covers. It asked nobody.
	confirmGranted = "session_grant"
)

// bulkField is the boolean field of the bulk question that changes
// mail. Only the value true with action "accept" changes mail (DS9.4,
// H4).
const bulkField = "apply"

// bulkRemember is the optional boolean field of the bulk question.
// The value true with apply true and action "accept" gives the
// session grant (DS14.11). Alone it changes nothing and grants
// nothing.
const bulkRemember = "remember"

// bulkSchema is the requested schema of the bulk question.
var bulkSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		bulkField: map[string]any{
			"type":        "boolean",
			"title":       "Apply this change",
			"description": "Set to true to change the messages above.",
		},
		bulkRemember: map[string]any{
			"type":        "boolean",
			"title":       "Yes, and do not ask again until reconnect",
			"description": "Set to true with apply to make later bulk changes on this account with no question until the client reconnects.",
			"default":     false,
		},
	},
	"required": []string{bulkField},
}

// errBulkNoElicitation is the fixed refusal for a client that cannot
// ask the human. It has the shape of [errNoElicitation]: it does not
// name the config key, because the model reads this text and only the
// human may turn the question off.
var errBulkNoElicitation = public("refused", "this client cannot ask the human to confirm a bulk change, so nothing changed; the human can make the change in a mail program")

// bulkNotConfirmedText is the error text of a question that did not
// complete: the client failed or the call ended during the wait.
const bulkNotConfirmedText = "the confirmation did not complete, so nothing changed"

// bulkActions maps each action word to its change. move takes its
// target from move_to.
var bulkActions = map[string]func() mail.Change{
	"read":    func() mail.Change { v := true; return mail.Change{Read: &v} },
	"unread":  func() mail.Change { v := false; return mail.Change{Read: &v} },
	"star":    func() mail.Change { v := true; return mail.Change{Starred: &v} },
	"unstar":  func() mail.Change { v := false; return mail.Change{Starred: &v} },
	"archive": func() mail.Change { return mail.Change{Archive: true} },
	"trash":   func() mail.Change { return mail.Change{Trash: true} },
	"move":    func() mail.Change { return mail.Change{} },
}

// AddBulk adds the "bulk" tool to srv (DS9.4). It is not in a toolset
// yet; T270 registers it.
//
// The tool uses [WrapReq], because it asks the human through the
// session of the call, and [LongTimeout], because a set of 5000 ids
// takes 50 search pages and 10 change calls. It carries the Meta key
// anthropic/requiresUserInteraction, as send does (D5.2, layer B).
// DestructiveHint is false: the journal reverses the change, and trash
// and archive are moves (C12).
//
// arch: DS9.4, DS9.5, D5.1, D5.2
func AddBulk(srv *mcp.Server, logger *slog.Logger, m Mail) {
	addBulk(srv, &bulkTool{mail: m, journal: undo.Open, logger: logger})
}

// addBulk adds the bulk tool h to srv. A test gives its own h.
func addBulk(srv *mcp.Server, h *bulkTool) {
	no := false
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "bulk",
		Description: "Change every message that matches a query, after the human confirms (one time, or for this account until reconnect); or undo. Before a change by sender, call with dry_run; keep receipts, invoices and account mail out of the query.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &no},
		Meta:        mcp.Meta{requiresUserInteraction: true},
	}, WrapReq(h.logger, "bulk", LongTimeout, h.handleReq))
}

// bulkTool is the bulk handler. journal gives the undo directory; nil
// means undo.Open. logger takes the confirm line and the warn line of
// a journal write that failed; nil means slog.Default().
//
// pending keeps each open confirmation of the MRTR path (DS14.3).
// grants keeps the session grants (DS14.11). Their zero values work.
type bulkTool struct {
	mail    Mail
	journal func() (*undo.Journal, error)
	logger  *slog.Logger
	pending pendingStore[pendingBulk]
	grants  grantStore
}

// pendingBulk is the record of one open bulk confirmation (DS14.6).
// The retry must give the same session, account and input fields
// (DS14.7). The change of the retry runs on ids, the set that the
// human saw, and not on a new search.
//
// arch: DS14.6, DS14.7
type pendingBulk struct {
	session *mcp.ServerSession
	account string
	// input holds query, folder, action, move_to and max of the first
	// call. Account and Undo are empty.
	input BulkIn
	set   bulkSet
}

// bulkSet is the match set of one bulk call: the ids, the sample rows
// of the question, and more, which is true when the set stopped at
// max. The sample holds plain text with no fence, so the pending
// store keeps no fence and no nonce (INV-6).
type bulkSet struct {
	ids    []string
	sample []bulkSample
	more   bool
}

// bulkSample is one sample row as the provider gave it, with no fence.
// [bulkRows] fences it for the result of each response, and
// [bulkQuestion] shows it to the human with [plainLine].
//
// arch: DU5.4, INV-6
type bulkSample struct {
	id, from, subject string
	date              time.Time
}

// askFunc asks the human to accept message. It gives one of the
// confirm outcomes of send.go, or an error.
type askFunc func(ctx context.Context, acct config.Account, message string) (string, error)

// confirmSetFunc is [askFunc] that also gets the match set. The first
// call of the MRTR path keeps that set in its record (DS14.6).
type confirmSetFunc func(ctx context.Context, acct config.Account, set bulkSet, message string) (string, error)

// claimFunc is the claim step of the MRTR retry (DS14.7). It gets the
// alias that OpenWriter gave and gives the match set of the record.
type claimFunc func(account string) (bulkSet, error)

// handleReq is the handler that [addBulk] registers.
//
// A session on a protocol before [elicitCutoffProtocol] asks the
// human through the session of req with [askBulk], as before
// (DS14.1). Such a session that gives a request state gets
// [errConfirmStale] (DS14.8).
//
// A session on [elicitCutoffProtocol] or later uses the MRTR path. A
// call with no request state is the first call: it gives the question
// as an [inputRequired] value (DS14.6). A call with a request state is
// the retry: it takes the record of that state and reads the answer
// (DS14.7).
//
// On both paths, a session that holds the grant of the account asks
// nobody and gives [confirmGranted]. An answer of
// [confirmAcceptSession] gives that grant (DS14.11).
//
// A call with dry_run skips both paths and runs [bulkTool.dryRun]
// (DS14.14).
//
// arch: DS9.4, DS14.1, DS14.6, DS14.7, DS14.8, DS14.11, DS14.14
func (t *bulkTool) handleReq(ctx context.Context, req *mcp.CallToolRequest, in BulkIn) (BulkOut, error) {
	if in.DryRun {
		return t.dryRun(ctx, in)
	}
	ss := sessionOf(req)
	state, answers := retryOf(req)
	if !newProtocol(ss) {
		if state != "" {
			return BulkOut{}, errConfirmStale
		}
		return t.run(ctx, in, func(ctx context.Context, acct config.Account, message string) (string, error) {
			if t.grants.has(ss, acct.Alias) {
				return confirmGranted, nil
			}
			outcome, err := askBulk(ctx, ss, acct, message)
			t.keepGrant(ss, acct, outcome)
			return outcome, err
		})
	}
	if state == "" {
		return t.runSet(ctx, in, nil, func(_ context.Context, acct config.Account, set bulkSet, message string) (string, error) {
			if t.grants.has(ss, acct.Alias) {
				return confirmGranted, nil
			}
			return t.askFirst(ss, acct, in, set, message)
		})
	}
	claim := func(account string) (bulkSet, error) {
		return t.claimPending(ss, state, account, in)
	}
	return t.runSet(ctx, in, claim, func(_ context.Context, acct config.Account, _ bulkSet, _ string) (string, error) {
		outcome := bulkAnswer(answers)
		t.keepGrant(ss, acct, outcome)
		return outcome, nil
	})
}

// dryRun answers a call with dry_run (DS14.14). It needs the access
// level read, because nothing changes. It collects the ids as a bulk
// call does and gives the count and up to [bulkDryRunSample] rows with
// their dates. It asks nobody, checks no grant, and keeps no pending
// record, no undo record and no journal line. It opens the provider
// as a reader, so no write method can run (IS14.9). The action is not
// run, so it is not checked. A call with undo is an input error.
//
// The rows of the result have the shape of DU5.4: the id after
// normalizeID and the date outside, the sender text in fences.
//
// arch: DS14.14, IS14.9, DU5.4, DU3.3
func (t *bulkTool) dryRun(ctx context.Context, in BulkIn) (BulkOut, error) {
	f := fencer(ctx)
	if strings.TrimSpace(in.Undo) != "" {
		return BulkOut{}, public("invalid_input", "dry_run and undo do not go together; send them in two calls")
	}
	p, acct, err := t.mail.Open(ctx, in.Account)
	if err != nil {
		return BulkOut{}, err
	}
	if err := guard.Require(acct, guard.LevelRead); err != nil {
		return BulkOut{}, err
	}
	sel, err := in.folderInput()
	if err != nil {
		return BulkOut{}, err
	}
	limit := in.Max
	if limit <= 0 {
		limit = DefaultBulkMax
	}
	limit = min(limit, MaxBulkIDs)
	ids, sample, more, err := collectIDs(ctx, p, sel, limit, bulkDryRunSample)
	if err != nil {
		return BulkOut{}, err
	}
	out := BulkOut{Count: len(ids), Sample: bulkRows(f, acct.Provider, sample), Note: bulkDryRunNote}
	if more {
		out.Note = joinNote(out.Note, fmt.Sprintf("the set stops at max = %d; more messages can match", limit))
	}
	return out, nil
}

// keepGrant gives ss the grant of the account acct when outcome is
// [confirmAcceptSession]. Any other outcome grants nothing (DS14.11).
//
// arch: DS14.11
func (t *bulkTool) keepGrant(ss *mcp.ServerSession, acct config.Account, outcome string) {
	if outcome == confirmAcceptSession {
		t.grants.grant(ss, acct.Alias)
	}
}

// askFirst is the question of the first call on the MRTR path
// (DS14.6). It keeps a pending record with a copy of the match set and
// gives the question of [askBulk] as an [inputRequired] value with the
// outcome [confirmPending].
//
// A client with no form elicitation gives [errBulkNoElicitation],
// unless accounts.toml has [bulk] allow_without_elicitation = true
// (DS14.2). A full store gives [errPendingFull] and a full session
// share gives [errPendingSessionFull]; both ask nobody (DS14.3,
// DS14.12).
//
// The record goes into a place from [pendingStore.hold] that matches
// the session, the account and [bulkInput] of in, the fields that
// [bulkTool.claimPending] checks. A repeat first call with the same
// input removes the open record, takes its place and gets a new
// state; the old state is then stale. A different input takes a new
// place (DS14.13, IS14.8).
//
// arch: DS14.2, DS14.3, DS14.6, DS14.9, DS14.12, DS14.13, IS14.8
func (t *bulkTool) askFirst(ss *mcp.ServerSession, acct config.Account, in BulkIn, set bulkSet, message string) (string, error) {
	if !canElicit(ss) {
		if acct.BulkAllowWithoutElicitation {
			return confirmNoElicitAllowed, nil
		}
		return confirmNoElicitRefused, errBulkNoElicitation
	}
	input := bulkInput(in)
	// A repeat first call with the same input gets the place of the
	// open record and a new state, so an accept of the old prompt
	// cannot act on the new set (DS14.13).
	place, _, err := t.pending.hold(ss, func(r pendingBulk) bool {
		return r.session == ss && r.account == acct.Alias && r.input == input
	})
	if err != nil {
		return "", err
	}
	state, err := place.fill(pendingBulk{
		session: ss,
		account: acct.Alias,
		input:   input,
		set: bulkSet{
			ids:    slices.Clone(set.ids),
			sample: slices.Clone(set.sample),
			more:   set.more,
		},
	})
	if err != nil {
		return "", err
	}
	return confirmPending, &inputRequired{
		requests: mcp.InputRequestMap{confirmInputID: &mcp.ElicitParams{
			Mode:            "form",
			Message:         message,
			RequestedSchema: bulkSchema,
		}},
		state: state,
	}
}

// bulkInput gives the input fields of in that a record covers: query,
// folder, action, move_to and max (DS14.6).
func bulkInput(in BulkIn) BulkIn {
	in.Account = ""
	in.Undo = ""
	return in
}

// claimPending is the claim step of the retry (DS14.7). It takes the
// record of state, so the state works one time only. It gives
// [errConfirmStale] when the store has no open record of state, or
// when the session, the account or the input fields of the record
// differ from the retry (IS14.2).
//
// arch: DS14.7, IS14.2
func (t *bulkTool) claimPending(ss *mcp.ServerSession, state, account string, in BulkIn) (bulkSet, error) {
	rec, ok := t.pending.take(state)
	if !ok || rec.session != ss || rec.account != account || rec.input != bulkInput(in) {
		return bulkSet{}, errConfirmStale
	}
	return rec.set, nil
}

// bulkAnswer reads the answer of the retry under [confirmInputID]
// (DS14.7) with the rules of [bulkOutcome]. No answer gives
// [confirmDecline].
//
// arch: DS14.5, DS14.7, DS14.11, IS14.6
func bulkAnswer(answers mcp.InputResponseMap) string {
	res, ok := answers[confirmInputID].(*mcp.ElicitResult)
	if !ok || res == nil {
		return confirmDecline
	}
	return bulkOutcome(res)
}

// bulkOutcome reads one answer of the bulk question. Only the action
// "accept" with the field apply equal to true changes mail: with the
// field remember also equal to true it gives [confirmAcceptSession],
// else [confirmAccept]. The action "cancel" gives [confirmCancel].
// Any other answer gives [confirmDecline].
//
// arch: DS9.4, DS14.7, DS14.11, H4
func bulkOutcome(res *mcp.ElicitResult) string {
	switch res.Action {
	case "accept":
		if v, ok := res.Content[bulkField].(bool); !ok || !v {
			return confirmDecline
		}
		if v, ok := res.Content[bulkRemember].(bool); ok && v {
			return confirmAcceptSession
		}
		return confirmAccept
	case "cancel":
		return confirmCancel
	default:
		return confirmDecline
	}
}

// run runs one bulk call in the order of DS9.4: the account and the
// access check, the undo branch, the checks of the input, the id
// collection, the question, then the change in chunks on a detached
// context.
//
// arch: DS9.4, DS9.5, DS9.11, DS9.12, IS9.2, IS9.3, IS9.10, H1, H2, H4
func (t *bulkTool) run(ctx context.Context, in BulkIn, ask askFunc) (BulkOut, error) {
	return t.runSet(ctx, in, nil, func(ctx context.Context, acct config.Account, _ bulkSet, message string) (string, error) {
		return ask(ctx, acct, message)
	})
}

// runSet is [bulkTool.run] with the claim step of the MRTR retry.
// claim is nil on every call except that retry. On the retry, a call
// with undo set is refused, and claim runs after the input checks in
// place of the id collection: the change runs on the ids of the
// record (DS14.7). The other steps are the steps of run.
//
// The folder and move_to accept a name or a folder_ref (DU3.3). The
// sample rows of the result are made from the plain sample of the set
// with the Fencer of this call, so a retry fences them with its own
// nonce (DU5.4, INV-6).
//
// arch: DS9.4, DS9.5, DS9.11, DS9.12, DS14.6, DS14.7, IS9.2, IS9.3, IS9.10, IS14.1, H1, H2, H4, DU5.4, DU3.3
func (t *bulkTool) runSet(ctx context.Context, in BulkIn, claim claimFunc, ask confirmSetFunc) (BulkOut, error) {
	f := fencer(ctx)
	p, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return BulkOut{}, err
	}
	if err := guard.Require(acct, guard.LevelDraft); err != nil {
		return BulkOut{}, err
	}

	if token := strings.TrimSpace(in.Undo); token != "" {
		if claim != nil {
			// No first call with undo set gives a request state.
			return BulkOut{}, errConfirmStale
		}
		if in.Query != "" || in.Folder != "" || in.Action != "" || in.MoveTo != "" || in.Max != 0 {
			return BulkOut{}, public("invalid_input", "undo takes the call on its own; send the change in a second call")
		}
		return t.undo(ctx, f, p, acct, token)
	}

	ch, err := bulkChange(in)
	if err != nil {
		return BulkOut{}, err
	}
	// sel is in with the folder name that a ref holds. The pending
	// record keeps in as the call gave it, so the retry compares the
	// same input (DS14.7).
	sel, err := in.folderInput()
	if err != nil {
		return BulkOut{}, err
	}
	limit := in.Max
	if limit <= 0 {
		limit = DefaultBulkMax
	}
	limit = min(limit, MaxBulkIDs)

	var set bulkSet
	if claim != nil {
		set, err = claim(acct.Alias)
	} else {
		set.ids, set.sample, set.more, err = collectIDs(ctx, p, sel, limit, bulkSampleRows)
	}
	if err != nil {
		return BulkOut{}, err
	}
	ids, sample, more := set.ids, set.sample, set.more
	out := BulkOut{Count: len(ids), Sample: bulkRows(f, acct.Provider, sample)}
	if len(ids) == 0 {
		out.Note = bulkNothingNote
		return out, nil
	}
	if more {
		out.Note = fmt.Sprintf("the set stops at max = %d; more messages can match, and a second bulk call takes them", limit)
	}

	outcome, err := ask(ctx, acct, set, bulkQuestion(sel, ch, len(ids), more, sample))
	if outcome != "" {
		t.log().Info("bulk-confirm", "tool", "bulk", "confirm", outcome, "count", len(ids))
	}
	if err != nil {
		return BulkOut{}, err
	}
	base := ctx
	switch outcome {
	case confirmAccept, confirmAcceptSession:
		// D5.2: the wait for the human does not count against the
		// tool deadline, so the change gets a full deadline of its own.
		if wait, _, ok := untimed(ctx); ok {
			base = wait
		}
		if outcome == confirmAcceptSession {
			out.Note = joinNote(out.Note, bulkGrantGivenNote)
		}
	case confirmGranted:
		// DS14.11: no wait came first; the change keeps the tool
		// deadline.
		out.Note = joinNote(out.Note, bulkGrantUsedNote)
	case confirmNoElicitAllowed:
		// No wait came first; the change keeps the tool deadline.
	default:
		out.Note = bulkDeclinedNote
		return out, nil
	}

	// DS11.9, IS9.10: the first provider call is the point of no
	// return. From here the change completes without the session.
	dctx, cancel := detach(base, LongTimeout)
	defer cancel()
	if err := t.apply(dctx, f, p, in.Account, ids, ch, &out); err != nil && out.Applied == 0 {
		// Nothing changed, so the call fails as modify does.
		return BulkOut{}, err
	}
	return out, nil
}

// apply runs the change over ids in chunks of bulkChunk. After the
// first chunk with a changed row it writes the journal record with
// Append, and after each later chunk it adds the rows with Extend, so
// one bulk is one record and a stop after chunk n leaves the rows of
// chunks 1 to n in it (IS9.3, IRV.9).
//
// A chunk error stops the loop. The rows that the failed chunk changed
// go to the record first (DRV.11). A journal that cannot be written
// does not stop the change: the human accepted it (C14). A move whose
// rows give undo nothing to restore is not journaled (unresolvedMove,
// as in modify).
//
// It gives the chunk error, if any; the rows that changed are in out.
// The note names the class word of that error, and its text goes to
// out.Untrusted.Detail in a fence of f (DU3.5, DU6.2).
//
// arch: DS9.4, DS9.5, IS9.3, IRV.9, C14, DS78.5, DU3.5, DU6.2
func (t *bulkTool) apply(ctx context.Context, f guard.Fencer, p Writer, account string, ids []string, ch mail.Change, out *BulkOut) error {
	open := t.journal
	if open == nil {
		open = undo.Open
	}
	j, jerr := open()
	if jerr != nil {
		t.log().Warn("undo journal open failed", "account", account, "err", jerr)
	}
	// The summary goes to the journal with chunk 1, before the count
	// of changed rows is known. So it names the matched count as
	// matched; the undo list gives the changed rows in Count (R16-L8).
	summary := bulkSummary(ch, len(ids))

	var rec undo.Record
	recorded, journalFailed, unresolved, pending := false, jerr != nil, false, false
	journaled := 0
	var stopErr error
	for start := 0; start < len(ids); start += bulkChunk {
		chunk := ids[start:min(start+bulkChunk, len(ids))]
		res, err := p.ModifyDetail(ctx, chunk, ch)
		out.Applied += len(res.Applied)
		out.Gone += len(res.Gone)
		pending = pending || res.ExpungePending || expungePending(res.Applied)
		if unresolvedMove(ch, res.Applied) {
			unresolved = true
		}
		clearUnmoved(res.Applied)
		if len(res.Applied) > 0 && !journalFailed && !unresolved {
			var next undo.Record
			var werr error
			if !recorded {
				next, werr = j.Append(account, "bulk", summary, res.Applied)
			} else {
				next, werr = j.Extend(rec.ID, res.Applied)
			}
			if werr != nil {
				// rec keeps the record of the chunks before, so its
				// token still reaches them (R16-L2).
				t.log().Warn("undo journal write failed", "account", account, "err", werr)
				journalFailed = true
			} else {
				rec = next
				recorded = true
				journaled += len(res.Applied)
			}
		}
		if err != nil {
			stopErr = err
			break
		}
	}

	var notes []string
	if stopErr != nil {
		notes = append(notes, "the change stopped part of the way: "+classOf(stopErr),
			fmt.Sprintf("%d of the %d messages changed", out.Applied, len(ids)))
		out.Untrusted = errDetail(f, stopErr)
	}
	if stopErr == nil && out.Applied == 0 {
		notes = append(notes, "no message changed; every id is gone, because another client expunged or moved the message")
	}
	if out.Note != "" {
		notes = append(notes, out.Note)
	}
	if pending {
		notes = append(notes, "the server could not remove the old copies of the moved messages, so they are in two folders")
	}
	switch {
	case unresolved:
		text := "the change is done; this operation has no undo token, because the server gave no new id for the move, and undo cannot find the message again by its old id"
		if recorded {
			text += fmt.Sprintf("; undo record %s holds the first %d messages", rec.ID, journaled)
		}
		notes = append(notes, text)
	case recorded:
		out.Undo = rec.ID
		if journaled < out.Applied {
			notes = append(notes, fmt.Sprintf("the journal could not be written for every chunk; the undo token reverses %d of the %d messages that changed", journaled, out.Applied))
		}
	case out.Applied > 0:
		notes = append(notes, "the change is done; this operation has no undo token, because the journal could not be written")
	}
	out.Note = strings.Join(notes, noteSep)
	return stopErr
}

// bulkSummary is the summary the journal keeps for one bulk (§3.18,
// DU3.5), in the form of modifySummary. Its first line is a text of
// the note registry: "bulk: " and the closed action words, then the
// matched count. A move adds a second line with the words of
// changeWords, which name the target folder; the undo list shows that
// line in a fence (undoRow).
//
// arch: DS9.5, §3.18, R16-L8, DU3.5
func bulkSummary(ch mail.Change, matched int) string {
	s := "bulk: " + actionWords(ch) + noteSep + plural(matched, "message") + " matched"
	if ch.MoveTo != "" {
		s += summaryNamesSep + changeWords(ch)
	}
	return s
}

// undo answers undo: "list" and undo: "<token>" through the helpers
// that modify uses, so either tool reverses the records of both
// (DS9.5). f fences the folder names of the undo list rows. The
// skipped ids pass normalizeID for the provider kind of acct (DU3.2).
//
// arch: DS9.5, H3, G17, DU3.2, DU3.5, DU5.4
func (t *bulkTool) undo(ctx context.Context, f guard.Fencer, p Writer, acct config.Account, token string) (BulkOut, error) {
	if strings.EqualFold(token, undoListWord) {
		rows, err := undoList(f, t.journal, acct.Alias)
		if err != nil {
			return BulkOut{}, err
		}
		out := BulkOut{Records: rows}
		if len(rows) == 0 {
			out.Note = "this account has no recorded operation"
		}
		return out, nil
	}
	r, err := reverseRecord(ctx, t.journal, p, acct.Alias, token, t.logger)
	if err != nil {
		return BulkOut{}, err
	}
	out := BulkOut{Applied: len(r.Rows), Skipped: normalIDs(acct.Provider, r.Skipped)}
	if len(r.Rows) == 0 {
		out.Note = "the operation is marked reversed; no message needed a change to go back"
	}
	if len(r.Skipped) > 0 {
		out.Note = joinNote(out.Note, fmt.Sprintf("%d messages changed or gone since the operation were left as they are", len(r.Skipped)))
	}
	if r.ExpungePending {
		out.Note = joinNote(out.Note, "the server could not remove the old copies of the moved messages, so they are in two folders")
	}
	return out, nil
}

// joinNote joins two notes of one bulk result with "; ", as apply
// joins its notes.
func joinNote(have, add string) string {
	if have == "" {
		return add
	}
	return have + "; " + add
}

// bulkActionHelp is the error text of an action that is missing or
// not known.
const bulkActionHelp = "action: name one of read, unread, star, unstar, archive, trash, move"

// bulkChange checks action and move_to and gives the change. move_to
// accepts a name or a folder_ref (DU3.3). An unknown action is echoed
// only in the fenced detail of the error (DU6.2, INV-10).
//
// arch: DS9.4, DU3.3, DU6.2
func bulkChange(in BulkIn) (mail.Change, error) {
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action == "" {
		return mail.Change{}, public("invalid_input", bulkActionHelp)
	}
	build, ok := bulkActions[action]
	if !ok {
		return mail.Change{}, publicDetail("invalid_input", bulkActionHelp, in.Action)
	}
	ch := build()
	moveTo, err := folderArg(strings.TrimSpace(in.MoveTo))
	if err != nil {
		return mail.Change{}, err
	}
	switch {
	case action == "move" && moveTo == "":
		return mail.Change{}, public("invalid_input", "action move needs move_to")
	case action == "move":
		ch.MoveTo = moveTo
	case moveTo != "":
		return mail.Change{}, public("invalid_input", "move_to belongs to action move only")
	}
	return ch, nil
}

// folderInput gives a copy of in whose folder passed folderArg
// (DU3.3): a folder_ref decodes to the raw name, and a name loses its
// fence markers.
//
// arch: DU3.3, INV-10
func (in BulkIn) folderInput() (BulkIn, error) {
	folder, err := folderArg(in.Folder)
	if err != nil {
		return BulkIn{}, err
	}
	in.Folder = folder
	return in, nil
}

// collectIDs gives the ids of the match set, at most limit, in the
// order of the search. The first page is a normal search, and its rows
// give the sample; the later pages are ids only (DS9.4). A page with
// Partial set is refused: the count must be exact (H2, S9-GAP1). more
// is true when the set stopped at limit and a cursor was left. The
// sample holds at most sampleN rows, in plain text. in.Folder is a
// folder name: the caller decodes a ref first (folderInput).
//
// The note of a Partial page goes to the fenced detail of the error,
// because it is provider text (DU3.5, DU6.2).
//
// arch: DS9.4, H2, S9-GAP1, DU5.4, DU6.2
func collectIDs(ctx context.Context, p Reader, in BulkIn, limit, sampleN int) (ids []string, sample []bulkSample, more bool, err error) {
	seen := make(map[string]bool, limit)
	cursor := ""
	for first := true; ; first = false {
		q := mail.Query{
			Raw:     in.Query,
			Folder:  in.Folder,
			Limit:   min(bulkPage, limit-len(ids)),
			Cursor:  cursor,
			IDsOnly: !first,
		}
		page, err := p.Search(ctx, q)
		if err != nil {
			return nil, nil, false, err
		}
		if page.Partial {
			if page.Note == "" {
				return nil, nil, false, public("refused", "bulk needs an exact match set; the provider filtered part of the query on the client")
			}
			return nil, nil, false, publicDetail("refused", "bulk needs an exact match set", page.Note)
		}
		for i := range page.Messages {
			m := &page.Messages[i]
			if m.ID == "" || seen[m.ID] || len(ids) >= limit {
				continue
			}
			seen[m.ID] = true
			ids = append(ids, m.ID)
			if first && len(sample) < sampleN {
				sample = append(sample, bulkSample{id: m.ID, from: addressText(m.From), subject: m.Subject, date: m.Date})
			}
		}
		cursor = page.NextCursor
		if cursor == "" || len(page.Messages) == 0 {
			return ids, sample, false, nil
		}
		if len(ids) >= limit {
			return ids, sample, true, nil
		}
	}
}

// bulkRows gives the sample rows of one result (DU5.4). The id passes
// normalizeID for the provider kind; an id that does not pass is left
// out of its row (DU3.2). The from line and the subject each go into
// one fence of f, after the steps of toSearchRow: a link that Sanitize
// makes whole again is defanged (D4.1 item 3). An empty text stays
// empty, so its field is omitted. No sample gives nil.
//
// arch: DS9.4, D4.1, DU5.1, DU5.4, DU3.2
func bulkRows(f guard.Fencer, kind string, sample []bulkSample) []BulkRow {
	if len(sample) == 0 {
		return nil
	}
	shown := func(s string) string {
		if s == "" {
			return ""
		}
		return f.Wrap(mime.DefangLinks(guard.Sanitize(s)))
	}
	rows := make([]BulkRow, 0, len(sample))
	for _, s := range sample {
		id, _ := normalizeID(kind, s.id)
		rows = append(rows, BulkRow{
			ID:        id,
			Date:      dateText(s.date),
			Untrusted: BulkUntrusted{From: shown(s.from), Subject: shown(s.subject)},
		})
	}
	return rows
}

// plainLineMax is the most runes that [plainLine] gives (DU5.4).
const plainLineMax = 120

// plainLine makes one line of sender text for the human (DU5.4): it
// runs guard.Sanitize, so a forged marker loses its bracket and a
// hidden character goes; it turns each line break, other white space
// and control character into a space; and it cuts the text to
// plainLineMax runes. A cut text ends in "…", so the human sees that
// it was cut. The result holds no marker and no nonce.
//
// arch: DU5.4, INV-7
func plainLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r != ' ' && (unicode.IsSpace(r) || unicode.IsControl(r)) {
			return ' '
		}
		return r
	}, guard.Sanitize(s))
	if utf8.RuneCountInString(s) <= plainLineMax {
		return s
	}
	runes := []rune(s)
	return string(runes[:plainLineMax-1]) + "…"
}

// bulkQuestion is the text the human accepts (DS9.4 step 6, DU5.4):
// "<action> <count> messages in <alias>/<folder> that match "<query>".
// First 5:" and the sample, one line for the from line and one for the
// subject of each row. The question goes to the human through
// elicitation or MRTR, so it holds no fence marker and no nonce. The
// sender text of each row passes [plainLine], and its links are
// defanged after it (D4.1). The alias, the folder and the query are
// model text, so each loses its hidden characters and its fence
// markers first (serverText); the folder name also passes plainLine.
//
// arch: DS9.4, DU5.4, D4.1, INV-7
func bulkQuestion(in BulkIn, ch mail.Change, count int, more bool, sample []bulkSample) string {
	var b strings.Builder
	b.WriteString(bulkActionText(ch))
	fmt.Fprintf(&b, " %s in %s", plural(count, "message"), serverText(in.Account))
	if in.Folder != "" {
		b.WriteString("/" + plainLine(serverText(in.Folder)))
	}
	if q := strings.TrimSpace(in.Query); q != "" {
		fmt.Fprintf(&b, " that match %q", serverText(q))
	} else {
		b.WriteString(" (no query: every message)")
	}
	b.WriteString(".")
	if more {
		b.WriteString(" More messages can match; this change takes these only.")
	}
	fmt.Fprintf(&b, " First %d:", len(sample))
	for _, r := range sample {
		b.WriteString("\n- ")
		b.WriteString(mime.DefangLinks(plainLine(r.from)))
		b.WriteString("\n  ")
		b.WriteString(mime.DefangLinks(plainLine(r.subject)))
	}
	return b.String()
}

// bulkActionText gives the verb of the question.
func bulkActionText(ch mail.Change) string {
	switch {
	case ch.Read != nil:
		return pick(*ch.Read, "Mark read", "Mark unread")
	case ch.Starred != nil:
		return pick(*ch.Starred, "Star", "Unstar")
	case ch.Archive:
		return "Archive"
	case ch.Trash:
		return "Trash"
	default:
		return "Move to " + plainLine(serverText(ch.MoveTo)) + ":"
	}
}

// askBulk is the question of DS9.4 step 6, in the pattern of
// [confirmByElicit]: a form with the boolean field apply and the
// optional boolean field remember. [bulkOutcome] reads the answer
// (DS14.11). A client with no elicitation
// gives a fixed refusal, unless accounts.toml has [bulk]
// allow_without_elicitation = true. The wait uses the call context
// without the tool deadline, bounded by [confirmWaitLimit].
//
// arch: DS9.4, D5.1, D5.2, H1, H4
func askBulk(ctx context.Context, ss *mcp.ServerSession, acct config.Account, message string) (string, error) {
	outcome, err := askConfirm(ctx, ss, acct, message, bulkSchema, bulkNotConfirmedText)
	if outcome == confirmNoElicitRefused {
		return outcome, errBulkNoElicitation
	}
	return outcome, err
}

// askConfirm asks the human one question with the form schema and
// reads the answer with [bulkOutcome]. A client with no elicitation
// gives [confirmNoElicitAllowed] when acct has [bulk]
// allow_without_elicitation = true, and else
// [confirmNoElicitRefused] with a nil error, so that each caller
// gives its own fixed refusal. The wait uses the call context without
// the tool deadline, bounded by [confirmWaitLimit]. A question that
// does not complete gives an error with the text notConfirmedText.
//
// arch: DH3.4, DS9.4, D5.2, H4
func askConfirm(ctx context.Context, ss *mcp.ServerSession, acct config.Account, message string, schema map[string]any, notConfirmedText string) (string, error) {
	if !canElicit(ss) {
		if acct.BulkAllowWithoutElicitation {
			return confirmNoElicitAllowed, nil
		}
		return confirmNoElicitRefused, nil
	}
	wait, _, _ := untimed(ctx)
	wait, cancel := context.WithTimeout(wait, confirmWaitLimit)
	defer cancel()
	res, err := ss.Elicit(wait, &mcp.ElicitParams{
		Mode:            "form",
		Message:         message,
		RequestedSchema: schema,
	})
	if err != nil {
		if ctxErr := wait.Err(); ctxErr != nil {
			return "", fmt.Errorf("%s: %w", notConfirmedText, ctxErr)
		}
		return "", errors.New(notConfirmedText)
	}
	return bulkOutcome(res), nil
}

func (t *bulkTool) log() *slog.Logger {
	if t.logger == nil {
		return slog.Default()
	}
	return t.logger
}
