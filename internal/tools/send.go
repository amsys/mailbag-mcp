// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	netmail "net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	gomessage "github.com/emersion/go-message"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// originalMaxChars bounds the text this tool reads from the message a
// reply quotes or a forward carries. It is the read tool's own
// ceiling (§3.16), so one send can never pull more characters out of
// a mailbox than one read can.
const originalMaxChars = 100000

// sendsPerWindow and sendWindow are the send limit of §3.11 and M12:
// 10 messages in one minute for each account. A model in a loop hits
// the limit and stops; a person does not reach it.
const (
	sendsPerWindow = 10
	sendWindow     = time.Minute
)

// sendLimiter counts the messages that left, for each account, inside
// the last [sendWindow]. It holds the count in memory only, so a
// restart of the server clears it (§3.11).
//
// The zero value works and uses the wall clock. A test replaces now
// with its own clock and moves time by hand, because a test must
// never wait a minute (C24).
//
// One send tool serves every MCP call of one process, and those calls
// can run at the same time, so every read and write of the map is
// under the mutex.
//
// arch: T5.6, §3.11, M12, §8 S5
type sendLimiter struct {
	mu  sync.Mutex
	now func() time.Time
	at  map[string][]time.Time
}

// take records one send for account key, or gives the error that
// refuses it. The caller calls it immediately before the send, so a
// call that fails its checks first spends nothing.
//
// The window slides: each recorded time older than [sendWindow] goes
// away before the count, so a burst of 10 does not block the account
// for longer than one minute.
func (l *sendLimiter) take(key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	clock := l.now
	if clock == nil {
		clock = time.Now
	}
	now := clock()

	kept := make([]time.Time, 0, sendsPerWindow)
	for _, t := range l.at[key] {
		if now.Sub(t) < sendWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) >= sendsPerWindow {
		l.at[key] = kept
		wait := sendWindow - now.Sub(kept[0])
		return fmt.Errorf("account %s reached the limit of %d sends in one minute; wait %d seconds and send again",
			key, sendsPerWindow, int(wait.Seconds())+1)
	}
	if l.at == nil {
		l.at = make(map[string][]time.Time)
	}
	l.at[key] = append(kept, now)
	return nil
}

// SendIn is the input of the send tool (D5.1). The send tool sends
// one saved draft. The draft tool holds the message content.
//
// IdempotencyKey names the send for the key store of D5.3. A second
// call with the same account and key sends nothing and gives the
// result of the first call. The key is required: an empty key gives
// a fixed error, and a key that another draft_id used gives a fixed
// error too.
//
// arch: D5.1, D5.3
type SendIn struct {
	Account        string `json:"account"`
	DraftID        string `json:"draft_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

// SendOut is the send tool result (§3.16): the id, whether the mail
// left, and whether a copy went to Sent.
//
// Every field of this struct is text this server wrote or an id a
// server gave, so none of it is fenced (§3.15). No sender-controlled
// value reaches a send result. TestSend_ResultCarriesNoSenderText
// holds that rule the way the fence walk holds it for the read
// results (G3).
type SendOut struct {
	Account string `json:"account"`
	// ID is the Message-ID of the sent mail.
	ID          string `json:"id,omitempty"`
	Sent        bool   `json:"sent"`
	SavedToSent bool   `json:"saved_to_sent,omitempty"`
	// Note is text this server wrote: a secondary step that failed
	// after the mail left (C14).
	Note string `json:"note,omitempty"`
}

// addSend adds the send tool h to srv. The tool sends one draft that
// the draft tool saved, and it needs access = "send" (D5.1).
//
// [Toolsets]' "send" group keeps one sendTool for the life of the
// server and gives that same tool to addSend on every Enable, so the
// key store (D5.3) and the send limit (§3.11) do not start empty
// again (DRV.7). A test gives its own h, so it can read the limit and
// the key store of h after a call.
//
// The tool gets [DefaultTimeout]. §3.1 gives the 120 second deadline
// to attachment, export and bulk only, and send is not one of them.
//
// It claims no annotation. §3.16 names ReadOnlyHint for accounts,
// search and read, and DestructiveHint for modify; a send is neither
// read-only nor reversible, so it states nothing it cannot keep.
//
// The tool uses [WrapReq], because it asks the human through the
// session of the call before the mail leaves (D5.2).
//
// The tool carries the Meta key anthropic/requiresUserInteraction
// (D5.2, layer B). A host that knows the key asks the human before
// the call starts. The prompt shows the arguments only, not the
// message, so it is a backstop to the confirmation of layer A.
//
// arch: T5.2, D5.1, D5.2, D8.3, D10.3, DRV.7, §3.16, App B
func addSend(srv *mcp.Server, h *sendTool) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "send",
		Description: "Send a saved draft.",
		Meta:        mcp.Meta{requiresUserInteraction: true},
	}, WrapReq(h.logger, "send", DefaultTimeout, h.handleReq))
}

// requiresUserInteraction is the Meta key of D5.2, layer B.
const requiresUserInteraction = "anthropic/requiresUserInteraction"

// idemKeyTag gives the idem_key field of the send log line (D10.3):
// the first 8 hex characters of the SHA-256 of key. The log never
// holds the key itself. An empty key gives "".
//
// arch: D10.3
func idemKeyTag(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:4])
}

// The outcomes of the confirmation step (D10.3). Each is also the
// value of the confirm field of the send log line.
const (
	confirmAccept          = "elicit_accept"
	confirmDecline         = "elicit_decline"
	confirmCancel          = "elicit_cancel"
	confirmNoElicitAllowed = "no_elicitation_allowed"
	confirmNoElicitRefused = "no_elicitation_refused"
	// confirmPending is the outcome of the first call of the MRTR
	// path: the question went to the client, and no answer came yet
	// (DS14.9).
	confirmPending = "elicit_pending"
)

// errNoElicitation is the fixed refusal of D5.2 for a client that
// cannot ask the human. The text does not name the config key that
// permits the send: the model reads this text, and only the human
// may decide to turn the confirmation off.
var errNoElicitation = errors.New("this client cannot ask the human to confirm a send, so nothing was sent; the human can send the draft from a mail program")

// elicitCutoffProtocol is the first protocol version on which go-sdk
// refuses a server request during a tool call. On that protocol the
// confirmation uses the MRTR path of DS14.1. go-sdk does not export
// its own constant. The versions are dates, so a string compare
// orders them, as go-sdk also does.
const elicitCutoffProtocol = "2026-07-28"

// confirmInputID is the id of the one input request of the MRTR path
// (DS14.4). The retry gives the answer under this id (DS14.5).
const confirmInputID = "confirm"

// errDraftChanged is the fixed refusal of a retry whose stored draft
// source is not the source that the human saw in the confirmation
// (DS14.5, IS14.1).
var errDraftChanged = errors.New("the draft changed after the confirmation was shown, so nothing was sent; call send again to confirm the new draft")

// errNotDraft is the fixed refusal for a draft_id that names a
// message with no \Draft flag. The check runs before the prompt and
// before the limit, so the human sees no prompt and the call spends
// no send (D8.3).
var errNotDraft = errors.New("draft_id names a message that is not a draft, so nothing was sent; save the message with the draft tool, then send its draft_id")

// errHTMLNotClean is the fixed refusal of D5.5 for a draft whose
// HTML part is not already cut to the allowlist of [mime.AllowHTML].
// The confirmation cannot show all of such a part, so nothing leaves.
// The check runs before the prompt and before the limit, so the call
// spends no send. It covers a draft that a mail program wrote too.
var errHTMLNotClean = errors.New("the draft holds HTML that the confirmation cannot show in full, so nothing was sent; save it again with the draft tool")

// notConfirmedText is the fixed error text of a confirmation that did
// not complete: the client failed or the call ended during the wait.
const notConfirmedText = "the confirmation did not complete, so nothing was sent"

// confirmWaitLimit bounds the wait for the human's answer to the
// elicitation of D5.2. [untimed] frees that wait from the tool
// deadline, so with no limit of its own a client that never answers
// keeps the send call open, and the idempotency key of D5.3 in
// flight, without end. The limit is long because a human may step
// away, and fixed because the client sets no timeout of its own.
//
// A var, not a const: a test shrinks it, because a test must never
// wait 10 minutes for a client that does not answer (C24).
var confirmWaitLimit = 10 * time.Minute

// notSentNote is the fixed note of D8.3 step 7: the human declined or
// cancelled, and nothing was sent.
const notSentNote = "not sent: the human did not confirm"

// confirmField is the one boolean field of the confirmation form. Only
// the value true with action "accept" sends (D5.2).
const confirmField = "send"

// confirmSchema is the requested schema of the confirmation form: one
// boolean field (D5.2).
var confirmSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		confirmField: map[string]any{
			"type":        "boolean",
			"title":       "Send this message",
			"description": "Set to true to send the message above.",
		},
	},
	"required": []string{confirmField},
}

// confirmMaxRunes bounds the unquoted text of one body part. The
// confirmation shows all of that text, so a longer part cannot get a
// confirmation. [confirmReady] refuses it with [errDraftTooLong]
// (DRV.20.1).
const confirmMaxRunes = 4000

// errDraftTooLong is the fixed refusal for a body part whose unquoted
// text is longer than [confirmMaxRunes]. The check runs before the
// limit, so the call spends no send (D8.3).
var errDraftTooLong = errors.New("the draft text is longer than 4000 characters, so the confirmation cannot show all of it; nothing was sent. Shorten the draft, or send it from a mail program")

// confirmFunc is the confirmation step of one send call. It runs after
// the access check and the limit, and before the mail leaves. It gives
// one of the confirm outcomes above.
type confirmFunc func(ctx context.Context, p Writer, acct config.Account, alias, draftID string) (string, error)

// checkFunc is the step of one send call that runs before the limit.
// It refuses a call that cannot get a confirmation, or whose draft_id
// is not a draft, so the refusal spends no send (D8.3). A refusal
// gives a confirm outcome for the log line, or "" when it has none.
// A nil checkFunc checks nothing.
type checkFunc func(ctx context.Context, p Writer, acct config.Account, draftID string) (string, error)

type sendTool struct {
	mail Mail
	// logger gets the send-confirm line of D10.3. A nil logger
	// writes nothing.
	logger *slog.Logger
	// limit is the send limit of §3.11. Its zero value works, so
	// every sendTool has a live limit and no construction site can
	// forget one.
	limit sendLimiter
	// keys is the idempotency key store of D5.3. Its zero value
	// works, for the same reason.
	keys keyStore
	// pending keeps each open confirmation of the MRTR path
	// (DS14.3). Its zero value works, for the same reason.
	pending pendingStore[pendingSend]
}

// pendingSend is the record of one open send confirmation (DS14.4).
// The retry must give the same session, account, draft id and key,
// and the stored source must have the same SHA-256 (DS14.5).
//
// arch: DS14.4, DS14.5
type pendingSend struct {
	session *mcp.ServerSession
	account string
	draftID string
	idemKey string
	digest  [sha256.Size]byte
}

// handleReq is the send handler that [addSend] registers. It asks
// the human through the session of req before the mail leaves (D5.2).
//
// A session on a protocol before [elicitCutoffProtocol] uses
// [confirmByElicit], as before (DS14.1). Such a session that gives a
// request state gets [errConfirmStale] (DS14.8).
//
// A session on [elicitCutoffProtocol] or later uses the MRTR path. A
// call with no request state is the first call: it gives the question
// as an [inputRequired] value (DS14.4). Before the limit, it holds a
// place in the store: the open record of the same session, account,
// draft id and key, or a free place (DS14.3). A call with a request state is
// the retry: it takes the record of that state and reads the answer
// (DS14.5).
//
// arch: D5.2, D8.3, DS14.1, DS14.4, DS14.5, DS14.8
func (t *sendTool) handleReq(ctx context.Context, req *mcp.CallToolRequest, in SendIn) (SendOut, error) {
	ss := sessionOf(req)
	state, answers := retryOf(req)
	check := func(ctx context.Context, p Writer, acct config.Account, draftID string) (string, error) {
		return confirmReady(ctx, ss, p, acct, draftID)
	}
	if !newProtocol(ss) {
		if state != "" {
			return SendOut{}, errConfirmStale
		}
		return t.run(ctx, in, check, func(ctx context.Context, p Writer, acct config.Account, alias, draftID string) (string, error) {
			return confirmByElicit(ctx, ss, p, acct, alias, draftID)
		})
	}
	if state == "" {
		var place *pendingHold[pendingSend]
		defer func() { place.drop() }()
		hold := func(account string) (bool, error) {
			var reuse bool
			var err error
			place, reuse, err = t.pending.hold(ss, func(r pendingSend) bool {
				return r.session == ss && r.account == account && r.draftID == in.DraftID && r.idemKey == in.IdempotencyKey
			})
			return reuse, err
		}
		return t.runClaim(ctx, in, nil, hold, check, func(ctx context.Context, p Writer, acct config.Account, alias, draftID string) (string, error) {
			return t.confirmFirst(ctx, ss, p, acct, alias, draftID, in.IdempotencyKey, place)
		})
	}
	var rec pendingSend
	claim := func(account string) error {
		var err error
		rec, err = t.claimPending(ss, state, account, in.DraftID, in.IdempotencyKey)
		return err
	}
	return t.runClaim(ctx, in, claim, nil, check, func(ctx context.Context, p Writer, _ config.Account, _, draftID string) (string, error) {
		return confirmRetry(ctx, p, rec, draftID, answers)
	})
}

// retryOf gives the request state and the input responses of req. A
// first call gives an empty state.
//
// arch: DS14.5
func retryOf(req *mcp.CallToolRequest) (string, mcp.InputResponseMap) {
	if req == nil || req.Params == nil {
		return "", nil
	}
	return req.Params.RequestState, req.Params.InputResponses
}

// confirmFirst is the confirmation step of the first call on the MRTR
// path (DS14.4). It builds the summary of D5.2 from the stored source,
// writes a pending record with the SHA-256 of that same source into
// place, the place that the first call held before the limit, and
// gives the question as an [inputRequired] value with the outcome
// [confirmPending]. The caller then releases the key, because nothing
// was sent.
//
// A client with no form elicitation gives [errNoElicitation], unless
// accounts.toml has [send] allow_without_elicitation = true (DS14.2).
// A full store or a full session share refused the call before the
// limit, so it asked nobody (DS14.3, DS14.12).
//
// arch: DS14.2, DS14.3, DS14.4, DS14.9, D5.2
func (t *sendTool) confirmFirst(ctx context.Context, ss *mcp.ServerSession, p Writer, acct config.Account, alias, draftID, idemKey string, place *pendingHold[pendingSend]) (string, error) {
	if !canElicit(ss) {
		if acct.AllowWithoutElicitation {
			return confirmNoElicitAllowed, nil
		}
		return confirmNoElicitRefused, errNoElicitation
	}
	raw, err := p.Raw(ctx, draftID)
	if err != nil {
		return "", err
	}
	// The summary reads the same bytes that the digest covers, so the
	// human approves the exact source of the record (IS14.1).
	summary, err := draftSummary(ctx, pinnedRaw{Writer: p, raw: raw}, acct, alias, draftID)
	if err != nil {
		return "", err
	}
	state, err := place.fill(pendingSend{
		session: ss,
		account: acct.Alias,
		draftID: draftID,
		idemKey: idemKey,
		digest:  sha256.Sum256(raw),
	})
	if err != nil {
		return "", err
	}
	return confirmPending, &inputRequired{
		requests: mcp.InputRequestMap{confirmInputID: &mcp.ElicitParams{
			Mode:            "form",
			Message:         summary,
			RequestedSchema: confirmSchema,
		}},
		state: state,
	}
}

// pinnedRaw is a [Writer] whose Raw gives the bytes that the caller
// read before. [confirmFirst] gives it to [draftSummary], so that the
// summary and the digest of the record come from one read.
//
// arch: DS14.4, IS14.1
type pinnedRaw struct {
	Writer
	raw []byte
}

// Raw gives the pinned bytes for every id.
func (p pinnedRaw) Raw(context.Context, string) ([]byte, error) {
	return p.raw, nil
}

// claimPending is the claim step of the retry (DS14.5). It takes the
// record of state, so the state works one time only. It gives
// [errConfirmStale] when the store has no open record of state, or
// when the session, the account, the draft id or the key of the
// record differ from the retry (IS14.2).
//
// arch: DS14.5, IS14.2
func (t *sendTool) claimPending(ss *mcp.ServerSession, state, account, draftID, idemKey string) (pendingSend, error) {
	rec, ok := t.pending.take(state)
	if !ok || rec.session != ss || rec.account != account || rec.draftID != draftID || rec.idemKey != idemKey {
		return pendingSend{}, errConfirmStale
	}
	return rec, nil
}

// confirmRetry is the confirmation step of the retry (DS14.5). It
// reads the stored source again and gives [errDraftChanged] when its
// SHA-256 is not the digest of rec. Then it reads the answer under
// [confirmInputID]: only an ElicitResult with action "accept" and the
// field send equal to true gives [confirmAccept]. The action "cancel"
// gives [confirmCancel]. Any other value, or no answer, gives
// [confirmDecline].
//
// arch: DS14.5, IS14.1, IS14.6
func confirmRetry(ctx context.Context, p Writer, rec pendingSend, draftID string, answers mcp.InputResponseMap) (string, error) {
	raw, err := p.Raw(ctx, draftID)
	if err != nil {
		return "", err
	}
	if sha256.Sum256(raw) != rec.digest {
		return "", errDraftChanged
	}
	res, ok := answers[confirmInputID].(*mcp.ElicitResult)
	if !ok || res == nil {
		return confirmDecline, nil
	}
	switch res.Action {
	case "accept":
		if v, ok := res.Content[confirmField].(bool); ok && v {
			return confirmAccept, nil
		}
		return confirmDecline, nil
	case "cancel":
		return confirmCancel, nil
	default:
		return confirmDecline, nil
	}
}

// run sends the stored draft draft_id after confirm permits it. The
// provider removes the Bcc header from the copy that SMTP sees (C16).
//
// The access check is the first line after the account opens
// (§3.17). A draft account gets ErrAccessDenied: its draft stays in
// the mailbox and nothing leaves (D5.1).
//
// The order is the order of D8.3: the checks, the key store, the
// check step, the limit, then the confirmation, then the send. A
// decline or a cancel gives the fixed result "not sent" and no error.
// The check step refuses before the limit, so its refusal spends no
// send.
//
// The key store comes before the limit: a repeat of a done key sends
// nothing and asks nobody, so it spends no send of the limit. A key
// that is free is in flight from here to the end of run. Each path
// that ends before the send releases it (D8.3 step 7), and the send
// makes it done with its result, error or not (D5.3, I9).
//
// The send runs on a detached context (DS11.9): after the
// confirmation step, a client that goes away does not stop it.
//
// run has no claim step: see [sendTool.runClaim] for the retry of the
// MRTR path.
//
// arch: T5.2, D5.1, D5.2, D5.3, D8.3, §3.16, §3.17, §3.11, C16, I9, DS11.9
func (t *sendTool) run(ctx context.Context, in SendIn, check checkFunc, confirm confirmFunc) (SendOut, error) {
	return t.runClaim(ctx, in, nil, nil, check, confirm)
}

// runClaim is [sendTool.run] with the claim step of the MRTR retry.
// claim is nil on every call except that retry. On the retry, claim
// runs after the draft id check and before the key store, and the
// limit does not run, because the first call spent it (DS14.5,
// IS14.3). The other steps are the steps of run.
//
// hold is nil on every call except the first call of the MRTR path.
// On that call, hold runs after the check step and immediately before
// the limit, so a full store or a full session share refuses before
// the call spends a send (DS14.3, DS14.12). When hold reuses an open
// record of the same send, the limit does not run: the first call of
// that record spent it (DS14.4, IS14.3).
//
// arch: DS14.3, DS14.4, DS14.5, DS14.12, IS14.3, D8.3
func (t *sendTool) runClaim(ctx context.Context, in SendIn, claim func(account string) error, hold func(account string) (reuse bool, err error), check checkFunc, confirm confirmFunc) (out SendOut, err error) {
	p, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return SendOut{}, err
	}
	if err := guard.Require(acct, guard.LevelSend); err != nil {
		return SendOut{}, err
	}
	if strings.TrimSpace(in.DraftID) == "" {
		return SendOut{}, errors.New("draft_id is empty; save the message with the draft tool first, then send its draft_id")
	}
	// The alias that OpenWriter gives back names the account of the
	// limit and of the key store: the account the provider opened.
	account := acct.Alias
	if claim != nil {
		if err := claim(account); err != nil {
			return SendOut{}, err
		}
	}
	prior, replay, err := t.keys.begin(account, in.IdempotencyKey, in.DraftID)
	if err != nil || replay {
		return prior, err
	}
	sending := false
	defer func() {
		if !sending {
			t.keys.release(account, in.IdempotencyKey)
			return
		}
		if r := recover(); r != nil {
			// The mail may have left before the panic, so the key
			// stays done and a repeat sends nothing.
			t.keys.finish(account, in.IdempotencyKey, SendOut{}, errSendUnknown)
			panic(r)
		}
		t.keys.finish(account, in.IdempotencyKey, out, err)
	}()
	logConfirm := func(outcome string) {
		if outcome != "" && t.logger != nil {
			// D10.3: the audit fields of one confirmation. The key
			// goes to the log as a hash tag only.
			t.logger.Info("send-confirm", "tool", "send",
				"confirm", outcome, "idem_key", idemKeyTag(in.IdempotencyKey))
		}
	}
	if check != nil {
		outcome, err := check(ctx, p, acct, in.DraftID)
		logConfirm(outcome)
		if err != nil {
			return SendOut{}, err
		}
	}
	// §3.11 and D8.3 step 4: the limit comes before the confirmation,
	// so a model in a loop cannot ask the human more than the limit
	// permits. The retry of the MRTR path does not spend it again
	// (DS14.5), and nor does a first call that reuses an open record
	// (DS14.4).
	if claim == nil {
		reuse := false
		if hold != nil {
			if reuse, err = hold(account); err != nil {
				return SendOut{}, err
			}
		}
		if !reuse {
			if err := t.limit.take(account); err != nil {
				return SendOut{}, err
			}
		}
	}
	outcome, err := confirm(ctx, p, acct, in.Account, in.DraftID)
	logConfirm(outcome)
	if err != nil {
		return SendOut{}, err
	}
	// DS11.9: the confirmation step passed, on either branch, so this
	// is the point of no return of the send (DS11.20 G3). The send
	// context is detached from the session: when the client goes away
	// now, the send completes and the key store holds its result, so a
	// retry with the same key gets that result (DS11.18.3).
	switch outcome {
	case confirmAccept:
		// D5.2: the wait for the human does not count against the
		// tool deadline. The send gets a new full deadline.
		if wait, timeout, ok := untimed(ctx); ok {
			var cancel context.CancelFunc
			ctx, cancel = detach(wait, timeout)
			defer cancel()
		}
	case confirmNoElicitAllowed:
		// No wait for the human came first, so the send keeps the
		// tool deadline that ctx has.
		if _, timeout, ok := untimed(ctx); ok {
			var cancel context.CancelFunc
			ctx, cancel = detach(ctx, timeout)
			defer cancel()
		}
	default:
		return SendOut{Account: in.Account, Sent: false, Note: notSentNote}, nil
	}
	sending = true
	res, err := p.SendDraft(ctx, in.DraftID)
	if err != nil {
		return SendOut{}, err
	}
	return sendResult(in.Account, res), nil
}

// errSendUnknown is the stored result of a send that stopped in a
// panic. Nobody knows if the mail left, so the key keeps this error
// and a repeat sends nothing (D5.3, I9).
var errSendUnknown = errors.New("the send stopped with an internal error, and it is not known if the mail left; look in the Sent folder before you send again")

// sessionOf gives the session of req, or nil when req has none.
func sessionOf(req *mcp.CallToolRequest) *mcp.ServerSession {
	if req == nil {
		return nil
	}
	return req.Session
}

// canElicit reports whether the client of ss can show the form
// elicitation of D5.2. A client that declares only the url mode cannot
// show the form. The SDK reads a capability with neither mode as form,
// so this check does too. The rule is the same on every protocol
// (DS14.2).
//
// arch: D5.2, DS14.2
func canElicit(ss *mcp.ServerSession) bool {
	if ss == nil {
		return false
	}
	ip := ss.InitializeParams()
	if ip == nil || ip.Capabilities == nil || ip.Capabilities.Elicitation == nil {
		return false
	}
	caps := ip.Capabilities.Elicitation
	return caps.Form != nil || caps.URL == nil
}

// newProtocol reports whether ss runs on [elicitCutoffProtocol] or
// later.
func newProtocol(ss *mcp.ServerSession) bool {
	if ss == nil {
		return false
	}
	ip := ss.InitializeParams()
	return ip != nil && ip.ProtocolVersion >= elicitCutoffProtocol
}

// confirmReady is the check step of the send tool (D8.3). It runs
// before the limit and before the prompt. It refuses a session that
// cannot ask the human, unless accounts.toml permits that, it
// refuses a draft_id with no \Draft flag, it refuses a draft whose
// HTML part is not clean (D5.5), and it refuses a body part whose
// unquoted text is longer than [confirmMaxRunes] (DRV.20.1). Each
// refusal gives a fixed error, and the call spends no send of the
// limit.
//
// The HTML check runs on the path with no prompt too, so no path
// sends HTML that is not clean (I8). A body that cannot be read
// cannot be checked, so it is refused as well.
//
// arch: D5.2, D5.3, D5.5, D8.3, DRV.20.1
func confirmReady(ctx context.Context, ss *mcp.ServerSession, p Writer, acct config.Account, draftID string) (string, error) {
	if !canElicit(ss) && !acct.AllowWithoutElicitation {
		return confirmNoElicitRefused, errNoElicitation
	}
	msg, err := p.Read(ctx, draftID, mail.ReadOpts{Format: "text", MaxChars: 1})
	if err != nil {
		return "", err
	}
	if msg == nil {
		return "", errors.New("draft_id names no message")
	}
	if !msg.Flags.Draft {
		return "", errNotDraft
	}
	raw, err := p.Raw(ctx, draftID)
	if err != nil {
		return "", err
	}
	parts, _, err := bodyParts(raw)
	if err != nil {
		return "", err
	}
	// DRV.20.1: the summary shows all unquoted text, so a part that
	// is too long to show is refused here, before the limit.
	for _, part := range parts {
		if _, _, n := partLines(part.text); n > confirmMaxRunes {
			return "", errDraftTooLong
		}
	}
	return "", nil
}

// confirmByElicit is the confirmation of D5.2, layer A. It builds the
// summary of the stored draft on the server and shows it to the human
// in a form with one boolean field. Only action "accept" with the
// value true gives [confirmAccept].
//
// A client with no elicitation gives errNoElicitation, unless
// accounts.toml has [send] allow_without_elicitation = true.
//
// The wait uses the call context without the tool deadline (D5.2).
//
// arch: D5.2, D8.3, D10.3
func confirmByElicit(ctx context.Context, ss *mcp.ServerSession, p Writer, acct config.Account, alias, draftID string) (string, error) {
	if !canElicit(ss) {
		if acct.AllowWithoutElicitation {
			return confirmNoElicitAllowed, nil
		}
		return confirmNoElicitRefused, errNoElicitation
	}
	summary, err := draftSummary(ctx, p, acct, alias, draftID)
	if err != nil {
		return "", err
	}
	wait, _, _ := untimed(ctx)
	// D5.2 carry (T105): the deadline-free wait above has no limit of
	// its own, so a client that never answers would hold the call,
	// and the key of D5.3, open forever. Bound it here.
	wait, cancel := context.WithTimeout(wait, confirmWaitLimit)
	defer cancel()
	res, err := ss.Elicit(wait, &mcp.ElicitParams{
		Mode:            "form",
		Message:         summary,
		RequestedSchema: confirmSchema,
	})
	if err != nil {
		if ctxErr := wait.Err(); ctxErr != nil {
			return "", fmt.Errorf("%s: %w", notConfirmedText, ctxErr)
		}
		return "", errors.New(notConfirmedText)
	}
	switch res.Action {
	case "accept":
		if v, ok := res.Content[confirmField].(bool); ok && v {
			return confirmAccept, nil
		}
		return confirmDecline, nil
	case "cancel":
		return confirmCancel, nil
	default:
		return confirmDecline, nil
	}
}

// draftSummary builds the text the human confirms (D5.2): the
// identity, every recipient with Bcc, the subject, all unquoted text
// of each body part, and the name and size of each attachment.
//
// The body parts come from the stored source, because SendDraft sends
// that same source (C16). Each text/plain part and each text/html
// part shows, the HTML part as text. Each line that is not a quote
// line shows in full (DRV.20.1). A quote line is counted, not shown.
// After an HTML part comes a "Links:" list with the count and each
// href target (D5.5). The attachment list comes from the same walk of
// the source, so each part that leaves and is not body text has a
// line (DRV.20.1, IRV.6).
//
// The addresses and the subject come from the stored header block,
// because SendDraft takes the envelope from that same block. Read
// gives no Bcc. Each address shows bare, with no display name, so a
// name cannot pose as another address. Each header value folds onto
// one line, so a value cannot add a line that looks like a field.
//
// The summary holds model text and sender text, so the whole text
// passes through guard.StripInvisible.
//
// The summary reads the stored source only. [confirmReady] reads the
// message and checks its \Draft flag before this runs (R16-L23).
//
// arch: D5.2, D5.5, §3.15, C16
func draftSummary(ctx context.Context, p Writer, acct config.Account, alias, draftID string) (string, error) {
	raw, err := p.Raw(ctx, draftID)
	if err != nil {
		return "", err
	}
	head, err := netmail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return "", errors.New("the draft has no readable header block; save it again with the draft tool")
	}

	// DRV.9: fromMailbox now removes the hidden characters itself,
	// inside guard.StripFenceMarkers, so the StripInvisible call at
	// the end no longer sees them. show counts them first, so the
	// note line still tells the human about them (§3.15).
	hidden := 0
	show := func(s string) string {
		_, n := guard.StripInvisible(s)
		hidden += n
		return fromMailbox(s)
	}

	from, err := summaryAddrs(head.Header.Get("From"), show)
	if err != nil {
		// The From header is not a recipient. SendDraft checks it
		// against the identities of the account, so the summary
		// shows its decoded text on one line.
		from = show(mime.DecodeHeaderText(head.Header.Get("From")))
	}
	if from == "" {
		from = show(acct.Email)
	}

	var b strings.Builder
	b.WriteString("Send this message?\n")
	fmt.Fprintf(&b, "Account: %s\n", show(alias))
	fmt.Fprintf(&b, "From: %s\n", from)
	for _, h := range []string{"To", "Cc", "Bcc"} {
		// REVIEW-2026-10-12 H3: SendDraft builds the envelope with
		// this same parser and stops on the same error. A summary
		// with a recipient that the envelope cannot hold is never
		// shown, so the human approves only the real envelope.
		addrs, err := summaryAddrs(head.Header.Get(h), show)
		if err != nil {
			return "", recipientUnreadable(h)
		}
		fmt.Fprintf(&b, "%s: %s\n", h, addrs)
	}
	fmt.Fprintf(&b, "Subject: %s\n", show(mime.DecodeHeaderText(head.Header.Get("Subject"))))
	parts, other, err := bodyParts(raw)
	if err != nil {
		return "", err
	}
	// DI5.1: in identity mode only, one line after the headers tells
	// the human whether the signature is the one in accounts.toml.
	// Outside identity mode the summary is as at 97a33ec (I2).
	if acct.IdentityMode() {
		b.WriteString(signatureLine(acct, head.Header.Get("From"), parts, show) + "\n")
	}
	if len(parts) == 0 {
		b.WriteString("Body: none\n")
	}
	for _, part := range parts {
		// DRV.20.1: every unquoted line shows in full. A quote line
		// is counted, not shown (IRV.6).
		lines, quoted, _ := partLines(part.text)
		fmt.Fprintf(&b, "%s: %d lines, %d not shown\n", part.label, len(lines)+quoted, quoted)
		for _, line := range lines {
			b.WriteString("> " + line + "\n")
		}
		if quoted > 0 {
			fmt.Fprintf(&b, "%d quoted lines not shown\n", quoted)
		}
		if part.html {
			// D5.5: every link target that leaves shows, with no
			// cut. A clean href holds no control character, so each
			// target is one line.
			fmt.Fprintf(&b, "Links: %d\n", len(part.links))
			for _, l := range part.links {
				b.WriteString("- " + l + "\n")
			}
		}
	}
	if len(other) == 0 {
		b.WriteString("Attachments: none\n")
	} else {
		b.WriteString("Attachments:\n")
		// DRV.20.1 (L4): every part bodyParts did not show as body
		// text goes here, whatever its disposition. The list comes
		// only from the walk of the bytes that leave (IRV.6).
		for _, o := range other {
			if o.name != "" {
				fmt.Fprintf(&b, "- %s (%d bytes)\n", show(mime.DecodeHeaderText(o.name)), o.size)
				continue
			}
			fmt.Fprintf(&b, "- %s\n", otherLabel(o.ct))
		}
	}

	text, removed := guard.StripInvisible(b.String())
	removed += hidden
	if removed > 0 {
		text += fmt.Sprintf("note: %d hidden characters removed\n", removed)
	}
	return text, nil
}

// signatureLine gives the "Signature:" line of the send summary for an
// account in identity mode (DI5.1). It is information for the human and
// never refuses (DI5.2).
//
// The identity comes from the stored From header: an identity email
// (acct.Identity), else a reply_match pattern (acct.MatchReply). A
// blank From gives acct.Email, the address the summary shows. A From
// that is not exactly one address matches no identity.
//
// The text is the first text/plain part of parts, with CRLF changed to
// LF. The signature matches only as whole lines: the "-- " line starts
// a line, and the last signature line ends a line or the text. So a
// longer last line, such as a changed name, does not show as a match.
// The first case that applies gives the line:
//
//   - From matches no identity: "none (the sender is no identity)".
//   - The identity has no signature: "none (identity <email> has none)".
//   - The text holds "-- \n" + Signature: "matches accounts.toml".
//   - A line of the text above the forward block of
//     [mime.ForwardBody] is "--" after a right trim: "DIFFERS".
//   - Else: "none (identity <email>)".
//
// arch: DI5.1, DI5.2, DI2.0
func signatureLine(acct config.Account, fromHeader string, parts []summaryPart, show func(string) string) string {
	addr := acct.Email
	if strings.TrimSpace(fromHeader) != "" {
		addr = ""
		if list, err := mime.ParseAddressList(fromHeader); err == nil && len(list) == 1 {
			addr = list[0].Address
		}
	}
	id, ok := config.Identity{}, false
	if addr != "" {
		id, ok = acct.Identity(addr)
		if !ok {
			id, ok = acct.MatchReply(addr)
		}
	}
	if !ok {
		return "Signature: none (the sender is no identity)"
	}
	email := show(id.Email)
	if id.Signature == "" {
		return fmt.Sprintf("Signature: none (identity %s has none)", email)
	}
	text := ""
	for _, p := range parts {
		if !p.html {
			text = strings.ReplaceAll(p.text, "\r\n", "\n")
			break
		}
	}
	if strings.Contains("\n"+text+"\n", "\n-- \n"+id.Signature+"\n") {
		return fmt.Sprintf("Signature: matches accounts.toml (identity %s)", email)
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if forwardBlockAt(lines, i) {
			// R16-L5, I10: a "--" line of the forwarded mail is not a
			// signature of this draft.
			break
		}
		if strings.TrimRightFunc(l, unicode.IsSpace) == "--" {
			return fmt.Sprintf("Signature: DIFFERS from accounts.toml (identity %s)", email)
		}
	}
	return fmt.Sprintf("Signature: none (identity %s)", email)
}

// forwardBlockFields are the first fields of the forward block that
// [mime.ForwardBody] writes, one on each line, in this order.
var forwardBlockFields = []string{"From:", "Date:", "Subject:", "To:"}

// forwardBlockAt tells whether the forward block of [mime.ForwardBody]
// starts at lines[i]. [signatureLine] stops its "--" search there
// (R16-L5).
func forwardBlockAt(lines []string, i int) bool {
	if len(lines)-i < len(forwardBlockFields) {
		return false
	}
	for k, f := range forwardBlockFields {
		if !strings.HasPrefix(lines[i+k], f) {
			return false
		}
	}
	return true
}

// summaryAddrs gives the bare addresses of one header value, joined
// by ", ". A blank value gives "". A value that does not parse gives
// the parse error. mime.ParseAddressList is also the parser of the
// SMTP envelope in SendDraft, so the two read the same addresses.
// Each value goes through show, which cleans it the way fromMailbox
// does and counts the hidden characters it removes.
//
// arch: REVIEW-2026-10-12 H2, REVIEW-2026-10-12 H3
func summaryAddrs(value string, show func(string) string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	list, err := mime.ParseAddressList(value)
	if err != nil {
		return "", err
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, show(a.Address))
	}
	return strings.Join(out, ", "), nil
}

// recipientUnreadable is the fixed error for a draft whose To, Cc or
// Bcc header h does not parse. The error names the header only. It
// does not repeat the header text, because that text can come from
// another mail program or a sender (REVIEW-2026-10-12 H3).
func recipientUnreadable(h string) error {
	return fmt.Errorf("the %s header of the draft cannot be read as a list of addresses, so the confirmation cannot show its recipients and nothing was sent; save the draft again with the draft tool", h)
}

// errBodyUnreadable is the fixed error for a draft whose body parts
// cannot be read. The summary must show each part that leaves, so a
// body it cannot read gives no prompt.
var errBodyUnreadable = errors.New("the draft body cannot be read for the confirmation, so nothing was sent; save it again with the draft tool")

// summaryPart is one body part of the confirmation summary. links
// holds the href targets of an HTML part.
type summaryPart struct {
	label string
	text  string
	html  bool
	links []string
}

// summaryOther is one part of the confirmation summary's attachment
// list: a part that bodyParts does not show as body text. name is the
// file name of the part, or "". size is the decoded size in bytes.
// ct is the content type (DRV.8, DRV.20.1).
type summaryOther struct {
	name string
	size int
	ct   string
}

// otherLabel gives the Attachments: line for one part that bodyParts
// does not show as body text: "inline <content-type>", so a part with
// no name and no attachment disposition still leaves a line and not
// silence (DRV.8, IRV.6).
func otherLabel(ct string) string {
	return "inline " + ct
}

// partLines gives the summary view of the text of one body part:
// each line that is not a quote line, the count of the quote lines,
// and the rune count of the unquoted text with its line breaks. A
// quote line starts with ">". The check of [confirmReady] and
// [draftSummary] both use this one function, so the limit counts the
// text that the summary shows (DRV.20.1, IRV.6). Line breaks at the
// end make no line. A CR, U+2028 or U+2029 inside a line becomes a
// space ([lineBreakFolder]).
//
// arch: DRV.20.1, IRV.6
func partLines(text string) (lines []string, quoted, runes int) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil, 0, 0
	}
	for _, l := range strings.Split(text, "\n") {
		l = lineBreakFolder.Replace(l)
		if strings.HasPrefix(l, ">") {
			quoted++
			continue
		}
		if len(lines) > 0 {
			runes++ // the line break before this line
		}
		runes += utf8.RuneCountInString(l)
		lines = append(lines, l)
	}
	return lines, quoted, runes
}

// bodyParts gives the text of each shown body part of the stored
// source raw, in source order: each text/plain part as it is, and
// each text/html part as text with its link targets. other gives
// every part that is not shown as body text, with its file name and
// decoded size: a named part, an attachment-disposed part, and an
// inline part that is neither text/plain nor text/html. The summary's
// attachment list comes from other only, so one walk decides both
// lists (DRV.8, DRV.20.1).
//
// An HTML part must already be clean: [mime.AllowHTML] must not
// change it (D5.5). Clean HTML has no style, so it hides no text, and
// its only URLs are the href targets that the summary lists. A part
// that is not clean gives [errHTMLNotClean] (I8). Line breaks do not
// count as a change, because the tokenizer reads CRLF as LF. A clean
// part that nests allowlist elements past [mime.HTMLToTextCount]'s
// depth limit also gives [errHTMLNotClean]: text past that depth
// would leave with no line in the summary (D5.5, D5.2, I8).
//
// An unknown charset or transfer encoding gives the raw bytes of the
// part, so the human still sees them. Any other parse error gives
// [errBodyUnreadable]. A Content-Type that does not parse is such an
// error, and so is a multipart type that gives no part reader
// (R16-M4).
//
// arch: D5.2, D5.5, D4.1, C16, DRV.8, DRV.20.1, IRV.6
func bodyParts(raw []byte) ([]summaryPart, []summaryOther, error) {
	root, err := gomessage.Read(strings.NewReader(string(raw)))
	if err != nil && !gomessage.IsUnknownCharset(err) && !gomessage.IsUnknownEncoding(err) {
		return nil, nil, errBodyUnreadable
	}
	var parts []summaryPart
	var other []summaryOther
	// Walk gives its function no error but an unknown charset or
	// transfer encoding, and those keep the raw bytes of the part
	// (R16-L24). Any other error of Walk comes back from Walk itself.
	err = root.Walk(func(_ []int, e *gomessage.Entity, _ error) error {
		// R16-M4: a Content-Type that does not parse cannot be shown
		// as it leaves, so the draft gets no prompt. The library reads
		// a part as multipart only when it gives a reader; a multipart
		// type with no reader would leave its parts unshown.
		ct, params, ctErr := e.Header.ContentType()
		if ctErr != nil {
			return errBodyUnreadable
		}
		ct = strings.ToLower(ct)
		if e.MultipartReader() != nil {
			return nil // Walk reads its parts next.
		}
		if strings.HasPrefix(ct, "multipart/") {
			return errBodyUnreadable
		}
		if ct == "" {
			ct = "text/plain"
		}
		disp, dparams, _ := e.Header.ContentDisposition()
		name := dparams["filename"]
		if name == "" {
			name = params["name"]
		}
		shown := name == "" && !strings.EqualFold(disp, "attachment") && (ct == "text/plain" || ct == "text/html")
		if !shown {
			body, err := io.ReadAll(e.Body)
			if err != nil {
				return err
			}
			other = append(other, summaryOther{name: name, size: len(body), ct: ct})
			return nil
		}
		body, err := io.ReadAll(e.Body)
		if err != nil {
			return err
		}
		if ct == "text/html" {
			src := strings.ReplaceAll(string(body), "\r\n", "\n")
			src = strings.ReplaceAll(src, "\r", "\n")
			clean, _ := mime.AllowHTML(src)
			if clean != src {
				return errHTMLNotClean
			}
			// AllowHTML keeps an allowlist element at any nest depth,
			// but HTMLToText below stops after a depth limit and
			// leaves later text uncounted (D5.5, D5.2, I8). A part
			// that nests that deep is refused here, before the text
			// view is built, so the summary never under-counts.
			if _, nested := mime.HTMLToTextCount(clean); nested > 0 {
				return errHTMLNotClean
			}
			parts = append(parts, summaryPart{
				label: "HTML part as text",
				text:  mime.HTMLToText(clean),
				html:  true,
				links: mime.HTMLLinks(clean),
			})
			return nil
		}
		parts = append(parts, summaryPart{label: "Text part", text: string(body)})
		return nil
	})
	if errors.Is(err, errHTMLNotClean) {
		return nil, nil, err
	}
	if err != nil {
		return nil, nil, errBodyUnreadable
	}
	return parts, other, nil
}

// draftInsteadNote is the note of the draft tool for an account that
// may not send: the message is saved as a draft, and the text names
// the level, the draft id and the line of accounts.toml that permits
// sending (§3.17).
//
// arch: T5.4, §3.17, D5, D5.1, §10.5
func draftInsteadNote(alias string, acct config.Account, id string) string {
	return fmt.Sprintf("account %s has access=%s. The message is saved as a draft (id %s). Set access = %q in accounts.toml to permit sending.",
		alias, guard.LevelOf(acct), id, guard.LevelSend)
}

// sendResult turns a provider result into a tool result. A warning
// from the provider is server text and never turns sent into false:
// the mail already left (C14).
func sendResult(alias string, res mail.SendResult) SendOut {
	return SendOut{
		Account:     alias,
		ID:          res.ID,
		Sent:        res.Sent,
		SavedToSent: res.SavedToSent,
		Note:        res.Warning,
	}
}

// compose builds the outgoing message of one draft call: the caller's
// own fields, then the reply or forward fields on top of them. It
// stays in this file since R1-C split draft from send (D5.1).
//
// The returned function removes the temporary copies of the
// attachments a forward carries. It is never nil, so a caller defers
// it before it looks at the error.
//
// In identity mode (DI2.0), the From value comes from [pickIdentity]
// and compose gives the identity sentence of the draft Note (DI2.3).
// Outside identity mode, [identityFrom] checks the from value as it
// did before DI2, and the note is empty (I2).
//
// The original of a reply or a forward is read once, through
// [readOriginal], before the body is built. The pick, addReply and
// addForward share that one read (DI2.1).
//
// In identity mode the signature step of DI3 runs on the caller's own
// text, before any quote or forward block joins it (I10). compose
// takes the own text out of m.Text before addReply and addForward
// run, so m.Text then holds only their block, and [placeSignature]
// lays out the parts. Outside identity mode the body is built as
// before DI3 (I2).
//
// arch: T5.2, §3.14, §3.15, M7, M13, M14, M10, M11, DI2.0, DI2.1, DI2.3, DI6.1, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func (t *draftTool) compose(ctx context.Context, p Writer, acct config.Account, in DraftIn) (*mail.Outgoing, string, func(), error) {
	nothing := func() {}
	mode := acct.IdentityMode()

	var from string
	if !mode {
		var err error
		from, err = identityFrom(in.From, acct)
		if err != nil {
			return nil, "", nothing, err
		}
	}
	if err := guard.ValidateAddresses(in.To); err != nil {
		return nil, "", nothing, fmt.Errorf("to: %w", err)
	}
	if err := guard.ValidateAddresses(in.Cc); err != nil {
		return nil, "", nothing, fmt.Errorf("cc: %w", err)
	}
	if err := guard.ValidateAddresses(in.Bcc); err != nil {
		return nil, "", nothing, fmt.Errorf("bcc: %w", err)
	}
	subject, err := guard.ValidateField(in.Subject)
	if err != nil {
		return nil, "", nothing, fmt.Errorf("subject: %w", err)
	}

	// M14: a model can copy a fence marker out of a result it read.
	// The marker must leave the outgoing subject and body, because
	// the receiving side is another mail reader and not this
	// server's own fence parser.
	//
	// The quote of a reply is this layer's work (§3.14, and addReply
	// below puts it in Text): mail.Outgoing carries no Quote field of
	// its own (DRV.16a), so a provider cannot quote a second time.
	m := &mail.Outgoing{
		From:    from,
		To:      append([]string(nil), in.To...),
		Cc:      append([]string(nil), in.Cc...),
		Bcc:     append([]string(nil), in.Bcc...),
		Subject: guard.StripFenceMarkers(subject),
		Text:    guard.StripFenceMarkers(in.Body),
		HTML:    guard.StripFenceMarkers(in.HTML),
	}

	used, err := t.callerAttachments(m, in.Attachments)
	if err != nil {
		return nil, "", nothing, err
	}

	orig, err := readOriginal(ctx, p, in, mode)
	if err != nil {
		return nil, "", nothing, err
	}
	drop := selfAddresses(acct)
	note := ""
	var pk picked
	var own ownBody
	if mode {
		pk, err = pickIdentity(acct, in, orig)
		if err != nil {
			return nil, "", nothing, err
		}
		m.From = pk.From
		drop = replyDrop(acct, pk)
		own, err = prepareOwn(m, pk.Identity, in)
		if err != nil {
			return nil, "", nothing, err
		}
		note = pickNote(pk, own.add)
		// addReply and addForward join their block to m.Text. With
		// m.Text empty, m.Text afterwards is that block alone.
		m.Text = ""
	}

	cleanup := nothing
	switch {
	case in.ReplyToID != "":
		if err := t.addReply(m, in, orig, drop); err != nil {
			return nil, "", nothing, err
		}
	case in.ForwardID != "":
		cleanup, err = t.addForward(ctx, p, m, used, orig)
		if err != nil {
			return nil, "", cleanup, err
		}
	}
	if mode {
		if err := placeSignature(m, pk.Identity, in, own, m.Text); err != nil {
			return nil, "", cleanup, err
		}
	}
	return m, note, cleanup, nil
}

// identityFrom checks the from address of a call (M13). An empty
// value means the account address. Any other value must be the
// account address or one of the identities of accounts.toml.
//
// The identity list comes from [config.Account], which OpenWriter
// already hands back, so the provider interface needs no Identities
// method for this check (owner gate open point, 2026-09-20).
//
// arch: T5.2, §3.14, §3.15, M13
func identityFrom(from string, acct config.Account) (string, error) {
	if strings.TrimSpace(from) == "" {
		return "", nil // the provider fills in the account address
	}
	if err := guard.ValidateAddress(from); err != nil {
		return "", fmt.Errorf("from: %w", err)
	}
	want, err := netAddress(from)
	if err != nil {
		return "", fmt.Errorf("from: %w", err)
	}
	for _, own := range selfAddresses(acct) {
		if strings.EqualFold(own, want) {
			return from, nil
		}
	}
	return "", errFromNotIdentity
}

// selfAddresses lists the account address and its identities, as bare
// addresses. A reply drops every one of them from its recipients
// (M6), and a from check accepts one of them (M13).
func selfAddresses(acct config.Account) []string {
	out := make([]string, 0, len(acct.Identities)+1)
	for _, a := range append([]string{acct.Email}, acct.Identities...) {
		if strings.TrimSpace(a) == "" {
			continue
		}
		if bare, err := netAddress(a); err == nil {
			out = append(out, bare)
		}
	}
	return out
}

// netAddress gives the bare address of one header value, with no
// display name. M15: the parse belongs to the library, because
// "Smith, John" <j@x> must not be cut at the comma.
func netAddress(value string) (string, error) {
	list, err := mime.ParseAddressList(value)
	if err != nil {
		return "", guard.ErrInvalidAddress
	}
	if len(list) != 1 {
		return "", guard.ErrInvalidAddress
	}
	return list[0].Address, nil
}

// callerAttachments resolves each path the caller named and adds it to
// m. It returns the bytes those files hold.
//
// Every path goes through [guard.AttachPath] with the attach_dirs list
// of accounts.toml, which refuses a hidden path component, a path
// under /proc, /sys or /dev, and a file above 25 MB. This is the path
// a prompt injection uses to steal a private key (G7, M11).
//
// arch: T5.2, §3.15, §3.14, G7, M11
func (t *draftTool) callerAttachments(m *mail.Outgoing, paths []string) (int64, error) {
	allow := t.mail.AttachDirs()
	var used int64
	for _, one := range paths {
		resolved, size, err := guard.AttachPath(one, allow)
		if err != nil {
			return 0, err
		}
		used += size
		if used > guard.MaxAttachBytes {
			return 0, errors.New("the attachments together exceed the 25 MB limit of one message")
		}
		m.Attachments = append(m.Attachments, resolved)
	}
	return used, nil
}

// addReply fills in the reply fields of m from the message the caller
// answers (§3.14).
//
// The recipients, the Re: prefix and the thread headers all come from
// internal/mime, and each value of the original that reaches the
// outgoing message loses its fence markers first (M5, M6, M14, M15).
//
// A field the caller gave wins: a call that names its own to list or
// its own subject keeps them.
//
// compose reads the original once and passes it in (DI2.1). drop
// lists the addresses that a reply_all leaves out: the own addresses
// of the account, and in identity mode the picked From address too
// (DI2.4).
//
// arch: T5.2, §3.14, M5, M6, M14, M15, DI2.1, DI2.4
func (t *draftTool) addReply(m *mail.Outgoing, in DraftIn, orig *mail.Message, drop []string) error {
	m.InReplyTo, m.References = mime.ReplyHeaders(orig.MessageID, orig.References)
	m.ReplyToID = in.ReplyToID

	if m.Subject == "" {
		m.Subject = mime.RePrefix(fromMailbox(orig.Subject))
	}
	if len(m.To) == 0 {
		to, cc, err := mime.ReplyRecipients(
			firstBare(orig.ReplyTo), orig.From.Address,
			bareList(orig.To), bareList(orig.Cc),
			in.ReplyAll, drop)
		if err != nil {
			return err
		}
		m.To = to
		if len(m.Cc) == 0 {
			m.Cc = cc
		}
	}
	if in.Quote == nil || *in.Quote {
		quote := mime.QuoteText(orig.Date, fromMailbox(addressText(orig.From)),
			guard.StripFenceMarkers(orig.Body))
		m.Text = joinBody(m.Text, quote)
	}
	return nil
}

// addForward fills in the forward fields of m and copies the
// attachments of the original into a temporary directory, so the
// outgoing message carries them again (M7).
//
// The returned function removes that directory. It is never nil,
// because the message is built later, inside the provider, and the
// files must still be there then.
//
// compose reads the original once and passes it in (DI2.1). The
// attachment reads stay here.
//
// arch: T5.2, §3.14, §3.15, M7, M11, DI2.1
func (t *draftTool) addForward(ctx context.Context, p Writer, m *mail.Outgoing, used int64, orig *mail.Message) (func(), error) {
	nothing := func() {}
	if m.Subject == "" {
		m.Subject = mime.FwdPrefix(fromMailbox(orig.Subject))
	}
	block := mime.ForwardBody(
		fromMailbox(addressText(orig.From)), orig.Date,
		fromMailbox(orig.Subject), bareList(orig.To),
		guard.StripFenceMarkers(orig.Body))
	m.Text = joinBody(m.Text, block)

	if len(orig.Attachments) == 0 {
		return nothing, nil
	}
	dir, err := os.MkdirTemp("", "mailbag-forward-")
	if err != nil {
		return nothing, fmt.Errorf("forward attachments: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	for i, a := range orig.Attachments {
		path, size, err := copyAttachment(ctx, p, dir, i, orig.ID, a, guard.MaxAttachBytes-used)
		if err != nil {
			return cleanup, err
		}
		used += size
		m.Attachments = append(m.Attachments, path)
	}
	return cleanup, nil
}

// copyAttachment writes one attachment of the original into its own
// sub-directory of dir, and gives the path of the copy.
//
// Each copy gets its own sub-directory, so two parts that carry the
// same file name never take each other's place and the name in the
// outgoing message stays the name the first sender chose. The name
// itself goes through [guard.StripFenceMarkers] and then
// [guard.SaveName], because a sender picks it (§3.15, M14): the name
// travels on to another mail reader with the forwarded message, so a
// marker must leave it the way a marker leaves the subject.
//
// The copy stops at left bytes. Two messages of 20 MB each must not
// become one message of 40 MB (M11).
//
// arch: T5.2, §3.14, §3.15, M7, M11, C19
func copyAttachment(ctx context.Context, p Writer, dir string, i int, id string, a mail.Attachment, left int64) (string, int64, error) {
	name, err := guard.SaveName(guard.StripFenceMarkers(a.Filename))
	if err != nil {
		name = "attachment-" + strconv.Itoa(i+1)
	}
	if left <= 0 {
		return "", 0, errors.New("the attachments together exceed the 25 MB limit of one message")
	}

	sub := filepath.Join(dir, strconv.Itoa(i))
	if err := os.Mkdir(sub, 0o700); err != nil {
		return "", 0, fmt.Errorf("forward attachments: %w", err)
	}
	rc, _, err := p.Attachment(ctx, id, a.Ref)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = rc.Close() }()

	path := filepath.Join(sub, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: the path is the forward temp dir plus a name the code made safe; O_EXCL stops a symlink or an existing file
	if err != nil {
		return "", 0, fmt.Errorf("forward attachments: %w", err)
	}
	size, err := io.Copy(f, io.LimitReader(rc, left+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, fmt.Errorf("forward attachments: %w", err)
	}
	if size > left {
		return "", 0, errors.New("the attachments together exceed the 25 MB limit of one message")
	}
	return path, size, nil
}

// firstBare gives the first bare address of a header, or "" when the
// header is absent. §3.14 makes Reply-To the one base recipient of a
// reply; a second address in it joins the Cc list of a reply_all
// through the To and Cc of the original, not the To of the reply.
func firstBare(list []mail.Address) string {
	for _, a := range list {
		if a.Address != "" {
			return a.Address
		}
	}
	return ""
}

// fromMailbox makes one value of a stored message safe to put in an
// outgoing header: it takes the fence markers out (M14) and folds CR,
// LF, U+2028 and U+2029 onto one space ([lineBreakFolder]).
//
// §3.15 says to refuse a CR or an LF in tool input and never to
// remove one. That rule holds for a value a caller typed, and
// [guard.ValidateField] applies it. This value comes from a mailbox
// instead, where a sender already put the break, and a reply to such
// a message must still work. One line is therefore the answer here,
// the same answer mime.ForwardBody gives its own header block. A raw
// break in a Subject header would otherwise add a header (M10).
//
// arch: T5.2, §3.14, §3.15, M10, M14
func fromMailbox(s string) string {
	s = guard.StripFenceMarkers(s)
	return lineBreakFolder.Replace(s)
}

// lineBreakFolder folds each line break to one space: CR, LF, and the
// Unicode line and paragraph separators U+2028 and U+2029. A web
// client breaks the line at a Unicode separator too, so a summary line
// that keeps one can show a field with no "> " prefix (R16-L6).
var lineBreakFolder = strings.NewReplacer("\r", " ", "\n", " ", " ", " ", " ", " ")

// bareList gives the bare addresses of a header, with no display
// name, so every entry parses again on its own (M15).
func bareList(list []mail.Address) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		if a.Address != "" {
			out = append(out, a.Address)
		}
	}
	return out
}

// joinBody puts the caller's own text above the quoted or forwarded
// block.
func joinBody(own, block string) string {
	if own == "" {
		return block
	}
	return own + "\n\n" + block
}
