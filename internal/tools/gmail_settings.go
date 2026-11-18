// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The gmail_settings tool of S9 (DS9.7). It reads and changes the
// filters, the vacation auto-reply and the signature of a Gmail
// account through the gmail.Settings interface. An account of another
// provider gets a note and no error. The access level depends on the
// action (G21). Filter criteria, label names, vacation text and the
// signature are fenced (§3.15). Four writes ask the human first: a
// vacation that goes on, a signature, a filter that hides mail (DH3.2)
// and a filter delete (DU8.1). On protocol 2026-07-28 and later the question goes back as
// an input-required result, and the retry applies the stored change
// (DH3.5).

package tools

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
)

// GmailSettingsIn is the input of the gmail_settings tool. Action
// selects which of the other fields count: the filter fields for
// create_filter, FilterID for delete_filter, Enabled, Subject, Body,
// Start and End for set_vacation, SendAs and Body for the signature.
//
// arch: DS9.7
type GmailSettingsIn struct {
	Account       string   `json:"account"`
	Action        string   `json:"action" jsonschema:"list_filters create_filter delete_filter get_vacation set_vacation get_signature set_signature"`
	FilterID      string   `json:"filter_id,omitempty"`
	From          string   `json:"from,omitempty"`
	To            string   `json:"to,omitempty"`
	Subject       string   `json:"subject,omitempty"`
	Query         string   `json:"query,omitempty"`
	HasAttachment *bool    `json:"has_attachment,omitempty"`
	AddLabels     []string `json:"add_labels,omitempty"`
	RemoveLabels  []string `json:"remove_labels,omitempty"`
	MarkRead      bool     `json:"mark_read,omitempty"`
	Star          bool     `json:"star,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty" jsonschema:"vacation on or off"`
	Body          string   `json:"body,omitempty" jsonschema:"vacation or signature"`
	Start         string   `json:"start,omitempty" jsonschema:"date"`
	End           string   `json:"end,omitempty" jsonschema:"date"`
	SendAs        string   `json:"send_as,omitempty" jsonschema:"default primary"`
}

// FilterRow is one Gmail filter of a result (S9-GAP8). The ID is the
// id Gmail gave. The criteria and the label names are sender text and
// sit in Untrusted, one fence each. A filter with no criteria or no
// action has empty fields (E13).
//
// arch: DS9.7, DU5.1, DU5.6
type FilterRow struct {
	ID            string          `json:"id" strict:"id"`
	HasAttachment *bool           `json:"has_attachment,omitempty"`
	MarkRead      bool            `json:"mark_read,omitempty"`
	Star          bool            `json:"star,omitempty"`
	Untrusted     FilterUntrusted `json:"untrusted"`
}

// FilterUntrusted holds the fenced text of one filter. A list is an
// array of fences.
//
// arch: DU5.1, DU5.6
type FilterUntrusted struct {
	From         string   `json:"from,omitempty"`
	To           string   `json:"to,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	Query        string   `json:"query,omitempty"`
	AddLabels    []string `json:"add_labels,omitempty"`
	RemoveLabels []string `json:"remove_labels,omitempty"`
}

// VacationRow is the vacation auto-reply of a result (S9-GAP8). The
// subject and the body sit in Untrusted. Start and End are YYYY-MM-DD
// in the local zone of the host (S9-GAP7); End is the last day.
//
// arch: DS9.7, DU5.6
type VacationRow struct {
	Enabled   bool              `json:"enabled"`
	Start     string            `json:"start,omitempty" strict:"day"`
	End       string            `json:"end,omitempty" strict:"day"`
	Untrusted VacationUntrusted `json:"untrusted"`
}

// VacationUntrusted holds the fenced text of the vacation reply.
//
// arch: DU5.1, DU5.6
type VacationUntrusted struct {
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`
}

// SignatureUntrusted holds the fenced signature text.
//
// arch: DU5.1, DU5.6
type SignatureUntrusted struct {
	Signature string `json:"signature,omitempty"`
}

// GmailSettingsOut is the result of the gmail_settings tool. Head
// gives the nonce first. Filters is set by list_filters and
// create_filter, Vacation by get_vacation, the named field Untrusted
// (`untrusted.signature`, fenced) by get_signature. Outside the
// fence: the filter ids, the flags, the dates and Note, which is text
// this server wrote. Untrusted is not an embedded struct:
// jsonschema-go flattens an embedded struct with a JSON tag, and the
// SDK then refuses the output (DU12.2).
//
// arch: DS9.7, DU5.1, DU5.6, DU12.2
type GmailSettingsOut struct {
	Head
	Filters   []FilterRow        `json:"filters,omitempty"`
	Vacation  *VacationRow       `json:"vacation,omitempty"`
	Untrusted SignatureUntrusted `json:"untrusted,omitzero"`
	Note      string             `json:"note,omitempty" strict:"note"`
}

// dayLayout is the date form of Start and End (DS9.7).
const dayLayout = "2006-01-02"

// AddGmailSettings adds the "gmail_settings" tool to srv. The tool is
// not in a toolset until T270 registers it (DS9.8).
//
// arch: DS9.7, G21
func AddGmailSettings(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &gmailSettingsTool{mail: m}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gmail_settings",
		Description: "Read or change Gmail filters, vacation reply and signature.",
	}, WrapReq(logger, "gmail_settings", DefaultTimeout, h.handleReq))
}

// gmailSettingsTool is the gmail_settings handler. pending keeps each
// open settings question of the MRTR path (DH3.5). Its zero value
// works, so a tool that a test builds with no store also works.
//
// arch: DH3.1, DH3.5
type gmailSettingsTool struct {
	mail    Mail
	pending pendingStore[pendingSetting]
}

// pendingSetting is the record of one open settings question on the
// MRTR path. The retry must give the same session, account, action and
// input; digest is the SHA-256 of the JSON form of the first input.
// change holds the prepared change, so the retry writes the value that
// the human saw and reads Gmail no more (I7).
//
// arch: DH3.5, DH8.2
type pendingSetting struct {
	session *mcp.ServerSession
	account string
	action  string
	digest  [sha256.Size]byte // of json.Marshal(in)
	change  settingChange
}

// settingAsk asks the human about one settings change and gives a
// confirm outcome. It gets the account and the text of the question.
//
// arch: DH3.1
type settingAsk func(ctx context.Context, acct config.Account, message string) (string, error)

// errSettingNoElicitation is the fixed refusal for a client that
// cannot ask the human about a settings change. Like
// [errBulkNoElicitation], it does not name the config key, because the
// model reads this text and only the human may turn the question off.
//
// arch: DH3.4, DH3.6
var errSettingNoElicitation = errors.New("this client cannot ask the human to confirm this Gmail settings change, so nothing changed; the human can make the change in Gmail")

// errFilterNotFound is the refusal of a delete_filter whose filter_id
// names no filter of the account. Nobody is asked and nothing changes.
// The text does not echo the id, because the id is model input
// (INV-10).
//
// arch: DU8.1, DU9.1
var errFilterNotFound = public("not_found", "gmail_settings: the account has no filter with this filter_id; list_filters gives the ids")

// settingSchema is the requested schema of a settings question. It has
// no remember field: a session grant never covers these questions.
//
// arch: DH3.4
var settingSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		bulkField: map[string]any{
			"type":        "boolean",
			"title":       "Apply this change",
			"description": "Set to true to change the setting above.",
		},
	},
	"required": []string{bulkField},
}

// handleReq is the handler that [AddGmailSettings] registers.
//
// A session on a protocol before [elicitCutoffProtocol] asks the human
// through the session of req (DH3.4). Such a session that gives a
// request state gets [errConfirmStale], because no first call of that
// session made a record.
//
// A session on [elicitCutoffProtocol] or later uses the MRTR path
// (DH3.5). A call with no request state is the first call: a change
// that asks gives its question as an [inputRequired] value. A call
// with a request state is the retry: it takes the record of that state
// and applies the stored change after an accept.
//
// arch: DH3.1, DH3.4, DH3.5
func (t *gmailSettingsTool) handleReq(ctx context.Context, req *mcp.CallToolRequest, in GmailSettingsIn) (GmailSettingsOut, error) {
	ss := sessionOf(req)
	state, answers := retryOf(req)
	if !newProtocol(ss) {
		if state != "" {
			return GmailSettingsOut{}, errConfirmStale
		}
		return t.run(ctx, in, settingsAsk(ss))
	}
	if state == "" {
		return t.open(ctx, in, func(ctx context.Context, s gmail.Settings, acct config.Account) (GmailSettingsOut, error) {
			return runSetting(ctx, s, in, func(_ context.Context, c settingChange) (string, error) {
				return t.askFirst(ss, acct, in, c)
			})
		})
	}
	// The retry: the level check and the type assertion of open come
	// before take, so a refusal there keeps the record open (I9).
	return t.open(ctx, in, func(ctx context.Context, s gmail.Settings, acct config.Account) (GmailSettingsOut, error) {
		c, err := t.claim(ss, state, acct, in)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		return applyAfter(ctx, s, c, bulkAnswer(answers))
	})
}

// askFirst is the question of the first call on the MRTR path
// (DH3.5). It keeps a record of c and gives the question of c as an
// [inputRequired] value with the outcome [confirmPending].
//
// A client with no form elicitation gets [errSettingNoElicitation],
// unless the account has [bulk] allow_without_elicitation = true; then
// the change runs with no question (DH3.6). A full store or a full
// session share gives its fixed refusal, and nobody is asked.
//
// A repeat first call with the same session, account, action and
// input takes the place of the open record and gets a new state, so
// the old state is then stale (H12).
//
// arch: DH3.5, DH3.6
func (t *gmailSettingsTool) askFirst(ss *mcp.ServerSession, acct config.Account, in GmailSettingsIn, c settingChange) (string, error) {
	if !canElicit(ss) {
		if acct.BulkAllowWithoutElicitation {
			return confirmNoElicitAllowed, nil
		}
		return confirmNoElicitRefused, errSettingNoElicitation
	}
	digest, err := settingDigest(in)
	if err != nil {
		return "", err
	}
	place, _, err := t.pending.hold(ss, func(r pendingSetting) bool {
		return r.session == ss && r.account == acct.Alias && r.action == in.Action && r.digest == digest
	})
	if err != nil {
		return "", err
	}
	state, err := place.fill(pendingSetting{
		session: ss,
		account: acct.Alias,
		action:  in.Action,
		digest:  digest,
		change:  c,
	})
	if err != nil {
		return "", err
	}
	return confirmPending, &inputRequired{
		requests: mcp.InputRequestMap{confirmInputID: &mcp.ElicitParams{
			Mode:            "form",
			Message:         c.question(),
			RequestedSchema: settingSchema,
		}},
		state: state,
	}
}

// claim is the claim step of the retry (DH3.5). It takes the record
// of state, so the state works one time only. It gives
// [errConfirmStale] when the store has no open record of state, or
// when the session, the account, the action or the digest of the input
// differ from the retry (I10).
//
// arch: DH3.5, DH8.2
func (t *gmailSettingsTool) claim(ss *mcp.ServerSession, state string, acct config.Account, in GmailSettingsIn) (settingChange, error) {
	rec, ok := t.pending.take(state)
	if !ok {
		return settingChange{}, errConfirmStale
	}
	digest, err := settingDigest(in)
	if err != nil || rec.session != ss || rec.account != acct.Alias || rec.action != in.Action || rec.digest != digest {
		return settingChange{}, errConfirmStale
	}
	return rec.change, nil
}

// settingDigest gives the SHA-256 of the JSON form of in (DH3.5).
func settingDigest(in GmailSettingsIn) ([sha256.Size]byte, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// handle runs one action with no session. A change that needs a
// question is refused unless the account has [bulk]
// allow_without_elicitation = true (DH3.6).
//
// arch: DH3.1, DH3.6
func (t *gmailSettingsTool) handle(ctx context.Context, in GmailSettingsIn) (GmailSettingsOut, error) {
	return t.run(ctx, in, settingsAsk(nil))
}

// settingsAsk gives the question of one change on the session ss. A
// nil ss has no way to ask, and [askConfirm] treats it as a client
// with no elicitation. [bulkOutcome] reads the answer, so an accept
// with remember true is only an accept here (DH3.4, I8).
//
// arch: DH3.4, DH3.6
func settingsAsk(ss *mcp.ServerSession) settingAsk {
	return func(ctx context.Context, acct config.Account, message string) (string, error) {
		outcome, err := askConfirm(ctx, ss, acct, message, settingSchema, bulkNotConfirmedText)
		if outcome == confirmNoElicitRefused {
			return outcome, errSettingNoElicitation
		}
		return outcome, err
	}
}

// run runs one action. The order is fixed (S9-GAP6): OpenWriter,
// so an unknown alias fails as in every other tool (G10); then the
// level check of the action (G21); then the gmail.Settings type
// assertion; then the question, then the change (DH3.1). So an account
// of another provider at a level too low gets the denial, at a level
// high enough it gets the note, and neither gets a question.
//
// arch: DS9.7, DS9.11, G10, G21, DH3.1
func (t *gmailSettingsTool) run(ctx context.Context, in GmailSettingsIn, ask settingAsk) (GmailSettingsOut, error) {
	return t.open(ctx, in, func(ctx context.Context, s gmail.Settings, acct config.Account) (GmailSettingsOut, error) {
		return runSetting(ctx, s, in, func(ctx context.Context, c settingChange) (string, error) {
			return ask(ctx, acct, c.question())
		})
	})
}

// settingStep is the part of one call that comes after the level
// check and the type assertion of [gmailSettingsTool.open].
//
// arch: DH3.1, DH3.5
type settingStep func(ctx context.Context, s gmail.Settings, acct config.Account) (GmailSettingsOut, error)

// open does the steps of [gmailSettingsTool.run] before the question
// in their fixed order, then runs step. Every path uses it: the old
// protocol, and the first call and the retry of the MRTR path, so a
// level refusal and the note for another provider always come before
// any question and any record (DH3.1, I9).
//
// arch: DS9.7, DS9.11, G10, G21, DH3.1, DH3.5
func (t *gmailSettingsTool) open(ctx context.Context, in GmailSettingsIn, step settingStep) (GmailSettingsOut, error) {
	p, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return GmailSettingsOut{}, err
	}
	need, err := settingsLevel(in)
	if err != nil {
		return GmailSettingsOut{}, err
	}
	if err := guard.Require(acct, need); err != nil {
		return GmailSettingsOut{}, err
	}
	s, ok := p.(gmail.Settings)
	if !ok {
		alias := acct.Alias
		if alias == "" {
			alias = in.Account
		}
		return GmailSettingsOut{Note: fmt.Sprintf("gmail_settings works for Gmail accounts only; %s uses %s", alias, acct.Provider)}, nil
	}
	out, err := step(ctx, s, acct)
	if errors.Is(err, gmail.ErrScope) {
		// The fixed text of DS7.3: it tells the person how to get the
		// missing scope, and nothing else.
		return GmailSettingsOut{}, gmail.ErrScope
	}
	return out, err
}

// settingsLevel gives the level an action needs (G21): the three
// reads need read; filter create and delete, the signature and
// vacation off need draft; vacation on needs send, because Gmail then
// sends mail to each writer. set_vacation with no enabled is an error,
// so a missing value never picks the lower level.
//
// arch: DS9.7, G21
func settingsLevel(in GmailSettingsIn) (guard.Level, error) {
	switch in.Action {
	case "list_filters", "get_vacation", "get_signature":
		return guard.LevelRead, nil
	case "create_filter", "delete_filter", "set_signature":
		return guard.LevelDraft, nil
	case "set_vacation":
		if in.Enabled == nil {
			return "", errors.New("gmail_settings: set_vacation needs enabled true or false")
		}
		if *in.Enabled {
			return guard.LevelSend, nil
		}
		return guard.LevelDraft, nil
	default:
		return "", fmt.Errorf("gmail_settings: action %q is not one of list_filters, create_filter, delete_filter, get_vacation, set_vacation, get_signature, set_signature", in.Action)
	}
}

// changeAsk asks about the prepared change c and gives a confirm
// outcome.
//
// arch: DH3.1, DH3.5
type changeAsk func(ctx context.Context, c settingChange) (string, error)

// runSetting does one action on s. The level check is done. A read
// goes straight to [readSetting]. A write is prepared, asked about when
// [settingChange.asks] says so, and then applied by [applyAfter].
//
// arch: DH3.1, DH3.2, DH3.4, DH3.5
func runSetting(ctx context.Context, s gmail.Settings, in GmailSettingsIn, ask changeAsk) (GmailSettingsOut, error) {
	switch in.Action {
	case "list_filters", "get_vacation", "get_signature":
		return readSetting(ctx, s, in)
	}
	c, err := prepareSetting(ctx, s, in)
	if err != nil {
		return GmailSettingsOut{}, err
	}
	if !c.asks() {
		return c.apply(ctx, s)
	}
	outcome, err := ask(ctx, c)
	if err != nil {
		return GmailSettingsOut{}, err
	}
	return applyAfter(ctx, s, c, outcome)
}

// applyAfter applies c on s when outcome is an accept, or when the
// config key lets a client that cannot ask make the change. Any other
// outcome changes nothing and gives the declined note (I10).
//
// arch: DH3.4, DH3.5, DH3.6, DS11.9, DU12.3
func applyAfter(ctx context.Context, s gmail.Settings, c settingChange, outcome string) (GmailSettingsOut, error) {
	// DS11.9: an accept is the point of no return of the change. The
	// wait for the human does not count against the tool deadline, so
	// an accept gets a new full deadline, as a send does.
	switch outcome {
	case confirmAccept, confirmAcceptSession:
		if wait, timeout, ok := untimed(ctx); ok {
			// DU12.3: wait has no Fencer, so the Fencer of the call
			// goes back on the detached context before apply builds
			// the result.
			f := fencer(ctx)
			var cancel context.CancelFunc
			ctx, cancel = detach(wait, timeout)
			defer cancel()
			ctx = withFencer(ctx, f)
		}
	case confirmNoElicitAllowed:
		// No wait for the human came first, so the change keeps the
		// tool deadline that ctx has.
		if _, timeout, ok := untimed(ctx); ok {
			var cancel context.CancelFunc
			ctx, cancel = detach(ctx, timeout)
			defer cancel()
		}
	default:
		return GmailSettingsOut{Note: bulkDeclinedNote}, nil
	}
	return c.apply(ctx, s)
}

// readSetting does one of the three reads.
func readSetting(ctx context.Context, s gmail.Settings, in GmailSettingsIn) (GmailSettingsOut, error) {
	fc := fencer(ctx)
	switch in.Action {
	case "list_filters":
		fs, err := s.ListFilters(ctx)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		out := GmailSettingsOut{Filters: make([]FilterRow, 0, len(fs))}
		for _, f := range fs {
			out.Filters = append(out.Filters, filterRow(fc, f))
		}
		if len(fs) == 0 {
			out.Note = "the account has no filters"
		}
		return out, nil
	case "get_vacation":
		v, err := s.Vacation(ctx)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		return GmailSettingsOut{Vacation: vacationRow(fc, v)}, nil
	default: // get_signature; runSetting sends only the three reads here
		sig, err := s.Signature(ctx, in.SendAs)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		if sig == "" {
			return GmailSettingsOut{Note: "the address has no signature"}, nil
		}
		return GmailSettingsOut{Untrusted: SignatureUntrusted{Signature: fc.Wrap(sig)}}, nil
	}
}

// settingChange is one settings write, ready to apply. It holds the
// bytes that leave, so the question shows what the change writes
// (DH3.3, I7). account is the alias that the question names.
//
// arch: DH3.2
type settingChange struct {
	action    string
	account   string
	vacation  gmail.Vacation
	filter    gmail.Filter
	sendAs    string
	signature string
}

// prepareSetting builds the change of one write action. For
// set_vacation it makes the one read of the current setting and merges
// the call into it (R16-L7). For delete_filter it makes the one read of
// the filter list and keeps the filter as Gmail holds it, so the
// question shows what the filter does (DU8.1). It removes the fence markers from each
// text that the call gives (DH2.6), so the question shows the stripped
// value. The stored vacation subject and body stay as Gmail holds them.
//
// arch: DH2.6, DH3.2, DS9.7, R16-L7, DU8.1
func prepareSetting(ctx context.Context, s gmail.Settings, in GmailSettingsIn) (settingChange, error) {
	c := settingChange{action: in.Action, account: in.Account}
	switch in.Action {
	case "set_vacation":
		// Gmail replaces the whole setting, so read it first: a field
		// the call does not give keeps its value (R16-L7).
		cur, err := s.Vacation(ctx)
		if err != nil {
			return settingChange{}, err
		}
		// Strip only the text of the call. A strip of the merged value
		// also changes the stored text, because StripInvisible removes
		// ZWJ, ZWNJ and bidi marks (DH2.6, review M1).
		in.Subject = guard.StripFenceMarkers(in.Subject)
		in.Body = guard.StripFenceMarkers(in.Body)
		v, err := vacationOf(in, cur)
		if err != nil {
			return settingChange{}, err
		}
		c.vacation = v
	case "create_filter":
		c.filter = gmail.Filter{
			From:          guard.StripFenceMarkers(in.From),
			To:            guard.StripFenceMarkers(in.To),
			Subject:       guard.StripFenceMarkers(in.Subject),
			Query:         guard.StripFenceMarkers(in.Query),
			HasAttachment: in.HasAttachment,
			AddLabels:     stripAll(in.AddLabels),
			RemoveLabels:  stripAll(in.RemoveLabels),
			MarkRead:      in.MarkRead,
			Star:          in.Star,
		}
	case "delete_filter":
		if strings.TrimSpace(in.FilterID) == "" {
			return settingChange{}, errors.New("gmail_settings: delete_filter needs filter_id")
		}
		// The retry of the MRTR path deletes the id of this stored
		// filter and reads Gmail no more, so the human sees the filter
		// that goes (I7).
		fs, err := s.ListFilters(ctx)
		if err != nil {
			return settingChange{}, err
		}
		found := false
		for _, f := range fs {
			if f.ID == in.FilterID {
				c.filter, found = f, true
				break
			}
		}
		if !found {
			return settingChange{}, errFilterNotFound
		}
	default: // set_signature; settingsLevel refused every other action
		c.sendAs = in.SendAs
		c.signature = guard.StripFenceMarkers(in.Body)
	}
	return c, nil
}

// stripAll removes the fence markers from each name of a label list.
func stripAll(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = guard.StripFenceMarkers(n)
	}
	return out
}

// removesLabel reports whether names holds the system label word, in
// any case and with outer spaces. It reads the stripped names, so a
// marker or a hidden character inside the word cannot avoid the
// question (DH3.2). It also compares the lower-case forms, because the
// provider finds a label by its lower-case name (DH7.1, I6). The lower
// case of U+0130 is "i", but U+0130 does not fold to "i", so
// [strings.EqualFold] alone misses a name that the provider resolves.
func removesLabel(names []string, word string) bool {
	lower := strings.ToLower(word)
	for _, n := range names {
		n = strings.TrimSpace(n)
		if strings.EqualFold(n, word) || strings.ToLower(n) == lower {
			return true
		}
	}
	return false
}

// asks reports whether the human must confirm c: a vacation that goes
// on (Gmail then sends mail), every signature, a filter that hides
// mail from the owner (it marks mail read or takes it out of the
// inbox), and every filter delete (DU8.1). Undo cannot bring back a
// deleted filter, and mail text must not start a write that the human
// did not see.
//
// arch: DH3.2, DU8.1
func (c settingChange) asks() bool {
	switch c.action {
	case "set_vacation":
		return c.vacation.Enabled
	case "set_signature", "delete_filter":
		return true
	case "create_filter":
		return c.filter.MarkRead || c.hidesInbox() || removesLabel(c.filter.RemoveLabels, "UNREAD")
	default:
		return false
	}
}

// hidesInbox reports whether the filter takes mail out of the inbox.
func (c settingChange) hidesInbox() bool {
	return removesLabel(c.filter.RemoveLabels, "INBOX")
}

// question gives the text that the human accepts. It comes only from
// c, which holds the bytes that leave, or for a delete the filter that
// goes. Each value folds onto one line,
// and each body line has the "> " prefix of the send summary, so a
// value cannot look like another field. No line and no field is cut,
// because a text that the human does not see must not go out (DH3.3).
//
// arch: DH3.3, DU8.1
func (c settingChange) question() string {
	var b strings.Builder
	field := func(label, value string) {
		fmt.Fprintf(&b, "%s: %s\n", label, lineBreakFolder.Replace(value))
	}
	body := func(label, text string) {
		if text == "" {
			fmt.Fprintf(&b, "%s: (empty)\n", label)
			return
		}
		fmt.Fprintf(&b, "%s:\n", label)
		for _, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
			b.WriteString("> " + lineBreakFolder.Replace(l) + "\n")
		}
	}
	// filter writes the criteria and the actions of a filter. A create
	// and a delete show the same lines.
	filter := func(f gmail.Filter) {
		if f.From != "" {
			field("From", f.From)
		}
		if f.To != "" {
			field("To", f.To)
		}
		if f.Subject != "" {
			field("Subject", f.Subject)
		}
		if f.Query != "" {
			field("Query", f.Query)
		}
		if f.HasAttachment != nil {
			field("Has attachment", pick(*f.HasAttachment, "yes", "no"))
		}
		if removesLabel(f.RemoveLabels, "INBOX") {
			b.WriteString("A matching message skips the inbox.\n")
		}
		if f.MarkRead || removesLabel(f.RemoveLabels, "UNREAD") {
			b.WriteString("A matching message is marked read.\n")
		}
		if f.Star {
			b.WriteString("A matching message gets a star.\n")
		}
		for _, n := range f.AddLabels {
			field("Add label", n)
		}
		for _, n := range f.RemoveLabels {
			field("Remove label", n)
		}
	}
	day := func(t time.Time) string {
		if t.IsZero() {
			return "not set"
		}
		return t.In(time.Local).Format(dayLayout)
	}
	switch c.action {
	case "set_vacation":
		b.WriteString("Turn on this Gmail vacation reply? Gmail then sends it to each person who writes to the account.\n")
		field("Account", c.account)
		field("Enabled", pick(c.vacation.Enabled, "yes", "no"))
		field("Subject", c.vacation.Subject)
		field("Start", day(c.vacation.Start))
		end := "not set"
		if !c.vacation.End.IsZero() {
			end = day(c.vacation.End.Add(-time.Millisecond))
		}
		field("Last day", end)
		body("Body", c.vacation.Body)
	case "set_signature":
		b.WriteString("Replace this Gmail signature?\n")
		field("Account", c.account)
		sendAs := c.sendAs
		if sendAs == "" {
			sendAs = "the primary address"
		}
		field("Send-as address", sendAs)
		body("Signature", c.signature)
	case "delete_filter":
		b.WriteString("Delete this Gmail filter? Gmail then stops changing the messages that match it, and undo cannot bring the filter back.\n")
		field("Account", c.account)
		field("Filter id", c.filter.ID)
		filter(c.filter)
	default: // create_filter; asks is true for no other action
		b.WriteString("Create this Gmail filter? It changes each message that matches, with no later question.\n")
		field("Account", c.account)
		filter(c.filter)
	}
	return b.String()
}

// apply does the write of c on s and gives the result of the call.
//
// arch: DH3.2
func (c settingChange) apply(ctx context.Context, s gmail.Settings) (GmailSettingsOut, error) {
	fc := fencer(ctx)
	switch c.action {
	case "create_filter":
		f, err := s.CreateFilter(ctx, c.filter)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		return GmailSettingsOut{Filters: []FilterRow{filterRow(fc, f)}, Note: "filter created"}, nil
	case "delete_filter":
		if err := s.DeleteFilter(ctx, c.filter.ID); err != nil {
			return GmailSettingsOut{}, err
		}
		return GmailSettingsOut{Note: "filter deleted"}, nil
	case "set_vacation":
		if err := s.SetVacation(ctx, c.vacation); err != nil {
			return GmailSettingsOut{}, err
		}
		return GmailSettingsOut{Note: "vacation reply " + pick(c.vacation.Enabled, "on", "off")}, nil
	default: // set_signature
		if err := s.SetSignature(ctx, c.sendAs, c.signature); err != nil {
			return GmailSettingsOut{}, err
		}
		return GmailSettingsOut{Note: "signature saved"}, nil
	}
}

// fenceIf fences a non-empty value. An empty value stays empty, so
// omitempty drops it and a filter with missing parts shows only the
// parts it has (E13).
func fenceIf(f guard.Fencer, s string) string {
	if s == "" {
		return ""
	}
	return f.Wrap(s)
}

// fenceAll fences each name of a label list.
func fenceAll(f guard.Fencer, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = f.Wrap(n)
	}
	return out
}

// filterRow gives the result row of f with every text part fenced.
// A user can name a label, so the label names are fenced too.
//
// arch: DS9.7
func filterRow(fc guard.Fencer, f gmail.Filter) FilterRow {
	return FilterRow{
		ID:            f.ID,
		HasAttachment: f.HasAttachment,
		MarkRead:      f.MarkRead,
		Star:          f.Star,
		Untrusted: FilterUntrusted{
			From:         fenceIf(fc, f.From),
			To:           fenceIf(fc, f.To),
			Subject:      fenceIf(fc, f.Subject),
			Query:        fenceIf(fc, f.Query),
			AddLabels:    fenceAll(fc, f.AddLabels),
			RemoveLabels: fenceAll(fc, f.RemoveLabels),
		},
	}
}

// vacationRow gives the result row of v. The subject and the body are
// fenced. End on the wire is the first instant with no reply, so the
// row shows the day before it as the last day (see vacationOf).
//
// arch: DS9.7, S9-GAP7
func vacationRow(fc guard.Fencer, v gmail.Vacation) *VacationRow {
	row := &VacationRow{
		Enabled: v.Enabled,
		Untrusted: VacationUntrusted{
			Subject: fenceIf(fc, v.Subject),
			Body:    fenceIf(fc, v.Body),
		},
	}
	if !v.Start.IsZero() {
		row.Start = v.Start.In(time.Local).Format(dayLayout)
	}
	if !v.End.IsZero() {
		row.End = v.End.Add(-time.Millisecond).In(time.Local).Format(dayLayout)
	}
	return row
}

// vacationOf gives the vacation of a set_vacation call over cur, the
// setting that Gmail holds now. A field that the call does not give
// keeps its value in cur, so "vacation off" keeps the stored reply
// (R16-L7). A date is a day in the local zone of the host (S9-GAP7):
// Start is the first instant of its day, and End, the last day,
// becomes the first instant of the day after it, so the reply runs
// through the whole last day. An end before the start is an error.
//
// arch: DS9.7, S9-GAP7, R16-L7
func vacationOf(in GmailSettingsIn, cur gmail.Vacation) (gmail.Vacation, error) {
	v := cur
	v.Enabled = *in.Enabled
	if in.Subject != "" {
		v.Subject = in.Subject
	}
	if in.Body != "" {
		v.Body = in.Body
	}
	if in.Start != "" {
		d, err := time.ParseInLocation(dayLayout, in.Start, time.Local)
		if err != nil {
			return gmail.Vacation{}, fmt.Errorf("gmail_settings: start %q is not a date of the form YYYY-MM-DD", in.Start)
		}
		v.Start = d
	}
	if in.End != "" {
		d, err := time.ParseInLocation(dayLayout, in.End, time.Local)
		if err != nil {
			return gmail.Vacation{}, fmt.Errorf("gmail_settings: end %q is not a date of the form YYYY-MM-DD", in.End)
		}
		v.End = d.AddDate(0, 0, 1)
	}
	if !v.Start.IsZero() && !v.End.IsZero() && !v.Start.Before(v.End) {
		return gmail.Vacation{}, errors.New("gmail_settings: end is before start")
	}
	return v, nil
}
