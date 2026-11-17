// SPDX-License-Identifier: MIT

// Tests of the human confirmations of the gmail_settings tool, and of
// the rule that no fence marker reaches a provider in outgoing text.
// The confirmation tests go through a real session on the old protocol,
// and TestGmailSettings_MRTRRetry goes through the new protocol.

package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// settingsAcceptAll is a [settingAsk] of a human who accepts.
func settingsAcceptAll(context.Context, config.Account, string) (string, error) {
	return confirmAccept, nil
}

// settingsDial connects a client on the old protocol to a server that
// holds the gmail_settings tool over the fake of h. elicit says whether
// the client declares form elicitation.
func settingsDial(t *testing.T, h *gmailSettingsTool, elicit bool) *bulkWire {
	t.Helper()
	return dialBulk(t, func(srv *mcp.Server) { AddGmailSettings(srv, nil, h.mail) }, elicit)
}

// settingsOutOf decodes the structured result of one call.
func settingsOutOf(t *testing.T, res *mcp.CallToolResult) GmailSettingsOut {
	t.Helper()
	if res.IsError {
		t.Fatalf("gmail_settings failed: %s", bulkText(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out GmailSettingsOut
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode structured content %s: %v", b, err)
	}
	return out
}

// settingAccept is the answer of a human who accepts, and prompts
// records each question it gets.
func settingAccept(prompts *[]*mcp.ElicitParams) func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
	return func(p *mcp.ElicitParams) (*mcp.ElicitResult, error) {
		*prompts = append(*prompts, p)
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{bulkField: true}}, nil
	}
}

// vacationOnArgs are the arguments of a vacation that goes on.
func vacationOnArgs() map[string]any {
	return map[string]any{
		"account": "work", "action": "set_vacation", "enabled": true,
		"subject": "Away", "body": "Back on Monday.\nAsk Ann.",
		"start": "2026-10-14", "end": "2026-10-20",
	}
}

// ctxSettings records the context error and the deadline that
// SetVacation sees.
type ctxSettings struct {
	*settingsWriter
	seen     error
	deadline time.Time
}

func (c *ctxSettings) SetVacation(ctx context.Context, v gmail.Vacation) error {
	c.seen = ctx.Err()
	c.deadline, _ = ctx.Deadline()
	return c.settingsWriter.SetVacation(ctx, v)
}

// TestGmailSettings_VacationOnAsks holds DH3.2 and DH3.4 for a vacation
// that goes on: one question that shows the reply, the write only after
// an accept, a fixed refusal for a client that cannot ask unless the
// key allows it, and a level refusal before any question. After an
// accept the write has its own context, because the human may have
// used up the tool deadline.
//
// arch: DH2.6, DH3.1, DH3.2, DH3.3, DH3.4, DH3.6, DH3.7
func TestGmailSettings_VacationOnAsks(t *testing.T) {
	t.Run("accept writes once after one question", func(t *testing.T) {
		h, w := settingsFixture("send")
		var prompts []*mcp.ElicitParams
		res, asked := settingsDial(t, h, true).run("gmail_settings", vacationOnArgs(), settingAccept(&prompts))
		out := settingsOutOf(t, res)
		if asked != 1 || len(prompts) != 1 {
			t.Fatalf("asked %d times, want 1", asked)
		}
		if got := strings.Join(w.calls, ","); got != "Vacation,SetVacation" {
			t.Fatalf("calls = %s, want one read and one write", got)
		}
		q := prompts[0].Message
		for _, want := range []string{"Account: work", "Enabled: yes", "Subject: Away", "Start: 2026-10-14", "Last day: 2026-10-20", "> Back on Monday.", "> Ask Ann."} {
			if !strings.Contains(q, want) {
				t.Errorf("question lacks %q:\n%s", want, q)
			}
		}
		if !reflect.DeepEqual(prompts[0].RequestedSchema, mustJSON(t, settingSchema)) {
			t.Errorf("schema = %#v, want settingSchema", prompts[0].RequestedSchema)
		}
		props, _ := settingSchema["properties"].(map[string]any)
		if _, ok := props[bulkRemember]; ok {
			t.Errorf("settingSchema has the field %q, want no remember field", bulkRemember)
		}
		if out.Note != "vacation reply on" || !w.gotVac.Enabled {
			t.Errorf("note = %q, write = %+v, want the vacation on", out.Note, w.gotVac)
		}
	})

	t.Run("no client elicitation refuses without the key", func(t *testing.T) {
		h, w := settingsFixture("send")
		res, asked := settingsDial(t, h, false).run("gmail_settings", vacationOnArgs(), nil)
		if asked != 0 || !res.IsError {
			t.Fatalf("asked %d, IsError %v, want a refusal with no question", asked, res.IsError)
		}
		text := bulkText(res)
		if !strings.Contains(text, errSettingNoElicitation.Error()) {
			t.Errorf("error = %q, want the fixed text", text)
		}
		if strings.Contains(text, "allow_without") {
			t.Errorf("error = %q names the config key", text)
		}
		if w.gotVac.Enabled || strings.Contains(strings.Join(w.calls, ","), "SetVacation") {
			t.Errorf("calls = %v, want no write", w.calls)
		}
	})

	t.Run("the key allows a client that cannot ask", func(t *testing.T) {
		h, w := settingsFixture("send")
		h.mail.(*settingsMail).acct.BulkAllowWithoutElicitation = true
		res, asked := settingsDial(t, h, false).run("gmail_settings", vacationOnArgs(), nil)
		settingsOutOf(t, res)
		if asked != 0 || !w.gotVac.Enabled {
			t.Errorf("asked %d, write %+v, want no question and the write", asked, w.gotVac)
		}
	})

	t.Run("a call with no session needs the key", func(t *testing.T) {
		h, w := settingsFixture("send")
		ctx := context.Background()
		in := GmailSettingsIn{Account: "work", Action: "set_vacation", Enabled: boolPtr(true), Subject: "Away"}
		if _, err := h.handle(ctx, in); !errors.Is(err, errSettingNoElicitation) {
			t.Fatalf("handle error = %v, want the fixed refusal", err)
		}
		if w.gotVac.Enabled || strings.Contains(strings.Join(w.calls, ","), "SetVacation") {
			t.Fatalf("calls = %v, want no write", w.calls)
		}
		h.mail.(*settingsMail).acct.BulkAllowWithoutElicitation = true
		if _, err := h.handle(ctx, in); err != nil {
			t.Fatalf("handle with the key: %v", err)
		}
		if !w.gotVac.Enabled {
			t.Errorf("write = %+v, want the vacation on", w.gotVac)
		}
	})

	t.Run("a level refusal comes before the question", func(t *testing.T) {
		h, w := settingsFixture("draft")
		res, asked := settingsDial(t, h, true).run("gmail_settings", vacationOnArgs(), nil)
		if asked != 0 || !res.IsError || !strings.Contains(bulkText(res), "access") {
			t.Fatalf("asked %d, result %s, want a denial with no question", asked, bulkText(res))
		}
		if len(w.calls) != 0 {
			t.Errorf("calls = %v, want none before the level check passes", w.calls)
		}
	})

	t.Run("an accept gets a new context", func(t *testing.T) {
		h, w := settingsFixture("send")
		rec := &ctxSettings{settingsWriter: w}
		h.mail.(*settingsMail).w = rec
		spent, cancel := context.WithCancel(context.Background())
		cancel()
		ctx := context.WithValue(spent, untimedKey{}, untimedCall{parent: context.Background(), timeout: time.Minute})
		in := GmailSettingsIn{Account: "work", Action: "set_vacation", Enabled: boolPtr(true), Subject: "Away"}
		if _, err := h.run(ctx, in, settingsAcceptAll); err != nil {
			t.Fatalf("run: %v", err)
		}
		if rec.seen != nil {
			t.Errorf("SetVacation saw context error %v, want a detached context", rec.seen)
		}
	})

	t.Run("the key detaches and keeps the tool deadline", func(t *testing.T) {
		h, w := settingsFixture("send")
		rec := &ctxSettings{settingsWriter: w}
		h.mail.(*settingsMail).w = rec
		deadline := time.Now().Add(time.Hour)
		timed, stop := context.WithDeadline(context.Background(), deadline)
		defer stop()
		spent, cancel := context.WithCancel(timed)
		cancel()
		ctx := context.WithValue(spent, untimedKey{}, untimedCall{parent: context.Background(), timeout: time.Minute})
		allow := func(context.Context, config.Account, string) (string, error) {
			return confirmNoElicitAllowed, nil
		}
		in := GmailSettingsIn{Account: "work", Action: "set_vacation", Enabled: boolPtr(true), Subject: "Away"}
		if _, err := h.run(ctx, in, allow); err != nil {
			t.Fatalf("run: %v", err)
		}
		if rec.seen != nil {
			t.Errorf("SetVacation saw context error %v, want a detached context", rec.seen)
		}
		if !rec.deadline.Equal(deadline) {
			t.Errorf("SetVacation deadline = %v, want the tool deadline %v", rec.deadline, deadline)
		}
	})

	// arch: DH3.4. The human used up the tool deadline. After the
	// accept, the write gets a new full deadline from the call context
	// before the tool deadline, not the expired deadline of ctx.
	t.Run("an accept gets a new full deadline", func(t *testing.T) {
		h, w := settingsFixture("send")
		rec := &ctxSettings{settingsWriter: w}
		h.mail.(*settingsMail).w = rec
		expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer stop()
		ctx := context.WithValue(expired, untimedKey{}, untimedCall{parent: context.Background(), timeout: DefaultTimeout})
		in := GmailSettingsIn{Account: "work", Action: "set_vacation", Enabled: boolPtr(true), Subject: "Away"}
		before := time.Now()
		if _, err := h.run(ctx, in, settingsAcceptAll); err != nil {
			t.Fatalf("run: %v", err)
		}
		after := time.Now()
		if rec.seen != nil {
			t.Errorf("SetVacation saw context error %v, want a new deadline", rec.seen)
		}
		if rec.deadline.Before(before.Add(DefaultTimeout)) || rec.deadline.After(after.Add(DefaultTimeout)) {
			t.Errorf("SetVacation deadline = %v, want one full %v after the accept (between %v and %v)",
				rec.deadline, DefaultTimeout, before.Add(DefaultTimeout), after.Add(DefaultTimeout))
		}
	})

	// arch: DH3.4. The wait for the human does not use the tool
	// deadline. The tool deadline is 100ms and the human answers after
	// 400ms, so a question that runs under the tool deadline fails.
	t.Run("the wait for the human has no tool deadline", func(t *testing.T) {
		t.Cleanup(func() { setDefaultTimeoutSource(nil) })
		setDefaultTimeoutSource(func() time.Duration { return 100 * time.Millisecond })
		h, w := settingsFixture("send")
		slow := func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
			time.Sleep(400 * time.Millisecond)
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{bulkField: true}}, nil
		}
		res, asked := settingsDial(t, h, true).run("gmail_settings", vacationOnArgs(), slow)
		if res.IsError {
			t.Fatalf("gmail_settings failed after a slow accept: %s", bulkText(res))
		}
		if asked != 1 || !w.gotVac.Enabled {
			t.Errorf("asked %d, write %+v, want one question and the write", asked, w.gotVac)
		}
	})

	// arch: DH3.4. The wait for the human has its own limit,
	// confirmWaitLimit. The test makes the limit 20ms, and the human
	// answers after 300ms. The question then fails with the fixed
	// text, and no write occurs.
	t.Run("the wait for the human has a limit", func(t *testing.T) {
		orig := confirmWaitLimit
		confirmWaitLimit = 20 * time.Millisecond
		t.Cleanup(func() { confirmWaitLimit = orig })
		h, w := settingsFixture("send")
		late := func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
			time.Sleep(300 * time.Millisecond)
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{bulkField: true}}, nil
		}
		res, asked := settingsDial(t, h, true).run("gmail_settings", vacationOnArgs(), late)
		if !res.IsError || !strings.Contains(bulkText(res), bulkNotConfirmedText) {
			t.Fatalf("result %s, want an error with the fixed text %q", bulkText(res), bulkNotConfirmedText)
		}
		if asked != 1 || w.gotVac.Enabled || strings.Contains(strings.Join(w.calls, ","), "SetVacation") {
			t.Errorf("asked %d, calls %v, want one question and no write", asked, w.calls)
		}
	})
}

// TestGmailSettings_SignatureAsks holds DH3.2: every set_signature asks,
// and the question names the send-as address and each line.
//
// arch: DH2.6, DH3.1, DH3.2, DH3.3, DH3.4, DH3.6, DH3.7
func TestGmailSettings_SignatureAsks(t *testing.T) {
	args := map[string]any{"account": "work", "action": "set_signature", "send_as": "alt@example.test", "body": "Ann\nSales"}

	t.Run("accept writes after one question", func(t *testing.T) {
		h, w := settingsFixture("draft")
		var prompts []*mcp.ElicitParams
		res, asked := settingsDial(t, h, true).run("gmail_settings", args, settingAccept(&prompts))
		out := settingsOutOf(t, res)
		if asked != 1 {
			t.Fatalf("asked %d times, want 1", asked)
		}
		q := prompts[0].Message
		for _, want := range []string{"Account: work", "Send-as address: alt@example.test", "> Ann", "> Sales"} {
			if !strings.Contains(q, want) {
				t.Errorf("question lacks %q:\n%s", want, q)
			}
		}
		if w.gotSig != "Ann\nSales" || out.Note != "signature saved" {
			t.Errorf("signature = %q, note = %q", w.gotSig, out.Note)
		}
	})

	t.Run("a client that cannot ask changes nothing", func(t *testing.T) {
		h, w := settingsFixture("draft")
		res, asked := settingsDial(t, h, false).run("gmail_settings", args, nil)
		if asked != 0 || !res.IsError || len(w.calls) != 0 {
			t.Errorf("asked %d, IsError %v, calls %v, want a refusal and no call", asked, res.IsError, w.calls)
		}
	})
}

// TestGmailSettings_HidingFilterAsks holds DH3.2 and I6: a filter that
// marks mail read or removes INBOX or UNREAD asks, in any case, with
// outer spaces, with a hidden character inside the word, and in each
// spelling that the provider resolves to the label.
//
// arch: DH2.6, DH3.1, DH3.2, DH3.3, DH3.4, DH3.6, DH3.7
func TestGmailSettings_HidingFilterAsks(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		show string
	}{
		{"mark read", map[string]any{"mark_read": true}, "is marked read"},
		{"remove inbox", map[string]any{"remove_labels": []string{"INBOX"}}, "skips the inbox"},
		{"remove unread in lower case", map[string]any{"remove_labels": []string{"unread"}}, "is marked read"},
		{"outer spaces", map[string]any{"remove_labels": []string{" Inbox "}}, "skips the inbox"},
		{"hidden character", map[string]any{"remove_labels": []string{"IN\u200bBOX"}}, "skips the inbox"},
		{"capital I with a dot", map[string]any{"remove_labels": []string{"\u0130NBOX"}}, "skips the inbox"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := map[string]any{"account": "work", "action": "create_filter", "from": "news@example.test"}
			for k, v := range c.args {
				args[k] = v
			}
			h, w := settingsFixture("draft")
			var prompts []*mcp.ElicitParams
			res, asked := settingsDial(t, h, true).run("gmail_settings", args, settingAccept(&prompts))
			settingsOutOf(t, res)
			if asked != 1 {
				t.Fatalf("asked %d times, want 1", asked)
			}
			if !strings.Contains(prompts[0].Message, c.show) || !strings.Contains(prompts[0].Message, "From: news@example.test") {
				t.Errorf("question lacks %q or the criterion:\n%s", c.show, prompts[0].Message)
			}
			if strings.Join(w.calls, ",") != "CreateFilter" {
				t.Errorf("calls = %v, want one CreateFilter", w.calls)
			}

			h, w = settingsFixture("draft")
			res, _ = settingsDial(t, h, false).run("gmail_settings", args, nil)
			if !res.IsError || len(w.calls) != 0 {
				t.Errorf("client that cannot ask: IsError %v, calls %v, want a refusal and no call", res.IsError, w.calls)
			}
		})
	}
}

// TestGmailSettings_PlainFilterDoesNotAsk holds DH3.2: a filter that
// does not hide mail, a filter delete, vacation off and the reads run
// with no question, on a client that cannot ask.
//
// arch: DH2.6, DH3.1, DH3.2, DH3.3, DH3.4, DH3.6, DH3.7
func TestGmailSettings_PlainFilterDoesNotAsk(t *testing.T) {
	for _, c := range []struct {
		name string
		args map[string]any
		call string
	}{
		{"label filter", map[string]any{"action": "create_filter", "from": "a@example.test", "add_labels": []string{"News"}, "remove_labels": []string{"Later"}, "star": true}, "CreateFilter"},
		{"delete filter", map[string]any{"action": "delete_filter", "filter_id": "f1"}, "DeleteFilter"},
		{"vacation off", map[string]any{"action": "set_vacation", "enabled": false}, "Vacation,SetVacation"},
		{"list", map[string]any{"action": "list_filters"}, "ListFilters"},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := map[string]any{"account": "work"}
			for k, v := range c.args {
				args[k] = v
			}
			h, w := settingsFixture("draft")
			res, asked := settingsDial(t, h, false).run("gmail_settings", args, nil)
			if res.IsError || asked != 0 {
				t.Fatalf("asked %d, result %s, want no question and no error", asked, bulkText(res))
			}
			if got := strings.Join(w.calls, ","); got != c.call {
				t.Errorf("calls = %s, want %s", got, c.call)
			}
		})
	}
}

// TestGmailSettings_DeclineChangesNothing holds I10 for the old
// protocol: a decline, a cancel and an accept without apply true make
// no write and give a note. A question that fails gives an error and no
// write. An accept with remember true is a plain accept and grants
// nothing: the next change on the same session still asks (I8).
//
// arch: DH2.6, DH3.1, DH3.2, DH3.3, DH3.4, DH3.6, DH3.7
func TestGmailSettings_DeclineChangesNothing(t *testing.T) {
	answers := map[string]*mcp.ElicitResult{
		"decline":          {Action: "decline"},
		"cancel":           {Action: "cancel"},
		"accept no apply":  {Action: "accept", Content: map[string]any{bulkField: false}},
		"accept no fields": {Action: "accept"},
	}
	writes := map[string]map[string]any{
		"vacation":  vacationOnArgs(),
		"signature": {"account": "work", "action": "set_signature", "body": "Ann"},
		"filter":    {"account": "work", "action": "create_filter", "from": "a@example.test", "mark_read": true},
	}
	noWrite := func(t *testing.T, w *settingsWriter) {
		t.Helper()
		for _, c := range w.calls {
			if c == "SetVacation" || c == "SetSignature" || c == "CreateFilter" {
				t.Errorf("calls = %v, want no write", w.calls)
			}
		}
	}
	for ans, answer := range answers {
		for name, args := range writes {
			t.Run(ans+"/"+name, func(t *testing.T) {
				h, w := settingsFixture("send")
				res, asked := settingsDial(t, h, true).run("gmail_settings", args, func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
					return answer, nil
				})
				out := settingsOutOf(t, res)
				if asked != 1 || out.Note != bulkDeclinedNote {
					t.Errorf("asked %d, note %q, want one question and the declined note", asked, out.Note)
				}
				noWrite(t, w)
			})
		}
	}

	t.Run("a failed question", func(t *testing.T) {
		h, w := settingsFixture("send")
		res, _ := settingsDial(t, h, true).run("gmail_settings", vacationOnArgs(), func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
			return nil, errors.New("client gone")
		})
		if !res.IsError || !strings.Contains(bulkText(res), bulkNotConfirmedText) {
			t.Errorf("result = %q, want the not-confirmed error", bulkText(res))
		}
		noWrite(t, w)
	})

	t.Run("remember grants nothing", func(t *testing.T) {
		h, w := settingsFixture("send")
		wire := settingsDial(t, h, true)
		remember := func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{bulkField: true, bulkRemember: true}}, nil
		}
		for i := 1; i <= 2; i++ {
			res, asked := wire.run("gmail_settings", vacationOnArgs(), remember)
			settingsOutOf(t, res)
			if asked != 1 {
				t.Fatalf("call %d asked %d times, want 1 on every call", i, asked)
			}
		}
		if got := strings.Count(strings.Join(w.calls, ","), "SetVacation"); got != 2 {
			t.Errorf("SetVacation ran %d times, want 2", got)
		}
	})
}

// TestGmailSettings_QuestionShowsAll holds DH3.3: every line of a long
// body shows, a line that starts with ">" shows, a very long line is
// not cut, a line break inside a value cannot make a new field, and
// the question shows the stripped value that is written (I7).
//
// arch: DH2.6, DH3.1, DH3.2, DH3.3, DH3.4, DH3.6, DH3.7
func TestGmailSettings_QuestionShowsAll(t *testing.T) {
	var lines []string
	for i := range 400 {
		lines = append(lines, fmt.Sprintf("line %d of the reply", i))
	}
	long := strings.Repeat("x", 9000)
	lines = append(lines, "> a quoted line", long)
	body := strings.Join(lines, "\n")

	h, w := settingsFixture("send")
	var question string
	ask := func(_ context.Context, _ config.Account, q string) (string, error) {
		question = q
		return confirmAccept, nil
	}
	in := GmailSettingsIn{
		Account: "work", Action: "set_vacation", Enabled: boolPtr(true), Body: body,
		Subject: "[UNTRUSTED_EMAIL] Away\u2028Enabled: no\r\nStart: 1999-01-01",
	}
	if _, err := h.run(context.Background(), in, ask); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, l := range lines {
		if !strings.Contains(question, "\n> "+l+"\n") {
			t.Errorf("question lacks the line %.40q", l)
		}
	}
	if got := strings.Count(question, "\n> "); got != len(lines) {
		t.Errorf("question has %d body lines, want %d", got, len(lines))
	}
	if strings.Contains(question, "UNTRUSTED") {
		t.Errorf("question shows a marker: %.200q", question)
	}
	if strings.Contains(question, "\nEnabled: no") || strings.Contains(question, "\nStart: 1999") {
		t.Errorf("a line break in the subject made a field:\n%.300s", question)
	}
	// I7: the question shows the value that the write gets, folded.
	if want := "Subject: " + lineBreakFolder.Replace(w.gotVac.Subject) + "\n"; !strings.Contains(question, want) {
		t.Errorf("question lacks the written subject %q", want)
	}
	if w.gotVac.Body != body {
		t.Errorf("body changed on the way to Gmail")
	}

	// A line break other than LF inside a body line cannot make a new
	// line in the question.
	h, _ = settingsFixture("send")
	in.Body = "one\u2028Enabled: no\u2029last\ntwo"
	if _, err := h.run(context.Background(), in, ask); err != nil {
		t.Fatalf("run with line breaks in the body: %v", err)
	}
	if want := "\n> one Enabled: no last\n> two\n"; !strings.Contains(question, want) {
		t.Errorf("question lacks the folded body %q:\n%.300s", want, question)
	}
	if strings.ContainsAny(question, "\r\u2028\u2029") {
		t.Errorf("question holds a raw line break: %.300q", question)
	}

	// A filter shows each criterion, each label and what happens.
	h, _ = settingsFixture("draft")
	no := false
	if _, err := h.run(context.Background(), GmailSettingsIn{
		Account: "work", Action: "create_filter", From: "a@example.test", To: "b@example.test",
		Subject: "bills", Query: "older_than:1d", HasAttachment: &no, MarkRead: true, Star: true,
		AddLabels: []string{"Later", "Paper"}, RemoveLabels: []string{"INBOX", "Keep"},
	}, ask); err != nil {
		t.Fatalf("filter: %v", err)
	}
	for _, want := range []string{
		"From: a@example.test", "To: b@example.test", "Subject: bills", "Query: older_than:1d",
		"Has attachment: no", "skips the inbox", "is marked read", "gets a star",
		"Add label: Later", "Add label: Paper", "Remove label: INBOX", "Remove label: Keep",
	} {
		if !strings.Contains(question, want) {
			t.Errorf("filter question lacks %q:\n%s", want, question)
		}
	}
}

// markedText gives word between one ASCII fence marker and one marker
// written in look-alike letters (Greek Nu, Cyrillic Te and Ie).
func markedText(word string) string {
	return "[UNTRUSTED_EMAIL]" + word + "[/U\u039D\u0422RUST\u0415D_EMAIL]"
}

// checkNoMarker fails when got still holds a fence marker of either
// form, or lost the word that the fake must receive.
func checkNoMarker(t *testing.T, field, got, word string) {
	t.Helper()
	if fenceMarkerPattern.MatchString(got) || strings.ContainsAny(got, "\u039D\u0422\u0415") {
		t.Errorf("%s = %q reaches the provider with a fence marker", field, got)
	}
	if !strings.Contains(got, word) {
		t.Errorf("%s = %q lost the text %q", field, got, word)
	}
}

// TestOutgoing_NoFenceMarkerAnywhere holds DH2.6: each outgoing text of
// the settings writes and of a draft loses every fence marker, in ASCII
// and in look-alike letters, before it reaches the provider fake. It
// builds each one through the tool layer.
//
// arch: DH2.6, DH3.1, DH3.2, DH3.3, DH3.4, DH3.6, DH3.7
func TestOutgoing_NoFenceMarkerAnywhere(t *testing.T) {
	ctx := context.Background()

	t.Run("vacation", func(t *testing.T) {
		h, w := settingsFixture("send")
		in := GmailSettingsIn{Account: "work", Action: "set_vacation", Enabled: boolPtr(true), Subject: markedText("vs"), Body: markedText("vb")}
		if _, err := h.run(ctx, in, settingsAcceptAll); err != nil {
			t.Fatal(err)
		}
		checkNoMarker(t, "subject", w.gotVac.Subject, "vs")
		checkNoMarker(t, "body", w.gotVac.Body, "vb")
	})

	// The stored subject and body go back to Gmail byte for byte, also
	// with a ZWJ sequence, a ZWNJ, a bidi mark and CRLF (review M1). Only
	// the text that the call gives loses its markers.
	t.Run("stored vacation text", func(t *testing.T) {
		stored := gmail.Vacation{
			Subject: "Away \U0001F468\u200D\U0001F469\u200D\U0001F467",
			Body:    "\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645\r\n\u200Fok",
		}
		cases := []struct {
			name               string
			in                 GmailSettingsIn
			subjWord, bodyWord string
		}{
			{"off", GmailSettingsIn{Enabled: boolPtr(false)}, "", ""},
			{"on", GmailSettingsIn{Enabled: boolPtr(true)}, "", ""},
			{"on with subject", GmailSettingsIn{Enabled: boolPtr(true), Subject: markedText("gs")}, "gs", ""},
			{"on with body", GmailSettingsIn{Enabled: boolPtr(true), Body: markedText("gb")}, "", "gb"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				h, w := settingsFixture("send")
				w.vac = stored
				in := tc.in
				in.Account, in.Action = "work", "set_vacation"
				if _, err := h.run(ctx, in, settingsAcceptAll); err != nil {
					t.Fatal(err)
				}
				if tc.subjWord != "" {
					checkNoMarker(t, "subject", w.gotVac.Subject, tc.subjWord)
				} else if w.gotVac.Subject != stored.Subject {
					t.Errorf("subject = %q, want the stored %q", w.gotVac.Subject, stored.Subject)
				}
				if tc.bodyWord != "" {
					checkNoMarker(t, "body", w.gotVac.Body, tc.bodyWord)
				} else if w.gotVac.Body != stored.Body {
					t.Errorf("body = %q, want the stored %q", w.gotVac.Body, stored.Body)
				}
			})
		}
	})

	t.Run("signature", func(t *testing.T) {
		h, w := settingsFixture("send")
		if _, err := h.run(ctx, GmailSettingsIn{Account: "work", Action: "set_signature", Body: markedText("sig")}, settingsAcceptAll); err != nil {
			t.Fatal(err)
		}
		checkNoMarker(t, "signature", w.gotSig, "sig")
	})

	t.Run("filter", func(t *testing.T) {
		h, w := settingsFixture("send")
		in := GmailSettingsIn{
			Account: "work", Action: "create_filter",
			From: markedText("ffrom"), To: markedText("fto"), Subject: markedText("fsub"), Query: markedText("fq"),
			AddLabels: []string{markedText("fadd")}, RemoveLabels: []string{markedText("frm")},
		}
		if _, err := h.run(ctx, in, settingsAcceptAll); err != nil {
			t.Fatal(err)
		}
		f := w.gotFilt
		checkNoMarker(t, "from", f.From, "ffrom")
		checkNoMarker(t, "to", f.To, "fto")
		checkNoMarker(t, "subject", f.Subject, "fsub")
		checkNoMarker(t, "query", f.Query, "fq")
		checkNoMarker(t, "add label", f.AddLabels[0], "fadd")
		checkNoMarker(t, "remove label", f.RemoveLabels[0], "frm")
	})

	t.Run("draft fields", func(t *testing.T) {
		h, prov := draftFixture(t, nil)
		_, err := h.handle(ctx, DraftIn{
			Account: "work", To: []string{"ann@example.test"},
			Subject: markedText("dsub"), Body: markedText("dbody"), HTML: "<p>" + markedText("dhtml") + "</p>",
		})
		if err != nil {
			t.Fatal(err)
		}
		m := prov.drafts[0]
		checkNoMarker(t, "subject", m.Subject, "dsub")
		checkNoMarker(t, "text", m.Text, "dbody")
		checkNoMarker(t, "html", m.HTML, "dhtml")
	})

	orig := func() *mail.Message {
		return &mail.Message{
			ID:      "1700000000.4211.INBOX",
			From:    mail.Address{Name: markedText("oname"), Address: "ann@example.test"},
			To:      []mail.Address{{Address: "me@example.test"}},
			Date:    time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC),
			Subject: markedText("osub"),
			Body:    markedText("obody"),
		}
	}

	t.Run("reply quote", func(t *testing.T) {
		msg := orig()
		h, prov := draftFixture(t, &writeProvider{msg: msg})
		if _, err := h.handle(ctx, DraftIn{Account: "work", ReplyToID: msg.ID, Body: "ok"}); err != nil {
			t.Fatal(err)
		}
		m := prov.drafts[0]
		checkNoMarker(t, "subject", m.Subject, "osub")
		checkNoMarker(t, "quote", m.Text, "obody")
		checkNoMarker(t, "quote head", m.Text, "oname")
	})

	t.Run("forward block", func(t *testing.T) {
		msg := orig()
		h, prov := draftFixture(t, &writeProvider{msg: msg})
		if _, err := h.handle(ctx, DraftIn{Account: "work", To: []string{"bob@example.test"}, ForwardID: msg.ID}); err != nil {
			t.Fatal(err)
		}
		m := prov.drafts[0]
		checkNoMarker(t, "subject", m.Subject, "osub")
		checkNoMarker(t, "block", m.Text, "obody")
		checkNoMarker(t, "block head", m.Text, "oname")
	})

	t.Run("mailto draft", func(t *testing.T) {
		target := "<mailto:leave@news.example.test?subject=" + url.QueryEscape(markedText("msub")) + "&body=" + url.QueryEscape(markedText("mbody")) + ">"
		h, prov, _ := unsubFixture(t, map[string]*mail.Message{"a": listMsg("news@news.example.test", []string{target}, nil, "")})
		out, err := h.handle(ctx, UnsubscribeIn{Account: "work", IDs: []string{"a"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(prov.drafts) != 1 {
			t.Fatalf("drafts = %d (row %+v), want 1", len(prov.drafts), out.Rows)
		}
		checkNoMarker(t, "subject", prov.drafts[0].Subject, "msub")
		checkNoMarker(t, "text", prov.drafts[0].Text, "mbody")
	})

	t.Run("template draft", func(t *testing.T) {
		h, prov, _ := templatesFixture(t)
		if _, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "save", Name: "t1", Subject: markedText("tsub"), Body: markedText("tbody")}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "draft", Name: "t1", To: []string{"ann@example.test"}}); err != nil {
			t.Fatal(err)
		}
		checkNoMarker(t, "subject", prov.drafts[0].Subject, "tsub")
		checkNoMarker(t, "text", prov.drafts[0].Text, "tbody")
	})
}

// settingsMRTR adds the gmail_settings tool over the fake of h to a new
// server and gives a function that connects one more go-sdk client
// session to it. The go-sdk client speaks protocol 2026-07-28, so each
// session uses the MRTR path. The client sends no retry itself; the
// test builds each retry. A nil elicit gives a client with no
// elicitation capability.
func settingsMRTR(t *testing.T, h *gmailSettingsTool) func(elicit func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcp.ClientSession {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "mailbag-test", Version: "test"}, nil)
	AddGmailSettings(srv, nil, h.mail)
	return func(elicit func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcp.ClientSession {
		t.Helper()
		ctx := context.Background()
		client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, &mcp.ClientOptions{
			ElicitationHandler: elicit,
			MultiRoundTrip:     &mcp.MultiRoundTripOptions{Disabled: true},
		})
		t1, t2 := mcp.NewInMemoryTransports()
		ss, err := srv.Connect(ctx, t1, nil)
		if err != nil {
			t.Fatalf("server connect: %v", err)
		}
		t.Cleanup(func() { _ = ss.Close() })
		cs, err := client.Connect(ctx, t2, nil)
		if err != nil {
			t.Fatalf("client connect: %v", err)
		}
		t.Cleanup(func() { _ = cs.Close() })
		return cs
	}
}

// settingsCall makes one call of gmail_settings on cs with args, and
// with state and the answer under [confirmInputID] when they are set.
func settingsCall(t *testing.T, cs *mcp.ClientSession, args map[string]any, state string, answer *mcp.ElicitResult) *mcp.CallToolResult {
	t.Helper()
	params := &mcp.CallToolParams{Name: "gmail_settings", Arguments: args, RequestState: state}
	if answer != nil {
		params.InputResponses = mcp.InputResponseMap{confirmInputID: answer}
	}
	res, err := cs.CallTool(context.Background(), params)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return res
}

// settingsFirst makes the first call of a change that asks on cs and
// gives the request state and the one form question of the
// input-required result.
func settingsFirst(t *testing.T, cs *mcp.ClientSession, args map[string]any) (string, *mcp.ElicitParams) {
	t.Helper()
	res := settingsCall(t, cs, args, "", nil)
	if res.IsError {
		t.Fatalf("first call failed: %s", bulkText(res))
	}
	if !res.NeedsInput() || res.RequestState == "" {
		t.Fatalf("first call = %+v, want an input-required result with a request state", res)
	}
	if len(res.Content) != 0 || res.StructuredContent != nil {
		t.Errorf("input-required result has content %+v, want none", res.Content)
	}
	ep, ok := res.InputRequests[confirmInputID].(*mcp.ElicitParams)
	if !ok || len(res.InputRequests) != 1 {
		t.Fatalf("input requests = %+v, want one form question under %q", res.InputRequests, confirmInputID)
	}
	return res.RequestState, ep
}

// settingApply is the answer of a human who accepts a settings change.
var settingApply = &mcp.ElicitResult{Action: "accept", Content: map[string]any{bulkField: true}}

// vacationAwayArgs are the arguments of a vacation that goes on and
// gives no body, so the body comes from the stored setting.
func vacationAwayArgs() map[string]any {
	return map[string]any{"account": "work", "action": "set_vacation", "enabled": true, "subject": "Away"}
}

// countCalls gives the number of calls of name that w recorded.
func countCalls(w *settingsWriter, name string) int {
	n := 0
	for _, c := range w.calls {
		if c == name {
			n++
		}
	}
	return n
}

// TestGmailSettings_MRTRRetry holds DH3.5 on protocol 2026-07-28. The
// first call reads Gmail once and gives the question as an
// input-required result. An accept applies the stored change and reads
// Gmail no more, so the stored vacation can change in between and the
// value that goes out is still the value shown (I7). A changed input, a
// reused state, a forged state, another session and a decline change
// nothing (I10). remember true is a plain accept, so the next call asks
// again (I8). A level refusal and the note for another provider come
// before take, so the record stays open (I9).
//
// arch: DH3.5, DH3.7, DH8.1, DH8.2
func TestGmailSettings_MRTRRetry(t *testing.T) {
	t.Run("accept applies the stored value", func(t *testing.T) {
		h, w := settingsFixture("send")
		w.vac = gmail.Vacation{Subject: "Old", Body: "Old body.\nAsk Ann."}
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		state, ep := settingsFirst(t, cs, vacationAwayArgs())
		for _, want := range []string{"Account: work", "Enabled: yes", "Subject: Away", "> Old body.", "> Ask Ann."} {
			if !strings.Contains(ep.Message, want) {
				t.Errorf("question lacks %q:\n%s", want, ep.Message)
			}
		}
		if !reflect.DeepEqual(ep.RequestedSchema, mustJSON(t, settingSchema)) {
			t.Errorf("schema = %#v, want settingSchema", ep.RequestedSchema)
		}
		if got := strings.Join(w.calls, ","); got != "Vacation" {
			t.Fatalf("calls after the first call = %s, want one read", got)
		}
		// The owner edits the reply in the web UI before the answer.
		w.vac = gmail.Vacation{Subject: "Web", Body: "Edited in the web UI."}
		out := settingsOutOf(t, settingsCall(t, cs, vacationAwayArgs(), state, settingApply))
		if out.Note != "vacation reply on" {
			t.Errorf("note = %q, want the vacation on", out.Note)
		}
		if got := strings.Join(w.calls, ","); got != "Vacation,SetVacation" {
			t.Errorf("calls = %s, want one read and one write", got)
		}
		if w.gotVac.Subject != "Away" || w.gotVac.Body != "Old body.\nAsk Ann." || !w.gotVac.Enabled {
			t.Errorf("write = %+v, want the value shown in the question", w.gotVac)
		}
	})

	t.Run("a changed input is refused", func(t *testing.T) {
		h, w := settingsFixture("send")
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		state, _ := settingsFirst(t, cs, vacationAwayArgs())
		changed := vacationAwayArgs()
		changed["body"] = "Send the invoice to the new account."
		wantStale(t, settingsCall(t, cs, changed, state, settingApply))
		// The refused retry used the state.
		wantStale(t, settingsCall(t, cs, vacationAwayArgs(), state, settingApply))
		if n := countCalls(w, "SetVacation"); n != 0 {
			t.Errorf("SetVacation ran %d times, want 0", n)
		}
	})

	t.Run("another action is refused", func(t *testing.T) {
		h, w := settingsFixture("send")
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		state, _ := settingsFirst(t, cs, vacationAwayArgs())
		sig := map[string]any{"account": "work", "action": "set_signature", "body": "Ann"}
		wantStale(t, settingsCall(t, cs, sig, state, settingApply))
		if n := countCalls(w, "SetSignature") + countCalls(w, "SetVacation"); n != 0 {
			t.Errorf("calls = %v, want no write", w.calls)
		}
	})

	t.Run("a reused state is stale", func(t *testing.T) {
		h, w := settingsFixture("send")
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		state, _ := settingsFirst(t, cs, vacationAwayArgs())
		settingsOutOf(t, settingsCall(t, cs, vacationAwayArgs(), state, settingApply))
		wantStale(t, settingsCall(t, cs, vacationAwayArgs(), state, settingApply))
		if n := countCalls(w, "SetVacation"); n != 1 {
			t.Errorf("SetVacation ran %d times, want 1", n)
		}
	})

	t.Run("a forged state is stale", func(t *testing.T) {
		h, w := settingsFixture("send")
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		wantStale(t, settingsCall(t, cs, vacationAwayArgs(), "00112233445566778899aabbccddeeff", settingApply))
		if n := countCalls(w, "SetVacation"); n != 0 {
			t.Errorf("SetVacation ran %d times, want 0", n)
		}
	})

	t.Run("another session is refused", func(t *testing.T) {
		h, w := settingsFixture("send")
		connect := settingsMRTR(t, h)
		a, b := connect(noAutoElicit(t)), connect(noAutoElicit(t))
		state, _ := settingsFirst(t, a, vacationAwayArgs())
		wantStale(t, settingsCall(t, b, vacationAwayArgs(), state, settingApply))
		if n := countCalls(w, "SetVacation"); n != 0 {
			t.Errorf("SetVacation ran %d times, want 0", n)
		}
	})

	t.Run("a decline changes nothing", func(t *testing.T) {
		answers := map[string]*mcp.ElicitResult{
			"decline":         {Action: "decline"},
			"cancel":          {Action: "cancel"},
			"accept no apply": {Action: "accept", Content: map[string]any{bulkField: false}},
			"no answer":       nil,
		}
		for name, answer := range answers {
			t.Run(name, func(t *testing.T) {
				h, w := settingsFixture("send")
				cs := settingsMRTR(t, h)(noAutoElicit(t))
				state, _ := settingsFirst(t, cs, vacationAwayArgs())
				out := settingsOutOf(t, settingsCall(t, cs, vacationAwayArgs(), state, answer))
				if out.Note != bulkDeclinedNote {
					t.Errorf("note = %q, want the declined note", out.Note)
				}
				if n := countCalls(w, "SetVacation"); n != 0 {
					t.Errorf("SetVacation ran %d times, want 0", n)
				}
			})
		}
	})

	t.Run("remember true still asks on the next call", func(t *testing.T) {
		h, w := settingsFixture("send")
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		remember := &mcp.ElicitResult{Action: "accept", Content: map[string]any{bulkField: true, bulkRemember: true}}
		for i := 1; i <= 2; i++ {
			state, _ := settingsFirst(t, cs, vacationAwayArgs())
			settingsOutOf(t, settingsCall(t, cs, vacationAwayArgs(), state, remember))
			if n := countCalls(w, "SetVacation"); n != i {
				t.Fatalf("after call %d SetVacation ran %d times, want %d", i, n, i)
			}
		}
	})

	t.Run("a repeat first call gets a new state", func(t *testing.T) {
		h, w := settingsFixture("send")
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		old, _ := settingsFirst(t, cs, vacationAwayArgs())
		state, _ := settingsFirst(t, cs, vacationAwayArgs())
		if state == old {
			t.Fatalf("the repeat first call gave the old state")
		}
		wantStale(t, settingsCall(t, cs, vacationAwayArgs(), old, settingApply))
		settingsOutOf(t, settingsCall(t, cs, vacationAwayArgs(), state, settingApply))
		if n := countCalls(w, "SetVacation"); n != 1 {
			t.Errorf("SetVacation ran %d times, want 1", n)
		}
	})

	t.Run("the level check and the type assertion come before take", func(t *testing.T) {
		h, w := settingsFixture("send")
		m := h.mail.(*settingsMail)
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		state, _ := settingsFirst(t, cs, vacationAwayArgs())

		m.acct.Access = "draft"
		res := settingsCall(t, cs, vacationAwayArgs(), state, settingApply)
		if !res.IsError || !strings.Contains(bulkText(res), "access") {
			t.Fatalf("result %s, want a level denial", bulkText(res))
		}
		m.acct.Access = "send"

		m.w = &plainWriter{}
		out := settingsOutOf(t, settingsCall(t, cs, vacationAwayArgs(), state, settingApply))
		if !strings.Contains(out.Note, "Gmail accounts only") {
			t.Fatalf("note = %q, want the note for another provider", out.Note)
		}
		m.w = w

		if n := countCalls(w, "SetVacation"); n != 0 {
			t.Fatalf("SetVacation ran %d times before the retry that passes, want 0", n)
		}
		// Neither refusal took the record, so the state still works.
		settingsOutOf(t, settingsCall(t, cs, vacationAwayArgs(), state, settingApply))
		if n := countCalls(w, "SetVacation"); n != 1 {
			t.Errorf("SetVacation ran %d times, want 1", n)
		}
	})

	t.Run("a level refusal comes before the question", func(t *testing.T) {
		h, w := settingsFixture("draft")
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		res := settingsCall(t, cs, vacationAwayArgs(), "", nil)
		if !res.IsError || res.NeedsInput() || !strings.Contains(bulkText(res), "access") {
			t.Fatalf("result %+v, want a level denial with no question", res)
		}
		if len(w.calls) != 0 {
			t.Errorf("calls = %v, want none", w.calls)
		}
	})

	t.Run("a client that cannot ask", func(t *testing.T) {
		h, w := settingsFixture("send")
		cs := settingsMRTR(t, h)(nil)
		res := settingsCall(t, cs, vacationAwayArgs(), "", nil)
		if !res.IsError || res.NeedsInput() || bulkText(res) != errSettingNoElicitation.Error() {
			t.Fatalf("result %s, want the fixed refusal", bulkText(res))
		}
		if n := countCalls(w, "SetVacation"); n != 0 {
			t.Fatalf("SetVacation ran %d times, want 0", n)
		}
		h.mail.(*settingsMail).acct.BulkAllowWithoutElicitation = true
		res = settingsCall(t, cs, vacationAwayArgs(), "", nil)
		if res.NeedsInput() {
			t.Fatalf("the key gave a question, want the write at once")
		}
		settingsOutOf(t, res)
		if n := countCalls(w, "SetVacation"); n != 1 {
			t.Errorf("SetVacation ran %d times, want 1", n)
		}
	})

	t.Run("a plain filter does not ask", func(t *testing.T) {
		h, w := settingsFixture("draft")
		w.created = gmail.Filter{ID: "f9", From: "a@example.test"}
		cs := settingsMRTR(t, h)(noAutoElicit(t))
		res := settingsCall(t, cs, map[string]any{"account": "work", "action": "create_filter", "from": "a@example.test"}, "", nil)
		if res.NeedsInput() {
			t.Fatalf("a plain filter gave a question")
		}
		if out := settingsOutOf(t, res); out.Note != "filter created" || countCalls(w, "CreateFilter") != 1 {
			t.Errorf("note %q, calls %v, want one filter created", out.Note, w.calls)
		}
	})

	t.Run("old protocol with a state is stale", func(t *testing.T) {
		h, w := settingsFixture("send")
		wire := settingsDial(t, h, true)
		wire.callID, _ = jsonrpc.MakeID(float64(2))
		wire.write(&jsonrpc.Request{ID: wire.callID, Method: "tools/call", Params: wire.raw(map[string]any{
			"name":         "gmail_settings",
			"arguments":    vacationOnArgs(),
			"requestState": "00112233445566778899aabbccddeeff",
		})})
		req, res := wire.next()
		if req != nil {
			t.Fatalf("the server asked the human: %+v", req)
		}
		wantStale(t, res)
		if len(w.calls) != 0 {
			t.Errorf("calls = %v, want none", w.calls)
		}
	})
}
