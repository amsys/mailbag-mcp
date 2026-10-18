// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools: grant_test.go holds the tests of the session grant of
// the bulk tool (DS14.11): the third answer "Yes, and do not ask again
// until reconnect", on the old protocol and on the MRTR path.
package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// bulkRememberAnswer is the answer of a human who accepts and asks for
// no more questions until reconnect.
func bulkRememberAnswer(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
	return &mcp.ElicitResult{Action: "accept", Content: map[string]any{bulkField: true, bulkRemember: true}}, nil
}

// bulkStarArgs are the arguments of a second bulk call on the account
// alias.
func bulkStarArgs(alias string) map[string]any {
	return map[string]any{"account": alias, "query": "from:news", "folder": "INBOX", "action": "star"}
}

// sessions gives the count of sessions that hold a grant.
func (g *grantStore) sessions() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.grants)
}

// grantOn makes one bulk call on w that the human accepts with
// remember true, and checks the note of the grant.
func grantOn(t *testing.T, w *bulkWire) {
	t.Helper()
	res, asked := w.run("bulk", bulkReadArgs(), bulkRememberAnswer)
	out := bulkOutOf(t, res)
	if asked != 1 || out.Applied != 3 || out.Undo == "" {
		t.Fatalf("grant call = %+v with %d questions, want 1 question, applied 3 and an undo token", out, asked)
	}
	if !strings.Contains(out.Note, bulkGrantGivenNote) {
		t.Errorf("note = %q, want the grant note %q", out.Note, bulkGrantGivenNote)
	}
}

// TestBulk_SessionGrantSkipsQuestion holds DS14.11 on the old
// protocol: after an accept with remember true, the next bulk call of
// the session on that account asks nobody and runs as an accepted
// call. It has its own undo token and journal record, and its note
// says that it ran under the grant.
//
// arch: DS14.11, DS9.4, DS9.5
func TestBulk_SessionGrantSkipsQuestion(t *testing.T) {
	h, prov, j := bulkFixture(t, 3)
	w := dialBulk(t, func(srv *mcp.Server) { addBulk(srv, h) }, true)
	grantOn(t, w)

	res, asked := w.run("bulk", bulkStarArgs("work"), nil)
	out := bulkOutOf(t, res)
	if asked != 0 {
		t.Errorf("the second call asked %d times, want 0", asked)
	}
	if out.Applied != 3 || out.Undo == "" {
		t.Errorf("second call = %+v, want applied 3 and an undo token", out)
	}
	if !strings.Contains(out.Note, bulkGrantUsedNote) {
		t.Errorf("note = %q, want the note %q", out.Note, bulkGrantUsedNote)
	}
	if n := prov.callCount(); n != 2 {
		t.Errorf("%d change calls, want 2", n)
	}
	if recs := bulkRecords(t, j); len(recs) != 2 {
		t.Errorf("journal = %+v, want two records", recs)
	}
}

// TestBulk_SessionGrantPerAccount holds DS14.11: a grant on one
// account does not cover another account of the same session.
//
// arch: DS14.11
func TestBulk_SessionGrantPerAccount(t *testing.T) {
	h, _, _ := bulkFixture(t, 3)
	w := dialBulk(t, func(srv *mcp.Server) { addBulk(srv, h) }, true)
	grantOn(t, w)

	res, asked := w.run("bulk", bulkStarArgs("home"), func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})
	out := bulkOutOf(t, res)
	if asked != 1 || out.Note != bulkDeclinedNote {
		t.Errorf("call on home = %+v with %d questions, want 1 question and the note %q", out, asked, bulkDeclinedNote)
	}
}

// TestBulk_SessionGrantPerSession holds DS14.11: a grant of one
// session does not cover another session, and the grant goes away
// when its session ends. A reconnect is a new session and gets the
// question again.
//
// arch: DS14.11
func TestBulk_SessionGrantPerSession(t *testing.T) {
	h, _, _ := bulkFixture(t, 3)
	register := func(srv *mcp.Server) { addBulk(srv, h) }
	a := dialBulk(t, register, true)
	b := dialBulk(t, register, true)
	grantOn(t, a)

	_, asked := b.run("bulk", bulkStarArgs("work"), func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})
	if asked != 1 {
		t.Errorf("the other session asked %d times, want 1", asked)
	}

	_ = a.conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for h.grants.sessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions hold a grant after the session ended, want 0", h.grants.sessions())
		}
		time.Sleep(5 * time.Millisecond)
	}
	c := dialBulk(t, register, true)
	_, asked = c.run("bulk", bulkStarArgs("work"), func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})
	if asked != 1 {
		t.Errorf("the session after the reconnect asked %d times, want 1", asked)
	}
}

// TestBulk_SessionGrantDeclineGrantsNothing holds DS14.11: remember
// true with a decline, a cancel or apply false grants nothing, and the
// next call asks again.
//
// arch: DS14.11, IS14.6
func TestBulk_SessionGrantDeclineGrantsNothing(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer *mcp.ElicitResult
	}{
		{"decline", &mcp.ElicitResult{Action: "decline", Content: map[string]any{bulkRemember: true}}},
		{"cancel", &mcp.ElicitResult{Action: "cancel", Content: map[string]any{bulkRemember: true}}},
		{"apply false", &mcp.ElicitResult{Action: "accept", Content: map[string]any{bulkField: false, bulkRemember: true}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, prov, _ := bulkFixture(t, 3)
			w := dialBulk(t, func(srv *mcp.Server) { addBulk(srv, h) }, true)
			res, _ := w.run("bulk", bulkReadArgs(), func(*mcp.ElicitParams) (*mcp.ElicitResult, error) { return c.answer, nil })
			if out := bulkOutOf(t, res); out.Note != bulkDeclinedNote {
				t.Fatalf("first call = %+v, want the note %q", out, bulkDeclinedNote)
			}
			_, asked := w.run("bulk", bulkStarArgs("work"), func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
				return &mcp.ElicitResult{Action: "decline"}, nil
			})
			if asked != 1 {
				t.Errorf("the next call asked %d times, want 1", asked)
			}
			if n := prov.callCount(); n != 0 {
				t.Errorf("%d change calls, want 0", n)
			}
			if n := h.grants.sessions(); n != 0 {
				t.Errorf("%d sessions hold a grant, want 0", n)
			}
		})
	}
}

// TestBulk_SessionGrantSendStillAsks holds DS14.11: a bulk grant does
// not cover send. A send on the same session after the grant still
// asks the human, and a decline sends nothing.
//
// arch: DS14.11, D5.2
func TestBulk_SessionGrantSendStillAsks(t *testing.T) {
	h, _, _ := bulkFixture(t, 3)
	fm, sendProv := confirmFixture(t)
	w := dialBulk(t, func(srv *mcp.Server) {
		addBulk(srv, h)
		addSend(srv, &sendTool{mail: fm})
	}, true)
	grantOn(t, w)

	res, asked := w.run("send", sendArgs(), func(*mcp.ElicitParams) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})
	if asked != 1 {
		t.Errorf("send asked %d times after the bulk grant, want 1", asked)
	}
	if res.IsError {
		t.Errorf("send failed: %s", bulkText(res))
	}
	if n := len(sendProv.sentDrafts); n != 0 {
		t.Errorf("%d drafts sent after a decline, want 0", n)
	}
}

// TestBulk_MRTRSessionGrant holds DS14.11 on protocol 2026-07-28: the
// input-required question offers the field remember, an accept with
// remember true grants the session, and the next first call of that
// session on that account runs at once with no input-required result.
// Another session still gets the question.
//
// arch: DS14.11, DS14.6, DS14.7
func TestBulk_MRTRSessionGrant(t *testing.T) {
	h, prov, j := bulkFixture(t, 3)
	connect := bulkMRTR(t, h)
	cs := connect(bulkNoAuto(t), false)

	state, ep := bulkFirst(t, cs, bulkReadArgs())
	props, _ := ep.RequestedSchema.(map[string]any)["properties"].(map[string]any)
	if _, ok := props[bulkRemember]; !ok {
		t.Fatalf("schema = %#v, want the field %q", ep.RequestedSchema, bulkRemember)
	}
	remember := &mcp.ElicitResult{Action: "accept", Content: map[string]any{bulkField: true, bulkRemember: true}}
	out := bulkOutOf(t, bulkRetry(t, cs, bulkReadArgs(), state, remember))
	if out.Applied != 3 || !strings.Contains(out.Note, bulkGrantGivenNote) {
		t.Fatalf("retry = %+v, want applied 3 and the note %q", out, bulkGrantGivenNote)
	}

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "bulk", Arguments: bulkStarArgs("work")})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.NeedsInput() {
		t.Fatalf("second call = %+v, want a result with no question", res)
	}
	out = bulkOutOf(t, res)
	if out.Applied != 3 || out.Undo == "" || !strings.Contains(out.Note, bulkGrantUsedNote) {
		t.Errorf("second call = %+v, want applied 3, an undo token and the note %q", out, bulkGrantUsedNote)
	}
	if n := len(h.pending.entries); n != 0 {
		t.Errorf("the store holds %d records, want 0", n)
	}
	if recs := bulkRecords(t, j); len(recs) != 2 {
		t.Errorf("journal = %+v, want two records", recs)
	}

	other := connect(bulkNoAuto(t), false)
	if state, _ := bulkFirst(t, other, bulkStarArgs("work")); state == "" {
		t.Error("the other session got no question")
	}
	if n := prov.callCount(); n != 2 {
		t.Errorf("%d change calls, want 2", n)
	}
}
