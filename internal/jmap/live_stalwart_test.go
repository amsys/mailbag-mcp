//go:build live

// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Live tests of the JMAP provider against a Stalwart account (C3). They
// run only with the build tag "live" and only when MAILBAG_LIVE_JMAP
// names an alias. The owner runs them. A test changes only the message
// that it created, and it destroys that message at the end (IS14.10).
// The tests print counts only, never a message value.

package jmap_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/jmap"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/tools"
)

// openLive opens the provider of the alias in MAILBAG_LIVE_JMAP, as
// TestLive_JMAP does, and skips the test when the variable is not set.
func openLive(t *testing.T, ctx context.Context) (*jmap.Provider, config.Account) {
	t.Helper()
	alias := os.Getenv("MAILBAG_LIVE_JMAP")
	if alias == "" {
		t.Skip("MAILBAG_LIVE_JMAP is not set; set it to a jmap alias to run the live test")
	}
	f := tools.NewFactory(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(f.Close)
	r, acct, err := f.Open(ctx, alias)
	if err != nil {
		t.Fatalf("open %q: %v", alias, err)
	}
	p, ok := r.(*jmap.Provider)
	if !ok {
		t.Fatalf("alias %q does not open a JMAP provider", alias)
	}
	return p, acct
}

// answer decodes the arguments of the response with call id into out.
func answer(t *testing.T, r *jmap.Response, id string, out any) {
	t.Helper()
	for _, inv := range r.MethodResponses {
		if inv.ID != id {
			continue
		}
		if err := inv.Err(); err != nil {
			t.Fatalf("call %s: %v", id, err)
		}
		b, err := json.Marshal(inv.Args)
		if err == nil {
			err = json.Unmarshal(b, out)
		}
		if err != nil {
			t.Fatalf("decode call %s: %v", id, err)
		}
		return
	}
	t.Fatalf("no answer for call %s", id)
}

// TestLive_LimitRetry sends 3 * MaxConcurrentRequests reads at the same
// time through one client. Each read must succeed. It logs how many
// requests postCapped sent again after the error "limit". No mail
// changes.
//
// arch: DS14.15, IS14.10, DF.4
func TestLive_LimitRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, _ := openLive(t, ctx)
	s, err := jmap.ClientOf(p).Session(ctx)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	max := s.MaxConcurrentRequests
	if max <= 0 {
		max = 4
	}
	n := 3 * max
	before := jmap.LimitRetries()
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = p.Folders(ctx) // Mailbox/get, read-only
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("read %d of %d: %v", i, n, err)
		}
	}
	t.Logf("%d reads, MaxConcurrentRequests %d, limit retries %d", n, max, jmap.LimitRetries()-before)
}

// TestLive_MoveOutOfJunkSetsNotJunk creates one message in the junk
// mailbox with $junk, moves it to the inbox with ModifyDetail, and
// reads its keywords: $notjunk is set, $junk is not, the mailbox is
// the inbox. t.Cleanup destroys the message whatever the result. Every
// call names the created id only.
//
// arch: DS14.15, IS14.10, DF.4
func TestLive_MoveOutOfJunkSetsNotJunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, acct := openLive(t, ctx)
	c := jmap.ClientOf(p)
	s, err := c.Session(ctx)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	acc := s.AccountID

	r, err := c.Call(ctx, jmap.Invocation{Name: "Mailbox/get", ID: "m", Args: map[string]any{
		"accountId": acc, "ids": nil, "properties": []string{"id", "role"},
	}})
	if err != nil {
		t.Fatalf("Mailbox/get: %v", err)
	}
	var boxes struct {
		List []struct{ ID, Role string } `json:"list"`
	}
	answer(t, r, "m", &boxes)
	var junk, inbox string
	for _, b := range boxes.List {
		switch b.Role {
		case "junk":
			junk = b.ID
		case "inbox":
			inbox = b.ID
		}
	}
	if junk == "" || inbox == "" {
		t.Fatalf("the account needs a junk and an inbox mailbox (junk found: %t, inbox found: %t)", junk != "", inbox != "")
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("random: %v", err)
	}
	addr := []map[string]string{{"email": acct.Email}}
	r, err = c.Call(ctx, jmap.Invocation{Name: "Email/set", ID: "c", Args: map[string]any{
		"accountId": acc,
		"create": map[string]any{"t": map[string]any{
			"mailboxIds": map[string]bool{junk: true},
			"keywords":   map[string]bool{"$junk": true},
			"from":       addr,
			"to":         addr,
			"subject":    "mailbag live test " + hex.EncodeToString(rnd[:]),
			"bodyValues": map[string]any{"b": map[string]string{"value": "mailbag live test message"}},
			"textBody":   []map[string]string{{"partId": "b", "type": "text/plain"}},
		}},
	}})
	if err != nil {
		t.Fatalf("Email/set create: %v", err)
	}
	var created struct {
		Created    map[string]struct{ ID string } `json:"created"`
		NotCreated map[string]json.RawMessage     `json:"notCreated"`
	}
	answer(t, r, "c", &created)
	id := created.Created["t"].ID
	if id == "" {
		t.Fatalf("the server did not create the message: %s", created.NotCreated["t"])
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		if _, err := c.Call(cctx, jmap.Invocation{Name: "Email/set", ID: "d", Args: map[string]any{
			"accountId": acc, "destroy": []string{id},
		}}); err != nil {
			t.Errorf("destroy the test message: %v", err)
		}
	})

	if _, err := p.ModifyDetail(ctx, []string{id}, mail.Change{MoveTo: "INBOX"}); err != nil {
		t.Fatalf("move to the inbox: %v", err)
	}

	r, err = c.Call(ctx, jmap.Invocation{Name: "Email/get", ID: "g", Args: map[string]any{
		"accountId": acc, "ids": []string{id}, "properties": []string{"keywords", "mailboxIds"},
	}})
	if err != nil {
		t.Fatalf("Email/get: %v", err)
	}
	var got struct {
		List []struct {
			Keywords   map[string]bool `json:"keywords"`
			MailboxIDs map[string]bool `json:"mailboxIds"`
		} `json:"list"`
	}
	answer(t, r, "g", &got)
	if len(got.List) != 1 {
		t.Fatalf("Email/get gave %d messages, want 1", len(got.List))
	}
	m := got.List[0]
	if !m.Keywords["$notjunk"] {
		t.Errorf("$notjunk is not set; keywords: %v", m.Keywords)
	}
	if m.Keywords["$junk"] {
		t.Errorf("$junk is still set; keywords: %v", m.Keywords)
	}
	if len(m.MailboxIDs) != 1 || !m.MailboxIDs[inbox] {
		t.Errorf("the message is not in the inbox only; mailbox count %d", len(m.MailboxIDs))
	}
}
