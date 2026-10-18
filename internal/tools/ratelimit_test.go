// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// limitClock is the injected clock of the send limit. A test moves it
// by hand, so no test waits a minute of real time (C24).
type limitClock struct {
	mu sync.Mutex
	t  time.Time
}

func newLimitClock() *limitClock {
	return &limitClock{t: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)}
}

func (c *limitClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *limitClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// limitFixture gives a send handler whose limit runs on a fake clock.
func limitFixture(t *testing.T) (*sendTool, *writeProvider, *limitClock) {
	t.Helper()
	h, prov := sendFixture(t, nil)
	clk := newLimitClock()
	h.limit.now = clk.Now
	return h, prov, clk
}

// sendOnce sends one stored draft through the handler. Since D5.1
// the send tool sends only a saved draft.
func sendOnce(t *testing.T, h *sendTool, account string) error {
	t.Helper()
	_, err := h.handle(context.Background(), SendIn{
		Account: account,
		DraftID: "1700000000.99.Drafts",
	})
	return err
}

// TestSend_RateLimit holds M12: a model in a loop must stop at 10
// sends in one minute for each account. The 11th call is refused, the
// message never reaches the provider, and the window slides, so the
// account sends again one minute later.
//
// arch: T5.6, §3.11, M12, §8 S5
func TestSend_RateLimit(t *testing.T) {
	t.Run("ten pass and the eleventh is refused", func(t *testing.T) {
		h, prov, _ := limitFixture(t)
		for i := 0; i < sendsPerWindow; i++ {
			if err := sendOnce(t, h, "work"); err != nil {
				t.Fatalf("send %d: %v", i+1, err)
			}
		}
		err := sendOnce(t, h, "work")
		if err == nil {
			t.Fatal("the 11th send passed; the limit of M12 did not hold")
		}
		if !strings.Contains(err.Error(), "10 sends in one minute") {
			t.Errorf("the error does not name the limit: %v", err)
		}
		if len(prov.sentDrafts) != sendsPerWindow {
			t.Errorf("the provider saw %d messages, want %d: the refused call still sent", len(prov.sentDrafts), sendsPerWindow)
		}
	})

	t.Run("the window slides", func(t *testing.T) {
		h, prov, clk := limitFixture(t)
		for i := 0; i < sendsPerWindow; i++ {
			if err := sendOnce(t, h, "work"); err != nil {
				t.Fatalf("send %d: %v", i+1, err)
			}
		}
		clk.Add(59 * time.Second)
		if err := sendOnce(t, h, "work"); err == nil {
			t.Fatal("a send passed inside the minute")
		}
		clk.Add(2 * time.Second)
		if err := sendOnce(t, h, "work"); err != nil {
			t.Fatalf("a send failed after the minute: %v", err)
		}
		if len(prov.sentDrafts) != sendsPerWindow+1 {
			t.Errorf("the provider saw %d messages, want %d", len(prov.sentDrafts), sendsPerWindow+1)
		}
	})

	t.Run("a draft does not count", func(t *testing.T) {
		h, prov, _ := limitFixture(t)
		d := &draftTool{mail: h.mail}
		for i := 0; i < sendsPerWindow*2; i++ {
			_, err := d.handle(context.Background(), DraftIn{
				Account: "work",
				To:      []string{"ann@example.test"},
				Subject: "hello",
				Body:    "text",
			})
			if err != nil {
				t.Fatalf("draft %d: %v", i+1, err)
			}
		}
		if len(prov.sent) != 0 || len(prov.sentDrafts) != 0 {
			t.Fatalf("a draft reached Send")
		}
		if err := sendOnce(t, h, "work"); err != nil {
			t.Errorf("the drafts spent the limit: %v", err)
		}
	})

	t.Run("a refused message spends nothing", func(t *testing.T) {
		h, _, _ := limitFixture(t)
		for i := 0; i < sendsPerWindow*2; i++ {
			_, err := h.handle(context.Background(), SendIn{
				Account: "work",
				DraftID: " ",
			})
			if err == nil {
				t.Fatalf("the send tool passed an empty draft_id")
			}
		}
		if err := sendOnce(t, h, "work"); err != nil {
			t.Errorf("the refused calls spent the limit: %v", err)
		}
	})

	t.Run("the count is for each account", func(t *testing.T) {
		h, _, _ := limitFixture(t)
		for i := 0; i < sendsPerWindow; i++ {
			if err := sendOnce(t, h, "work"); err != nil {
				t.Fatalf("send %d: %v", i+1, err)
			}
		}
		if err := h.limit.take("home"); err != nil {
			t.Errorf("a second account starts at the limit of the first: %v", err)
		}
	})

	t.Run("a send draft counts", func(t *testing.T) {
		h, prov, _ := limitFixture(t)
		for i := 0; i < sendsPerWindow; i++ {
			if _, err := h.handle(context.Background(), SendIn{
				Account: "work",
				DraftID: "1700000000.99.Drafts",
			}); err != nil {
				t.Fatalf("send draft %d: %v", i+1, err)
			}
		}
		if _, err := h.handle(context.Background(), SendIn{
			Account: "work",
			DraftID: "1700000000.99.Drafts",
		}); err == nil {
			t.Fatal("the 11th stored draft went out")
		}
		if len(prov.sentDrafts) != sendsPerWindow {
			t.Errorf("the provider saw %d drafts, want %d", len(prov.sentDrafts), sendsPerWindow)
		}
	})

	t.Run("parallel takes never pass more than ten", func(t *testing.T) {
		// The limit is one value shared by every MCP call of one
		// process, so the count must hold under -race. This subtest
		// drives the limiter itself: the fake provider of the send
		// tests keeps its lists without a mutex.
		var l sendLimiter
		clk := newLimitClock()
		l.now = clk.Now
		var wg sync.WaitGroup
		var mu sync.Mutex
		passed := 0
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := l.take("work"); err == nil {
					mu.Lock()
					passed++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if passed != sendsPerWindow {
			t.Errorf("%d takes passed, want %d", passed, sendsPerWindow)
		}
	})
}
