// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the store of open confirmations (DS14.3, DS14.12): the zero
// value, the single-use take, the expiry, the full store and the share
// of each session.
package tools

import (
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestPendingStore_ZeroValueTakesOnce holds DS14.3 and IS14.2: the
// zero value of the store works, a request state is 32 hex characters
// (16 random bytes), two puts give two states, and a take gives a
// record one time only.
//
// arch: DS14.3, IS14.2
func TestPendingStore_ZeroValueTakesOnce(t *testing.T) {
	var s pendingStore[string]
	a, err := s.put(nil, "a")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	b, err := s.put(nil, "b")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	hex := regexp.MustCompile(`^[0-9a-f]{32}$`)
	if !hex.MatchString(a) || !hex.MatchString(b) {
		t.Errorf("states %q and %q, want 32 hex characters each", a, b)
	}
	if a == b {
		t.Errorf("two puts gave the same state %q", a)
	}
	if rec, ok := s.take(a); !ok || rec != "a" {
		t.Errorf("take(a) = %q, %v, want \"a\", true", rec, ok)
	}
	if _, ok := s.take(a); ok {
		t.Error("a second take of the same state gave a record (IS14.2)")
	}
	if _, ok := s.take("00112233445566778899aabbccddeeff"); ok {
		t.Error("take of an unknown state gave a record")
	}
	if rec, ok := s.take(b); !ok || rec != "b" {
		t.Errorf("take(b) = %q, %v, want \"b\", true", rec, ok)
	}
}

// TestPendingStore_Expires holds DS14.3: a record expires
// [confirmWaitLimit] after its put, and a take of an expired record
// gives no record.
//
// arch: DS14.3, IS14.2
func TestPendingStore_Expires(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := pendingStore[string]{now: func() time.Time { return now }}
	early, _ := s.put(nil, "early")
	late, _ := s.put(nil, "late")
	now = now.Add(confirmWaitLimit - time.Second)
	if _, ok := s.take(early); !ok {
		t.Error("take before the expiry gave no record")
	}
	now = now.Add(time.Second)
	if _, ok := s.take(late); ok {
		t.Error("take at the expiry gave a record")
	}
}

// TestPendingStore_FullRefuses holds DS14.3: a store with
// [pendingLimit] open records refuses a put with the fixed
// [errPendingFull], and a put into a full store first removes the
// expired records. Four sessions fill the store, each with its share
// of [pendingPerSession] (DS14.12); a fifth session with a free share
// gets [errPendingFull].
//
// arch: DS14.3, DS14.12
func TestPendingStore_FullRefuses(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := pendingStore[int]{now: func() time.Time { return now }}
	sess := shareSessions(pendingLimit / pendingPerSession)
	fifth := new(mcp.ServerSession)
	old, _ := s.put(sess[0], -1)
	now = now.Add(time.Minute)
	for i := 1; i < pendingLimit; i++ {
		if _, err := s.put(sess[i/pendingPerSession], i); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if _, err := s.put(fifth, pendingLimit); !errors.Is(err, errPendingFull) {
		t.Fatalf("put into a full store = %v, want %v", err, errPendingFull)
	}
	if n := len(s.entries); n != pendingLimit {
		t.Errorf("the store holds %d records, want %d", n, pendingLimit)
	}

	// The first record expires first; the next put removes it and
	// keeps the new record.
	now = now.Add(confirmWaitLimit - time.Minute)
	if _, err := s.put(fifth, pendingLimit); err != nil {
		t.Fatalf("put after one record expired: %v", err)
	}
	if _, ok := s.take(old); ok {
		t.Error("the expired record is still in the store")
	}
	if n := len(s.entries); n != pendingLimit {
		t.Errorf("the store holds %d records, want %d", n, pendingLimit)
	}
}

// TestPendingStore_HoldCountsUntilFillOrDrop holds DS14.3: a held
// place counts against [pendingLimit] until fill or drop, a drop gives
// it back, a second drop does nothing, and a hold that reuses an open
// record removes the state of that record. Four sessions share the
// places, each within its share of [pendingPerSession] (DS14.12).
//
// arch: DS14.3, DS14.4, DS14.12
func TestPendingStore_HoldCountsUntilFillOrDrop(t *testing.T) {
	var s pendingStore[int]
	sess := shareSessions(pendingLimit / pendingPerSession)
	fifth := new(mcp.ServerSession)
	for i := 1; i < pendingLimit; i++ {
		if _, err := s.put(sess[i/pendingPerSession], i); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	h, reuse, err := s.hold(sess[0], func(int) bool { return false })
	if err != nil || reuse {
		t.Fatalf("hold = %v, %v, want a free place", reuse, err)
	}
	if _, err := s.put(fifth, 0); !errors.Is(err, errPendingFull) {
		t.Fatalf("put with the last place held = %v, want %v", err, errPendingFull)
	}
	h.drop()
	h.drop()
	if s.held != 0 {
		t.Fatalf("held = %d after two drops, want 0", s.held)
	}
	old, err := s.put(sess[0], 0)
	if err != nil {
		t.Fatalf("put after the drop: %v", err)
	}

	h, reuse, err = s.hold(sess[0], func(r int) bool { return r == 0 })
	if err != nil || !reuse {
		t.Fatalf("hold = %v, %v, want the open record of 0", reuse, err)
	}
	state, err := h.fill(0)
	if err != nil {
		t.Fatalf("fill: %v", err)
	}
	h.drop()
	if _, ok := s.take(old); ok {
		t.Error("the state of the reused record still works")
	}
	if rec, ok := s.take(state); !ok || rec != 0 {
		t.Errorf("take(new state) = %d, %v, want 0, true", rec, ok)
	}
	if s.held != 0 || len(s.entries) != pendingLimit-1 {
		t.Errorf("held = %d, records = %d, want 0 and %d", s.held, len(s.entries), pendingLimit-1)
	}
}

// TestClaimPending_EachFieldMustMatch holds IS14.2 for each field of
// a send record and of a bulk record: a retry that differs in one
// field gets [errConfirmStale], and the record is gone after the
// claim, also after a refusal.
//
// arch: DS14.5, DS14.7, IS14.2
func TestClaimPending_EachFieldMustMatch(t *testing.T) {
	ss, other := new(mcp.ServerSession), new(mcp.ServerSession)

	t.Run("send", func(t *testing.T) {
		rec := pendingSend{session: ss, account: "work", draftID: "d1", idemKey: "k1"}
		cases := []struct {
			name                  string
			sess                  *mcp.ServerSession
			account, draftID, key string
			wantErr               bool
		}{
			{"all match", ss, "work", "d1", "k1", false},
			{"other session", other, "work", "d1", "k1", true},
			{"other account", ss, "home", "d1", "k1", true},
			{"other draft", ss, "work", "d2", "k1", true},
			{"other key", ss, "work", "d1", "k2", true},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				h := &sendTool{}
				state, err := h.pending.put(ss, rec)
				if err != nil {
					t.Fatalf("put: %v", err)
				}
				_, err = h.claimPending(c.sess, state, c.account, c.draftID, c.key)
				if c.wantErr && !errors.Is(err, errConfirmStale) {
					t.Errorf("claim = %v, want errConfirmStale", err)
				}
				if !c.wantErr && err != nil {
					t.Errorf("claim = %v, want nil", err)
				}
				if _, err := h.claimPending(ss, state, "work", "d1", "k1"); !errors.Is(err, errConfirmStale) {
					t.Errorf("second claim = %v, want errConfirmStale", err)
				}
			})
		}
	})

	t.Run("bulk", func(t *testing.T) {
		in := BulkIn{Query: "from:a", Action: "archive"}
		rec := pendingBulk{session: ss, account: "work", input: bulkInput(in)}
		otherIn := in
		otherIn.Query = "from:b"
		cases := []struct {
			name    string
			sess    *mcp.ServerSession
			account string
			in      BulkIn
			wantErr bool
		}{
			{"all match", ss, "work", in, false},
			{"other session", other, "work", in, true},
			{"other account", ss, "home", in, true},
			{"other input", ss, "work", otherIn, true},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				h := &bulkTool{}
				state, err := h.pending.put(ss, rec)
				if err != nil {
					t.Fatalf("put: %v", err)
				}
				_, err = h.claimPending(c.sess, state, c.account, c.in)
				if c.wantErr && !errors.Is(err, errConfirmStale) {
					t.Errorf("claim = %v, want errConfirmStale", err)
				}
				if !c.wantErr && err != nil {
					t.Errorf("claim = %v, want nil", err)
				}
				if _, err := h.claimPending(ss, state, "work", in); !errors.Is(err, errConfirmStale) {
					t.Errorf("second claim = %v, want errConfirmStale", err)
				}
			})
		}
	})
}

// shareSessions gives n distinct sessions, one for each share of a
// test that fills a [pendingStore].
func shareSessions(n int) []*mcp.ServerSession {
	sess := make([]*mcp.ServerSession, n)
	for i := range sess {
		sess[i] = new(mcp.ServerSession)
	}
	return sess
}

// TestPendingStore_SessionShare holds DS14.12 and IS14.7: one session
// gets at most [pendingPerSession] places; the next put and the next
// hold of a new place get [errPendingSessionFull]; a hold that reuses
// an open record of that session still works; a second session still
// gets a place. Sessions that put at the same time never pass their
// share or the store cap.
//
// arch: DS14.12, IS14.7, IS14.8
func TestPendingStore_SessionShare(t *testing.T) {
	var s pendingStore[int]
	a, b := new(mcp.ServerSession), new(mcp.ServerSession)
	for i := range pendingPerSession {
		if _, err := s.put(a, i); err != nil {
			t.Fatalf("put %d of session a: %v", i, err)
		}
	}
	if _, err := s.put(a, pendingPerSession); !errors.Is(err, errPendingSessionFull) {
		t.Fatalf("put %d of session a = %v, want %v", pendingPerSession+1, err, errPendingSessionFull)
	}
	if h, _, err := s.hold(a, func(int) bool { return false }); !errors.Is(err, errPendingSessionFull) {
		h.drop()
		t.Fatalf("hold of a new place of session a = %v, want %v", err, errPendingSessionFull)
	}
	if n := len(s.entries); n != pendingPerSession {
		t.Errorf("the store holds %d records after the refusals, want %d", n, pendingPerSession)
	}

	// A record of session a never gives its place to session b.
	h, reuse, err := s.hold(b, func(r int) bool { return r == 0 })
	if err != nil || reuse {
		t.Fatalf("hold of session b = %v, %v, want a free place", reuse, err)
	}
	if _, err := h.fill(0); err != nil {
		t.Fatalf("fill: %v", err)
	}
	if _, err := s.put(b, 1); err != nil {
		t.Fatalf("put of session b: %v", err)
	}

	// A reuse takes no new place, so it works in a full share.
	h, reuse, err = s.hold(a, func(r int) bool { return r == 0 })
	if err != nil || !reuse {
		t.Fatalf("hold of session a = %v, %v, want the reuse of its open record", reuse, err)
	}
	if _, err := h.fill(0); err != nil {
		t.Fatalf("fill: %v", err)
	}
	if got := s.perSession[a]; got != pendingPerSession {
		t.Errorf("session a has %d places, want %d", got, pendingPerSession)
	}
	if got := s.perSession[b]; got != 2 {
		t.Errorf("session b has %d places, want 2", got)
	}

	// Eight sessions put at the same time into a new store: the store
	// takes [pendingLimit] records, and no session passes its share.
	var c pendingStore[int]
	sess := shareSessions(8)
	var wg sync.WaitGroup
	for _, ss := range sess {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range pendingPerSession + 4 {
				_, _ = c.put(ss, i)
			}
		}()
	}
	wg.Wait()
	if n := len(c.entries); n != pendingLimit {
		t.Errorf("the store holds %d records, want %d", n, pendingLimit)
	}
	total := 0
	for _, ss := range sess {
		n := c.perSession[ss]
		if n > pendingPerSession {
			t.Errorf("a session has %d places, want at most %d", n, pendingPerSession)
		}
		total += n
	}
	if total != pendingLimit {
		t.Errorf("the session counts add up to %d, want %d", total, pendingLimit)
	}
}

// TestPendingStore_SessionShareReturns holds DS14.12 and IS14.8: take,
// drop, expiry and reuse each give the place back to the session that
// held it, a count never goes below 0, and a count of 0 leaves no map
// key.
//
// arch: DS14.12, IS14.7, IS14.8
func TestPendingStore_SessionShareReturns(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := pendingStore[int]{now: func() time.Time { return now }}
	a := new(mcp.ServerSession)
	places := func(want int) {
		t.Helper()
		got, found := s.perSession[a]
		if got != want {
			t.Errorf("session a has %d places, want %d", got, want)
		}
		if want == 0 && found {
			t.Error("a count of 0 left a map key (IS14.8)")
		}
	}

	t.Run("take", func(t *testing.T) {
		state, err := s.put(a, 1)
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		places(1)
		if _, ok := s.take(state); !ok {
			t.Fatal("take gave no record")
		}
		places(0)
		s.take(state)
		places(0)
	})

	t.Run("drop", func(t *testing.T) {
		h, _, err := s.hold(a, func(int) bool { return false })
		if err != nil {
			t.Fatalf("hold: %v", err)
		}
		places(1)
		h.drop()
		h.drop()
		places(0)
	})

	t.Run("reuse", func(t *testing.T) {
		old, _ := s.put(a, 1)
		h, reuse, err := s.hold(a, func(r int) bool { return r == 1 })
		if err != nil || !reuse {
			t.Fatalf("hold = %v, %v, want a reuse", reuse, err)
		}
		places(1)
		state, err := h.fill(1)
		if err != nil {
			t.Fatalf("fill: %v", err)
		}
		places(1)
		if _, ok := s.take(old); ok {
			t.Error("the state of the reused record still works")
		}
		places(1)
		s.take(state)
		places(0)
	})

	t.Run("expiry", func(t *testing.T) {
		var last string
		for i := range pendingPerSession {
			last, _ = s.put(a, i)
		}
		places(pendingPerSession)
		now = now.Add(confirmWaitLimit)
		// The take of an expired record gives no record, but it
		// gives the place back.
		if _, ok := s.take(last); ok {
			t.Error("take of an expired record gave a record")
		}
		places(pendingPerSession - 1)
		// The share is not full, so this put sweeps nothing.
		state, err := s.put(a, 0)
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		places(pendingPerSession)
		// The share is full, so this put first removes the expired
		// records and gives their places back.
		if _, err := s.put(a, 1); err != nil {
			t.Fatalf("put into a share of expired records: %v", err)
		}
		places(2)
		s.take(state)
		places(1)
		if n := len(s.entries); n != 1 {
			t.Errorf("the store holds %d records, want 1", n)
		}
	})
}
