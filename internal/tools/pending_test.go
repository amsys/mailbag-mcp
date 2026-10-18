// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the store of open confirmations (DS14.3): the zero value,
// the single-use take, the expiry and the full store.
package tools

import (
	"errors"
	"regexp"
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
	a, err := s.put("a")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	b, err := s.put("b")
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
	early, _ := s.put("early")
	late, _ := s.put("late")
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
// expired records.
//
// arch: DS14.3
func TestPendingStore_FullRefuses(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := pendingStore[int]{now: func() time.Time { return now }}
	old, _ := s.put(-1)
	now = now.Add(time.Minute)
	for i := 1; i < pendingLimit; i++ {
		if _, err := s.put(i); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if _, err := s.put(pendingLimit); !errors.Is(err, errPendingFull) {
		t.Fatalf("put into a full store = %v, want %v", err, errPendingFull)
	}
	if n := len(s.entries); n != pendingLimit {
		t.Errorf("the store holds %d records, want %d", n, pendingLimit)
	}

	// The first record expires first; the next put removes it and
	// keeps the new record.
	now = now.Add(confirmWaitLimit - time.Minute)
	if _, err := s.put(pendingLimit); err != nil {
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
// record removes the state of that record.
//
// arch: DS14.3, DS14.4
func TestPendingStore_HoldCountsUntilFillOrDrop(t *testing.T) {
	var s pendingStore[int]
	for i := 1; i < pendingLimit; i++ {
		if _, err := s.put(i); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	h, reuse, err := s.hold(func(int) bool { return false })
	if err != nil || reuse {
		t.Fatalf("hold = %v, %v, want a free place", reuse, err)
	}
	if _, err := s.put(0); !errors.Is(err, errPendingFull) {
		t.Fatalf("put with the last place held = %v, want %v", err, errPendingFull)
	}
	h.drop()
	h.drop()
	if s.held != 0 {
		t.Fatalf("held = %d after two drops, want 0", s.held)
	}
	old, err := s.put(0)
	if err != nil {
		t.Fatalf("put after the drop: %v", err)
	}

	h, reuse, err = s.hold(func(r int) bool { return r == 0 })
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
				state, err := h.pending.put(rec)
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
				state, err := h.pending.put(rec)
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
