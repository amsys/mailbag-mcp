// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools holds, in pending.go, the store of the open
// confirmations of the MRTR path (DS14.3). The send and bulk tools
// keep a record there between the first call and the retry.
package tools

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// pendingLimit is the maximum number of open confirmations that one
// [pendingStore] keeps (DS14.3).
const pendingLimit = 64

// errPendingFull is the fixed refusal of a full [pendingStore]. The
// call asks nobody and nothing leaves or changes (DS14.3).
var errPendingFull = errors.New("too many confirmations are open, so nothing was sent or changed; answer an open confirmation, or wait some minutes, then call again")

// errConfirmStale is the fixed refusal of a retry whose request state
// names no open confirmation of this call: the state is unknown, used,
// expired, or from another session or another call (DS14.5, IS14.2).
var errConfirmStale = errors.New("the confirmation is not open any more (it was used, it expired, or it belongs to another call), so nothing was sent or changed; call the tool again to get a new confirmation")

// pendingStore keeps each open confirmation of the MRTR path (DS14.3)
// in memory, per process. The key of a record is the request state
// that the input-required result gives to the client.
//
// A record expires [confirmWaitLimit] after [pendingStore.put]. A
// [pendingStore.take] removes the record, so a request state works one
// time only (IS14.2).
//
// A first call of a send takes a place with [pendingStore.hold]
// before it spends a send of the limit, and writes its record into
// that place later with [pendingHold.fill] (DS14.3, DS14.4).
//
// The zero value works and uses the wall clock. A test replaces now
// with its own clock, because a test must never wait 10 minutes (C24).
//
// One tool serves every MCP call of one process, and those calls can
// run at the same time, so every read and write of the map is under
// the mutex.
//
// arch: DS14.3
type pendingStore[T any] struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]pendingEntry[T]
	// held counts the places that hold gave and that no fill or drop
	// ended yet. A held place counts against [pendingLimit].
	held int
}

// pendingEntry is one open confirmation and the time it expires.
//
// arch: DS14.3
type pendingEntry[T any] struct {
	rec     T
	expires time.Time
}

// clock gives the time of the store.
func (s *pendingStore[T]) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

// put keeps rec and gives its request state: 16 random bytes from
// crypto/rand in hex. When the records and the held places fill the
// store, put first removes the expired records. When the store is full
// after that, put gives [errPendingFull] and keeps nothing.
//
// arch: DS14.3
func (s *pendingStore[T]) put(rec T) (string, error) {
	state, err := newState()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.room(); err != nil {
		return "", err
	}
	s.add(state, rec)
	return state, nil
}

// room gives [errPendingFull] when the records and the held places
// fill the store after the expired records go. The caller holds mu.
//
// arch: DS14.3
func (s *pendingStore[T]) room() error {
	if len(s.entries)+s.held < pendingLimit {
		return nil
	}
	now := s.clock()
	for k, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, k)
		}
	}
	if len(s.entries)+s.held >= pendingLimit {
		return errPendingFull
	}
	return nil
}

// add keeps rec under state with an expiry of [confirmWaitLimit]. The
// caller holds mu.
func (s *pendingStore[T]) add(state string, rec T) {
	if s.entries == nil {
		s.entries = make(map[string]pendingEntry[T])
	}
	s.entries[state] = pendingEntry[T]{rec: rec, expires: s.clock().Add(confirmWaitLimit)}
}

// newState gives a request state: 16 random bytes from crypto/rand in
// hex.
func newState() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// pendingHold is one place in a [pendingStore] that
// [pendingStore.hold] gave. [pendingHold.fill] writes the record into
// the place; [pendingHold.drop] gives the place back. After the first
// of the two, the hold does nothing more. A nil hold is safe to drop.
//
// arch: DS14.3, DS14.4
type pendingHold[T any] struct {
	s    *pendingStore[T]
	done bool
}

// hold takes one place in the store for a first call (DS14.4). When an
// open record matches, hold removes it and gives its place with reuse
// true: the state of that record does not work any more, and the
// caller writes a new record with a new state. When no open record
// matches, hold takes a free place, or gives [errPendingFull] when the
// store is full after the expired records go.
//
// The place counts against [pendingLimit] until fill or drop, so the
// caller can spend a send of the limit between hold and fill and a
// full store still refuses before that spend.
//
// arch: DS14.3, DS14.4
func (s *pendingStore[T]) hold(match func(T) bool) (h *pendingHold[T], reuse bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	for k, e := range s.entries {
		if now.Before(e.expires) && match(e.rec) {
			delete(s.entries, k)
			s.held++
			return &pendingHold[T]{s: s}, true, nil
		}
	}
	if err := s.room(); err != nil {
		return nil, false, err
	}
	s.held++
	return &pendingHold[T]{s: s}, false, nil
}

// fill keeps rec in the held place and gives its new request state.
// When crypto/rand fails, fill gives the place back and keeps nothing.
//
// arch: DS14.3, DS14.4
func (h *pendingHold[T]) fill(rec T) (string, error) {
	state, err := newState()
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	h.done = true
	h.s.held--
	if err != nil {
		return "", err
	}
	h.s.add(state, rec)
	return state, nil
}

// drop gives the held place back when no fill used it.
//
// arch: DS14.3
func (h *pendingHold[T]) drop() {
	if h == nil {
		return
	}
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	if h.done {
		return
	}
	h.done = true
	h.s.held--
}

// take removes the record of state and gives it. ok is false when the
// store has no record of state, or when the record expired. A second
// take of the same state always gives ok false (IS14.2).
//
// arch: DS14.3, IS14.2
func (s *pendingStore[T]) take(state string) (rec T, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, found := s.entries[state]
	if !found {
		return rec, false
	}
	delete(s.entries, state)
	if !s.clock().Before(e.expires) {
		return rec, false
	}
	return e.rec, true
}
