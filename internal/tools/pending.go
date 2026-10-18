// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools holds, in pending.go, the store of the open
// confirmations of the MRTR path (DS14.3, DS14.12). The send and bulk
// tools keep a record there between the first call and the retry.
package tools

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// pendingLimit is the maximum number of open confirmations that one
// [pendingStore] keeps (DS14.3).
const pendingLimit = 64

// pendingPerSession is the maximum number of places that one session
// has in one [pendingStore]: its open records plus its held places
// (DS14.12). Four sessions must fill their share to fill the store.
const pendingPerSession = 16

// errPendingSessionFull is the fixed refusal of a call whose session
// has [pendingPerSession] places in the store. The call asks nobody,
// nothing leaves or changes, and the call spends no send (DS14.12).
var errPendingSessionFull = errors.New("this session has 16 open confirmations, so nothing was sent or changed; answer an open confirmation of this session, or wait 10 minutes, then call again")

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
// Each place belongs to one session. One session has at most
// [pendingPerSession] places; every place goes back to its session on
// take, drop, expiry or reuse (DS14.12, IS14.7, IS14.8).
//
// One tool serves every MCP call of one process, and those calls can
// run at the same time, so every read and write of the maps is under
// the mutex.
//
// arch: DS14.3, DS14.12
type pendingStore[T any] struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]pendingEntry[T]
	// held counts the places that hold gave and that no fill or drop
	// ended yet. A held place counts against [pendingLimit].
	held int
	// perSession counts the places of each session: open records plus
	// held places. A count of 0 has no key, so the map does not grow
	// with the sessions that ended (IS14.8).
	perSession map[*mcp.ServerSession]int
}

// pendingEntry is one open confirmation, the session that owns its
// place, and the time it expires.
//
// arch: DS14.3, DS14.12
type pendingEntry[T any] struct {
	rec     T
	sess    *mcp.ServerSession
	expires time.Time
}

// clock gives the time of the store.
func (s *pendingStore[T]) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

// put keeps rec in a new place of sess and gives its request state:
// 16 random bytes from crypto/rand in hex. When sess has
// [pendingPerSession] places, put gives [errPendingSessionFull]; when
// the store is full, put gives [errPendingFull]. Both checks come after
// the expired records go, and a refused put keeps nothing.
//
// arch: DS14.3, DS14.12
func (s *pendingStore[T]) put(sess *mcp.ServerSession, rec T) (string, error) {
	state, err := newState()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.room(sess); err != nil {
		return "", err
	}
	s.count(sess, 1)
	s.add(state, sess, rec)
	return state, nil
}

// room gives [errPendingSessionFull] when sess has
// [pendingPerSession] places, and then [errPendingFull] when the
// records and the held places fill the store. When either limit is
// reached, room first removes the expired records and gives their
// places back. The caller holds mu.
//
// arch: DS14.3, DS14.12, IS14.7
func (s *pendingStore[T]) room(sess *mcp.ServerSession) error {
	if s.perSession[sess] < pendingPerSession && len(s.entries)+s.held < pendingLimit {
		return nil
	}
	now := s.clock()
	for k, e := range s.entries {
		if !now.Before(e.expires) {
			s.remove(k, e)
		}
	}
	if s.perSession[sess] >= pendingPerSession {
		return errPendingSessionFull
	}
	if len(s.entries)+s.held >= pendingLimit {
		return errPendingFull
	}
	return nil
}

// count adds n to the places of sess. A count that reaches 0 deletes
// the key of sess (IS14.8). The caller holds mu.
//
// arch: DS14.12, IS14.8
func (s *pendingStore[T]) count(sess *mcp.ServerSession, n int) {
	if s.perSession == nil {
		s.perSession = make(map[*mcp.ServerSession]int)
	}
	c := s.perSession[sess] + n
	if c <= 0 {
		delete(s.perSession, sess)
		return
	}
	s.perSession[sess] = c
}

// remove deletes the record e of state and gives its place back to
// its session. The caller holds mu.
//
// arch: DS14.12, IS14.8
func (s *pendingStore[T]) remove(state string, e pendingEntry[T]) {
	delete(s.entries, state)
	s.count(e.sess, -1)
}

// add keeps rec under state, in a place of sess that the caller
// already counted, with an expiry of [confirmWaitLimit]. The caller
// holds mu.
func (s *pendingStore[T]) add(state string, sess *mcp.ServerSession, rec T) {
	if s.entries == nil {
		s.entries = make(map[string]pendingEntry[T])
	}
	s.entries[state] = pendingEntry[T]{rec: rec, sess: sess, expires: s.clock().Add(confirmWaitLimit)}
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
// arch: DS14.3, DS14.4, DS14.12
type pendingHold[T any] struct {
	s    *pendingStore[T]
	sess *mcp.ServerSession
	done bool
}

// hold takes one place of sess in the store for a first call (DS14.4).
// When an open record of sess matches, hold removes it and gives its
// place with reuse true: the state of that record does not work any
// more, and the caller writes a new record with a new state. A reuse
// takes no new place of the share. When no open record matches, hold
// takes a free place, or gives [errPendingSessionFull] when sess has
// [pendingPerSession] places, or [errPendingFull] when the store is
// full after the expired records go.
//
// The place counts against [pendingLimit] and the share of sess until
// fill or drop, so the caller can spend a send of the limit between
// hold and fill and a full share or store still refuses before that
// spend (DS14.12).
//
// arch: DS14.3, DS14.4, DS14.12, IS14.7
func (s *pendingStore[T]) hold(sess *mcp.ServerSession, match func(T) bool) (h *pendingHold[T], reuse bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	for k, e := range s.entries {
		// Only a record of sess can give its place to sess, so a
		// reuse never moves a place from one share to another.
		if e.sess == sess && now.Before(e.expires) && match(e.rec) {
			delete(s.entries, k)
			s.held++
			return &pendingHold[T]{s: s, sess: sess}, true, nil
		}
	}
	if err := s.room(sess); err != nil {
		return nil, false, err
	}
	s.count(sess, 1)
	s.held++
	return &pendingHold[T]{s: s, sess: sess}, false, nil
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
		h.s.count(h.sess, -1)
		return "", err
	}
	h.s.add(state, h.sess, rec)
	return state, nil
}

// drop gives the held place back to the store and to its session
// when no fill used it.
//
// arch: DS14.3, DS14.12, IS14.8
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
	h.s.count(h.sess, -1)
}

// take removes the record of state, gives its place back to its
// session, and gives the record. ok is false when the store has no
// record of state, or when the record expired. A second take of the
// same state always gives ok false (IS14.2).
//
// arch: DS14.3, DS14.12, IS14.2, IS14.8
func (s *pendingStore[T]) take(state string) (rec T, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, found := s.entries[state]
	if !found {
		return rec, false
	}
	s.remove(state, e)
	if !s.clock().Before(e.expires) {
		return rec, false
	}
	return e.rec, true
}
