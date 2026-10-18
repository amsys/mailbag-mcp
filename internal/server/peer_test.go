// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build linux || darwin

// Tests of peerUID over a real Unix socket (DS11.12): each end of a
// connection gives the uid of this process, and a closed connection
// gives an error, never uid 0 with no error.

package server

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newPeerTestPair gives the two ends of one connection over a Unix
// socket in a short temp dir: the accepted end and the dialed end. A
// socket path above 100 bytes makes the test skip (sun_path limit).
func newPeerTestPair(t *testing.T) (accepted, dialed *net.UnixConn) {
	t.Helper()
	dir, err := os.MkdirTemp("", "mbp-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	if len(path) > 100 {
		t.Skipf("socket path has %d bytes, above the sun_path limit: %s", len(path), path)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if err := l.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	dialed, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialed.Close() })
	accepted, err = l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accepted.Close() })
	return accepted, dialed
}

// TestPeerUID_SameUIDOverRealSocket checks that peerUID gives
// os.Getuid() on the accepted end (the end that the daemon checks) and
// on the dialed end. This process is both peers, so the kernel records
// its uid for each end. A test cannot run as another uid (no root), so
// the refusal of another uid is TestSocket_PeerUIDRefused with an
// injected peerUID.
//
// arch: DS11.12, IS11.3
func TestPeerUID_SameUIDOverRealSocket(t *testing.T) {
	accepted, dialed := newPeerTestPair(t)
	want := uint32(os.Getuid()) //nolint:gosec // G115: a process uid is never negative and fits in 32 bits
	for _, end := range []struct {
		name string
		conn *net.UnixConn
	}{{"accepted", accepted}, {"dialed", dialed}} {
		got, err := peerUID(end.conn)
		if err != nil {
			t.Fatalf("%s end: peerUID: %v", end.name, err)
		}
		if got != want {
			t.Fatalf("%s end: peerUID = %d, want os.Getuid() = %d", end.name, got, want)
		}
	}
}

// TestPeerUID_ClosedConnFails checks that peerUID on a closed
// connection gives an error and uid 0, so that the daemon refuses the
// connection and never takes a failed read as a valid uid.
//
// arch: DS11.12, IS11.3
func TestPeerUID_ClosedConnFails(t *testing.T) {
	accepted, _ := newPeerTestPair(t)
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := peerUID(accepted)
	if err == nil {
		t.Fatalf("peerUID on a closed connection = %d, nil; want an error", got)
	}
	if got != 0 {
		t.Fatalf("peerUID on a closed connection = %d with error %v; want 0", got, err)
	}
}
