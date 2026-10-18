// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build linux || darwin

// Tests of activationListener (DS11.10) with an injected environment
// and an injected newFile over a Unix socket that the test makes in a
// short temp dir. No test uses the real XDG_RUNTIME_DIR (IS11.9).

package server

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

// activationTestEnv is an injected environment. unset records each
// name that unsetenv got, in order.
type activationTestEnv struct {
	vars  map[string]string
	unset []string
	fail  string // unsetenv of this name fails
}

func (e *activationTestEnv) getenv(name string) string { return e.vars[name] }

func (e *activationTestEnv) unsetenv(name string) error {
	e.unset = append(e.unset, name)
	if name == e.fail {
		return errors.New("unsetenv failed")
	}
	delete(e.vars, name)
	return nil
}

// checkUnsetAll fails the test when unsetenv did not get each of the
// four activation variables.
func (e *activationTestEnv) checkUnsetAll(t *testing.T) {
	t.Helper()
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"} {
		if !slices.Contains(e.unset, name) {
			t.Errorf("unsetenv(%q) not called; calls: %v", name, e.unset)
		}
	}
}

// activationTestDir gives a short temp dir for a test socket. The dir
// comes from os.MkdirTemp, never from XDG_RUNTIME_DIR, so the test
// never touches the live socket (IS11.9). A socket path above 100 bytes
// makes the test skip (sun_path limit).
func activationTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mba-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if len(filepath.Join(dir, "s")) > 100 {
		t.Skipf("socket path has more than 100 bytes, above the sun_path limit: %s", dir)
	}
	return dir
}

// activationTestSocket listens on a Unix stream socket in a short temp
// dir and gives its path and a copy of its fd as an *os.File: the fd
// that systemd passes as fd 3. The first listener stays open with
// unlink off, as the copy that systemd keeps.
func activationTestSocket(t *testing.T) (string, *os.File) {
	t.Helper()
	path := filepath.Join(activationTestDir(t), "s")
	sys, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	sys.SetUnlinkOnClose(false)
	t.Cleanup(func() { _ = sys.Close() })
	f, err := sys.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return path, f
}

// TestActivation_FD3 checks activationListener with an injected
// environment and newFile over a socket that the test made. With
// LISTEN_PID equal to this pid and LISTEN_FDS=1 it gives a
// *net.UnixListener on fd 3 that accepts on the socket path, closes the
// fd that newFile gave, and does not unlink the socket file when it is
// closed. Each call unsets the four LISTEN_ variables. When the
// variables are not for this process it gives nil and opens no fd. An
// unset that fails, a nil file and a datagram socket give an error and
// no listener.
//
// arch: DS11.10, DS11.16, IS11.9
func TestActivation_FD3(t *testing.T) {
	self := strconv.Itoa(os.Getpid())

	t.Run("activated", func(t *testing.T) {
		path, f := activationTestSocket(t)
		env := &activationTestEnv{vars: map[string]string{
			"LISTEN_PID":     self,
			"LISTEN_FDS":     "1",
			"LISTEN_FDNAMES": "mailbag.socket",
			"LISTEN_PIDFDID": "540869",
		}}
		var gotFDs []uintptr
		newFile := func(fd uintptr, _ string) *os.File {
			gotFDs = append(gotFDs, fd)
			return f
		}

		ln, err := activationListener(env.getenv, env.unsetenv, newFile)
		if err != nil {
			t.Fatalf("activationListener: %v", err)
		}
		if ln == nil {
			t.Fatal("activationListener = nil, want a *net.UnixListener")
		}
		t.Cleanup(func() { _ = ln.Close() })
		if !slices.Equal(gotFDs, []uintptr{3}) {
			t.Fatalf("newFile fds = %v, want [3]", gotFDs)
		}
		env.checkUnsetAll(t)
		if len(env.vars) != 0 {
			t.Fatalf("variables left after the call: %v", env.vars)
		}
		if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("fd 3 file after the call: Stat error = %v, want os.ErrClosed", err)
		}
		if got := ln.Addr().String(); got != path {
			t.Fatalf("listener address = %q, want %q", got, path)
		}

		// The listener accepts a connection to the socket path.
		if err := ln.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		dialed, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("dial %s: %v", path, err)
		}
		t.Cleanup(func() { _ = dialed.Close() })
		accepted, err := ln.AcceptUnix()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		t.Cleanup(func() { _ = accepted.Close() })
		if _, err := dialed.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := accepted.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1)
		if _, err := accepted.Read(buf); err != nil || buf[0] != 'x' {
			t.Fatalf("read on the accepted end = %q, %v; want \"x\"", buf, err)
		}

		// Close never unlinks the socket file, and the socket that
		// systemd keeps still takes a connection.
		if err := ln.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("socket file after close: %v; want it kept", err)
		}
		if fi.Mode().Type() != os.ModeSocket {
			t.Fatalf("socket file after close has mode %v, want a socket", fi.Mode())
		}
		again, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("dial after close: %v; want the socket of systemd to stay", err)
		}
		_ = again.Close()
	})

	// Not for this process: nil, no error, no fd opened, env unset.
	for _, tc := range []struct {
		name string
		vars map[string]string
	}{
		{"no variables", map[string]string{}},
		{"other pid", map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid() + 1), "LISTEN_FDS": "1"}},
		{"pid not a number", map[string]string{"LISTEN_PID": "x" + self, "LISTEN_FDS": "1"}},
		{"no LISTEN_FDS", map[string]string{"LISTEN_PID": self}},
		{"zero fds", map[string]string{"LISTEN_PID": self, "LISTEN_FDS": "0"}},
		{"fds not a number", map[string]string{"LISTEN_PID": self, "LISTEN_FDS": "one"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := &activationTestEnv{vars: tc.vars}
			newFile := func(fd uintptr, _ string) *os.File {
				t.Errorf("newFile(%d) called; want no fd opened", fd)
				return nil
			}
			ln, err := activationListener(env.getenv, env.unsetenv, newFile)
			if ln != nil || err != nil {
				t.Fatalf("activationListener = %v, %v; want nil, nil", ln, err)
			}
			env.checkUnsetAll(t)
			if len(env.vars) != 0 {
				t.Fatalf("variables left after the call: %v", env.vars)
			}
		})
	}

	t.Run("unset fails", func(t *testing.T) {
		env := &activationTestEnv{
			vars: map[string]string{"LISTEN_PID": self, "LISTEN_FDS": "1"},
			fail: "LISTEN_FDNAMES",
		}
		newFile := func(fd uintptr, _ string) *os.File {
			t.Errorf("newFile(%d) called after a failed unset", fd)
			return nil
		}
		ln, err := activationListener(env.getenv, env.unsetenv, newFile)
		if ln != nil || err == nil {
			t.Fatalf("activationListener = %v, %v; want nil and an error", ln, err)
		}
		env.checkUnsetAll(t)
	})

	t.Run("nil file", func(t *testing.T) {
		env := &activationTestEnv{vars: map[string]string{"LISTEN_PID": self, "LISTEN_FDS": "1"}}
		ln, err := activationListener(env.getenv, env.unsetenv, func(uintptr, string) *os.File { return nil })
		if ln != nil || err == nil {
			t.Fatalf("activationListener = %v, %v; want nil and an error", ln, err)
		}
	})

	t.Run("datagram socket", func(t *testing.T) {
		path := filepath.Join(activationTestDir(t), "d")
		dg, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = dg.Close() })
		f, err := dg.File()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		env := &activationTestEnv{vars: map[string]string{"LISTEN_PID": self, "LISTEN_FDS": "1"}}
		ln, err := activationListener(env.getenv, env.unsetenv, func(uintptr, string) *os.File { return f })
		if ln != nil || err == nil {
			t.Fatalf("activationListener on a datagram socket = %v, %v; want nil and an error", ln, err)
		}
		env.checkUnsetAll(t)
	})
}
