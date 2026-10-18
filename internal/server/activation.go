// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Socket activation (DS11.10): the daemon takes the listener that
// systemd passed as fd 3. The code reads LISTEN_PID and LISTEN_FDS
// itself and has no dependency on go-systemd (DS11.16).

package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
)

// listenFDsStart is the first fd that systemd passes
// (SD_LISTEN_FDS_START in sd_listen_fds(3)).
const listenFDsStart = 3

// activationEnv holds the variables that sd_listen_fds(3) unsets so
// that a child does not inherit them.
var activationEnv = []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"}

// activationListener returns the listener that systemd passed as fd 3
// when LISTEN_PID equals this pid and LISTEN_FDS is at least 1, else
// nil. It unsets LISTEN_PID, LISTEN_FDS, LISTEN_FDNAMES and
// LISTEN_PIDFDID so that a child does not inherit them (sd_listen_fds(3)).
// The listener must be a *net.UnixListener; it is never unlinked.
//
// It unsets the four variables on each call, also when they are not for
// this process, as sd_listen_fds(3) does. A value that is not a number
// gives nil, the same as a value for another process. It does not check
// LISTEN_PIDFDID.
//
// The listener holds its own copy of fd 3, and fd 3 is closed. So when
// the daemon closes the listener, no fd of the daemon keeps the socket.
//
// It returns an error when an unset fails, when fd 3 is not a valid fd,
// or when fd 3 is not a Unix stream socket. Then the listener is nil.
//
// The arguments are the test seam; the daemon passes os.Getenv,
// os.Unsetenv and os.NewFile.
func activationListener(getenv func(string) string, unsetenv func(string) error, newFile func(uintptr, string) *os.File) (*net.UnixListener, error) {
	pid, pidErr := strconv.Atoi(getenv("LISTEN_PID"))
	n, fdsErr := strconv.Atoi(getenv("LISTEN_FDS"))
	var unsetErrs []error
	for _, name := range activationEnv {
		if err := unsetenv(name); err != nil {
			unsetErrs = append(unsetErrs, err)
		}
	}
	if err := errors.Join(unsetErrs...); err != nil {
		return nil, fmt.Errorf("server: socket activation: unset: %w", err)
	}
	if pidErr != nil || pid != os.Getpid() || fdsErr != nil || n < 1 {
		return nil, nil
	}
	f := newFile(listenFDsStart, "listen-fd-3")
	if f == nil {
		return nil, fmt.Errorf("server: socket activation: fd %d is not valid", listenFDsStart)
	}
	defer func() { _ = f.Close() }()
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("server: socket activation: %w", err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok || ln.Addr().Network() != "unix" {
		addr := ln.Addr()
		_ = ln.Close()
		return nil, fmt.Errorf("server: socket activation: fd %d is %s %s, not a Unix stream socket", listenFDsStart, addr.Network(), addr)
	}
	ul.SetUnlinkOnClose(false)
	return ul, nil
}
