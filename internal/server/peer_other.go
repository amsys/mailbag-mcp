// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

// The peer uid on a platform with no peer credential call that the
// daemon knows, other than Windows (DS11.12). On Windows the daemon
// does not start (owner decision 2026-10-09 at the run gate, G8), and
// no Windows code calls peerUID. On another platform the daemon
// refuses each connection, and the shim runs the server in process.

package server

import (
	"errors"
	"net"
)

// errPeerUnsupported is the error of peerUID on a platform where the
// daemon cannot read the uid of a socket peer.
var errPeerUnsupported = errors.New("server: peer uid: not supported on this platform")

// peerUID always fails here, so that the caller refuses each
// connection and never trusts an unknown peer.
func peerUID(_ *net.UnixConn) (uint32, error) {
	return 0, errPeerUnsupported
}
