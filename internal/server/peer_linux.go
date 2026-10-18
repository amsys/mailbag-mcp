// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The peer uid of a Unix socket on Linux (DS11.12). The daemon reads it
// for each connection before it reads a byte (IS11.3).

package server

import (
	"fmt"
	"net"
	"syscall"
)

// peerUID gives the uid of the process at the other end of a Unix
// socket (SO_PEERCRED through syscall.GetsockoptUcred on the raw fd).
// The kernel records the credentials when the connection is made. On
// an error the uid is 0 and the caller must refuse the connection.
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("server: peer uid: %w", err)
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("server: peer uid: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("server: peer uid: %w", credErr)
	}
	return cred.Uid, nil
}
