// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build windows

// Windows has no daemon (G8): Run calls Fallback at once. Windows has
// no flock and no Setsid, so the spawn lock and Spawn are stubs here
// that give errNoDaemon (G5 in DS11.20). main.go names Spawn on every
// OS, so the stub of Spawn exists; no Windows code starts a daemon.

package shim

import (
	"context"
	"errors"
	"time"
)

// errNoDaemon is the error of the stub. It gives the text of G8.
var errNoDaemon = errors.New("shim: no daemon on Windows; the MCP entry runs the in-process server")

// lockSpawn is the stub of lock.go. It gives errNoDaemon.
//
// arch: DS11.20
func lockSpawn(context.Context, string, time.Duration) (func(), error) {
	return nil, errNoDaemon
}

// Spawn is the stub of spawn.go. It starts no process and gives
// errNoDaemon.
//
// arch: DS11.13, DS11.20
func Spawn(context.Context, string) error {
	return errNoDaemon
}
