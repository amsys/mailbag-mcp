// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build !windows

// The start of the daemon by the shim (DS11.8 step 4). Windows has no
// Setsid; shim_windows.go holds the stub of Spawn.

package shim

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// spawn starts "<self> serve" with Setsid, no stdio (os/exec gives the
// null device, R§5) and the inherited environment, then releases the
// child. The daemon logs to server.log on its own. Setsid puts the
// daemon in a session of its own, so a signal to the process group
// of the client does not reach it. spawn starts no process when ctx
// already ended; ctx does not stop the daemon after the start.
//
// arch: DS11.8, DS11.18
func spawn(ctx context.Context, self string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(self, "serve")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("shim: start %s serve: %w", self, err)
	}
	return cmd.Process.Release()
}

// Spawn is spawn for main.go, which gives it to Run as Options.Spawn
// with self = os.Executable() (DS11.13, G4 in DS11.20).
//
// arch: DS11.8, DS11.13, DS11.20
func Spawn(ctx context.Context, self string) error {
	return spawn(ctx, self)
}
