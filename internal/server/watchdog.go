// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"log/slog"
	"time"
)

// Watchdog cancels ctx once getppid reports a value different from
// the one it returned at the start (§3.1 step 4). A client killed
// with SIGKILL sends the server nothing at all; the changed parent id
// (the server gets reparented to init once its real parent is gone)
// is the only signal left (A4). getppid is injected so a test can
// fake a parent change with no real process exit.
//
// Run it as its own goroutine. It recovers on its own, so a bug here
// cannot take the whole process down (§3.1, A7), and the recovery
// writes an error log line with the panic and its stack instead of
// discarding it (DRV.19.7). It returns once ctx ends or it cancels
// ctx itself.
//
// arch: T1.4, §3.1, A4, A7, DRV.19.7
func Watchdog(ctx context.Context, cancel context.CancelFunc, getppid func() int, interval time.Duration, logger *slog.Logger) {
	defer recoverBackground(logger, "watchdog") // A7, DRV.19.7

	start := getppid()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if getppid() != start {
				cancel()
				return
			}
		}
	}
}
