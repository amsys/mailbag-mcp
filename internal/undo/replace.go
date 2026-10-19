// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file holds the retry loop that replaceFile uses on Windows. The
// loop is in a file for all systems, so the tests run it on each
// system.

package undo

import (
	"os"
	"time"
)

// replaceBudget is the maximum total wait of retryRename. A reader
// holds a record open for one os.ReadFile only, so one or two retries
// are usually enough. The budget is much shorter than ClaimMaxAge, so
// the claim of the writer stays live while it waits.
const replaceBudget = 500 * time.Millisecond

// renameFunc and sleepFunc are the rename and the clock of
// retryRename. Only the tests change them, and those tests do not run
// at the same time as other tests.
var (
	renameFunc = os.Rename
	sleepFunc  = time.Sleep
)

// retryRename renames oldPath to newPath with renameFunc. When the
// error is one that retryable accepts, it waits and tries again. The
// first wait is 1 ms, and each next wait is two times longer. When the
// total wait gets to replaceBudget, retryRename gives the last error.
// An error that retryable does not accept goes back at once.
//
// cmd/go uses the same loop in its `internal/robustio` package.
func retryRename(oldPath, newPath string, retryable func(error) bool) error {
	delay := time.Millisecond
	var waited time.Duration
	for {
		err := renameFunc(oldPath, newPath)
		if err == nil || !retryable(err) || waited >= replaceBudget {
			return err
		}
		delay = min(delay, replaceBudget-waited)
		sleepFunc(delay)
		waited += delay
		delay *= 2
	}
}
