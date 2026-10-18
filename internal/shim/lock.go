// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build !windows

// The spawn lock of the shim (DS11.8 step 4): a flock on spawn.lock
// in the socket directory, so that two shims that start at the same
// time start one daemon (IS11.6). Windows has no flock;
// shim_windows.go holds the stub.

package shim

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// spawnLockName is the name of the lock file in Options.LockDir.
const spawnLockName = "spawn.lock"

// lockPoll is the period of the lock attempts while another shim
// holds the lock.
const lockPoll = 10 * time.Millisecond

// lockSpawn takes flock(LOCK_EX) on spawn.lock in dir, bounded by
// wait and by ctx. It makes dir with mode 0700 when dir is missing.
// The call to release releases the lock.
//
// The lock file stays in dir after release: a removed lock file lets
// two shims lock two different files. The file is opened with
// close-on-exec (the default of package os), so the daemon that Spawn
// starts under the lock does not get it.
//
// arch: DS11.8, DS11.19, IS11.6
func lockSpawn(ctx context.Context, dir string, wait time.Duration) (release func(), err error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("shim: lock dir %q is not an absolute path", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("shim: lock dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, spawnLockName), os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: an absolute lock dir from the shim options plus a fixed file name
	if err != nil {
		return nil, fmt.Errorf("shim: lock file: %w", err)
	}

	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("shim: lock %s: %w", f.Name(), err)
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("shim: lock %s: held by another process for %s", f.Name(), wait)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}
