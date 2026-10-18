// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build linux || darwin

// Test that a signature file which is a FIFO with no writer is refused
// at once and never blocks the load (DI1.7).

package config

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestIdentity_SignatureFileFIFO checks that Load refuses a FIFO in
// signature_file and returns. A plain open of a FIFO with no writer
// blocks for ever, so the load opens with O_NONBLOCK.
//
// arch: DI1.7
func TestIdentity_SignatureFileFIFO(t *testing.T) {
	dir, path := sigDirFixture(t, "signature_file = \"sig.txt\"\n")
	if err := syscall.Mkfifo(filepath.Join(dir, "sig.txt"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Load(path)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("Load with a FIFO: err = %v, want ErrInvalidIdentity", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load with a FIFO did not return within 5 s")
	}
}
