// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// sizeBudgetBytes is the ceiling for the stripped release binary. See
// docs/features/mailbag/size-baseline.md for the measured history and
// the decision record needed to raise this number.
//
// Raised from 13,000,000 to 13,500,000 (owner decision, 2026-09-27,
// DS6.1 correction): the OAuth token client makes net/http's HTTP/2
// client reachable, and binary size does not change run-time speed, so
// the owner puts run-time speed first over a smaller binary.
//
// Raised from 13,500,000 to 14,000,000 (owner decision, 2026-09-27, S6
// T42): the loopback sign-in and browser code bring the binary to
// 13,701,280 bytes; the owner puts run-time speed first and left room
// for S7 and S8.
//
// Raised from 14,000,000 to 15,000,000 (G7, T200,
// owner decision 2026-10-09 at the run gate): S7 to S11 add code, and
// windows/amd64 had only 85,888 bytes of room under the old budget.
// The new budget holds for the whole run.
const sizeBudgetBytes = 15_000_000

// TestBinarySize_Budget builds the release binary the same way a
// release build does, and checks it stays under the size budget. The
// owner wants one lightweight binary with all features, so a size
// creep must be a decision, not an accident.
//
// It builds a fresh binary into a temp dir instead of reading a
// binary left over from a prior build, so the check always measures
// the current source tree.
//
// arch: IR1G.13
func TestBinarySize_Budget(t *testing.T) {
	if testing.Short() {
		t.Skip("skip binary size build in -short mode")
	}

	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	out := filepath.Join(t.TempDir(), "mailbag-mcp")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", out, ".") //nolint:gosec // G204: the test builds this module with fixed arguments
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if buildOut, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stripped binary: %v\n%s", err, buildOut)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat built binary: %v", err)
	}
	size := info.Size()

	fmt.Printf("binary size: %d bytes (budget %d bytes)\n", size, sizeBudgetBytes)

	if size > sizeBudgetBytes {
		t.Fatalf("stripped binary is %d bytes, over the %d byte budget; "+
			"see docs/features/mailbag/size-baseline.md — raising the "+
			"budget needs a decision record there", size, sizeBudgetBytes)
	}
}
