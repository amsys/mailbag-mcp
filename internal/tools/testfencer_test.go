// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Test helper that gives a Fencer with a fixed nonce, for tests that
// call a handler direct, without WrapReq.
//
// arch: DU2.2
package tools

import (
	"bytes"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// testNonce is the nonce of every Fencer that testFencer gives.
const testNonce = "3fa9c2e17b604d55"

// testFencer gives a Fencer with the fixed nonce testNonce. A test that
// calls a handler direct puts it in the context with
// withFencer(ctx, testFencer(t)).
//
// arch: DU2.2
func testFencer(t *testing.T) guard.Fencer {
	t.Helper()
	f, err := guard.NewFencerFrom(bytes.NewReader([]byte{0x3f, 0xa9, 0xc2, 0xe1, 0x7b, 0x60, 0x4d, 0x55}))
	if err != nil {
		t.Fatalf("test Fencer: %v", err)
	}
	if f.Nonce() != testNonce {
		t.Fatalf("test Fencer nonce = %q, want %q", f.Nonce(), testNonce)
	}
	return f
}
