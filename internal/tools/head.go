// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Head is the first field of every tool result: the nonce of the
// response, under the key "_fence". This file also carries the
// Fencer of the call from WrapReq to the handler in the context.
//
// arch: DU2.1, DU2.2, DU12.2

package tools

import (
	"context"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// Head holds the nonce of one response. Each Out struct embeds it as
// its first field, so encoding/json writes "_fence" as the first key
// of the result. go-sdk writes the keys in byte order, and "_" sorts
// before each lowercase letter, so "_fence" is also first there. A
// handler never writes it: [WrapReq] sets it after the handler
// returns.
//
// arch: DU2.1, DU12.2
type Head struct {
	// Fence is the nonce of this response: 16 lowercase hex
	// characters. Every marker in the result carries it.
	Fence string `json:"_fence" strict:"nonce"`
}

// setFence writes the nonce n into the head. Only [WrapReq] calls it.
//
// arch: DU2.1
func (h *Head) setFence(n string) { h.Fence = n }

// fencerKey is the context key of the Fencer that [WrapReq] makes
// for one call.
type fencerKey struct{}

// withFencer gives a copy of ctx that carries f. [WrapReq] calls it
// once for each call. A test that calls a handler direct gives it a
// test Fencer.
//
// arch: DU2.2
func withFencer(ctx context.Context, f guard.Fencer) context.Context {
	return context.WithValue(ctx, fencerKey{}, f)
}

// fencer gives the Fencer of the call. A handler calls it once, at
// its top, before it starts a goroutine. When ctx carries no Fencer,
// fencer gives the zero Fencer, and its Wrap panics (DU1.1).
//
// arch: DU2.2
func fencer(ctx context.Context) guard.Fencer {
	f, _ := ctx.Value(fencerKey{}).(guard.Fencer)
	return f
}
