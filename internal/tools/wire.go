// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Receiving middleware of the MCP server: the tools/list reply loses
// outputSchema (D1.2), and a tools/call error that the SDK makes
// before WrapReq runs gets the error form of DU6.1 (DU6.3).
//
// arch: D1.2, DU6.1, DU6.3
package tools

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// stripOutputSchema removes outputSchema from a tools/list result.
// It copies each Tool first. listTools returns the stored pointers,
// so a middleware that edited a Tool in place would change the tool
// the server keeps, not just the reply on the wire.
//
// outputSchema is 40.8% of the tools/list payload (D1.1), and the
// SDK's top-level AddTool always fills it in from a handler's typed
// Out, with no field to opt out of at registration time (I2: a
// handler keeps its typed Out, so [mcp.AddTool] still validates each
// result's structuredContent against that schema; only the copy
// that reaches tools/list drops the field).
//
// arch: D1.2
func stripOutputSchema(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil || method != "tools/list" {
			return res, err
		}
		lr, ok := res.(*mcp.ListToolsResult)
		if !ok {
			return res, err
		}
		stripped := make([]*mcp.Tool, len(lr.Tools))
		for i, t := range lr.Tools {
			cp := *t
			cp.OutputSchema = nil
			stripped[i] = &cp
		}
		lr.Tools = stripped
		return lr, nil
	}
}

// callMarkKey is the context key of the [callMark] of one tools/call.
type callMarkKey struct{}

// callMark records that a tools/call reached [WrapReq]. markCalls
// puts one in the context, and WrapReq sets handled.
//
// arch: DU6.3
type callMark struct {
	handled atomic.Bool
}

// markHandled sets the mark of the call in ctx, when there is one.
// [WrapReq] calls it first, before any other work.
//
// arch: DU6.3
func markHandled(ctx context.Context) {
	if m, ok := ctx.Value(callMarkKey{}).(*callMark); ok {
		m.handled.Store(true)
	}
}

// markCalls gives each tools/call a [callMark]. The SDK checks the
// arguments of a call before the handler runs, and on a bad argument
// it makes an isError result with its own text (go-sdk mcp/server.go,
// the "validating arguments" and unmarshal paths). That text can hold
// model input. When the result is an error and WrapReq did not run,
// markCalls replaces the content with the error form of DU6.1: a new
// nonce, the class invalid_input, and the old text in a fence.
//
// arch: DU6.1, DU6.3, INV-2
func markCalls(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method != "tools/call" {
			return next(ctx, method, req)
		}
		mark := &callMark{}
		res, err := next(context.WithValue(ctx, callMarkKey{}, mark), method, req)
		if err != nil || mark.handled.Load() {
			return res, err
		}
		cr, ok := res.(*mcp.CallToolResult)
		if !ok || cr == nil || !cr.IsError {
			return res, err
		}
		cr.Content = []mcp.Content{&mcp.TextContent{Text: sdkErrText(cr)}}
		return cr, nil
	}
}

// sdkErrText gives the error form of DU6.1 for an isError result that
// the SDK made. The text of each text block of res becomes the detail.
// When no nonce can be made, it gives [noNonceText] (DU2.2).
//
// arch: DU6.1, DU6.3
func sdkErrText(res *mcp.CallToolResult) string {
	f, err := newFencer()
	if err != nil {
		return noNonceText
	}
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return errForm(f, "invalid_input", "", strings.Join(parts, "\n"))
}
