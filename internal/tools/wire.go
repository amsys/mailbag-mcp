// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"

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
