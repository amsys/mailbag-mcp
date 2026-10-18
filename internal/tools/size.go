// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SetSize is one row of "mailbag-mcp tools size" (D1.4): a toolset's
// name, the bytes of the JSON array of its tool names, and the bytes
// of its tools/list JSON after D1.2 strips outputSchema.
//
// arch: D1.4, D10.1
type SetSize struct {
	Set       string
	Names     int
	ListBytes int
}

// Sizes measures each toolset the same way the tools/list budget
// tests do: both call [ListTools], so both see a real in-memory MCP
// server with RegisterCore and RegisterToolsets, a real client's
// ListTools call, then json.Marshal on the result.
//
// Sizes lists one server with every toolset of [Toolsets] on, then
// splits the result: one "core" row for the tools no toolset owns, and
// one row for each toolset, in [Toolsets] order. So each row counts a
// tool one time, and the sum of the rows is near the bytes of the
// whole list.
//
// The "mailbag-mcp tools size" command (D10.1) and
// TestSizes_MatchesBudgetTest both call Sizes, so the row printed on
// a terminal and the number a budget test enforces cannot drift apart
// (I3).
//
// arch: D1.4, D10.1, D2.1, D2.2
func Sizes(logger *slog.Logger) ([]SetSize, error) {
	sets := Toolsets()
	all := make([]string, len(sets))
	owner := map[string]string{}
	for i, g := range sets {
		all[i] = g.Name
		for _, name := range g.Tools {
			owner[name] = g.Name
		}
	}

	res, err := ListTools(logger, all...)
	if err != nil {
		return nil, err
	}

	bySet := map[string][]*mcp.Tool{}
	for _, t := range res.Tools {
		set := owner[t.Name]
		if set == "" {
			set = "core"
		}
		bySet[set] = append(bySet[set], t)
	}

	order := append([]string{"core"}, all...)
	out := make([]SetSize, 0, len(order))
	for _, set := range order {
		row, err := setSize(set, bySet[set])
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

// setSize measures the two D1.4 numbers of one toolset's tools. A
// toolset with no tool on the list gives the bytes of an empty array.
func setSize(set string, list []*mcp.Tool) (SetSize, error) {
	if list == nil {
		list = []*mcp.Tool{}
	}
	names := make([]string, len(list))
	for i, t := range list {
		names[i] = t.Name
	}
	nb, err := json.Marshal(names)
	if err != nil {
		return SetSize{}, fmt.Errorf("tools size: marshal %s names: %w", set, err)
	}
	lb, err := json.Marshal(list)
	if err != nil {
		return SetSize{}, fmt.Errorf("tools size: marshal %s tools: %w", set, err)
	}
	return SetSize{Set: set, Names: len(nb), ListBytes: len(lb)}, nil
}

// ListTools builds one *mcp.Server with RegisterCore and
// RegisterToolsets(toolsets), connects an in-memory client, and gives
// back the tools/list result that client sees. [Sizes] and the test
// helper listTools in schema_test.go both call it, so the size command
// and the budget tests measure the same server (D2.4, D9.2). It closes
// the server, the client and the Factory before it returns.
//
// It cannot call internal/server's server-building code: internal/server
// imports this package, and internal/server has its own tools/list
// tests for that path.
//
// arch: D1.4, D2.2, D2.4
func ListTools(logger *slog.Logger, toolsets ...string) (*mcp.ListToolsResult, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "mailbag-mcp", Version: "size"},
		&mcp.ServerOptions{Logger: logger, Instructions: Instructions})
	f := RegisterCore(srv, logger)
	defer f.Close()
	if _, err := RegisterToolsets(srv, logger, f, toolsets); err != nil {
		return nil, fmt.Errorf("tools size: %w", err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "mailbag-mcp-tools-size", Version: "size"}, nil)
	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()

	ss, err := srv.Connect(ctx, t1, nil)
	if err != nil {
		return nil, fmt.Errorf("tools size: connect server: %w", err)
	}
	defer func() { _ = ss.Close() }()

	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		return nil, fmt.Errorf("tools size: connect client: %w", err)
	}
	defer func() { _ = cs.Close() }()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("tools size: list tools: %w", err)
	}
	return res, nil
}
