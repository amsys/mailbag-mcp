// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// package tools_test, same package as schema_test.go, so this file
// can call listCoreTools directly: TestSizes_MatchesBudgetTest proves
// tools.Sizes and the budget tests measure the "core" toolset through
// the exact same helper (see the test doc comment). The external test
// package also lets TestToolsSizeCommand_UsesSizes import internal/cli:
// internal/cli imports package tools (not tools_test), so this stays
// free of an import cycle.
package tools_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"regexp"
	"strconv"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/cli"
	"github.com/amsys/mailbag-mcp/internal/tools"
)

// TestSizes_MatchesBudgetTest proves that "mailbag-mcp tools size"
// (backed by tools.Sizes) and the tools/list budget tests
// (TestToolsList_Budget) measure the "core" toolset through the same
// wire path: tools.ListTools, which schema_test.go's listCoreTools
// calls. If a later change moved Sizes onto a different or
// hand-built tool list, this test would show the drift as unequal
// byte counts (I3).
//
// arch: D1.4, D10.1
func TestSizes_MatchesBudgetTest(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	sizes, err := tools.Sizes(logger)
	if err != nil {
		t.Fatalf("Sizes: %v", err)
	}

	var (
		core  tools.SetSize
		found bool
	)
	for _, s := range sizes {
		if s.Set == "core" {
			core, found = s, true
			break
		}
	}
	if !found {
		t.Fatal(`Sizes returned no "core" row`)
	}

	res := listCoreTools(t)
	want, err := json.Marshal(res.Tools)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if core.ListBytes != len(want) {
		t.Errorf("Sizes core ListBytes = %d, budget test's listCoreTools measures %d bytes (I3: Sizes has drifted from the budget tests)",
			core.ListBytes, len(want))
	}
	if core.Names <= 0 {
		t.Errorf("Sizes core Names = %d, want > 0", core.Names)
	}
}

// coreListBytesRE matches toolsSize's printed "core" row, for
// example "core       names=123B tools/list=4637B", and captures the
// tools/list byte count.
var coreListBytesRE = regexp.MustCompile(`core\s+names=\d+B tools/list=(\d+)B`)

// TestToolsSizeCommand_UsesSizes proves that "mailbag-mcp tools size"
// (D10.1: cli.Run's "tools" case, routed to toolsCmd and toolsSize in
// internal/cli/tools.go) prints the same "core" tools/list byte count
// that tools.Sizes returns. Unlike TestSizes_MatchesBudgetTest, which
// only calls tools.Sizes and listCoreTools, this test runs the actual
// command line, so deleting the "tools" case from cli.Run would show up
// here as a usage-error exit code instead of a passing test (I3, D10.1).
//
// arch: D1.4, D10.1
func TestToolsSizeCommand_UsesSizes(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	sizes, err := tools.Sizes(logger)
	if err != nil {
		t.Fatalf("Sizes: %v", err)
	}
	var (
		want  int
		found bool
	)
	for _, s := range sizes {
		if s.Set == "core" {
			want, found = s.ListBytes, true
			break
		}
	}
	if !found {
		t.Fatal(`Sizes returned no "core" row`)
	}

	var out, errOut bytes.Buffer
	code := cli.Run([]string{"tools", "size"}, cli.Env{Stdout: &out, Stderr: &errOut})
	if code != 0 {
		t.Fatalf(`cli.Run(["tools","size"]) exit = %d, stderr = %q`, code, errOut.String())
	}

	m := coreListBytesRE.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no core row with tools/list=<N>B in command output: %q", out.String())
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse tools/list byte count %q: %v", m[1], err)
	}

	if got != want {
		t.Errorf("cli.Run(tools size) core tools/list = %dB, Sizes core ListBytes = %dB (I3: the command has drifted from Sizes)",
			got, want)
	}
}
