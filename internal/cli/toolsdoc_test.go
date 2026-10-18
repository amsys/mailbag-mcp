// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of "tools markdown" and of the reference text in fieldText
// (DS10.6).

package cli

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/tools"
)

// TestToolsDoc_EveryFieldHasText proves that fieldText and the live
// tools/list schema hold the same fields: a field with no text fails,
// an entry with no field fails, and an empty text fails.
//
// arch: DS10.1, DS10.6, DS10.13, IS10.9
func TestToolsDoc_EveryFieldHasText(t *testing.T) {
	sandbox(t)
	list, err := referenceTools()
	if err != nil {
		t.Fatalf("referenceTools: %v", err)
	}
	fields := map[string]bool{}
	for _, rt := range list {
		s, err := inputSchema(rt.tool)
		if err != nil {
			t.Fatal(err)
		}
		for name := range s.Properties {
			key := rt.tool.Name + "." + name
			fields[key] = true
			if _, ok := fieldText[key]; !ok {
				t.Errorf("field %s has no entry in fieldText", key)
			}
		}
	}
	for key, text := range fieldText {
		if !fields[key] {
			t.Errorf("fieldText entry %s names no field of tools/list", key)
		}
		if strings.TrimSpace(text) == "" {
			t.Errorf("fieldText entry %s is empty", key)
		}
	}
}

// TestToolsMarkdown_Deterministic proves the order of the reference:
// "### core" first, then one "###" per toolset in Toolsets() order,
// the core tools in name order and each toolset's tools in its
// ExtraGroup.Tools order, and in each table the required fields first,
// each part in name order. Two runs give the same bytes, and nothing
// goes to stderr.
//
// arch: DS10.1, DS10.6, DS10.13, IS10.9
func TestToolsMarkdown_Deterministic(t *testing.T) {
	sandbox(t)
	run := func() string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := Run([]string{"tools", "markdown"}, Env{Stdout: &out, Stderr: &errOut}); code != exitOK {
			t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
		}
		if errOut.Len() != 0 {
			t.Errorf("stderr is not empty:\n%s", errOut.String())
		}
		return out.String()
	}
	first, second := run(), run()
	if first != second {
		t.Fatalf("two runs differ:\n--- first\n%s\n--- second\n%s", first, second)
	}

	lines := strings.Split(strings.TrimSuffix(first, "\n"), "\n")
	if lines[0] != "### core" {
		t.Fatalf("first line = %q, want \"### core\"", lines[0])
	}

	sets := tools.Toolsets()
	wantSets := []string{"core"}
	owned := map[string]bool{}
	for _, g := range sets {
		wantSets = append(wantSets, g.Name)
		for _, name := range g.Tools {
			owned[name] = true
		}
	}

	var gotSets []string
	toolsBySet := map[string][]string{}
	set, tool := "", ""
	var rows [][]string
	checkRows := func() {
		if tool == "" {
			return
		}
		var names []string
		seenOptional := false
		for _, r := range rows {
			names = append(names, r[0])
			switch r[2] {
			case "yes":
				if seenOptional {
					t.Errorf("tool %s: required field %s comes after an optional field", tool, r[0])
				}
			case "no":
				seenOptional = true
			default:
				t.Errorf("tool %s: field %s: required = %q, want yes or no", tool, r[0], r[2])
			}
			if r[3] == "" {
				t.Errorf("tool %s: field %s has no meaning text", tool, r[0])
			}
		}
		var req, opt []string
		for _, r := range rows {
			if r[2] == "yes" {
				req = append(req, r[0])
			} else {
				opt = append(opt, r[0])
			}
		}
		if !sort.StringsAreSorted(req) || !sort.StringsAreSorted(opt) {
			t.Errorf("tool %s: fields are not in name order inside each part: %v", tool, names)
		}
	}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "### "):
			checkRows()
			set, tool, rows = strings.TrimPrefix(l, "### "), "", nil
			gotSets = append(gotSets, set)
		case strings.HasPrefix(l, "#### "):
			checkRows()
			tool, rows = strings.TrimPrefix(l, "#### "), nil
			toolsBySet[set] = append(toolsBySet[set], tool)
		case strings.HasPrefix(l, "| `"):
			cells := strings.Split(strings.Trim(l, "|"), " | ")
			if len(cells) != 4 {
				t.Fatalf("table row %q has %d cells, want 4", l, len(cells))
			}
			for i := range cells {
				cells[i] = strings.TrimSpace(cells[i])
			}
			cells[0] = strings.Trim(cells[0], "`")
			rows = append(rows, cells)
		}
	}
	checkRows()

	if strings.Join(gotSets, ",") != strings.Join(wantSets, ",") {
		t.Errorf("toolset headings = %v, want %v", gotSets, wantSets)
	}
	core := toolsBySet["core"]
	if len(core) == 0 || !sort.StringsAreSorted(core) {
		t.Errorf("core tools = %v, want a non-empty list in name order", core)
	}
	for _, name := range core {
		if owned[name] {
			t.Errorf("core lists %s, which a toolset owns", name)
		}
	}
	for _, g := range sets {
		if strings.Join(toolsBySet[g.Name], ",") != strings.Join(g.Tools, ",") {
			t.Errorf("toolset %s tools = %v, want %v", g.Name, toolsBySet[g.Name], g.Tools)
		}
	}
}
