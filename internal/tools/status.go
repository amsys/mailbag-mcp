// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools gives, in status.go, the one function that turns a
// [config.Config] into the lines a human reads about which toolsets
// and which decrypt state are on, so serve and doctor print the same
// words (03-design-R1G.md DR1G.10).
package tools

import (
	"strings"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// ToolsetNames gives the names of [Toolsets], the off-by-default
// groups that have code today (D2.1, D2.2). It moved here from
// server.toolsetNames so [StatusLines] and a later doctor command
// (T90) can read the same list without server importing anything
// doctor needs or doctor importing server.
func ToolsetNames() []string {
	groups := Toolsets()
	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = g.Name
	}
	return names
}

// StatusLines gives the lines that tell a human which toolsets are on
// and the decrypt state. serve writes both at start; doctor writes
// both as checks 3 and 5 (T90). Both read the words from this one
// function, which is what makes IR1G.10 ("serve and doctor print
// status lines from one function") hold. After start, serve calls
// this again only to re-check decrypt, at each runtime change
// (03-design-R1G.md T135, DR1G.10's "Runtime change" note); the
// toolsets line is never rewritten after start, for the reason the
// next paragraph gives.
//
// toolsets is empty when every name [ToolsetNames] gives is already
// on; otherwise it holds one line naming the off ones (D2.1's
// migration check, [config.Config.OffToolsets]). A caller that wants
// a person to see this also writes it to stderr: it always applies
// (there was no prior state to compare against, unlike decrypt, so
// nothing here needs the dedup T135 gives decrypt).
//
// decrypt always holds one line: a line that starts "decrypt-on: "
// followed by [DecryptWarning] when every key
// [config.Config.DecryptMissing] checks is set, or a line that starts
// "decrypt-off: " naming the missing keys otherwise. A caller decides
// from that prefix whether the line also belongs on stderr and at
// which log level, exactly as the pre-DR1G.10 logDecryptState did.
//
// arch: DR1G.10, IR1G.10
func StatusLines(cfg *config.Config) (toolsets, decrypt []string) {
	if off := cfg.OffToolsets(ToolsetNames()); len(off) > 0 {
		toolsets = []string{"toolsets off: " + strings.Join(off, ", ")}
	}
	if missing := cfg.DecryptMissing(); len(missing) > 0 {
		decrypt = []string{"decrypt-off: missing " + strings.Join(missing, ", ")}
	} else {
		decrypt = []string{"decrypt-on: " + DecryptWarning}
	}
	return toolsets, decrypt
}
