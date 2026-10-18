// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package cli

import (
	"log/slog"

	"github.com/amsys/mailbag-mcp/internal/tools"
)

// toolsCmd runs "mailbag-mcp tools ...": "size" (D10.1) and
// "markdown" (DS10.6). The CLI uses subcommands, so the design text
// "--markdown" is replaced (DS10.13).
func toolsCmd(args []string, env Env) int {
	if len(args) == 0 {
		return usageErrf(env, "tools needs a subcommand: size or markdown")
	}
	switch args[0] {
	case "size":
		return toolsSize(env)
	case "markdown":
		return toolsMarkdown(env)
	default:
		return usageErrf(env, "unknown tools subcommand %q", args[0])
	}
}

// toolsSize runs "mailbag-mcp tools size" (D1.4). It prints one line
// for each toolset tools.Sizes reports, then one total line. The
// total line also carries the Instructions bytes, since that string
// counts toward the same tools/list context budget (§3.16, U7) but
// belongs to no one toolset.
func toolsSize(env Env) int {
	sizes, err := tools.Sizes(slog.New(slog.DiscardHandler))
	if err != nil {
		return failf(env, "tools size: %v", err)
	}

	var totalNames, totalList int
	for _, s := range sizes {
		printf(env, "%-10s names=%dB tools/list=%dB", s.Set, s.Names, s.ListBytes)
		totalNames += s.Names
		totalList += s.ListBytes
	}
	printf(env, "%-10s names=%dB tools/list=%dB instructions=%dB",
		"total", totalNames, totalList, len(tools.Instructions))
	return exitOK
}

// toolsMarkdown runs "mailbag-mcp tools markdown" (DS10.6). It prints
// the tool reference of [toolsReference], one line at a time, through
// printf only, so stdout stays in this package (IS10.9).
//
// arch: DS10.6, IS10.9
func toolsMarkdown(env Env) int {
	lines, err := toolsReference()
	if err != nil {
		return failf(env, "tools markdown: %v", err)
	}
	for _, l := range lines {
		printf(env, "%s", l)
	}
	return exitOK
}
