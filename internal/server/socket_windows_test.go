// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build windows

// Test of "mailbag-mcp serve" on Windows (G8): there is no daemon, and
// the text tells the person that the MCP entry runs in process.

package server

import "testing"

// TestServeSocket_WindowsText checks the text of G8 and the exit code
// of ServeSocket on Windows. CI runs it on windows-latest; on Linux,
// GOOS=windows go vet compiles it.
//
// arch: DS11.4, DS11.15, DS11.20
func TestServeSocket_WindowsText(t *testing.T) {
	const want = "serve is not available on Windows; the MCP entry runs the in-process server"
	if serveWindowsText != want {
		t.Errorf("serveWindowsText = %q, want %q", serveWindowsText, want)
	}
	if code := ServeSocket("test"); code != 2 {
		t.Errorf("ServeSocket = %d, want 2", code)
	}
}
