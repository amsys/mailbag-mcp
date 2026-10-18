// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir returns the directory that holds accounts.toml and the file
// secrets fallback. MAILBAG_CONFIG_DIR replaces it, for tests.
//
// arch: T1.2, §3.3
func ConfigDir() (string, error) { //nolint:revive // exported: other packages call config.ConfigDir; the rename belongs in a separate change
	if d := os.Getenv("MAILBAG_CONFIG_DIR"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "mailbag-mcp"), nil
}

// StateDir returns the directory that holds the log and the undo
// journal. MAILBAG_STATE_DIR replaces it, for tests.
//
// On Linux, the base comes from XDG_STATE_HOME (default
// ~/.local/state), matching the base desktop specification. macOS and
// Windows have no such directory, so the state dir sits under the
// config dir instead (§3.3).
//
// arch: T1.2, §3.3
func StateDir() (string, error) {
	if d := os.Getenv("MAILBAG_STATE_DIR"); d != "" {
		return d, nil
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		cfg, err := ConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(cfg, "state"), nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "mailbag-mcp"), nil
}

// AccountsPath returns the path to accounts.toml inside ConfigDir.
//
// arch: T1.2, §3.3
func AccountsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "accounts.toml"), nil
}
