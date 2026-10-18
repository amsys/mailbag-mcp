// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// MaxAttachBytes is the largest file AttachPath accepts (§3.14, M11:
// "25 MB for a file and for a message"). AttachPath checks this
// against the size Stat reports at call time; the file can grow after
// that, so the caller must cap its own read of the file at
// MaxAttachBytes too, not trust that AttachPath already bounded it.
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
const MaxAttachBytes = 25 * 1024 * 1024

// blockedSystemDirs lists the trees AttachPath refuses outright, even
// when a path inside them is a regular file under the size cap.
// /proc lets a prompt injection reach another process's environment
// or memory by pid (§3.15, G7); /sys and /dev expose kernel and
// device state no attachment should ever carry.
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
var blockedSystemDirs = []string{"/proc", "/sys", "/dev"}

// underSystemDir reports whether resolved is one of blockedSystemDirs
// or sits inside one of them.
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
func underSystemDir(resolved string) bool {
	for _, d := range blockedSystemDirs {
		if resolved == d || strings.HasPrefix(resolved, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// underOwnDir reports whether resolved is in the config dir or the
// state dir of mailbag-mcp ([config.ConfigDir], [config.StateDir]).
// These dirs hold accounts.toml, the secrets file of
// `secrets = "file"`, the log and the undo journal. Their path can
// have no dot component (on macOS the config dir is
// "~/Library/Application Support/mailbag-mcp"), so the rule for hidden
// components does not always refuse them. underRoot canonicalizes
// each dir, so a symbolic link cannot go around this check. A dir
// that cannot be found gives an error, and AttachPath then refuses
// the path.
//
// arch: T2.4, §3.15, G7, R16-M2
func underOwnDir(resolved string) (bool, error) {
	cfg, err := config.ConfigDir()
	if err != nil {
		return false, err
	}
	state, err := config.StateDir()
	if err != nil {
		return false, err
	}
	return underRoot(resolved, []string{cfg, state}), nil
}

// AttachPath resolves path for an outgoing attachment and refuses it
// under the rules of §3.15 "Attach path (outgoing)": empty, a NUL
// byte, missing, under /proc, /sys or /dev, under the config or state
// dir of mailbag-mcp (R16-M2), not a regular file, over
// MaxAttachBytes, a hidden path component (the way a prompt injection
// reaches "~/.ssh/id_ed25519", G7), or, when allowDirs is not empty,
// outside every directory in it. It returns the canonical path and
// its size; the caller uses filepath.Base of the returned path as the
// file name in the message, never the caller-supplied text. The
// caller must also cap its own read of the file at MaxAttachBytes:
// this check only sees the size at Stat time, and the file can grow
// after that.
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
func AttachPath(path string, allowDirs []string) (string, int64, error) {
	if path == "" {
		return "", 0, errors.New("guard: attach path: empty")
	}
	if strings.ContainsRune(path, 0) {
		return "", 0, errors.New("guard: attach path: contains a NUL byte")
	}
	path, err := expandHome(path)
	if err != nil {
		return "", 0, fmt.Errorf("guard: attach path: %w", err)
	}
	resolved, err := canonicalize(path)
	if err != nil {
		return "", 0, fmt.Errorf("guard: attach path: %w", err)
	}
	if underSystemDir(resolved) {
		return "", 0, errors.New("guard: attach path: refuses a path under /proc, /sys or /dev")
	}
	own, err := underOwnDir(resolved)
	if err != nil {
		return "", 0, fmt.Errorf("guard: attach path: %w", err)
	}
	if own {
		return "", 0, errors.New("guard: attach path: refuses a path under the config or state dir of mailbag-mcp")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", 0, fmt.Errorf("guard: attach path: does not exist")
		}
		return "", 0, fmt.Errorf("guard: attach path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", 0, errors.New("guard: attach path: not a regular file")
	}
	if info.Size() > MaxAttachBytes {
		return "", 0, fmt.Errorf("guard: attach path: %d bytes exceeds the 25 MB cap", info.Size())
	}
	if hasHiddenComponent(resolved) {
		return "", 0, errors.New("guard: attach path: a hidden path component is refused")
	}
	if len(allowDirs) > 0 && !underRoot(resolved, allowDirs) {
		return "", 0, errors.New("guard: attach path: outside every attach_dirs entry")
	}
	return resolved, info.Size(), nil
}

// hasHiddenComponent reports whether any component of the canonical
// path starts with a dot ("~/.ssh", "~/.gnupg", "~/.config"), the
// path a prompt injection uses to reach a private key (§3.15, G7).
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
func hasHiddenComponent(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part != "" && strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

// expandHome replaces a leading "~" or "~/..." with the user's home
// directory. A path that does not start with "~" is returned as is.
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}
