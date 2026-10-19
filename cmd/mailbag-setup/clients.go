// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file holds the writers of the MCP client configs: Claude
// Desktop (a JSON file) and Claude Code (the claude CLI). The file of
// another program is not mailbag state, so each write makes a backup
// first, writes a temp file, and renames it. A file that is not valid
// JSON is never written. The tool never stops the Claude app.
//
// arch: DS13.3, DS13.8, IS13.4, IS13.5
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// serverName is the key of mailbag in a client config.
const serverName = "mailbag"

// backupTimeFormat is the UTC time in the name of a backup file.
const backupTimeFormat = "20060102T150405Z"

// errAppRunning is the refusal to write while the Claude app runs.
var errAppRunning = errors.New("the Claude app runs; quit it, then apply again")

// field is one key and its raw JSON value. A slice of fields keeps the
// key order of the file.
type field struct {
	key string
	val json.RawMessage
}

// desktopConfigPath gives the Claude Desktop config path under home
// for the operating system goos. It gives "" when no path is known.
func desktopConfigPath(home, goos string) string {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "linux":
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	}
	return ""
}

// parseObject reads data as one JSON object and returns its fields in
// file order. Anything else, and any text after the object, is an error.
func parseObject(data []byte) ([]field, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	fields := []field{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("not valid JSON: %w", err)
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("not valid JSON: %w", err)
		}
		fields = append(fields, field{key, raw})
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("not valid JSON: text after the object")
	}
	return fields, nil
}

// encodeObject writes fields as an indented JSON object, in order.
func encodeObject(fields []field) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(f.key)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(f.val)
	}
	b.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, b.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// setField replaces the value of key, or appends the key at the end.
func setField(fields []field, key string, val json.RawMessage) []field {
	for i := range fields {
		if fields[i].key == key {
			fields[i].val = val
			return fields
		}
	}
	return append(fields, field{key, val})
}

// mergeDesktop returns the config text with mcpServers.mailbag set to
// the binary at binPath. data is the current file, or nil when there
// is no file. Other keys keep their order. Invalid JSON is an error.
func mergeDesktop(data []byte, binPath string) ([]byte, error) {
	top := []field{}
	if data != nil {
		var err error
		if top, err = parseObject(data); err != nil {
			return nil, err
		}
	}
	servers := []field{}
	for _, f := range top {
		if f.key != "mcpServers" {
			continue
		}
		if string(bytes.TrimSpace(f.val)) == "null" {
			break
		}
		var err error
		if servers, err = parseObject(f.val); err != nil {
			return nil, fmt.Errorf("mcpServers: %w", err)
		}
		break
	}
	entry, err := json.Marshal(map[string]string{"command": binPath})
	if err != nil {
		return nil, err
	}
	servers = setField(servers, serverName, entry)
	sv, err := encodeObject(servers)
	if err != nil {
		return nil, err
	}
	top = setField(top, "mcpServers", bytes.TrimSpace(sv))
	return encodeObject(top)
}

// desktopPlan is the before-and-after view of a Claude Desktop change.
type desktopPlan struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// planDesktop reads the file at path and returns the change that
// applyDesktop would make. It writes nothing.
func planDesktop(path, binPath string) (desktopPlan, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the Claude Desktop config path from desktopConfigPath, not request input
	if errors.Is(err, fs.ErrNotExist) {
		data = nil
	} else if err != nil {
		return desktopPlan{}, err
	}
	after, err := mergeDesktop(data, binPath)
	if err != nil {
		return desktopPlan{}, fmt.Errorf("%s: %w", path, err)
	}
	return desktopPlan{Path: path, Before: string(data), After: string(after)}, nil
}

// applyDesktop merges mailbag into the Claude Desktop config at path.
// binPath is the path of mailbag-mcp as the person gave it, before any
// symlink is resolved. running reports whether the Claude app runs;
// nil means no check. now gives the time for the backup name. It
// returns the backup path, or "" when there was no file to back up.
func applyDesktop(path, binPath string, running func() bool, now func() time.Time) (string, error) {
	if running != nil && running() {
		return "", errAppRunning
	}
	target := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		target = r
	}
	data, err := os.ReadFile(target) //nolint:gosec // G304: target is the Claude Desktop config path from desktopConfigPath, not request input
	mode := fs.FileMode(0o600)
	if errors.Is(err, fs.ErrNotExist) {
		data = nil
	} else if err != nil {
		return "", err
	} else if st, err := os.Stat(target); err == nil {
		mode = st.Mode().Perm()
	}
	after, err := mergeDesktop(data, binPath)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	backup := ""
	if data != nil {
		backup = target + ".bak-" + now().UTC().Format(backupTimeFormat)
		if err := os.WriteFile(backup, data, mode); err != nil { //nolint:gosec // G703: backup is the Claude Desktop config path from desktopConfigPath plus a time suffix; no request value reaches it
			return "", err
		}
	}
	tmp, err := os.CreateTemp(dir, ".mailbag-setup-*")
	if err != nil {
		return backup, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // fails when the rename worked; that is fine
	if _, err := tmp.Write(after); err != nil {
		_ = tmp.Close()
		return backup, err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return backup, err
	}
	if err := tmp.Close(); err != nil {
		return backup, err
	}
	return backup, os.Rename(tmp.Name(), target)
}

// cmdRunner runs a program and returns its output. Tests replace it.
type cmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner is the cmdRunner that starts a real process. main gives
// it to the server; tests give a fake.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: the program is claude and the arguments are fixed words plus a path
}

// claudeCodeAddArgs gives the arguments of "claude" that add mailbag
// for the user. binPath is the path before symlink resolution.
func claudeCodeAddArgs(binPath string) []string {
	return []string{"mcp", "add", "--scope", "user", serverName, "--", binPath}
}

// claudeCodeCurrent returns the output of "claude mcp get mailbag" and
// whether it mentions binPath. A failed call means mailbag is not set.
func claudeCodeCurrent(ctx context.Context, run cmdRunner, binPath string) (string, bool) {
	out, err := run(ctx, "claude", "mcp", "get", serverName)
	if err != nil {
		return "", false
	}
	return string(out), strings.Contains(string(out), binPath)
}

// applyClaudeCode runs "claude mcp add --scope user". It does not
// touch the config file of Claude Code itself.
func applyClaudeCode(ctx context.Context, run cmdRunner, binPath string) error {
	out, err := run(ctx, "claude", claudeCodeAddArgs(binPath)...)
	if err != nil {
		return fmt.Errorf("claude mcp add: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// The names of the two clients in the API (DS13.10).
const (
	clientDesktop = "claude-desktop"
	clientCode    = "claude-code"
)

// desktopAppPattern is the pgrep pattern of the Claude Desktop process:
// "Claude" on macOS, "claude-desktop" in the Linux builds.
const desktopAppPattern = "Claude|claude-desktop"

// clientView is one client in the answer of GET /api/clients.
//
// arch: DS13.8, DS13.10
type clientView struct {
	// Name is the name in POST /api/clients/<name>.
	Name string `json:"name"`
	// Label is the name that the page shows.
	Label string `json:"label"`
	// Present is true when the client is on this computer.
	Present bool `json:"present"`
	// Path is the config file (Claude Desktop) or the program (Claude Code).
	Path string `json:"path"`
	// Current is the mailbag entry that the client has now, or "".
	Current string `json:"current"`
	// Same is true when the current entry runs the CLI of this server.
	Same bool `json:"same"`
	// Running is true when the Claude Desktop app runs.
	Running bool `json:"running"`
	// Before and After show the change that "Apply" makes.
	Before string `json:"before"`
	After  string `json:"after"`
	// Error is the reason that no change can be made, such as bad JSON.
	Error string `json:"error,omitempty"`
}

// clientApplied is the answer of POST /api/clients/<name>.
//
// arch: DS13.8, DS13.10
type clientApplied struct {
	Name string `json:"name"`
	// Changed is false when the client had the same entry already.
	Changed bool `json:"changed"`
	// Backup is the backup of the Claude Desktop config, or "".
	Backup string `json:"backup,omitempty"`
}

// desktopAppRunning reports whether the Claude Desktop app runs. It
// only reads the process list; it never stops the app (IS13.5). A
// failed pgrep, also a missing one, counts as "not running".
func desktopAppRunning(ctx context.Context, run cmdRunner) bool {
	_, err := run(ctx, "pgrep", "-x", desktopAppPattern)
	return err == nil
}

// desktopEntry gives the raw mcpServers.mailbag value of the config
// text data and its command, or "" when there is none.
func desktopEntry(data string) (string, string) {
	if data == "" {
		return "", ""
	}
	top, err := parseObject([]byte(data))
	if err != nil {
		return "", ""
	}
	for _, f := range top {
		if f.key != "mcpServers" {
			continue
		}
		servers, err := parseObject(f.val)
		if err != nil {
			return "", ""
		}
		for _, sv := range servers {
			if sv.key == serverName {
				var e struct {
					Command string `json:"command"`
				}
				_ = json.Unmarshal(sv.val, &e) // an entry with another shape has no command
				return string(sv.val), e.Command
			}
		}
	}
	return "", ""
}

// desktopPresent reports whether Claude Desktop is on this computer:
// the directory of its config path exists.
func desktopPresent(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(filepath.Dir(path))
	return err == nil && st.IsDir()
}

// desktopState gives the view of Claude Desktop. The app is present
// when the directory of its config exists. It writes nothing.
//
// arch: DS13.3, DS13.8
func desktopState(path, binPath string, running bool) clientView {
	v := clientView{Name: clientDesktop, Label: "Claude Desktop", Path: path, Running: running}
	if !desktopPresent(path) {
		return v
	}
	v.Present = true
	p, err := planDesktop(path, binPath)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Before, v.After = p.Before, p.After
	var cmd string
	v.Current, cmd = desktopEntry(p.Before)
	v.Same = cmd == binPath
	return v
}

// claudeCodeState gives the view of Claude Code. The program is
// present when "claude --version" works. It changes nothing.
//
// arch: DS13.3, DS13.8
func claudeCodeState(ctx context.Context, run cmdRunner, binPath string) clientView {
	v := clientView{
		Name: clientCode, Label: "Claude Code", Path: "claude",
		After: "claude " + strings.Join(claudeCodeAddArgs(binPath), " "),
	}
	if _, err := run(ctx, "claude", "--version"); err != nil {
		return v
	}
	v.Present = true
	v.Current, v.Same = claudeCodeCurrent(ctx, run, binPath)
	v.Before = v.Current
	return v
}

// connectClaudeCode adds mailbag to Claude Code for the user. It does
// nothing when the entry runs binPath already. An entry with another
// path is removed from the user scope first, because "claude mcp add"
// refuses a name that is in use. The remove fails when the old entry
// is in another scope; then the add still works, so the remove error
// is not used.
//
// arch: DS13.3, DS13.8
func connectClaudeCode(ctx context.Context, run cmdRunner, binPath string) (bool, error) {
	cur, same := claudeCodeCurrent(ctx, run, binPath)
	if same {
		return false, nil
	}
	if cur != "" {
		_, _ = run(ctx, "claude", "mcp", "remove", "--scope", "user", serverName)
	}
	return true, applyClaudeCode(ctx, run, binPath)
}
