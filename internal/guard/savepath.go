// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// maxSaveNameBytes is the longest file name SaveName returns (§3.15:
// "200 bytes at most and keep the extension").
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
const maxSaveNameBytes = 200

// maxSaveAttempts bounds the "name (n).ext" search of CreateSaveFile,
// so a directory an attacker filled with decoys cannot hang the call.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
const maxSaveAttempts = 1000

// windowsReserved lists the device names Windows refuses as a file
// name in any extension ("con.txt" included). §3.15 asks for a "_"
// prefix so a name ported from another OS still saves there.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// DefaultRoots returns the permitted save roots of §3.15:
// "~/Downloads/mailbag-mcp", the system temp directory, and the
// account's configured download_dirs. It fails only when the home
// directory cannot be found.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func DefaultRoots(downloadDirs []string) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("guard: save roots: %w", err)
	}
	roots := []string{filepath.Join(home, "Downloads", "mailbag-mcp"), os.TempDir()}
	roots = append(roots, downloadDirs...)
	return roots, nil
}

// canonicalize resolves path the way §3.15 asks: find the deepest
// ancestor that exists, resolve that ancestor's symbolic links with
// filepath.EvalSymlinks, and append the rest literally (those
// components cannot be a symlink of their own, because they do not
// exist yet).
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func canonicalize(path string) (string, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		path = abs
	}
	var tail []string
	cur := path
	for {
		if _, err := os.Lstat(cur); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break // filesystem root; Lstat always finds it in practice
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
	resolved, err := filepath.EvalSymlinks(cur)
	if err != nil {
		return "", err
	}
	for _, part := range tail {
		resolved = filepath.Join(resolved, part)
	}
	return resolved, nil
}

// ResolveSaveDir canonicalizes dir and confirms it falls inside one of
// roots, so a name like "/tmp-fake" cannot pass as "/tmp" and a
// symbolic link cannot walk the target out of every permitted root
// (§3.15, G6). It also refuses dir when its part below the matched
// root has a hidden component: with the root "~", a save into
// "~/.config/autostart" or "~/.ssh" can make a file that runs or
// grants access later (R16-M3). A dot component in the root itself
// is the choice of the owner and passes.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9, R16-M3
func ResolveSaveDir(dir string, roots []string) (string, error) {
	cdir, err := canonicalize(dir)
	if err != nil {
		return "", fmt.Errorf("guard: save dir: %w", err)
	}
	_, rel, err := matchRoot(cdir, roots)
	if err != nil {
		return "", fmt.Errorf("guard: save dir %q is outside every permitted root", dir)
	}
	if rel != "." && hasHiddenComponent(rel) {
		return "", fmt.Errorf("guard: save dir %q: a hidden path component below the root is refused", dir)
	}
	return cdir, nil
}

// matchRoot finds the entry of roots that resolved falls under, after
// expanding "~" and canonicalizing each entry the same way as
// resolved, so a symbolic link cannot walk the target out of every
// permitted root and a root written as "~/Downloads" matches the way
// the person expects (§3.15, G6, G7). resolved itself is never
// touched on disk here: only the trusted root entries are resolved,
// so a swap of an untrusted path below a root cannot influence which
// root it is checked against. It returns the matched canonical root
// and the path of resolved relative to it ("." when they are equal).
//
// arch: T2.3, T2.4, §3.15, §5.4, G6, G7, §10.9
func matchRoot(resolved string, roots []string) (root, rel string, err error) {
	for _, r := range roots {
		r, err := expandHome(r)
		if err != nil {
			continue // an unusable root cannot match; try the rest
		}
		cr, err := canonicalize(r)
		if err != nil {
			continue
		}
		if resolved == cr {
			return cr, ".", nil
		}
		if strings.HasPrefix(resolved, cr+string(filepath.Separator)) {
			return cr, strings.TrimPrefix(resolved, cr+string(filepath.Separator)), nil
		}
	}
	return "", "", fmt.Errorf("guard: %q is outside every permitted root", resolved)
}

// underRoot reports whether resolved falls inside one of roots
// (matchRoot, §3.15, G6, G7).
//
// arch: T2.3, T2.4, §3.15, §5.4, G6, G7, §10.9
func underRoot(resolved string, roots []string) bool {
	_, _, err := matchRoot(resolved, roots)
	return err == nil
}

// SaveName turns a sender-supplied file name into one safe to create
// on disk, applying §3.15's rules in order: base name only, no path
// separators, no control or hidden characters, no leading dots, a
// byte limit that keeps the extension, and a Windows device name
// guard.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func SaveName(name string) (string, error) {
	// The name comes from another host, so both "/" and "\" are
	// separators here on every OS. path.Base (not filepath.Base) gives
	// the same result on Linux and on Windows.
	name = path.Base(strings.ReplaceAll(name, `\`, "/"))
	name = strings.ReplaceAll(name, "/", "_") // path.Base("/") is "/"
	name = strings.ToValidUTF8(name, "")      // a stray byte is not a character
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || isInvisible(r) {
			continue // control or hidden character (§3.15)
		}
		b.WriteRune(r)
	}
	name = strings.TrimLeft(b.String(), ".")
	if name == "" {
		return "", errors.New("guard: save name: empty after cleanup")
	}
	name = truncateSaveName(name, maxSaveNameBytes)
	if isWindowsReserved(name) {
		// A cut of "_x" keeps the "_", so the result is never reserved.
		name = truncateSaveName("_"+name, maxSaveNameBytes)
	}
	return name, nil
}

// isWindowsReserved reports whether Windows reads name as a device.
// Windows ignores all text from the first dot and trailing spaces, so
// "con.tar.gz" and "con .txt" are devices too.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func isWindowsReserved(name string) bool {
	stem, _, _ := strings.Cut(name, ".")
	return windowsReserved[strings.ToLower(strings.TrimRight(stem, " "))]
}

// truncateSaveName shortens name to at most limit bytes, keeping the
// extension and cutting on a rune boundary.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func truncateSaveName(name string, limit int) string {
	if len(name) <= limit {
		return name
	}
	ext := filepath.Ext(name)
	if len(ext) >= limit {
		return runeSafeCut(name, limit) // the extension alone does not fit; cut blind
	}
	base := runeSafeCut(strings.TrimSuffix(name, ext), limit-len(ext))
	if base == "" {
		// The first rune does not fit beside the extension. A result
		// of ext alone would start with a dot, so cut blind instead.
		return runeSafeCut(name, limit)
	}
	return base + ext
}

// runeSafeCut cuts s to at most n bytes without splitting a multi-byte
// rune in half.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func runeSafeCut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// CreateSaveFile creates name inside dir, one of roots (or a
// subdirectory of one), and returns the open file and the path used.
// dir is the value ResolveSaveDir already validated; CreateSaveFile
// checks it again here, against roots, and never resolves dir itself
// on disk to do that (matchRoot compares it as text against the
// canonicalized roots). The file is opened through os.OpenRoot(root)
// and Root.OpenFile(rel/name, ...): os.Root refuses a symbolic link
// that resolves outside root on every path component it walks, not
// only the last one, so a parent directory swapped for a symlink
// between the ResolveSaveDir check and this call cannot walk the
// create outside the permitted root (§3.15's O_NOFOLLOW guarantee,
// G6). O_CREATE|O_EXCL|O_WRONLY, mode 0600, refuses a
// target that already exists, symlink or not. name must already be a
// bare file name (SaveName's result); a name that still carries a
// path separator or ".." is refused. On a collision it tries "name
// (1).ext", "name (2).ext", and so on, up to maxSaveAttempts, and it
// never overwrites or opens through an existing name (§3.15, G6,
// §10.9).
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func CreateSaveFile(dir, name string, roots []string) (*os.File, string, error) {
	if name != filepath.Base(name) {
		return nil, "", fmt.Errorf("guard: save file: name %q is not a bare file name", name)
	}
	root, rel, err := matchRoot(dir, roots)
	if err != nil {
		return nil, "", fmt.Errorf("guard: save file: %w", err)
	}
	rf, err := os.OpenRoot(root)
	if err != nil {
		return nil, "", fmt.Errorf("guard: save file: %w", err)
	}
	defer func() { _ = rf.Close() }()

	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 0; i < maxSaveAttempts; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", base, i, ext)
		}
		f, err := rf.OpenFile(filepath.Join(rel, candidate), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return f, filepath.Join(dir, candidate), nil
		}
		if errors.Is(err, fs.ErrExist) {
			continue // name taken (a real file or a symlink left in its place); try the next one
		}
		return nil, "", fmt.Errorf("guard: save file: %w", err)
	}
	return nil, "", fmt.Errorf("guard: save file: no free name for %q after %d attempts", name, maxSaveAttempts)
}
