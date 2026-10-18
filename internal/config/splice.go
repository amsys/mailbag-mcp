// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// spliceOp names which edit verifySplice is checking.
type spliceOp int

const (
	spliceAdd spliceOp = iota
	spliceRemove
	// spliceIdentities adds identity settings to one account (DI7.6).
	spliceIdentities
)

// AddAccountBlock appends block, the raw TOML text of one new
// "[accounts.<alias>]" table, to the file at path. It never runs the
// file through a TOML encoder, because that deletes comments a person
// wrote (D14, B18). Before it writes anything, it decodes the result
// and confirms it matches the original file with exactly alias's
// account added; on a mismatch it leaves the file untouched and
// returns an error wrapping ErrSpliceMismatch.
//
// arch: T1.2, §3.3, D14, B17, B18, A10
func AddAccountBlock(path, alias, block string) error {
	if !ValidAlias(alias) {
		return fmt.Errorf("config: add %q: %w", alias, ErrInvalidAlias)
	}

	before, err := readAliases(path)
	if err != nil {
		return err
	}
	if _, exists := before[alias]; exists {
		return fmt.Errorf("config: add %q: alias already exists", alias)
	}

	orig, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the user's own config
	if err != nil {
		return err
	}
	text := string(orig)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += "\n" + strings.TrimRight(block, "\n") + "\n"

	if err := verifySplice(orig, []byte(text), alias, spliceAdd); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(text), 0o600)
}

// RemoveAccountBlock cuts the lines from "[accounts.<alias>]" up to,
// but not including, the next header line that is not one of the
// alias's own sub-tables (or the end of the file); see
// cutAccountBlock. It then decodes the result and confirms it matches
// the original file with exactly alias's account removed; on a
// mismatch it leaves the file untouched and returns an error wrapping
// ErrSpliceMismatch, so the person edits the file by hand instead of
// trusting a half-correct cut.
//
// arch: T1.2, §3.3, D14, B17, B18, A10
func RemoveAccountBlock(path, alias string) error {
	before, err := readAliases(path)
	if err != nil {
		return err
	}
	if _, exists := before[alias]; !exists {
		return fmt.Errorf("config: remove %q: alias not found", alias)
	}

	orig, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the user's own config
	if err != nil {
		return err
	}
	cut, err := cutAccountBlock(string(orig), alias)
	if err != nil {
		return err
	}

	if err := verifySplice(orig, []byte(cut), alias, spliceRemove); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(cut), 0o600)
}

// AddIdentityTables adds identity settings to the account alias in the
// file at path, for "identities detect" (DI7.6). When defaultIdentity
// is not empty, it inserts the line default_identity = "<value>"
// directly after the "[accounts.<alias>]" header. It inserts tables,
// the raw TOML text of one or more "[[accounts.<alias>.identity]]"
// tables, after the last key line of the account's block, as
// accountBlock finds it. Blank lines and comment lines at the end of
// the block stay after the new tables, next to the header that
// follows. No TOML encoder runs, so every comment stays.
//
// It refuses an account that already has an identity table or a
// default_identity key. Before it writes, verifySplice confirms that
// every other account and every top-level key decode unchanged, and
// that alias decodes unchanged once Identity and DefaultIdentity are
// zeroed. Then the new text must pass the strict load (loadSnapshot)
// before the atomic rename. On any failure the file stays unchanged.
//
// arch: DI7.6, DI8 I7, D14, B18, A10
func AddIdentityTables(path, alias, defaultIdentity, tables string) error {
	if !ValidAlias(alias) {
		return fmt.Errorf("config: identities %q: %w", alias, ErrInvalidAlias)
	}
	if defaultIdentity == "" && strings.TrimSpace(tables) == "" {
		return fmt.Errorf("config: identities %q: nothing to add", alias)
	}
	if !plainBasicString(defaultIdentity) {
		return fmt.Errorf("config: identities %q: default_identity %q holds a quote, a backslash or a control character", alias, defaultIdentity)
	}

	orig, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the user's own config
	if err != nil {
		return err
	}
	raw, err := decodeRawFile(orig)
	if err != nil {
		return fmt.Errorf("config: splice source is invalid TOML: %w", err)
	}
	ra, exists := raw.Accounts[alias]
	if !exists {
		return fmt.Errorf("config: identities %q: alias not found", alias)
	}
	if len(ra.Identity) > 0 || ra.DefaultIdentity != "" {
		return fmt.Errorf("config: identities %q: account already has identity settings; edit accounts.toml by hand", alias)
	}

	text := string(orig)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	lines := strings.Split(text, "\n")
	start, end, err := accountBlock(lines, alias)
	if err != nil {
		return err
	}
	last := start
	for i := start + 1; i < end; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			last = i
		}
	}

	// text ends with "\n", so the last element of lines is "" and
	// last+1 is always a valid index.
	out := make([]string, 0, len(lines)+8)
	out = append(out, lines[:start+1]...)
	if defaultIdentity != "" {
		out = append(out, `default_identity = "`+defaultIdentity+`"`)
	}
	out = append(out, lines[start+1:last+1]...)
	if strings.TrimSpace(tables) != "" {
		out = append(out, "")
		out = append(out, strings.Split(strings.TrimRight(tables, "\n"), "\n")...)
		if strings.TrimSpace(lines[last+1]) != "" {
			out = append(out, "")
		}
	}
	out = append(out, lines[last+1:]...)
	newText := []byte(strings.Join(out, "\n"))

	if err := verifySplice(orig, newText, alias, spliceIdentities); err != nil {
		return err
	}
	return writeFileAtomicChecked(path, newText, 0o600, strictLoadCheck)
}

// plainBasicString reports whether s can go between the quotes of a
// TOML basic string with no escape: it holds no quote, no backslash and
// no control character.
func plainBasicString(s string) bool {
	for _, r := range s {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// strictLoadCheck runs the strict load of Load (unknown keys and
// validateIn) on the file at tmpPath. AddIdentityTables calls it on the
// temporary file before the rename (DI7.6).
func strictLoadCheck(tmpPath string) error {
	if _, err := loadSnapshot(tmpPath, time.Time{}); err != nil {
		return fmt.Errorf("config: splice result fails the strict load, file unchanged: %w", err)
	}
	return nil
}

// accountBlock finds the block of alias in lines. start is the index
// of the "[accounts.<alias>]" header line. end is the index of the
// first later line that opens a header ("[" or "[[") which is not one
// of the alias's own sub-tables ("[accounts.<alias>.…]" or
// "[[accounts.<alias>.…]]"), or len(lines). See DRV.19.1.
func accountBlock(lines []string, alias string) (start, end int, err error) {
	header := "[accounts." + alias + "]"
	subTable := "[accounts." + alias + "."
	subArrayTable := "[[accounts." + alias + "."

	start = -1
	for i, line := range lines {
		if strings.TrimSpace(line) == header {
			start = i
			break
		}
	}
	if start == -1 {
		return 0, 0, fmt.Errorf("config: account %q: header %q not found", alias, header)
	}

	end = len(lines)
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, "[") {
			continue
		}
		if strings.HasPrefix(trimmed, subTable) || strings.HasPrefix(trimmed, subArrayTable) {
			continue
		}
		end = i
		break
	}
	return start, end, nil
}

// cutAccountBlock removes the header line "[accounts.<alias>]" and
// every line after it, up to but not including the first line that
// opens a header ("[" or "[[") which is not one of the alias's own
// sub-tables ("[accounts.<alias>.…]" or "[[accounts.<alias>.…]]"), or
// the end of the file. Stopping only at the next "[accounts." header,
// as the old cut did, let a "[verify]", "[send]" or "[decrypt]" table
// placed right after the account get cut away too (DRV.19.1).
func cutAccountBlock(text, alias string) (string, error) {
	lines := strings.Split(text, "\n")
	start, end, err := accountBlock(lines, alias)
	if err != nil {
		return "", fmt.Errorf("config: remove %q: header %q not found", alias, "[accounts."+alias+"]")
	}

	out := make([]string, 0, len(lines)-(end-start))
	out = append(out, lines[:start]...)
	out = append(out, lines[end:]...)
	return strings.Join(out, "\n"), nil
}

// verifySplice decodes origText and newText and confirms that newText
// differs from origText by exactly one account: alias added
// (spliceAdd) or removed (spliceRemove), or alias changed only in its
// Identity and DefaultIdentity fields (spliceIdentities, DI7.6). Every
// other top-level key,
// and every account the splice did not touch, must decode unchanged.
// This is what catches a cut that also removed a "[verify]", "[send]"
// or "[decrypt]" table: dropping one of those does not change the
// account alias set, so a set-only check would miss it (DRV.19.1). It
// never writes anything; the caller decides what "unchanged" means.
func verifySplice(origText, newText []byte, alias string, op spliceOp) error {
	orig, err := decodeRawFile(origText)
	if err != nil {
		return fmt.Errorf("config: splice source is invalid TOML: %w", err)
	}
	got, err := decodeRawFile(newText)
	if err != nil {
		return fmt.Errorf("config: splice produced invalid TOML, file unchanged: %w", err)
	}

	want := make(map[string]rawAccount, len(orig.Accounts))
	for k, v := range orig.Accounts {
		want[k] = v
	}
	switch op {
	case spliceAdd:
		gotAccount, exists := got.Accounts[alias]
		if !exists {
			return fmt.Errorf("config: splice mismatch: %q missing after add, file unchanged: %w", alias, ErrSpliceMismatch)
		}
		want[alias] = gotAccount
	case spliceRemove:
		delete(want, alias)
	case spliceIdentities:
		origAccount, inOrig := want[alias]
		gotAccount, inGot := got.Accounts[alias]
		if !inOrig || !inGot {
			return fmt.Errorf("config: splice mismatch: %q missing, file unchanged: %w", alias, ErrSpliceMismatch)
		}
		origAccount.Identity, origAccount.DefaultIdentity = nil, ""
		bare := gotAccount
		bare.Identity, bare.DefaultIdentity = nil, ""
		if !reflect.DeepEqual(origAccount, bare) {
			return fmt.Errorf("config: splice mismatch: %q changed outside identity and default_identity, file unchanged: %w", alias, ErrSpliceMismatch)
		}
		want[alias] = gotAccount
	}

	// Accounts is compared separately from the rest of rawFile, and
	// by key/value rather than by map identity: a file that ends up
	// with no accounts section at all decodes Accounts as a nil map,
	// while want is always a freshly made, possibly empty, map.
	// reflect.DeepEqual treats a nil map and an empty map as unequal,
	// so comparing the whole struct in one call would misreport that
	// as a mismatch.
	rest, gotRest := orig, got
	rest.Accounts, gotRest.Accounts = nil, nil

	if !reflect.DeepEqual(rest, gotRest) || !accountsEqual(want, got.Accounts) {
		return fmt.Errorf("config: splice mismatch (got accounts %v, want accounts %v), file unchanged: %w",
			acctKeys(got.Accounts), acctKeys(want), ErrSpliceMismatch)
	}
	return nil
}

// accountsEqual compares two account maps by key and decoded value.
// A nil map and a non-nil, empty map both mean "no accounts" and
// compare equal.
func accountsEqual(a, b map[string]rawAccount) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || !reflect.DeepEqual(av, bv) {
			return false
		}
	}
	return true
}

// PeekFile decodes the file at path with no check of its values: no
// unknown-key check, no signature file read, no account check. It
// gives the set of account aliases and the recorded secrets kind. An
// absent secrets key gives "keyring", as the strict load does. "account
// remove" uses it, so a broken account or a bad other block does not
// stop the removal; the splice uses the same decode.
//
// arch: §3.3, B18, R16-L15
func PeekFile(path string) (aliases map[string]struct{}, secretsKind string, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the user's own config
	if err != nil {
		return nil, "", err
	}
	raw, err := decodeRawFile(data)
	if err != nil {
		return nil, "", err
	}
	aliases = make(map[string]struct{}, len(raw.Accounts))
	for alias := range raw.Accounts {
		aliases[alias] = struct{}{}
	}
	secretsKind = raw.Secrets
	if secretsKind == "" {
		secretsKind = "keyring"
	}
	return aliases, secretsKind, nil
}

func readAliases(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the user's own config
	if err != nil {
		return nil, err
	}
	return parseAliases(data)
}

func parseAliases(data []byte) (map[string]struct{}, error) {
	raw, err := decodeRawFile(data)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(raw.Accounts))
	for alias := range raw.Accounts {
		set[alias] = struct{}{}
	}
	return set, nil
}

func decodeRawFile(data []byte) (rawFile, error) {
	var raw rawFile
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return rawFile{}, err
	}
	return raw, nil
}

func acctKeys(m map[string]rawAccount) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// writeFileAtomic writes data to a temporary file in the same
// directory as path, then renames it into place, so a reader never
// sees a half-written accounts.toml (A10: several server processes
// run at one time).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomicChecked(path, data, perm, nil)
}

// writeFileAtomicChecked is writeFileAtomic with a check. When check is
// not nil, it runs on the closed temporary file before the rename. An
// error from check stops the rename, removes the temporary file and
// leaves path unchanged.
//
// A symlinked path is resolved first, so the rename replaces the
// target and the link stays a link. The temporary file is synced
// before the rename, so a crash cannot leave an empty accounts.toml
// (R16-L17).
func writeFileAtomicChecked(path string, data []byte, perm os.FileMode, check func(tmpPath string) error) error {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".accounts-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if check != nil {
		if err := check(tmpPath); err != nil {
			return err
		}
	}
	return os.Rename(tmpPath, path)
}
