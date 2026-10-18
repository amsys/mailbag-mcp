// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestConfig_SpliceKeepsSymlink checks that a splice writes through a
// symlinked accounts.toml: the link stays a link, and its target gets
// the new text. A rename onto the link path would replace the link
// with a plain file, and the dotfiles copy would go stale.
//
// arch: T1.2, §3.3, B18, A10, R16-L17
func TestConfig_SpliceKeepsSymlink(t *testing.T) {
	target := writeTemp(t, "[accounts.work]\nprovider = \"imap\"\nemail    = \"me@example.com\"\n")
	link := filepath.Join(t.TempDir(), "accounts.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symlink on this system: %v", err)
	}

	block := "[accounts.home]\nprovider = \"gmail\"\nemail    = \"me@gmail.com\"\n"
	if err := AddAccountBlock(link, "home", block); err != nil {
		t.Fatalf("AddAccountBlock: %v", err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat the link: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("accounts.toml is no longer a symlink: mode %v", info.Mode())
	}
	got, err := os.ReadFile(target) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read the target: %v", err)
	}
	if !strings.Contains(string(got), "[accounts.home]") {
		t.Errorf("the target did not get the new block:\n%s", got)
	}
	tmps, err := filepath.Glob(filepath.Join(filepath.Dir(link), ".accounts-*.tmp"))
	if err != nil || len(tmps) != 0 {
		t.Errorf("temporary files left next to the link: %v %v", tmps, err)
	}
}

// TestConfig_AddKeepsComments checks that AddAccountBlock never runs
// the file through a TOML encoder, so a comment a person wrote by
// hand survives (D14, B18).
//
// arch: T1.2, §3.3, D14, B18
func TestConfig_AddKeepsComments(t *testing.T) {
	const original = `# accounts.toml -- edited by hand and by "account add"
secrets = "keyring"
extras  = []

[accounts.work]
provider = "imap"          # primary account
email    = "me@example.com"
access   = "send"
`
	path := writeTemp(t, original)

	block := "[accounts.home]\nprovider = \"gmail\"\nemail    = \"me@gmail.com\"\n"
	if err := AddAccountBlock(path, "home", block); err != nil {
		t.Fatalf("AddAccountBlock: %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	text := string(got)

	for _, want := range []string{
		`# accounts.toml -- edited by hand and by "account add"`,
		`provider = "imap"          # primary account`,
		`[accounts.home]`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("result missing %q\ngot:\n%s", want, text)
		}
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load after add: %v", err)
	}
	if _, ok := c.Account("work"); !ok {
		t.Errorf("account work lost after add")
	}
	if _, ok := c.Account("home"); !ok {
		t.Errorf("account home missing after add")
	}
}

// TestConfig_AddRejectsInvalidAlias checks that the splice path
// enforces the alias pattern too (B17: checked in the config loader,
// in the CLI and in each tool), and that a rejected add leaves the
// file untouched.
//
// arch: T1.2, §3.3, B17
func TestConfig_AddRejectsInvalidAlias(t *testing.T) {
	const original = "[accounts.work]\nprovider = \"imap\"\nemail    = \"me@example.com\"\n"
	path := writeTemp(t, original)

	err := AddAccountBlock(path, "a.b", "[accounts.\"a.b\"]\nprovider = \"imap\"\nemail = \"x@example.com\"\n")
	if !errors.Is(err, ErrInvalidAlias) {
		t.Fatalf("AddAccountBlock: err = %v, want ErrInvalidAlias", err)
	}
	assertUnchanged(t, path, original)
}

// TestConfig_RemoveCutsOnlyBlock checks that RemoveAccountBlock cuts
// exactly the lines of the target account and leaves every other line
// - including comments and sibling accounts - unchanged.
//
// arch: T1.2, §3.3, D14, B18
func TestConfig_RemoveCutsOnlyBlock(t *testing.T) {
	const original = `# accounts.toml
secrets = "keyring"
extras  = []

[accounts.work]
provider = "imap"          # primary account
email    = "me@example.com"
access   = "send"

[accounts.home]
provider = "gmail"
email    = "me@gmail.com"
`
	const want = `# accounts.toml
secrets = "keyring"
extras  = []

[accounts.home]
provider = "gmail"
email    = "me@gmail.com"
`
	path := writeTemp(t, original)

	if err := RemoveAccountBlock(path, "work"); err != nil {
		t.Fatalf("RemoveAccountBlock: %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != want {
		t.Fatalf("result mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load after remove: %v", err)
	}
	if _, ok := c.Account("work"); ok {
		t.Errorf("account work still present after remove")
	}
	if _, ok := c.Account("home"); !ok {
		t.Errorf("account home lost after remove")
	}
}

// TestConfig_RemoveRejectsUnknownAlias checks that removing an alias
// that is not in the file is an error, not a silent no-op write.
//
// arch: T1.2, §3.3, B18
func TestConfig_RemoveRejectsUnknownAlias(t *testing.T) {
	const original = "[accounts.work]\nprovider = \"imap\"\nemail = \"me@example.com\"\n"
	path := writeTemp(t, original)

	if err := RemoveAccountBlock(path, "home"); err == nil {
		t.Fatalf("RemoveAccountBlock(home): want an error, got nil")
	}
	assertUnchanged(t, path, original)
}

// TestConfig_SpliceMismatchAborts checks the safety net of B18: the
// cut described by DRV.19.1 (up to the first header line that is not
// one of the removed alias's own sub-tables) stops at the "[verify]"
// table, since that table belongs to no account. A later
// "[accounts.work.folders]" sub-table, on the far side of that stop,
// is never reached by the cut and reintroduces the alias as an
// implicit TOML table. The splice detects the mismatch, changes
// nothing on disk and returns an error wrapping ErrSpliceMismatch.
//
// arch: T1.2, §3.3, D14, B18, DRV.19.1
func TestConfig_SpliceMismatchAborts(t *testing.T) {
	const original = `secrets = "keyring"

[accounts.work]
provider = "imap"
email    = "me@example.com"

[verify]
authserv_id = "mail.example.com"

[accounts.work.folders]
sent = "Sent Items"

[accounts.home]
provider = "gmail"
email    = "me@gmail.com"
`
	path := writeTemp(t, original)

	err := RemoveAccountBlock(path, "work")
	if !errors.Is(err, ErrSpliceMismatch) {
		t.Fatalf("RemoveAccountBlock: err = %v, want ErrSpliceMismatch", err)
	}
	assertUnchanged(t, path, original)
}

// TestRemoveAccountBlock_KeepsFollowingTables checks that removing an
// account does not also remove a file-level table ([verify], [send],
// ...) that happens to sit right after it, with no other account
// header between them to stop the old cut.
//
// arch: DRV.19.1
func TestRemoveAccountBlock_KeepsFollowingTables(t *testing.T) {
	const original = `secrets = "keyring"

[accounts.work]
provider = "imap"
email    = "me@example.com"

[verify]
authserv_id   = "mail.example.com"
smime_ca_file = "/etc/mailbag/ca.pem"

[send]
allow_without_elicitation = true
`
	const want = `secrets = "keyring"

[verify]
authserv_id   = "mail.example.com"
smime_ca_file = "/etc/mailbag/ca.pem"

[send]
allow_without_elicitation = true
`
	path := writeTemp(t, original)

	if err := RemoveAccountBlock(path, "work"); err != nil {
		t.Fatalf("RemoveAccountBlock: %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != want {
		t.Fatalf("result mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load after remove: %v", err)
	}
	if _, ok := c.Account("work"); ok {
		t.Errorf("account work still present after remove")
	}
}

// TestRemoveAccountBlock_RemovesOwnSubTables checks that removing an
// account also removes a sub-table of that same account
// ("[accounts.<alias>.folders]") that sits past the header, rather
// than stopping the cut at that sub-table's header and leaving it
// behind to reintroduce the alias as an implicit TOML table.
//
// arch: DRV.19.1
func TestRemoveAccountBlock_RemovesOwnSubTables(t *testing.T) {
	const original = `secrets = "keyring"

[accounts.work]
provider = "imap"
email    = "me@example.com"
[accounts.work.folders]
sent  = "Sent Items"
trash = "Deleted Items"

[accounts.home]
provider = "gmail"
email    = "me@gmail.com"
`
	const want = `secrets = "keyring"

[accounts.home]
provider = "gmail"
email    = "me@gmail.com"
`
	path := writeTemp(t, original)

	if err := RemoveAccountBlock(path, "work"); err != nil {
		t.Fatalf("RemoveAccountBlock: %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != want {
		t.Fatalf("result mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load after remove: %v", err)
	}
	if _, ok := c.Account("work"); ok {
		t.Errorf("account work still present after remove")
	}
	if _, ok := c.Account("home"); !ok {
		t.Errorf("account home lost after remove")
	}
}

func assertUnchanged(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != want {
		t.Fatalf("file changed on a rejected splice\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// identityTablesFixture is an accounts.toml with comments, top-level
// keys, a file-level table and two accounts. The work account has a
// folders sub-table and ends with a comment that belongs to the next
// header.
const identityTablesFixture = `# accounts.toml -- edited by hand
secrets = "keyring"
extras  = []

[accounts.work]  
provider = "imap"          # primary account
email    = "me@example.com"
access   = "send"
[accounts.work.folders]
sent = "Sent Items"        # localized name

# the home account follows
[accounts.home]
provider = "gmail"
email    = "me@gmail.com"

[verify]
authserv_id = "mail.example.com"
`

// workIdentityTables is the tables text for the work account, as the
// detect command writes it: comments with evidence, basic strings with
// \n escapes.
const workIdentityTables = `[[accounts.work.identity]]
# 14 of 17 sent mails
email = "me@example.com"
name  = "Me"
signature = "Regards,\nMe"

[[accounts.work.identity]]
email = "sales@example.com"
reply_match = ["*@example.com"]
`

// TestAddIdentityTables_KeepsCommentsAndOtherAccounts checks DI7.6:
// default_identity goes on the line after the account header, the
// tables go after the last key line of the account's block (after its
// own sub-table, before the comment of the next header), and every
// other byte of the file stays as it was. The result loads with the
// strict loader and the other account is unchanged.
//
// arch: DI7.6, DI8 I7
func TestAddIdentityTables_KeepsCommentsAndOtherAccounts(t *testing.T) {
	path := writeTemp(t, identityTablesFixture)
	before, err := Load(path)
	if err != nil {
		t.Fatalf("Load before: %v", err)
	}
	homeBefore, _ := before.Account("home")

	if err := AddIdentityTables(path, "work", "sales@example.com", workIdentityTables); err != nil {
		t.Fatalf("AddIdentityTables: %v", err)
	}

	const want = `# accounts.toml -- edited by hand
secrets = "keyring"
extras  = []

[accounts.work]  
default_identity = "sales@example.com"
provider = "imap"          # primary account
email    = "me@example.com"
access   = "send"
[accounts.work.folders]
sent = "Sent Items"        # localized name

[[accounts.work.identity]]
# 14 of 17 sent mails
email = "me@example.com"
name  = "Me"
signature = "Regards,\nMe"

[[accounts.work.identity]]
email = "sales@example.com"
reply_match = ["*@example.com"]

# the home account follows
[accounts.home]
provider = "gmail"
email    = "me@gmail.com"

[verify]
authserv_id = "mail.example.com"
`
	got, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != want {
		t.Fatalf("result mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load after: %v", err)
	}
	work, ok := c.Account("work")
	if !ok {
		t.Fatalf("account work lost")
	}
	if work.DefaultIdentity != "sales@example.com" {
		t.Errorf("DefaultIdentity = %q, want sales@example.com", work.DefaultIdentity)
	}
	if len(work.IdentityList) != 2 || work.IdentityList[0].Signature != "Regards,\nMe" {
		t.Errorf("IdentityList = %+v, want two identities, first with the signature", work.IdentityList)
	}
	if work.Folders["sent"] != "Sent Items" || work.Access != "send" {
		t.Errorf("work account changed outside identities: %+v", work)
	}
	homeAfter, _ := c.Account("home")
	if !reflect.DeepEqual(homeBefore, homeAfter) {
		t.Errorf("home account changed\nbefore: %+v\nafter:  %+v", homeBefore, homeAfter)
	}
}

// TestAddIdentityTables_NoDefaultAtEndOfFile checks DI7.6 for an
// account that is the last block of a file with no final newline: with
// no default identity, no default_identity line is written, and the
// tables are added at the end.
//
// arch: DI7.6, DI8 I7
func TestAddIdentityTables_NoDefaultAtEndOfFile(t *testing.T) {
	const original = "# top\n[accounts.home]\nprovider = \"gmail\"\nemail = \"me@gmail.com\" # mine"
	path := writeTemp(t, original)

	tables := "[[accounts.home.identity]]\nemail = \"me@gmail.com\"\nsignature = \"Me\"\n"
	if err := AddIdentityTables(path, "home", "", tables); err != nil {
		t.Fatalf("AddIdentityTables: %v", err)
	}

	const want = "# top\n[accounts.home]\nprovider = \"gmail\"\nemail = \"me@gmail.com\" # mine\n" +
		"\n[[accounts.home.identity]]\nemail = \"me@gmail.com\"\nsignature = \"Me\"\n"
	got, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != want {
		t.Fatalf("result mismatch\ngot:\n%q\nwant:\n%q", got, want)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load after: %v", err)
	}
	home, _ := c.Account("home")
	if home.DefaultIdentity != "" || len(home.IdentityList) != 1 {
		t.Errorf("home = %+v, want one identity and no default", home)
	}
}

// TestAddIdentityTables_Refuses checks that each refused call of DI7.6
// returns an error and leaves the file byte for byte unchanged, with no
// temporary file left in the directory. The cases cover the input
// checks, an account that already has identity settings, a splice that
// changes more than the identity keys (verifySplice, I7), and a result
// that decodes but fails the strict load.
//
// arch: DI7.6, DI8 I7, DI8 I3
func TestAddIdentityTables_Refuses(t *testing.T) {
	const withIdentity = `[accounts.work]
provider = "imap"
email    = "me@example.com"

[[accounts.work.identity]]
email = "me@example.com"
`
	const withDefault = `[accounts.work]
provider = "imap"
email    = "me@example.com"
default_identity = "me@example.com"
`
	const okTables = "[[accounts.work.identity]]\nemail = \"me@example.com\"\n"

	cases := []struct {
		name     string
		original string
		alias    string
		def      string
		tables   string
		wantErr  error // nil: any error
	}{
		{"invalid alias", identityTablesFixture, "a.b", "", okTables, ErrInvalidAlias},
		{"unknown alias", identityTablesFixture, "nope", "", okTables, nil},
		{"nothing to add", identityTablesFixture, "work", "", " \n", nil},
		{"quote in default", identityTablesFixture, "work", `me"@example.com`, okTables, nil},
		{"control character in default", identityTablesFixture, "work", "me@example.com\n", okTables, nil},
		{"has identity table", withIdentity, "work", "", okTables, nil},
		{"has default_identity", withDefault, "work", "", okTables, nil},
		{"header with comment not found", "[accounts.work] # x\nprovider = \"imap\"\nemail = \"me@example.com\"\n", "work", "", okTables, nil},
		{"tables change another account", identityTablesFixture, "work", "",
			okTables + "[accounts.home.folders]\nsent = \"Sent\"\n", ErrSpliceMismatch},
		{"tables change a top-level table", identityTablesFixture, "work", "",
			okTables + "[send]\nallow_without_elicitation = true\n", ErrSpliceMismatch},
		{"tables change the account itself", identityTablesFixture, "work", "",
			"access = \"read\"\n" + okTables, ErrSpliceMismatch},
		{"unknown key in identity", identityTablesFixture, "work", "",
			"[[accounts.work.identity]]\nemail = \"me@example.com\"\nsignatur = \"x\"\n", ErrUnknownKey},
		{"default is no identity", identityTablesFixture, "work", "other@example.com", okTables, ErrInvalidIdentity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.original)
			err := AddIdentityTables(path, tc.alias, tc.def, tc.tables)
			if err == nil {
				t.Fatalf("AddIdentityTables: want an error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("AddIdentityTables: err = %v, want %v", err, tc.wantErr)
			}
			assertUnchanged(t, path, tc.original)
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatalf("read dir: %v", err)
			}
			if len(entries) != 1 {
				t.Errorf("directory holds %d entries after a refused splice, want 1", len(entries))
			}
		})
	}
}

// TestConfig_SpliceIdentitiesVerify checks the spliceIdentities op of
// verifySplice directly: a change of only Identity and DefaultIdentity
// passes, and a change of any other field of the account fails with
// ErrSpliceMismatch.
//
// arch: DI7.6, DI8 I7
func TestConfig_SpliceIdentitiesVerify(t *testing.T) {
	const orig = "[accounts.work]\nprovider = \"imap\"\nemail = \"me@example.com\"\n"
	ok := orig + "default_identity = \"me@example.com\"\n[[accounts.work.identity]]\nemail = \"me@example.com\"\n"
	if err := verifySplice([]byte(orig), []byte(ok), "work", spliceIdentities); err != nil {
		t.Errorf("identity-only change: err = %v, want nil", err)
	}
	bad := "[accounts.work]\nprovider = \"imap\"\nemail = \"you@example.com\"\n[[accounts.work.identity]]\nemail = \"me@example.com\"\n"
	if err := verifySplice([]byte(orig), []byte(bad), "work", spliceIdentities); !errors.Is(err, ErrSpliceMismatch) {
		t.Errorf("email change: err = %v, want ErrSpliceMismatch", err)
	}
	if err := verifySplice([]byte(orig), []byte(""), "work", spliceIdentities); !errors.Is(err, ErrSpliceMismatch) {
		t.Errorf("account removed: err = %v, want ErrSpliceMismatch", err)
	}
}

// TestAddIdentityTables_SignatureFileRelative checks that the strict
// load of the splice result resolves a relative signature_file against
// the directory of accounts.toml (DI1.7), and refuses when it is
// missing.
//
// arch: DI1.7, DI7.6
func TestAddIdentityTables_SignatureFileRelative(t *testing.T) {
	tables := "[[accounts.work.identity]]\nemail = \"a@example.com\"\nsignature_file = \"sig.txt\"\n"
	path := writeTemp(t, "[accounts.work]\nprovider = \"imap\"\nemail = \"me@example.com\"\n")
	if err := AddIdentityTables(path, "work", "", tables); err == nil {
		t.Fatal("AddIdentityTables accepted a missing signature file")
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "sig.txt"), []byte("Ann\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AddIdentityTables(path, "work", "", tables); err != nil {
		t.Fatalf("AddIdentityTables: %v", err)
	}
}
