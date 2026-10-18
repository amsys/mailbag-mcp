// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/undo"
	"github.com/amsys/mailbag-mcp/internal/verify"
)

// accessProv is a Writer that counts the work each tool asks of it.
// The embedded interface is nil, so a method these tests do not
// expect panics instead of answering in silence.
//
// The counters are what makes "permitted" and "denied" different
// facts: a denied call must leave every counter at zero, which proves
// the access check ran above the work and not after it.
type accessProv struct {
	Writer

	folders int
	searchs int
	reads   int
	raws    int
	atts    int
	sent    int
	drafts  int
	mods    int
	// settings counts the gmail.Settings calls of gmail_settings.
	settings int
}

func (p *accessProv) Folders(context.Context) ([]mail.Folder, error) {
	p.folders++
	return []mail.Folder{{Name: "INBOX", Role: "inbox", Total: 1}}, nil
}

func (p *accessProv) Search(context.Context, mail.Query) (mail.Page, error) {
	p.searchs++
	return mail.Page{Messages: []mail.Message{accessMessage()}}, nil
}

// Read gives accessMessage. When the caller asks for headers, as
// unsubscribe does (DS9.2), the message carries a one-click
// List-Unsubscribe pair, so the unsubscribe row of the matrix reaches
// its POST.
func (p *accessProv) Read(_ context.Context, _ string, o mail.ReadOpts) (*mail.Message, error) {
	p.reads++
	m := accessMessage()
	if len(o.Headers) > 0 {
		m.Headers = map[string][]string{
			hdrListUnsubscribe:     {"<https://list.example.test/u/1>"},
			hdrListUnsubscribePost: {oneClickBody},
		}
	}
	return &m, nil
}

func (p *accessProv) Raw(context.Context, string) ([]byte, error) {
	p.raws++
	return []byte("Subject: hello\r\n\r\nbody\r\n"), nil
}

func (p *accessProv) Attachment(context.Context, string, string) (io.ReadCloser, mail.AttachmentInfo, error) {
	p.atts++
	body := []byte("attached bytes")
	return io.NopCloser(bytes.NewReader(body)), mail.AttachmentInfo{Filename: "note.txt", Size: int64(len(body))}, nil
}

func (p *accessProv) SendDraft(context.Context, string) (mail.SendResult, error) {
	p.sent++
	return mail.SendResult{ID: "<sent@example.test>", Sent: true}, nil
}

func (p *accessProv) SaveDraft(context.Context, *mail.Outgoing, string) (string, error) {
	p.drafts++
	return "1700000000.9.Drafts", nil
}

func (p *accessProv) Modify(_ context.Context, ids []string, _ mail.Change) ([]mail.Applied, error) {
	p.mods++
	out := make([]mail.Applied, 0, len(ids))
	for _, id := range ids {
		out = append(out, mail.Applied{ID: id})
	}
	return out, nil
}

// ModifyDetail is the path of the modify tool. It counts in mods the
// same way Modify does, so the matrix sees one change per call.
func (p *accessProv) ModifyDetail(ctx context.Context, ids []string, ch mail.Change) (mail.ModifyResult, error) {
	applied, err := p.Modify(ctx, ids, ch)
	return mail.ModifyResult{Applied: applied}, err
}

// The gmail.Settings methods make accessProv a Gmail provider for the
// gmail_settings row. Each one counts in settings, so the matrix sees
// one settings call per permitted call.
var _ gmail.Settings = (*accessProv)(nil)

func (p *accessProv) ListFilters(context.Context) ([]gmail.Filter, error) {
	p.settings++
	return nil, nil
}

func (p *accessProv) CreateFilter(_ context.Context, f gmail.Filter) (gmail.Filter, error) {
	p.settings++
	f.ID = "f1"
	return f, nil
}

func (p *accessProv) DeleteFilter(context.Context, string) error {
	p.settings++
	return nil
}

func (p *accessProv) Vacation(context.Context) (gmail.Vacation, error) {
	p.settings++
	return gmail.Vacation{}, nil
}

func (p *accessProv) SetVacation(context.Context, gmail.Vacation) error {
	p.settings++
	return nil
}

func (p *accessProv) Signature(context.Context, string) (string, error) {
	p.settings++
	return "", nil
}

func (p *accessProv) SetSignature(context.Context, string, string) error {
	p.settings++
	return nil
}

// accessMessage is the one message every tool of the matrix reads.
func accessMessage() mail.Message {
	return mail.Message{
		ID:      "1.10.INBOX",
		Folder:  "INBOX",
		From:    mail.Address{Name: "Ann", Address: "ann@example.test"},
		Date:    time.Unix(1700000000, 0).UTC(),
		Subject: "hello",
		Body:    "body",
		Preview: "body",
	}
}

// accessMail is a Mail over one account whose access level the test
// picks.
type accessMail struct {
	alias string
	acct  config.Account
	prov  *accessProv
	dirs  []string
}

func (f *accessMail) Aliases() ([]string, error) { return []string{f.alias}, nil }
func (f *accessMail) AttachDirs() []string       { return f.dirs }
func (f *accessMail) DownloadDirs() []string     { return f.dirs }

func (f *accessMail) Open(ctx context.Context, alias string) (Reader, config.Account, error) {
	w, acct, err := f.OpenWriter(ctx, alias)
	return w, acct, err
}

func (f *accessMail) OpenWriter(_ context.Context, alias string) (Writer, config.Account, error) {
	if alias != f.alias {
		return nil, config.Account{}, fmt.Errorf("%w: %q", ErrUnknownAccount, alias)
	}
	return f.prov, f.acct, nil
}

// accessFixture holds one account at one access level, the fake
// provider every tool of the matrix calls, and the save directory the
// two save tools write into.
type accessFixture struct {
	mail    *accessMail
	prov    *accessProv
	saveDir string
	rows    int // accounts tool: the rows of the last call
	posts   int // unsubscribe tool: the one-click POSTs sent
}

// newAccessFixture builds one account of alias "work" at level.
//
// The account names an identity, so the from check of the send tool
// (M13) accepts the address the matrix sends from, and the matrix
// measures the access level and nothing else.
func newAccessFixture(t *testing.T, level guard.Level) *accessFixture {
	t.Helper()
	dir := t.TempDir()
	prov := &accessProv{}
	return &accessFixture{
		mail: &accessMail{
			alias: "work",
			prov:  prov,
			dirs:  []string{dir},
			acct: config.Account{
				Alias:    "work",
				Provider: "imap",
				Email:    "me@example.test",
				Access:   string(level),
			},
		},
		prov:    prov,
		saveDir: dir,
	}
}

// accessOutcome is what §3.17 says one tool does at one level.
type accessOutcome int

const (
	// accessPermitted: the tool ran and did its work.
	accessPermitted accessOutcome = iota
	// accessDenied: the tool refused with ErrAccessDenied and did no
	// work at all.
	accessDenied
)

// accessCase is one row of the matrix: one tool, what it does at each
// of the three levels, and how to see that it really ran.
type accessCase struct {
	tool string
	want map[guard.Level]accessOutcome
	// run calls the tool. It gives back the note of the result, which
	// only the draft, send and modify tools set.
	run func(ctx context.Context, fx *accessFixture) (string, error)
	// ran reports whether the provider did the work of this tool.
	ran func(fx *accessFixture) bool
}

// TestAccess_Matrix holds §3.17 and invariant 5 (§10.5) for every
// core tool at every access level: an account with access = "read"
// cannot change a mailbox, and an account with access = "draft"
// cannot send.
//
// The matrix checks two facts for each cell, not one. A refused call
// must return ErrAccessDenied *and* leave every provider counter at
// zero, which is what proves guard.Require is the first line of the
// handler and not a check that runs after the work. A permitted call
// must return no error *and* show the provider did the work, so a
// handler that returns an empty result without calling the mailbox
// cannot pass as "permitted".
//
// The extras list of §3.16 is not part of this test on purpose: it
// controls the size of the tool list, and the access level is the
// security control (G9). The four S9 tools have one row each (IS9.9).
// unsubscribe counts its one-click POSTs and templates its files in
// ran, because neither side effect is a provider call. A refused call
// must also leave ran false, so a refused unsubscribe sent no POST and
// a refused templates call wrote no file.
//
// Each cell points MAILBAG_CONFIG_DIR at its own directory, so no
// cell reads or writes the real config directory.
//
// arch: T5.4, §3.17, §9 U7, G9, D5, §10.5, §10.11, §5.3
// arch: DS9.8, DS9.9, IS9.8, IS9.9
func TestAccess_Matrix(t *testing.T) {
	always := map[guard.Level]accessOutcome{
		guard.LevelRead:  accessPermitted,
		guard.LevelDraft: accessPermitted,
		guard.LevelSend:  accessPermitted,
	}
	draftAndUp := map[guard.Level]accessOutcome{
		guard.LevelRead:  accessDenied,
		guard.LevelDraft: accessPermitted,
		guard.LevelSend:  accessPermitted,
	}
	sendOnly := map[guard.Level]accessOutcome{
		guard.LevelRead:  accessDenied,
		guard.LevelDraft: accessDenied,
		guard.LevelSend:  accessPermitted,
	}

	cases := []accessCase{{
		tool: "accounts",
		want: always,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			out, err := accountsHandler(nil)(ctx, AccountsIn{})
			fx.rows = len(out.Accounts)
			return "", err
		},
		ran: func(fx *accessFixture) bool { return fx.rows == 1 },
	}, {
		tool: "folders",
		want: always,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &foldersTool{mail: fx.mail}
			_, err := h.handle(ctx, FoldersIn{Account: "work"})
			return "", err
		},
		ran: func(fx *accessFixture) bool { return fx.prov.folders == 1 },
	}, {
		tool: "search",
		want: always,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &searchTool{mail: fx.mail}
			_, err := h.handle(ctx, SearchIn{Account: "work"})
			return "", err
		},
		ran: func(fx *accessFixture) bool { return fx.prov.searchs == 1 },
	}, {
		tool: "read",
		want: always,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &readTool{mail: fx.mail}
			_, err := h.handle(ctx, ReadIn{Account: "work", ID: "1.10.INBOX"})
			return "", err
		},
		ran: func(fx *accessFixture) bool { return fx.prov.reads == 1 },
	}, {
		tool: "attachment",
		want: always,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &attachmentTool{mail: fx.mail}
			_, err := h.handle(ctx, AttachmentIn{Account: "work", ID: "1.10.INBOX", Ref: "2", SaveDir: fx.saveDir})
			return "", err
		},
		ran: func(fx *accessFixture) bool { return fx.prov.atts == 1 },
	}, {
		tool: "export",
		want: always,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &exportTool{mail: fx.mail}
			_, err := h.handle(ctx, ExportIn{Account: "work", ID: "1.10.INBOX", SaveDir: fx.saveDir})
			return "", err
		},
		ran: func(fx *accessFixture) bool { return fx.prov.raws == 1 },
	}, {
		tool: "modify",
		want: draftAndUp,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &modifyTool{mail: fx.mail, journal: accessJournal(fx)}
			read := true
			out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"1.10.INBOX"}, Read: &read})
			return out.Note, err
		},
		ran: func(fx *accessFixture) bool { return fx.prov.mods == 1 },
	}, {
		tool: "draft",
		want: draftAndUp,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &draftTool{mail: fx.mail}
			out, err := h.handle(ctx, accessDraftIn())
			return out.Note, err
		},
		ran: func(fx *accessFixture) bool { return fx.prov.drafts == 1 && fx.prov.sent == 0 },
	}, {
		tool: "send a stored draft",
		want: map[guard.Level]accessOutcome{
			guard.LevelRead:  accessDenied,
			guard.LevelDraft: accessDenied,
			guard.LevelSend:  accessPermitted,
		},
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &sendTool{mail: fx.mail}
			out, err := h.handle(ctx, SendIn{Account: "work", DraftID: "1700000000.9.Drafts"})
			return out.Note, err
		},
		ran: func(fx *accessFixture) bool { return fx.prov.sent == 1 },
	}, {
		// G18: the whole tool is draft level. The dkim seam passes, so
		// the access level is the only thing that can stop the POST.
		tool: "unsubscribe",
		want: draftAndUp,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := newUnsubscribeTool(fx.mail)
			h.post = func(context.Context, string) (int, error) {
				fx.posts++
				return 200, nil
			}
			h.dkim = func(*mail.Message, verify.Config) bool { return true }
			_, err := h.handle(ctx, UnsubscribeIn{Account: "work", IDs: []string{"1.10.INBOX"}})
			return "", err
		},
		ran: func(fx *accessFixture) bool { return fx.posts == 1 },
	}, {
		tool: "bulk",
		want: draftAndUp,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &bulkTool{mail: fx.mail, journal: accessJournal(fx)}
			out, err := h.run(ctx, BulkIn{Account: "work", Action: "read"}, bulkAcceptAll)
			return out.Note, err
		},
		ran: func(fx *accessFixture) bool { return fx.prov.mods == 1 },
	}, {
		// G22: save needs draft; list (read) is not the row here.
		tool: "templates",
		want: draftAndUp,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &templatesTool{mail: fx.mail}
			out, err := h.handle(ctx, TemplatesIn{Account: "work", Action: "save", Name: "note", Subject: "hello", Body: "text"})
			return out.Note, err
		},
		ran: func(fx *accessFixture) bool {
			_, err := os.Stat(filepath.Join(fx.saveDir, templatesDirName, "note"+templateSuffix))
			return err == nil
		},
	}, {
		// G21: vacation on needs send, because Gmail then sends mail.
		tool: "gmail_settings",
		want: sendOnly,
		run: func(ctx context.Context, fx *accessFixture) (string, error) {
			h := &gmailSettingsTool{mail: fx.mail}
			on := true
			out, err := h.handle(ctx, GmailSettingsIn{Account: "work", Action: "set_vacation", Enabled: &on, Subject: "away", Body: "back soon"})
			return out.Note, err
		},
		// Two calls: set_vacation reads the current setting, then
		// writes it (R16-L7).
		ran: func(fx *accessFixture) bool { return fx.prov.settings == 2 },
	}}

	for _, level := range []guard.Level{guard.LevelRead, guard.LevelDraft, guard.LevelSend} {
		for _, c := range cases {
			t.Run(string(level)+"/"+c.tool, func(t *testing.T) {
				fx := newAccessFixture(t, level)
				t.Setenv("MAILBAG_CONFIG_DIR", fx.saveDir)
				if c.tool == "accounts" {
					accessWriteConfig(t, level)
				}
				_, err := c.run(context.Background(), fx)

				switch c.want[level] {
				case accessPermitted:
					if err != nil {
						t.Fatalf("access=%s: %s: %v, want the call to run", level, c.tool, err)
					}
					if !c.ran(fx) {
						t.Errorf("access=%s: %s returned no error but did no work; the result is empty, not permitted", level, c.tool)
					}
				case accessDenied:
					if !errors.Is(err, guard.ErrAccessDenied) {
						t.Fatalf("access=%s: %s gave %v, want ErrAccessDenied (§10.5)", level, c.tool, err)
					}
					if fx.prov.sent+fx.prov.drafts+fx.prov.mods+fx.prov.settings != 0 {
						t.Errorf("access=%s: %s wrote to the mailbox before it refused; the check must be the first line (§3.17)", level, c.tool)
					}
					if c.ran(fx) {
						t.Errorf("access=%s: %s refused but did its work (a POST, a file or a provider call); the check must be the first line (§3.17)", level, c.tool)
					}
				}
			})
		}
	}
}

// accessDraftIn builds the one message the matrix saves as a draft.
func accessDraftIn() DraftIn {
	return DraftIn{
		Account: "work",
		To:      []string{"her@example.test"},
		Subject: "hello",
		Body:    "text",
	}
}

// accessJournal gives the modify tool an undo journal under the
// fixture's own directory, so no test writes in the real state
// directory (§3.18).
func accessJournal(fx *accessFixture) func() (*undo.Journal, error) {
	j := undo.New(filepath.Join(fx.saveDir, "undo"))
	return func() (*undo.Journal, error) { return j, nil }
}

// accessWriteConfig puts one account at level in a temporary
// accounts.toml, because the accounts tool reads the file itself
// (§3.16) instead of taking a provider.
func accessWriteConfig(t *testing.T, level guard.Level) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MAILBAG_CONFIG_DIR", dir)
	toml := fmt.Sprintf(`
secrets = "file"

[accounts.work]
provider = "imap"
email    = "me@example.test"
access   = %q
`, level)
	if err := os.WriteFile(filepath.Join(dir, "accounts.toml"), []byte(toml), 0o600); err != nil {
		t.Fatalf("write accounts.toml: %v", err)
	}
}

// TestAccess_DraftFallbackSavesTheMessage holds the answer of
// §3.17 for a draft account after the draft and send split (D5.1).
// The draft tool saves the message, gives back the draft id, and its
// note names the level and the line of accounts.toml that permits
// sending. The send tool then refuses that draft id with
// ErrAccessDenied, so the message stays a draft and nothing leaves.
//
// The matrix above checks each tool alone. This test follows one
// message through both tools on one draft account.
//
// arch: T5.4, §3.17, §3.16, D5, D5.1, §10.5
func TestAccess_DraftFallbackSavesTheMessage(t *testing.T) {
	fx := newAccessFixture(t, guard.LevelDraft)
	ctx := context.Background()

	out, err := (&draftTool{mail: fx.mail}).handle(ctx, accessDraftIn())
	if err != nil {
		t.Fatalf("draft: %v", err)
	}
	if out.DraftID == "" {
		t.Error("DraftID is empty; §3.17 gives the caller the id of the saved draft")
	}
	if fx.prov.drafts != 1 {
		t.Fatalf("SaveDraft ran %d times, want 1", fx.prov.drafts)
	}
	if !strings.Contains(out.Note, out.DraftID) {
		t.Errorf("note %q does not name the draft id %q", out.Note, out.DraftID)
	}
	for _, want := range []string{"access=draft", `access = "send"`, "accounts.toml"} {
		if !strings.Contains(out.Note, want) {
			t.Errorf("note %q holds no %q; §3.17 names the level and the fix", out.Note, want)
		}
	}

	_, err = (&sendTool{mail: fx.mail}).handle(ctx, SendIn{Account: "work", DraftID: out.DraftID})
	if !errors.Is(err, guard.ErrAccessDenied) {
		t.Fatalf("send on a draft account gave %v, want ErrAccessDenied (D5.1)", err)
	}
	if !strings.Contains(err.Error(), `access = "send"`) {
		t.Errorf("the refusal %q does not name the accounts.toml line that permits sending", err)
	}
	if fx.prov.sent != 0 {
		t.Errorf("a draft account sent %d messages (§10.5)", fx.prov.sent)
	}
}
