// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of "mailbag-mcp identities detect <alias>" (DI7): the Sent-mail
// analysis, the vote, the merge with the provider signature, the TOML
// proposal and the "yes" gate before the write.

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/tools"
)

// fakeSent is a network-free [tools.Reader] with one Sent folder. It
// records the search query and the read options that detect uses.
type fakeSent struct {
	folders []mail.Folder
	msgs    []mail.Message
	query   *mail.Query
	opts    []mail.ReadOpts
}

func (f *fakeSent) Folders(context.Context) ([]mail.Folder, error) { return f.folders, nil }

func (f *fakeSent) Search(_ context.Context, q mail.Query) (mail.Page, error) {
	f.query = &q
	var rows []mail.Message
	for _, m := range f.msgs {
		if len(rows) == q.Limit {
			break
		}
		rows = append(rows, mail.Message{ID: m.ID, From: m.From, Date: m.Date})
	}
	return mail.Page{Messages: rows}, nil
}

func (f *fakeSent) Read(_ context.Context, id string, o mail.ReadOpts) (*mail.Message, error) {
	f.opts = append(f.opts, o)
	for _, m := range f.msgs {
		if m.ID == id {
			c := m
			return &c, nil
		}
	}
	return nil, errors.New("no such message")
}

func (f *fakeSent) Thread(context.Context, string) (mail.ThreadResult, error) {
	return mail.ThreadResult{}, errors.New("not used")
}

func (f *fakeSent) Raw(context.Context, string) ([]byte, error) { return nil, errors.New("not used") }

func (f *fakeSent) Attachment(context.Context, string, string) (io.ReadCloser, mail.AttachmentInfo, error) {
	return nil, mail.AttachmentInfo{}, errors.New("not used")
}

// fakeSentSource adds the provider identities of [tools.IdentitySource].
type fakeSentSource struct {
	*fakeSent
	ids []mail.ProviderIdentity
}

func (f fakeSentSource) ProviderIdentities(context.Context) ([]mail.ProviderIdentity, error) {
	return f.ids, nil
}

// sentFolders is a folder list with a Sent folder.
var sentFolders = []mail.Folder{{Name: "INBOX", Role: "inbox"}, {Name: "Sent Items", Role: "sent"}}

// sentMsg builds the i-th Sent mail from addr with body. A mailbag
// mail gets a Message-ID of 32 hex digits.
func sentMsg(i int, addr, body string, mailbag bool) mail.Message {
	id := fmt.Sprintf("<CAF%d.person@mail.example.com>", i)
	if mailbag {
		id = fmt.Sprintf("<%032x@example.com>", i+1)
	}
	return mail.Message{
		ID:        fmt.Sprintf("Sent Items:%d", i+1),
		Folder:    "Sent Items",
		From:      mail.Address{Name: "Ann Example", Address: addr},
		Date:      time.Date(2026, 8, 1+i, 9, 0, 0, 0, time.UTC),
		Body:      body,
		MessageID: id,
		Headers:   map[string][]string{"Message-ID": {id}},
	}
}

// detectRun runs "identities detect" against p with the config of the
// sandbox. answer is what the terminal gives; a nil readLine fails the
// test when detect asks.
func detectRun(t *testing.T, p tools.Reader, readLine func(string) (string, error), args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	if readLine == nil {
		readLine = func(string) (string, error) {
			t.Errorf("detect asked for an answer, but it must not ask here")
			return "", errors.New("not asked")
		}
	}
	env := Env{
		Stdout:   &out,
		Stderr:   &errOut,
		ReadLine: readLine,
		OpenAccount: func(_ context.Context, alias string) (tools.Reader, config.Account, func(), error) {
			path, err := config.AccountsPath()
			if err != nil {
				return nil, config.Account{}, nil, err
			}
			cfg, err := config.Load(path)
			if err != nil {
				return nil, config.Account{}, nil, err
			}
			acct, ok := cfg.Account(alias)
			if !ok {
				return nil, config.Account{}, nil, fmt.Errorf("no account %q", alias)
			}
			return p, acct, func() {}, nil
		},
	}
	code := Run(append([]string{"identities", "detect"}, args...), env)
	return code, out.String(), errOut.String()
}

// answer gives a ReadLine that types s.
func answer(s string) func(string) (string, error) {
	return func(string) (string, error) { return s, nil }
}

// noisySignature is the owner's signature with one empty line between
// its two paragraphs. Each mail gets a different white-space noise in
// that empty line, as an HTML-to-text conversion gives it.
const wantSignature = "Thanking you in anticipation,\nYours faithfully,\n\nAnn Example\nExample Rental Ltd"

func noisyBody(noise string) string {
	return "Dear Sir,\n" + noise + "\nPlease find the invoice attached.\n\n-- \n" +
		"Thanking you in anticipation,\nYours faithfully,\n" + noise + "\nAnn Example\nExample Rental Ltd\n" + noise + "\n"
}

// TestIdentitiesDetect_WhitespaceNoiseKeepsOneEmptyLine checks a Sent
// sample whose signature has white-space-only lines (HTML-to-text
// noise) that differ from mail to mail. All mails agree once such a
// line is an empty line, so the proposal holds the signature with
// exactly one empty line between its paragraphs. After "yes" the file
// loads, keeps its comment, and the identity holds that exact
// signature. The search and read have the DI7.2 shape, and the
// proposal has no compose_html key.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_WhitespaceNoiseKeepsOneEmptyLine(t *testing.T) {
	dir := sandbox(t)
	path := seedAccount(t, dir, "work")

	noise := []string{" ", "\u00a0", "\t", " \u00a0 ", "", "   \t"}
	p := &fakeSent{folders: sentFolders}
	for i, n := range noise {
		body := noisyBody(n)
		if i%2 == 1 {
			body = strings.ReplaceAll(body, "\n", "\r\n")
		}
		p.msgs = append(p.msgs, sentMsg(i, "me@example.com", body, false))
	}

	code, out, errOut := detectRun(t, p, answer("yes"), "work", "--sample", "20")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, out, errOut)
	}
	wantLine := `signature = "Thanking you in anticipation,\nYours faithfully,\n\nAnn Example\nExample Rental Ltd"`
	if !strings.Contains(out, wantLine) {
		t.Errorf("proposal lacks %s\nstdout:\n%s", wantLine, out)
	}
	if !strings.Contains(out, "# 6 of 6 sent mails, 2026-08-01..2026-08-06\n"+wantLine) {
		t.Errorf("signature has no evidence comment above it\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "    | (empty line)") {
		t.Errorf("the empty line of the signature has no visible mark\nstdout:\n%s", out)
	}
	if strings.Contains(out, "compose_html") {
		t.Errorf("proposal holds compose_html, which detect must leave out (DI7.3 item 6)\nstdout:\n%s", out)
	}

	if p.query == nil || p.query.Folder != "Sent Items" || p.query.Limit != 20 || p.query.Raw != "" {
		t.Errorf("search query = %+v, want Folder %q, Limit 20, empty Raw", p.query, "Sent Items")
	}
	for _, o := range p.opts {
		if o.Format != "text" || o.MaxChars != 20000 || len(o.Headers) != 1 || o.Headers[0] != "Message-ID" {
			t.Errorf("read options = %+v, want Format text, MaxChars 20000, Headers [Message-ID]", o)
		}
	}

	text := readFile(t, path)
	if !strings.Contains(text, "# a comment a person wrote") {
		t.Errorf("the write lost a comment:\n%s", text)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load after the write: %v\n%s", err, text)
	}
	acct, _ := cfg.Account("work")
	id, ok := acct.Identity("me@example.com")
	if !ok {
		t.Fatalf("no identity me@example.com after the write:\n%s", text)
	}
	if id.Signature != wantSignature {
		t.Errorf("signature = %q, want %q", id.Signature, wantSignature)
	}
	if strings.Count(id.Signature, "\n\n") != 1 || strings.Contains(id.Signature, "\n\n\n") {
		t.Errorf("signature %q does not hold exactly one empty line between paragraphs", id.Signature)
	}
	if id.ComposeHTML {
		t.Errorf("compose_html = true, want the default false")
	}
}

// agreeingSample gives a Sent folder with 6 mails from me@example.com
// that all carry wantSignature.
func agreeingSample() *fakeSent {
	p := &fakeSent{folders: sentFolders}
	for i := 0; i < 6; i++ {
		p.msgs = append(p.msgs, sentMsg(i, "me@example.com", noisyBody(""), false))
	}
	return p
}

// TestIdentitiesDetect_YesGate checks that only the exact word "yes"
// writes. Any other answer, and a stdin that is not a terminal, print
// the proposal and leave the file byte for byte as it was.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_YesGate(t *testing.T) {
	cases := []struct {
		name    string
		read    func(string) (string, error)
		writes  bool
		wantOut string
	}{
		{"y", answer("y"), false, "nothing written"},
		{"upper case", answer("YES"), false, "nothing written"},
		{"more words", answer("yes please"), false, "nothing written"},
		{"no", answer("no"), false, "nothing written"},
		{"empty", answer(""), false, "nothing written"},
		{"pipe", func(string) (string, error) { return "", errNotTerminal }, false, "stdin is not a terminal; nothing written"},
		{"spaces round yes", answer("  yes  "), true, "written to"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := sandbox(t)
			path := seedAccount(t, dir, "work")
			before := readFile(t, path)

			var prompt string
			read := func(s string) (string, error) {
				prompt = s
				return tc.read(s)
			}
			code, out, errOut := detectRun(t, agreeingSample(), read, "work")
			if code != exitOK {
				t.Fatalf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
			}
			if want := "Write this to " + path + "? Type yes: "; prompt != want {
				t.Errorf("prompt = %q, want %q", prompt, want)
			}
			if !strings.Contains(out, "[[accounts.work.identity]]") {
				t.Errorf("the proposal was not printed:\n%s", out)
			}
			if !strings.Contains(out, tc.wantOut) {
				t.Errorf("stdout lacks %q:\n%s", tc.wantOut, out)
			}
			after := readFile(t, path)
			if tc.writes {
				if after == before {
					t.Errorf("answer %q wrote nothing", tc.name)
				}
				if _, err := config.Load(path); err != nil {
					t.Errorf("the written file fails the strict load: %v", err)
				}
			} else if after != before {
				t.Errorf("answer %q changed the file:\n%s", tc.name, after)
			}
		})
	}
}

// TestIdentitiesDetect_ExistingSettingsWriteNothing checks that an
// account that already has an identity table, or only a
// default_identity, gets the proposal printed, no question, and no
// write.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_ExistingSettingsWriteNothing(t *testing.T) {
	extras := map[string]string{
		"table":            "\n[[accounts.work.identity]]\nemail = \"me@example.com\"\n",
		"default_identity": "default_identity = \"me@example.com\"\n",
	}
	for name, extra := range extras {
		t.Run(name, func(t *testing.T) {
			dir := sandbox(t)
			path := seedAccount(t, dir, "work")
			if err := os.WriteFile(path, []byte(readFile(t, path)+extra), 0o600); err != nil {
				t.Fatal(err)
			}
			before := readFile(t, path)

			code, out, errOut := detectRun(t, agreeingSample(), nil, "work")
			if code != exitOK {
				t.Fatalf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
			}
			if !strings.Contains(out, "[[accounts.work.identity]]") {
				t.Errorf("the proposal was not printed:\n%s", out)
			}
			if !strings.Contains(out, "Edit accounts.toml by hand.") {
				t.Errorf("stdout does not tell to edit by hand:\n%s", out)
			}
			if after := readFile(t, path); after != before {
				t.Errorf("the file changed:\n%s", after)
			}
		})
	}
}

// mailsWith gives n sent mails of addr; the first agree of them carry
// signature sig and the others carry a signature of their own.
func mailsWith(addr, sig string, agree, n int) []sentMail {
	var ms []sentMail
	for i := 0; i < n; i++ {
		block := sig
		if i >= agree {
			block = fmt.Sprintf("Other %d", i)
		}
		ms = append(ms, sentMail{
			addr:  addr,
			date:  time.Date(2026, 9, 1+i, 0, 0, 0, 0, time.UTC),
			shape: mailShape{block: block},
		})
	}
	return ms
}

// TestIdentitiesDetect_VoteThresholds checks the DI7.3 item 4 vote: a
// block is proposed only when its group holds at least 60 % of the
// mails of the address and at least 5 mails. Otherwise the proposal
// has no signature and the largest groups are shown.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_VoteThresholds(t *testing.T) {
	t.Parallel()
	acct := config.Account{Email: "me@example.com"}
	cases := []struct {
		agree, total int
		want         bool
	}{
		{4, 4, false},   // fewer than 5 mails
		{5, 5, true},    // 100 %
		{5, 9, false},   // 55 %
		{6, 10, true},   // 60 %
		{5, 8, true},    // 62 %
		{11, 20, false}, // 55 %
	}
	for _, tc := range cases {
		prop := buildProposal(acct, "work", nil, mailsWith("me@example.com", "Ann", tc.agree, tc.total))
		if len(prop.tables) != 1 {
			t.Fatalf("%d of %d: %d tables, want 1", tc.agree, tc.total, len(prop.tables))
		}
		got := prop.tables[0].sig == "Ann"
		if got != tc.want {
			t.Errorf("%d of %d: proposed = %v, want %v (why: %s)", tc.agree, tc.total, got, tc.want, prop.tables[0].sigWhy)
		}
		if !tc.want {
			if strings.Contains(prop.tablesText(), "signature =") {
				t.Errorf("%d of %d: TOML holds a signature:\n%s", tc.agree, tc.total, prop.tablesText())
			}
			if !strings.Contains(strings.Join(prop.render(), "\n"), "signature group 1 of me@example.com") {
				t.Errorf("%d of %d: the largest group is not shown:\n%s", tc.agree, tc.total, strings.Join(prop.render(), "\n"))
			}
		}
	}
}

// TestIdentitiesDetect_SkipsMailbagMails checks that a mail with a
// mailbag Message-ID never counts in the vote (DI7.2): six mailbag
// mails with a near copy lose against five mails a person sent.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_SkipsMailbagMails(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	p := &fakeSent{folders: sentFolders}
	for i := 0; i < 6; i++ {
		p.msgs = append(p.msgs, sentMsg(i, "me@example.com", "Hi\n\n-- \nThanking you in anticipation,\nYours faithfully,\nAnn Example", true))
	}
	for i := 6; i < 11; i++ {
		p.msgs = append(p.msgs, sentMsg(i, "me@example.com", noisyBody(""), false))
	}

	code, out, errOut := detectRun(t, p, answer("no"), "work")
	if code != exitOK {
		t.Fatalf("exit code = %d\nstderr:\n%s", code, errOut)
	}
	if !strings.Contains(out, "5 mails read, 6 made by mailbag and skipped") {
		t.Errorf("stdout does not count the skipped mails:\n%s", out)
	}
	if !strings.Contains(out, "# 5 of 5 sent mails") || !strings.Contains(out, `Yours faithfully,\n\nAnn Example`) {
		t.Errorf("the vote did not elect the mails a person sent:\n%s", out)
	}
}

// TestIdentitiesDetect_MergeProvider checks the DI7.4 merge of the
// provider signature with the Sent-mail vote, the gmail_settings label
// and the source of signature_html.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_MergeProvider(t *testing.T) {
	t.Parallel()
	acct := config.Account{Email: "me@example.com"}
	gmailID := func(text, html string) []mail.ProviderIdentity {
		return []mail.ProviderIdentity{{Email: "me@example.com", Name: "Example Rental", TextSignature: text, HTMLSignature: html, Default: true, Source: "gmail sendAs"}}
	}

	t.Run("differ", func(t *testing.T) {
		prop := buildProposal(acct, "work", gmailID("Ann\nExample Rental", "Ann<br>Example Rental"), mailsWith("me@example.com", "Ann Example", 5, 5))
		toml := prop.tablesText()
		if strings.Contains(toml, "signature =") || strings.Contains(toml, "signature_html =") {
			t.Errorf("a signature was proposed although provider and vote differ:\n%s", toml)
		}
		shown := strings.Join(prop.render(), "\n")
		for _, want := range []string{"provider signature of me@example.com (gmail sendAs (" + gmailSettingsLabel + "))", "    | Example Rental", "Sent-mail signature of me@example.com (5 of 5 sent mails", "    | Ann Example"} {
			if !strings.Contains(shown, want) {
				t.Errorf("output lacks %q:\n%s", want, shown)
			}
		}
	})

	t.Run("provider only", func(t *testing.T) {
		prop := buildProposal(acct, "work", gmailID("Ann\nExample Rental", "Ann<br>Example Rental"), mailsWith("me@example.com", "", 5, 5))
		toml := prop.tablesText()
		want := "# gmail sendAs (" + gmailSettingsLabel + ")\nsignature = \"Ann\\nExample Rental\"\n"
		if !strings.Contains(toml, want) {
			t.Errorf("TOML lacks %q:\n%s", want, toml)
		}
		if !strings.Contains(toml, "signature_html = \"Ann<br>Example Rental\"") {
			t.Errorf("TOML lacks the provider signature_html:\n%s", toml)
		}
		if !strings.Contains(toml, "# gmail sendAs\nname = \"Example Rental\"") {
			t.Errorf("TOML lacks the provider name:\n%s", toml)
		}
	})

	t.Run("agree", func(t *testing.T) {
		prop := buildProposal(acct, "work", gmailID("Ann\nExample Rental", ""), mailsWith("me@example.com", "Ann\nExample Rental", 5, 6))
		toml := prop.tablesText()
		if !strings.Contains(toml, "# 5 of 6 sent mails, 2026-09-01..2026-09-05; gmail sendAs ("+gmailSettingsLabel+")\nsignature = ") {
			t.Errorf("TOML lacks the joined evidence:\n%s", toml)
		}
	})

	t.Run("html with no exact text", func(t *testing.T) {
		prop := buildProposal(acct, "work", gmailID("", `<div dir="ltr">Ann</div>`), mailsWith("me@example.com", "Ann Example", 5, 5))
		toml := prop.tablesText()
		if !strings.Contains(toml, "# 5 of 5 sent mails, 2026-09-01..2026-09-05\nsignature = \"Ann Example\"") {
			t.Errorf("TOML lacks the voted signature:\n%s", toml)
		}
		if strings.Contains(toml, "signature_html =") {
			t.Errorf("signature_html was proposed from HTML with no exact text form:\n%s", toml)
		}
	})

	t.Run("unclean html", func(t *testing.T) {
		ids := []mail.ProviderIdentity{{Email: "me@example.com", TextSignature: "Ann", HTMLSignature: `<p style="color:red">Ann</p>`, Source: "jmap Identity"}}
		prop := buildProposal(acct, "work", ids, nil)
		toml := prop.tablesText()
		if !strings.Contains(toml, "# jmap Identity\nsignature = \"Ann\"") {
			t.Errorf("TOML lacks the JMAP signature with its source:\n%s", toml)
		}
		if strings.Contains(toml, "signature_html =") || !strings.Contains(toml, "# signature_html: not proposed: the provider HTML holds markup") {
			t.Errorf("unclean signature_html was not refused:\n%s", toml)
		}
		if strings.Contains(toml, gmailSettingsLabel) {
			t.Errorf("a JMAP signature carries the gmail label:\n%s", toml)
		}
	})
}

// TestIdentitiesDetect_AnalyseBody checks the own region, the
// signature block and the reply layout of one body (DI7.3 items 1, 2,
// 3 and 5).
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_AnalyseBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want mailShape
	}{
		{"new mail", "Hi\n\n-- \nSig\n", mailShape{block: "Sig", above: true}},
		{"no delimiter", "Hi\n\nAnn\n", mailShape{above: true}},
		{"bare dashes", "Hi\n--\nSig", mailShape{block: "Sig", above: true}},
		{"last delimiter wins", "Hi\n-- \nOld\n\n-- \nSig", mailShape{block: "Sig", above: true}},
		{"signature above quote",
			"Reply\n\n-- \nSig\n\nOn Mon, 1 Oct 2026, Ann wrote:\n> q\n> -- \n> Ann",
			mailShape{block: "Sig", hasQuote: true, above: true}},
		{"signature below quote",
			"Reply\n\nOn Mon, 1 Oct 2026, Ann <a@example.org> wrote:\n> q\n\n-- \nSig\n",
			mailShape{block: "Sig", hasQuote: true, above: true, sigAfter: true}},
		{"own text below quote, wrapped attribution",
			"On Mon, 1 Oct 2026 at 10:00, Ann\n<a@example.org> wrote:\n\n> q\n> r\n\nReply\n\n-- \nSig",
			mailShape{block: "Sig", hasQuote: true, below: true, sigAfter: true}},
		{"quote only has a delimiter", "> -- \n> Ann", mailShape{hasQuote: true}},
		{"forward block is not own text",
			"FYI\n\n-- \nSig\n\n---------- Forwarded message ---------\nFrom: x\n\n-- \nOther",
			mailShape{block: "Sig", above: true}},
		{"forward, no own signature",
			"FYI\n\nBegin forwarded message:\n\n-- \nOther", mailShape{above: true}},
		{"white space line in block", "Hi\n-- \nA\n \u00a0\t\nB\n\u00a0\n", mailShape{block: "A\n\nB", above: true}},
	}
	for _, tc := range cases {
		if got := analyseBody(tc.body); got != tc.want {
			t.Errorf("%s: analyseBody = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// layoutMails gives n mails with a quote and the shape s.
func layoutMails(n int, s mailShape) []sentMail {
	var ms []sentMail
	for i := 0; i < n; i++ {
		ms = append(ms, sentMail{addr: "me@example.com", shape: s})
	}
	return ms
}

// TestIdentitiesDetect_LayoutVote checks the reply_above_quote and
// signature_below_quote votes (DI7.3 item 5): the majority, with at
// least 5 mails, else the key is left out.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_LayoutVote(t *testing.T) {
	t.Parallel()
	acct := config.Account{Email: "me@example.com"}
	top := mailShape{block: "Sig", hasQuote: true, above: true}
	topSigBelow := mailShape{block: "Sig", hasQuote: true, above: true, sigAfter: true}
	bottom := mailShape{block: "Sig", hasQuote: true, below: true, sigAfter: true}

	toml := buildProposal(acct, "work", nil, layoutMails(5, top)).tablesText()
	if !strings.Contains(toml, "\nreply_above_quote = true\n") || !strings.Contains(toml, "\nsignature_below_quote = false\n") {
		t.Errorf("top posting: TOML = \n%s", toml)
	}

	toml = buildProposal(acct, "work", nil, append(layoutMails(6, topSigBelow), layoutMails(1, top)...)).tablesText()
	if !strings.Contains(toml, "\nreply_above_quote = true\n") || !strings.Contains(toml, "\nsignature_below_quote = true\n") {
		t.Errorf("signature below the quote: TOML = \n%s", toml)
	}

	toml = buildProposal(acct, "work", nil, layoutMails(5, bottom)).tablesText()
	if !strings.Contains(toml, "\nreply_above_quote = false\n") || strings.Contains(toml, "signature_below_quote") {
		t.Errorf("bottom posting: TOML = \n%s", toml)
	}

	toml = buildProposal(acct, "work", nil, layoutMails(4, top)).tablesText()
	if strings.Contains(toml, "reply_above_quote =") || !strings.Contains(toml, "# reply_above_quote: not proposed") {
		t.Errorf("4 mails: TOML = \n%s", toml)
	}
}

// TestIdentitiesDetect_ForeignAddressNotProposed checks that a Sent
// address that the account does not own gets no table, so detect never
// widens the From check (I6). With only such mails, nothing is
// proposed and nothing is asked.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_ForeignAddressNotProposed(t *testing.T) {
	dir := sandbox(t)
	path := seedAccount(t, dir, "work")
	before := readFile(t, path)
	p := &fakeSent{folders: sentFolders}
	for i := 0; i < 5; i++ {
		p.msgs = append(p.msgs, sentMsg(i, "boss@other.example", noisyBody(""), false))
	}
	code, out, errOut := detectRun(t, p, nil, "work")
	if code != exitOK {
		t.Fatalf("exit code = %d\nstderr:\n%s", code, errOut)
	}
	if !strings.Contains(out, `"boss@other.example": 5 sent mails, but it is not an address of account "work"; not proposed`) {
		t.Errorf("stdout does not name the foreign address:\n%s", out)
	}
	if strings.Contains(out, "[[accounts.work.identity]]") || !strings.Contains(out, "nothing to propose; nothing written") {
		t.Errorf("a table was proposed for a foreign address:\n%s", out)
	}
	if readFile(t, path) != before {
		t.Errorf("the file changed")
	}
}

// TestIdentitiesDetect_DefaultIdentity checks that two identities get
// a default_identity (the provider default), that the write puts it in
// the account table, and that the result passes the strict load.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_DefaultIdentity(t *testing.T) {
	dir := sandbox(t)
	path := seedAccount(t, dir, "work")
	p := fakeSentSource{
		fakeSent: agreeingSample(),
		ids: []mail.ProviderIdentity{
			{Email: "me@example.com", Name: "Ann", Source: "gmail sendAs"},
			{Email: "sales@example.com", Name: "Sales", TextSignature: "Sales team", Default: true, Source: "gmail sendAs"},
		},
	}
	code, out, errOut := detectRun(t, p, answer("yes"), "work")
	if code != exitOK {
		t.Fatalf("exit code = %d\nstderr:\n%s\nstdout:\n%s", code, errOut, out)
	}
	if !strings.Contains(out, "# gmail sendAs marks it as the default\ndefault_identity = \"sales@example.com\"") {
		t.Errorf("stdout lacks the default_identity proposal:\n%s", out)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, readFile(t, path))
	}
	acct, _ := cfg.Account("work")
	if acct.DefaultIdentity != "sales@example.com" || acct.Default().Signature != "Sales team" {
		t.Errorf("default = %q with signature %q", acct.DefaultIdentity, acct.Default().Signature)
	}
	if id, _ := acct.Identity("me@example.com"); id.Signature != wantSignature || id.Name != "Ann" {
		t.Errorf("me@example.com = %+v", id)
	}
}

// TestIdentitiesDetect_TOMLStringExact checks that a proposed value
// goes into the TOML as a basic string that decodes to the same bytes,
// and that the printed proposal holds no raw invisible character.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_TOMLStringExact(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		wantSignature,
		"quote \" and \\ back",
		"tab\there, nbsp\u00a0here, trailing  ",
		"zero\u200bwidth \u202eoverride\u202c end",
		"emoji \U0001F600 and tag \U000E0041",
	} {
		enc := tomlString(s)
		if strings.ContainsAny(enc, "\n\t\u00a0\u200b\u202e\U000E0041") {
			t.Errorf("tomlString(%q) = %s holds a raw invisible character", s, enc)
		}
		var v struct{ S string }
		if _, err := toml.Decode("S = "+enc, &v); err != nil {
			t.Errorf("decode %s: %v", enc, err)
			continue
		}
		if v.S != s {
			t.Errorf("round trip of %q gave %q", s, v.S)
		}
	}

	acct := config.Account{Email: "me@example.com"}
	prop := buildProposal(acct, "work", nil, mailsWith("me@example.com", "Ann\u202e Example  ", 5, 5))
	shown := strings.Join(prop.render(), "\n")
	if strings.ContainsRune(shown, '\u202e') {
		t.Errorf("the output holds a raw U+202E:\n%s", shown)
	}
	if !strings.Contains(shown, "    | Ann Example  (+2 trailing white space)") {
		t.Errorf("trailing spaces have no visible mark:\n%s", shown)
	}
}

// TestIdentitiesDetect_NoSentFolder checks that an account with no
// folder of role sent fails with a hint to set folders.sent (DI7.2).
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_NoSentFolder(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	p := &fakeSent{folders: []mail.Folder{{Name: "INBOX", Role: "inbox"}}}
	code, _, errOut := detectRun(t, p, nil, "work")
	if code != exitFail {
		t.Fatalf("exit code = %d, want %d", code, exitFail)
	}
	if !strings.Contains(errOut, "set folders.sent for account \"work\"") {
		t.Errorf("stderr lacks the folders.sent hint:\n%s", errOut)
	}
	if p.query != nil {
		t.Errorf("detect searched with no Sent folder")
	}
}

// TestIdentitiesDetect_UsageErrors checks the command line of DI7.1:
// an alias first, --sample from 1 to 100, no other argument. A usage
// error opens no account.
//
// arch: DI7.1, DI7.2, DI7.3, DI7.4, DI7.5, DI7.6
func TestIdentitiesDetect_UsageErrors(t *testing.T) {
	sandbox(t)
	for _, args := range [][]string{
		{"identities"},
		{"identities", "list"},
		{"identities", "detect"},
		{"identities", "detect", "--sample", "5"},
		{"identities", "detect", "work", "--sample", "0"},
		{"identities", "detect", "work", "--sample", "101"},
		{"identities", "detect", "work", "extra"},
		{"identities", "detect", "../work"},
	} {
		var out, errOut bytes.Buffer
		opened := false
		env := Env{Stdout: &out, Stderr: &errOut, OpenAccount: func(context.Context, string) (tools.Reader, config.Account, func(), error) {
			opened = true
			return nil, config.Account{}, nil, errors.New("not used")
		}}
		if code := Run(args, env); code != exitUsage {
			t.Errorf("%q: exit code = %d, want %d", args, code, exitUsage)
		}
		if !strings.HasPrefix(errOut.String(), "usage:") || !strings.Contains(errOut.String(), "identities detect <alias> [--sample N]") {
			t.Errorf("%q: stderr has no usage block with the detect line:\n%s", args, errOut.String())
		}
		if opened {
			t.Errorf("%q: a usage error opened the account", args)
		}
	}
}
