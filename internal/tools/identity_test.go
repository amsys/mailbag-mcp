// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the identity pick of the draft tool (DI2): the pick rules,
// the one read of the original with the delivery headers, the Note
// sentence and the reply-all drop list.
package tools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// identityTOML is an account in identity mode. It has a flat entry
// with no table, a default_identity, an identity with no name and a
// catch-all pattern, so each pick rule has an input.
const identityTOML = `secrets = "file"

[accounts.work]
provider = "imap"
email = "me@example.test"
imap = "127.0.0.1:1"
smtp = "127.0.0.1:2"
identities = ["Flat Name <flat@example.test>"]
default_identity = "sales@example.test"

[[accounts.work.identity]]
email = "me@example.test"
name = "Me Person"

[[accounts.work.identity]]
email = "sales@example.test"
name = "Sales Team"

[[accounts.work.identity]]
email = "support@example.test"
name = "Support"
reply_match = ["*@shop.test"]
`

// plainTOML is the same account with no identity table and no
// default_identity, so it is not in identity mode (DI2.0).
const plainTOML = `secrets = "file"

[accounts.work]
provider = "imap"
email = "me@example.test"
imap = "127.0.0.1:1"
smtp = "127.0.0.1:2"
identities = ["Flat Name <flat@example.test>"]
`

// loadAccount loads body through the real config loader, so the
// identity list is the merged list of DI1.5 and not a hand-made one.
func loadAccount(t *testing.T, body string) config.Account {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	acct, ok := cfg.Account("work")
	if !ok {
		t.Fatal("no account work")
	}
	return acct
}

// readRecorder is a write provider that records the options of each
// Read, so a test can count the reads of the original.
type readRecorder struct {
	*writeProvider
	reads []mail.ReadOpts
}

func (p *readRecorder) Read(ctx context.Context, id string, opts mail.ReadOpts) (*mail.Message, error) {
	p.reads = append(p.reads, opts)
	return p.writeProvider.Read(ctx, id, opts)
}

// identityMail is a Mail whose OpenWriter gives one provider and one
// loaded account.
type identityMail struct {
	prov Writer
	acct config.Account
}

func (f *identityMail) Aliases() ([]string, error) { return []string{"work"}, nil }

func (f *identityMail) DownloadDirs() []string { return nil }

func (f *identityMail) AttachDirs() []string { return nil }

func (f *identityMail) Open(ctx context.Context, alias string) (Reader, config.Account, error) {
	return f.OpenWriter(ctx, alias)
}

func (f *identityMail) OpenWriter(_ context.Context, alias string) (Writer, config.Account, error) {
	if alias != "work" {
		return nil, config.Account{}, ErrUnknownAccount
	}
	return f.prov, f.acct, nil
}

// identityDraft builds a draft handler over an account loaded from
// body and a provider that gives orig to each Read.
func identityDraft(t *testing.T, body string, orig *mail.Message) (*draftTool, *readRecorder) {
	t.Helper()
	if orig == nil {
		orig = &mail.Message{}
	}
	rec := &readRecorder{writeProvider: &writeProvider{msg: orig, draftID: "d1"}}
	return &draftTool{mail: &identityMail{prov: rec, acct: loadAccount(t, body)}}, rec
}

// TestPickIdentity_Rules holds the pick order of DI2.2: an explicit
// from, then an exact identity email in To, Cc and the delivery
// headers, then a reply_match pattern, then the default. It also
// holds I6: an explicit from is an identity email, or on a reply the
// catch-all address that rule 3 picks, and nothing else.
//
// arch: DI2.0, DI2.1, DI2.2, DI2.3, DI2.4, DI6.1
func TestPickIdentity_Rules(t *testing.T) {
	acct := loadAccount(t, identityTOML)
	if !acct.IdentityMode() {
		t.Fatal("the fixture account is not in identity mode")
	}
	addrs := func(list ...string) []mail.Address {
		out := make([]mail.Address, 0, len(list))
		for _, a := range list {
			out = append(out, mail.Address{Address: a})
		}
		return out
	}
	cases := []struct {
		name   string
		from   string
		orig   *mail.Message
		ident  string
		addr   string
		header string
		reason string
		refuse bool
	}{
		{
			name:  "new draft takes the default identity",
			ident: "sales@example.test", addr: "sales@example.test",
			header: `"Sales Team" <sales@example.test>`, reason: "default",
		},
		{
			name: "explicit bare from gets the identity name",
			from: "me@example.test", ident: "me@example.test", addr: "me@example.test",
			header: `"Me Person" <me@example.test>`, reason: "from",
		},
		{
			name: "explicit from with a display name gets the identity name",
			from: "Boss <ME@example.test>", ident: "me@example.test", addr: "ME@example.test",
			header: `"Me Person" <ME@example.test>`, reason: "from",
		},
		{
			name: "a flat entry with no table is an identity with no name",
			from: "flat@example.test", ident: "flat@example.test", addr: "flat@example.test",
			header: "flat@example.test", reason: "from",
		},
		{
			name: "a catch-all address on a new draft is refused (I6)",
			from: "desk@shop.test", refuse: true,
		},
		{
			name: "another person is refused",
			from: "boss@example.test", refuse: true,
		},
		{
			name:  "reply: identity in To",
			orig:  &mail.Message{To: addrs("ann@other.test", "Sales@Example.test"), Cc: addrs("me@example.test")},
			ident: "sales@example.test", addr: "sales@example.test",
			header: `"Sales Team" <sales@example.test>`, reason: "to",
		},
		{
			name:  "reply: identity in Cc",
			orig:  &mail.Message{To: addrs("ann@other.test"), Cc: addrs("me@example.test")},
			ident: "me@example.test", addr: "me@example.test",
			header: `"Me Person" <me@example.test>`, reason: "cc",
		},
		{
			name: "reply: identity in Delivered-To",
			orig: &mail.Message{To: addrs("list@other.test"), Headers: map[string][]string{
				"Delivered-To": {"not an address", "<me@example.test>"},
			}},
			ident: "me@example.test", addr: "me@example.test",
			header: `"Me Person" <me@example.test>`, reason: "delivered-to",
		},
		{
			name: "reply: identity in X-Original-To",
			orig: &mail.Message{To: addrs("list@other.test"), Headers: map[string][]string{
				"X-Original-To": {"sales@example.test"},
			}},
			ident: "sales@example.test", addr: "sales@example.test",
			header: `"Sales Team" <sales@example.test>`, reason: "delivered-to",
		},
		{
			name:  "reply: catch-all address in To, lower case",
			orig:  &mail.Message{To: addrs("Desk@Shop.test")},
			ident: "support@example.test", addr: "desk@shop.test",
			header: `"Support" <desk@shop.test>`, reason: "reply_match",
		},
		{
			name:  "reply: an exact identity beats a pattern that comes first",
			orig:  &mail.Message{To: addrs("desk@shop.test"), Cc: addrs("me@example.test")},
			ident: "me@example.test", addr: "me@example.test",
			header: `"Me Person" <me@example.test>`, reason: "cc",
		},
		{
			name:  "reply: explicit from is the catch-all address of the original",
			from:  "desk@shop.test",
			orig:  &mail.Message{To: addrs("desk@shop.test")},
			ident: "support@example.test", addr: "desk@shop.test",
			header: `"Support" <desk@shop.test>`, reason: "from",
		},
		{
			name:   "reply: explicit from that matches the pattern but is not the picked address",
			from:   "other@shop.test",
			orig:   &mail.Message{To: addrs("desk@shop.test")},
			refuse: true,
		},
		{
			name:  "reply: no candidate gives the default",
			orig:  &mail.Message{To: addrs("ann@other.test")},
			ident: "sales@example.test", addr: "sales@example.test",
			header: `"Sales Team" <sales@example.test>`, reason: "default",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := DraftIn{Account: "work", From: tc.from}
			if tc.orig != nil {
				in.ReplyToID = "1"
			}
			got, err := pickIdentity(acct, in, tc.orig)
			if tc.refuse {
				if !errors.Is(err, errFromNotIdentity) {
					t.Fatalf("from %q: err = %v, want the identity refusal", tc.from, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("pick: %v", err)
			}
			if got.Identity.Email != tc.ident || got.Addr != tc.addr || got.From != tc.header || got.Reason != tc.reason {
				t.Errorf("pick = {%s %s %q %s}, want {%s %s %q %s}",
					got.Identity.Email, got.Addr, got.From, got.Reason,
					tc.ident, tc.addr, tc.header, tc.reason)
			}
		})
	}
}

// TestDraft_IdentityReadsOriginalOnce holds DI2.1: a reply and a
// forward read the original once. In identity mode that read also
// asks for the delivery headers; outside identity mode it has the
// options it had before DI2 (I2).
//
// arch: DI2.0, DI2.1, DI2.2, DI2.3, DI2.4, DI6.1
func TestDraft_IdentityReadsOriginalOnce(t *testing.T) {
	orig := &mail.Message{
		ID:      "1",
		From:    mail.Address{Address: "ann@other.test"},
		To:      []mail.Address{{Address: "me@example.test"}},
		Date:    internalDate,
		Subject: "hello",
		Body:    "text",
	}
	for _, mode := range []struct {
		name    string
		toml    string
		headers []string
	}{
		{name: "identity mode", toml: identityTOML, headers: []string{"Delivered-To", "X-Original-To"}},
		{name: "not identity mode", toml: plainTOML, headers: nil},
	} {
		for _, path := range []string{"reply", "forward"} {
			t.Run(mode.name+"/"+path, func(t *testing.T) {
				h, rec := identityDraft(t, mode.toml, orig)
				in := DraftIn{Account: "work", Body: "thanks"}
				if path == "reply" {
					in.ReplyToID = "1"
				} else {
					in.ForwardID = "1"
					in.To = []string{"bob@other.test"}
				}
				if _, err := h.handle(context.Background(), in); err != nil {
					t.Fatalf("draft: %v", err)
				}
				if len(rec.reads) != 1 {
					t.Fatalf("Read ran %d times, want 1", len(rec.reads))
				}
				want := mail.ReadOpts{Format: "text", MaxChars: originalMaxChars, Headers: mode.headers}
				if !reflect.DeepEqual(rec.reads[0], want) {
					t.Errorf("read options = %+v, want %+v", rec.reads[0], want)
				}
			})
		}
	}
}

// TestDraft_IdentityFromAndNote holds DI2.2 and DI2.3 at the draft
// tool: in identity mode the saved From is the picked header value,
// and the Note names the address, the identity and the rule. Outside
// identity mode the From stays empty and the Note has no such
// sentence (DI2.0, I2).
//
// arch: DI2.0, DI2.1, DI2.2, DI2.3, DI2.4, DI6.1
func TestDraft_IdentityFromAndNote(t *testing.T) {
	t.Run("identity mode", func(t *testing.T) {
		h, rec := identityDraft(t, identityTOML, nil)
		out, err := h.handle(context.Background(), DraftIn{
			Account: "work", To: []string{"ann@other.test"}, Subject: "hi", Body: "text",
		})
		if err != nil {
			t.Fatalf("draft: %v", err)
		}
		if got := rec.drafts[0].From; got != `"Sales Team" <sales@example.test>` {
			t.Errorf("From = %q, want the default identity", got)
		}
		want := "From sales@example.test: identity sales@example.test, picked by default. No signature."
		if !strings.Contains(out.Note, want) {
			t.Errorf("Note = %q, want it to hold %q", out.Note, want)
		}
		if len(rec.reads) != 0 {
			t.Errorf("a new draft read %d messages, want 0", len(rec.reads))
		}
	})
	t.Run("not identity mode", func(t *testing.T) {
		h, rec := identityDraft(t, plainTOML, nil)
		out, err := h.handle(context.Background(), DraftIn{
			Account: "work", To: []string{"ann@other.test"}, Subject: "hi", Body: "text",
		})
		if err != nil {
			t.Fatalf("draft: %v", err)
		}
		if got := rec.drafts[0].From; got != "" {
			t.Errorf("From = %q, want empty so the provider fills it in", got)
		}
		if strings.Contains(out.Note, "picked by") {
			t.Errorf("Note = %q holds the identity sentence outside identity mode", out.Note)
		}
	})
}

// TestDraft_IdentityCatchAllFromRefused holds I6 at the draft tool:
// a catch-all address as an explicit from on a new draft is refused,
// and nothing reaches SaveDraft.
//
// arch: DI2.0, DI2.1, DI2.2, DI2.3, DI2.4, DI6.1
func TestDraft_IdentityCatchAllFromRefused(t *testing.T) {
	h, rec := identityDraft(t, identityTOML, nil)
	_, err := h.handle(context.Background(), DraftIn{
		Account: "work", To: []string{"ann@other.test"}, Body: "text", From: "desk@shop.test",
	})
	if !errors.Is(err, errFromNotIdentity) {
		t.Fatalf("err = %v, want the identity refusal", err)
	}
	if len(rec.drafts) != 0 {
		t.Errorf("SaveDraft ran %d times after a refused from", len(rec.drafts))
	}
}

// TestDraft_ReplyAllDropsPicked holds DI2.4: a reply_all from a
// catch-all address leaves that address and every own address out of
// the recipients, and the draft comes from the catch-all address.
//
// arch: DI2.0, DI2.1, DI2.2, DI2.3, DI2.4, DI6.1
func TestDraft_ReplyAllDropsPicked(t *testing.T) {
	orig := &mail.Message{
		ID:      "1",
		From:    mail.Address{Address: "ann@other.test"},
		To:      []mail.Address{{Address: "Desk@Shop.test"}, {Address: "bob@other.test"}},
		Cc:      []mail.Address{{Address: "carol@other.test"}, {Address: "flat@example.test"}},
		Date:    internalDate,
		Subject: "order",
		Body:    "where is it",
	}
	h, rec := identityDraft(t, identityTOML, orig)
	out, err := h.handle(context.Background(), DraftIn{
		Account: "work", ReplyToID: "1", ReplyAll: true, Body: "on its way",
	})
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	m := rec.drafts[0]
	// flat@example.test is an exact identity in Cc, so rule 2 picks it
	// before the pattern of rule 3.
	if m.From != "flat@example.test" {
		t.Errorf("From = %q, want the exact identity in Cc", m.From)
	}
	if got := strings.Join(m.To, ","); got != "ann@other.test" {
		t.Errorf("to = %q, want the sender of the original", got)
	}
	if got := strings.Join(m.Cc, ","); got != "Desk@Shop.test,bob@other.test,carol@other.test" {
		t.Errorf("cc = %q", got)
	}
	if !strings.Contains(out.Note, "picked by cc") {
		t.Errorf("Note = %q", out.Note)
	}

	// Without the exact identity, the catch-all address is picked and
	// leaves the recipient list.
	orig.Cc = []mail.Address{{Address: "carol@other.test"}}
	h, rec = identityDraft(t, identityTOML, orig)
	out, err = h.handle(context.Background(), DraftIn{
		Account: "work", ReplyToID: "1", ReplyAll: true, Body: "on its way",
	})
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	m = rec.drafts[0]
	if m.From != `"Support" <desk@shop.test>` {
		t.Errorf("From = %q, want the catch-all address", m.From)
	}
	if got := strings.Join(m.To, ","); got != "ann@other.test" {
		t.Errorf("to = %q, want the sender of the original", got)
	}
	if got := strings.Join(m.Cc, ","); got != "bob@other.test,carol@other.test" {
		t.Errorf("cc = %q, want no catch-all address and no own address (DI2.4)", got)
	}
	want := "From desk@shop.test: identity support@example.test, picked by reply_match."
	if !strings.Contains(out.Note, want) {
		t.Errorf("Note = %q, want it to hold %q", out.Note, want)
	}
}

// TestPickIdentity_FromNameIsConfigured pins that the From value uses
// the configured name of the identity and never the name that the
// caller wrote. An identity with no name gives the bare address.
//
// arch: DI2.2
func TestPickIdentity_FromNameIsConfigured(t *testing.T) {
	acct := loadAccount(t, identityTOML)
	cases := []struct{ from, want string }{
		{"IT Support <me@example.test>", `"Me Person" <me@example.test>`},
		{"IT Support <flat@example.test>", "flat@example.test"},
	}
	for _, c := range cases {
		got, err := pickIdentity(acct, DraftIn{From: c.from}, nil)
		if err != nil {
			t.Fatalf("from %q: %v", c.from, err)
		}
		if got.From != c.want {
			t.Errorf("from %q: got %q, want %q", c.from, got.From, c.want)
		}
	}
}
