// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// This file tests the IMAP write path of the send tool: the copy in
// Sent, the draft id, the Bcc rule and the \Answered flag. The SMTP
// transport itself is in smtp_test.go; here the wire is a hook, so a
// case can read the bytes that left and can make a send fail.
//
// arch: T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7

// sentCalls records every message that went to the wire.
type sentCalls struct {
	mu    sync.Mutex
	calls []SendParams
	err   error
}

// hook is the SendFunc a write fixture uses.
func (s *sentCalls) hook(_ context.Context, _ config.Account, _ Credential, p SendParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.calls = append(s.calls, p)
	return nil
}

func (s *sentCalls) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *sentCalls) last(t *testing.T) SendParams {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		t.Fatal("no message went to the wire")
	}
	return s.calls[len(s.calls)-1]
}

// writeFix is a memory server with a write provider on the same pool,
// so a read after a write goes through the real provider.
type writeFix struct {
	*fixture
	w    *WriteProvider
	sent *sentCalls
}

// newWriteFix starts a server and builds the write provider of acct.
// Alias, Email and SMTP get a value when acct names none.
func newWriteFix(t *testing.T, opts fixtureOpts, acct config.Account) *writeFix {
	t.Helper()
	f := newFixture(t, opts)
	acct.Alias = "acct"
	if acct.Email == "" {
		acct.Email = "bob@example.test"
	}
	if acct.SMTP == "" {
		acct.SMTP = "mail.example.test:587"
	}
	sent := &sentCalls{}
	w := NewWriter("acct", f.pool, acct, func(context.Context) (Credential, error) {
		return Credential{Username: acct.Email, Password: "pw"}, nil
	}, nil)
	w.send = sent.hook
	w.now = func() time.Time { return baseTime }
	return &writeFix{fixture: f, w: w, sent: sent}
}

// countIn gives the number of messages in one folder.
func countIn(t *testing.T, f *fixture, folder string) int {
	t.Helper()
	page, err := f.prov.Search(context.Background(), mail.Query{Folder: folder, Limit: 50})
	if err != nil {
		t.Fatalf("search %q: %v", folder, err)
	}
	return len(page.Messages)
}

// aMessage is the standard outgoing message of a case.
func aMessage() *mail.Outgoing {
	return &mail.Outgoing{
		To:      []string{"ann@example.test"},
		Subject: "hello",
		Text:    "body text",
	}
}

// TestSendDraft_SavedToSentRules checks trap C13: the client adds its
// own copy in Sent, unless the SMTP host saves one itself. save_sent
// "always" and "never" answer for the host. Moved from the deleted
// WriteProvider.Send (DRV.16a): afterSend is shared by Send and
// SendDraft, so the same rule is checked here through SaveDraft plus
// SendDraft, the one send path that survives.
// arch: DRV.16a, T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestSendDraft_SavedToSentRules(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		saveSent string
		smtp     string
		wantCopy bool
	}{
		{"an empty rule is auto and a normal host gets a copy", "", "mail.example.test:587", true},
		{"auto adds no copy on gmail", "auto", "smtp.gmail.com:587", false},
		{"auto adds no copy on office365", "auto", "smtp.office365.com:587", false},
		{"auto adds a copy on a host that only ends like gmail", "auto", "smtp.notgmail.com:587", true},
		{"always adds a copy on gmail", "always", "smtp.gmail.com:587", true},
		{"never adds no copy on a normal host", "never", "mail.example.test:587", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// Arrange
			x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}},
				config.Account{SaveSent: c.saveSent, SMTP: c.smtp})
			id, err := x.w.SaveDraft(context.Background(), aMessage(), "")
			if err != nil {
				t.Fatalf("SaveDraft: %v", err)
			}

			// Act
			res, err := x.w.SendDraft(context.Background(), id)

			// Assert
			if err != nil {
				t.Fatalf("SendDraft: %v", err)
			}
			if !res.Sent {
				t.Fatal("sent = false, want true")
			}
			if res.Warning != "" {
				t.Errorf("warning = %q, want none", res.Warning)
			}
			if res.SavedToSent != c.wantCopy {
				t.Errorf("saved_to_sent = %v, want %v", res.SavedToSent, c.wantCopy)
			}
			if x.sent.count() != 1 {
				t.Fatalf("the message went to the wire %d times, want 1", x.sent.count())
			}
			want := 0
			if c.wantCopy {
				want = 1
			}
			if got := countIn(t, x.fixture, "Sent"); got != want {
				t.Errorf("the Sent folder holds %d messages, want %d", got, want)
			}
			if !c.wantCopy {
				if res.ID != "" {
					t.Errorf("id = %q, want none when no copy was saved", res.ID)
				}
				return
			}
			msg, err := x.prov.Read(context.Background(), res.ID, mail.ReadOpts{})
			if err != nil {
				t.Fatalf("read the copy in Sent by its id %q: %v", res.ID, err)
			}
			if msg.Subject != "hello" {
				t.Errorf("subject of the copy = %q, want %q", msg.Subject, "hello")
			}
		})
	}
}

// TestSendDraft_AppendFailureStillSent checks trap C14: after the mail
// left, no later step turns the result into a failure. A copy in Sent
// that fails gives sent: true with a warning, so the model does not
// send the message a second time. Moved from the deleted
// WriteProvider.Send (DRV.16a): the copy-in-Sent step and the wire
// failure are both inside afterSend/wire, shared by SendDraft.
// arch: DRV.16a, T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestSendDraft_AppendFailureStillSent(t *testing.T) {
	t.Parallel()

	t.Run("no Sent folder gives a warning, not a failure", func(t *testing.T) {
		t.Parallel()
		// Arrange: the account has no folder with the sent role.
		x := newWriteFix(t, fixtureOpts{folders: []string{"Drafts"}},
			config.Account{SaveSent: "always"})
		id, err := x.w.SaveDraft(context.Background(), aMessage(), "")
		if err != nil {
			t.Fatalf("SaveDraft: %v", err)
		}

		// Act
		res, err := x.w.SendDraft(context.Background(), id)

		// Assert
		if err != nil {
			t.Fatalf("SendDraft: %v, want no error", err)
		}
		if !res.Sent {
			t.Fatal("sent = false, want true: the mail left")
		}
		if res.SavedToSent {
			t.Error("saved_to_sent = true, want false")
		}
		if res.Warning == "" {
			t.Fatal("warning is empty, want the reason the copy failed")
		}
		if !strings.Contains(res.Warning, "Sent") {
			t.Errorf("warning = %q, want it to name the Sent folder", res.Warning)
		}
		if x.sent.count() != 1 {
			t.Errorf("the message went to the wire %d times, want 1", x.sent.count())
		}
	})

	t.Run("a failed send reports sent false and saves no copy", func(t *testing.T) {
		t.Parallel()
		// Arrange
		x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "always"})
		id, err := x.w.SaveDraft(context.Background(), aMessage(), "")
		if err != nil {
			t.Fatalf("SaveDraft: %v", err)
		}
		x.sent.err = errors.New("smtp: MAIL FROM: 550 the server said no")

		// Act
		res, err := x.w.SendDraft(context.Background(), id)

		// Assert
		if err == nil {
			t.Fatal("SendDraft: want an error, got nil")
		}
		if res.Sent {
			t.Error("sent = true, want false")
		}
		if got := countIn(t, x.fixture, "Sent"); got != 0 {
			t.Errorf("the Sent folder holds %d messages, want 0", got)
		}
	})
}

// TestDraft_IDIsUsable checks trap C15: the id of a saved draft is an
// id that every other tool takes. APPENDUID gives it, and a search
// for the Message-ID gives it on a server with no UIDPLUS.
// arch: T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestDraft_IDIsUsable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		caps       imap.CapSet
		wantSearch int
	}{
		{"the server gives APPENDUID", fullCaps, 0},
		{"the server has no UIDPLUS", noListStatusCaps, 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// Arrange
			x := newWriteFix(t, fixtureOpts{caps: c.caps, folders: []string{"Sent", "Drafts"}}, config.Account{})
			x.warm()

			// Act
			id, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
				To:      []string{"ann@example.test"},
				Subject: "a draft",
				Text:    "draft text",
			}, "")

			// Assert
			if err != nil {
				t.Fatalf("SaveDraft: %v", err)
			}
			_, _, folder, err := mail.ParseIMAPID(id)
			if err != nil {
				t.Fatalf("the draft id %q has the wrong shape: %v", id, err)
			}
			if folder != "Drafts" {
				t.Errorf("the id names folder %q, want %q", folder, "Drafts")
			}
			// The branch, not only its result: a server with UIDPLUS
			// needs no search, and a server without it needs one.
			if got := x.countCommands("UID SEARCH"); got != c.wantSearch {
				t.Errorf("UID SEARCH went out %d times, want %d\ncommands: %v", got, c.wantSearch, x.commands())
			}
			msg, err := x.prov.Read(context.Background(), id, mail.ReadOpts{})
			if err != nil {
				t.Fatalf("read the draft by its id %q: %v", id, err)
			}
			if msg.Subject != "a draft" {
				t.Errorf("subject = %q, want %q", msg.Subject, "a draft")
			}
			if !msg.Flags.Draft {
				t.Error("the stored message does not carry \\Draft")
			}
		})
	}
}

// TestSendDraft_StripsBcc checks trap C16: the hidden addresses reach
// the SMTP envelope and the copy in Sent, never the message that a
// recipient reads.
// arch: DRV.16a, T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestSendDraft_StripsBcc(t *testing.T) {
	t.Parallel()

	t.Run("a stored draft goes out with no Bcc header", func(t *testing.T) {
		t.Parallel()
		// Arrange
		x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}},
			config.Account{SaveSent: "always"})
		id, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
			To:      []string{"ann@example.test"},
			Bcc:     []string{"hidden@example.test"},
			Subject: "with a hidden reader",
			Text:    "draft text",
		}, "")
		if err != nil {
			t.Fatalf("SaveDraft: %v", err)
		}

		// Act
		res, err := x.w.SendDraft(context.Background(), id)

		// Assert
		if err != nil {
			t.Fatalf("SendDraft: %v", err)
		}
		if !res.Sent {
			t.Fatal("sent = false, want true")
		}
		p := x.sent.last(t)
		if !equalStrings(p.To, []string{"ann@example.test", "hidden@example.test"}) {
			t.Errorf("envelope recipients = %v, want the hidden address in them", p.To)
		}
		if strings.Contains(strings.ToLower(string(p.Raw)), "bcc:") {
			t.Errorf("the message on the wire still holds a Bcc header:\n%s", p.Raw)
		}
		if strings.Contains(string(p.Raw), "hidden@example.test") {
			t.Errorf("the message on the wire names the hidden address:\n%s", p.Raw)
		}
		if !strings.Contains(string(p.Raw), "ann@example.test") {
			t.Errorf("the message on the wire lost its To header:\n%s", p.Raw)
		}

		// The copy in Sent is the record of the person and keeps it.
		raw, err := x.prov.Raw(context.Background(), res.ID)
		if err != nil {
			t.Fatalf("read the copy in Sent: %v", err)
		}
		if !strings.Contains(string(raw), "hidden@example.test") {
			t.Errorf("the copy in Sent lost the Bcc header:\n%s", raw)
		}

		// The draft went away, so nobody sends it a second time.
		if _, err := x.prov.Read(context.Background(), id, mail.ReadOpts{}); err == nil {
			t.Error("the draft is still there after the send")
		}
	})

	t.Run("a stored draft dedups the hidden address with Cc", func(t *testing.T) {
		t.Parallel()
		// Arrange. Moved from the deleted WriteProvider.Send (DRV.16a):
		// the recipient dedup is envelopeTo, shared by SendDraft.
		x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "always"})
		id, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
			To:      []string{"ann@example.test"},
			Cc:      []string{"cc@example.test"},
			Bcc:     []string{"hidden@example.test", "ANN@example.test"},
			Subject: "hello",
			Text:    "body text",
		}, "")
		if err != nil {
			t.Fatalf("SaveDraft: %v", err)
		}

		// Act
		res, err := x.w.SendDraft(context.Background(), id)

		// Assert
		if err != nil {
			t.Fatalf("SendDraft: %v", err)
		}
		p := x.sent.last(t)
		want := []string{"ann@example.test", "cc@example.test", "hidden@example.test"}
		if !equalStrings(p.To, want) {
			t.Errorf("envelope recipients = %v, want %v with the duplicate removed", p.To, want)
		}
		if strings.Contains(string(p.Raw), "hidden@example.test") {
			t.Errorf("the message on the wire names the hidden address:\n%s", p.Raw)
		}
		raw, err := x.prov.Raw(context.Background(), res.ID)
		if err != nil {
			t.Fatalf("read the copy in Sent: %v", err)
		}
		if !strings.Contains(string(raw), "hidden@example.test") {
			t.Errorf("the copy in Sent lost the Bcc header:\n%s", raw)
		}
	})

	t.Run("a folded Bcc header goes away whole", func(t *testing.T) {
		t.Parallel()
		// Arrange: the header runs over three lines, as a long
		// recipient list does.
		raw := []byte("From: <bob@example.test>\r\n" +
			"Bcc: <one@example.test>,\r\n" +
			"\t<two@example.test>,\r\n" +
			" <three@example.test>\r\n" +
			"Subject: hi\r\n" +
			"\r\n" +
			"Bcc: this line is body text\r\n")

		// Act
		got := string(stripHeader(raw, "Bcc"))

		// Assert
		for _, addr := range []string{"one@", "two@", "three@"} {
			if strings.Contains(got, addr) {
				t.Errorf("a folded line stayed: %q\n%s", addr, got)
			}
		}
		if !strings.Contains(got, "Subject: hi") {
			t.Errorf("the headers after the Bcc went away:\n%s", got)
		}
		if !strings.Contains(got, "Bcc: this line is body text") {
			t.Errorf("the body changed:\n%s", got)
		}
	})
}

// TestSendDraft_MarksOriginalAnswered checks the last rule of the
// write path of §3.10: after a reply, the message it answers carries
// \Answered. Moved from the deleted WriteProvider.Send (DRV.16a):
// afterSend's \Answered step is shared by SendDraft.
// arch: DRV.16a, T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestSendDraft_MarksOriginalAnswered(t *testing.T) {
	t.Parallel()

	// Arrange
	x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "never"})
	x.add(msgSpec{subject: "the question", body: "text"})
	orig, err := x.prov.Read(context.Background(), newestID(t, x.fixture, "INBOX"), mail.ReadOpts{})
	if err != nil {
		t.Fatalf("read the original: %v", err)
	}
	if orig.MessageID == "" {
		t.Fatal("the original has no Message-ID")
	}

	id, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
		To:        []string{"ann@example.test"},
		Subject:   "Re: the question",
		Text:      "the answer",
		InReplyTo: orig.MessageID,
	}, "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}

	// Act
	if _, err := x.w.SendDraft(context.Background(), id); err != nil {
		t.Fatalf("SendDraft: %v", err)
	}

	// Assert
	_, uid, folder, err := mail.ParseIMAPID(orig.ID)
	if err != nil {
		t.Fatalf("parse the id of the original: %v", err)
	}
	flags := serverFlags(t, x.fixture, folder, imap.UID(uid))
	if !hasFlag(flags, imap.FlagAnswered) {
		t.Errorf("flags of the original = %v, want \\Answered in them", flags)
	}
}

// The tests below cover the reply id of a draft (DR1G.8, G-RV.3). They
// take the place of a note that said markAnsweredByID never ran:
// SaveDraft now writes mime.ReplyIDHeader, and SendDraft gives that id
// to afterSend. Each test checks one branch of IR1G.9.

// replyRaw is the source of a received message with a fixed
// Message-ID, so a case knows the In-Reply-To that answers it.
func replyRaw(subject, messageID string) string {
	return "From: Ann <ann@example.test>\r\n" +
		"To: Bob <bob@example.test>\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: Tue, 01 Sep 2026 12:00:00 +0000\r\n" +
		"Message-ID: " + messageID + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"text\r\n"
}

// answered reports whether the message at id carries \Answered.
func answered(t *testing.T, f *fixture, id string) bool {
	t.Helper()
	_, uid, folder, err := mail.ParseIMAPID(id)
	if err != nil {
		t.Fatalf("parse id %q: %v", id, err)
	}
	return hasFlag(serverFlags(t, f, folder, imap.UID(uid)), imap.FlagAnswered)
}

// holdsReplyID reports whether raw has a reply id header, in any case
// of the header name.
func holdsReplyID(raw []byte) bool {
	return strings.Contains(strings.ToLower(string(raw)), strings.ToLower(mime.ReplyIDHeader)+":")
}

// saveReply stores a draft that answers inReplyTo and carries replyID
// in its reply id header, and gives the draft id.
func saveReply(t *testing.T, x *writeFix, inReplyTo, replyID string) string {
	t.Helper()
	id, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
		To:        []string{"ann@example.test"},
		Bcc:       []string{"hidden@example.test"},
		Subject:   "Re: the question",
		Text:      "the answer",
		InReplyTo: inReplyTo,
		ReplyToID: replyID,
	}, "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	return id
}

// TestDraft_ReplyIdHeaderSaved checks DR1G.18.6: SaveDraft writes the
// reply id header from ReplyToID, writes none without it, and a
// replace follows the new call.
//
// arch: DR1G.8, DR1G.18, IR1G.9
func TestDraft_ReplyIdHeaderSaved(t *testing.T) {
	t.Parallel()

	// Arrange
	x := newWriteFix(t, fixtureOpts{folders: []string{"Drafts"}}, config.Account{})
	x.add(msgSpec{raw: replyRaw("the question", "<a@example.test>")})
	orig := newestID(t, x.fixture, "INBOX")

	// Act
	withID := saveReply(t, x, "<a@example.test>", orig)
	plain, err := x.w.SaveDraft(context.Background(), aMessage(), "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	replaced, err := x.w.SaveDraft(context.Background(), aMessage(), withID)
	if err != nil {
		t.Fatalf("SaveDraft with a replace id: %v", err)
	}

	// Assert
	raw, err := x.prov.Raw(context.Background(), replaced)
	if err != nil {
		t.Fatalf("read the replaced draft: %v", err)
	}
	if holdsReplyID(raw) {
		t.Errorf("a replace with no reply_to_id kept the header:\n%s", raw)
	}
	raw, err = x.prov.Raw(context.Background(), plain)
	if err != nil {
		t.Fatalf("read the plain draft: %v", err)
	}
	if holdsReplyID(raw) {
		t.Errorf("a draft with no reply_to_id holds the header:\n%s", raw)
	}

	// The replace removed withID, so the header check of a draft that
	// keeps it runs on a new one.
	kept := saveReply(t, x, "<a@example.test>", orig)
	raw, err = x.prov.Raw(context.Background(), kept)
	if err != nil {
		t.Fatalf("read the reply draft: %v", err)
	}
	want := mime.ReplyIDHeader + ": " + orig + "\r\n"
	if got := strings.Count(string(raw), want); got != 1 {
		t.Errorf("the draft holds %q %d times, want 1:\n%s", want, got, raw)
	}
}

// TestSend_ReplyIdNotOnWire checks IR1G.9: the reply id header never
// goes on the wire. That holds for a draft of SaveDraft, and for a
// draft of another client with a folded header in another case.
//
// arch: DR1G.8, DR1G.18, IR1G.9
func TestSend_ReplyIdNotOnWire(t *testing.T) {
	t.Parallel()

	t.Run("a draft of SaveDraft", func(t *testing.T) {
		t.Parallel()
		// Arrange
		x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "never"})
		x.add(msgSpec{raw: replyRaw("the question", "<a@example.test>")})
		orig := newestID(t, x.fixture, "INBOX")
		id := saveReply(t, x, "<a@example.test>", orig)

		// Act
		if _, err := x.w.SendDraft(context.Background(), id); err != nil {
			t.Fatalf("SendDraft: %v", err)
		}

		// Assert
		p := x.sent.last(t)
		if holdsReplyID(p.Raw) || strings.Contains(string(p.Raw), orig) {
			t.Errorf("the message on the wire holds the reply id:\n%s", p.Raw)
		}
		for _, want := range []string{"In-Reply-To: <a@example.test>", "Subject: Re: the question", "the answer"} {
			if !strings.Contains(string(p.Raw), want) {
				t.Errorf("the message on the wire lost %q:\n%s", want, p.Raw)
			}
		}
	})

	t.Run("a folded header of another client", func(t *testing.T) {
		t.Parallel()
		// Arrange
		x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "never"})
		draft := "From: <bob@example.test>\r\n" +
			"To: <ann@example.test>\r\n" +
			"x-mailbag-reply-id: 1.2.\r\n" +
			"\tFolded Folder\r\n" +
			"Subject: hi\r\n" +
			"Message-ID: <d@example.test>\r\n" +
			"\r\n" +
			"X-Mailbag-Reply-Id: this line is body text\r\n"
		x.add(msgSpec{folder: "Drafts", raw: draft, flags: []imap.Flag{imap.FlagDraft}})
		id := newestID(t, x.fixture, "Drafts")

		// Act
		if _, err := x.w.SendDraft(context.Background(), id); err != nil {
			t.Fatalf("SendDraft: %v", err)
		}

		// Assert
		got := string(x.sent.last(t).Raw)
		head, body, _ := strings.Cut(got, "\r\n\r\n")
		if holdsReplyID([]byte(head)) || strings.Contains(got, "Folded Folder") {
			t.Errorf("a line of the reply id header went on the wire:\n%s", got)
		}
		if !strings.Contains(head, "Subject: hi") {
			t.Errorf("the headers after the reply id went away:\n%s", got)
		}
		if body != "X-Mailbag-Reply-Id: this line is body text\r\n" {
			t.Errorf("the body changed: %q", body)
		}
	})
}

// TestSend_ReplyIdNotInSentCopy checks IR1G.9: the Sent copy holds no
// reply id header. It keeps the Bcc header, as C16 says.
//
// arch: DR1G.8, DR1G.18, IR1G.9
func TestSend_ReplyIdNotInSentCopy(t *testing.T) {
	t.Parallel()

	// Arrange
	x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "always"})
	x.add(msgSpec{raw: replyRaw("the question", "<a@example.test>")})
	orig := newestID(t, x.fixture, "INBOX")
	id := saveReply(t, x, "<a@example.test>", orig)

	// Act
	res, err := x.w.SendDraft(context.Background(), id)

	// Assert
	if err != nil {
		t.Fatalf("SendDraft: %v", err)
	}
	if !res.SavedToSent || res.ID == "" {
		t.Fatalf("saved_to_sent = %v, id = %q; want a copy in Sent", res.SavedToSent, res.ID)
	}
	raw, err := x.prov.Raw(context.Background(), res.ID)
	if err != nil {
		t.Fatalf("read the copy in Sent: %v", err)
	}
	if holdsReplyID(raw) || strings.Contains(string(raw), orig) {
		t.Errorf("the copy in Sent holds the reply id:\n%s", raw)
	}
	if !strings.Contains(string(raw), "hidden@example.test") {
		t.Errorf("the copy in Sent lost the Bcc header:\n%s", raw)
	}
}

// TestSend_AnsweredByIDNeedsMessageIDMatch checks IR1G.9: the id in
// the draft sets \Answered only on a message with the Message-ID of
// In-Reply-To. The original sits in a folder with no role, so only
// the id reaches it; a forged id that names another message flags
// nothing.
//
// arch: DR1G.8, DR1G.18, IR1G.9
func TestSend_AnsweredByIDNeedsMessageIDMatch(t *testing.T) {
	t.Parallel()

	arrange := func(t *testing.T) (x *writeFix, orig, other string) {
		t.Helper()
		x = newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts", "Old Größe", "Other"}},
			config.Account{SaveSent: "never"})
		x.add(
			msgSpec{folder: "Old Größe", raw: replyRaw("the question", "<a@example.test>")},
			msgSpec{folder: "Other", raw: replyRaw("another mail", "<b@example.test>")},
		)
		return x, newestID(t, x.fixture, "Old Größe"), newestID(t, x.fixture, "Other")
	}

	t.Run("the id of the original sets the flag", func(t *testing.T) {
		t.Parallel()
		// Arrange
		x, orig, other := arrange(t)
		id := saveReply(t, x, "<a@example.test>", orig)

		// Act
		if _, err := x.w.SendDraft(context.Background(), id); err != nil {
			t.Fatalf("SendDraft: %v", err)
		}

		// Assert
		if !answered(t, x.fixture, orig) {
			t.Error("the original does not carry \\Answered")
		}
		if answered(t, x.fixture, other) {
			t.Error("the other message carries \\Answered")
		}
	})

	t.Run("a forged id flags nothing", func(t *testing.T) {
		t.Parallel()
		// Arrange: the header names another message than In-Reply-To.
		x, orig, other := arrange(t)
		id := saveReply(t, x, "<a@example.test>", other)

		// Act
		if _, err := x.w.SendDraft(context.Background(), id); err != nil {
			t.Fatalf("SendDraft: %v", err)
		}

		// Assert
		if answered(t, x.fixture, other) {
			t.Error("the message the forged id names carries \\Answered")
		}
		if answered(t, x.fixture, orig) {
			t.Error("the original outside the role folders carries \\Answered; only the id reaches it")
		}
	})
}

// TestSend_AnsweredByIDFallsBackToSearch checks DR1G.8: when the id
// in the draft is bad, names a message that is gone, or names a
// message with another Message-ID, the Message-ID search flags the
// original in the inbox.
//
// arch: DR1G.8, DR1G.18, IR1G.9
func TestSend_AnsweredByIDFallsBackToSearch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		replyID func(orig, other string) string
	}{
		{"a bad id", func(string, string) string { return "not-an-id" }},
		{"a message that is gone", func(orig, _ string) string {
			v, _, folder, _ := mail.ParseIMAPID(orig)
			return mail.FormatIMAPID(v, 999, folder)
		}},
		{"another Message-ID", func(_, other string) string { return other }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// Arrange
			x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "never"})
			x.add(msgSpec{raw: replyRaw("the question", "<a@example.test>")})
			orig := newestID(t, x.fixture, "INBOX")
			x.add(msgSpec{raw: replyRaw("another mail", "<b@example.test>")})
			other := newestID(t, x.fixture, "INBOX")
			id := saveReply(t, x, "<a@example.test>", c.replyID(orig, other))

			// Act
			if _, err := x.w.SendDraft(context.Background(), id); err != nil {
				t.Fatalf("SendDraft: %v", err)
			}

			// Assert
			if !answered(t, x.fixture, orig) {
				t.Error("the original does not carry \\Answered; the search did not run")
			}
			if answered(t, x.fixture, other) {
				t.Error("the other message carries \\Answered")
			}
		})
	}
}

// TestSend_ForeignDraftUsesSearch checks DR1G.8: a draft that another
// program wrote has no reply id header. Its bytes go on the wire as
// stored, and the Message-ID search flags the original.
//
// arch: DR1G.8, DR1G.18, IR1G.9
func TestSend_ForeignDraftUsesSearch(t *testing.T) {
	t.Parallel()

	// Arrange
	x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "never"})
	x.add(msgSpec{raw: replyRaw("the question", "<a@example.test>")})
	orig := newestID(t, x.fixture, "INBOX")
	draft := "From: <bob@example.test>\r\n" +
		"To: <ann@example.test>\r\n" +
		"Subject: Re: the question\r\n" +
		"In-Reply-To: <a@example.test>\r\n" +
		"Message-ID: <d@example.test>\r\n" +
		"\r\n" +
		"the answer\r\n"
	x.add(msgSpec{folder: "Drafts", raw: draft, flags: []imap.Flag{imap.FlagDraft}})
	id := newestID(t, x.fixture, "Drafts")

	// Act
	if _, err := x.w.SendDraft(context.Background(), id); err != nil {
		t.Fatalf("SendDraft: %v", err)
	}

	// Assert
	if got := string(x.sent.last(t).Raw); got != draft {
		t.Errorf("the wire bytes differ from the stored draft:\ngot:\n%s\nwant:\n%s", got, draft)
	}
	if !answered(t, x.fixture, orig) {
		t.Error("the original does not carry \\Answered")
	}
}

// TestDraft_ReplaceRemovesOld checks the draft update rule of §3.10:
// the new text goes in first, the older draft goes away after it.
// arch: T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestDraft_ReplaceRemovesOld(t *testing.T) {
	t.Parallel()

	// Arrange
	x := newWriteFix(t, fixtureOpts{folders: []string{"Drafts"}}, config.Account{})
	first, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
		To: []string{"ann@example.test"}, Subject: "first text", Text: "one",
	}, "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}

	// Act
	second, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
		To: []string{"ann@example.test"}, Subject: "second text", Text: "two",
	}, first)

	// Assert
	if err != nil {
		t.Fatalf("SaveDraft with a replace id: %v", err)
	}
	if second == first {
		t.Fatal("the new draft has the id of the old one")
	}
	if got := countIn(t, x.fixture, "Drafts"); got != 1 {
		t.Errorf("the Drafts folder holds %d messages, want 1", got)
	}
	msg, err := x.prov.Read(context.Background(), second, mail.ReadOpts{})
	if err != nil {
		t.Fatalf("read the new draft: %v", err)
	}
	if msg.Subject != "second text" {
		t.Errorf("subject = %q, want %q", msg.Subject, "second text")
	}
}

// TestSaveDraft_StoredIDMissIsWarning checks DRV.19.2: APPEND can
// store a message on a server that then fails to find it again by
// its Message-ID (no UIDPLUS, and the search itself finds nothing).
// That miss is not a reason to fail a call that already stored the
// message, so SaveDraft gives no error and still removes the draft
// it replaces, and the afterSend warning of a send names the miss
// instead of calling it a failure.
//
// The real memory server always finds the message it just stored
// (TestDraft_IDIsUsable), so the miss is forced with a stub in place
// of findStoredID. This reuses the technique send already has for
// SendFunc (C14: "a test replaces it... to make a send fail at a
// chosen step") because that is exactly this case: one step of a
// call that must not fail the call as a whole.
// arch: DRV.19.2
func TestSaveDraft_StoredIDMissIsWarning(t *testing.T) {
	t.Parallel()

	t.Run("SaveDraft still removes the draft it replaces", func(t *testing.T) {
		t.Parallel()
		// Arrange: a real first draft, saved normally.
		x := newWriteFix(t, fixtureOpts{folders: []string{"Drafts"}}, config.Account{})
		first, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
			To: []string{"ann@example.test"}, Subject: "first text", Text: "one",
		}, "")
		if err != nil {
			t.Fatalf("SaveDraft: %v", err)
		}

		// The second save's APPEND works, but its id search misses.
		x.w.findStoredID = func(_ *Conn, folder string, _ *imap.AppendData, _ string) (string, error) {
			return "", &storedIDMissError{folder: folder}
		}

		// Act
		second, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
			To: []string{"ann@example.test"}, Subject: "second text", Text: "two",
		}, first)

		// Assert
		if err != nil {
			t.Fatalf("SaveDraft: %v, want no error for a stored-but-not-found copy", err)
		}
		if second != "" {
			t.Errorf("draft id = %q, want empty: the server never gave one", second)
		}
		if got := countIn(t, x.fixture, "Drafts"); got != 1 {
			t.Errorf("the Drafts folder holds %d messages, want 1: the old draft must still go away", got)
		}
		if _, err := x.prov.Read(context.Background(), first, mail.ReadOpts{}); err == nil {
			t.Error("the old draft is still readable by its id, want it removed")
		}
	})

	t.Run("afterSend warns instead of saying the copy failed", func(t *testing.T) {
		t.Parallel()
		// Arrange
		x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}},
			config.Account{SaveSent: "always"})
		id, err := x.w.SaveDraft(context.Background(), aMessage(), "")
		if err != nil {
			t.Fatalf("SaveDraft: %v", err)
		}
		x.w.findStoredID = func(_ *Conn, folder string, _ *imap.AppendData, _ string) (string, error) {
			return "", &storedIDMissError{folder: folder}
		}

		// Act
		res, err := x.w.SendDraft(context.Background(), id)

		// Assert
		if err != nil {
			t.Fatalf("SendDraft: %v, want no error", err)
		}
		if !res.Sent {
			t.Fatal("sent = false, want true: the mail left")
		}
		if !res.SavedToSent {
			t.Error("saved_to_sent = false, want true: the copy did go into Sent")
		}
		if res.Warning == "" {
			t.Fatal("warning is empty, want the stored-but-not-found notice")
		}
		if !strings.Contains(res.Warning, "stored but not found again") {
			t.Errorf("warning = %q, want it to say the copy was stored but not found again, not that it failed", res.Warning)
		}
		if strings.Contains(res.Warning, "failed") {
			t.Errorf("warning = %q, must not say the copy failed: it is in the Sent folder", res.Warning)
		}
	})

	t.Run("SaveDraft logs the miss instead of staying silent", func(t *testing.T) {
		t.Parallel()
		// Arrange: SendDraft and afterSend carry their warning in
		// mail.SendResult.Warning, but SaveDraft's signature is
		// (string, error) alone (the tools.Writer interface, out of
		// this row's scope). A miss that SaveDraft swallows with no
		// error and no id would then reach no one at all, so the
		// pool's logger carries the word out instead (DRV.19.2),
		// the same way thread.go already logs a per-folder miss
		// that its own result has no field for (G-RV.2).
		x := newWriteFix(t, fixtureOpts{folders: []string{"Drafts"}}, config.Account{})
		var buf bytes.Buffer
		x.w.pool.log = slog.New(slog.NewTextHandler(&buf, nil))
		x.w.findStoredID = func(_ *Conn, folder string, _ *imap.AppendData, _ string) (string, error) {
			return "", &storedIDMissError{folder: folder}
		}

		// Act
		if _, err := x.w.SaveDraft(context.Background(), aMessage(), ""); err != nil {
			t.Fatalf("SaveDraft: %v, want no error for a stored-but-not-found copy", err)
		}

		// Assert
		if got := buf.String(); !strings.Contains(got, "level=WARN") || !strings.Contains(got, "Drafts") {
			t.Errorf("log = %q, want a WARN line naming the Drafts folder", got)
		}
	})

	t.Run("a wording miss names the id as unknown, not blank", func(t *testing.T) {
		t.Parallel()
		// Arrange: a real first draft, so replaceID is a well-formed
		// id the server once held, then the APPEND of the second
		// draft works but its id search misses (so id == ""), and
		// the removal of the first draft also fails (it names a UID
		// the server never had). Both failures together are the path
		// that was not reachable before DRV.19.2: id can now be ""
		// when the %s-formatted error below fires.
		x := newWriteFix(t, fixtureOpts{folders: []string{"Drafts"}}, config.Account{})
		first, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
			To: []string{"ann@example.test"}, Subject: "first text", Text: "one",
		}, "")
		if err != nil {
			t.Fatalf("SaveDraft: %v", err)
		}
		v, _, folder, err := mail.ParseIMAPID(first)
		if err != nil {
			t.Fatalf("ParseIMAPID(%q): %v", first, err)
		}
		missingReplace := mail.FormatIMAPID(v, 999999, folder)
		x.w.findStoredID = func(_ *Conn, folder string, _ *imap.AppendData, _ string) (string, error) {
			return "", &storedIDMissError{folder: folder}
		}

		// Act
		_, err = x.w.SaveDraft(context.Background(), &mail.Outgoing{
			To: []string{"ann@example.test"}, Subject: "second text", Text: "two",
		}, missingReplace)

		// Assert
		if err == nil {
			t.Fatal("SaveDraft: want an error, the replace id names no real message")
		}
		if strings.Contains(err.Error(), "saved as , ") {
			t.Errorf("error = %q, names an empty id as if the draft had one", err)
		}
	})
}

// TestDraft_ReplaceRefusesNonDraft checks that a replace id from a
// tool call cannot remove a message that is not a draft. The id comes
// from a model, so an inbox message must survive it (§3.8, §3.15).
// arch: T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestDraft_ReplaceRefusesNonDraft(t *testing.T) {
	t.Parallel()

	// Arrange
	x := newWriteFix(t, fixtureOpts{folders: []string{"Drafts"}}, config.Account{})
	x.add(msgSpec{subject: "a real letter", body: "text"})
	inboxID := newestID(t, x.fixture, "INBOX")

	// Act
	_, err := x.w.SaveDraft(context.Background(), &mail.Outgoing{
		To: []string{"ann@example.test"}, Subject: "a draft", Text: "text",
	}, inboxID)

	// Assert
	if err == nil {
		t.Fatal("SaveDraft with an inbox id: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "not a draft") {
		t.Errorf("error = %v, want it to say that the message is not a draft", err)
	}
	if _, err := x.prov.Read(context.Background(), inboxID, mail.ReadOpts{}); err != nil {
		t.Errorf("the inbox message went away: %v", err)
	}
}

// TestSendDraft_FromIsTheAccountOrAnIdentity checks M13: the envelope
// sender is the account address or one of the identities of
// accounts.toml, and nothing else. Moved from the deleted
// WriteProvider.Send (DRV.16a): envelopeFrom is shared, and SaveDraft
// calls it just as Send did, so the refusal now happens at SaveDraft
// time instead.
// arch: DRV.16a, T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestSendDraft_FromIsTheAccountOrAnIdentity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		from string
		want string
		ok   bool
	}{
		{"an empty from is the account address", "", "bob@example.test", true},
		{"the account address itself", "bob@example.test", "bob@example.test", true},
		{"an identity of the account", "Bob at work <bob@work.test>", "bob@work.test", true},
		{"any other address is refused", "ann@example.test", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// Arrange
			x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}},
				config.Account{SaveSent: "never", Identities: []string{"bob@work.test"}})
			m := aMessage()
			m.From = c.from

			// Act
			id, err := x.w.SaveDraft(context.Background(), m, "")

			// Assert
			if !c.ok {
				if err == nil {
					t.Fatal("SaveDraft: want an error, got nil")
				}
				if x.sent.count() != 0 {
					t.Error("the message went to the wire with a sender that is not an identity")
				}
				return
			}
			if err != nil {
				t.Fatalf("SaveDraft: %v", err)
			}
			if _, err := x.w.SendDraft(context.Background(), id); err != nil {
				t.Fatalf("SendDraft: %v", err)
			}
			if got := x.sent.last(t).From; got != c.want {
				t.Errorf("envelope sender = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSendDraft_UsesSendMail checks the wiring: a write provider that
// NewWriter built puts the message on the wire with SendMail, not
// with a hook a test set. The account names a closed port, so the
// error can only come from the real SMTP dial. Moved from the deleted
// WriteProvider.Send (DRV.16a): wire, which calls SendMail, is shared
// by SendDraft.
// arch: DRV.16a, T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestSendDraft_UsesSendMail(t *testing.T) {
	t.Parallel()

	// Arrange: a port nobody listens on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	f := newFixture(t, fixtureOpts{folders: []string{"Sent", "Drafts"}})
	acct := config.Account{Alias: "acct", Email: "bob@example.test", SMTP: addr}
	w := NewWriter("acct", f.pool, acct, func(context.Context) (Credential, error) {
		return Credential{Username: acct.Email, Password: "pw"}, nil
	}, nil)
	id, err := w.SaveDraft(context.Background(), aMessage(), "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}

	// Act
	res, err := w.SendDraft(context.Background(), id)

	// Assert
	if err == nil {
		t.Fatal("SendDraft: want the dial error of SendMail, got nil")
	}
	if !strings.Contains(err.Error(), "smtp: dial "+addr) {
		t.Errorf("error = %v, want the dial error of SendMail for %s", err, addr)
	}
	if res.Sent {
		t.Error("sent = true after a failed dial")
	}
}

// TestSendDraft_NoLoginNoSend checks that a write provider with no
// credential source refuses to send instead of sending with an empty
// login. Moved from the deleted WriteProvider.Send (DRV.16a): the
// login check lives in wire, shared by SendDraft.
// arch: DRV.16a, T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
func TestSendDraft_NoLoginNoSend(t *testing.T) {
	t.Parallel()

	// Arrange
	f := newFixture(t, fixtureOpts{folders: []string{"Sent", "Drafts"}})
	w := NewWriter("acct", f.pool, config.Account{Alias: "acct", Email: "bob@example.test"}, nil, nil)
	sent := &sentCalls{}
	w.send = sent.hook
	id, err := w.SaveDraft(context.Background(), aMessage(), "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}

	// Act
	_, err = w.SendDraft(context.Background(), id)

	// Assert
	if err == nil {
		t.Fatal("SendDraft: want an error, got nil")
	}
	if sent.count() != 0 {
		t.Error("the message went to the wire with no login")
	}
}

// tokenCache stands in for the Factory's cached token source: get
// gives the cached access token, forget drops it, and the next get
// mints a new one ("at-1", "at-2", ...).
type tokenCache struct {
	mu      sync.Mutex
	cur     string
	minted  int
	forgets int
}

func (c *tokenCache) get(context.Context) (Credential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur == "" {
		c.minted++
		c.cur = fmt.Sprintf("at-%d", c.minted)
	}
	return Credential{Username: "bob@example.test", Token: c.cur}, nil
}

func (c *tokenCache) forget() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forgets++
	c.cur = ""
}

func (c *tokenCache) counts() (minted, forgets int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.minted, c.forgets
}

// newSMTPWriter gives a write provider whose wire is the real SMTP
// client against an in-process XOAUTH2 server that refuses the tokens
// in refuse. The credential comes from cache.
func newSMTPWriter(t *testing.T, cache *tokenCache, refuse ...string) (*WriteProvider, *smtpFixture) {
	t.Helper()
	sf := newSMTPFixture(t, smtpOpts{mechs: []string{XOAUTH2}, refuseTokens: refuse})
	f := newFixture(t, fixtureOpts{folders: []string{"Sent", "Drafts"}})
	acct := config.Account{Alias: "acct", Email: "bob@example.test", SMTP: "mail.example.test:587"}
	w := NewWriter("acct", f.pool, acct, cache.get, cache.forget)
	w.send = func(ctx context.Context, _ config.Account, cred Credential, p SendParams) error {
		return smtpSend(ctx, sf.addr, false, sf.client, cred, p)
	}
	return w, sf
}

// TestWriter_SMTPAuthRetriesOnceWithFreshToken checks G6: the SMTP
// server refuses the cached token with 535 5.7.8; the writer drops the
// cache, reads a fresh token, logs in again and sends. The server gets
// two logins and one message: AUTH comes before MAIL FROM, so the
// retry makes no second copy.
//
// arch: DS11.14, IS11.7, G6
func TestWriter_SMTPAuthRetriesOnceWithFreshToken(t *testing.T) {
	t.Parallel()

	// Arrange
	cache := &tokenCache{}
	w, sf := newSMTPWriter(t, cache, "at-1")
	id, err := w.SaveDraft(context.Background(), aMessage(), "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}

	// Act
	res, err := w.SendDraft(context.Background(), id)

	// Assert
	if err != nil {
		t.Fatalf("SendDraft: %v, want the retry with a fresh token to send", err)
	}
	if !res.Sent {
		t.Error("sent = false after the retry worked")
	}
	got := sf.be.snapshot()
	if len(got.authMechs) != 2 {
		t.Errorf("logins = %d (%v), want 2: the refused one and one retry", len(got.authMechs), got.authMechs)
	}
	if got.authToken != "at-2" {
		t.Errorf("accepted token = %q, want the fresh token at-2", got.authToken)
	}
	if len(got.mails) != 1 || got.dataCalls != 1 {
		t.Errorf("MAIL FROM = %d, DATA = %d, want 1 and 1: the message goes out once", len(got.mails), got.dataCalls)
	}
	if minted, forgets := cache.counts(); minted != 2 || forgets != 1 {
		t.Errorf("tokens minted = %d, forgets = %d, want 2 and 1", minted, forgets)
	}
}

// TestWriter_SMTPAuthSecondRefusalIsReturned checks the other half of
// G6: when the server refuses the fresh token too, the writer stops
// after one retry and gives the second refusal as it is. No message
// goes out.
//
// arch: DS11.14, IS11.7, G6
func TestWriter_SMTPAuthSecondRefusalIsReturned(t *testing.T) {
	t.Parallel()

	// Arrange
	cache := &tokenCache{}
	w, sf := newSMTPWriter(t, cache, "at-1", "at-2", "at-3")
	id, err := w.SaveDraft(context.Background(), aMessage(), "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}

	// Act
	res, err := w.SendDraft(context.Background(), id)

	// Assert
	var authErr *SMTPAuthError
	if !errors.As(err, &authErr) || authErr.Code != 535 {
		t.Fatalf("SendDraft error = %v, want the second 535 refusal as *SMTPAuthError", err)
	}
	if n := strings.Count(err.Error(), "login failed"); n != 1 {
		t.Errorf("error = %q holds %d refusals, want the second one only", err.Error(), n)
	}
	if res.Sent {
		t.Error("sent = true after two refused logins")
	}
	got := sf.be.snapshot()
	if len(got.authMechs) != 2 {
		t.Errorf("logins = %d (%v), want 2: one retry and no more", len(got.authMechs), got.authMechs)
	}
	if len(got.mails) != 0 || got.dataCalls != 0 {
		t.Errorf("MAIL FROM = %d, DATA = %d after refused logins, want none", len(got.mails), got.dataCalls)
	}
	if minted, forgets := cache.counts(); minted != 2 || forgets != 1 {
		t.Errorf("tokens minted = %d, forgets = %d, want 2 and 1", minted, forgets)
	}
}

// TestWriter_SMTPAuthRetryNeedsToken535 checks the limits of the retry
// (DS11.20 G1): a password login, a 535 5.7.139 tenant refusal, a
// different 5xx code and a 454 each go back after one send, with no
// forget.
//
// arch: DS11.14, IS11.7, G6
func TestWriter_SMTPAuthRetryNeedsToken535(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cred Credential
		err  error
	}{
		{"535 on a password login", Credential{Username: "bob@example.test", Password: "pw"}, &SMTPAuthError{Code: 535, Msg: "5.7.8 Bad credentials"}},
		{"535 5.7.139 on a token login", Credential{Username: "bob@example.test", Token: "at-1"}, &SMTPAuthError{Code: 535, Msg: "5.7.139 Authentication unsuccessful"}},
		{"534 on a token login", Credential{Username: "bob@example.test", Token: "at-1"}, &SMTPAuthError{Code: 534, Msg: "5.7.9 Mechanism too weak"}},
		{"454 on a token login", Credential{Username: "bob@example.test", Token: "at-1"}, errors.New("smtp: login failed: SMTP error 454: try again later")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// Arrange
			f := newFixture(t, fixtureOpts{folders: []string{"Sent", "Drafts"}})
			acct := config.Account{Alias: "acct", Email: "bob@example.test", SMTP: "mail.example.test:587"}
			var mu sync.Mutex
			sends, forgets := 0, 0
			w := NewWriter("acct", f.pool, acct, func(context.Context) (Credential, error) {
				return c.cred, nil
			}, func() {
				mu.Lock()
				forgets++
				mu.Unlock()
			})
			w.send = func(context.Context, config.Account, Credential, SendParams) error {
				mu.Lock()
				sends++
				mu.Unlock()
				return c.err
			}
			id, err := w.SaveDraft(context.Background(), aMessage(), "")
			if err != nil {
				t.Fatalf("SaveDraft: %v", err)
			}

			// Act
			_, err = w.SendDraft(context.Background(), id)

			// Assert
			if !errors.Is(err, c.err) {
				t.Errorf("SendDraft error = %v, want %v as it is", err, c.err)
			}
			mu.Lock()
			defer mu.Unlock()
			if sends != 1 || forgets != 0 {
				t.Errorf("sends = %d, forgets = %d, want 1 and 0: no retry", sends, forgets)
			}
		})
	}
}

// TestSentCopy_AdviceTable checks every row of the save_sent advice
// table of DR1G.18.7: SaveSentAdvice must read the same mailbagSaves
// / hostKeeps decision sentCopy makes, never a second copy of the
// rule (IR1G.15).
//
// arch: DR1G.11, DR1G.18.7, DR1G.18.8, IR1G.15
func TestSentCopy_AdviceTable(t *testing.T) {
	t.Parallel()

	const keepsHost = "smtp.gmail.com:587"    // in hostsThatSaveSent
	const plainHost = "mail.example.test:587" // not in hostsThatSaveSent

	cases := []struct {
		name     string
		saveSent string
		smtp     string
		want     string
	}{
		{"always, a host that keeps none", "always", plainHost, "save_sent = always: mailbag saves a copy in Sent"},
		{"always, a host that keeps its own copy too", "always", keepsHost, "save_sent = always: mailbag saves a copy in Sent"},
		{"auto, a host that keeps sent mail", "auto", keepsHost, "save_sent = auto: this server keeps sent mail, so mailbag saves no copy"},
		{"auto, a host that keeps none", "auto", plainHost, "save_sent = auto: mailbag saves a copy in Sent"},
		{"an empty setting is auto", "", plainHost, "save_sent = auto: mailbag saves a copy in Sent"},
		{"never, a host that keeps sent mail", "never", keepsHost, "save_sent = never: this server keeps sent mail"},
		{"never, a host that keeps none", "never", plainHost, `save_sent = never: WARNING sent mail is not kept anywhere; set save_sent = "auto"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := SaveSentAdvice(c.saveSent, c.smtp); got != c.want {
				t.Errorf("SaveSentAdvice(%q, %q) = %q, want %q", c.saveSent, c.smtp, got, c.want)
			}
		})
	}
}

// TestSentCopy_UnsplitSMTPSaves checks OR1G's "keep today's behavior"
// ruling for sentCopy (DR1G.18.7): splitSMTPAddr's only error is an
// empty address (splitHostPort), and on that error sentCopy must give
// the same mailbagSaves each save_sent setting gave before hostKeeps
// existed, with hostKeeps false because an empty address tells
// nothing about the host.
//
// arch: DR1G.11, DR1G.18.7, IR1G.15
func TestSentCopy_UnsplitSMTPSaves(t *testing.T) {
	t.Parallel()

	cases := []struct {
		saveSent  string
		wantSaves bool
	}{
		{"", true},
		{"auto", true},
		{"always", true},
		{"never", false},
	}
	for _, c := range cases {
		t.Run("save_sent="+c.saveSent, func(t *testing.T) {
			t.Parallel()
			saves, keeps := sentCopy(c.saveSent, "")
			if saves != c.wantSaves {
				t.Errorf("mailbagSaves = %v, want %v", saves, c.wantSaves)
			}
			if keeps {
				t.Error("hostKeeps = true, want false: an empty address tells nothing about the host")
			}
		})
	}
}

// TestCaps_SaveSentUsesSentCopy holds IR1G.15 across a range of
// settings: savesSentCopy and SaveSentAdvice must never disagree
// about whether mailbag itself adds a copy, because both read it
// from the one function sentCopy.
//
// arch: DR1G.11, DR1G.18.7, DR1G.18.8, IR1G.15
func TestCaps_SaveSentUsesSentCopy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		saveSent string
		smtp     string
	}{
		{"", "mail.example.test:587"},
		{"auto", "smtp.gmail.com:587"},
		{"auto", "smtp.notgmail.com:587"},
		{"always", "smtp.gmail.com:587"},
		{"never", "mail.example.test:587"},
		{"never", "smtp.office365.com:587"},
	}
	for _, c := range cases {
		t.Run(c.saveSent+"/"+c.smtp, func(t *testing.T) {
			t.Parallel()
			w := &WriteProvider{acct: config.Account{SaveSent: c.saveSent, SMTP: c.smtp}}
			mailbagSaves, _ := sentCopy(c.saveSent, c.smtp)
			if got := w.savesSentCopy(); got != mailbagSaves {
				t.Fatalf("savesSentCopy() = %v, sentCopy() mailbagSaves = %v", got, mailbagSaves)
			}
			advice := SaveSentAdvice(c.saveSent, c.smtp)
			saysMailbagSaves := strings.Contains(advice, "mailbag saves a copy")
			if saysMailbagSaves != mailbagSaves {
				t.Errorf("advice %q claims mailbag saves = %v, sentCopy says %v", advice, saysMailbagSaves, mailbagSaves)
			}
		})
	}
}

// TestCaps_Report checks imap.Provider.Caps against a real memory
// IMAP server: UIDPlus and Move come from the server's advertised
// capability list, and Keywords from INBOX's PERMANENTFLAGS of the
// same login (IR1G.15); SaveSent stays empty, because Provider
// carries no account config to build the save_sent advice from.
//
// CondStore is checked as always false through this harness and not
// as true on a server that offers it: go-imap/v2 v2.0.0-beta.8's
// imapserver never puts CONDSTORE or QRESYNC in a CAPABILITY answer,
// for any state of imapserver.Options.Caps (imapserver/capability.go
// availableCaps lists neither), so no fixture in this repo can prove
// the true branch today. Has(imap.CapCondStore) itself is go-imap
// library code, not ours; report this gap rather than fake a case
// the vendored server cannot produce.
//
// arch: DR1G.11, DR1G.18.8, IR1G.15
func TestCaps_Report(t *testing.T) {
	t.Parallel()

	t.Run("a modern server reports MOVE, UIDPLUS and keyword support", func(t *testing.T) {
		t.Parallel()
		caps := imap.CapSet{
			imap.CapIMAP4rev1:    {},
			imap.CapListExtended: {},
			imap.CapListStatus:   {},
			imap.CapSpecialUse:   {},
			imap.CapESearch:      {},
			imap.CapUIDPlus:      {},
			imap.CapMove:         {},
		}
		f := newFixture(t, fixtureOpts{caps: caps})
		got, err := f.prov.Caps(context.Background())
		if err != nil {
			t.Fatalf("Caps: %v", err)
		}
		want := mail.Caps{Keywords: true, UIDPlus: true, Move: true, CondStore: false}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Caps = %+v, want %+v", got, want)
		}
	})

	t.Run("a server with no MOVE reports it false", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, fixtureOpts{}) // fullCaps: UIDPLUS but no MOVE
		got, err := f.prov.Caps(context.Background())
		if err != nil {
			t.Fatalf("Caps: %v", err)
		}
		if got.Move {
			t.Error("Move = true, want false: fullCaps has no MOVE")
		}
		if !got.UIDPlus {
			t.Error("UIDPlus = false, want true: fullCaps has UIDPLUS")
		}
		if !got.Keywords {
			t.Error("Keywords = false, want true: the memory server allows \\*")
		}
		if got.SaveSent != "" {
			t.Errorf("SaveSent = %q, want empty: Provider.Caps does not know the account config", got.SaveSent)
		}
	})
}

// examineNoFlagsSession is a server that answers EXAMINE as RFC 3501
// shows in its example: a read-only folder has `PERMANENTFLAGS ()`.
// Dovecot does this. SELECT keeps the `\*` of the memory server.
//
// arch: R16-M9
type examineNoFlagsSession struct {
	imapserver.Session
}

func (s examineNoFlagsSession) Select(mailbox string, opts *imap.SelectOptions) (*imap.SelectData, error) {
	d, err := s.Session.Select(mailbox, opts)
	if err != nil || d == nil {
		return d, err
	}
	if opts != nil && opts.ReadOnly {
		d.PermanentFlags = nil
	}
	return d, nil
}

// TestCaps_KeywordsFromSelect checks that the keyword line of the
// capability report reads PERMANENTFLAGS from a SELECT of INBOX, as
// modify does (C17). An EXAMINE answer has `PERMANENTFLAGS ()` on many
// servers, so a report from it says no while add_labels works.
//
// arch: DR1G.11, C17, R16-M9
func TestCaps_KeywordsFromSelect(t *testing.T) {
	t.Parallel()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser(fixtureUser, fixturePass)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatalf("create INBOX: %v", err)
	}
	mem.AddUser(user)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return examineNoFlagsSession{Session: mem.NewSession()}, nil, nil
		},
		InsecureAuth: true,
		Caps:         fullCaps,
		Logger:       discardLogger{},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	f := &fixture{t: t, addr: ln.Addr().String(), user: user, wire: &syncBuf{}}
	f.pool = NewPool(f.dial, nil)
	t.Cleanup(f.pool.CloseAll)
	f.prov = New("acct", f.pool)

	got, err := f.prov.Caps(context.Background())
	if err != nil {
		t.Fatalf("Caps: %v", err)
	}
	if !got.Keywords {
		t.Errorf("Keywords = false, want true: SELECT INBOX gives \\*; commands: %v", f.commands())
	}
}

// TestSendDraft_CharsetRecipientsKept holds REVIEW-2026-10-12 H2 and
// H3: a draft from another client has a To header with an encoded
// word in windows-1250. The envelope keeps both To addresses and the
// Cc address, because the envelope uses the go-message parser of the
// confirmation summary.
//
// arch: REVIEW-2026-10-12 H2, REVIEW-2026-10-12 H3
func TestSendDraft_CharsetRecipientsKept(t *testing.T) {
	t.Parallel()

	// Arrange
	x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "never"})
	draft := "From: <bob@example.test>\r\n" +
		"To: =?windows-1250?Q?Petr_Nov=E1k?= <petr@x.cz>, anna@y.cz\r\n" +
		"Cc: boss@z.cz\r\n" +
		"Subject: hello\r\n" +
		"Message-ID: <charset@example.test>\r\n" +
		"\r\n" +
		"body text\r\n"
	x.add(msgSpec{folder: "Drafts", raw: draft, flags: []imap.Flag{imap.FlagDraft}})
	id := newestID(t, x.fixture, "Drafts")

	// Act
	res, err := x.w.SendDraft(context.Background(), id)

	// Assert
	if err != nil {
		t.Fatalf("SendDraft: %v", err)
	}
	if !res.Sent {
		t.Fatal("sent = false, want true")
	}
	want := []string{"petr@x.cz", "anna@y.cz", "boss@z.cz"}
	if got := x.sent.last(t).To; !equalStrings(got, want) {
		t.Errorf("envelope recipients = %v, want %v", got, want)
	}
}

// TestSendDraft_BadRecipientHeaderFailsBeforeSend holds
// REVIEW-2026-10-12 H2 and H3: a To header that does not parse, here
// an unquoted display name with a comma, gives an error before the
// SMTP call. The send does not go to the Cc address only.
//
// arch: REVIEW-2026-10-12 H2, REVIEW-2026-10-12 H3
func TestSendDraft_BadRecipientHeaderFailsBeforeSend(t *testing.T) {
	t.Parallel()

	// Arrange
	x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, config.Account{SaveSent: "never"})
	draft := "From: <bob@example.test>\r\n" +
		"To: Smith, John <j@x.example>\r\n" +
		"Cc: boss@z.cz\r\n" +
		"Subject: hello\r\n" +
		"Message-ID: <bad@example.test>\r\n" +
		"\r\n" +
		"body text\r\n"
	x.add(msgSpec{folder: "Drafts", raw: draft, flags: []imap.Flag{imap.FlagDraft}})
	id := newestID(t, x.fixture, "Drafts")

	// Act
	res, err := x.w.SendDraft(context.Background(), id)

	// Assert
	if err == nil {
		t.Fatalf("SendDraft: want an error, got nil and %+v", res)
	}
	if !strings.Contains(err.Error(), "To") {
		t.Errorf("error = %q, want it to name the To header", err)
	}
	if res.Sent {
		t.Error("sent = true, want false")
	}
	if n := x.sent.count(); n != 0 {
		t.Errorf("SMTP got %d messages, want 0; envelope %v", n, x.sent.last(t).To)
	}
	if _, err := x.prov.Read(context.Background(), id, mail.ReadOpts{}); err != nil {
		t.Errorf("the draft went away after a failed send: %v", err)
	}
}

// identityAcct is an account in identity mode: two identity tables,
// one with a reply_match pattern, and one flat entry.
func identityAcct() config.Account {
	return config.Account{
		Email:      "bob@example.test",
		Identities: []string{"flat@example.test"},
		IdentityList: []config.Identity{
			{Email: "bob@example.test", Name: "Bob", Signature: "Bob", OnNew: true},
			{Email: "sales@example.test", Name: "Sales Team", Signature: "Sales", OnNew: true,
				ReplyMatch: []string{"*@sales.example.test"}},
		},
	}
}

// TestEnvelopeFrom_OwnsAddress checks that envelopeFrom asks
// Account.OwnsAddress: an identity table and a reply_match address pass
// in identity mode, the result is the bare address, and an account
// outside identity mode keeps the raw compare (I2).
// arch: DI6.1
func TestEnvelopeFrom_OwnsAddress(t *testing.T) {
	t.Parallel()

	flat := config.Account{Email: "bob@example.test", Identities: []string{"flat@example.test"}}
	cases := []struct {
		name string
		acct config.Account
		from string
		want string
		ok   bool
	}{
		{"identity mode: identity table with a name", identityAcct(), "Sales Team <sales@example.test>", "sales@example.test", true},
		{"identity mode: reply_match address", identityAcct(), "info@sales.example.test", "info@sales.example.test", true},
		{"identity mode: flat entry", identityAcct(), "flat@example.test", "flat@example.test", true},
		{"identity mode: stranger", identityAcct(), "eve@example.test", "", false},
		{"flat account: flat entry", flat, "Flat <flat@example.test>", "flat@example.test", true},
		{"flat account: stranger", flat, "sales@example.test", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := NewWriter("acct", nil, c.acct, nil, nil)
			got, err := w.envelopeFrom(c.from)
			if c.ok != (err == nil) {
				t.Fatalf("envelopeFrom(%q) error = %v, want ok=%v", c.from, err, c.ok)
			}
			if got != c.want {
				t.Fatalf("envelopeFrom(%q) = %q, want %q", c.from, got, c.want)
			}
		})
	}
}

// TestBuild_FromHeaderAndSignature checks that the From header keeps
// the display name only in identity mode (the envelope sender stays the
// bare address), and that the text part of the draft holds the
// signature byte for byte (I1 for IMAP).
// arch: DI6.1, I1
func TestBuild_FromHeaderAndSignature(t *testing.T) {
	t.Parallel()

	const sig = "Sales\nTeam line two"
	text := "Hello.\n\n-- \n" + sig
	cases := []struct {
		name     string
		acct     config.Account
		wantFrom string
	}{
		{"identity mode keeps the display name", identityAcct(), `"Sales Team" <sales@example.test>`},
		{"outside identity mode the header is the bare address", config.Account{
			Email: "bob@example.test", Identities: []string{"sales@example.test"}}, "<sales@example.test>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := NewWriter("acct", nil, c.acct, nil, nil)
			w.now = func() time.Time { return baseTime }
			m := aMessage()
			m.From = "Sales Team <sales@example.test>"
			m.Text = text

			bare, err := w.envelopeFrom(m.From)
			if err != nil {
				t.Fatalf("envelopeFrom: %v", err)
			}
			if bare != "sales@example.test" {
				t.Fatalf("envelope sender = %q, want the bare address", bare)
			}
			raw, err := w.build(m, w.headerFrom(m.From, bare))
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			msg, err := netmail.ReadMessage(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("read built message: %v", err)
			}
			if got := msg.Header.Get("From"); got != c.wantFrom {
				t.Errorf("From header = %q, want %q", got, c.wantFrom)
			}
			rd := msg.Body
			if strings.EqualFold(msg.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
				rd = quotedprintable.NewReader(msg.Body)
			}
			body, err := io.ReadAll(rd)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			got := strings.ReplaceAll(string(body), "\r\n", "\n")
			if !strings.Contains(got, "-- \n"+sig) {
				t.Errorf("text part = %q, want it to hold %q byte for byte", got, "-- \n"+sig)
			}
		})
	}
}

// TestSaveDraft_IdentityFromHeader checks the SaveDraft entry point in
// identity mode: the stored draft keeps the display name in the From
// header and the signature bytes in the text part (I1), and SendDraft
// puts the bare address on the wire as envelope sender. An account
// outside identity mode stores the bare address. This pins the
// SaveDraft call of headerFrom: without it the header loses the name.
// arch: DI6.1
func TestSaveDraft_IdentityFromHeader(t *testing.T) {
	t.Parallel()

	const sig = "Sales\nTeam line two"
	cases := []struct {
		name     string
		acct     config.Account
		wantFrom string
	}{
		{"identity mode keeps the display name", identityAcct(), `"Sales Team" <sales@example.test>`},
		{"outside identity mode the header is the bare address", config.Account{
			Email: "bob@example.test", Identities: []string{"sales@example.test"}}, "<sales@example.test>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// Arrange
			x := newWriteFix(t, fixtureOpts{folders: []string{"Sent", "Drafts"}}, c.acct)
			m := aMessage()
			m.From = "Sales Team <sales@example.test>"
			m.Text = "Hello.\n\n-- \n" + sig

			// Act
			id, err := x.w.SaveDraft(context.Background(), m, "")
			if err != nil {
				t.Fatalf("SaveDraft: %v", err)
			}

			// Assert: the stored draft.
			raw, err := x.w.draftSource(context.Background(), id)
			if err != nil {
				t.Fatalf("draftSource: %v", err)
			}
			msg, err := netmail.ReadMessage(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("read stored draft: %v", err)
			}
			if got := msg.Header.Get("From"); got != c.wantFrom {
				t.Errorf("stored From header = %q, want %q", got, c.wantFrom)
			}
			rd := msg.Body
			if strings.EqualFold(msg.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
				rd = quotedprintable.NewReader(msg.Body)
			}
			body, err := io.ReadAll(rd)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if got := strings.ReplaceAll(string(body), "\r\n", "\n"); !strings.Contains(got, "-- \n"+sig) {
				t.Errorf("stored text part = %q, want it to hold %q byte for byte", got, "-- \n"+sig)
			}

			// Assert: the wire.
			if _, err := x.w.SendDraft(context.Background(), id); err != nil {
				t.Fatalf("SendDraft: %v", err)
			}
			if got := x.sent.last(t).From; got != "sales@example.test" {
				t.Errorf("envelope sender = %q, want the bare address", got)
			}
		})
	}
}
