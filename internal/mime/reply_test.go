// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestReply_ThreadHeaders is M5: a reply must carry In-Reply-To and a
// bounded References list (the first id, plus the last 20).
//
// arch: T3.4, §3.14, M5, M6, M15, §8 S3
func TestReply_ThreadHeaders(t *testing.T) {
	t.Run("short thread", func(t *testing.T) {
		msgID := "<orig@example.com>"
		refs := []string{"<a@example.com>", "<b@example.com>"}

		inReplyTo, references := ReplyHeaders(msgID, refs)

		if inReplyTo != msgID {
			t.Errorf("inReplyTo = %q, want %q", inReplyTo, msgID)
		}
		want := []string{"<a@example.com>", "<b@example.com>", "<orig@example.com>"}
		if !equalStrings(references, want) {
			t.Errorf("references = %v, want %v", references, want)
		}
	})

	t.Run("long thread is capped", func(t *testing.T) {
		msgID := "<orig@example.com>"
		refs := make([]string, 25)
		for i := range refs {
			refs[i] = fmt.Sprintf("<r%d@example.com>", i)
		}

		inReplyTo, references := ReplyHeaders(msgID, refs)

		if inReplyTo != msgID {
			t.Errorf("inReplyTo = %q, want %q", inReplyTo, msgID)
		}
		if len(references) != keepReferences+1 {
			t.Fatalf("len(references) = %d, want %d", len(references), keepReferences+1)
		}
		if references[0] != refs[0] {
			t.Errorf("references[0] = %q, want the thread root %q", references[0], refs[0])
		}
		if references[len(references)-1] != msgID {
			t.Errorf("references[last] = %q, want %q", references[len(references)-1], msgID)
		}
		if references[1] != refs[6] {
			t.Errorf("references[1] = %q, want %q (last 20 of the merged list)", references[1], refs[6])
		}
	})
}

// TestReplyAll_DedupeAndSelf is M6: reply-all must add the original
// To and Cc, then drop the account's own address and every duplicate,
// with no regard to case.
//
// arch: T3.4, §3.14, M5, M6, M15, §8 S3
func TestReplyAll_DedupeAndSelf(t *testing.T) {
	from := "Original Sender <orig@example.com>"
	origTo := []string{"Me <me@example.com>", "Bob <bob@example.com>"}
	origCc := []string{"Alice <ALICE@example.com>", "Bob <BOB@example.com>"}
	self := []string{"me@example.com"}

	to, cc, err := ReplyRecipients("", from, origTo, origCc, true, self)
	if err != nil {
		t.Fatalf("ReplyRecipients: %v", err)
	}

	if len(to) != 1 || to[0] != from {
		t.Fatalf("to = %v, want [%q] (Reply-To empty, falls back to From)", to, from)
	}

	wantCc := []string{"Bob <bob@example.com>", "Alice <ALICE@example.com>"}
	if !equalStrings(cc, wantCc) {
		t.Fatalf("cc = %v, want %v (self removed, BOB@example.com deduped)", cc, wantCc)
	}
	for _, a := range cc {
		if strings.Contains(strings.ToLower(a), "me@example.com") {
			t.Errorf("cc still holds the account address: %v", cc)
		}
	}
}

// TestReplyAll_UsesReplyTo checks the other half of M6: when the
// original carries a Reply-To, that address is the base, not From.
//
// arch: T3.4, §3.14, M5, M6, M15, §8 S3
func TestReplyAll_UsesReplyTo(t *testing.T) {
	to, _, err := ReplyRecipients("List <list@example.com>", "Original <orig@example.com>", nil, nil, false, nil)
	if err != nil {
		t.Fatalf("ReplyRecipients: %v", err)
	}
	if len(to) != 1 || to[0] != "List <list@example.com>" {
		t.Errorf("to = %v, want the Reply-To address", to)
	}
}

// TestHeaders_RePrefix is M15: the Re: check is anchored at the start
// of the subject, so "Are: ..." and "Report: ..." are not mistaken
// for an existing Re: prefix.
//
// arch: T3.4, §3.14, M5, M6, M15, §8 S3
func TestHeaders_RePrefix(t *testing.T) {
	cases := []struct {
		subject string
		want    string
	}{
		{"Meeting notes", "Re: Meeting notes"},
		{"Re: Meeting notes", "Re: Meeting notes"},
		{"RE: shout case", "RE: shout case"},
		{"  re:   spaced colon", "  re:   spaced colon"},
		{"Are: not a reply", "Re: Are: not a reply"},
		{"Report: quarterly numbers", "Re: Report: quarterly numbers"},
	}
	for _, c := range cases {
		if got := RePrefix(c.subject); got != c.want {
			t.Errorf("RePrefix(%q) = %q, want %q", c.subject, got, c.want)
		}
	}
}

// arch: T3.4, §3.14, M5, M6, M15, §8 S3
func TestFwdPrefix(t *testing.T) {
	cases := []struct {
		subject string
		want    string
	}{
		{"Quarterly report", "Fwd: Quarterly report"},
		{"Fwd: Quarterly report", "Fwd: Quarterly report"},
		{"FWD: shout case", "FWD: shout case"},
	}
	for _, c := range cases {
		if got := FwdPrefix(c.subject); got != c.want {
			t.Errorf("FwdPrefix(%q) = %q, want %q", c.subject, got, c.want)
		}
	}
}

// arch: T3.4, §3.14, M5, M6, M15, §8 S3
func TestQuoteText(t *testing.T) {
	date := time.Date(2026, 9, 20, 10, 30, 0, 0, time.UTC)
	got := QuoteText(date, "Alice <alice@example.com>", "line one\nline two")
	want := "On " + date.Format(time.RFC1123Z) + ", Alice <alice@example.com> wrote:\n> line one\n> line two"
	if got != want {
		t.Errorf("QuoteText = %q, want %q", got, want)
	}
}

// arch: T3.4, §3.14, M5, M6, M15, §8 S3
func TestForwardBody(t *testing.T) {
	date := time.Date(2026, 9, 20, 10, 30, 0, 0, time.UTC)
	got := ForwardBody("Alice <alice@example.com>", date, "Quarterly numbers",
		[]string{"Bob <bob@example.com>"}, "the original text")

	for _, want := range []string{
		"From: Alice <alice@example.com>",
		"Date: " + date.Format(time.RFC1123Z),
		"Subject: Quarterly numbers",
		"To: Bob <bob@example.com>",
		"the original text",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ForwardBody: missing %q in:\n%s", want, got)
		}
	}
}

// TestReplyRecipients_SelfOnlyErrors is finding 5: a reply to your own
// message must fail with a named cause, not build a headerless
// message.
//
// arch: T3.4, §3.14, M6, S3 fix finding 5
func TestReplyRecipients_SelfOnlyErrors(t *testing.T) {
	to, cc, err := ReplyRecipients("", "me@x.test", nil, nil, true, []string{"me@x.test"})
	if err == nil {
		t.Fatalf("ReplyRecipients: want an error, got to=%v cc=%v err=%v", to, cc, err)
	}
	if !strings.Contains(err.Error(), "own address") {
		t.Errorf("ReplyRecipients error = %q, want it to name the self-address cause", err.Error())
	}
}

// TestReplyRecipients_OwnSentMail is defect T98: a reply to a message
// the account sent goes to the original To, less the own addresses.
// The live case had Reply-To and Cc set to the own address.
//
// arch: T3.4, §3.14, M6, T98
func TestReplyRecipients_OwnSentMail(t *testing.T) {
	self := []string{"me@example.test"}
	origTo := []string{"Car <car@example.test>", "M <me@example.test>"}
	origCc := []string{"me@example.test", "Other <other@x.test>"}

	to, cc, err := ReplyRecipients("me@example.test", "M <me@example.test>", origTo, origCc, false, self)
	if err != nil {
		t.Fatalf("reply: unexpected error: %v", err)
	}
	if len(to) != 1 || to[0] != "Car <car@example.test>" || len(cc) != 0 {
		t.Errorf("reply: to=%v cc=%v, want to=[Car <car@example.test>] cc=[]", to, cc)
	}

	to, cc, err = ReplyRecipients("me@example.test", "M <me@example.test>", origTo, origCc, true, self)
	if err != nil {
		t.Fatalf("reply_all: unexpected error: %v", err)
	}
	if len(to) != 1 || to[0] != "Car <car@example.test>" {
		t.Errorf("reply_all: to=%v, want [Car <car@example.test>]", to)
	}
	if len(cc) != 1 || cc[0] != "Other <other@x.test>" {
		t.Errorf("reply_all: cc=%v, want [Other <other@x.test>]", cc)
	}
}

// TestReplyHeaders_NoAliasing is finding 6: the returned References
// slice must not share storage with the caller's refs slice.
//
// arch: T3.4, §3.14, M5, S3 fix finding 6
func TestReplyHeaders_NoAliasing(t *testing.T) {
	refs := []string{"<a@example.com>", "<b@example.com>"}

	_, references := ReplyHeaders("", refs)
	references[0] = "<mutated@example.com>"

	if refs[0] != "<a@example.com>" {
		t.Errorf("caller's refs[0] = %q, want unchanged %q", refs[0], "<a@example.com>")
	}
}

// TestQuoteText_CRLF is gap 10: a CRLF body, and a body with a lone
// CR, must quote to the same lines as the LF form, with no carriage
// return left in the output.
//
// arch: T3.4, §3.14, S3 fix gap 10
func TestQuoteText_CRLF(t *testing.T) {
	date := time.Date(2026, 9, 20, 10, 30, 0, 0, time.UTC)
	want := QuoteText(date, "Alice <alice@example.com>", "line one\nline two")

	crlf := QuoteText(date, "Alice <alice@example.com>", "line one\r\nline two")
	if crlf != want {
		t.Errorf("QuoteText(CRLF) = %q, want %q", crlf, want)
	}
	if strings.Contains(crlf, "\r") {
		t.Errorf("QuoteText(CRLF) still holds a carriage return: %q", crlf)
	}

	loneCR := QuoteText(date, "Alice <alice@example.com>", "line one\rline two")
	if loneCR != want {
		t.Errorf("QuoteText(lone CR) = %q, want %q", loneCR, want)
	}
	if strings.Contains(loneCR, "\r") {
		t.Errorf("QuoteText(lone CR) still holds a carriage return: %q", loneCR)
	}
}

// TestForwardBody_NormalisesNewlines is gap 9: a newline inside from,
// subject or a recipient must not forge an extra line in the header
// block.
//
// arch: T3.4, §3.14, S3 fix gap 9
func TestForwardBody_NormalisesNewlines(t *testing.T) {
	date := time.Date(2026, 9, 20, 10, 30, 0, 0, time.UTC)
	got := ForwardBody("Alice <alice@example.com>", date, "s\nX\nTo: c@d",
		[]string{"Bob\r\n<bob@example.com>"}, "the original text")

	lines := strings.Split(got, "\n")
	var subjectLines, toLines int
	for _, line := range lines {
		if strings.HasPrefix(line, "Subject:") {
			subjectLines++
		}
		if strings.HasPrefix(line, "To:") {
			toLines++
		}
	}
	if subjectLines != 1 {
		t.Errorf("ForwardBody: got %d lines starting with Subject:, want 1:\n%s", subjectLines, got)
	}
	if toLines != 1 {
		t.Errorf("ForwardBody: got %d lines starting with To:, want 1:\n%s", toLines, got)
	}
	if strings.Contains(got, "X\nTo: c@d") {
		t.Errorf("ForwardBody: forged To: line survived:\n%s", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
