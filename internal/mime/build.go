// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package mime builds outgoing RFC 5322 / MIME messages (T3.2). A later
// stage adds part decoding (T3.3) to the same package. Nothing here
// talks to a network, a provider or the guard package: a caller passes
// already-validated addresses and text (see Build), and it resolves
// attachment paths before calling Build (§3.15, "Attach path").
//
// Build only writes UTF-8 content, so this file never imports
// github.com/emersion/go-message/charset (that package registers a
// charset reader for decoding, T3.3's job, and pulls in golang.org/x/text,
// which is not yet in go.sum: T6 added the direct Appendix A deps, not
// this transitive one). T3.3 adds that import in its own file.
package mime

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	stdmime "mime"

	gomail "github.com/emersion/go-message/mail"
)

// ReplyIDHeader is the header that carries the mailbag id of the
// message a draft answers. Only a stored draft carries it. The send
// path reads it, then removes it from the wire bytes and from the
// Sent copy (DR1G.8, IR1G.9).
//
// arch: DR1G.8, DR1G.18, IR1G.9
const ReplyIDHeader = "X-Mailbag-Reply-Id"

// Input is the content Build turns into one message. It carries the
// subset of mail.Outgoing that a message needs on the wire. Quoting a
// reply body is computed by T3.4 and is not part of this stage.
type Input struct {
	From        string
	To, Cc, Bcc []string
	Subject     string
	Text        string
	HTML        string
	Attachments []string // resolved, existing file paths

	// InReplyTo and References are the wire values of a reply, already
	// computed by mime.ReplyHeaders (T3.4), angle brackets kept. Build
	// writes each as its own header only when it is not empty (M5).
	InReplyTo  string
	References []string

	// ReplyID is the mailbag id (§3.8) of the message this one
	// answers. Build writes it as ReplyIDHeader only when it is not
	// empty. Only SaveDraft sets it (DR1G.18.6).
	ReplyID string
}

// Build writes one MIME message for in to w.
//
// Every message gets Message-ID, Date and MIME-Version (M4). now
// becomes the Date header; rnd feeds the random half of the
// Message-ID, so a test can pass a fixed reader and reproduce the
// exact bytes. Production code passes crypto/rand.Reader and
// time.Now(). A reply also gets In-Reply-To and References, built
// from in.InReplyTo and in.References (M5). A draft that answers a
// message also gets ReplyIDHeader, from in.ReplyID (DR1G.8).
//
// The go-message library encodes the Subject header and attachment
// file names (RFC 2047 / RFC 2231) on its own (M8). When html is
// given, the message holds a multipart/alternative part with the text
// first and the HTML last (M9). Attachments wrap that part in
// multipart/mixed. Text and HTML parts use quoted-printable, which the
// library line-wraps well inside the 998-character limit (M16).
//
// Build trusts in.From, in.To, in.Cc and in.Bcc to already be
// well-formed and in.Subject/in.Text/in.HTML to already be free of
// CR, LF and NUL: guard.ValidateField and guard.ValidateAddress do
// that check at the tool boundary (§3.15, "Tool input"), and Build
// does not repeat it.
//
// Attachment size limits are also a guard concern (guard.AttachPath,
// §3.15) and are not re-checked here.
//
// arch: T3.2, §3.14, M4, M8, M9, M16, DR1G.8, DR1G.18
func Build(w io.Writer, in Input, now time.Time, rnd io.Reader) error {
	from, err := gomail.ParseAddress(in.From)
	if err != nil {
		return fmt.Errorf("mime: from address: %w", err)
	}
	to, err := parseAddresses(in.To)
	if err != nil {
		return fmt.Errorf("mime: to address: %w", err)
	}
	cc, err := parseAddresses(in.Cc)
	if err != nil {
		return fmt.Errorf("mime: cc address: %w", err)
	}
	bcc, err := parseAddresses(in.Bcc)
	if err != nil {
		return fmt.Errorf("mime: bcc address: %w", err)
	}
	id, err := newMessageID(rnd, domainOf(from.Address))
	if err != nil {
		return err
	}

	var h gomail.Header
	h.SetAddressList("From", []*gomail.Address{from})
	h.SetAddressList("To", to)
	h.SetAddressList("Cc", cc)
	h.SetAddressList("Bcc", bcc)
	h.SetSubject(in.Subject)
	h.SetDate(now)
	h.SetMessageID(id)
	if in.InReplyTo != "" {
		h.Set("In-Reply-To", in.InReplyTo)
	}
	if len(in.References) > 0 {
		h.Set("References", strings.Join(in.References, " "))
	}
	if in.ReplyID != "" {
		// The folder part of an id can hold any text. SetText encodes
		// a value that is not plain ASCII as RFC 2047 words, so the
		// header stays 7-bit. The reader decodes it again.
		h.SetText(ReplyIDHeader, in.ReplyID)
	}

	hasHTML := in.HTML != ""
	hasAttachments := len(in.Attachments) > 0

	switch {
	case hasAttachments:
		mw, err := gomail.CreateWriter(w, h)
		if err != nil {
			return fmt.Errorf("mime: header: %w", err)
		}
		if hasHTML {
			iw, err := mw.CreateInline()
			if err != nil {
				return fmt.Errorf("mime: alternative part: %w", err)
			}
			if err := writeAlternative(iw, in); err != nil {
				return err
			}
		} else {
			if err := writeSinglePart(mw, in.Text); err != nil {
				return err
			}
		}
		for _, path := range in.Attachments {
			if err := writeAttachment(mw, path); err != nil {
				return err
			}
		}
		return mw.Close()

	case hasHTML:
		iw, err := gomail.CreateInlineWriter(w, h)
		if err != nil {
			return fmt.Errorf("mime: header: %w", err)
		}
		if err := writeAlternative(iw, in); err != nil {
			return err
		}
		return iw.Close()

	default:
		h.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
		pw, err := gomail.CreateSingleInlineWriter(w, h)
		if err != nil {
			return fmt.Errorf("mime: header: %w", err)
		}
		if _, err := io.WriteString(pw, in.Text); err != nil {
			return fmt.Errorf("mime: text part: %w", err)
		}
		return pw.Close()
	}
}

// parseAddresses parses each address in addrs. An empty addrs gives a
// nil list, which SetAddressList turns into no header (§3.14).
func parseAddresses(addrs []string) ([]*gomail.Address, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	out := make([]*gomail.Address, len(addrs))
	for i, a := range addrs {
		addr, err := gomail.ParseAddress(a)
		if err != nil {
			return nil, err
		}
		out[i] = addr
	}
	return out, nil
}

// domainOf returns the part of addr after '@'. gomail.ParseAddress
// already refused addr if it had no '@'.
func domainOf(addr string) string {
	_, domain, _ := strings.Cut(addr, "@")
	return domain
}

// newMessageID reads 16 bytes from rnd and formats them with domain as
// an RFC 5322 message id, without the angle brackets (§3.14: "Message-ID
// (<random@domain of From>)").
func newMessageID(rnd io.Reader, domain string) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		return "", fmt.Errorf("mime: message id: %w", err)
	}
	return fmt.Sprintf("%x@%s", b, domain), nil
}

// writeSinglePart writes text as the one text/plain sub-part of a
// multipart/mixed message (the attachments-but-no-html case).
func writeSinglePart(mw *gomail.Writer, text string) error {
	var th gomail.InlineHeader
	th.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
	pw, err := mw.CreateSingleInline(th)
	if err != nil {
		return fmt.Errorf("mime: text part: %w", err)
	}
	if _, err := io.WriteString(pw, text); err != nil {
		return fmt.Errorf("mime: text part: %w", err)
	}
	return pw.Close()
}

// writeAlternative writes the text part, then the HTML part, into a
// multipart/alternative writer. A reader picks the last part it
// understands, so text (the least capable readers understand it)
// comes first and HTML last (§3.14, M9).
func writeAlternative(iw *gomail.InlineWriter, in Input) error {
	text := in.Text
	if text == "" {
		// A caller gave only HTML: build the text/plain half from it
		// (§3.14, M9).
		text = HTMLToText(in.HTML)
	}

	var th gomail.InlineHeader
	th.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
	tw, err := iw.CreatePart(th)
	if err != nil {
		return fmt.Errorf("mime: text part: %w", err)
	}
	if _, err := io.WriteString(tw, text); err != nil {
		return fmt.Errorf("mime: text part: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("mime: text part: %w", err)
	}

	var hh gomail.InlineHeader
	hh.SetContentType("text/html", map[string]string{"charset": "utf-8"})
	hw, err := iw.CreatePart(hh)
	if err != nil {
		return fmt.Errorf("mime: html part: %w", err)
	}
	if _, err := io.WriteString(hw, in.HTML); err != nil {
		return fmt.Errorf("mime: html part: %w", err)
	}
	return hw.Close()
}

// writeAttachment opens path, guesses its content type from the file
// extension, and writes it as a base64 attachment (M16 lists only text
// lines; the library always base64-encodes attachments regardless of
// content).
func writeAttachment(mw *gomail.Writer, path string) error {
	f, err := os.Open(path) //nolint:gosec // G304: tools.callerAttachments checks a caller path with guard.AttachPath; addForward writes the other paths in its own temp dir
	if err != nil {
		return fmt.Errorf("mime: attachment: %w", err)
	}
	defer func() { _ = f.Close() }()

	name := filepath.Base(path)
	ct := "application/octet-stream"
	// TypeByExtension returns a full "type/subtype; param=..." string
	// (e.g. "text/plain; charset=utf-8" for .txt); ParseMediaType
	// splits it back to the bare type SetContentType wants.
	if guess := stdmime.TypeByExtension(filepath.Ext(name)); guess != "" {
		if t, _, err := stdmime.ParseMediaType(guess); err == nil {
			ct = t
		}
	}

	var ah gomail.AttachmentHeader
	ah.SetContentType(ct, nil)
	ah.SetFilename(name)
	aw, err := mw.CreateAttachment(ah)
	if err != nil {
		return fmt.Errorf("mime: attachment: %w", err)
	}
	if _, err := io.Copy(aw, f); err != nil {
		return fmt.Errorf("mime: attachment: %w", err)
	}
	return aw.Close()
}
