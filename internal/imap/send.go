// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	stdmime "mime"
	netmail "net/mail"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	gomail "github.com/emersion/go-message/mail"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// hostsThatSaveSent are the SMTP hosts that put a copy of an outgoing
// message in the Sent folder themselves. With save_sent = "auto" this
// account adds no copy for such a host, because a second copy shows
// the person two of every message (C13).
//
// arch: T5.2, §3.10, C13
var hostsThatSaveSent = []string{
	"gmail.com",
	"googlemail.com",
	"outlook.com",
	"office365.com",
}

// SendFunc puts one message on the wire. [NewWriter] uses [SendMail].
// A test replaces it, so a case can read the bytes that left and can
// make the send fail at a chosen step (C14).
//
// arch: T5.2, §3.11, C14
type SendFunc func(ctx context.Context, acct config.Account, cred Credential, p SendParams) error

// CredentialFunc reads the login of the account each time it runs.
// The pool reads the credential the same way, because a token ends
// after about an hour and a value that a caller read once and kept
// then fails every send after it (B14).
//
// arch: T5.2, §3.4, B14
type CredentialFunc func(ctx context.Context) (Credential, error)

// WriteProvider is [Provider] plus the write half of [tools.Writer]:
// SaveDraft and SendDraft. It embeds the read provider, so it answers
// every read method as well.
//
// arch: DRV.16a
//
// It is a second type and not more fields on Provider for one
// reason: a write needs the account block (the Sent rule, the SMTP
// address, the identities) and the login, and a read needs neither.
// A read call site therefore keeps a value that carries no secret
// source at all.
//
// arch: T5.2, §3.10, §3.11, C13, C14, C15, C16, §10.7
type WriteProvider struct {
	*Provider

	acct config.Account
	cred CredentialFunc

	// forget drops the cached credential of the account, so that the
	// next cred call reads a fresh token. It may be nil (DS11.14).
	forget func()

	// send puts the message on the wire. NewWriter sets SendMail.
	send SendFunc

	// now and rnd feed the Date and the Message-ID of a built
	// message. A test replaces them to get the same bytes each run.
	now func() time.Time
	rnd io.Reader

	// findStoredID gives the id of a message APPEND just stored.
	// NewWriter sets storedID. A test replaces it to force the one
	// case a real server will not reproduce on demand: APPEND
	// worked, but the id search that follows it finds nothing
	// (DRV.19.2).
	//
	// arch: DRV.19.2
	findStoredID func(c *Conn, folder string, data *imap.AppendData, messageID string) (string, error)
}

// NewWriter makes a write provider for one account. cred may be nil;
// a send then fails with a clear error, while a draft or a flag
// change still works, because neither needs the SMTP login.
//
// NewWriter gets a function that drops the cached credential of alias
// (the Factory's forget), so that a refused SMTP login can read a fresh
// token once. forget may be nil; the retry then reads cred again with
// no cache to drop.
//
// arch: T5.2, §3.10, §3.11, T199 item 3, DS11.14
func NewWriter(alias string, pool *Pool, acct config.Account, cred CredentialFunc, forget func()) *WriteProvider {
	return &WriteProvider{
		Provider:     New(alias, pool),
		acct:         acct,
		cred:         cred,
		forget:       forget,
		send:         SendMail,
		now:          time.Now,
		rnd:          rand.Reader,
		findStoredID: storedID,
	}
}

// SendDraft sends a draft that SaveDraft stored before (§3.10).
//
// It reads the stored source, takes the envelope out of its headers,
// and sends that source with the Bcc header removed (C16). The copy
// in Sent keeps the Bcc header. The draft goes away after the send,
// so a person does not send it a second time by hand.
//
// The reply id header (mime.ReplyIDHeader) is for this account only.
// SendDraft reads it, then removes it from the bytes that go on the
// wire and from the Sent copy. afterSend gets the id; the flag
// \Answered by id then needs a Message-ID match (DR1G.8, IR1G.9).
//
// arch: T5.2, §3.10, §3.11, C13, C14, C16, §10.7, DR1G.8, DR1G.18, IR1G.9
func (w *WriteProvider) SendDraft(ctx context.Context, id string) (mail.SendResult, error) {
	raw, err := w.draftSource(ctx, id)
	if err != nil {
		return mail.SendResult{}, err
	}
	head, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return mail.SendResult{}, fmt.Errorf("imap: this draft has no readable header block: %w", err)
	}
	from, err := w.envelopeFrom(head.Header.Get("From"))
	if err != nil {
		return mail.SendResult{}, err
	}
	// REVIEW-2026-10-12 H2: a recipient header that does not parse
	// stops the send here, before any SMTP call. The mail never goes
	// to the other headers only.
	var groups [3][]string
	for i, key := range []string{"To", "Cc", "Bcc"} {
		if groups[i], err = headerAddrs(head.Header, key); err != nil {
			return mail.SendResult{}, err
		}
	}
	to, err := envelopeTo(groups[0], groups[1], groups[2])
	if err != nil {
		return mail.SendResult{}, err
	}
	replyID := decodeReplyID(head.Header.Get(mime.ReplyIDHeader))
	out := stripHeader(raw, mime.ReplyIDHeader)
	if err := w.wire(ctx, from, to, out); err != nil {
		return mail.SendResult{}, err
	}

	res := mail.SendResult{Sent: true}
	// A draft that another program wrote has no reply id. Then
	// replyID is "" and \Answered uses the Message-ID search.
	w.afterSend(ctx, &res, out, head.Header.Get("In-Reply-To"), replyID)
	// The mail left. A draft that stays is a second copy the person
	// may send again, so the removal runs after the send and never
	// changes sent: true (M3).
	if err := w.dropDraft(ctx, id); err != nil && res.Warning == "" {
		res.Warning = "the message was sent, but the draft could not be removed: " + err.Error()
	}
	return res, nil
}

// wire puts one message on the SMTP wire. The bytes that leave carry
// no Bcc header (C16).
//
// When the server refuses a token login with 535, wire drops the
// cached credential, reads a fresh token and sends one more time. A
// wall clock that stepped back can make an expired token look fresh,
// and the IMAP dial already recovers the same way (Factory.login).
// The refusal comes from AUTH, before MAIL FROM and DATA, so the
// message has not left and the second send cannot make a copy
// (IS11.7). A second refusal comes back as it is.
//
// arch: T5.2, §3.11, C16, DS11.14, DS11.20, IS11.7, G6
func (w *WriteProvider) wire(ctx context.Context, from string, to []string, raw []byte) error {
	if w.cred == nil {
		return errors.New("imap: this account has no login for sending")
	}
	p := SendParams{
		From:  from,
		To:    to,
		Raw:   stripHeader(raw, "Bcc"),
		Debug: WireDebug(),
	}
	cred, err := w.cred(ctx)
	if err != nil {
		return err
	}
	err = w.send(ctx, w.acct, cred, p)
	if !staleTokenRefused(err, cred) {
		return err
	}
	if w.forget != nil {
		w.forget()
	}
	cred, reread := w.cred(ctx)
	if reread != nil {
		return errors.Join(err, reread)
	}
	return w.send(ctx, w.acct, cred, p)
}

// staleTokenRefused reports whether a fresh token can fix the send
// error err: the server refused a token login with 535, and the reply
// is not 5.7.139 (the tenant has SMTP AUTH off, which no token fixes).
// A password login, a 454 and every other code give false, so the
// error goes back as it is (DS11.20 G1).
//
// arch: DS11.14, DS11.20, G6
func staleTokenRefused(err error, cred Credential) bool {
	var authErr *SMTPAuthError
	return cred.Token != "" && errors.As(err, &authErr) && authErr.Code == 535 && !authErr.tenantAuthOff()
}

// afterSend runs the two steps that follow a send: the copy in Sent
// and the \Answered flag on the message that this one answers.
//
// replyToID comes from the draft, so it can be forged or out of date.
// markAnsweredByID sets the flag only when the message at that id has
// the Message-ID inReplyTo. Else the Message-ID search runs
// (DR1G.8).
//
// Neither step can fail the call. The mail already left, so a failure
// here gives a warning and nothing else (C14).
//
// arch: T5.2, §3.10, C13, C14, DR1G.8, IR1G.9
func (w *WriteProvider) afterSend(ctx context.Context, res *mail.SendResult, raw []byte, inReplyTo, replyToID string) {
	copyToSent := w.savesSentCopy()
	if !copyToSent && inReplyTo == "" && replyToID == "" {
		return
	}
	err := w.pool.WithWrite(ctx, w.alias, func(c *Conn) error {
		folders, err := w.roleFolders(c)
		if err != nil {
			return err
		}
		if copyToSent {
			id, err := w.appendToRole(c, folders, "sent", raw, []imap.Flag{imap.FlagSeen})
			var miss *storedIDMissError
			switch {
			case err == nil:
				res.ID, res.SavedToSent = id, true
			case errors.As(err, &miss):
				// The copy is in Sent; only its id is unknown. That
				// is not a reason to fail the two best-effort steps
				// that follow, so the loop carries on (DRV.19.2).
				res.SavedToSent = true
				res.Warning = "the message was sent, but the Sent copy was stored but not found again: " + err.Error()
			default:
				return err
			}
		}
		// Best effort: the flag is a courtesy for the other mail
		// clients of the person, not part of the send (§3.10).
		if replyToID != "" && inReplyTo != "" {
			// replyToID names the exact folder and UID (§3.8), so the
			// STORE addresses the original directly, in any folder,
			// instead of guessing with a search over a few role
			// folders. With no In-Reply-To there is nothing to
			// match, so the id alone sets no flag.
			if err := markAnsweredByID(c, replyToID, inReplyTo); err == nil {
				return nil
			}
		}
		if inReplyTo != "" {
			markAnswered(c, folders, inReplyTo)
		}
		return nil
	})
	if err != nil && copyToSent {
		res.Warning = "the message was sent, but the copy in the Sent folder failed: " + err.Error()
	}
}

// savesSentCopy says whether this account adds its own copy in Sent
// (C13). It keeps the signature afterSend already uses; sentCopy
// makes the decision.
//
// arch: T5.2, §3.10, C13, DR1G.18.7
func (w *WriteProvider) savesSentCopy() bool {
	mailbagSaves, _ := sentCopy(w.acct.SaveSent, w.acct.SMTP)
	return mailbagSaves
}

// sentCopy gives whether mailbag saves a copy of an outgoing message
// in Sent, and whether the SMTP host keeps one on its own (C13).
// "always" always adds one and "never" never does. "auto", the
// default, adds one unless the host saves a copy itself. The send
// path (savesSentCopy) and the capability report's save_sent advice
// (imap.SaveSentAdvice) both read this one decision, so the rule is
// never restated (IR1G.15).
//
// An SMTP address that cannot be split (today, an empty one; see
// splitHostPort) keeps the per-setting behavior this function had
// before hostKeeps existed, and reports the host's own behavior as
// unknown (false).
//
// arch: T5.2, §3.10, C13, DR1G.11, DR1G.18.7, IR1G.15
func sentCopy(saveSent, smtp string) (mailbagSaves, hostKeeps bool) {
	switch strings.ToLower(strings.TrimSpace(saveSent)) {
	case "always":
		host, _, err := splitSMTPAddr(smtp)
		if err != nil {
			return true, false
		}
		return true, hostSavesSent(host)
	case "never":
		host, _, err := splitSMTPAddr(smtp)
		if err != nil {
			return false, false
		}
		return false, hostSavesSent(host)
	default: // "auto", including the empty default
		host, _, err := splitSMTPAddr(smtp)
		if err != nil {
			return true, false
		}
		keeps := hostSavesSent(host)
		return !keeps, keeps
	}
}

// hostSavesSent reports whether the SMTP host puts the message in
// Sent on its own (C13). A host matches on its domain or on any name
// below it, so "notgmail.com" is not "gmail.com".
//
// arch: T5.2, §3.10, C13
func hostSavesSent(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, d := range hostsThatSaveSent {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// appendToRole puts raw in the folder that carries role and gives the
// id of the new message.
//
// arch: T5.2, §3.10, C15
func (w *WriteProvider) appendToRole(c *Conn, folders []mail.Folder, role string, raw []byte, flags []imap.Flag) (string, error) {
	name, ok := folderNamed(folders, role)
	if !ok {
		return "", fmt.Errorf("imap: this account has no %s folder; name one with folders.%s in accounts.toml", role, role)
	}
	data, err := appendMessage(c, name, raw, flags, w.now())
	if err != nil {
		return "", err
	}
	return w.findStoredID(c, name, data, messageIDOf(raw))
}

// markAnsweredByID sets \Answered on the exact message that id names
// (§3.8, §3.10). It reaches any folder, not only the role folders
// markAnswered searches, because the id already carries the folder
// and the UID.
//
// The id comes from a draft header, which another client can edit.
// So the flag goes on only when that message has the Message-ID
// inReplyTo. A bad id, a message that is gone, or another Message-ID
// gives an error, and the caller uses the Message-ID search instead
// (DR1G.8, IR1G.9).
//
// arch: T5.2, §3.8, §3.10, C10, DR1G.8, IR1G.9
func markAnsweredByID(c *Conn, id, inReplyTo string) error {
	v, u, folder, err := mail.ParseIMAPID(id)
	if err != nil {
		return err
	}
	folder, err = resolveFolder(c, folder)
	if err != nil {
		return err
	}
	sel, err := selectWrite(c, folder)
	if err != nil {
		return err
	}
	if err := checkUIDValidity(sel, v); err != nil {
		return err
	}
	ids, err := fetchMessageIDs(c, []imap.UID{imap.UID(u)})
	if err != nil {
		return err
	}
	want := angled(strings.TrimSpace(inReplyTo))
	if got := ids[imap.UID(u)]; want == "" || got != want {
		return fmt.Errorf("imap: message %s is not the message this reply answers", id)
	}
	op := &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagAnswered}, Silent: true}
	return c.Store(imap.UIDSetNum(imap.UID(u)), op, nil).Close()
}

// decodeReplyID gives the mailbag id in the value of a reply id
// header. mime.Build writes an id that is not plain ASCII as RFC 2047
// words. A value that does not decode stays as it is; then
// markAnsweredByID refuses it and the Message-ID search runs.
//
// arch: DR1G.8, DR1G.18
func decodeReplyID(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if dec, err := new(stdmime.WordDecoder).DecodeHeader(v); err == nil {
		return dec
	}
	return v
}

// markAnswered sets \Answered on the message that a reply answers
// (§3.10). inReplyTo is its Message-ID.
//
// IMAP has no index over the whole account, so the search runs in the
// inbox, the archive and the all-mail folder, and stops at the first
// hit. A message in another folder keeps its flags: the flag is a
// courtesy, and a search over every folder would cost a command for
// each of them on every reply.
//
// It reports nothing. A failure here must never change the result of
// a send that already left (C14).
//
// arch: T5.2, §3.10, C10
func markAnswered(c *Conn, folders []mail.Folder, inReplyTo string) {
	crit := &imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: inReplyTo}},
	}
	for _, role := range []string{"inbox", "archive", "all"} {
		name, ok := folderNamed(folders, role)
		if !ok {
			continue
		}
		if _, err := selectWrite(c, name); err != nil {
			continue
		}
		uids, err := uidSearch(c, crit)
		if err != nil || len(uids) == 0 {
			continue
		}
		op := &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagAnswered}, Silent: true}
		if err := c.Store(imap.UIDSetNum(uids...), op, nil).Close(); err == nil {
			return
		}
	}
}

// build writes the RFC 822 source of one outgoing message. The source
// holds the Bcc header; the caller removes it from the copy that goes
// on the wire (C16). It also holds the reply id header when m answers
// a message; the send path removes it from the wire and the Sent copy
// (DR1G.8).
//
// arch: T5.2, §3.14, C16, DR1G.8, DR1G.18
func (w *WriteProvider) build(m *mail.Outgoing, from string) ([]byte, error) {
	var b bytes.Buffer
	in := mime.Input{
		From:        from,
		To:          m.To,
		Cc:          m.Cc,
		Bcc:         m.Bcc,
		Subject:     m.Subject,
		Text:        m.Text,
		HTML:        m.HTML,
		Attachments: m.Attachments,
		InReplyTo:   m.InReplyTo,
		References:  m.References,
		// SaveDraft is the only caller of build, so only a stored
		// draft carries the reply id header (DR1G.18.6).
		ReplyID: m.ReplyToID,
	}
	if err := mime.Build(&b, in, w.now(), w.rnd); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// headerFrom gives the value of the From header. In identity mode it
// is the caller value with its display name, which envelopeFrom has
// parsed already. Outside identity mode, and for an empty caller
// value, it is the bare address, as before (DI6.1).
//
// arch: DI6.1
func (w *WriteProvider) headerFrom(callerFrom, bare string) string {
	if w.acct.IdentityMode() && strings.TrimSpace(callerFrom) != "" {
		return strings.TrimSpace(callerFrom)
	}
	return bare
}

// envelopeFrom gives the envelope sender. An empty from means the
// account address. Any other value must be the account address or one
// of its identities, so a model cannot send as another person (M13).
//
// The identity list comes from the account block of accounts.toml.
// The provider needs no method of its own for it. Account.OwnsAddress
// decides: outside identity mode it is the raw compare of the account
// address and the flat list; in identity mode it also accepts the
// identity tables and the reply_match patterns (DI6.1).
//
// arch: T5.2, §3.11, M13, DI6.1
func (w *WriteProvider) envelopeFrom(from string) (string, error) {
	if strings.TrimSpace(from) == "" {
		if w.acct.Email == "" {
			return "", errors.New("imap: this account has no email address; add one to accounts.toml")
		}
		return w.acct.Email, nil
	}
	addr, err := gomail.ParseAddress(from)
	if err != nil {
		return "", fmt.Errorf("imap: from address: %w", err)
	}
	if w.acct.OwnsAddress(addr.Address) {
		return addr.Address, nil
	}
	return "", fmt.Errorf("imap: %q is not the address of this account and not one of its identities", addr.Address)
}

// envelopeTo gives the recipients of the SMTP envelope: To, Cc and
// Bcc together, as bare addresses, with the duplicates removed
// (§3.11).
//
// arch: T5.2, §3.11
func envelopeTo(to, cc, bcc []string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for _, group := range [][]string{to, cc, bcc} {
		for _, one := range group {
			if strings.TrimSpace(one) == "" {
				continue
			}
			addr, err := gomail.ParseAddress(one)
			if err != nil {
				return nil, fmt.Errorf("imap: recipient address: %w", err)
			}
			key := strings.ToLower(addr.Address)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, addr.Address)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("imap: the message has no recipient")
	}
	return out, nil
}

// headerAddrs gives the addresses of one header as text, one entry
// for each address. A header that is not there or is blank gives
// nothing and no error. A header that does not parse gives an error,
// so the send stops: a recipient list with a gap is never sent.
//
// It parses with mime.ParseAddressList, the go-message parser that
// the confirmation summary of the send tool also uses. That parser
// reads encoded words in each charset go-message knows, so the human
// approves the same recipients that the envelope holds.
//
// arch: REVIEW-2026-10-12 H2, REVIEW-2026-10-12 H3
func headerAddrs(h netmail.Header, key string) ([]string, error) {
	list, err := mime.ParseAddressList(h.Get(key))
	if err != nil {
		return nil, fmt.Errorf("imap: the %s header of this draft does not parse as a list of addresses, so nothing was sent: %w", key, err)
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out, nil
}

// messageIDOf reads the Message-ID of a built message. It gives an
// empty string when the header block does not parse, and the caller
// then has no fallback for the id (C15).
func messageIDOf(raw []byte) string {
	head, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(head.Header.Get("Message-ID"))
}

// stripHeader removes one header, with every folded line of it, from
// the header block of a message. The body stays byte for byte as it
// was: the message is signed or encoded already, and a rebuild would
// change it.
//
// This is the Bcc rule of C16: the hidden addresses belong in the
// envelope and in the copy in Sent, never in the message that a
// recipient reads.
//
// arch: T5.2, §3.10, C16
func stripHeader(raw []byte, name string) []byte {
	head, body := splitHeaders(raw)
	prefix := strings.ToLower(name) + ":"

	out := make([]byte, 0, len(raw))
	drop := false
	for len(head) > 0 {
		line, rest := nextLine(head)
		head = rest
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if drop {
				continue // a folded line of the header that goes away
			}
			out = append(out, line...)
			continue
		}
		drop = strings.HasPrefix(strings.ToLower(string(line)), prefix)
		if drop {
			continue
		}
		out = append(out, line...)
	}
	return append(out, body...)
}

// splitHeaders cuts a message in two at the empty line. head holds
// the header lines with their line ends; body starts with the empty
// line. A message with no empty line is all header, which is what a
// header-only draft looks like.
func splitHeaders(raw []byte) (head, body []byte) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i+2], raw[i+2:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i+1], raw[i+1:]
	}
	return raw, nil
}

// nextLine cuts one line, with its line end, off the front.
func nextLine(b []byte) (line, rest []byte) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return b, nil
	}
	return b[:i+1], b[i+1:]
}

// --- write-path primitives -----------------------------------------

// selectWrite opens folder for writing. A read uses examine, which
// sends EXAMINE (C3); a STORE, an APPEND with an expunge, or a MOVE
// needs SELECT. Both keep Conn.Selected in step, so the next call
// knows which folder is open (§3.10).
//
// arch: T5.2, §3.10, C3
func selectWrite(c *Conn, folder string) (*imap.SelectData, error) {
	data, err := c.Select(folder, nil).Wait()
	if err != nil {
		c.Selected = ""
		return nil, fmt.Errorf("imap: select %q: %w", folder, err)
	}
	c.Selected = folder
	return data, nil
}

// appendMessage stores one message in a folder. The answer carries
// the UID when the server has UIDPLUS (C15).
//
// arch: T5.2, §3.10, C15
func appendMessage(c *Conn, folder string, raw []byte, flags []imap.Flag, when time.Time) (*imap.AppendData, error) {
	cmd := c.Append(folder, int64(len(raw)), &imap.AppendOptions{Flags: flags, Time: when})
	if _, err := cmd.Write(raw); err != nil {
		_ = cmd.Close()
		return nil, fmt.Errorf("imap: append to %q: %w", folder, err)
	}
	if err := cmd.Close(); err != nil {
		return nil, fmt.Errorf("imap: append to %q: %w", folder, err)
	}
	data, err := cmd.Wait()
	if err != nil {
		return nil, fmt.Errorf("imap: append to %q: %w", folder, err)
	}
	return data, nil
}

// storedIDMissError marks the one storedID failure that is not a
// true failure: APPEND put the message in folder, but the follow-up
// search for it by Message-ID (used when the server has no UIDPLUS)
// found nothing. The message is still there; only its id is unknown.
// SaveDraft and afterSend turn this one into a warning instead of
// failing a call that already stored the message (DRV.19.2).
//
// arch: DRV.19.2
type storedIDMissError struct {
	folder string
}

func (e *storedIDMissError) Error() string {
	return fmt.Sprintf("imap: the message went into %q, but the server does not find it again by its Message-ID", e.folder)
}

// storedID gives the id of the message that APPEND just stored.
//
// APPENDUID gives it in the answer of the command itself. A server
// with no UIDPLUS sends no such code, so the id comes from a search
// for the Message-ID of the message (C15). Both give an id of the
// form that every other tool takes.
//
// arch: T5.2, §3.10, §3.8, C15
func storedID(c *Conn, folder string, data *imap.AppendData, messageID string) (string, error) {
	if c.Caps().Has(imap.CapUIDPlus) && data != nil && data.UID != 0 {
		return mail.FormatIMAPID(data.UIDValidity, uint32(data.UID), folder), nil
	}
	if messageID == "" {
		return "", fmt.Errorf("imap: the server gave no APPENDUID for %q and the message has no Message-ID", folder)
	}
	sel, err := examine(c, folder)
	if err != nil {
		return "", err
	}
	crit := &imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: messageID}},
	}
	uids, err := uidSearch(c, crit)
	if err != nil {
		return "", err
	}
	newest, ok := newestUID(uids)
	if !ok {
		return "", &storedIDMissError{folder: folder}
	}
	return mail.FormatIMAPID(sel.UIDValidity, uint32(newest), folder), nil
}

// roleFolders lists the folders of the account with their roles, with
// the [accounts.<alias>.folders] table of accounts.toml applied over
// what the server said (C10).
//
// arch: T5.2, §3.10, C10
func (w *WriteProvider) roleFolders(c *Conn) ([]mail.Folder, error) {
	list, err := listMailboxes(c, listOptions(c, false))
	if err != nil {
		return nil, err
	}
	out := make([]mail.Folder, 0, len(list))
	roles := listRoles(list)
	for i, d := range list {
		if hasAttr(d.Attrs, imap.MailboxAttrNoSelect) || hasAttr(d.Attrs, imap.MailboxAttrNonExistent) {
			continue
		}
		out = append(out, mail.Folder{Name: d.Mailbox, Role: roles[i]})
	}
	ApplyRoleOverrides(out, w.acct.Folders)
	return out, nil
}

// folderNamed gives the name of the folder that carries role.
func folderNamed(folders []mail.Folder, role string) (string, bool) {
	for _, f := range folders {
		if f.Role == role {
			return f.Name, true
		}
	}
	return "", false
}
