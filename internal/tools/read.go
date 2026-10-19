// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	stdmime "mime"
	"mime/multipart"
	netmail "net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
	"github.com/amsys/mailbag-mcp/internal/undo"
	"github.com/amsys/mailbag-mcp/internal/verify"
)

// readDefaultMaxChars is the body limit of Appendix B.
// readCeilingMaxChars is the largest value a caller may ask for. The
// IMAP layer caps the bytes it fetches (§3.10), and this second cap
// bounds the characters that reach one tool result, so a long message
// cannot fill the model context in one call.
const (
	readDefaultMaxChars = 20000
	readCeilingMaxChars = 100000
)

// ReadIn is the input of the read tool (App B).
type ReadIn struct {
	Account  string `json:"account"`
	ID       string `json:"id" jsonschema:"from search"`
	Thread   bool   `json:"thread,omitempty"`
	Format   string `json:"format,omitempty" jsonschema:"text (default) or html"`
	MaxChars int    `json:"max_chars,omitempty" jsonschema:"default 20000, max 100000"`
	Offset   int    `json:"offset,omitempty" jsonschema:"continue a truncated body"`
	MarkRead bool   `json:"mark_read,omitempty"`
}

// AttachmentRow is one attachment of a read result.
//
// Ref and Size come from the server structure (BODYSTRUCTURE), so
// they stay outside the fence. File holds the sender's file name and
// the sender's media type, which §3.15 lists as sender-controlled, so
// it is fenced (G3).
type AttachmentRow struct {
	Ref  string `json:"ref"`
	Size int64  `json:"size,omitempty"`
	File string `json:"file"`
}

// ReadMessage is one message of a read result (§3.16).
//
// Date is the server time (INTERNALDATE), never a Date header a
// sender wrote, so it is the one date outside the fence (E12). Every
// sender-controlled field of this message sits in Headers, Body or
// AttachmentRow.File, each of them fenced (G3, §3.15).
type ReadMessage struct {
	ID     string `json:"id"`
	Folder string `json:"folder"`
	Date   string `json:"date"`
	Flags  string `json:"flags,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// Headers holds from, to, cc, reply-to and subject inside one
	// fence. In a thread row of a message that the caller did not
	// name, it also holds the preview of the thread search.
	Headers string `json:"headers"`
	// Body holds the decoded text of the message inside its own
	// fence.
	Body        string          `json:"body"`
	Attachments []AttachmentRow `json:"attachments,omitempty"`
	// Truncated is true when the body stopped at max_chars. Call
	// read again with offset = next_offset for the rest.
	Truncated  bool `json:"truncated,omitempty"`
	NextOffset int  `json:"next_offset,omitempty"`
	// Hidden counts what was taken out as hidden: the hidden
	// characters of the fenced fields (§3.15) plus the HTML text runs
	// removed as hidden when the body came from an HTML part (D4.1,
	// D4.2). The server counted them, so it stays outside.
	Hidden int `json:"hidden_removed,omitempty"`
	// PartsDiffer is true when the text part and the HTML part differ
	// and Body holds the text of the HTML part (D4.2). The server set
	// it, so it stays outside.
	PartsDiffer bool `json:"parts_differ,omitempty"`
	// Signature is the result of the signature check (D6.1). The
	// server computed each field of it: enum words, hex and booleans
	// only, never sender text (I11). So it stays outside the fence.
	// A message with no signature has no block.
	Signature *verify.Signature `json:"signature,omitempty"`
}

// ReadOut is the read tool result (§3.16). Messages holds one entry,
// or the conversation when thread is true, oldest first.
type ReadOut struct {
	Account  string        `json:"account"`
	Messages []ReadMessage `json:"messages"`
	// Note is text this server wrote, never sender text: what a
	// partial answer left out, or why an option did nothing.
	Note string `json:"note,omitempty"`
}

// AddRead adds the "read" tool to srv (§3.16): read level, one
// message, no change to the mailbox.
//
// arch: T4.5, §3.16, §3.15, App B, G3, E12
func AddRead(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &readTool{mail: m, journal: undo.Open, logger: logger}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "read",
		Description: "Read one message; sender text is fenced.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, Wrap(logger, "read", DefaultTimeout, h.handle))
}

// readTool is the read handler. journal gives the undo directory for
// the entry of mark_read; nil means no entry, so a test that does not
// set it never writes in the real state directory. AddRead sets it.
// logger takes the warn line of a journal write that failed.
type readTool struct {
	mail    Mail
	journal func() (*undo.Journal, error)
	logger  *slog.Logger
}

// handle reads one message, and the rest of its conversation when
// thread is true.
//
// It asks the provider for one character more than the caller's
// limit. That one extra character says whether more text follows, so
// the result can set truncated and next_offset without a second
// fetch.
//
// arch: T4.5, §3.16, §3.15, App B, G3, E12, G10
func (t *readTool) handle(ctx context.Context, in ReadIn) (ReadOut, error) {
	// mark_read is a write (it carries out the STORE of §3.10), so it
	// opens the same write-capable provider the modify tool uses
	// (internal/tools/modify.go) instead of a second path to the IMAP
	// layer. A plain read keeps the read-only provider, which is the
	// right value for a call site that never writes (owner gate
	// decision D-S5.1).
	var reader Reader
	var writer Writer
	var acct config.Account
	var err error
	if in.MarkRead {
		writer, acct, err = t.mail.OpenWriter(ctx, in.Account)
		reader = writer
	} else {
		reader, acct, err = t.mail.Open(ctx, in.Account)
	}
	if err != nil {
		return ReadOut{}, err
	}
	// §3.17: the access check is the line above the work. A plain read
	// stays at the lowest level; mark_read changes the mailbox, so it
	// needs the same draft level the modify tool needs for its writes.
	need := guard.LevelRead
	if in.MarkRead {
		need = guard.LevelDraft
	}
	if err := guard.Require(acct, need); err != nil {
		return ReadOut{}, err
	}
	if in.ID == "" {
		return ReadOut{}, errors.New("id is required; take one from a search row")
	}
	if in.Offset < 0 {
		return ReadOut{}, errors.New("offset must not be negative")
	}
	limit := in.MaxChars
	if limit <= 0 {
		limit = readDefaultMaxChars
	}
	if limit > readCeilingMaxChars {
		limit = readCeilingMaxChars
	}

	m, err := reader.Read(ctx, in.ID, mail.ReadOpts{
		Format:   in.Format,
		MaxChars: limit + 1,
		Offset:   in.Offset,
		MarkRead: in.MarkRead,
	})
	if err != nil {
		return ReadOut{}, err
	}

	var note string
	if in.MarkRead && !m.Flags.Seen {
		// Read always peeks (C2), so the flag never moves on its own;
		// this call is the STORE that internal/imap/modify.go carries
		// out for the modify tool, reused here for the one message
		// just read.
		//
		// The STORE changes the mailbox, so it writes the same undo
		// journal entry as modify with read:true (DRV.11, IRV.9).
		seen := true
		ch := mail.Change{Read: &seen}
		applied, merr := writer.Modify(ctx, []string{in.ID}, ch)
		if merr != nil {
			note = addNote(note, "mark_read could not be applied: "+guard.Redact(merr.Error()))
		} else {
			m.Flags.Seen = true
		}
		if len(applied) > 0 && t.journal != nil {
			recordChange(t.journal, t.logger, in.Account, modifySummary(ch, len(applied)), applied)
		}
	}

	sig, raw, sigNote := t.signature(ctx, reader, m)
	if sigNote != "" {
		note = addNote(note, sigNote)
	}
	if encrypted(m) {
		note = addNote(note, encryptedNote)
	}
	// sigNote is empty only when verify.Check finished. A check that
	// did not finish gives an unsupported verdict over no verified
	// bytes, and a second walk of the source here would run past the
	// D6.2 time limit, so the provider body stays. The same holds for
	// an unsupported verdict that Check gives itself, for example at
	// its own deadline: it names no signer, so no body sits next to a
	// claim. An Unsigned result keeps the D6.2 rule of every earlier
	// stage, whatever its verdict.
	var ent []byte
	var entOK, show bool
	if sigNote == "" && sig != nil && (sig.Unsigned || sig.Verdict != verify.VerdictUnsupported) {
		ent, entOK, show = bodyEntity(raw, sig)
	}
	if show {
		// D6.2: when content sits outside the signed entity, the body
		// shows only the signed entity. Text the signature does not
		// cover never sits next to a verdict. IRV.2: for every
		// multipart/signed verdict, the body comes from the bytes that
		// the check read, not from the provider's own MIME parse.
		var text string
		var removed int
		var differ, ok bool
		if entOK {
			// read's own attachment list comes from the provider
			// structure (toReadMessage), not from this walk, so the
			// DR1G.9 attachment return values are not read here.
			text, removed, differ, ok, _, _ = signedText(ent, in.Format)
		}
		if !ok {
			text, removed, differ = "", 0, false
			switch {
			case entOK && envelopedEntity(ent):
				// The signed content is itself encrypted, for
				// example an opaque signed-data whose content is
				// enveloped-data: the D7.3 note, not text (DR1G.3).
				note = addNote(note, encryptedNote)
			case sig.Unsigned:
				note = addNote(note, "the body is empty: content sits outside the signature and the signed part has no text that this server can show")
			default:
				note = addNote(note, "the body is empty: the signed part has no text that this server can show")
			}
		}
		m.Body = cutRunes(text, in.Offset, limit+1)
		m.HiddenRemoved = removed
		m.PartsDiffer = differ
	}

	full := toReadMessage(*m, limit, in.Offset)
	full.Signature = sig
	out := ReadOut{Account: in.Account, Messages: []ReadMessage{full}, Note: note}

	if in.Thread {
		tr, terr := reader.Thread(ctx, in.ID)
		if terr != nil {
			// The message itself was read. A conversation that
			// failed is a note, not a failed call (§3.10).
			out.Note = addNote(out.Note, "the conversation could not be read: "+guard.Redact(terr.Error()))
			return out, nil
		}
		list := tr.Messages
		// imap already keeps only the newest threadCutAt messages of a
		// conversation (§3.10, internal/imap/thread.go maxThread). This
		// layer cannot tell a thread that was cut to that size apart
		// from one that happened to have exactly that many messages, so
		// a thread of that size gets a best-effort note either way
		// (DRV.16d).
		if len(list) >= threadCutAt {
			out.Note = addNote(out.Note, "the conversation may be longer than "+strconv.Itoa(threadCutAt)+" messages; only the newest "+strconv.Itoa(threadCutAt)+" are shown")
		}
		// A folder the search could not read, or a preview it could
		// not fetch, is a count only: no folder name, no sender text
		// (DR1G.4, DR1G.5, DR1G.18.3, I14).
		if tr.Skipped > 0 {
			out.Note = addNote(out.Note, skippedFoldersNote(tr.Skipped))
		}
		if tr.PreviewsMissing > 0 {
			out.Note = addNote(out.Note, missingPreviewsNote(tr.PreviewsMissing))
		}
		out.Messages = threadRows(list, full, in.ID, limit)
	}
	return out, nil
}

// skippedFoldersNote is the fixed text read and export give when a
// thread search could not check every folder. It never names a
// folder: that is server data (DR1G.4, I14).
//
// arch: DR1G.4, DR1G.18
func skippedFoldersNote(n int) string {
	return fmt.Sprintf("%d folder(s) could not be searched; the conversation may be incomplete", n)
}

// missingPreviewsNote is the fixed text read and export give when a
// thread search left some messages with no preview (DR1G.5,
// DR1G.18.3). search.go's searchIn gives the same text on a Page.
//
// arch: DR1G.5, DR1G.18
func missingPreviewsNote(n int) string {
	return fmt.Sprintf("previews are missing for %d message(s)", n)
}

// threadRows turns the conversation into result rows. The message the
// caller named keeps the full body that Read decoded; the others come
// from the thread search, which reads the headers and a preview only
// (§3.10). The preview goes into the header fence as a "preview:"
// line, as in a search row, so the note on missing previews names
// data that the result holds (DR1G.18.3, R16-M7).
func threadRows(list []*mail.Message, full ReadMessage, id string, limit int) []ReadMessage {
	rows := make([]ReadMessage, 0, len(list)+1)
	found := false
	for _, m := range list {
		if m == nil {
			continue
		}
		if m.ID == id {
			rows = append(rows, full)
			found = true
			continue
		}
		head := headerText(*m)
		if m.Preview != "" {
			head += "\npreview: " + m.Preview
		}
		rows = append(rows, readRow(*m, head, limit, 0))
	}
	if !found {
		rows = append(rows, full)
	}
	return rows
}

// toReadMessage builds one result row and fences every
// sender-controlled field of it (§3.15, G3).
func toReadMessage(m mail.Message, limit, offset int) ReadMessage {
	return readRow(m, headerText(m), limit, offset)
}

// readRow builds one result row with head as the text of the header
// fence. It fences every sender-controlled field (§3.15, G3).
func readRow(m mail.Message, head string, limit, offset int) ReadMessage {
	body := m.Body
	truncated := false
	next := 0
	if r := []rune(body); limit > 0 && len(r) > limit {
		body = string(r[:limit])
		truncated = true
		next = offset + limit
	}

	fencedHead, headHidden := fencedCount("EMAIL", head)
	fencedBody, bodyHidden := fencedCount("BODY", body)
	row := ReadMessage{
		ID:          m.ID,
		Folder:      m.Folder,
		Date:        m.Date.UTC().Format(time.RFC3339),
		Flags:       flagText(m.Flags),
		Size:        m.Size,
		Headers:     fencedHead,
		Body:        fencedBody,
		Truncated:   truncated,
		NextOffset:  next,
		Hidden:      headHidden + bodyHidden + m.HiddenRemoved,
		PartsDiffer: m.PartsDiffer,
	}
	for _, a := range m.Attachments {
		file, hidden := fencedCount("ATTACHMENT", "name: "+a.Filename+"\ntype: "+a.ContentType)
		row.Hidden += hidden
		row.Attachments = append(row.Attachments, AttachmentRow{Ref: a.Ref, Size: a.Size, File: file})
	}
	return row
}

// headerText writes the sender-controlled header lines of one
// message. Every line here goes inside a fence.
//
// The Date header is not in this text because [mail.Message] does not
// carry it: the provider reads INTERNALDATE, which the server owns,
// and that value is the ReadMessage.Date field outside the fence
// (E12). No sender-written date reaches the result at all.
func headerText(m mail.Message) string {
	var b strings.Builder
	b.WriteString("from: ")
	b.WriteString(addressText(m.From))
	if len(m.To) > 0 {
		b.WriteString("\nto: ")
		b.WriteString(addressListText(m.To))
	}
	if len(m.Cc) > 0 {
		b.WriteString("\ncc: ")
		b.WriteString(addressListText(m.Cc))
	}
	if len(m.ReplyTo) > 0 {
		b.WriteString("\nreply-to: ")
		b.WriteString(addressListText(m.ReplyTo))
	}
	b.WriteString("\nsubject: ")
	b.WriteString(m.Subject)
	return b.String()
}

// addressListText writes a list of addresses on one line.
func addressListText(list []mail.Address) string {
	parts := make([]string, 0, len(list))
	for _, a := range list {
		parts = append(parts, addressText(a))
	}
	return strings.Join(parts, ", ")
}

// fencedCount fences body and also reports how many hidden characters
// the fence took out, so the row can show that count outside the
// fence (§3.15).
func fencedCount(kind, body string) (string, int) {
	_, hidden := guard.StripInvisible(body)
	return guard.Fence(kind, body), hidden
}

// addNote joins two note lines.
func addNote(have, add string) string {
	if have == "" {
		return add
	}
	return have + "\n" + add
}

// encryptedNote is the fixed note read gives for an encrypted
// message. It holds no sender text (I11). read fetches nothing for
// it: the decrypt tool reads the source itself (D7.3).
const encryptedNote = "this message is encrypted; the decrypt tool can open it when decryption is on"

// encrypted reports whether the top-level media type of m names an
// encrypted message: multipart/encrypted, or a part that
// mail.SMIMEKindOfValue names SMIMEEnveloped (smime-type
// enveloped-data or authenveloped-data). All compares ignore case. It
// reads only the fields the provider already gave, so it causes no
// fetch, and it does not change the signature check (D7.3, D6.2,
// DR1G.2).
func encrypted(m *mail.Message) bool {
	if strings.EqualFold(strings.TrimSpace(m.MediaType), "multipart/encrypted") {
		return true
	}
	return mail.SMIMEKindOfValue(m.MediaType, m.SMIMEType) == mail.SMIMEEnveloped
}

// notCheckedNote is the fixed note read gives when the provider hints
// a signature but the source never reached the check: the size cap or
// a Raw error. It tells "not checked" apart from "no signature"
// (D10.3, R1E-fix-judge.md new finding 3).
const notCheckedNote = "the signature was not checked: the source could not be fetched"

// checkNotFinishedNote is the fixed note read gives when the server
// fetched the source but the check did not finish: the D6.2 time limit
// ended it, or it panicked. The source was fetched, so notCheckedNote
// would state a false reason (R1E-close-judge.md new finding 1). It
// holds no sender text (I11).
const checkNotFinishedNote = "the signature was not checked: the check did not finish"

// verifyTimeout is the D6.2 time limit on one signature check. A test
// makes it short to reach the limit.
var verifyTimeout = verify.Timeout

// verifyCheckDone is called, when set, right after the background
// goroutine of signature's call to verify.Check returns or recovers
// from a panic, so a test can learn exactly when that goroutine ends
// instead of reading runtime.NumGoroutine(): the count right after
// signature returns already carries this same goroutine, so a
// tolerance wide enough to allow for it hides the very thing a test
// of F-D6 needs to see (R1E-judge.md finding 7). nil in production.
var verifyCheckDone func()

// verifyCheck is the check that signature runs. It is verify.Check in
// production. A test replaces it to make the check panic or block.
var verifyCheck = verify.Check

// verifyConfigSource is a [Mail] that can give the [verify] keys of
// accounts.toml. [Factory] is one. A Mail that is not one checks with
// no keys: no key gives trust, so no verdict is verified.
type verifyConfigSource interface {
	VerifyConfig() verify.Config
}

// VerifyConfig gives the [verify] keys of accounts.toml (D6.2). A
// config that cannot be read gives no keys. The Open call of the same
// read already failed with the real reason in that case.
//
// arch: D6.2
func (f *Factory) VerifyConfig() verify.Config {
	cfg, err := f.config()
	if err != nil {
		return verify.Config{}
	}
	return cfg.Verify()
}

// signature gives the signature result of m (D6.1, D6.2), the raw
// source it checked, and a note for the human when the source could
// not be checked. A nil result means no signature.
//
// The provider hint mail.Message.SignedHint decides whether the whole
// source is fetched (R1E-fix-plan F-D1 option b). The hint has three
// states and the gate fails closed: mail.SignedYes and
// mail.SignedUnknown both fetch the source and check it, and only
// mail.SignedNo skips the fetch. A provider that sets nothing reports
// mail.SignedUnknown, so a new provider costs one fetch per read and
// never a lost check (R1E-fix2-judge.md new finding 1).
//
// A message the provider marks mail.SignedNo can still carry a DKIM
// result, so the check then runs on the Authentication-Results header
// block that the provider already fetched with the row. An unsigned
// message from such a provider costs no extra fetch, on the first
// page and on each further page.
//
// DKIM never hides a signature on the content: verify.Check runs
// OpenPGP and S/MIME on the whole source before DKIM, so a message
// read on the unknown branch gets the content verdict when it has
// one, and the header verdict only when it has none.
//
// The provider view of the tool layer is not the gate: the hint comes
// from BODYSTRUCTURE at any depth and from the full decoded text,
// before the cut to offset and max_chars, so a signature part with no
// file name and a marker past the offset both keep their verdict. The
// verdict never depends on a paging argument.
//
// A D6.2 limit (25 MB, MIME depth 10, 5 seconds), a Raw fetch that
// fails and a panic in the check give verdict unsupported, never
// invalid, because the server did not check the signature (D10.3). A
// hinted message whose source the server never fetched, because of
// the size cap or a Raw error, also carries the fixed note
// notCheckedNote, so the human can tell "not checked" from "no
// signature" (R1E-fix-judge.md new finding 3). A check that ran on the
// fetched source but did not finish, because of the time limit or a
// panic, carries the fixed note checkNotFinishedNote instead
// (R1E-close-judge.md new finding 1). An unsupported verdict that
// verify.Check itself gives (depth, algorithm, no openssl) carries no
// note: verify gives no reason with it, so read has no true reason to
// add, and the verdict already says "not checked" (D10.3,
// R1E-close-judge.md new finding 2). The type of that
// unsupported result comes from signedKind, the only place a type
// hint can come from when the server has no source to check.
//
// Once the check has run on the real source, a nil result means that
// source has no signature. read then gives no block at all, even when
// a marker line sits in the body or a stray application/pgp-signature
// attachment row sits beside it: signedKind is a hint for a message
// the server never fetched, not a second vote against a check that
// already ran on the real bytes (I12, R1E-fix-judge.md new finding
// 5).
//
// The switch below is the one mail.SignedNo reaches, and every branch
// of it gives no block at all: mail.SignedNo means a provider read
// BODYSTRUCTURE and the full decoded text and, on its own view, found
// nothing to check (D6.2), so the tool layer never raises a verdict
// the provider already ruled out.
//
//   - No signed structure, no marker, no attachment row: the plain
//     case, no block (D6.1).
//   - A lone application/pgp-signature or pkcs7-signature attachment
//     signs nothing on its own (imap.signedStructure leaves it out of
//     the hint on purpose): no block, the source was already checked
//     by the provider's own structure walk (R1E-fix2-judge.md new
//     finding 2, rule 2).
//   - signedKind still names a type here (an inline marker in m.Body
//     that the hint disagrees with): the shape never happens on
//     today's IMAP provider, because hasInlinePGP feeds the same
//     hint the marker check repeats, so kind and the hint cannot
//     disagree from that one provider. The default branch does not
//     lean on that coupling holding for a provider added later
//     (S6-S8): it gives no block either way, so this branch raises
//     no unsupported block for a provider that said mail.SignedNo,
//     whatever signedKind guesses from the same text the provider
//     already read. Every unsupported block that read itself makes
//     carries a fixed note; one that verify.Check gives carries none
//     (R1E-close-judge.md new finding 2).
//
// arch: D6.1, D6.2, D10.3, I11, I12
func (t *readTool) signature(ctx context.Context, reader Reader, m *mail.Message) (sig *verify.Signature, raw []byte, note string) {
	kind := signedKind(m)
	unsupported := func(kind string) *verify.Signature {
		if kind == "" {
			return nil
		}
		return &verify.Signature{Type: kind, Verdict: verify.VerdictUnsupported}
	}
	switch {
	case m.SignedHint != mail.SignedNo:
		// mail.SignedYes and mail.SignedUnknown both fetch. Only a
		// provider that read the structure and the full text may say
		// mail.SignedNo, so the default is to check (D6.2).
		if m.Size > verify.MaxInput {
			return unsupported(kind), nil, notCheckedNote
		}
		b, err := reader.Raw(ctx, m.ID)
		if err != nil || len(b) > verify.MaxInput {
			return unsupported(kind), nil, notCheckedNote
		}
		raw = b
	case strings.TrimSpace(m.AuthResults) != "":
		// No signed structure and no marker: only DKIM can give a
		// result, and it reads the header block alone (D6.2).
		raw = authHeaderRaw(m.AuthResults)
	default:
		// mail.SignedNo and no DKIM header: no block. This covers two
		// shapes with one answer (R1E-close-judge.md new finding 4):
		//   - A signature attachment row: D6.1, a stray signature part
		//     alone makes no block (R1E-fix2-judge.md new finding 2,
		//     rule 2).
		//   - Only a marker in the body: no block, whatever signedKind
		//     still guesses from the body text (D6.1,
		//     R1E-fix2-judge.md new finding 2, rule 1).
		// kind is not read here on purpose: a provider that said
		// mail.SignedNo already ruled out a signature, so this branch
		// must never turn that into an unsupported verdict, noted or
		// not.
		return nil, nil, ""
	}
	// hintOf gives the type of a result the server could not finish.
	// It reads the bytes only on those branches, so TypeHint never
	// runs on a read that ends with a verdict.
	hintOf := func() string {
		if kind != "" {
			return kind
		}
		return verify.TypeHint(raw)
	}
	var cfg verify.Config
	if src, ok := t.mail.(verifyConfigSource); ok {
		cfg = src.VerifyConfig()
	}

	type result struct {
		sig      *verify.Signature
		panicked bool
	}
	// checkCtx carries the D6.2 5-second limit into Check, and it ends
	// at whichever comes first: verifyTimeout or ctx itself (the
	// caller's own deadline or cancellation). Check and its walks check
	// checkCtx.Err() between MIME parts and stop there (F-D6), so
	// cancelling it here is what makes the goroutine below return
	// instead of reading on after this call gives up on it.
	checkCtx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	done := make(chan result, 1)
	// check and checkDone are read here, not in the goroutine, so a
	// test that sets verifyCheck or verifyCheckDone after signature
	// returns does not race with a goroutine that still runs.
	check, checkDone := verifyCheck, verifyCheckDone
	go func() {
		// checkDone fires last, once this goroutine is about to
		// exit either way, so a test sees the true end of the call to
		// verify.Check and not just of the panic recovery.
		defer func() {
			if checkDone != nil {
				checkDone()
			}
		}()
		// The check runs on sender bytes. A panic in it must not stop
		// the server; the verdict is then unsupported.
		defer func() {
			if recover() != nil {
				done <- result{panicked: true}
			}
		}()
		done <- result{sig: check(checkCtx, raw, m.From.Address, cfg)}
	}()
	select {
	case r := <-done:
		if r.panicked {
			// The check ran on the real source and could not finish:
			// unsupported, never invalid (D10.3). The source was
			// fetched, so the note says the check did not finish
			// (R1E-close-judge.md new finding 1).
			return unsupported(hintOf()), raw, checkNotFinishedNote
		}
		if r.sig == nil {
			// The check ran on the real source and found no signature
			// there: the source has none. signedKind is not asked
			// again (I12, R1E-fix-judge.md new finding 5).
			return nil, raw, ""
		}
		return r.sig, raw, ""
	case <-checkCtx.Done():
		return unsupported(hintOf()), raw, checkNotFinishedNote
	}
}

// authHeaderRaw makes a message out of the Authentication-Results
// header block alone: the header lines, then the empty line that ends
// a header. verify.Check reads the DKIM result from it and finds no
// signed structure in it, which is the answer the hint already gave.
func authHeaderRaw(h string) []byte {
	h = strings.ReplaceAll(h, "\r\n", "\n")
	return []byte(strings.TrimRight(h, "\n") + "\n\n")
}

// inlinePGPMarker starts an inline clearsigned OpenPGP block. The
// provider looks for the same word in the full text to set
// SignedHint, so both read one definition (internal/mail).
const inlinePGPMarker = mail.InlinePGPMarker

// signedKind gives the signature type that the provider view of m
// shows, or "" for none: a signature attachment row, or an inline
// marker line in the cut body. It is only the type of an unsupported
// result (F-D1). It is not a gate, because it misses a signature part
// with no file name and a marker outside the cut body. The verdict
// comes from verify.Check alone.
func signedKind(m *mail.Message) string {
	if k := signedAttachmentKind(m); k != "" {
		return k
	}
	if strings.HasPrefix(m.Body, inlinePGPMarker) || strings.Contains(m.Body, "\n"+inlinePGPMarker) {
		return verify.TypeOpenPGP
	}
	return ""
}

// signedAttachmentKind gives the signature type that a signature
// attachment row of m names, or "" when no attachment does. It is the
// one signal signedKind takes from m.Attachments. signature does not
// read it as a gate: a lone signature attachment with no signed
// structure around it signs nothing (D6.1), so it gives no block,
// never an unsupported one (R1E-fix2-judge.md new finding 2).
//
// A pkcs7-mime row counts as signed when mail.SMIMEKindOfValue names
// it SMIMESigned or SMIMEUnknown: an unknown part can be signed, so it
// fails closed. An SMIMEEnveloped row is not a signature (DR1G.18.2).
func signedAttachmentKind(m *mail.Message) string {
	for _, a := range m.Attachments {
		switch strings.ToLower(strings.TrimSpace(a.ContentType)) {
		case "application/pgp-signature":
			return verify.TypeOpenPGP
		case "application/pkcs7-signature", "application/x-pkcs7-signature":
			return verify.TypeSMIME
		}
		switch mail.SMIMEKindOfValue(a.ContentType, a.SMIMEType) {
		case mail.SMIMESigned, mail.SMIMEUnknown:
			return verify.TypeSMIME
		}
	}
	return ""
}

// bodyEntity gives the entity that the verdict sig covers in raw, and
// whether read shows the body from it.
//
// read shows the signed entity in three cases:
//   - sig.Unsigned: content sits outside the signed entity (D6.2).
//     When there is no entity, entOK is false and the body is empty.
//   - A multipart/signed verdict of any value (DRV.3, IRV.2). The
//     entity is then the first part of the multipart/signed entity,
//     a slice of raw. An inline clearsigned block is out of scope:
//     verify.SignedEntity builds a new text/plain entity for it, so
//     its bytes are not in raw, and read keeps the provider body.
//   - An S/MIME verdict of any value (DR1G.3, IR1G.4). An S/MIME
//     entity is the first part of a multipart/signed entity, or the
//     content of an opaque signed-data entity. verify.SignedEntity
//     reads that content with the extractor that gives openssl its
//     bytes, so the content is the verified bytes, though it is not
//     a slice of raw. S/MIME has no inline form.
//
// The test "the entity bytes are in raw" can only err one way. An
// inline entity whose bytes also occur in raw shows the signed text of
// the checked block, which is still the verified text.
//
// arch: D6.2, I17, DRV.3, IRV.2, DR1G.3, IR1G.4
func bodyEntity(raw []byte, sig *verify.Signature) (ent []byte, entOK, show bool) {
	if sig == nil {
		return nil, false, false
	}
	ent, entOK = verify.SignedEntity(raw, sig.Type)
	return ent, entOK, sig.Unsigned || (entOK && (sig.Type == verify.TypeSMIME || bytes.Contains(raw, ent)))
}

// envelopedEntity is true when the header of ent, a signed entity,
// names a part that mail.SMIMEKindOf names SMIMEEnveloped. It reads
// the top header only; the text walk of signedText stays the one walk
// (DR1G.2, DR1G.3).
//
// arch: DR1G.3, IR1G.2
func envelopedEntity(ent []byte) bool {
	part, err := netmail.ReadMessage(bytes.NewReader(ent))
	if err != nil {
		return false
	}
	mt, params, err := stdmime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return mail.SMIMEKindOf(mt, params) == mail.SMIMEEnveloped
}

// signedText gives the text of ent, the entity that a verdict covers.
// verify.SignedEntity picks that entity with the same walk as the
// checker, so the body never comes from another entity (finding 2 of
// R1E-judge.md). The part rule is the one of an unsigned message:
// entityBody finds the first text/plain part and the first text/html
// part that are not attachments, and mime.PickBody chooses (DRV.3).
// removed counts the hidden HTML runs taken out when the text came
// from an HTML part (D4.1). differ is true when the plain part and the
// HTML part differ (D4.2). ok is false when the entity has no text
// part.
//
// The entity is the first part of the multipart/signed entity, so the
// preamble and the epilogue never reach the result (I17).
//
// arch: D6.2, I17, DRV.3, IRV.2
func signedText(ent []byte, format string) (text string, removed int, differ, ok bool, attachments []DecryptedFile, attachmentsHidden int) {
	part, err := netmail.ReadMessage(bytes.NewReader(ent))
	if err != nil {
		return "", 0, false, false, nil, 0
	}
	return entityBody(textproto.MIMEHeader(part.Header), part.Body, format)
}

// entityBody gives the text of one entity with the part rule of an
// unsigned message: the walk finds the first text/plain part and the
// first text/html part that are not attachments, and mime.PickBody
// chooses between them (DRV.3). read calls it for the signed entity
// and decrypt for the decrypted entity, each with the full header of
// the entity, so both share one rule. ok is false when the entity has
// no such part. attachments and attachmentsHidden are the walk's DR1G.9
// list of skipped attachments and the hidden count fencing them took
// out; they are filled whether or not a text part was found, since
// the walk does not stop early for decrypt's sake (IR1G.6).
//
// arch: DRV.3, D4.2, DR1G.9, IR1G.6
func entityBody(h textproto.MIMEHeader, body io.Reader, format string) (text string, removed int, differ, ok bool, attachments []DecryptedFile, attachmentsHidden int) {
	var tp textParts
	tp.walk(h, body, 0)
	if !tp.hasPlain && !tp.hasHTML {
		return "", 0, false, false, tp.attachments, tp.attachmentsHidden
	}
	text, removed, differ = mime.PickBody(tp.plain, tp.html, tp.hasPlain, tp.hasHTML, strings.EqualFold(format, "html"))
	return text, removed, differ, true, tp.attachments, tp.attachmentsHidden
}

// textParts holds the first text/plain part and the first text/html
// part of an entity that are not attachments, decoded. html is the
// HTML source. attachments is the DR1G.9 list that the same walk
// fills for a part it skips as an attachment, so decrypt needs no
// second walk over the entity (IR1G.6). attachmentsHidden counts what
// fencing each File name took out, for a caller's running hidden
// count.
type textParts struct {
	plain, html       string
	hasPlain, hasHTML bool
	attachments       []DecryptedFile
	attachmentsHidden int
}

// walk reads one entity of the signed content. It opens every
// multipart entity, records a part that mime.IsAttachment names as a
// DecryptedFile (DR1G.9), and keeps the first plain part and the
// first HTML part among the rest. Each text part is capped at
// mime.MaxPartBytes before it is decoded, the window that the IMAP
// provider fetches (§3.10).
//
// arch: DRV.3, §3.10, DR1G.9, IR1G.6
func (tp *textParts) walk(h textproto.MIMEHeader, body io.Reader, depth int) {
	if depth > verify.MaxDepth {
		return
	}
	ct := h.Get("Content-Type")
	mt, params, err := stdmime.ParseMediaType(ct)
	if err != nil {
		mt, params = "text/plain", nil
	}
	if strings.HasPrefix(mt, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return
			}
			tp.walk(p.Header, p, depth+1)
		}
	}
	if disposition, filename := dispositionOf(h, params); mime.IsAttachment(disposition, filename) {
		tp.addAttachment(filename, mt, ct, h.Get("Content-Transfer-Encoding"), body)
		return
	}
	isPlain, isHTML := mt == "text/plain", mt == "text/html"
	if (!isPlain || tp.hasPlain) && (!isHTML || tp.hasHTML) {
		return
	}
	b, err := io.ReadAll(io.LimitReader(body, mime.MaxPartBytes))
	if err != nil {
		return
	}
	dec := mime.DecodePart(b, ct, h.Get("Content-Transfer-Encoding"))
	if isHTML {
		tp.html, tp.hasHTML = dec, true
		return
	}
	tp.plain, tp.hasPlain = dec, true
}

// addAttachment appends one DecryptedFile for a part the walk skips as
// an attachment (DR1G.9). File is the sender's own file name, fenced
// like read's attachment names (§3.15, G3, IR1G.14); mt is the
// sanitized media type stdmime.ParseMediaType gave the caller, a
// token that cannot itself carry a fence marker or a hidden
// character, so Type needs no fence. Size is the decoded byte count,
// from mime.DecodedSize reading body as a stream: no decoded buffer
// of the part is ever built, so decrypt gives no attachment content
// (D7.2).
//
// arch: DR1G.9, D7.2, IR1G.14, IR1G.6
func (tp *textParts) addAttachment(filename, mt, ct, cte string, body io.Reader) {
	size := mime.DecodedSize(body, ct, cte)
	file, hidden := fencedCount("ATTACHMENT", filename)
	tp.attachmentsHidden += hidden
	tp.attachments = append(tp.attachments, DecryptedFile{File: file, Size: size, Type: mt})
}

// dispositionOf gives the disposition value and the file name of one
// part, the two inputs of mime.IsAttachment. The file name is the
// filename parameter of Content-Disposition, or else the name
// parameter of Content-Type, the same order as the IMAP provider
// reads it (go-imap Filename).
func dispositionOf(h textproto.MIMEHeader, ctParams map[string]string) (disposition, filename string) {
	cd := h.Get("Content-Disposition")
	disposition, dParams, err := stdmime.ParseMediaType(cd)
	if err != nil && disposition == "" {
		disposition, _, _ = strings.Cut(cd, ";")
		disposition = strings.TrimSpace(disposition)
	}
	filename = dParams["filename"]
	if filename == "" {
		filename = ctParams["name"]
	}
	return disposition, filename
}

// cutRunes applies the offset and the limit of §3.16 to s, the same
// rule the provider applies to the body it decodes.
func cutRunes(s string, offset, maxChars int) string {
	r := []rune(s)
	if offset > 0 {
		if offset >= len(r) {
			return ""
		}
		r = r[offset:]
	}
	if maxChars > 0 && len(r) > maxChars {
		r = r[:maxChars]
	}
	return string(r)
}
