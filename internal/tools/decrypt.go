// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	stdmime "mime"
	"mime/multipart"
	"mime/quotedprintable"
	netmail "net/mail"
	"net/textproto"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/verify"
)

// DecryptIn is the input of the decrypt tool (D7.2, D10.3).
type DecryptIn struct {
	Account string `json:"account"`
	ID      string `json:"id" jsonschema:"from search"`
}

// DecryptOut is the decrypt tool result (D7.2).
//
// Account and ID are the values of the call. Body holds the decrypted
// text inside a BODY fence, because decrypted text is sender text
// (G3). Truncated is true when the text stopped at the DRV.15 100k
// character cut; NextOffset then says where, the same field names
// [ReadOut] uses for the same cut. Signature is the result of the
// signature check on the decrypted entity; each field of it is server
// text (I11). Hidden counts the hidden text that the sanitizer took
// out of Body and of each Attachments[].File (D4.1). Note carries the
// note that decryptTool.signature's call to readTool.signature gives
// for the signature check on the decrypted entity. In practice that
// is always checkNotFinishedNote or the empty string: decrypt already
// holds the plain bytes, so the fetch that notCheckedNote reports as
// failed can never fail here, and the DRV.15 cap on the gpg output
// keeps the size under the D6.2 limit notCheckedNote's other branch
// reports; the field keeps the same note names read uses for the same
// underlying check, in case a future change opens either of those two
// branches. Note also carries, when the decrypted entity has no text
// part to show, the fixed text noTextPartNote; the two join with a
// line break when both apply (DR1G.9). Attachments is the walk's list
// of the parts it skipped as attachments; decrypt gives no attachment
// content (D7.2).
//
// arch: DR1G.9
type DecryptOut struct {
	Account     string            `json:"account"`
	ID          string            `json:"id"`
	Body        string            `json:"body"`
	Truncated   bool              `json:"truncated,omitempty"`
	NextOffset  int               `json:"next_offset,omitempty"`
	Signature   *verify.Signature `json:"signature,omitempty"`
	Hidden      int               `json:"hidden_removed,omitempty"`
	Note        string            `json:"note,omitempty"`
	Attachments []DecryptedFile   `json:"attachments,omitempty"`
}

// DecryptedFile is one part of the decrypted entity that textParts.walk
// (internal/tools/read.go) skipped as an attachment (DR1G.9, IR1G.6).
// File is the sender's own file name, fenced the way read fences its
// attachment names (§3.15, G3, IR1G.14). Type is the sanitized media
// type stdmime.ParseMediaType gave the walk, a token that cannot carry
// a fence marker or a hidden character, so it needs no fence. decrypt
// gives no attachment content: Size is the decoded byte count, never
// the bytes themselves (D7.2).
//
// arch: DR1G.9, D7.2, IR1G.14
type DecryptedFile struct {
	File string `json:"file"`
	Size int    `json:"size"`
	Type string `json:"type"`
}

// noTextPartNote is the fixed text decrypt gives when the decrypted
// entity has no text part that can be shown (DR1G.9). Body stays
// empty; it holds no sender text.
//
// arch: DR1G.9
const noTextPartNote = "the decrypted message has no text part that can be shown"

// DecryptWarning is the fixed D7.1 warning. serve writes it as one
// stderr line at start when decryption is on. The config template and
// doctor show the same text. It holds no mail text.
//
// arch: D7.1
const DecryptWarning = "Decryption is ON. Decrypted mail text goes to the model provider of your MCP host. Use this only with a model that runs on your machine, or behind a proxy that filters what leaves it."

// decryptLimit is the D10.3 time limit on one gpg run. It includes
// the wait for the passphrase in pinentry.
const decryptLimit = 60 * time.Second

// gpgArgs is the D10.3 argument list. It is fixed. No argument comes
// from the caller or from the message, and none of them lets gpg use
// the network (D7.2).
var gpgArgs = []string{"--batch", "--no-tty", "--status-fd", "3", "--decrypt", "--no-auto-key-retrieve", "--no-auto-key-locate", "--disable-dirmngr"}

// maxStatus bounds the status lines that one run can give. The status
// holds key ids and keywords only, so 64 KiB is much more than enough.
const maxStatus = 64 << 10

// errSMIMEDecryptOff is the fixed error for an S/MIME encrypted
// message. R1 decrypts OpenPGP only (D7.2). S/MIME enveloped-data uses
// CBC, which has no integrity check, and gpgsm gives no GOODMDC, so
// the EFAIL rule does not let text out. The error holds no sender
// text.
//
// arch: D7.2, EFAIL
const errSMIMEDecryptOff = "unsupported: S/MIME encryption has no integrity check, so decrypt does not open it"

// The fixed errors of the decrypt tool. None of them holds gpg output,
// sender text or decrypted text (I18, EFAIL).
var (
	errDecryptFailed      = errors.New("decryption failed: no verified integrity check, so no text is shown")
	errDecryptTimeout     = errors.New("decryption stopped at the 60 second limit; no text is shown")
	errNotEncrypted       = errors.New("this message is not PGP/MIME or S/MIME encrypted; decrypt cannot open it")
	errDecryptTooLarge    = errors.New("this message is too large to decrypt")
	errDecryptUnsupported = errors.New("unsupported: gpg is not on PATH on this machine")
)

// AddDecrypt adds the "decrypt" tool to srv (D7.2). The "decrypt"
// group of [Toolsets] calls it. config.Config.Extras gives that group
// only when the three D7.1 keys agree (I13).
//
// The tool sets anthropic/requiresUserInteraction, so the client asks
// the human before each call. The tool deadline is the D10.3 limit
// plus [DefaultTimeout] for the fetch of the source, so the D10.3
// limit ends a slow gpg first and the caller gets the fixed timeout
// error.
//
// arch: D7.1, D7.2, D10.3, I13
func AddDecrypt(srv *mcp.Server, logger *slog.Logger, m Mail) {
	addDecrypt(srv, logger, &decryptTool{mail: m, gpg: "gpg", limit: decryptLimit})
}

// addDecrypt adds the decrypt tool h to srv. A test gives its own h,
// so it can point h at a stand-in program or set a short limit.
func addDecrypt(srv *mcp.Server, logger *slog.Logger, h *decryptTool) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "decrypt",
		Description: "Decrypt one message with gpg.",
		Meta:        mcp.Meta{requiresUserInteraction: true},
	}, Wrap(logger, "decrypt", h.limit+DefaultTimeout, h.handle))
}

// decryptTool holds the program name and the time limit. gpg is a
// name that exec.LookPath resolves at each call, so a program that is
// installed later is found without a restart.
type decryptTool struct {
	mail  Mail
	gpg   string
	limit time.Duration
}

// handle reads the source of one message through Reader.Raw, finds
// the encrypted part, and runs gpg on it (D7.2, D7.3). An S/MIME
// encrypted message gives errSMIMEDecryptOff and starts no program.
//
// The text reaches the result only when the status of the run has
// DECRYPTION_OKAY and GOODMDC. Every other state gives a fixed error
// and no text (EFAIL). The decrypted text goes through the read-side
// sanitizer (D4.1) and into a BODY fence. It never goes to the log:
// [Wrap] logs an error class only, and every error here is fixed text.
//
// arch: D7.2, D7.3, D10.3, D4.1, I10, I18, EFAIL
func (t *decryptTool) handle(ctx context.Context, in DecryptIn) (DecryptOut, error) {
	p, _, err := t.mail.Open(ctx, in.Account)
	if err != nil {
		return DecryptOut{}, err
	}
	if in.ID == "" {
		return DecryptOut{}, errors.New("id is required; take it from a search result")
	}
	raw, err := p.Raw(ctx, in.ID)
	if err != nil {
		return DecryptOut{}, err
	}
	if len(raw) > verify.MaxInput {
		return DecryptOut{}, errDecryptTooLarge
	}
	cipher, from, err := encryptedPart(raw)
	if err != nil {
		return DecryptOut{}, err
	}
	path, err := exec.LookPath(t.gpg)
	if err != nil {
		return DecryptOut{}, errDecryptUnsupported
	}
	plain, status, err := runDecrypt(ctx, path, gpgArgs, cipher, t.limit)
	if err != nil {
		return DecryptOut{}, err
	}

	sig, sigNote := t.signature(ctx, p, in.ID, from, plain)
	if sig == nil {
		// DRV.15: gpg can sign and encrypt in one OpenPGP packet, and
		// it verifies that signature itself while it decrypts. The
		// literal output then holds no MIME or inline trace of it, so
		// the walk above finds nothing. statusSignature reads gpg's
		// own verdict from the status lines instead, so that signature
		// is not lost.
		sig = statusSignature(status)
	}
	text, removed, attachments, attachmentsHidden, hasText := decryptedText(plain, sig)
	runes := []rune(text)
	truncated := len(runes) > readCeilingMaxChars
	var nextOffset int
	if truncated {
		nextOffset = readCeilingMaxChars
	}
	// DR1G.9: a decrypted entity with no text part shown keeps Body
	// empty, with the fixed note instead of a fence over nothing.
	var body string
	var hidden int
	note := sigNote
	if hasText {
		body, hidden = fencedCount("BODY", cutRunes(text, 0, readCeilingMaxChars))
	} else {
		note = addNote(note, noTextPartNote)
	}
	return DecryptOut{
		Account:     in.Account,
		ID:          in.ID,
		Body:        body,
		Truncated:   truncated,
		NextOffset:  nextOffset,
		Signature:   sig,
		Hidden:      removed + hidden + attachmentsHidden,
		Note:        note,
		Attachments: attachments,
	}, nil
}

// decryptedText gives the text next to sig for the decrypted entity
// plain (DRV.15), the DR1G.9 attachment list the same walk found and
// its hidden count, and whether a text part was found at all (hasText
// false means handle leaves Body empty and adds noTextPartNote).
// decrypt uses the same DRV.3 functions and the same Unsigned rule as
// read (IRV.2): when plain is a multipart/signed entity, or sig shows
// unsigned_parts_present, the text comes from the signed entity alone,
// through bodyEntity and signedText, so text outside the signature
// never sits next to the verdict. Every other case keeps the
// whole-entity walk of plainText, the part rule of an unsigned
// message. The attachment list comes from that same walk either way,
// whether or not it also found text (IR1G.6).
//
// arch: DRV.15, DRV.3, IRV.2, DR1G.9, IR1G.6
func decryptedText(plain []byte, sig *verify.Signature) (text string, removed int, attachments []DecryptedFile, attachmentsHidden int, hasText bool) {
	if ent, entOK, show := bodyEntity(plain, sig); show {
		if entOK {
			text, removed, _, hasText, attachments, attachmentsHidden = signedText(ent, "text")
			if !hasText {
				text, removed = "", 0
			}
			return text, removed, attachments, attachmentsHidden, hasText
		}
		return "", 0, nil, 0, false
	}
	return plainText(plain)
}

// signature checks a signature inside the decrypted entity with the
// same code that read uses, so the D6.2 limits and the fixed verdicts
// are the same. note is readTool.signature's own note; handle carries
// it into DecryptOut.Note instead of dropping it (DR1G.9).
// plainReader.Raw below never fails and plain is already capped under
// verify.MaxInput (runDecrypt's capBuffer), so of readTool.signature's
// two notes only checkNotFinishedNote can reach the caller here; see
// [DecryptOut.Note].
//
// arch: DR1G.9
func (t *decryptTool) signature(ctx context.Context, p Reader, id, from string, plain []byte) (sig *verify.Signature, note string) {
	m := &mail.Message{ID: id, Size: int64(len(plain)), From: mail.Address{Address: from}}
	sig, _, note = (&readTool{mail: t.mail}).signature(ctx, plainReader{Reader: p, plain: plain}, m)
	return sig, note
}

// plainReader is a Reader whose Raw gives the decrypted entity. The
// signature code of read reads the source through Raw only.
type plainReader struct {
	Reader
	plain []byte
}

func (r plainReader) Raw(context.Context, string) ([]byte, error) { return r.plain, nil }

// encryptedPart finds the encrypted data of raw:
//
//   - multipart/encrypted with protocol application/pgp-encrypted
//     (RFC 3156): the second part, which goes to gpg.
//   - a part that mail.SMIMEKindOf names SMIMEEnveloped:
//     application/pkcs7-mime (or application/x-pkcs7-mime) with
//     smime-type enveloped-data or authenveloped-data (RFC 8551,
//     DR1G.18.1). R1 does not open it. encryptedPart gives errSMIMEDecryptOff
//     before any program starts, so gpgsm and pinentry do not run
//     (D7.2).
//
// Any other shape gives errNotEncrypted. from is the address of the
// From header, for the signature check only.
func encryptedPart(raw []byte) (cipher []byte, from string, err error) {
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, "", errNotEncrypted
	}
	if a, err := netmail.ParseAddress(msg.Header.Get("From")); err == nil {
		from = a.Address
	}
	mt, params, err := stdmime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, "", errNotEncrypted
	}
	if mail.SMIMEKindOf(mt, params) == mail.SMIMEEnveloped {
		// DR1G.18.1: the one predicate decides the S/MIME kind.
		return nil, "", errors.New(errSMIMEDecryptOff)
	}
	switch mt {
	case "multipart/encrypted":
		if !strings.EqualFold(params["protocol"], "application/pgp-encrypted") || params["boundary"] == "" {
			return nil, "", errNotEncrypted
		}
		mr := multipart.NewReader(msg.Body, params["boundary"])
		if _, err := mr.NextPart(); err != nil {
			return nil, "", errNotEncrypted
		}
		part, err := mr.NextPart()
		if err != nil {
			return nil, "", errNotEncrypted
		}
		b, err := decodeTransfer(part, part.Header.Get("Content-Transfer-Encoding"))
		if err != nil {
			return nil, "", errNotEncrypted
		}
		return b, from, nil
	}
	return nil, "", errNotEncrypted
}

// decodeTransfer reads body and removes the transfer encoding cte.
// The read stops at verify.MaxInput.
func decodeTransfer(body io.Reader, cte string) ([]byte, error) {
	body = io.LimitReader(body, verify.MaxInput)
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return io.ReadAll(base64.NewDecoder(base64.StdEncoding, newlineDropper{body}))
	case "quoted-printable":
		return io.ReadAll(quotedprintable.NewReader(body))
	}
	return io.ReadAll(body)
}

// newlineDropper removes CR and LF, which base64.NewDecoder does not
// skip in every position.
type newlineDropper struct{ r io.Reader }

func (d newlineDropper) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	out := p[:0]
	for _, c := range p[:n] {
		if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
			out = append(out, c)
		}
	}
	return len(out), err
}

// plainText gives the text of the decrypted entity, the DR1G.9
// attachment list the walk found, and whether a text part was found.
// PGP/MIME and S/MIME give a MIME entity, so the text comes from
// entityBody, the read-side walk: an HTML part goes through
// mime.HTMLToTextCount (D4.1). The walk gets the full header of the
// entity, as signedText gives it, so a top-level part with
// Content-Disposition: attachment is an attachment, the same as a
// nested one (R16-L3). Output that is not a MIME entity (no
// Content-Type at all) is plain text with no walk, so no attachment
// list.
//
// arch: DR1G.9, DRV.3, R16-L3
func plainText(plain []byte) (text string, removed int, attachments []DecryptedFile, attachmentsHidden int, hasText bool) {
	part, err := netmail.ReadMessage(bytes.NewReader(plain))
	if err != nil || part.Header.Get("Content-Type") == "" {
		return string(plain), 0, nil, 0, true
	}
	text, removed, _, hasText, attachments, attachmentsHidden = entityBody(textproto.MIMEHeader(part.Header), part.Body, "text")
	return text, removed, attachments, attachmentsHidden, hasText
}

// runDecrypt runs the program at path with args, cipher on stdin, the
// status on fd 3, and stderr to the null device, so no gpg message
// reaches a result or the log (I18).
//
// The run gets limit (D10.3). At the limit the context kills the
// process and runDecrypt gives errDecryptTimeout. The plain text is
// given back only when goodStatus accepts the status lines (EFAIL).
// The exit code is not used: gpg exits with 2 when a signature inside
// the message has no public key, and the decryption is still good.
// A process that a signal ended gives errDecryptFailed. status is the
// status lines of the run, given back only on success, so
// statusSignature can read the same signature codes goodStatus read
// past (DRV.15).
//
// arch: D7.2, D10.3, I18, EFAIL, DRV.15
func runDecrypt(ctx context.Context, path string, args []string, cipher []byte, limit time.Duration) (plain, status []byte, err error) {
	runCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	sr, sw, err := os.Pipe()
	if err != nil {
		return nil, nil, errDecryptFailed
	}
	defer func() { _ = sr.Close() }()

	out := &capBuffer{max: verify.MaxInput}
	cmd := exec.CommandContext(runCtx, path, args...) //nolint:gosec // G204: path comes from exec.LookPath of the configured gpg name, the arguments are a fixed list, there is no shell, and mail data goes to stdin only
	cmd.Stdin = bytes.NewReader(cipher)
	cmd.Stdout = out
	cmd.ExtraFiles = []*os.File{sw}
	// A gpg-agent that gpg starts can keep a copy of stdout. WaitDelay
	// stops Wait from waiting on it for ever.
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		_ = sw.Close()
		return nil, nil, errDecryptFailed
	}
	_ = sw.Close()

	statusCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(sr, maxStatus))
		_, _ = io.Copy(io.Discard, sr)
		statusCh <- b
	}()
	werr := cmd.Wait()

	var statusLines []byte
	select {
	case statusLines = <-statusCh:
	case <-time.After(time.Second):
		// A child process still holds fd 3. Close the read end, so
		// the goroutine above ends.
		_ = sr.Close()
		statusLines = <-statusCh
	}

	switch {
	case ctx.Err() != nil:
		return nil, nil, ctx.Err()
	case runCtx.Err() != nil:
		return nil, nil, errDecryptTimeout
	}
	var exitErr *exec.ExitError
	if werr != nil && (!errors.As(werr, &exitErr) || !exitErr.Exited()) {
		return nil, nil, errDecryptFailed
	}
	if out.over || !goodStatus(statusLines) {
		return nil, nil, errDecryptFailed
	}
	return out.buf.Bytes(), statusLines, nil
}

// goodStatus reports whether the status lines of one run show a
// decryption with a good integrity check: DECRYPTION_OKAY and GOODMDC,
// and no DECRYPTION_FAILED and no BADMDC (D7.2, EFAIL).
func goodStatus(status []byte) bool {
	var okay, mdc, bad bool
	for _, line := range strings.Split(string(status), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "[GNUPG:] "))
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "DECRYPTION_OKAY":
			okay = true
		case "GOODMDC":
			mdc = true
		case "DECRYPTION_FAILED", "BADMDC":
			bad = true
		}
	}
	return okay && mdc && !bad
}

// statusSignature gives the Signature that the status lines of a run
// name, or nil when none of the seven signature codes below appear
// (DRV.15). It is the fallback for the one-pass sign+encrypt case:
// gpg verifies that signature itself while it decrypts, and the
// literal output holds no MIME or inline trace of it, so the walk in
// decryptedText finds nothing. This reads gpg's own verdict instead,
// proven with a real gpg fixture (TestDecrypt_SignedAndEncryptedKeepsSignature).
//
// The mapping never claims more than gpg reported (EFAIL, I11):
//   - BADSIG: the signature math is wrong -> VerdictInvalid.
//   - REVKEYSIG, EXPKEYSIG, EXPSIG: the math is correct but the key or
//     the signature has a trust problem gpg found ->
//     VerdictValidUnknownSigner with the matching Trust word, the same
//     pairing [pgpVerify] gives a correct signature with no pinned
//     trust.
//   - ERRSIG: gpg could not check the signature at all. Its rc field
//     says why: 9 is "no public key" (VerdictKeyUnavailable), every
//     other value covers an algorithm or a form this server does not
//     read either (VerdictUnsupported).
//   - GOODSIG with VALIDSIG and none of the above: the math is
//     correct and gpg found no trust problem, but this run reads no
//     configured, pinned keyring the way [pgpVerify] does ->
//     VerdictValidUnknownSigner.
//
// Fingerprint comes from VALIDSIG's own fingerprint field when gpg
// gave one, else from the key id field of whichever code matched.
// Both are gpg's own hex output, not sender text, but clean guards it
// all the same (I11).
//
// arch: DRV.15, D6.1, I11, EFAIL
func statusSignature(status []byte) *verify.Signature {
	var goodsig, validsig, badsig, expsig, expkeysig, revkeysig, errsig bool
	var id, fpr, errRC string
	for _, line := range strings.Split(string(status), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "[GNUPG:] "))
		if len(f) == 0 {
			continue
		}
		// id is read from the matched signature line alone (the
		// Fingerprint doc's "key id field of whichever code
		// matched"), never from a later, unrelated status line that
		// also happens to have a second field.
		switch f[0] {
		case "GOODSIG":
			goodsig = true
			if len(f) > 1 {
				id = f[1]
			}
		case "VALIDSIG":
			validsig = true
			if len(f) > 1 {
				fpr = f[1]
			}
		case "BADSIG":
			badsig = true
			if len(f) > 1 {
				id = f[1]
			}
		case "EXPSIG":
			expsig = true
			if len(f) > 1 {
				id = f[1]
			}
		case "EXPKEYSIG":
			expkeysig = true
			if len(f) > 1 {
				id = f[1]
			}
		case "REVKEYSIG":
			revkeysig = true
			if len(f) > 1 {
				id = f[1]
			}
		case "ERRSIG":
			errsig = true
			if len(f) > 1 {
				id = f[1]
			}
			if len(f) > 6 {
				errRC = f[6]
			}
		}
	}
	if !goodsig && !badsig && !expsig && !expkeysig && !revkeysig && !errsig {
		return nil
	}
	if fpr == "" {
		fpr = id
	}
	s := &verify.Signature{Type: verify.TypeOpenPGP, Fingerprint: cleanFingerprint(fpr)}
	switch {
	case badsig:
		s.Verdict = verify.VerdictInvalid
	case revkeysig:
		s.Verdict, s.Trust = verify.VerdictValidUnknownSigner, verify.TrustRevoked
	case expkeysig, expsig:
		s.Verdict, s.Trust = verify.VerdictValidUnknownSigner, verify.TrustExpired
	case errsig:
		s.Verdict = verify.VerdictUnsupported
		if errRC == "9" {
			s.Verdict = verify.VerdictKeyUnavailable
		}
	case goodsig && validsig:
		s.Verdict = verify.VerdictValidUnknownSigner
	default:
		s.Verdict = verify.VerdictUnsupported
	}
	return s
}

// cleanFingerprint gives fpr as lowercase hex only, dropping it when
// it holds any other byte. gpg writes fpr on its own status fd, but
// this keeps the I11 rule of [verify.Signature] whatever gpg sends.
func cleanFingerprint(fpr string) string {
	fpr = strings.ToLower(fpr)
	for i := 0; i < len(fpr); i++ {
		c := fpr[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return fpr
}

// capBuffer keeps the first max bytes written to it and sets over
// when more come. It takes every write, so the program never blocks
// on a full pipe.
type capBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room < len(p) {
		c.over = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}
