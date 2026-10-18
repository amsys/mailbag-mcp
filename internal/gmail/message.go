// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Read, Raw and Attachment of the Gmail provider (DS7.4). Read gets
// messages.get with format=full and walks the MIME tree of the
// payload: the text/plain part first, then the text/html part. The
// body data is base64url with no padding (E8). A large text part has
// an attachmentId and no data, and its text comes from the attachment
// call (E9). Raw decodes format=raw. Attachment finds the part by its
// partId, which is stable, and gets the attachmentId of this fetch,
// which is not.

package gmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	stdmime "mime"
	"net/url"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// maxAttachmentIDLen bounds an attachmentId before it goes into a URL
// path. Gmail gives ids of some hundred characters.
const maxAttachmentIDLen = 4096

// partBody is the body of one message part, or the answer of the
// attachment call. Data is base64url (E8). A large part has an
// AttachmentID and no Data (E9).
type partBody struct {
	AttachmentID string `json:"attachmentId"`
	Size         int64  `json:"size"`
	Data         string `json:"data"`
}

// msgPart is one node of the MIME tree of a format=full answer. The
// top node is the payload; its PartID is "".
type msgPart struct {
	PartID   string       `json:"partId"`
	MimeType string       `json:"mimeType"`
	Filename string       `json:"filename"`
	Headers  []metaHeader `json:"headers"`
	Body     partBody     `json:"body"`
	Parts    []msgPart    `json:"parts"`
}

// header gives the value of the first header of the part with the
// name, in any case, or "".
func (p *msgPart) header(name string) string {
	for _, h := range p.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// contentType gives the Content-Type header of the part, with its
// charset, else the mimeType.
func (p *msgPart) contentType() string {
	if ct := strings.TrimSpace(p.header("Content-Type")); ct != "" {
		return ct
	}
	return p.MimeType
}

// params gives the parameters of the Content-Type header, or an empty
// map when the header is absent or does not parse.
func (p *msgPart) params() map[string]string {
	if ct := p.header("Content-Type"); ct != "" {
		if _, ps, err := stdmime.ParseMediaType(ct); err == nil {
			return ps
		}
	}
	return map[string]string{}
}

// isAttachment is the rule of §3.10 for one leaf part, from
// mime.IsAttachment, as on IMAP.
func (p *msgPart) isAttachment() bool {
	disp := p.header("Content-Disposition")
	if d, _, err := stdmime.ParseMediaType(disp); err == nil {
		disp = d
	}
	return mime.IsAttachment(disp, p.Filename)
}

// walk calls fn for each node of the tree, the node before its
// children.
func (p *msgPart) walk(fn func(*msgPart)) {
	fn(p)
	for i := range p.Parts {
		p.Parts[i].walk(fn)
	}
}

// fullMessage is a messages.get answer with format=full. Its Payload
// holds the whole tree; meta() gives the metaMessage of a row.
type fullMessage struct {
	metaMessage
	Payload msgPart `json:"payload"`
}

// meta gives the message as a metaMessage, with the headers of the
// payload, so that row can read it.
func (m *fullMessage) meta() *metaMessage {
	mm := m.metaMessage
	mm.Payload.Headers = m.Payload.Headers
	return &mm
}

// getFull calls messages.get with format=full for id.
func (p *Provider) getFull(ctx context.Context, id string) (*fullMessage, error) {
	if err := checkMsgID(id); err != nil {
		return nil, err
	}
	var m fullMessage
	if err := p.api.Get(ctx, "messages/"+id, url.Values{"format": {"full"}}, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// decodeData decodes base64url body data. Gmail sends it with no
// padding, or with padding at times; the padding is removed and the
// rest goes through base64.RawURLEncoding (E8).
func decodeData(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("gmail: the body data is not valid base64url")
	}
	return b, nil
}

// isAttachmentIDRune reports whether r may be in a Gmail id: a
// letter, a digit, "-" or "_".
func isAttachmentIDRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
}

// checkAttachmentID refuses an attachmentId that is not a Gmail id
// before it goes into a URL path: letters, digits, "-" and "_" only.
func checkAttachmentID(id string) error {
	if id == "" || len(id) > maxAttachmentIDLen || strings.ContainsFunc(id, func(r rune) bool { return !isAttachmentIDRune(r) }) {
		return errors.New("gmail: the server gave an attachment id that is not valid")
	}
	return nil
}

// partData gives the bytes of a leaf part of message id: the data in
// the answer, else the answer of the attachment call (E9). A part with
// neither is empty.
func (p *Provider) partData(ctx context.Context, id string, part *msgPart) ([]byte, error) {
	if part.Body.Data != "" {
		return decodeData(part.Body.Data)
	}
	if part.Body.AttachmentID == "" {
		return nil, nil
	}
	if err := checkAttachmentID(part.Body.AttachmentID); err != nil {
		return nil, err
	}
	var ans partBody
	if err := p.api.Get(ctx, "messages/"+id+"/attachments/"+part.Body.AttachmentID, nil, &ans); err != nil {
		return nil, err
	}
	return decodeData(ans.Data)
}

// Read gets one message with its text body, its attachment list and
// the headers of a reply and of the DKIM check (DS7.4). One
// messages.get with format=full gives the whole MIME tree; the row
// fields are those of Search, from payload.headers and internalDate.
// The body is the D4.2 choice of mime.PickBody between the first
// text/plain part and the first text/html part, as on IMAP. A part
// with no data is read through the attachment call (E9), and each
// part is cut at mime.MaxPartBytes. SignedHint comes from the MIME
// tree first (D6.2); SignedNo needs every text part decoded in full
// (DRV.4). A format=full call does not remove UNREAD, so the read
// changes nothing (C2). payload.headers holds every header of the
// message, so the headers that o.Headers names come from the same
// answer, with no other call (DS9.2).
//
// arch: DS7.4, D4.2, D6.2, DRV.4, E8, E9, DS9.2
func (p *Provider) Read(ctx context.Context, id string, o mail.ReadOpts) (*mail.Message, error) {
	m, err := p.getFull(ctx, id)
	if err != nil {
		return nil, err
	}
	tab, err := p.cachedLabels(ctx)
	if err != nil {
		return nil, err
	}
	meta := m.meta()
	msg := row(meta, "", tab)
	if v := meta.header("Reply-To"); v != "" {
		msg.ReplyTo = addressList(v)
	}
	msg.References = mail.MessageIDs(meta.header("References"))
	msg.AuthResults = authBlock(m.Payload.Headers)
	msg.Headers = pickHeaders(m.Payload.Headers, o.Headers)

	top := &m.Payload
	params := top.params()
	msg.MediaType = strings.ToLower(top.MimeType)
	if len(top.Parts) == 0 {
		for k, v := range params {
			if strings.EqualFold(k, "smime-type") {
				msg.SMIMEType = v
			}
		}
	}
	top.walk(func(part *msgPart) {
		if len(part.Parts) > 0 || !part.isAttachment() {
			return
		}
		a := mail.Attachment{
			Ref:         part.PartID,
			Filename:    part.Filename,
			ContentType: strings.ToLower(part.MimeType),
			Size:        part.Body.Size,
		}
		if a.Ref == "" {
			// The payload itself is the attachment; its partId is "".
			// Attachment also takes the file name as ref (C19).
			a.Ref = part.Filename
		}
		for k, v := range part.params() {
			if strings.EqualFold(k, "smime-type") {
				a.SMIMEType = v
			}
		}
		msg.Attachments = append(msg.Attachments, a)
	})

	body, err := p.readBody(ctx, id, top, o.Format)
	if err != nil {
		return nil, err
	}
	msg.HiddenRemoved = body.removed
	msg.PartsDiffer = body.differ
	switch {
	case signedTree(top, params) || body.marker:
		msg.SignedHint = mail.SignedYes
	case body.whole:
		msg.SignedHint = mail.SignedNo
	default:
		msg.SignedHint = mail.SignedUnknown
	}
	msg.Body = mail.CutBody(body.text, o.Offset, o.MaxChars)
	return &msg, nil
}

// readBody is the body that Read gives, with the values of the signed
// hint: marker is true when a decoded part holds the inline PGP
// marker; whole is true when Read decoded every non-attachment text
// part of the tree and cut none of them (DRV.4).
type readBody struct {
	text    string
	removed int
	differ  bool
	marker  bool
	whole   bool
}

// readBody decodes the parts of the D4.2 choice: the first text/plain
// and the first text/html leaf that is not an attachment, or only one
// of them for format "html" or when the other is absent. It fetches no
// part beyond that choice (DRV.4).
func (p *Provider) readBody(ctx context.Context, id string, top *msgPart, format string) (readBody, error) {
	wantHTML := strings.EqualFold(format, "html")
	var all []*msgPart
	var plain, html *msgPart
	top.walk(func(part *msgPart) {
		if len(part.Parts) > 0 || part.isAttachment() {
			return
		}
		switch strings.ToLower(part.MimeType) {
		case "text/plain":
			if plain == nil {
				plain = part
			}
		case "text/html":
			if html == nil {
				html = part
			}
		default:
			return
		}
		all = append(all, part)
	})
	var parts []*msgPart
	switch {
	case wantHTML && html != nil:
		parts = []*msgPart{html}
	case wantHTML || html == nil:
		if plain == nil {
			// No text part at all, so every text part is decoded.
			return readBody{whole: true}, nil
		}
		parts = []*msgPart{plain}
	case plain == nil:
		parts = []*msgPart{html}
	default:
		parts = []*msgPart{plain, html}
	}

	var b readBody
	cut := false
	var plainText, htmlSrc string
	var hasPlain, hasHTML bool
	for _, part := range parts {
		data, err := p.partData(ctx, id, part)
		if err != nil {
			return readBody{}, err
		}
		if part.Body.Size > mime.MaxPartBytes || int64(len(data)) > mime.MaxPartBytes {
			cut = true
			data = data[:min(int64(len(data)), mime.MaxPartBytes)]
		}
		text := mime.DecodePart(data, part.contentType(), "")
		if mail.HasInlinePGP(text) {
			b.marker = true
		}
		if part == html {
			htmlSrc, hasHTML = text, true
		} else {
			plainText, hasPlain = text, true
		}
	}
	b.text, b.removed, b.differ = mime.PickBody(plainText, htmlSrc, hasPlain, hasHTML, wantHTML)
	b.whole = !cut && len(parts) == len(all)
	return b, nil
}

// signedTree reports whether the MIME tree shows a signature that only
// the whole source can settle: a multipart/signed node or an
// application/(x-)pkcs7-mime node at any depth (D6.2). A message that
// is one top-level pkcs7-mime part that mail.SMIMEKindOf names
// SMIMEEnveloped is out (DR1G.7); any other pkcs7-mime part counts,
// so the check fails closed (IR1G.3). params are the Content-Type
// parameters of top.
func signedTree(top *msgPart, params map[string]string) bool {
	if len(top.Parts) == 0 && mail.SMIMEKindOf(top.MimeType, params) == mail.SMIMEEnveloped {
		return false
	}
	found := false
	top.walk(func(part *msgPart) {
		switch strings.ToLower(part.MimeType) {
		case "multipart/signed", "application/pkcs7-mime", "application/x-pkcs7-mime":
			found = true
		}
	})
	return found
}

// authBlock gives the Authentication-Results headers as header text,
// one field for each, as the IMAP header fetch gives it to the DKIM
// check (D6.2).
func authBlock(headers []metaHeader) string {
	var b strings.Builder
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Authentication-Results") {
			b.WriteString("Authentication-Results: ")
			b.WriteString(h.Value)
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

// Raw gives the whole RFC 5322 source, for export and for forward
// (DS7.4): messages.get with format=raw, then the base64url decode
// (E8). The body cap of the client bounds it (DS7.3).
//
// arch: DS7.4, E8
func (p *Provider) Raw(ctx context.Context, id string) ([]byte, error) {
	if err := checkMsgID(id); err != nil {
		return nil, err
	}
	var ans struct {
		Raw string `json:"raw"`
	}
	if err := p.api.Get(ctx, "messages/"+id, url.Values{"format": {"raw"}}, &ans); err != nil {
		return nil, err
	}
	if ans.Raw == "" {
		return nil, errors.New("gmail: the server gave no source for this message")
	}
	return decodeData(ans.Raw)
}

// Attachment opens one part of a message (DS7.4). ref is the partId of
// the part, which stays the same from one fetch to the next, or the
// file name of an attachment (C19). messages.get with format=full
// finds the part; its data comes from the answer or from
// messages/{id}/attachments/{attachmentId}, with the attachmentId of
// this fetch, because that id changes on each fetch (R§7.2). The
// caller closes the reader.
//
// arch: DS7.4, C19, E9
func (p *Provider) Attachment(ctx context.Context, id, ref string) (io.ReadCloser, mail.AttachmentInfo, error) {
	if ref == "" {
		return nil, mail.AttachmentInfo{}, errors.New("gmail: no attachment ref")
	}
	m, err := p.getFull(ctx, id)
	if err != nil {
		return nil, mail.AttachmentInfo{}, err
	}
	part := findPart(&m.Payload, ref)
	if part == nil {
		return nil, mail.AttachmentInfo{}, errors.New("gmail: the message has no attachment with this ref; read the message for the list")
	}
	data, err := p.partData(ctx, id, part)
	if err != nil {
		return nil, mail.AttachmentInfo{}, err
	}
	info := mail.AttachmentInfo{
		Filename:    part.Filename,
		ContentType: strings.ToLower(part.MimeType),
		Size:        int64(len(data)),
	}
	if info.ContentType == "" {
		info.ContentType = "application/octet-stream"
	}
	return io.NopCloser(bytes.NewReader(data)), info, nil
}

// findPart gives the leaf part with the partId ref, else the first
// attachment with the file name ref (C19), else nil.
func findPart(top *msgPart, ref string) *msgPart {
	var byID, byName *msgPart
	top.walk(func(part *msgPart) {
		if len(part.Parts) > 0 {
			return
		}
		if byID == nil && part.PartID != "" && part.PartID == ref {
			byID = part
		}
		if byName == nil && part.Filename != "" && part.Filename == ref && part.isAttachment() {
			byName = part
		}
	})
	if byID != nil {
		return byID
	}
	return byName
}
