// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// maxRawBytes caps Raw and one attachment. maxPartBytes is the cap of
// a text part that goes to internal/mime; this one is the cap of the
// bytes that go to a file. Mail has no size limit of its own and both
// calls hold the whole result in memory, so the fetch asks for one
// byte more than the cap and the call fails when the server sends it
// (§3.10).
//
// ponytail: 25 MB in memory for each call. Stream the part through
// the pool if a person ever needs a bigger attachment.
const maxRawBytes int64 = 25 << 20

// maxHeaderBytes caps the References and Authentication-Results
// header fetches. Either header is a single line folded by the
// sender, with no limit of its own, and a forged header of any size
// would otherwise arrive whole before parseReferences or the DKIM
// check ever look at it (DRV.19.4).
const maxHeaderBytes int64 = 64 << 10

// refsSection is the header fetch that fills mail.Message.References.
// The envelope carries Message-ID and Reply-To, but not References,
// and a reply must not download a whole message to read one header
// line (§3.14). It peeks, like every other fetch of the read path
// (C2), and its Partial caps it at maxHeaderBytes (DRV.19.4).
//
// arch: T4.3, §3.10, §3.14, C2, DRV.19.4
var refsSection = &imap.FetchItemBodySection{
	Specifier:    imap.PartSpecifierHeader,
	HeaderFields: []string{"References"},
	Peek:         true,
	Partial:      &imap.SectionPartial{Offset: 0, Size: maxHeaderBytes},
}

// authSection is the header fetch that fills
// mail.Message.AuthResults. The DKIM check of read reads these lines
// alone, so a message with no signed part gives a DKIM verdict for
// the price of one header, never of the whole source (D6.2). It
// peeks, like every other fetch of the read path (C2), and its
// Partial caps it at maxHeaderBytes (DRV.19.4).
//
// arch: T4.3, §3.10, D6.2, C2, DRV.19.4
var authSection = &imap.FetchItemBodySection{
	Specifier:    imap.PartSpecifierHeader,
	HeaderFields: []string{"Authentication-Results"},
	Peek:         true,
	Partial:      &imap.SectionPartial{Offset: 0, Size: maxHeaderBytes},
}

// readFetch is the row fetch of Read: the same items as a search row,
// plus the References header and the Authentication-Results header.
var readFetch = &imap.FetchOptions{
	UID:           true,
	Flags:         true,
	InternalDate:  true,
	RFC822Size:    true,
	Envelope:      true,
	BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
	BodySection:   []*imap.FetchItemBodySection{refsSection, authSection},
}

// headersSection is the header fetch that fills mail.Message.Headers
// with the names of mail.ReadOpts.Headers. It follows authSection: it
// peeks (C2), and its Partial caps it at maxHeaderBytes, because a
// sender sets the size of these headers too (DRV.19.4). A read with
// no names asks for no such section (DS9.2).
//
// arch: DS9.2, C2, DRV.19.4
func headersSection(names []string) *imap.FetchItemBodySection {
	return &imap.FetchItemBodySection{
		Specifier:    imap.PartSpecifierHeader,
		HeaderFields: names,
		Peek:         true,
		Partial:      &imap.SectionPartial{Offset: 0, Size: maxHeaderBytes},
	}
}

// checkHeaderNames refuses a header name that is not an RFC 5322
// field name (printable ASCII except the colon). The names go into
// the FETCH command, so a space or a line break must never reach it.
func checkHeaderNames(names []string) error {
	for _, n := range names {
		if n == "" {
			return fmt.Errorf("imap: read: a header name is empty")
		}
		for i := 0; i < len(n); i++ {
			if n[i] < 33 || n[i] > 126 || n[i] == ':' {
				return fmt.Errorf("imap: read: header name %q is not a field name", n)
			}
		}
	}
	return nil
}

// uniqueNames gives a new slice with each header name once. Names
// that differ only in case are one name, and the first spelling stays,
// so a repeated name never gives each value twice (DS9.2).
//
// arch: DS9.2
func uniqueNames(names []string) []string {
	var out []string
	for _, n := range names {
		if !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, n) }) {
			out = append(out, n)
		}
	}
	return out
}

// parseHeaderFields reads a HEADER.FIELDS section into one entry per
// header instance, keyed by the name the caller asked for. A header
// matches a name without regard to case. A value is unfolded and
// trimmed, never decoded. When the section reached the cap, the last
// instance can be cut, so it is dropped: a cut URL is worse than none.
//
// arch: DS9.2, DRV.19.4
func parseHeaderFields(section []byte, names []string) map[string][]string {
	text := strings.ReplaceAll(string(section), "\r\n", "\n")
	type field struct{ name, value string }
	var fields []field
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(fields) > 0 {
				fields[len(fields)-1].value += " " + strings.TrimSpace(line)
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields = append(fields, field{name: strings.TrimSpace(name), value: strings.TrimSpace(value)})
	}
	if int64(len(section)) >= maxHeaderBytes && len(fields) > 0 {
		fields = fields[:len(fields)-1]
	}
	var out map[string][]string
	for _, f := range fields {
		for _, want := range names {
			if !strings.EqualFold(f.name, want) {
				continue
			}
			if out == nil {
				out = make(map[string][]string)
			}
			out[want] = append(out[want], f.value)
		}
	}
	return out
}

// locate reads an id, checks its folder against the folder list the
// server gives now, opens that folder read only and refuses a stale
// id.
//
// The folder part of an id is text the caller sent, so it never
// reaches a command before the check (§3.8). The UIDVALIDITY check is
// C4: when the server built the folder again, the UID in the id
// points at another message or at nothing, and the call fails instead
// of reading the wrong mail.
//
// arch: T4.3, §3.8, §3.10, C3, C4
func locate(c *Conn, id string) (uid imap.UID, folder string, uidValidity uint32, err error) {
	v, u, name, err := mail.ParseIMAPID(id)
	if err != nil {
		return 0, "", 0, err
	}
	name, err = resolveFolder(c, name)
	if err != nil {
		return 0, "", 0, err
	}
	sel, err := examine(c, name)
	if err != nil {
		return 0, "", 0, err
	}
	if err := checkUIDValidity(sel, v); err != nil {
		return 0, "", 0, err
	}
	return imap.UID(u), name, v, nil
}

// fetchOne fetches one UID and gives the single row back.
func fetchOne(c *Conn, uid imap.UID, opts *imap.FetchOptions) (*imapclient.FetchMessageBuffer, error) {
	rows, err := c.Fetch(imap.UIDSetNum(uid), opts).Collect()
	if err != nil {
		return nil, fmt.Errorf("imap: fetch uid %d: %w", uid, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("imap: no message with uid %d in this folder; search again", uid)
	}
	return rows[0], nil
}

// Read gets one message with its text body and its attachment list.
//
// Every fetch peeks, so a read never sets \Seen (C2). The option
// MarkRead needs a STORE, which is the write path of S5; until then
// Read reports the flags as they are and changes nothing.
//
// arch: T4.3, §3.10, §3.8, §3.14, C2, C3, C4
func (p *Provider) Read(ctx context.Context, id string, o mail.ReadOpts) (*mail.Message, error) {
	if err := checkHeaderNames(o.Headers); err != nil {
		return nil, err
	}
	names := uniqueNames(o.Headers)
	fetch, hdrs := readFetch, (*imap.FetchItemBodySection)(nil)
	if len(names) > 0 {
		// A copy, so the shared readFetch never grows a section.
		hdrs = headersSection(names)
		cp := *readFetch
		cp.BodySection = append(slices.Clone(readFetch.BodySection), hdrs)
		fetch = &cp
	}
	var msg mail.Message
	err := p.pool.WithRead(ctx, p.alias, func(c *Conn) error {
		uid, folder, uidValidity, err := locate(c, id)
		if err != nil {
			return err
		}
		row, err := fetchOne(c, uid, fetch)
		if err != nil {
			return err
		}
		msg = rowToMessage(row, folder, uidValidity)
		msg.References = parseReferences(row.FindBodySection(refsSection))
		msg.AuthResults = string(row.FindBodySection(authSection))
		if hdrs != nil {
			msg.Headers = parseHeaderFields(row.FindBodySection(hdrs), names)
		}
		if row.BodyStructure == nil {
			// No structure arrived, so this provider did not look for
			// a signature. SignedHint stays mail.SignedUnknown and
			// read checks the source itself (D6.2).
			return nil
		}
		msg.Attachments = attachmentsOf(row.BodyStructure)
		msg.MediaType, msg.SMIMEType = topType(row.BodyStructure)
		if signedStructure(row.BodyStructure) {
			msg.SignedHint = mail.SignedYes
		}
		body, err := fetchBody(c, uid, row.BodyStructure, o.Format)
		if err != nil {
			return err
		}
		msg.HiddenRemoved = body.removed
		msg.PartsDiffer = body.differ
		// The marker test runs on every part this read decoded, before
		// the cut below, so the hint never depends on offset or
		// max_chars (D6.2). body.marker covers every part fetchBody
		// decoded, not only the one PickBody chose to show, so a
		// clearsigned plain part is still seen when a different HTML
		// part is the one shown (DRV.4). SignedNo needs more: this read
		// must have decoded every non-attachment text part in full,
		// with none cut by its fetch window (body.signedNoEligible,
		// DRV.4, IRV.3). The rejected alternative was to fetch the
		// rest to reach SignedNo: it costs a fetch on every read, and
		// SignedUnknown already fails closed through the verifier.
		if msg.SignedHint != mail.SignedYes {
			switch {
			case body.marker:
				msg.SignedHint = mail.SignedYes
			case body.signedNoEligible:
				msg.SignedHint = mail.SignedNo
			default:
				msg.SignedHint = mail.SignedUnknown
			}
		}
		msg.Body = mail.CutBody(body.text, o.Offset, o.MaxChars)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// Raw gives the whole RFC 822 source, for export and for forward.
//
// arch: T4.3, §3.10, C2, C4
func (p *Provider) Raw(ctx context.Context, id string) ([]byte, error) {
	var out []byte
	err := p.pool.WithRead(ctx, p.alias, func(c *Conn) error {
		uid, _, _, err := locate(c, id)
		if err != nil {
			return err
		}
		sec := &imap.FetchItemBodySection{
			Peek:    true,
			Partial: &imap.SectionPartial{Offset: 0, Size: maxRawBytes + 1},
		}
		row, err := fetchOne(c, uid, &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{sec}})
		if err != nil {
			return err
		}
		raw := row.FindBodySection(sec)
		if int64(len(raw)) > maxRawBytes {
			return fmt.Errorf("imap: this message is larger than the limit of %d MB", maxRawBytes>>20)
		}
		out = raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// bodyText is the text Read gives, with the two D4.2 values that go
// outside the fence: the count of hidden HTML runs removed, and
// whether the text part and the HTML part differ. marker and
// signedNoEligible are the two DRV.4 values Read needs to decide
// SignedNo: whether any part this call decoded held the inline PGP
// marker, and whether this call decoded every non-attachment text
// part in the structure, none of them cut by its fetch window.
//
// arch: DRV.4, IRV.3
type bodyText struct {
	text             string
	removed          int
	differ           bool
	marker           bool
	signedNoEligible bool
}

// bodyPart is one non-attachment text/plain or text/html part that
// fetchBody may decode: the path a fetch needs, plus size, the octet
// count BODYSTRUCTURE gives for the part before decoding. The fetch
// window of each part is maxPartBytes. DRV.4 compares size with that
// window to tell a full fetch from one the window cut.
type bodyPart struct {
	path        []int
	contentType string
	encoding    string
	size        int64
}

// fetchBody gets the text of the message and decodes it.
//
// The parts come from BODYSTRUCTURE, so one partial PEEK fetch is
// enough and a 20 MB message never arrives whole. The window is
// maxPartBytes for each part, because internal/mime holds the decoded
// part in memory (§3.10).
//
// Part choice (D4.2): when the message has a text/plain part and a
// text/html part, the one fetch gets both. If the plain text and the
// text of the HTML part differ after spaces and line breaks are
// collapsed, Read gives the HTML text, because a mail program with
// HTML shows that part, and sets differ. Otherwise Read gives the
// plain part. A caller that asks for format "html" gets the HTML
// source as before, and no run is removed from it. The choice itself
// is mime.PickBody, the one rule that the read tool also applies to a
// signed entity (DRV.3).
//
// DRV.4: this same pass also decides whether this call is allowed to
// answer SignedNo. marker is true when any part this call decoded
// held the inline PGP marker, checked on every decoded part and not
// only on the one PickBody chose to show (a clearsigned plain part
// must still be seen when a different HTML part is shown instead).
// signedNoEligible is true only when the parts this call decoded are
// every non-attachment text/plain and text/html part of the
// structure (textParts' all), and none of them was cut by its fetch
// window. It is false whenever format "html" or a second part of one
// type left a part undecoded, and whenever a part's BODYSTRUCTURE
// size is larger than its window. This call fetches no part beyond
// what the part choice above already asks for (DRV.4 rejects an extra
// fetch to reach SignedNo).
//
// arch: T4.3, §3.10, §3.14, C2, C20, C21, D4.2, DRV.3, DRV.4, IRV.3
func fetchBody(c *Conn, uid imap.UID, bs imap.BodyStructure, format string) (bodyText, error) {
	wantHTML := strings.EqualFold(format, "html")
	all, plain, html := textParts(bs)
	var parts []bodyPart
	switch {
	case wantHTML && html != nil:
		parts = []bodyPart{*html}
	case wantHTML || html == nil:
		if plain == nil {
			// Attachments only, or a media type with no text part.
			// There is then no non-attachment text/plain or text/html
			// part anywhere in the structure either (all is empty
			// too), so this call decoded every part there is.
			return bodyText{signedNoEligible: true}, nil
		}
		parts = []bodyPart{*plain}
	case plain == nil:
		parts = []bodyPart{*html}
	default:
		parts = []bodyPart{*plain, *html}
	}

	secs := make([]*imap.FetchItemBodySection, len(parts))
	for i, p := range parts {
		secs[i] = partialFetch(p.path, maxPartBytes)
	}
	row, err := fetchOne(c, uid, &imap.FetchOptions{UID: true, BodySection: secs})
	if err != nil {
		return bodyText{}, err
	}
	decoded := make([]string, len(parts))
	marker := false
	cut := false
	for i, p := range parts {
		raw := row.FindBodySection(secs[i])
		decoded[i] = mime.DecodePart(raw, p.contentType, p.encoding)
		if mail.HasInlinePGP(decoded[i]) {
			marker = true
		}
		// A section that fills the whole fetch window is a cut even
		// when the declared size (checked above) did not say so: a
		// server that gets BODYSTRUCTURE size wrong, for example 0,
		// cannot make a cut part look whole (DRV.20.4, IRV.3).
		if p.size > maxPartBytes || int64(len(raw)) >= maxPartBytes {
			cut = true
		}
	}

	var plainText, htmlSrc string
	var hasPlain, hasHTML bool
	for i, p := range parts {
		if isHTMLType(p.contentType) {
			htmlSrc, hasHTML = decoded[i], true
		} else {
			plainText, hasPlain = decoded[i], true
		}
	}
	text, removed, differ := mime.PickBody(plainText, htmlSrc, hasPlain, hasHTML, wantHTML)
	eligible := !cut && len(parts) == len(all)
	return bodyText{text: text, removed: removed, differ: differ, marker: marker, signedNoEligible: eligible}, nil
}

// textParts walks the structure once and gives every non-attachment
// text/plain or text/html part (all), together with the first
// text/plain part (plain) and the first text/html part (html); either
// may be nil when the structure has none. fetchBody decodes only
// plain and html, the D4.2 choice; all is the fuller list DRV.4
// compares against, to tell whether this call decoded every part or
// left one out (a second text/plain part, or the other part when
// format "html" asks for one only).
//
// It walks the structure itself instead of calling pickPreviewPart,
// because the preview has one rule (plain first, small window) and
// Read has another (the caller's format, the D4.2 part choice, full
// window).
//
// arch: T4.3, §3.10, D4.2, DRV.4
func textParts(bs imap.BodyStructure) (all []bodyPart, plain, html *bodyPart) {
	bs.Walk(func(path []int, part imap.BodyStructure) bool {
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok {
			return true
		}
		if isAttachment(sp) {
			return true
		}
		mt := strings.ToLower(sp.MediaType())
		if mt != "text/plain" && mt != "text/html" {
			return true
		}
		p := bodyPart{
			path:        slices.Clone(path),
			contentType: contentTypeOf(sp),
			encoding:    sp.Encoding,
			size:        int64(sp.Size),
		}
		all = append(all, p)
		switch mt {
		case "text/plain":
			if plain == nil {
				q := p
				plain = &q
			}
		case "text/html":
			if html == nil {
				q := p
				html = &q
			}
		}
		return true
	})
	return all, plain, html
}

// signedStructure reports whether BODYSTRUCTURE shows a signature
// that only the whole source can settle: a multipart/signed entity,
// or an application/(x-)pkcs7-mime part, at any depth (D6.2).
//
// A lone application/pgp-signature or pkcs7-signature part is not in
// the set. A detached signature says nothing without the
// multipart/signed entity that names what it covers, and that entity
// is already in the set; a signature part in a multipart/mixed
// message covers nothing this server can check. So it buys no verdict
// and it would cost the fetch of the whole message.
//
// One shape is out of the set (DR1G.7): a message that is one
// top-level pkcs7-mime part that mail.SMIMEKindOf names
// SMIMEEnveloped. Such a part holds no signature that read can see
// without the decrypt tool. The gate fails closed (IR1G.3): a
// pkcs7-mime part inside a multipart, a missing, unknown or
// conflicting smime-type, and signed-data all stay in the set, so read
// fetches the source for them.
//
// arch: D6.2, DR1G.7, DR1G.18, IR1G.2, IR1G.3
func signedStructure(bs imap.BodyStructure) bool {
	if singleEnveloped(bs) {
		return false
	}
	found := false
	bs.Walk(func(_ []int, part imap.BodyStructure) bool {
		switch strings.ToLower(part.MediaType()) {
		case "multipart/signed",
			"application/pkcs7-mime", "application/x-pkcs7-mime":
			found = true
			return false
		}
		return true
	})
	return found
}

// singleEnveloped reports whether bs is one top-level single part that
// mail.SMIMEKindOf names SMIMEEnveloped. go-imap keeps an RFC 2231 form
// of the smime-type key ("smime-type*", "smime-type*0", ...) in
// Params. SMIMEKindOf names such a part SMIMEUnknown, so it gives
// false here and the gate fetches (IR1G.3).
//
// arch: DR1G.7, IR1G.3
func singleEnveloped(bs imap.BodyStructure) bool {
	sp, ok := bs.(*imap.BodyStructureSinglePart)
	if !ok {
		return false
	}
	return mail.SMIMEKindOf(sp.MediaType(), sp.Params) == mail.SMIMEEnveloped
}

// topType gives the top-level media type of a message and the
// smime-type parameter of its Content-Type. read uses the two to name
// an encrypted message (D7.3). Only a single part carries smime-type,
// so a multipart message gives an empty parameter.
//
// DR1G.18.1 exemption: topType reads the smime-type key and passes the
// value on as it is. It compares no value, so it does not call the
// predicate; the caller decides the kind with mail.SMIMEKindOfValue.
func topType(bs imap.BodyStructure) (mediaType, smimeType string) {
	mediaType = bs.MediaType()
	if sp, ok := bs.(*imap.BodyStructureSinglePart); ok {
		for k, v := range sp.Params {
			if strings.EqualFold(k, "smime-type") {
				smimeType = v
			}
		}
	}
	return mediaType, smimeType
}

// isHTMLType reports whether a Content-Type names HTML.
func isHTMLType(ct string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "text/html")
}

// parseReferences reads the References header out of a header fetch.
// Each id keeps its angle brackets, and the order stays as the sender
// wrote it: oldest first (§3.14).
//
// It takes every token that looks like an id, so the header name and
// any comma between ids drop out on their own.
//
// arch: T4.3, §3.14
func parseReferences(section []byte) []string {
	if len(section) == 0 {
		return nil
	}
	var out []string
	for _, f := range strings.Fields(string(section)) {
		f = strings.Trim(f, ",;")
		if len(f) > 2 && strings.HasPrefix(f, "<") && strings.HasSuffix(f, ">") {
			out = append(out, f)
		}
	}
	return out
}
