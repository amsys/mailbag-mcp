// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"slices"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// maxRefNames is how many file names an "unknown attachment" error
// lists, and maxRefLen is how long one of those names may be. A file
// name comes from the sender, so the error holds a short, single-line
// copy of it (§3.15, C19).
const (
	maxRefNames = 20
	maxRefLen   = 100
)

// Attachment opens one attachment of a message.
//
// ref is the part path ("2", "1.3") or the file name, because a
// person and a model both give the name (C19). An unknown ref fails
// with the names this message really holds.
//
// The part size comes from BODYSTRUCTURE, so an attachment that is
// larger than the limit fails before any byte of it is fetched. The
// fetch itself still asks for one byte more than the limit, so a
// server that reports a wrong size cannot fill the memory either.
//
// arch: T4.3, §3.10, §3.8, C2, C4, C19
func (p *Provider) Attachment(ctx context.Context, id, ref string) (io.ReadCloser, mail.AttachmentInfo, error) {
	var info mail.AttachmentInfo
	var data []byte
	err := p.pool.WithRead(ctx, p.alias, func(c *Conn) error {
		uid, _, _, err := locate(c, id)
		if err != nil {
			return err
		}
		row, err := fetchOne(c, uid, &imap.FetchOptions{
			UID:           true,
			BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		})
		if err != nil {
			return err
		}
		if row.BodyStructure == nil {
			return fmt.Errorf("imap: the server sent no body structure for this message")
		}
		sp, path, err := findAttachment(row.BodyStructure, ref)
		if err != nil {
			return err
		}
		if int64(sp.Size) > maxRawBytes {
			return fmt.Errorf("imap: this attachment is %d MB, larger than the limit of %d MB",
				int64(sp.Size)>>20, maxRawBytes>>20)
		}
		sec := &imap.FetchItemBodySection{
			Part:    path,
			Peek:    true,
			Partial: &imap.SectionPartial{Offset: 0, Size: maxRawBytes + 1},
		}
		got, err := fetchOne(c, uid, &imap.FetchOptions{
			UID:         true,
			BodySection: []*imap.FetchItemBodySection{sec},
		})
		if err != nil {
			return err
		}
		raw := got.FindBodySection(sec)
		if int64(len(raw)) > maxRawBytes {
			return fmt.Errorf("imap: this attachment is larger than the limit of %d MB", maxRawBytes>>20)
		}
		body, err := decodeTransfer(raw, sp.Encoding)
		if err != nil {
			return fmt.Errorf("imap: decode attachment %q: %w", pathString(path), err)
		}
		data = body
		info = mail.AttachmentInfo{
			Filename:    sp.Filename(),
			ContentType: sp.MediaType(),
			Size:        int64(len(body)),
		}
		return nil
	})
	if err != nil {
		return nil, mail.AttachmentInfo{}, err
	}
	return io.NopCloser(bytes.NewReader(data)), info, nil
}

// attachmentsOf lists the attachment parts of a message, with no
// download. A part is an attachment when its disposition says so, or
// when it has a file name (§3.10). The content type comes from the
// parsed structure, never from a guess about the name (C19).
//
// arch: T4.3, §3.10, C19
func attachmentsOf(bs imap.BodyStructure) []mail.Attachment {
	var out []mail.Attachment
	bs.Walk(func(path []int, part imap.BodyStructure) bool {
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok || !isAttachment(sp) {
			return true
		}
		out = append(out, mail.Attachment{
			Ref:         pathString(path),
			Filename:    sp.Filename(),
			ContentType: sp.MediaType(),
			Size:        int64(sp.Size),
			SMIMEType:   smimeTypeParam(sp),
		})
		return true
	})
	return out
}

// smimeTypeParam gives the smime-type parameter of sp, or "" when it
// has none. go-imap gives the parameter keys in lower case, so one
// lookup finds it. It reads the key and passes the value on to
// mail.SMIMEKindOfValue. It compares no value, so it is exempt from
// the one-predicate rule (DR1G.18.1).
//
// arch: DR1G.18.1, DR1G.18.2
func smimeTypeParam(sp *imap.BodyStructureSinglePart) string {
	return sp.Params["smime-type"]
}

// isAttachment is the rule of §3.10 for one part, from
// mime.IsAttachment. A multipart node never reaches it, because only a
// single part carries a file name.
//
// arch: DRV.3, §3.10
func isAttachment(sp *imap.BodyStructureSinglePart) bool {
	var disp string
	if d := sp.Disposition(); d != nil {
		disp = d.Value
	}
	return mime.IsAttachment(disp, sp.Filename())
}

// findAttachment matches ref against the part paths and the file
// names of a message. The file name match ignores case, because a
// person types the name from the list.
//
// A ref that matches nothing gives the file names that do exist, so
// the next call works (C19).
//
// arch: T4.3, §3.10, C19
func findAttachment(bs imap.BodyStructure, ref string) (*imap.BodyStructureSinglePart, []int, error) {
	ref = strings.TrimSpace(ref)
	var found *imap.BodyStructureSinglePart
	var foundPath []int
	var names []string
	bs.Walk(func(path []int, part imap.BodyStructure) bool {
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok || !isAttachment(sp) {
			return true
		}
		id := pathString(path)
		name := sp.Filename()
		if name == "" {
			name = id
		}
		names = append(names, name)
		if found == nil && ref != "" && (ref == id || strings.EqualFold(ref, name)) {
			found, foundPath = sp, slices.Clone(path)
		}
		return true
	})
	if found != nil {
		return found, foundPath, nil
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("imap: this message has no attachment")
	}
	return nil, nil, fmt.Errorf("imap: this message has no attachment %q; it has: %s",
		safeName(ref), strings.Join(safeNames(names), ", "))
}

// safeNames makes the file name list of an error safe to print. A
// sender picks the names, so the list stays short and each name stays
// on one line (§3.15).
func safeNames(names []string) []string {
	if len(names) > maxRefNames {
		names = names[:maxRefNames]
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, strconv.Quote(safeName(n)))
	}
	return out
}

// safeName makes one sender-chosen name safe to put in an error.
//
// The error text leaves internal/imap unfenced: internal/tools sends
// it to the model as an isError text content, and §3.15 lets only
// internal/tools add a fence. So the name must carry no fence marker
// of its own. safeName removes the hidden characters first, then cuts
// the name to maxRefLen characters and drops every control character.
// It does not add a fence.
//
// It removes the marker text last, with guard.StripFenceMarkers,
// which loops to a fixed point itself: a one-off hidden or control
// character inside a marker can otherwise join two halves of it back
// together (DRV.9, IRV.7).
//
// arch: T4.3, DRV.9, §3.15, §3.10, C19, M14
func safeName(s string) string {
	clean, _ := guard.StripInvisible(s)
	r := []rune(clean)
	if len(r) > maxRefLen {
		r = r[:maxRefLen]
	}
	for i, c := range r {
		if c < 0x20 || c == 0x7f {
			r[i] = ' '
		}
	}
	return guard.StripFenceMarkers(string(r))
}

// pathString writes a part path the way IMAP and the read tool show
// it: "1", "2.1".
func pathString(path []int) string {
	if len(path) == 0 {
		return ""
	}
	parts := make([]string, 0, len(path))
	for _, n := range path {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ".")
}

// decodeTransfer undoes the Content-Transfer-Encoding of one part and
// gives the bytes of the file.
//
// It does not go through internal/mime: mime.DecodePart also converts
// the charset of a text part, which would change the bytes that a
// saved file holds. An attachment gets the bytes the sender sent.
// An unknown encoding gives the raw bytes, like §3.14 asks.
//
// arch: T4.3, §3.10, §3.14
func decodeTransfer(raw []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		// The decoder skips the line breaks of the wire form.
		return io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(raw)))
	case "quoted-printable":
		return io.ReadAll(quotedprintable.NewReader(bytes.NewReader(raw)))
	default:
		return raw, nil
	}
}
