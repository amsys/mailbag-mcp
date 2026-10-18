// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"bytes"
	"io"
	"strings"

	gomessage "github.com/emersion/go-message"

	// Registers every common charset with go-message (C21): with no
	// such import, decoding a part in any charset but UTF-8 fails.
	_ "github.com/emersion/go-message/charset"
)

// DecodePart decodes body, the raw bytes of one MIME part exactly as
// fetched from the wire, using the part's own Content-Transfer-Encoding
// and Content-Type. It returns UTF-8 text.
//
// It never fails. An unknown transfer encoding or an unknown charset
// gives the raw bytes back as text, not an error (§3.14: "an unknown
// charset or encoding gives the raw bytes as text, not an error").
// A transfer encoding that breaks mid-stream (a truncated base64
// group, a cut quoted-printable escape — the preview fetch of §3.10
// takes only the first 2048 bytes) keeps the prefix that decoded
// cleanly before the break, the same as [Preview] (DRV.13): it no
// longer shows the raw, still-encoded bytes. For base64, body is cut
// to the last complete 4-character group first, as [trimPartialBase64]
// does for Preview, so a fetch cut mid-line does not lose a group that
// was in fact complete.
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15, DRV.13
func DecodePart(body []byte, contentType, transferEncoding string) string {
	if strings.EqualFold(strings.TrimSpace(transferEncoding), "base64") {
		body = trimPartialBase64(body)
	}
	out, _ := decodePart(body, contentType, transferEncoding)
	return out
}

// DecodedSize gives the decoded byte count of r, one MIME part's raw
// bytes read as a stream, using the part's own
// Content-Transfer-Encoding. It does no charset step: the count is the
// bytes of the file that the attachment tool saves, not a UTF-8 copy
// (REVIEW-2026-10-16 L14). So it uses only the media type of
// contentType and drops its parameters. It keeps the other DecodePart
// rules (§3.14): an unknown encoding counts the raw bytes, and a
// transfer encoding that breaks mid-stream counts the clean prefix
// (DRV.13), the same as a truncated base64 group still counts the
// groups before it.
//
// It never holds the decoded part in memory: it copies from the
// decoding reader straight into a byte counter (D7.2: a caller that
// only wants the size never gets a buffer of the content).
//
// arch: DR1G.9, DRV.13
func DecodedSize(r io.Reader, contentType, transferEncoding string) int {
	var h gomessage.Header
	// go-message converts a text part with a charset parameter to
	// UTF-8. With no parameters it gives the transfer-decoded bytes.
	mediaType, _, _ := strings.Cut(contentType, ";")
	if mediaType = strings.TrimSpace(mediaType); mediaType == "" {
		mediaType = "text/plain"
	}
	h.Set("Content-Type", mediaType)
	if transferEncoding != "" {
		h.Set("Content-Transfer-Encoding", transferEncoding)
	}

	// message.New always returns a usable Entity (see decodePart):
	// on an unknown encoding, Entity.Body falls back to the untouched
	// bytes of r, so the count below still matches §3.14's "raw
	// bytes, not an error" rule.
	e, _ := gomessage.New(h, r)

	var c byteCounter
	// io.Copy keeps every byte the decoder already produced before a
	// mid-stream error (io.ReadAll does the same for DecodePart), so
	// a truncated base64 group still counts the clean prefix (DRV.13).
	_, _ = io.Copy(&c, e.Body)
	return int(c.n)
}

// byteCounter is an io.Writer that only counts the bytes written to
// it, so DecodedSize never keeps the decoded content itself.
type byteCounter struct{ n int64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// decodePart is DecodePart with the mid-stream decode error kept.
// Preview needs it: §3.10 wants an empty preview on any failure, not
// the raw encoded bytes. An unknown charset or encoding is still no
// error here (§3.14).
func decodePart(body []byte, contentType, transferEncoding string) (string, error) {
	var h gomessage.Header
	if contentType == "" {
		contentType = "text/plain"
	}
	h.Set("Content-Type", contentType)
	if transferEncoding != "" {
		h.Set("Content-Transfer-Encoding", transferEncoding)
	}

	// message.New always returns a usable Entity, even when it also
	// returns an UnknownCharsetError or UnknownEncodingError (its own
	// doc comment): Entity.Body then reads the untouched bytes. There
	// is nothing else New can fail on here, so the error is not worth
	// a caller-visible return.
	e, _ := gomessage.New(h, bytes.NewReader(body))

	out, err := io.ReadAll(e.Body)
	return string(out), err
}
