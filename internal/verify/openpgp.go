// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package verify

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func init() { checkOpenPGP = pgpCheck }

// maxKeyFile is the largest file in pgp_keys_dir that pgpCheck reads.
// A larger file is not a public key that a human put there.
const maxKeyFile = 1 << 20

// errStructure is a MIME tree that pgpCheck cannot read: a multipart
// with no close delimiter, or a tree deeper than MaxDepth.
var errStructure = errors.New("verify: MIME structure not readable")

// pgpCheck gives the OpenPGP result of raw (D6.2 step 2). It finds a
// PGP/MIME multipart/signed entity (RFC 3156) or an inline clearsigned
// block in a text/plain part.
//
// Public keys come only from cfg.PGPKeysDir, a directory the human
// controls. A key in the message is never read, so it gives no trust.
// There is no key fetch. A key from that directory gives trust pinned.
//
// The verdict comes from the signature bytes, the key and the MIME
// tree. It never comes from body text, so the words "signature
// verified" in a body do not change it (I12). The result holds only
// enum words, hex and booleans (I11).
//
// It gives nil when the message has no OpenPGP signature. An
// encrypted message gives nil, because this check does not decrypt.
//
// arch: D6.1, D6.2, D10.3, I11, I12, DRV.18
func pgpCheck(ctx context.Context, raw []byte, from string, cfg Config) *Signature {
	if len(raw) > MaxInput {
		return unsupportedIfPGP(raw)
	}
	var sc pgpScan
	if err := sc.walk(ctx, raw, 0, false); err != nil {
		return unsupportedIfPGP(raw)
	}
	switch {
	case sc.mimeSigned != nil:
		return sc.verifyMIME(from, cfg)
	case sc.inline != nil:
		return sc.verifyInline(from, cfg)
	}
	return nil
}

// unsupportedIfPGP gives verdict unsupported when raw holds an OpenPGP
// signature marker, and nil when it does not. The caller uses it when a
// D6.2 limit stops the check (D10.3).
func unsupportedIfPGP(raw []byte) *Signature {
	low := bytes.ToLower(raw)
	if bytes.Contains(low, []byte("application/pgp-signature")) ||
		bytes.Contains(low, []byte("-----begin pgp signed message-----")) {
		return &Signature{Type: TypeOpenPGP, Verdict: VerdictUnsupported}
	}
	return nil
}

// pgpScan is the result of one walk of the MIME tree.
type pgpScan struct {
	// mimeSigned is the body of the first multipart/signed entity with
	// protocol application/pgp-signature. mimeBoundary is its boundary.
	mimeSigned   []byte
	mimeBoundary string

	// inline is the decoded body of the first text/plain part that
	// holds a clearsigned block. It is used only when mimeSigned is nil.
	inline []byte
	// inlineCharset is the charset parameter of that part, or empty.
	inlineCharset string

	// outside counts the content parts that are not the signed entity
	// and that hold a byte that is not white space. inlineOutside is
	// the same count for the inline case.
	outside       int
	inlineOutside int
}

// walk reads one MIME entity. inSigned is true inside the signed
// entity, where no part counts as outside.
//
// It checks ctx.Err() first, before reading ent, so a walk over many
// sibling parts stops at the next part once ctx is past its deadline
// (F-D6) instead of reading the rest of the tree. The result is
// errStructure, the same as a tree this walk cannot read: the caller
// gives verdict unsupported, never a verdict the server did not
// finish checking (D10.3).
func (sc *pgpScan) walk(ctx context.Context, ent []byte, depth int, inSigned bool) error {
	if ctx.Err() != nil {
		return errStructure
	}
	if depth > MaxDepth {
		return errStructure
	}
	hdr, body := splitEntity(ent)
	mt, params, err := mime.ParseMediaType(hdr.Get("Content-Type"))
	if err != nil {
		mt = "text/plain"
	}

	if isPGPSigned(mt, params) && !inSigned {
		if sc.mimeSigned != nil {
			// A second signed entity sits outside the first one.
			sc.outside++
			sc.inlineOutside++
			return nil
		}
		if params["boundary"] == "" {
			return errStructure
		}
		sc.mimeSigned, sc.mimeBoundary = body, params["boundary"]
		// The signed content is a part of the signed entity: walk it
		// for depth and to stop an inline block inside it counting.
		_, parts, _, ok := splitMultipart(body, sc.mimeBoundary)
		if !ok {
			return errStructure
		}
		if len(parts) > 0 {
			return sc.walk(ctx, parts[0], depth+1, true)
		}
		return nil
	}

	if strings.HasPrefix(mt, "multipart/") && mt != "multipart/encrypted" {
		b := params["boundary"]
		if b == "" {
			return errStructure
		}
		_, parts, _, ok := splitMultipart(body, b)
		if !ok {
			return errStructure
		}
		for _, p := range parts {
			if err := sc.walk(ctx, p, depth+1, inSigned); err != nil {
				return err
			}
		}
		return nil
	}

	if inSigned {
		return nil
	}
	// A leaf part, or an entity that this check does not open.
	if mt == "text/plain" && sc.inline == nil {
		dec := decodeCTE(body, hdr.Get("Content-Transfer-Encoding"))
		if b, _ := clearsign.Decode(dec); b != nil {
			sc.inline, sc.inlineCharset = dec, params["charset"]
			sc.outside++ // outside a PGP/MIME signed entity, if one comes
			return nil
		}
	}
	if len(bytes.TrimSpace(body)) > 0 {
		sc.outside++
		sc.inlineOutside++
	}
	return nil
}

// verifyMIME checks the PGP/MIME entity that walk found (RFC 3156).
func (sc *pgpScan) verifyMIME(from string, cfg Config) *Signature {
	pre, parts, epi, _ := splitMultipart(sc.mimeSigned, sc.mimeBoundary)
	if len(parts) != 2 {
		return &Signature{Type: TypeOpenPGP, Verdict: VerdictUnsupported}
	}
	sigHdr, sigBody := splitEntity(parts[1])
	mt, _, _ := mime.ParseMediaType(sigHdr.Get("Content-Type"))
	if mt != "application/pgp-signature" {
		return &Signature{Type: TypeOpenPGP, Verdict: VerdictUnsupported}
	}
	sigBytes, err := dearmor(decodeCTE(sigBody, sigHdr.Get("Content-Transfer-Encoding")))
	if err != nil {
		return &Signature{Type: TypeOpenPGP, Verdict: VerdictInvalid}
	}
	// D6.2: a byte that is not white space in the preamble or the
	// epilogue is content outside the signature.
	unsigned := sc.outside > 0 ||
		len(bytes.TrimSpace(pre)) > 0 || len(bytes.TrimSpace(epi)) > 0
	return pgpVerify(canonicalCRLF(parts[0]), sigBytes, from, cfg, unsigned)
}

// verifyInline checks the clearsigned block that walk found. Text
// before or after the block is not signed.
func (sc *pgpScan) verifyInline(from string, cfg Config) *Signature {
	i := clearsignStart(sc.inline)
	b, rest := clearsign.Decode(sc.inline)
	if b == nil || i < 0 {
		return &Signature{Type: TypeOpenPGP, Verdict: VerdictUnsupported}
	}
	sigBytes, err := io.ReadAll(io.LimitReader(b.ArmoredSignature.Body, MaxInput))
	if err != nil {
		return &Signature{Type: TypeOpenPGP, Verdict: VerdictInvalid}
	}
	unsigned := sc.inlineOutside > 0 ||
		len(bytes.TrimSpace(sc.inline[:i])) > 0 || len(bytes.TrimSpace(rest)) > 0 ||
		unsignedArmorHeader(b.ArmoredSignature.Header)
	return pgpVerify(b.Bytes, sigBytes, from, cfg, unsigned)
}

// unsignedArmorHeader is true when the armor headers of the signature
// block hold a key other than Version. The signature does not cover
// these headers, and the read output shows them next to the verdict,
// so a "Comment:" line is text that the signer did not sign.
//
// arch: REVIEW-2026-10-12 H7
func unsignedArmorHeader(h map[string]string) bool {
	for k := range h {
		if k != "Version" {
			return true
		}
	}
	return false
}

// clearsignStart gives the index of the marker line that
// clearsign.Decode reads as the start of the block, or -1. Decode
// accepts the marker at byte 0, or else the first marker that follows
// a line break. A marker in the middle of a line, for example after a
// space, is not the start. All text before the index is unsigned.
func clearsignStart(b []byte) int {
	m := []byte("-----BEGIN PGP SIGNED MESSAGE-----")
	if bytes.HasPrefix(b, m) {
		return 0
	}
	if i := bytes.Index(b, append([]byte("\n"), m...)); i >= 0 {
		return i + 1
	}
	return -1
}

// pgpVerify checks sigBytes, a binary OpenPGP signature, over signed
// with the keys of cfg.PGPKeysDir and maps the result to a Signature.
//
// The go-crypto check returns a signer only after the signature math
// passes. A revoked or expired key or signature comes back as an error
// with that signer, so the math is correct and only the trust changes.
// Trust revoked or expired gives verdict bad, ahead of every other
// condition; a weak digest algorithm gives partial (DRV.18).
func pgpVerify(signed, sigBytes []byte, from string, cfg Config, unsigned bool) *Signature {
	s := &Signature{Type: TypeOpenPGP, Unsigned: unsigned, Fingerprint: issuerHex(sigBytes)}
	keys := LoadKeyring(cfg.PGPKeysDir)
	pc := &packet.Config{Time: time.Now}
	sig, signer, err := openpgp.VerifyDetachedSignature(keys, bytes.NewReader(signed), bytes.NewReader(sigBytes), pc)

	switch {
	case errors.Is(err, pgperrors.ErrUnknownIssuer):
		s.Verdict, s.Trust = VerdictKeyUnavailable, TrustUnknown
		return s
	case errors.As(err, new(pgperrors.UnsupportedError)):
		// An algorithm the library does not check, for example MD5.
		// The server did not check the signature (D10.3).
		s.Verdict = VerdictUnsupported
		return s
	case signer == nil:
		s.Verdict = VerdictInvalid
		return s
	case err == nil:
		s.Trust = TrustPinned
	case errors.Is(err, pgperrors.ErrKeyRevoked):
		s.Trust = TrustRevoked
	case errors.Is(err, pgperrors.ErrKeyExpired), errors.Is(err, pgperrors.ErrSignatureExpired):
		s.Trust = TrustExpired
	default:
		s.Verdict = VerdictInvalid
		return s
	}

	s.Fingerprint = hex.EncodeToString(signer.PrimaryKey.Fingerprint)
	s.SignerMatchesFrom = uidMatches(signer, fromAddress(from))
	s.Weak = sig != nil && (sig.Hash == crypto.SHA1 || sig.Hash == crypto.MD5)
	switch {
	case s.Trust == TrustRevoked || s.Trust == TrustExpired:
		// A revoked or expired key is bad even when the signature math
		// is correct and From matches: "valid" must never show on a
		// signer that is no longer trusted (DRV.18).
		s.Verdict = VerdictBad
	case unsigned:
		s.Verdict = VerdictPartial
	case s.Weak:
		// A weak digest algorithm never reaches verified (DRV.18).
		s.Verdict = VerdictPartial
	case s.Trust == TrustPinned && s.SignerMatchesFrom:
		s.Verdict = VerdictVerified
	default:
		s.Verdict = VerdictValidUnknownSigner
	}
	return s
}

// uidMatches is true when a user ID of e that is not revoked has the
// address addr. The address compares with no case.
func uidMatches(e *openpgp.Entity, addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	now := time.Now()
	for _, id := range e.Identities {
		if id.UserId == nil || id.Revoked(now) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(id.UserId.Email), addr) {
			return true
		}
	}
	return false
}

// LoadKeyring reads each regular file in dir as an armored or a binary
// key ring. A file that is not a key ring, or that is larger than
// maxKeyFile, is skipped. An empty dir gives no keys. It has two
// callers: pgpVerify, and "mailbag-mcp doctor" (DR1G.12), which prints
// the count this gives for cfg.PGPKeysDir so the two never drift. A
// symlink to a key file counts: dir is read with os.ReadDir, but the
// size and the regular-file check come from os.Stat, which follows the
// symlink; maxKeyFile is the one size bound both callers use.
func LoadKeyring(dir string) openpgp.EntityList {
	var out openpgp.EntityList
	if dir == "" {
		return out
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxKeyFile {
			continue
		}
		data, err := os.ReadFile(p) //nolint:gosec // G304: the key dir comes from the human's accounts.toml; the code reads only regular files up to a size limit
		if err != nil {
			continue
		}
		if el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data)); err == nil {
			out = append(out, el...)
		} else if el, err := openpgp.ReadKeyRing(bytes.NewReader(data)); err == nil {
			out = append(out, el...)
		}
	}
	return out
}

// issuerHex gives the issuer of the first signature packet in sigBytes
// as hex: the full fingerprint when the packet has one, else the key
// ID. It gives "" when no signature packet can be read.
func issuerHex(sigBytes []byte) string {
	p, err := packet.NewReader(bytes.NewReader(sigBytes)).Next()
	if err != nil {
		return ""
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		return ""
	}
	if len(sig.IssuerFingerprint) > 0 {
		return hex.EncodeToString(sig.IssuerFingerprint)
	}
	if sig.IssuerKeyId != nil {
		return fmt.Sprintf("%016x", *sig.IssuerKeyId)
	}
	return ""
}

// dearmor gives the binary body of an armored signature, or b itself
// when b is not armored.
func dearmor(b []byte) ([]byte, error) {
	if !bytes.Contains(b, []byte("-----BEGIN PGP")) {
		return b, nil
	}
	blk, err := armor.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(blk.Body, MaxInput))
}

// splitEntity splits a MIME entity into its header and its body. An
// entity that starts with an empty line has no header. A header that
// cannot be parsed is empty, so the entity is text/plain (RFC 2045).
func splitEntity(ent []byte) (textproto.MIMEHeader, []byte) {
	var hdrEnd, bodyStart int
	switch {
	case bytes.HasPrefix(ent, []byte("\r\n")):
		return textproto.MIMEHeader{}, ent[2:]
	case bytes.HasPrefix(ent, []byte("\n")):
		return textproto.MIMEHeader{}, ent[1:]
	}
	crlf := bytes.Index(ent, []byte("\r\n\r\n"))
	lf := bytes.Index(ent, []byte("\n\n"))
	switch {
	case crlf >= 0 && (lf < 0 || crlf < lf):
		hdrEnd, bodyStart = crlf+2, crlf+4
	case lf >= 0:
		hdrEnd, bodyStart = lf+1, lf+2
	default:
		hdrEnd, bodyStart = len(ent), len(ent)
	}
	r := textproto.NewReader(bufio.NewReader(io.MultiReader(
		bytes.NewReader(ent[:hdrEnd]), strings.NewReader("\r\n"))))
	h, err := r.ReadMIMEHeader()
	if err != nil {
		h = textproto.MIMEHeader{}
	}
	return h, ent[bodyStart:]
}

// splitMultipart splits the body of a multipart entity at the lines
// "--boundary" (RFC 2046 5.1.1). A part does not hold the line break
// before the next delimiter. ok is false when no close delimiter
// "--boundary--" is found.
func splitMultipart(body []byte, boundary string) (pre []byte, parts [][]byte, epi []byte, ok bool) {
	delim := []byte("--" + boundary)
	start := -1
	for pos := 0; pos < len(body); {
		next := len(body)
		if i := bytes.IndexByte(body[pos:], '\n'); i >= 0 {
			next = pos + i + 1
		}
		line := bytes.TrimRight(body[pos:next], "\r\n")
		if bytes.HasPrefix(line, delim) {
			rest := line[len(delim):]
			isClose := bytes.HasPrefix(rest, []byte("--"))
			if isClose {
				rest = rest[2:]
			}
			if len(bytes.TrimRight(rest, " \t")) == 0 {
				end := pos
				if end > 0 && body[end-1] == '\n' {
					end--
					if end > 0 && body[end-1] == '\r' {
						end--
					}
				}
				if start < 0 {
					pre = body[:end]
				} else {
					parts = append(parts, body[start:end])
				}
				if isClose {
					return pre, parts, body[next:], true
				}
				start = next
			}
		}
		pos = next
	}
	return pre, parts, nil, false
}

// decodeCTE decodes a quoted-printable or a base64 body. Any other
// transfer encoding gives the body as it is.
func decodeCTE(body []byte, cte string) []byte {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "quoted-printable":
		r = quotedprintable.NewReader(bytes.NewReader(body))
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, bytes.NewReader(bytes.Join(bytes.Fields(body), nil)))
	default:
		return body
	}
	out, err := io.ReadAll(io.LimitReader(r, MaxInput))
	if err != nil && len(out) == 0 {
		return body
	}
	return out
}

// canonicalCRLF gives b with each line break as CRLF. RFC 3156 signs
// the part in this form, and a stored message can have bare LF.
func canonicalCRLF(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
}
