// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package verify

import (
	"context"
	"mime"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

// SignedEntity gives the bytes of the entity that a verdict of type
// sigType covers in raw, the full message. read shows the body from
// these bytes only when content sits outside the signed entity (D6.2,
// I17).
//
// It runs the same walk as the checker of sigType, so it picks the
// same entity: the first PGP/MIME multipart/signed entity (the
// isPGPSigned rule), else the first inline clearsigned block, for
// openpgp; the first entity of the isSMIMESigned rule for smime.
//
// For a multipart/signed entity, the result is its first part, with
// its header. For an inline block, the result is a text/plain entity
// that holds only the signed text of the block that verifyInline
// checks, with the charset of the part that holds the block (utf-8
// when that part gives none). For an opaque S/MIME signed-data entity, the result is the
// content that opaqueEntity reads from the CMS bytes: the same
// extractor that gives smimeCheck the bytes openssl verifies (DR1G.3,
// IR1G.4). ok is false for dkim, for CMS bytes that opaqueContent does
// not accept, for a tree that the walk cannot read, and for raw over
// MaxInput. Then read shows no body text.
//
// arch: D6.2, I17, DR1G.3, IR1G.4
func SignedEntity(raw []byte, sigType string) (entity []byte, ok bool) {
	if len(raw) > MaxInput {
		return nil, false
	}
	defer func() {
		// The sender controls raw. A panic in a MIME helper gives no
		// entity, so no text sits next to the verdict.
		if recover() != nil {
			entity, ok = nil, false
		}
	}()
	switch sigType {
	case TypeOpenPGP:
		var sc pgpScan
		// read already has the checked Signature; this walk only picks
		// out the bytes it covers, so it runs with no deadline of its
		// own (F-D6 bounds Check, not this lookup).
		if err := sc.walk(context.Background(), raw, 0, false); err != nil {
			return nil, false
		}
		switch {
		case sc.mimeSigned != nil:
			return firstPart(sc.mimeSigned, sc.mimeBoundary)
		case sc.inline != nil:
			b, _ := clearsign.Decode(sc.inline)
			if b == nil || clearsignStart(sc.inline) < 0 {
				return nil, false
			}
			// The signed text keeps the bytes of the source part, so
			// the entity declares the charset of that part
			// (REVIEW-2026-10-16 L13).
			ct := "text/plain; charset=utf-8"
			if sc.inlineCharset != "" {
				ct = mime.FormatMediaType("text/plain", map[string]string{"charset": sc.inlineCharset})
			}
			return append([]byte("Content-Type: "+ct+"\r\n\r\n"), b.Plaintext...), true
		}
	case TypeSMIME:
		var sc smimeScan
		if err := sc.walk(context.Background(), raw, 0); err != nil || sc.entity == nil {
			return nil, false
		}
		if !sc.multipart {
			content, _, ok := opaqueEntity(sc.entity)
			return content, ok
		}
		// The walk already split the entity into its two parts; parts[0]
		// is the signed content that reframe gives openssl (DRV.1).
		return sc.parts[0], true
	}
	return nil, false
}

// firstPart gives the first part of a multipart/signed body, the
// signed content with its header.
func firstPart(body []byte, boundary string) ([]byte, bool) {
	_, parts, _, ok := splitMultipart(body, boundary)
	if !ok || len(parts) == 0 {
		return nil, false
	}
	return parts[0], true
}

// markUnsigned applies the unsigned_parts_present rule of D6.2 to s,
// the result of the OpenPGP or the S/MIME path for raw. Check calls it
// for each result, so the rule is in one place for both paths.
//
// The rule: content sits outside the signed entity when a MIME entity
// with text is outside it, or, for PGP/MIME only, when the preamble or
// the epilogue of the multipart/signed entity holds a byte that is not
// white space. Then Unsigned is true, and a verdict of verified or
// valid_unknown_signer becomes partial (I17). The rule never clears a
// flag that a path set, and it never changes invalid,
// key_unavailable or unsupported.
//
// The preamble and the epilogue of an S/MIME multipart/signed entity
// are not content (ORV.8). openssl and Thunderbird write a preamble
// line in each detached signature. openssl reads only the re-framed
// parts (DRV.1), and SignedEntity gives only the first part, so that
// text reaches neither the verified bytes nor the body.
//
// A DKIM result, or an inline OpenPGP result with no multipart/signed
// entity, stays as it is. DKIM covers the full body, and the OpenPGP
// path checks the text around an inline block itself.
//
// arch: D6.2, D6.1, I17, ORV.8
func markUnsigned(ctx context.Context, s *Signature, raw []byte) *Signature {
	if s == nil || len(raw) > MaxInput {
		return s
	}
	var sc structScan
	switch s.Type {
	case TypeOpenPGP:
		sc.isSigned = isPGPSigned
	case TypeSMIME:
		sc.isSigned = isSMIMESigned
		sc.frameNotContent = true
	default:
		return s
	}
	good := s.Verdict == VerdictVerified || s.Verdict == VerdictValidUnknownSigner
	if err := sc.safeWalk(ctx, raw); err != nil {
		// The tree cannot be read, so no byte is proven to be signed.
		// A path that could not read it either gave unsupported for
		// a D6.2 limit (D10.3); that result stays as it is.
		if !good {
			return s
		}
		sc.found, sc.unsigned = true, true
	}
	if !sc.found || !sc.unsigned {
		return s
	}
	s.Unsigned = true
	if good {
		s.Verdict = VerdictPartial
	}
	return s
}

// structScan is the result of one walk of the MIME tree for one kind
// of signed entity.
type structScan struct {
	// isSigned is true for the signed entity of the kind to find.
	isSigned func(mt string, params map[string]string) bool

	// found is true when the walk found a signed entity of that kind.
	found bool

	// unsigned is true when content sits outside that entity.
	unsigned bool

	// frameNotContent is true when the preamble and the epilogue of the
	// signed entity are not content: the S/MIME kind (ORV.8).
	frameNotContent bool
}

// safeWalk walks raw and gives errStructure when the walk panics.
// The sender controls raw. A panic in a MIME helper on bad input must
// not stop the read tool, and a tree that cannot be read proves no
// byte is signed. This walk does not follow the same order as the
// path walks, so it can reach an entity that a path did not split.
// The guard stops that difference from being a new way to a panic.
func (sc *structScan) safeWalk(ctx context.Context, raw []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = errStructure
		}
	}()
	return sc.walk(ctx, raw, 0)
}

// walk reads one MIME entity ent. It does not open the signed entity:
// all content in it is signed. It checks ctx.Err() first, the same
// stop rule as pgpScan.walk and smimeScan.walk (F-D6); markUnsigned
// then treats a stopped walk as one that could not be read.
func (sc *structScan) walk(ctx context.Context, ent []byte, depth int) error {
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

	if sc.isSigned(mt, params) {
		if sc.found {
			// A second signed entity sits outside the first one.
			sc.unsigned = true
			return nil
		}
		sc.found = true
		if mt != "multipart/signed" {
			return nil // an opaque signed entity has no preamble
		}
		if params["boundary"] == "" {
			return errStructure
		}
		pre, _, epi, ok := splitMultipart(body, params["boundary"])
		if !ok {
			return errStructure
		}
		if !sc.frameNotContent && (hasContent(pre) || hasContent(epi)) {
			sc.unsigned = true
		}
		return nil
	}

	if strings.HasPrefix(mt, "multipart/") {
		if params["boundary"] == "" {
			return errStructure
		}
		_, parts, _, ok := splitMultipart(body, params["boundary"])
		if !ok {
			return errStructure
		}
		for _, p := range parts {
			if err := sc.walk(ctx, p, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if hasContent(body) {
		sc.unsigned = true
	}
	return nil
}

// isPGPSigned is true for a PGP/MIME multipart/signed entity (RFC 3156).
func isPGPSigned(mt string, params map[string]string) bool {
	return mt == "multipart/signed" &&
		strings.EqualFold(params["protocol"], "application/pgp-signature")
}

// hasContent is true when b holds a byte that is not white space.
// White space is only space, tab, CR and LF. A Unicode space, such as
// a no-break space, is content, because a reader can not see that it
// is not text.
func hasContent(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			return true
		}
	}
	return false
}
