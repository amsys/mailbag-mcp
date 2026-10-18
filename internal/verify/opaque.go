// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Opaque S/MIME signed-data: a small BER reader and the extractor that
// gives the encapsulated content and a detached SignedData (DR1G.3).

package verify

import (
	"bytes"
	"errors"
)

// The BER reader limits (DR1G.3 rule 2). The input is untrusted, so a
// breach gives ok=false, and the verdict is then unsupported (D10.3).
// The total input limit is MaxInput.
const (
	maxBERDepth    = 32
	maxBERElements = 10000
)

// oidSignedData is the DER content octets of the CMS content type
// id-signedData, 1.2.840.113549.1.7.2 (RFC 5652 section 5.1).
var oidSignedData = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}

// The ASN.1 classes and universal tags that opaqueContent reads.
const (
	classUniversal = 0
	classContext   = 2

	tagInteger     = 2
	tagOctetString = 4
	tagOID         = 6
	tagSequence    = 16
	tagSet         = 17
)

// errBER is any input that the BER reader does not accept.
var errBER = errors.New("verify: bad or too large BER")

// berNode is one element that the BER reader read.
type berNode struct {
	class int
	tag   int
	cons  bool
	raw   []byte     // the element as it is in the input: header, value and end marker
	value []byte     // content octets of a primitive element; nil when cons
	kids  []*berNode // the elements in a constructed element
}

// is is true when n has the class, tag and form given.
func (n *berNode) is(class, tag int, cons bool) bool {
	return n.class == class && n.tag == tag && n.cons == cons
}

// berReader reads BER (X.690) with definite and indefinite lengths. It
// counts the elements it reads, for the element limit.
type berReader struct {
	count int
}

// parse reads one element at the start of b, at nesting level depth
// (the outermost element is level 1). It gives the element and the
// number of bytes it used. Each constructed element is read down to
// its leaves, because an indefinite length is known only at its end
// marker.
func (r *berReader) parse(b []byte, depth int) (*berNode, int, error) {
	if depth > maxBERDepth {
		return nil, 0, errBER
	}
	r.count++
	if r.count > maxBERElements {
		return nil, 0, errBER
	}
	if len(b) < 2 {
		return nil, 0, errBER
	}
	n := &berNode{class: int(b[0] >> 6), cons: b[0]&0x20 != 0, tag: int(b[0] & 0x1f)}
	i := 1
	if n.tag == 0x1f {
		// High tag number form: base 128, at most four bytes. A tag
		// below 31 must use the low form (X.690 8.1.2.3).
		n.tag = 0
		for {
			if i >= len(b) || i > 4 {
				return nil, 0, errBER
			}
			c := b[i]
			i++
			n.tag = n.tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
		if n.tag < 0x1f {
			return nil, 0, errBER
		}
	}
	// Universal tag 0 is only the end-of-contents marker, which the
	// caller of an indefinite length reads.
	if n.class == classUniversal && n.tag == 0 {
		return nil, 0, errBER
	}
	if i >= len(b) {
		return nil, 0, errBER
	}
	l := b[i]
	i++
	if l == 0x80 {
		// Indefinite length: constructed only (X.690 8.1.3.2).
		if !n.cons {
			return nil, 0, errBER
		}
		for {
			if len(b)-i >= 2 && b[i] == 0 && b[i+1] == 0 {
				i += 2
				break
			}
			k, used, err := r.parse(b[i:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			n.kids = append(n.kids, k)
			i += used
		}
		n.raw = b[:i]
		return n, i, nil
	}
	size := int(l)
	if l > 0x80 {
		cnt := int(l & 0x7f)
		if cnt > 4 || len(b)-i < cnt {
			return nil, 0, errBER
		}
		size = 0
		for _, c := range b[i : i+cnt] {
			size = size<<8 | int(c)
		}
		i += cnt
	}
	// Four length bytes can give a value above the int range of a
	// 32-bit platform. The value then wraps to a negative size.
	if size < 0 || size > len(b)-i {
		return nil, 0, errBER
	}
	end := i + size
	if !n.cons {
		n.value = b[i:end]
		n.raw = b[:end]
		return n, end, nil
	}
	for i < end {
		k, used, err := r.parse(b[i:end], depth+1)
		if err != nil {
			return nil, 0, err
		}
		n.kids = append(n.kids, k)
		i += used
	}
	n.raw = b[:end]
	return n, end, nil
}

// octets gives the content of an OCTET STRING. A constructed OCTET
// STRING is the join of its parts, which can themselves be constructed
// (X.690 8.7.3).
func octets(n *berNode, out *bytes.Buffer) bool {
	if !n.cons {
		out.Write(n.value)
		return true
	}
	for _, k := range n.kids {
		if !k.is(classUniversal, tagOctetString, k.cons) || !octets(k, out) {
			return false
		}
	}
	return true
}

// derFrame gives one element with tag byte tag, a definite DER length
// and the content parts joined.
func derFrame(tag byte, parts ...[]byte) []byte {
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	out := []byte{tag}
	if size < 0x80 {
		out = append(out, byte(size))
	} else {
		var lb []byte
		for v := size; v > 0; v >>= 8 {
			lb = append([]byte{byte(v)}, lb...)
		}
		out = append(out, 0x80|byte(len(lb))) //nolint:gosec // G115: lb holds the bytes of one int, so len(lb) is at most 8
		out = append(out, lb...)
	}
	out = append(make([]byte, 0, len(out)+size), out...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// opaqueContent reads a DER or BER CMS ContentInfo of type SignedData
// with encapsulated content. It gives the content bytes and a detached
// SignedData (the same fields, with eContent removed) in DER framing.
// ok is false when the input is not that shape or breaks a limit.
//
// The detached SignedData copies version, digestAlgorithms,
// certificates, crls and signerInfos as raw element bytes. Only
// encapContentInfo is rebuilt, with eContentType and no eContent. The
// outer frames have definite lengths. The signature does not cover
// these frames, so the re-frame does not change what is verified.
// The result does not share memory with cms.
//
// arch: DR1G.3, IR1G.4
func opaqueContent(cms []byte) (content, detached []byte, ok bool) {
	if len(cms) == 0 || len(cms) > MaxInput {
		return nil, nil, false
	}
	var r berReader
	ci, used, err := r.parse(cms, 1)
	if err != nil || used != len(cms) {
		return nil, nil, false
	}
	// ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT content }
	if !ci.is(classUniversal, tagSequence, true) || len(ci.kids) != 2 {
		return nil, nil, false
	}
	ctype, wrap := ci.kids[0], ci.kids[1]
	if !ctype.is(classUniversal, tagOID, false) || !bytes.Equal(ctype.value, oidSignedData) {
		return nil, nil, false
	}
	if !wrap.is(classContext, 0, true) || len(wrap.kids) != 1 {
		return nil, nil, false
	}
	// SignedData ::= SEQUENCE { version, digestAlgorithms,
	// encapContentInfo, [0] certificates OPTIONAL, [1] crls OPTIONAL,
	// signerInfos }
	sd := wrap.kids[0]
	if !sd.is(classUniversal, tagSequence, true) || len(sd.kids) < 4 || len(sd.kids) > 6 {
		return nil, nil, false
	}
	f := sd.kids
	version, algs, encap, signers := f[0], f[1], f[2], f[len(f)-1]
	if !version.is(classUniversal, tagInteger, false) ||
		!algs.is(classUniversal, tagSet, true) ||
		!encap.is(classUniversal, tagSequence, true) ||
		!signers.is(classUniversal, tagSet, true) {
		return nil, nil, false
	}
	// The optional fields come in tag order, each at most once.
	opt := f[3 : len(f)-1]
	next := 0
	for _, o := range opt {
		if o.class != classContext || !o.cons || o.tag < next || o.tag > 1 {
			return nil, nil, false
		}
		next = o.tag + 1
	}
	// EncapsulatedContentInfo ::= SEQUENCE { eContentType,
	// [0] EXPLICIT eContent OCTET STRING }. An absent eContent is a
	// detached signature, which is not opaque.
	if len(encap.kids) != 2 {
		return nil, nil, false
	}
	etype, econ := encap.kids[0], encap.kids[1]
	if !etype.is(classUniversal, tagOID, false) || !econ.is(classContext, 0, true) || len(econ.kids) != 1 {
		return nil, nil, false
	}
	oct := econ.kids[0]
	if !oct.is(classUniversal, tagOctetString, oct.cons) {
		return nil, nil, false
	}
	var buf bytes.Buffer
	if !octets(oct, &buf) {
		return nil, nil, false
	}

	parts := [][]byte{version.raw, algs.raw, derFrame(0x30, etype.raw)}
	for _, o := range opt {
		parts = append(parts, o.raw)
	}
	parts = append(parts, signers.raw)
	sdNew := derFrame(0x30, parts...)
	detached = derFrame(0x30, ctype.raw, derFrame(0xa0, sdNew))
	content = append([]byte{}, buf.Bytes()...)
	return content, detached, true
}
