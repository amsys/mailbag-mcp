// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the opaque CMS extractor and its BER reader (DR1G.3).

package verify

import (
	"bytes"
	"encoding/asn1"
	"os/exec"
	"strings"
	"testing"
)

// opaqueBody is the signed content of the opaque fixtures, as a MIME
// entity with CRLF line ends.
const opaqueBody = "Content-Type: text/plain\r\n\r\nopaque body line one\r\nline two\r\n"

// signOpaque signs content with l as an opaque SignedData in DER (or
// BER with -stream in extra). -binary keeps the content byte for byte.
func (p *smimePKI) signOpaque(l leaf, content []byte, extra ...string) []byte {
	p.t.Helper()
	in := p.write("opaque-in.bin", content)
	args := append([]string{"cms", "-sign", "-binary", "-nodetach", "-outform", "DER", "-md", "sha256",
		"-in", in, "-signer", l.cert, "-inkey", l.key}, extra...)
	out, err := exec.Command(p.openssl, args...).Output() //nolint:gosec // G204: test helper; p.openssl is the openssl found by the test and the arguments are built by the test
	if err != nil {
		p.t.Fatalf("openssl cms -sign: %v", err)
	}
	return out
}

// verifyDetached checks the detached SignedData det over content with
// openssl, against the test root only. It gives the openssl error.
func (p *smimePKI) verifyDetached(det, content []byte) error {
	p.t.Helper()
	d := p.write("opaque-det.der", det)
	c := p.write("opaque-content.bin", content)
	return exec.Command(p.openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", d, //nolint:gosec // G204: test code; the program and its arguments are built by the test
		"-content", c, "-CAfile", p.caFile, "-no-CApath", "-no-CAstore",
		"-purpose", "smimesign", "-out", "/dev/null").Run()
}

// tnode is one ASN.1 element of a test fixture. The tests read DER
// with encoding/asn1, not with the reader under test, change the tree
// and write it again as DER or BER.
type tnode struct {
	class, tag int
	cons       bool
	indef      bool // write an indefinite length
	value      []byte
	kids       []*tnode
}

func tparse(t testing.TB, der []byte) *tnode {
	t.Helper()
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(der, &rv)
	if err != nil || len(rest) != 0 {
		t.Fatalf("fixture DER: %v, %d bytes left", err, len(rest))
	}
	n := &tnode{class: rv.Class, tag: rv.Tag, cons: rv.IsCompound}
	if !rv.IsCompound {
		n.value = rv.Bytes
		return n
	}
	for b := rv.Bytes; len(b) > 0; {
		var k asn1.RawValue
		if b, err = asn1.Unmarshal(b, &k); err != nil {
			t.Fatalf("fixture DER: %v", err)
		}
		n.kids = append(n.kids, tparse(t, k.FullBytes))
	}
	return n
}

func (n *tnode) encode() []byte {
	var body []byte
	if n.cons {
		for _, k := range n.kids {
			body = append(body, k.encode()...)
		}
	} else {
		body = n.value
	}
	first := byte(n.class<<6) | 0x1f //nolint:gosec // G115: class is an ASN.1 class from 0 to 3, so class<<6 fits in a byte
	if n.cons {
		first |= 0x20
	}
	var out []byte
	if n.tag < 0x1f {
		out = []byte{first&^0x1f | byte(n.tag)} //nolint:gosec // G115: the branch checks n.tag < 0x1f
	} else {
		var tb []byte
		for v := n.tag; v > 0; v >>= 7 {
			tb = append([]byte{byte(v&0x7f) | 0x80}, tb...)
		}
		tb[len(tb)-1] &^= 0x80
		out = append([]byte{first}, tb...)
	}
	if n.indef {
		out = append(out, 0x80)
		out = append(out, body...)
		return append(out, 0, 0)
	}
	return append(append(out, tlen(len(body))...), body...)
}

// tlen gives a DER definite length.
func tlen(size int) []byte {
	if size < 0x80 {
		return []byte{byte(size)} //nolint:gosec // G115: the branch checks size < 0x80
	}
	var lb []byte
	for v := size; v > 0; v >>= 8 {
		lb = append([]byte{byte(v)}, lb...)
	}
	return append([]byte{0x80 | byte(len(lb))}, lb...) //nolint:gosec // G115: lb holds the bytes of one int, so len(lb) is at most 8
}

func (n *tnode) count() int {
	c := 1
	for _, k := range n.kids {
		c += k.count()
	}
	return c
}

// opaqueTree names the frames of a parsed opaque ContentInfo.
type opaqueTree struct {
	ci, wrap, sd, encap, econ, oct *tnode
}

func frames(t testing.TB, ci *tnode) opaqueTree {
	t.Helper()
	o := opaqueTree{ci: ci, wrap: ci.kids[1]}
	o.sd = o.wrap.kids[0]
	o.encap = o.sd.kids[2]
	if len(o.encap.kids) != 2 {
		t.Fatal("fixture has no eContent")
	}
	o.econ = o.encap.kids[1]
	o.oct = o.econ.kids[0]
	return o
}

// berFrames writes the outer frames with indefinite lengths and splits
// eContent into a constructed OCTET STRING with a nested constructed
// part, the shape that Outlook and other streaming clients send.
func berFrames(t testing.TB, der []byte, split bool) []byte {
	t.Helper()
	o := frames(t, tparse(t, der))
	for _, n := range []*tnode{o.ci, o.wrap, o.sd, o.encap, o.econ} {
		n.indef = true
	}
	if split {
		v := o.oct.value
		half := len(v) / 2
		inner := &tnode{class: 0, tag: tagOctetString, cons: true, indef: true}
		for i := half; i < len(v); i += 5 {
			inner.kids = append(inner.kids, &tnode{tag: tagOctetString, value: v[i:min(i+5, len(v))]})
		}
		o.oct.cons, o.oct.indef, o.oct.value = true, true, nil
		o.oct.kids = []*tnode{
			{tag: tagOctetString, value: v[:3]},
			{tag: tagOctetString, value: v[3:half]},
			{tag: tagOctetString, value: nil},
			inner,
		}
	}
	return o.ci.encode()
}

// allIndef marks every constructed element as indefinite.
func allIndef(n *tnode) {
	if n.cons {
		n.indef = true
	}
	for _, k := range n.kids {
		allIndef(k)
	}
}

// TestOpaqueContent_DER reads a DER opaque SignedData from openssl and
// gives the signed bytes; openssl verifies the detached result.
//
// arch: DR1G.3
func TestOpaqueContent_DER(t *testing.T) {
	p := newSMIMEPKI(t)
	l := p.leaf("signer", leafOpts{email: "alice@example.org"})
	der := p.signOpaque(l, []byte(opaqueBody))
	content, det, ok := opaqueContent(der)
	if !ok {
		t.Fatal("ok=false for DER opaque signed-data")
	}
	if string(content) != opaqueBody {
		t.Fatalf("content = %q", content)
	}
	if err := p.verifyDetached(det, content); err != nil {
		t.Fatalf("detached does not verify: %v", err)
	}
}

// TestOpaqueContent_BERIndefinite reads BER with indefinite lengths:
// the openssl -stream output and a re-encoded DER fixture.
//
// arch: DR1G.3
func TestOpaqueContent_BERIndefinite(t *testing.T) {
	p := newSMIMEPKI(t)
	l := p.leaf("signer", leafOpts{email: "alice@example.org"})
	der := p.signOpaque(l, []byte(opaqueBody))
	stream := p.signOpaque(l, []byte(opaqueBody), "-stream")
	if !bytes.HasPrefix(stream, []byte{0x30, 0x80}) {
		t.Fatalf("openssl -stream did not give an indefinite length: % x", stream[:2])
	}
	all := tparse(t, der)
	allIndef(all)
	cases := map[string][]byte{
		"openssl-stream":   stream,
		"frames-indef":     berFrames(t, der, false),
		"every-cons-indef": all.encode(),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			content, det, ok := opaqueContent(in)
			if !ok {
				t.Fatal("ok=false for BER opaque signed-data")
			}
			if string(content) != opaqueBody {
				t.Fatalf("content = %q", content)
			}
			if name == "every-cons-indef" {
				// The certificate and the signed attributes are BER
				// here too. openssl verifies the certificate over its
				// DER form, so this case does not verify (exit 4).
				// The reader must still read them.
				return
			}
			if err := p.verifyDetached(det, content); err != nil {
				t.Fatalf("detached does not verify: %v", err)
			}
		})
	}
}

// TestOpaqueContent_ConstructedOctetString joins the parts of a
// constructed eContent, also a nested constructed part and an empty
// part.
//
// arch: DR1G.3
func TestOpaqueContent_ConstructedOctetString(t *testing.T) {
	p := newSMIMEPKI(t)
	l := p.leaf("signer", leafOpts{email: "alice@example.org"})
	in := berFrames(t, p.signOpaque(l, []byte(opaqueBody)), true)
	content, det, ok := opaqueContent(in)
	if !ok {
		t.Fatal("ok=false for a constructed OCTET STRING")
	}
	if string(content) != opaqueBody {
		t.Fatalf("content = %q", content)
	}
	if err := p.verifyDetached(det, content); err != nil {
		t.Fatalf("detached does not verify: %v", err)
	}

	// A part that is not an OCTET STRING is not BER for eContent.
	o := frames(t, tparse(t, p.signOpaque(l, []byte(opaqueBody))))
	o.oct.cons, o.oct.kids = true, []*tnode{{tag: tagOctetString, value: []byte("a")}, {tag: tagInteger, value: []byte{1}}}
	if _, _, ok := opaqueContent(o.ci.encode()); ok {
		t.Fatal("ok=true for a constructed OCTET STRING with an INTEGER part")
	}
}

// TestOpaqueContent_Limits checks the reader limits at their bounds
// and malformed input. Each breach gives ok=false.
//
// arch: DR1G.3, D10.3
func TestOpaqueContent_Limits(t *testing.T) {
	p := newSMIMEPKI(t)
	l := p.leaf("signer", leafOpts{email: "alice@example.org"})
	der := p.signOpaque(l, []byte(opaqueBody))

	// certs gives a fixture with extra elements in the certificates
	// field, which the reader reads but opaqueContent does not judge.
	certs := func(add ...*tnode) []byte {
		o := frames(t, tparse(t, der))
		c := o.sd.kids[3]
		if c.class != classContext || c.tag != 0 {
			t.Fatal("fixture has no certificates field")
		}
		c.kids = append(c.kids, add...)
		return o.ci.encode()
	}
	// chain gives k nested SEQUENCEs around a NULL. The certificates
	// field is at level 4, so the NULL is at level 4+k+1.
	chain := func(k int) *tnode {
		n := &tnode{tag: 5}
		for i := 0; i < k; i++ {
			n = &tnode{tag: tagSequence, cons: true, kids: []*tnode{n}}
		}
		return n
	}
	nulls := func(k int) []*tnode {
		out := make([]*tnode, k)
		for i := range out {
			out[i] = &tnode{tag: 5}
		}
		return out
	}
	base := tparse(t, der).count()

	good := map[string][]byte{
		"depth-32":       certs(chain(27)),
		"elements-10000": certs(nulls(maxBERElements - base)...),
	}
	for name, in := range good {
		if _, _, ok := opaqueContent(in); !ok {
			t.Errorf("%s: ok=false at the limit", name)
		}
	}

	big := frames(t, tparse(t, der))
	big.oct.value = make([]byte, MaxInput)
	wrongType := frames(t, tparse(t, der))
	wrongType.ci.kids[0].value = append(append([]byte{}, oidSignedData[:8]...), 3) // enveloped-data
	detachedIn := frames(t, tparse(t, der))
	detachedIn.encap.kids = detachedIn.encap.kids[:1]
	indefPrim := frames(t, tparse(t, der))
	indefPrim.oct.indef = true
	ber := berFrames(t, der, false)
	eocInDef := frames(t, tparse(t, der))
	eocInDef.sd.kids[3].kids = append(eocInDef.sd.kids[3].kids, &tnode{tag: 0})

	bad := map[string][]byte{
		"depth-33":          certs(chain(28)),
		"elements-10001":    certs(nulls(maxBERElements - base + 1)...),
		"over-MaxInput":     big.ci.encode(),
		"empty":             nil,
		"truncated":         der[:len(der)-1],
		"trailing-byte":     append(append([]byte{}, der...), 0),
		"no-end-marker":     ber[:len(ber)-2],
		"indef-primitive":   indefPrim.ci.encode(),
		"eoc-in-definite":   eocInDef.ci.encode(),
		"enveloped-data":    wrongType.ci.encode(),
		"no-eContent":       detachedIn.ci.encode(),
		"length-five-bytes": {0x30, 0x85, 0, 0, 0, 0, 1, 5},
		"high-tag-low-num":  {0x3f, 0x10, 0x00},
		"not-asn1":          []byte("Content-Type: text/plain\r\n\r\nhi\r\n"),
	}
	for name, in := range bad {
		if c, d, ok := opaqueContent(in); ok || c != nil || d != nil {
			t.Errorf("%s: ok=%v, want ok=false and no bytes", name, ok)
		}
	}
}

// TestOpaqueContent_DetachedKeepsSignerInfos checks that the detached
// SignedData is DER framed, keeps version, digestAlgorithms,
// certificates and signerInfos byte for byte, and has no eContent.
// LF-only content verifies as signed, and a changed content does not.
//
// arch: DR1G.3
func TestOpaqueContent_DetachedKeepsSignerInfos(t *testing.T) {
	p := newSMIMEPKI(t)
	l := p.leaf("signer", leafOpts{email: "alice@example.org"})
	lf := []byte(strings.ReplaceAll(opaqueBody, "\r\n", "\n"))
	der := p.signOpaque(l, lf)
	for name, in := range map[string][]byte{"der": der, "ber": berFrames(t, der, true)} {
		t.Run(name, func(t *testing.T) {
			content, det, ok := opaqueContent(in)
			if !ok {
				t.Fatal("ok=false")
			}
			if !bytes.Equal(content, lf) {
				t.Fatalf("content = %q", content)
			}
			// tparse reads DER only, so this also checks the framing.
			got := frames0(t, tparse(t, det))
			want := frames(t, tparse(t, der))
			if len(got.sd.kids) != len(want.sd.kids) {
				t.Fatalf("detached has %d fields, want %d", len(got.sd.kids), len(want.sd.kids))
			}
			for i, k := range want.sd.kids {
				if i == 2 {
					continue
				}
				if !bytes.Equal(got.sd.kids[i].encode(), k.encode()) {
					t.Errorf("SignedData field %d changed", i)
				}
			}
			if len(got.encap.kids) != 1 || !bytes.Equal(got.encap.kids[0].encode(), want.encap.kids[0].encode()) {
				t.Errorf("encapContentInfo is not eContentType alone")
			}
			if err := p.verifyDetached(det, content); err != nil {
				t.Fatalf("LF-only detached does not verify: %v", err)
			}
			changed := append(append([]byte{}, content...), 'x')
			if p.verifyDetached(det, changed) == nil {
				t.Fatal("a changed content verifies")
			}
		})
	}
}

// frames0 is frames for a SignedData with no eContent.
func frames0(t *testing.T, ci *tnode) opaqueTree {
	t.Helper()
	o := opaqueTree{ci: ci, wrap: ci.kids[1]}
	o.sd = o.wrap.kids[0]
	o.encap = o.sd.kids[2]
	return o
}

// TestOpaqueContent_SameBytesTwice checks that two calls on one input
// give equal content and equal detached bytes, and that a change to
// the result of one call does not reach the next. openssl verifies
// and read shows bytes of one opaqueContent call; equal bytes per call
// is the base of that rule.
//
// arch: DR1G.3, IR1G.4
func TestOpaqueContent_SameBytesTwice(t *testing.T) {
	p := newSMIMEPKI(t)
	l := p.leaf("signer", leafOpts{email: "alice@example.org"})
	der := p.signOpaque(l, []byte(opaqueBody))
	for name, in := range map[string][]byte{"der": der, "ber": berFrames(t, der, true)} {
		t.Run(name, func(t *testing.T) {
			keep := append([]byte{}, in...)
			c1, d1, ok1 := opaqueContent(in)
			if !ok1 {
				t.Fatal("ok=false")
			}
			c1c, d1c := append([]byte{}, c1...), append([]byte{}, d1...)
			for i := range c1 {
				c1[i] = 'Z'
			}
			for i := range d1 {
				d1[i] = 0xff
			}
			c2, d2, ok2 := opaqueContent(in)
			if !ok2 || !bytes.Equal(c1c, c2) || !bytes.Equal(d1c, d2) {
				t.Fatal("two calls give different bytes")
			}
			if !bytes.Equal(in, keep) {
				t.Fatal("opaqueContent changed its input")
			}
		})
	}
}

// TestOpaqueContent_LengthWraps gives long-form lengths of four bytes
// that are above the int range of a 32-bit platform. On GOARCH=386 the
// value wraps to a negative size. The reader must give ok=false and
// must not panic.
//
// arch: DR1G.3, IR1G.4
func TestOpaqueContent_LengthWraps(t *testing.T) {
	cases := map[string][]byte{
		"cons-ffffffff":   {0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x05, 0x00},
		"cons-80000000":   {0x30, 0x84, 0x80, 0x00, 0x00, 0x00, 0x05, 0x00},
		"prim-ffffffff":   {0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 0x41},
		"prim-80000000":   {0x04, 0x84, 0x80, 0x00, 0x00, 0x00, 0x41},
		"nested-ffffffff": {0x30, 0x08, 0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 0x41, 0x42},
		"indef-80000000":  {0x30, 0x80, 0x04, 0x84, 0x80, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if c, d, ok := opaqueContent(in); ok || c != nil || d != nil {
				t.Fatalf("ok=%v, want ok=false and no bytes", ok)
			}
		})
	}
}

// opaqueSeeds gives the opaque fixtures of the tests above: the inputs
// that opaqueContent accepts (good) and malformed inputs (bad).
func opaqueSeeds(tb testing.TB) (good, bad [][]byte) {
	p := newSMIMEPKI(tb)
	l := p.leaf("signer", leafOpts{email: "alice@example.org"})
	der := p.signOpaque(l, []byte(opaqueBody))
	lf := p.signOpaque(l, []byte(strings.ReplaceAll(opaqueBody, "\r\n", "\n")))
	all := tparse(tb, der)
	allIndef(all)
	deep := frames(tb, tparse(tb, der))
	chain := &tnode{tag: 5}
	for i := 0; i < 27; i++ {
		chain = &tnode{tag: tagSequence, cons: true, kids: []*tnode{chain}}
	}
	deep.sd.kids[3].kids = append(deep.sd.kids[3].kids, chain)
	ber := berFrames(tb, der, false)
	good = [][]byte{
		der,
		p.signOpaque(l, []byte(opaqueBody), "-stream"),
		ber,
		all.encode(),
		berFrames(tb, der, true),
		lf,
		berFrames(tb, lf, true),
		deep.ci.encode(),
	}
	bad = [][]byte{
		der[:len(der)-1],
		append(append([]byte{}, der...), 0),
		ber[:len(ber)-2],
		{0x30, 0x85, 0, 0, 0, 0, 1, 5},
		{0x3f, 0x10, 0x00},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x05, 0x00},
		{0x30, 0x84, 0x80, 0x00, 0x00, 0x00, 0x05, 0x00},
	}
	return good, bad
}

// FuzzOpaqueContent checks the BER reader on random input:
// opaqueContent never panics, and ok=false gives no bytes. The seeds
// are the opaque fixtures. Each accepted seed cut short by one or more
// bytes gives ok=false; an accepted fuzz input cut short by one byte
// also gives ok=false.
//
// arch: DR1G.3, IR1G.4
func FuzzOpaqueContent(f *testing.F) {
	good, bad := opaqueSeeds(f)
	for _, s := range good {
		if _, _, ok := opaqueContent(s); !ok {
			f.Fatalf("seed of %d bytes: ok=false", len(s))
		}
		for n := 0; n < len(s); n++ {
			if _, _, ok := opaqueContent(s[:n]); ok {
				f.Fatalf("seed of %d bytes cut to %d bytes: ok=true", len(s), n)
			}
		}
		f.Add(s)
	}
	for _, s := range bad {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		c, d, ok := opaqueContent(in)
		if !ok {
			if c != nil || d != nil {
				t.Fatalf("ok=false with %d content and %d detached bytes", len(c), len(d))
			}
			return
		}
		if _, _, ok := opaqueContent(in[:len(in)-1]); ok {
			t.Fatalf("input of %d bytes cut by one byte: ok=true", len(in))
		}
	})
}
