// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"context"
	"encoding/hex"
	"mime"
	"strings"
	"testing"
)

// attackText is 31 bytes of text, the size the judge put in a
// preamble and an epilogue of a good signature (D6.2).
const attackText = "Pay invoice 99 to IBAN XX now.\n"

// stubVerified is a checker of type typ that always gives a verified
// result with no unsigned flag, as a path that misses the rule would.
func stubVerified(typ string) checker {
	return func(_ context.Context, _ []byte, _ string, _ Config) *Signature {
		return &Signature{Type: typ, Verdict: VerdictVerified, Trust: TrustPinned,
			SignerMatchesFrom: true, Fingerprint: "ab12"}
	}
}

// smimeShape is an S/MIME multipart/signed message with pre and epi as
// its preamble and epilogue. The signature bytes are not real: only a
// stub checker reads this message.
func smimeShape(pre, epi string) []byte {
	return []byte(crlf("From: alice@example.com\nMIME-Version: 1.0\n"+
		"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\";\n"+
		" micalg=sha-256; boundary=\"b1\"\n\n") +
		crlf(pre) + "--b1\r\n" + textPart("hi") + "\r\n--b1\r\n" +
		crlf("Content-Type: application/pkcs7-signature\nContent-Transfer-Encoding: base64\n\nAAAA\n") +
		"--b1--\r\n" + crlf(epi))
}

// TestVerify_PreambleEpilogueIsUnsigned proves I17: text in the
// preamble or the epilogue of a PGP/MIME multipart/signed entity never
// gives verified. It gives unsigned_parts_present and verdict partial.
// White space only is not content. For S/MIME, the preamble and the
// epilogue are not content, and the verdict stays verified (ORV.8).
// One PGP/MIME and one S/MIME fixture with a real good signature show
// the rule through Check. Stub checkers that miss the rule show that
// Check itself applies it, for both paths, so the rule is in one place.
//
// arch: D6.2, D6.1, ORV.8
func TestVerify_PreambleEpilogueIsUnsigned(t *testing.T) {
	if len(attackText) != 31 {
		t.Fatalf("attackText is %d bytes, want 31", len(attackText))
	}
	type want struct {
		verdict  string
		unsigned bool
	}
	check := func(t *testing.T, s *Signature, typ string, w want) {
		t.Helper()
		if s == nil {
			t.Fatal("Check gave no result for a signed message")
		}
		if s.Type != typ || s.Verdict != w.verdict || s.Unsigned != w.unsigned {
			t.Fatalf("got type=%s verdict=%s unsigned=%v, want type=%s verdict=%s unsigned=%v",
				s.Type, s.Verdict, s.Unsigned, typ, w.verdict, w.unsigned)
		}
		walkSignature(t, s)
	}

	t.Run("PGP/MIME fixture", func(t *testing.T) {
		alice := pgpKey(t, "Alice", "alice@example.com", nil)
		cfg := Config{PGPKeysDir: keyDir(t, alice)}
		msg := func(pre, epi string) []byte {
			return withFrom("alice@example.com", signedEntity(t, alice, textPart("hi"), pre, epi, nil))
		}
		cases := []struct {
			name string
			raw  []byte
			want want
		}{
			{"no preamble, no epilogue is verified", msg("", ""), want{VerdictVerified, false}},
			{"white space in preamble and epilogue is verified", msg(" \t\n\n", "\n \n"), want{VerdictVerified, false}},
			{"31 bytes of preamble text is partial", msg(attackText, ""), want{VerdictPartial, true}},
			{"31 bytes of epilogue text is partial", msg("", attackText), want{VerdictPartial, true}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				check(t, Check(context.Background(), tc.raw, "alice@example.com", cfg), TypeOpenPGP, tc.want)
			})
		}

		// The OpenPGP path does not open a multipart/encrypted entity,
		// but the rule walk does. An empty part in it made the shared
		// multipart split panic on sender input. The walk that cannot
		// read the tree must give partial, not a panic.
		t.Run("multipart/encrypted outside the signed entity is partial, no panic", func(t *testing.T) {
			enc := crlf("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"e\"\n\n") +
				"--e\r\n--e--\r\n"
			raw := withFrom("alice@example.com", mixed(signedEntity(t, alice, textPart("hi"), "", "", nil), enc))
			check(t, Check(context.Background(), raw, "alice@example.com", cfg), TypeOpenPGP, want{VerdictPartial, true})
		})
	})

	t.Run("S/MIME fixture", func(t *testing.T) {
		p := newSMIMEPKI(t)
		const alice = "alice@example.com"
		good := p.sign(p.leaf("alice", leafOpts{email: alice}), alice, "hello from alice")
		cfg := Config{SMIMECAFile: p.caFile}
		epilogue := append(append([]byte{}, good...), []byte(attackText)...)
		cases := []struct {
			name string
			raw  []byte
			want want
		}{
			{"no preamble text is verified", good, want{VerdictVerified, false}},
			// ORV.8: the preamble and the epilogue of an S/MIME
			// signed entity are not content.
			{"31 bytes of preamble text is verified", insertPreamble(t, good, attackText[:len(attackText)-1]), want{VerdictVerified, false}},
			{"31 bytes of epilogue text is verified", epilogue, want{VerdictVerified, false}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				check(t, Check(context.Background(), tc.raw, alice, cfg), TypeSMIME, tc.want)
			})
		}
	})

	t.Run("Check applies the rule for a path that misses it", func(t *testing.T) {
		oldP, oldS := checkOpenPGP, checkSMIME
		t.Cleanup(func() { checkOpenPGP, checkSMIME = oldP, oldS })

		// A PGP/MIME shape: the signature is not checked by the stub.
		pgpEnt := func(pre, epi string) string {
			return crlf("Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"s\"\n\n") +
				crlf(pre) + "--s\r\n" + textPart("hi") + "\r\n--s\r\n" +
				crlf("Content-Type: application/pgp-signature\n\nsig\n") + "--s--\r\n" + crlf(epi)
		}
		pgp := func(pre, epi string) []byte { return withFrom("alice@example.com", pgpEnt(pre, epi)) }
		cases := []struct {
			name string
			typ  string
			raw  []byte
			want want
		}{
			{"PGP/MIME clean stays verified", TypeOpenPGP, pgp("", ""), want{VerdictVerified, false}},
			{"PGP/MIME preamble text", TypeOpenPGP, pgp(attackText, ""), want{VerdictPartial, true}},
			{"PGP/MIME epilogue text", TypeOpenPGP, pgp("", attackText), want{VerdictPartial, true}},
			{"PGP/MIME no-break space in the preamble is content", TypeOpenPGP, pgp("\u00a0\n", ""), want{VerdictPartial, true}},
			{"PGP/MIME part outside the signed entity", TypeOpenPGP,
				withFrom("alice@example.com", mixed(textPart(attackText), pgpEnt("", ""))),
				want{VerdictPartial, true}},
			{"PGP/MIME with no close delimiter is not proven signed", TypeOpenPGP,
				pgp("", "")[:len(pgp("", ""))-len("--s--\r\n")], want{VerdictPartial, true}},
			{"S/MIME clean stays verified", TypeSMIME, smimeShape("", ""), want{VerdictVerified, false}},
			// ORV.8: S/MIME preamble and epilogue text is not content.
			{"S/MIME preamble text stays verified", TypeSMIME, smimeShape(attackText, ""), want{VerdictVerified, false}},
			{"S/MIME epilogue text stays verified", TypeSMIME, smimeShape("", attackText), want{VerdictVerified, false}},
			{"S/MIME white space only stays verified", TypeSMIME, smimeShape("\n \t\n", "\r\n\r\n"), want{VerdictVerified, false}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				// Only the stub of the case type runs, so the real
				// path cannot set the flag.
				checkOpenPGP, checkSMIME = nil, nil
				if tc.typ == TypeOpenPGP {
					checkOpenPGP = stubVerified(TypeOpenPGP)
				} else {
					checkSMIME = stubVerified(TypeSMIME)
				}
				check(t, Check(context.Background(), tc.raw, "alice@example.com", Config{}), tc.typ, tc.want)
			})
		}
	})

	t.Run("a tree that makes the split panic gives partial for both paths", func(t *testing.T) {
		// Two delimiter lines with no part between them.
		raw := []byte("Content-Type: multipart/mixed; boundary=a\n\n--a\n--a--\n")
		for _, typ := range []string{TypeOpenPGP, TypeSMIME} {
			s := markUnsigned(context.Background(), &Signature{Type: typ, Verdict: VerdictVerified}, raw)
			if s.Verdict != VerdictPartial || !s.Unsigned {
				t.Fatalf("%s: got verdict=%s unsigned=%v, want partial and true", typ, s.Verdict, s.Unsigned)
			}
		}
	})

	t.Run("the rule never raises a failed verdict", func(t *testing.T) {
		old := checkOpenPGP
		t.Cleanup(func() { checkOpenPGP = old })
		checkOpenPGP = func(_ context.Context, _ []byte, _ string, _ Config) *Signature {
			return &Signature{Type: TypeOpenPGP, Verdict: VerdictInvalid}
		}
		raw := withFrom("alice@example.com", crlf(
			"Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"s\"\n\n")+
			attackText+"--s\r\n"+textPart("hi")+"\r\n--s\r\n"+
			crlf("Content-Type: application/pgp-signature\n\nsig\n")+"--s--\r\n")
		check(t, Check(context.Background(), raw, "alice@example.com", Config{}), TypeOpenPGP, want{VerdictInvalid, true})
	})
}

// fakeSigned is a multipart/signed entity with a protocol that no
// checker reads. Its first part holds text. No signature covers it.
func fakeSigned(text string) string {
	return crlf("Content-Type: multipart/signed; protocol=\"application/x-fake\";\n"+
		" boundary=\"fk\"\n\n") +
		"--fk\r\n" + textPart(text) + "\r\n--fk\r\n" +
		crlf("Content-Type: application/x-fake\n\nAAAA\n") + "--fk--\r\n"
}

// TestSignedEntity_SameEntityAsTheChecker closes finding 2 of
// R1E-judge.md in package verify: SignedEntity gives the entity that
// the verdict covers, not the first multipart/signed entity of any
// protocol and not a clearsigned block that the checker did not use.
// The PGP rows also go through Check, so the verdict and the entity
// come from the same signed part.
//
// arch: D6.2, I17
func TestSignedEntity_SameEntityAsTheChecker(t *testing.T) {
	e := pgpKey(t, "Bank", "bank@example.test", nil)
	dir := keyDir(t, e)
	pgpReal := signedEntity(t, e, textPart("REAL SIGNED TEXT\n"), "", "", nil)
	smimeReal := string(smimeShape("", ""))
	smimeReal = smimeReal[strings.Index(smimeReal, "Content-Type:"):]

	tests := []struct {
		name, typ, raw   string
		want, attack     string
		ok, checkPartial bool
	}{
		{name: "fake protocol before PGP/MIME", typ: TypeOpenPGP,
			raw:  mixed(fakeSigned("ATTACKER UNSIGNED TEXT\n"), pgpReal),
			want: "REAL SIGNED TEXT", attack: "ATTACKER", ok: true, checkPartial: true},
		{name: "clearsigned text/plain before PGP/MIME", typ: TypeOpenPGP,
			raw:  mixed(textPart(clearsigned(t, e, "ATTACKER CLEARSIGN TEXT\n")), pgpReal),
			want: "REAL SIGNED TEXT", attack: "ATTACKER", ok: true, checkPartial: true},
		{name: "inline block with text around it", typ: TypeOpenPGP,
			raw:  textPart("ATTACKER BEFORE\n" + clearsigned(t, e, "REAL SIGNED TEXT\n") + "ATTACKER AFTER\n"),
			want: "REAL SIGNED TEXT", attack: "ATTACKER", ok: true},
		{name: "fake protocol before S/MIME", typ: TypeSMIME,
			raw:  mixed(fakeSigned("ATTACKER UNSIGNED TEXT\n"), smimeReal),
			want: "hi", attack: "ATTACKER", ok: true},
		{name: "opaque S/MIME has no text entity", typ: TypeSMIME,
			raw: crlf("Content-Type: application/pkcs7-mime; smime-type=signed-data\n" +
				"Content-Transfer-Encoding: base64\n\nAAAA\n")},
		{name: "dkim has no entity", typ: TypeDKIM, raw: textPart("ATTACKER\n"), attack: "ATTACKER"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := withFrom("Bank <bank@example.test>", tc.raw)
			ent, ok := SignedEntity(raw, tc.typ)
			if ok != tc.ok {
				t.Fatalf("SignedEntity ok = %v, want %v; entity %q", ok, tc.ok, ent)
			}
			if tc.attack != "" && strings.Contains(string(ent), tc.attack) {
				t.Errorf("the entity holds text that the verdict does not cover: %q", ent)
			}
			if !strings.Contains(string(ent), tc.want) {
				t.Errorf("the entity %q does not hold the signed text %q", ent, tc.want)
			}
			if !tc.checkPartial {
				return
			}
			s := Check(context.Background(), raw, "bank@example.test", Config{PGPKeysDir: dir})
			if s == nil || s.Type != TypeOpenPGP || s.Verdict != VerdictPartial || !s.Unsigned ||
				s.Fingerprint != hex.EncodeToString(e.PrimaryKey.Fingerprint) {
				t.Errorf("Check = %+v, want openpgp partial with the fingerprint of the real key", s)
			}
		})
	}
}

// TestVerify_OuterContentStillPartial proves the limit of ORV.8: the
// preamble and the epilogue of the S/MIME signed entity are not
// content, but content outside that entity still gives partial and
// unsigned_parts_present (I17). A stub checker that misses the rule
// shows that Check applies it. ORV.8 covers S/MIME only, so preamble
// and epilogue text of a PGP/MIME entity still give partial.
//
// arch: ORV.8
func TestVerify_OuterContentStillPartial(t *testing.T) {
	oldP, oldS := checkOpenPGP, checkSMIME
	t.Cleanup(func() { checkOpenPGP, checkSMIME = oldP, oldS })

	// smimeEnt is the S/MIME entity of smimeShape with no message header.
	smimeEnt := func(pre, epi string) string {
		s := string(smimeShape(pre, epi))
		return s[strings.Index(s, "Content-Type:"):]
	}
	pgpEnt := func(pre, epi string) string {
		return crlf("Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"s\"\n\n") +
			crlf(pre) + "--s\r\n" + textPart("hi") + "\r\n--s\r\n" +
			crlf("Content-Type: application/pgp-signature\n\nsig\n") + "--s--\r\n" + crlf(epi)
	}
	const from = "alice@example.com"
	cases := []struct {
		name     string
		typ      string
		raw      []byte
		verdict  string
		unsigned bool
	}{
		{"S/MIME preamble text alone is verified", TypeSMIME,
			withFrom(from, smimeEnt(attackText, attackText)), VerdictVerified, false},
		{"S/MIME text part before the signed entity", TypeSMIME,
			withFrom(from, mixed(textPart(attackText), smimeEnt("", ""))), VerdictPartial, true},
		{"S/MIME text part after the signed entity with a preamble", TypeSMIME,
			withFrom(from, mixed(smimeEnt(attackText, ""), textPart(attackText))), VerdictPartial, true},
		{"S/MIME second signed entity outside the first", TypeSMIME,
			withFrom(from, mixed(smimeEnt("", ""), smimeEnt("", ""))), VerdictPartial, true},
		{"S/MIME preamble of the outer multipart/mixed", TypeSMIME,
			withFrom(from, crlf("Content-Type: multipart/mixed; boundary=\"mix\"\n\n")+
				attackText+"--mix\r\n"+smimeEnt("", "")+"\r\n--mix--\r\n"), VerdictVerified, false},
		{"PGP/MIME preamble text is still partial", TypeOpenPGP,
			withFrom(from, pgpEnt(attackText, "")), VerdictPartial, true},
		{"PGP/MIME epilogue text is still partial", TypeOpenPGP,
			withFrom(from, pgpEnt("", attackText)), VerdictPartial, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkOpenPGP, checkSMIME = nil, nil
			if tc.typ == TypeOpenPGP {
				checkOpenPGP = stubVerified(TypeOpenPGP)
			} else {
				checkSMIME = stubVerified(TypeSMIME)
			}
			s := Check(context.Background(), tc.raw, from, Config{})
			if s == nil || s.Type != tc.typ || s.Verdict != tc.verdict || s.Unsigned != tc.unsigned {
				t.Fatalf("got %+v, want type=%s verdict=%s unsigned=%v", s, tc.typ, tc.verdict, tc.unsigned)
			}
		})
	}

	t.Run("S/MIME real signature nested with an outer part and an openssl preamble", func(t *testing.T) {
		checkOpenPGP, checkSMIME = oldP, oldS
		p := newSMIMEPKI(t)
		good := p.leaf("alice", leafOpts{email: from})
		raw := nestInMixed(withPreamble(t, p.sign(good, from, "hello from alice")), from)
		s := Check(context.Background(), raw, from, Config{SMIMECAFile: p.caFile})
		if s == nil || s.Type != TypeSMIME || s.Verdict != VerdictPartial || !s.Unsigned || s.Fingerprint != fp(good) {
			t.Fatalf("got %+v, want smime partial, unsigned=true, fingerprint of alice", s)
		}
	})
}

// TestSignedEntity_OpaqueEqualsVerifiedBytes proves IR1G.4: for an
// opaque signed-data message, the bytes that SignedEntity gives (the
// bytes read shows) are equal to the content part that openssl read
// and verified, and to the content of opaqueContent. Each check is
// for DER and BER, with CRLF and with LF-only content.
//
// arch: DR1G.3, IR1G.4
func TestSignedEntity_OpaqueEqualsVerifiedBytes(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	crlfDER := p.signOpaque(good, []byte(opaqueBody))
	lfDER := p.signOpaque(good, []byte(strings.ReplaceAll(opaqueBody, "\r\n", "\n")))
	cases := map[string][]byte{
		"crlf der": crlfDER,
		"crlf ber": berFrames(t, crlfDER, true),
		"lf der":   lfDER,
		"lf ber":   berFrames(t, lfDER, true),
	}
	for name, cms := range cases {
		t.Run(name, func(t *testing.T) {
			raw := opaqueMessage(alice, cms)
			bin, calls := recordOpenssl(t, p)
			s := Check(context.Background(), raw, alice, Config{SMIMECAFile: p.caFile, OpensslPath: bin})
			if s == nil || s.Verdict != VerdictVerified {
				t.Fatalf("got %+v, want verified", s)
			}
			ent, ok := SignedEntity(raw, TypeSMIME)
			if !ok {
				t.Fatal("SignedEntity ok=false for an opaque signed-data message")
			}
			content, _, ok := opaqueContent(cms)
			if !ok || !bytes.Equal(ent, content) {
				t.Fatalf("SignedEntity %q differs from opaqueContent %q", ent, content)
			}
			verified := 0
			for _, c := range calls() {
				if !contains(c.args, "-verify") {
					continue
				}
				verified++
				if got := framedContent(t, c.stdin); !bytes.Equal(got, ent) {
					t.Errorf("openssl verified %q, read shows %q", got, ent)
				}
			}
			if verified == 0 {
				t.Fatal("no openssl -verify call was recorded")
			}
		})
	}
}

// TestSignedEntity_InlineKeepsCharset proves that the entity for an
// inline clearsigned block declares the charset of its source part.
// The signed text keeps the bytes of that charset, so a fixed
// charset=utf-8 shows Latin-1 text broken. A part with no charset
// still gives utf-8. mime.FormatMediaType writes the value, so a value
// with a space stays one quoted parameter.
//
// arch: D6.2, I17, R16-L13
func TestSignedEntity_InlineKeepsCharset(t *testing.T) {
	e := pgpKey(t, "Bank", "bank@example.test", nil)
	latin1 := "Gr\xfc\xdfe aus K\xf6ln\n" // "Grüße aus Köln" in ISO-8859-1
	block := clearsigned(t, e, latin1)
	cases := []struct {
		name, ctype, want string
	}{
		{name: "latin-1", ctype: "text/plain; charset=iso-8859-1", want: "iso-8859-1"},
		{name: "quoted value", ctype: "text/plain; charset=\"windows-1252\"", want: "windows-1252"},
		{name: "no charset", ctype: "text/plain", want: "utf-8"},
		{name: "value with a space stays quoted", ctype: "text/plain; charset=\"a b\"", want: "a b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := withFrom("Bank <bank@example.test>", crlf("Content-Type: "+tc.ctype+"\n\n")+block)
			ent, ok := SignedEntity(raw, TypeOpenPGP)
			if !ok {
				t.Fatal("SignedEntity ok=false for an inline clearsigned block")
			}
			hdr, body := splitEntity(ent)
			mt, params, err := mime.ParseMediaType(hdr.Get("Content-Type"))
			if err != nil || mt != "text/plain" || params["charset"] != tc.want {
				t.Errorf("entity Content-Type %q, want text/plain with charset %s", hdr.Get("Content-Type"), tc.want)
			}
			if !bytes.Contains(body, []byte("Gr\xfc\xdfe")) {
				t.Errorf("entity body %q lost the source bytes", body)
			}
		})
	}
}
