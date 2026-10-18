// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// smimeCanary sits in the subject of every test certificate. It must
// never reach a result (I18).
const smimeCanary = "CANARY-T96-SUBJECT"

// smimePKI is the test trust material in a temporary directory.
type smimePKI struct {
	t       testing.TB
	dir     string
	openssl string
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caFile  string // the root only
	crlFile string // the root and a CRL that revokes serial 99
	serial  int64
}

func newSMIMEPKI(t testing.TB) *smimePKI {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not on PATH; the S/MIME fixtures need it to sign")
	}
	p := &smimePKI{t: t, dir: t.TempDir(), openssl: bin, serial: 10}
	p.caKey = newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "T96 Root " + smimeCanary},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &p.caKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.ca, _ = x509.ParseCertificate(der)
	root := pemOf("CERTIFICATE", der)
	p.caFile = p.write("root.pem", root)

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(30 * 24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(99), RevocationTime: time.Now().Add(-time.Hour)},
		},
	}, p.ca, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.crlFile = p.write("root-crl.pem", append(append([]byte{}, root...), pemOf("X509 CRL", crl)...))
	return p
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func (p *smimePKI) write(name string, data []byte) string {
	p.t.Helper()
	f := filepath.Join(p.dir, name)
	if err := os.WriteFile(f, data, 0o600); err != nil {
		p.t.Fatal(err)
	}
	return f
}

// leaf is one signer certificate and its key, as files.
type leaf struct {
	cert, key string
	der       []byte
}

// leafOpts shape one signer certificate.
type leafOpts struct {
	email      string
	serial     int64 // 0 picks the next serial
	notBefore  time.Time
	notAfter   time.Time
	eku        []x509.ExtKeyUsage
	selfSigned bool // not under the test root
}

func (p *smimePKI) leaf(name string, o leafOpts) leaf {
	p.t.Helper()
	if o.serial == 0 {
		p.serial++
		o.serial = p.serial
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(365 * 24 * time.Hour)
	}
	if o.eku == nil {
		o.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	}
	k := newKey(p.t)
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(o.serial),
		Subject:        pkix.Name{CommonName: name + " " + smimeCanary},
		NotBefore:      o.notBefore,
		NotAfter:       o.notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    o.eku,
		EmailAddresses: []string{o.email},
	}
	parent, signer := p.ca, p.caKey
	if o.selfSigned {
		parent, signer = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, signer)
	if err != nil {
		p.t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		p.t.Fatal(err)
	}
	return leaf{
		cert: p.write(name+".pem", pemOf("CERTIFICATE", der)),
		key:  p.write(name+".key", pemOf("PRIVATE KEY", kd)),
		der:  der,
	}
}

// sign gives an S/MIME message from l with From: from. extra are
// more openssl cms -sign arguments, for example -nodetach.
func (p *smimePKI) sign(l leaf, from, body string, extra ...string) []byte {
	p.t.Helper()
	in := p.write("content.txt", []byte("Content-Type: text/plain\r\n\r\n"+body+"\r\n"))
	args := append([]string{"cms", "-sign", "-in", in, "-signer", l.cert, "-inkey", l.key, "-outform", "SMIME"}, extra...)
	if !contains(extra, "-md") {
		args = append(args, "-md", "sha256")
	}
	out, err := exec.Command(p.openssl, args...).Output() //nolint:gosec // G204: test helper; p.openssl is the openssl found by the test and the arguments are built by the test
	if err != nil {
		p.t.Fatalf("openssl cms -sign: %v", err)
	}
	// openssl writes a preamble line. D6.2 reads a preamble that is not
	// white space as unsigned content, so the fixture removes it. The
	// case "openssl preamble gives partial" keeps it on purpose.
	out = bytes.Replace(out, []byte(opensslPreamble), nil, 1)
	return append([]byte("From: "+from+"\r\nTo: me@home.example\r\nSubject: hi\r\n"), out...)
}

// opensslPreamble is the preamble line that openssl cms -sign writes
// before the first boundary of a multipart/signed body.
const opensslPreamble = "This is an S/MIME signed message\n"

// withPreamble puts the openssl preamble line back into msg.
func withPreamble(t *testing.T, msg []byte) []byte {
	t.Helper()
	return insertPreamble(t, msg, strings.TrimSuffix(opensslPreamble, "\n"))
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// fp is the SHA-256 fingerprint, hex, of l.
func fp(l leaf) string {
	s := sha256.Sum256(l.der)
	return hex.EncodeToString(s[:])
}

// nestInMixed puts msg, an S/MIME message, as the first part of a
// multipart/mixed message and adds a plain text part after it.
func nestInMixed(msg []byte, from string) []byte {
	i := bytes.Index(msg, []byte("MIME-Version:"))
	inner := msg[i:]
	var b bytes.Buffer
	b.WriteString("From: " + from + "\r\nMIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n\r\n")
	b.WriteString("--OUTER\r\n")
	b.Write(inner)
	b.WriteString("\r\n--OUTER\r\nContent-Type: text/plain\r\n\r\nPay invoice 42 today.\r\n--OUTER--\r\n")
	return b.Bytes()
}

// insertPreamble puts text before the first boundary line of the
// multipart/signed body of msg.
func insertPreamble(t *testing.T, msg []byte, text string) []byte {
	t.Helper()
	i := bytes.Index(msg, []byte("\n------"))
	if i < 0 {
		t.Fatal("no boundary line in the signed message")
	}
	return append(append(append([]byte{}, msg[:i+1]...), []byte(text+"\n")...), msg[i+1:]...)
}

// toCRLF gives msg with every line break as CRLF, the wire form.
func toCRLF(msg []byte) []byte {
	return bytes.ReplaceAll(bytes.ReplaceAll(msg, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
}

// fakeOpenssl writes a shell script that answers "version" with
// version and runs cmsScript for every other call.
func fakeOpenssl(t *testing.T, version, cmsScript string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "openssl")
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo '" + version + "'; exit 0; fi\n" + cmsScript + "\n"
	if err := os.WriteFile(f, []byte(script), 0o700); err != nil { //nolint:gosec // G306: the fake openssl must be executable, and the file sits in the test temp dir
		t.Fatal(err)
	}
	return f
}

// TestVerify_SMIMETwoPassChain proves the D6.2 S/MIME contract. Pass A
// gives the signer and the signature verdict. Pass B gives the chain.
// expired comes from NotAfter parsed in Go. revoked comes from the pass
// B exit-code pair, and a CRL check that fails only because the CA
// file has no CRL is not revoked. A missing openssl, an openssl that
// is not 3.x, a pass A output over 64 KB and the time limit each give
// unsupported. No certificate text reaches the result (I11, I18).
//
// chain, the config most cases use, has smime_crl_check off, so trust
// chain_valid becomes chain_valid_no_crl (DRV.18, ORV.11): every case
// that used to want chain_valid with that config now wants
// chain_valid_no_crl, listed in the T169 report. revoked and expired
// now want verdict bad, and the weak-digest case now wants partial
// (DRV.18); these are the new behaviour the row adds, not a weakened
// test.
//
// arch: D6.2, DRV.18
func TestVerify_SMIMETwoPassChain(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	mallory := p.leaf("mallory", leafOpts{email: "mallory@example.com"})
	expired := p.leaf("expired", leafOpts{
		email:     alice,
		notBefore: time.Now().Add(-3 * 365 * 24 * time.Hour),
		notAfter:  time.Now().Add(-2 * 365 * 24 * time.Hour),
	})
	rogue := p.leaf("rogue", leafOpts{email: alice, selfSigned: true})
	tls := p.leaf("tls", leafOpts{email: alice, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	revoked := p.leaf("revoked", leafOpts{email: alice, serial: 99})

	goodMsg := p.sign(good, alice, "hello from alice")
	tampered := bytes.Replace(goodMsg, []byte("hello from alice"), []byte("hello from ALICE"), 1)

	// chain has smime_crl_check off, so a chain that passes gives
	// chain_valid_no_crl, not chain_valid (DRV.18).
	chain := Config{SMIMECAFile: p.caFile}
	crl := Config{SMIMECAFile: p.crlFile, SMIMECRLCheck: true}
	noCRL := Config{SMIMECAFile: p.caFile, SMIMECRLCheck: true}

	cases := []struct {
		name     string
		raw      []byte
		from     string
		cfg      Config
		verdict  string
		trust    string
		match    bool
		fp       string
		weak     bool
		unsigned bool
	}{
		{name: "detached, chain to the root, signer is From", raw: goodMsg, cfg: chain,
			verdict: VerdictVerified, trust: TrustChainValidNoCRL, match: true, fp: fp(good)},
		{name: "CRLF wire form", raw: toCRLF(goodMsg), cfg: chain,
			verdict: VerdictVerified, trust: TrustChainValidNoCRL, match: true, fp: fp(good)},
		{name: "opaque signed-data", raw: p.sign(good, alice, "opaque body", "-nodetach"), cfg: chain,
			verdict: VerdictVerified, trust: TrustChainValidNoCRL, match: true, fp: fp(good)},
		{name: "From in display form, domain in other case", raw: goodMsg, from: "Alice <alice@EXAMPLE.com>", cfg: chain,
			verdict: VerdictVerified, trust: TrustChainValidNoCRL, match: true, fp: fp(good)},
		{name: "local part differs in case is not the signer", raw: goodMsg, from: "Alice@example.com", cfg: chain,
			verdict: VerdictValidUnknownSigner, trust: TrustChainValidNoCRL, fp: fp(good)},
		{name: "valid chain, signer is not From", raw: p.sign(mallory, alice, "hi"), cfg: chain,
			verdict: VerdictValidUnknownSigner, trust: TrustChainValidNoCRL, fp: fp(mallory)},
		{name: "tampered body is invalid", raw: tampered, cfg: chain, verdict: VerdictInvalid},
		{name: "expired certificate, from NotAfter gives verdict bad (DRV.18)", raw: p.sign(expired, alice, "old"), cfg: chain,
			verdict: VerdictBad, trust: TrustExpired, match: true, fp: fp(expired)},
		{name: "self-signed signer is not trusted", raw: p.sign(rogue, alice, "hi"), cfg: chain,
			verdict: VerdictValidUnknownSigner, trust: TrustUnknown, match: true, fp: fp(rogue)},
		{name: "TLS server certificate fails -purpose smimesign", raw: p.sign(tls, alice, "hi"), cfg: chain,
			verdict: VerdictValidUnknownSigner, trust: TrustUnknown, match: true, fp: fp(tls)},
		{name: "no smime_ca_file gives trust unknown", raw: goodMsg, cfg: Config{},
			verdict: VerdictValidUnknownSigner, trust: TrustUnknown, match: true, fp: fp(good)},
		{name: "revoked by the exit-code pair and the CRL gives verdict bad (DRV.18)", raw: p.sign(revoked, alice, "hi"), cfg: crl,
			verdict: VerdictBad, trust: TrustRevoked, match: true, fp: fp(revoked)},
		{name: "CRL check on, signer not in the CRL", raw: goodMsg, cfg: crl,
			verdict: VerdictVerified, trust: TrustChainValid, match: true, fp: fp(good)},
		{name: "CRL check on, no CRL in the CA file is not revoked", raw: goodMsg, cfg: noCRL,
			verdict: VerdictValidUnknownSigner, trust: TrustUnknown, match: true, fp: fp(good)},
		{name: "SHA-1 digest is weak, gives verdict partial (DRV.18)", raw: p.sign(good, alice, "hi", "-md", "sha1"), cfg: chain,
			verdict: VerdictPartial, trust: TrustChainValidNoCRL, match: true, fp: fp(good), weak: true},
		{name: "part outside the signed entity gives partial", raw: nestInMixed(goodMsg, alice), cfg: chain,
			verdict: VerdictPartial, trust: TrustChainValidNoCRL, match: true, fp: fp(good), unsigned: true},
		{name: "openssl preamble is verified (ORV.8)", raw: withPreamble(t, goodMsg), cfg: chain,
			verdict: VerdictVerified, trust: TrustChainValidNoCRL, match: true, fp: fp(good)},
		{name: "preamble text is verified (ORV.8)", raw: insertPreamble(t, goodMsg, "Signed and verified by IT."), cfg: chain,
			verdict: VerdictVerified, trust: TrustChainValidNoCRL, match: true, fp: fp(good)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from := tc.from
			if from == "" {
				from = alice
			}
			s := Check(context.Background(), tc.raw, from, tc.cfg)
			if s == nil {
				t.Fatal("Check gave no result for a signed message")
			}
			if s.Type != TypeSMIME || s.Verdict != tc.verdict || s.Trust != tc.trust ||
				s.SignerMatchesFrom != tc.match || s.Fingerprint != tc.fp ||
				s.Weak != tc.weak || s.Unsigned != tc.unsigned {
				t.Errorf("got %+v\nwant verdict=%s trust=%s match=%v fp=%s weak=%v unsigned=%v",
					*s, tc.verdict, tc.trust, tc.match, tc.fp, tc.weak, tc.unsigned)
			}
			noCanary(t, s)
		})
	}

	t.Run("unsigned message gives nil", func(t *testing.T) {
		raw := []byte("From: alice@example.com\r\nContent-Type: text/plain\r\n\r\nsigned by alice, verified\r\n")
		if s := Check(context.Background(), raw, alice, chain); s != nil {
			t.Errorf("got %+v, want nil", *s)
		}
	})

	unsupported := []struct {
		name string
		cfg  Config
	}{
		{"no openssl at openssl_path", Config{SMIMECAFile: p.caFile, OpensslPath: filepath.Join(t.TempDir(), "no-openssl")}},
		{"relative openssl_path", Config{SMIMECAFile: p.caFile, OpensslPath: "openssl"}},
		{"openssl that is not 3.x", Config{SMIMECAFile: p.caFile, OpensslPath: fakeOpenssl(t, "OpenSSL 1.1.1w  11 Sep 2023", "exit 0")}},
		{"pass A output over 64 KB", Config{SMIMECAFile: p.caFile, OpensslPath: fakeOpenssl(t, "OpenSSL 3.6.4",
			"head -c 70000 /dev/zero | tr '\\0' 'A'; exit 0")}},
		{"pass A exit 2 (not CMS)", Config{SMIMECAFile: p.caFile, OpensslPath: fakeOpenssl(t, "OpenSSL 3.6.4",
			"cat >/dev/null; echo '"+smimeCanary+" invalid mime type' >&2; exit 2")}},
	}
	for _, tc := range unsupported {
		t.Run(tc.name, func(t *testing.T) {
			s := Check(context.Background(), goodMsg, alice, tc.cfg)
			if s == nil || s.Type != TypeSMIME || s.Verdict != VerdictUnsupported || s.Trust != "" || s.Fingerprint != "" {
				t.Errorf("got %+v, want type smime, verdict unsupported, no trust, no fingerprint", s)
			}
			noCanary(t, s)
		})
	}

	// openssl cms -verify checks the smimesign purpose by default, so a
	// verdict alone cannot show that pass B asks for it. This case runs
	// the real openssl through a wrapper that records each argument
	// list, and checks the lists that smimeCheck sends.
	t.Run("openssl argument lists", func(t *testing.T) {
		log := filepath.Join(t.TempDir(), "argv.log")
		bin := filepath.Join(t.TempDir(), "openssl")
		script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\nexec '" + p.openssl + "' \"$@\"\n"
		if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: the fixture must be executable or a directory, and it sits in the test temp dir
			t.Fatal(err)
		}
		s := Check(context.Background(), goodMsg, alice, Config{SMIMECAFile: p.crlFile, SMIMECRLCheck: true, OpensslPath: bin})
		if s == nil || s.Verdict != VerdictVerified || s.Trust != TrustChainValid {
			t.Fatalf("got %+v, want verdict verified, trust chain_valid through the wrapper", s)
		}
		data, err := os.ReadFile(log) //nolint:gosec // G304: test code; the path is built by the test
		if err != nil {
			t.Fatal(err)
		}
		var passA, passB, passBCRL int
		for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if l == "version" {
				continue
			}
			f := " " + l + " "
			if !strings.HasPrefix(l, "cms ") || !strings.Contains(f, " -in /dev/stdin ") {
				t.Errorf("call %q does not read the message from stdin", l)
			}
			if strings.Contains(f, " -no_check_time ") {
				t.Errorf("call %q uses -no_check_time", l)
			}
			if strings.Contains(l, "alice@") || strings.Contains(l, "hello") {
				t.Errorf("call %q holds a byte of the message", l)
			}
			switch {
			case strings.Contains(f, " -noverify "):
				passA++
				if !strings.Contains(f, " -signer /dev/stdout ") || strings.Contains(f, " -CAfile ") {
					t.Errorf("pass A %q: want -signer /dev/stdout and no -CAfile", l)
				}
			case strings.Contains(f, " -CAfile "):
				if !strings.Contains(f, " -CAfile "+p.crlFile+" ") || !strings.Contains(f, " -purpose smimesign ") {
					t.Errorf("pass B %q: want -CAfile smime_ca_file and -purpose smimesign", l)
				}
				if strings.Contains(f, " -crl_check ") {
					passBCRL++
				} else {
					passB++
				}
			}
		}
		if passA != 1 || passB != 1 || passBCRL != 1 {
			t.Errorf("got pass A %d, pass B %d, pass B with -crl_check %d; want 1 each", passA, passB, passBCRL)
		}
	})

	t.Run("time limit gives unsupported", func(t *testing.T) {
		old := smimeTimeout
		smimeTimeout = 300 * time.Millisecond
		defer func() { smimeTimeout = old }()
		bin := fakeOpenssl(t, "OpenSSL 3.6.4", "exec sleep 10")
		// The version answer is cached before the limit is short.
		opensslOK.Store(bin, true)
		start := time.Now()
		s := Check(context.Background(), goodMsg, alice, Config{SMIMECAFile: p.caFile, OpensslPath: bin})
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("Check took %v; the limit did not stop openssl", d)
		}
		if s == nil || s.Verdict != VerdictUnsupported {
			t.Errorf("got %+v, want verdict unsupported", s)
		}
	})

	t.Run("over MaxInput gives unsupported", func(t *testing.T) {
		big := append(append([]byte{}, goodMsg...), bytes.Repeat([]byte("x"), MaxInput)...)
		s := Check(context.Background(), big, alice, chain)
		if s == nil || s.Type != TypeSMIME || s.Verdict != VerdictUnsupported {
			t.Errorf("got %+v, want verdict unsupported", s)
		}
	})

	t.Run("MIME depth over the limit gives unsupported", func(t *testing.T) {
		msg := goodMsg[bytes.Index(goodMsg, []byte("MIME-Version:")):]
		for i := 0; i <= MaxDepth; i++ {
			b := "D" + strings.Repeat("x", i)
			msg = []byte("Content-Type: multipart/mixed; boundary=\"" + b + "\"\r\n\r\n--" + b + "\r\n" +
				string(msg) + "\r\n--" + b + "--\r\n")
		}
		s := Check(context.Background(), append([]byte("From: "+alice+"\r\n"), msg...), alice, chain)
		if s == nil || s.Verdict != VerdictUnsupported {
			t.Errorf("got %+v, want verdict unsupported", s)
		}
	})
}

// TestVerify_OpensslStatus proves the F-D3 reason classification of
// R1E-judge.md finding 4: not_found with no binary reachable at all,
// relative_path for a configured relative openssl_path, not_openssl_3
// for a binary that answers "version" with a non-3.x line, and
// ok=true with no reason for a real OpenSSL 3.x binary. It never
// returns openssl output (I18).
//
// arch: D6.2, I18
func TestVerify_OpensslStatus(t *testing.T) {
	t.Run("no binary at all gives not_found", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir()) // no openssl reachable
		ok, reason := OpensslStatus(context.Background(), Config{})
		if ok || reason != "not_found" {
			t.Errorf("got (%v, %q), want (false, \"not_found\")", ok, reason)
		}
	})

	t.Run("relative openssl_path gives relative_path", func(t *testing.T) {
		ok, reason := OpensslStatus(context.Background(), Config{OpensslPath: "openssl"})
		if ok || reason != "relative_path" {
			t.Errorf("got (%v, %q), want (false, \"relative_path\")", ok, reason)
		}
	})

	t.Run("openssl that is not 3.x gives not_openssl_3", func(t *testing.T) {
		bin := fakeOpenssl(t, "OpenSSL 1.1.1w  11 Sep 2023", "exit 0")
		ok, reason := OpensslStatus(context.Background(), Config{OpensslPath: bin})
		if ok || reason != "not_openssl_3" {
			t.Errorf("got (%v, %q), want (false, \"not_openssl_3\")", ok, reason)
		}
	})

	t.Run("openssl 3.x gives ok with no reason", func(t *testing.T) {
		bin := fakeOpenssl(t, "OpenSSL 3.6.4  9 Sep 2025", "exit 0")
		ok, reason := OpensslStatus(context.Background(), Config{OpensslPath: bin})
		if !ok || reason != "" {
			t.Errorf("got (%v, %q), want (true, \"\")", ok, reason)
		}
	})

	// arch: D6.2. R1E-fix2-judge.md finding 4: a probe that ctx stops
	// gives false, and it stores nothing in opensslOK. Otherwise a good
	// binary would stay marked unusable after one early shutdown.
	t.Run("canceled probe gives false and stores nothing", func(t *testing.T) {
		bin := fakeOpenssl(t, "OpenSSL 3.6.4  9 Sep 2025", "exit 0")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ok, reason := OpensslStatus(ctx, Config{OpensslPath: bin})
		if ok || reason != "not_openssl_3" {
			t.Errorf("got (%v, %q), want (false, \"not_openssl_3\")", ok, reason)
		}
		if _, stored := opensslOK.Load(bin); stored {
			t.Errorf("opensslOK holds a result for %s after a canceled probe", bin)
		}
		ok, reason = OpensslStatus(context.Background(), Config{OpensslPath: bin})
		if !ok || reason != "" {
			t.Errorf("after cancel, got (%v, %q), want (true, \"\")", ok, reason)
		}
	})
}

// noCanary fails when the JSON of s holds certificate subject text.
func noCanary(t *testing.T, s *Signature) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(smimeCanary)) {
		t.Errorf("certificate text reached the result (I18): %s", b)
	}
}

// signedParts gives the boundary and the two parts of the
// multipart/signed message msg, with every line break as LF. The
// look-alike tests build new messages from these parts.
func signedParts(t *testing.T, msg []byte) (boundary string, content, sig []byte) {
	t.Helper()
	raw := bytes.ReplaceAll(msg, []byte("\r\n"), []byte("\n"))
	hdr, body := splitEntity(raw)
	_, params, err := mime.ParseMediaType(hdr.Get("Content-Type"))
	if err != nil || params["boundary"] == "" {
		t.Fatalf("no multipart/signed boundary: %v", err)
	}
	_, parts, _, ok := splitMultipart(body, params["boundary"])
	if !ok || len(parts) != 2 {
		t.Fatalf("split of the signed message: ok=%v, %d parts", ok, len(parts))
	}
	return params["boundary"], parts[0], parts[1]
}

// lookalikeHead is the header of a look-alike message with boundary b.
func lookalikeHead(from, b string) string {
	return "From: " + from + "\nMIME-Version: 1.0\nContent-Type: multipart/signed; " +
		"protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"" + b + "\"\n\n"
}

// TestSMIME_LookalikeBoundaryPreamble proves IRV.1 for the preamble
// case. The genuine signed part of alice sits between "--Bfoo" and
// "--B--z" lines. openssl reads these lines as boundaries, and Go
// reads them as preamble. The one real "--B" content part holds
// attacker text. The verdict must not carry the fingerprint of alice,
// because Go shows the attacker text as the signed body.
//
// arch: DRV.1, DRV.2
func TestSMIME_LookalikeBoundaryPreamble(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	b, content, sig := signedParts(t, p.sign(good, alice, "hello from alice"))
	msg := toCRLF([]byte(lookalikeHead(alice, b) +
		"--" + b + "foo\n" + string(content) + "\n" +
		"--" + b + "bar\n" + string(sig) + "\n" +
		"--" + b + "--z\n" +
		"--" + b + "\nContent-Type: text/plain\n\nATTACKER: the payment details changed, use IBAN XX00 9999.\n" +
		"--" + b + "\nContent-Type: application/pkcs7-signature\n\nAAAA\n" +
		"--" + b + "--\n"))

	ent, ok := SignedEntity(msg, TypeSMIME)
	if !ok || !bytes.Contains(ent, []byte("ATTACKER")) {
		t.Fatalf("precondition: SignedEntity ok=%v, want the attacker part; got %q", ok, ent)
	}
	s := Check(context.Background(), msg, alice, Config{SMIMECAFile: p.caFile})
	if s == nil {
		t.Fatal("Check gave no result for a signed message")
	}
	if s.Fingerprint == fp(good) || s.Verdict == VerdictVerified || s.Verdict == VerdictPartial || s.Verdict == VerdictValidUnknownSigner {
		t.Errorf("got %+v; the verdict carries the signature of alice over bytes that Go does not show", *s)
	}
	noCanary(t, s)
}

// TestSMIME_LookalikeBoundaryAppend proves IRV.1 for the append case.
// The close line of openssl is "--B--x", and the signature part holds
// an extra header line. Go reads the genuine part, the "--Bx" line and
// the signature part as one content part. The verdict must not be
// verified.
//
// arch: DRV.1, DRV.2
func TestSMIME_LookalikeBoundaryAppend(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	b, content, sig := signedParts(t, p.sign(good, alice, "hello from alice"))
	sig = bytes.Replace(sig, []byte("Content-Disposition"),
		[]byte("X-Note: URGENT - wire 10000 EUR to IBAN XX00 1234 today\nContent-Disposition"), 1)
	if !bytes.Contains(sig, []byte("X-Note:")) {
		t.Fatal("precondition: the signature part has no Content-Disposition line")
	}
	msg := toCRLF([]byte(lookalikeHead(alice, b) +
		"--" + b + "\n" + string(content) + "\n" +
		"--" + b + "x\n" + string(sig) + "\n" +
		"--" + b + "--x\n" +
		"--" + b + "\nContent-Type: application/pkcs7-signature\n\nAAAA\n" +
		"--" + b + "--\n"))

	ent, ok := SignedEntity(msg, TypeSMIME)
	if !ok || !bytes.Contains(ent, []byte("URGENT")) {
		t.Fatalf("precondition: SignedEntity ok=%v, want the appended text; got %q", ok, ent)
	}
	s := Check(context.Background(), msg, alice, Config{SMIMECAFile: p.caFile})
	if s == nil {
		t.Fatal("Check gave no result for a signed message")
	}
	if s.Verdict == VerdictVerified || s.Fingerprint == fp(good) {
		t.Errorf("got %+v; want no verified verdict and no fingerprint of alice", *s)
	}
	noCanary(t, s)
}

// TestSMIME_ReframedGenuineStillVerifies proves that a normal signed
// message gives the same verdict as before DRV.1, and that openssl
// reads the new frame: a fresh boundary of 32 hex characters, and not
// the original boundary. A wrapper keeps the stdin of each openssl
// call. An opaque signed-data message is re-framed too, by the DR1G.3
// path; TestSMIME_OpaqueSignedVerifies checks that frame.
//
// arch: DRV.1, DRV.2
func TestSMIME_ReframedGenuineStillVerifies(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	goodMsg := p.sign(good, alice, "hello from alice")
	sha1Msg := p.sign(good, alice, "hi", "-md", "sha1")
	fresh := regexp.MustCompile(`^[0-9a-f]{32}$`)

	cases := []struct {
		name    string
		raw     []byte
		cfg     Config
		trust   string // DRV.18: chain_valid_no_crl when smime_crl_check is off
		verdict string // DRV.18: a weak digest keeps the chain but gives partial
		weak    bool
		reframe bool
	}{
		{name: "detached, LF", raw: goodMsg, cfg: Config{SMIMECAFile: p.caFile},
			trust: TrustChainValidNoCRL, verdict: VerdictVerified, reframe: true},
		{name: "detached, CRLF wire form", raw: toCRLF(goodMsg), cfg: Config{SMIMECAFile: p.caFile},
			trust: TrustChainValidNoCRL, verdict: VerdictVerified, reframe: true},
		{name: "detached, CRL check on", raw: goodMsg, cfg: Config{SMIMECAFile: p.crlFile, SMIMECRLCheck: true},
			trust: TrustChainValid, verdict: VerdictVerified, reframe: true},
		{name: "detached, SHA-1 is weak gives verdict partial (DRV.18)", raw: sha1Msg, cfg: Config{SMIMECAFile: p.caFile},
			trust: TrustChainValidNoCRL, verdict: VerdictPartial, weak: true, reframe: true},
		{name: "opaque signed-data", raw: p.sign(good, alice, "opaque body", "-nodetach"), cfg: Config{SMIMECAFile: p.caFile},
			trust: TrustChainValidNoCRL, verdict: VerdictVerified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(t.TempDir(), "openssl")
			script := "#!/bin/sh\nif [ \"$1\" = version ]; then exec '" + p.openssl + "' \"$@\"; fi\n" +
				"f=$(mktemp '" + dir + "/in.XXXXXX')\ncat > \"$f\"\nexec '" + p.openssl + "' \"$@\" < \"$f\"\n"
			if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: the fixture must be executable or a directory, and it sits in the test temp dir
				t.Fatal(err)
			}
			cfg := tc.cfg
			cfg.OpensslPath = bin
			s := Check(context.Background(), tc.raw, alice, cfg)
			if s == nil || s.Type != TypeSMIME || s.Verdict != tc.verdict || s.Trust != tc.trust ||
				!s.SignerMatchesFrom || s.Fingerprint != fp(good) || s.Weak != tc.weak || s.Unsigned {
				t.Fatalf("got %+v, want verdict %s, trust %s, signer alice, weak=%v", s, tc.verdict, tc.trust, tc.weak)
			}
			noCanary(t, s)
			if !tc.reframe {
				return
			}
			orig, _, _ := signedParts(t, tc.raw)
			files, err := filepath.Glob(filepath.Join(dir, "in.*"))
			if err != nil {
				t.Fatal(err)
			}
			seen := 0
			for _, f := range files {
				in, err := os.ReadFile(f) //nolint:gosec // G304: test code; the path is built by the test
				if err != nil {
					t.Fatal(err)
				}
				if len(in) == 0 {
					continue // a probe call with no message
				}
				seen++
				if bytes.Contains(in, []byte(orig)) {
					t.Errorf("openssl read the original boundary %q; want a new frame", orig)
				}
				hdr, _ := splitEntity(in)
				mt, params, err := mime.ParseMediaType(hdr.Get("Content-Type"))
				if err != nil || mt != "multipart/signed" || !fresh.MatchString(params["boundary"]) ||
					params["micalg"] == "" || hdr.Get("MIME-Version") != "1.0" {
					t.Errorf("openssl input header %q: want multipart/signed, micalg, a 32 hex boundary", hdr)
				}
			}
			if seen < 3 {
				t.Errorf("recorded %d openssl calls with a message; want pass A, trust and the weak probe", seen)
			}
		})
	}
}

// TestSMIME_SystemStoreIgnored proves DRV.2. SSL_CERT_DIR points at a
// hashed directory that holds the CA of the signer, and smime_ca_file
// names an unrelated CA. The trust must not be chain_valid. An openssl
// that does not accept -no-CApath and -no-CAstore gives trust unknown,
// and OpensslStatus names the reason.
//
// arch: DRV.1, DRV.2
func TestSMIME_SystemStoreIgnored(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	goodMsg := p.sign(good, alice, "hello from alice")

	// The unrelated CA has its own subject. A CA file that holds a
	// certificate with the subject of the real issuer stops the
	// openssl issuer search before the default directory.
	unrelatedKey := newKey(t)
	unrelatedTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Unrelated Root " + smimeCanary},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	unrelatedDER, err := x509.CreateCertificate(rand.Reader, unrelatedTmpl, unrelatedTmpl, &unrelatedKey.PublicKey, unrelatedKey)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := p.write("unrelated.pem", pemOf("CERTIFICATE", unrelatedDER))

	t.Run("SSL_CERT_DIR is not a trust source", func(t *testing.T) {
		hashed := t.TempDir()
		if err := os.WriteFile(filepath.Join(hashed, "root.pem"), pemOf("CERTIFICATE", p.ca.Raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(p.openssl, "rehash", hashed).CombinedOutput(); err != nil { //nolint:gosec // G204: test code; the program and its arguments are built by the test
			t.Fatalf("openssl rehash: %v: %s", err, out)
		}
		t.Setenv("SSL_CERT_DIR", hashed)
		s := Check(context.Background(), goodMsg, alice, Config{SMIMECAFile: unrelated})
		if s == nil || s.Fingerprint != fp(good) {
			t.Fatalf("got %+v, want the signer of alice from pass A", s)
		}
		if s.Trust == TrustChainValid || s.Verdict == VerdictVerified {
			t.Errorf("got %+v; the default CA directory gave trust", *s)
		}
		noCanary(t, s)
	})

	t.Run("openssl without the flags gives trust unknown", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "openssl")
		script := "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in -no-CApath|-no-CAstore) " +
			"echo 'cms: Unknown option' >&2; exit 1;; esac; done\nexec '" + p.openssl + "' \"$@\"\n"
		if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: the fixture must be executable or a directory, and it sits in the test temp dir
			t.Fatal(err)
		}
		cfg := Config{SMIMECAFile: p.caFile, OpensslPath: bin}
		s := Check(context.Background(), goodMsg, alice, cfg)
		if s == nil || s.Fingerprint != fp(good) || s.Trust != TrustUnknown || s.Verdict != VerdictValidUnknownSigner {
			t.Errorf("got %+v, want trust unknown and verdict valid_unknown_signer", s)
		}
		if ok, reason := OpensslStatus(context.Background(), cfg); ok || reason != "no_store_flags" {
			t.Errorf("OpensslStatus got (%v, %q), want (false, \"no_store_flags\")", ok, reason)
		}
	})
}

// TestVerify_OpensslPreambleNotPartial proves ORV.8: text in the
// preamble or the epilogue of the S/MIME multipart/signed entity does
// not make the verdict partial. openssl and Thunderbird write a
// preamble line in each detached signature, so a normal message must
// give verified. After DRV.1 the preamble cannot reach the verified
// bytes, and it is not in the entity that read shows.
//
// arch: ORV.8
func TestVerify_OpensslPreambleNotPartial(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	goodMsg := p.sign(good, alice, "hello from alice")
	cfg := Config{SMIMECAFile: p.caFile}
	cases := []struct {
		name string
		raw  []byte
		text string
	}{
		{"openssl preamble", withPreamble(t, goodMsg), "This is an S/MIME"},
		{"preamble text", insertPreamble(t, goodMsg, "Signed and verified by IT."), "Signed and verified"},
		{"epilogue text", append(append([]byte{}, goodMsg...), []byte(attackText)...), "Pay invoice"},
		{"preamble and epilogue text, CRLF",
			toCRLF(append(insertPreamble(t, goodMsg, "Signed and verified by IT."), []byte(attackText)...)), "Signed and verified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Check(context.Background(), tc.raw, alice, cfg)
			if s == nil {
				t.Fatal("Check gave no result for a signed message")
			}
			if s.Type != TypeSMIME || s.Verdict != VerdictVerified || s.Unsigned ||
				s.Trust != TrustChainValidNoCRL || s.Fingerprint != fp(good) {
				t.Errorf("got %+v; want smime verified, unsigned=false, chain_valid_no_crl (DRV.18, smime_crl_check is off), fingerprint of alice", *s)
			}
			ent, ok := SignedEntity(tc.raw, TypeSMIME)
			if !ok || !bytes.Contains(ent, []byte("hello from alice")) || bytes.Contains(ent, []byte(tc.text)) {
				t.Errorf("SignedEntity ok=%v %q; want the signed part only, with no preamble or epilogue text", ok, ent)
			}
		})
	}
}

// TestSMIME_WalkUsesKindPredicate checks that the verifier walk names
// a pkcs7-mime entity signed only when mail.SMIMEKindOf names it
// SMIMESigned. An enveloped, an authenveloped, a certs-only and a
// pkcs7-mime entity with no smime-type are not signed entities, and
// the case of the key and the value does not change the result.
//
// arch: DR1G.2, DR1G.18, IR1G.2
func TestSMIME_WalkUsesKindPredicate(t *testing.T) {
	cases := []struct {
		ct     string
		signed bool
	}{
		{"application/pkcs7-mime; smime-type=signed-data; name=smime.p7m", true},
		{"application/x-pkcs7-mime; SMIME-Type=Signed-Data", true},
		{"Application/PKCS7-MIME; smime-type=\"SIGNED-DATA\"", true},
		{"application/pkcs7-mime; smime-type=enveloped-data", false},
		{"application/pkcs7-mime; smime-type=authenveloped-data", false},
		{"application/pkcs7-mime; smime-type=certs-only", false},
		{"application/pkcs7-mime; name=smime.p7m", false},
		{"text/plain; smime-type=signed-data", false},
	}
	for _, c := range cases {
		mt, params, err := mime.ParseMediaType(c.ct)
		if err != nil {
			t.Fatalf("ParseMediaType(%q): %v", c.ct, err)
		}
		want := mail.SMIMEKindOf(mt, params) == mail.SMIMESigned
		if want != c.signed {
			t.Fatalf("%q: the predicate gives signed=%v, the table says %v", c.ct, want, c.signed)
		}
		if got := isSMIMESigned(mt, params); got != want {
			t.Errorf("isSMIMESigned(%q) = %v, want %v (mail.SMIMEKindOf)", c.ct, got, want)
		}
		raw := []byte("From: a@example.org\r\nMIME-Version: 1.0\r\nContent-Type: " + c.ct +
			"\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAGCSqGSIb3DQEHAqCAMIACAQEx\r\n")
		var sc smimeScan
		if err := sc.walk(context.Background(), raw, 0); err != nil {
			t.Fatalf("walk(%q): %v", c.ct, err)
		}
		if got := sc.entity != nil; got != want {
			t.Errorf("walk(%q) found a signed entity = %v, want %v", c.ct, got, want)
		}
	}
}

// opaqueMessage gives a message from from whose body is the opaque
// CMS bytes cms, as application/pkcs7-mime with smime-type
// signed-data, in base64 lines of 76 characters.
func opaqueMessage(from string, cms []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(cms)
	var b bytes.Buffer
	b.WriteString("From: " + from + "\r\nTo: me@home.example\r\nSubject: hi\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/pkcs7-mime; smime-type=signed-data; name=smime.p7m\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n")
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}

// opensslCall is one openssl call that recordOpenssl kept.
type opensslCall struct {
	args  []string
	stdin []byte
}

// recordOpenssl writes a wrapper around the real openssl of p that
// keeps the arguments and the stdin of each call. calls gives the
// calls with a message on stdin, in order.
func recordOpenssl(t *testing.T, p *smimePKI) (bin string, calls func() []opensslCall) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(t.TempDir(), "openssl")
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then exec '" + p.openssl + "' \"$@\"; fi\n" +
		"f=$(mktemp '" + dir + "/in.XXXXXX')\ncat > \"$f\"\nprintf '%s\\n' \"$@\" > \"$f.args\"\n" +
		"exec '" + p.openssl + "' \"$@\" < \"$f\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: the fixture must be executable or a directory, and it sits in the test temp dir
		t.Fatal(err)
	}
	return bin, func() []opensslCall {
		t.Helper()
		files, err := filepath.Glob(filepath.Join(dir, "in.??????"))
		if err != nil {
			t.Fatal(err)
		}
		var out []opensslCall
		for _, f := range files {
			in, err := os.ReadFile(f) //nolint:gosec // G304: test code; the path is built by the test
			if err != nil {
				t.Fatal(err)
			}
			a, err := os.ReadFile(f + ".args") //nolint:gosec // G304: test code; the path is built by the test
			if err != nil {
				t.Fatal(err)
			}
			if len(in) == 0 {
				continue // a probe call with no message
			}
			out = append(out, opensslCall{args: strings.Split(strings.TrimSuffix(string(a), "\n"), "\n"), stdin: in})
		}
		return out
	}
}

// framedContent gives the first part of fr, a frame that reframe built
// with binary line ends, byte for byte: the bytes between the first
// boundary line and the LF before the next one.
func framedContent(t *testing.T, fr []byte) []byte {
	t.Helper()
	hdr, body := splitEntity(fr)
	mt, params, err := mime.ParseMediaType(hdr.Get("Content-Type"))
	if err != nil || mt != "multipart/signed" || params["boundary"] == "" {
		t.Fatalf("openssl input is not a multipart/signed frame: %q", hdr)
	}
	open := []byte("--" + params["boundary"] + "\n")
	if !bytes.HasPrefix(body, open) {
		t.Fatalf("frame body does not start with an LF boundary line: %q", body[:min(len(body), 60)])
	}
	rest := body[len(open):]
	end := bytes.Index(rest, []byte("\n"+string(open)))
	if end < 0 {
		t.Fatal("frame has no second LF boundary line")
	}
	return rest[:end]
}

// TestSMIME_OpaqueSignedVerifies proves the DR1G.3 verify path for an
// opaque signed-data message in DER and in BER (indefinite lengths, a
// constructed eContent). The verdict is the same as for a detached
// signature. openssl reads a new frame with an LF boundary, and every
// call that checks the signature has -binary. A SHA-1 signature keeps
// the weak flag, so the probe reads the new frame too.
//
// arch: DR1G.3, IR1G.4
func TestSMIME_OpaqueSignedVerifies(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	der := p.signOpaque(good, []byte(opaqueBody))
	fresh := regexp.MustCompile(`^[0-9a-f]{32}$`)

	cases := []struct {
		name    string
		cms     []byte
		cfg     Config
		trust   string
		verdict string
		weak    bool
	}{
		{name: "DER", cms: der, cfg: Config{SMIMECAFile: p.caFile},
			trust: TrustChainValidNoCRL, verdict: VerdictVerified},
		{name: "BER from openssl -stream", cms: p.signOpaque(good, []byte(opaqueBody), "-stream"), cfg: Config{SMIMECAFile: p.caFile},
			trust: TrustChainValidNoCRL, verdict: VerdictVerified},
		{name: "BER indefinite frames, constructed eContent", cms: berFrames(t, der, true), cfg: Config{SMIMECAFile: p.caFile},
			trust: TrustChainValidNoCRL, verdict: VerdictVerified},
		{name: "DER, CRL check on", cms: der, cfg: Config{SMIMECAFile: p.crlFile, SMIMECRLCheck: true},
			trust: TrustChainValid, verdict: VerdictVerified},
		{name: "SHA-1 is weak", cms: p.signOpaque(good, []byte(opaqueBody), "-md", "sha1"), cfg: Config{SMIMECAFile: p.caFile},
			trust: TrustChainValidNoCRL, verdict: VerdictPartial, weak: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, calls := recordOpenssl(t, p)
			cfg := tc.cfg
			cfg.OpensslPath = bin
			s := Check(context.Background(), opaqueMessage(alice, tc.cms), alice, cfg)
			if s == nil || s.Type != TypeSMIME || s.Verdict != tc.verdict || s.Trust != tc.trust ||
				!s.SignerMatchesFrom || s.Fingerprint != fp(good) || s.Weak != tc.weak || s.Unsigned {
				t.Fatalf("got %+v, want verdict %s, trust %s, signer alice, weak=%v", s, tc.verdict, tc.trust, tc.weak)
			}
			noCanary(t, s)
			seen, binary := 0, 0
			for _, c := range calls() {
				seen++
				hdr, _ := splitEntity(c.stdin)
				_, params, err := mime.ParseMediaType(hdr.Get("Content-Type"))
				if err != nil || !fresh.MatchString(params["boundary"]) {
					t.Errorf("openssl input header %q: want a frame with a 32 hex boundary", hdr)
				}
				if got := framedContent(t, c.stdin); string(got) != opaqueBody {
					t.Errorf("framed content = %q, want the signed bytes", got)
				}
				if contains(c.args, "-verify") {
					if !contains(c.args, "-binary") {
						t.Errorf("openssl %v: want -binary on the opaque path", c.args)
					}
					binary++
				}
			}
			want := 2 // pass A and pass B
			if tc.cfg.SMIMECRLCheck {
				want = 3
			}
			if seen < want+1 || binary != want {
				t.Errorf("recorded %d calls, %d with -verify; want %d -verify calls and the probe", seen, binary, want)
			}
		})
	}
}

// TestSMIME_OpaqueLFOnlyVerifies proves the line-end rule of DR1G.3
// (DR1G.16 item 3): content with LF line ends, signed as it is,
// verifies, in DER and in BER. A changed byte in the content gives
// invalid, so the check reads the content and does not skip it.
//
// arch: DR1G.3, IR1G.4
func TestSMIME_OpaqueLFOnlyVerifies(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	lf := []byte(strings.ReplaceAll(opaqueBody, "\r\n", "\n"))
	der := p.signOpaque(good, lf)
	cfg := Config{SMIMECAFile: p.caFile}
	for name, cms := range map[string][]byte{"der": der, "ber": berFrames(t, der, true)} {
		t.Run(name, func(t *testing.T) {
			s := Check(context.Background(), opaqueMessage(alice, cms), alice, cfg)
			if s == nil || s.Verdict != VerdictVerified || s.Trust != TrustChainValidNoCRL || s.Fingerprint != fp(good) {
				t.Fatalf("got %+v, want verified by alice", s)
			}
			ent, ok := SignedEntity(opaqueMessage(alice, cms), TypeSMIME)
			if !ok || !bytes.Equal(ent, lf) {
				t.Fatalf("SignedEntity = %q, %v; want the LF-only content", ent, ok)
			}
		})
	}
	changed := bytes.Replace(der, []byte("line two"), []byte("line TWO"), 1)
	if bytes.Equal(changed, der) {
		t.Fatal("precondition: the content is not in the DER bytes")
	}
	s := Check(context.Background(), opaqueMessage(alice, changed), alice, cfg)
	if s == nil || s.Verdict != VerdictInvalid {
		t.Fatalf("changed content: got %+v, want invalid", s)
	}
}

// TestSMIME_OpaqueNoToolOutput proves IR1G.5 on the opaque path. The
// certificate subject and the signed content each hold a canary. No
// canary reaches the result. Pass A still sends the content to the
// null device, and stderr of each call goes to the null device.
//
// arch: DR1G.3, IR1G.5, I18
func TestSMIME_OpaqueNoToolOutput(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	const contentCanary = "CANARY-T190-CONTENT"
	good := p.leaf("alice", leafOpts{email: alice})
	cms := p.signOpaque(good, []byte("Content-Type: text/plain\r\n\r\n"+contentCanary+"\r\n"))
	bin, calls := recordOpenssl(t, p)
	s := Check(context.Background(), opaqueMessage(alice, cms), alice, Config{SMIMECAFile: p.caFile, OpensslPath: bin})
	if s == nil || s.Verdict != VerdictVerified {
		t.Fatalf("got %+v, want verified", s)
	}
	noCanary(t, s)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(contentCanary)) {
		t.Errorf("signed content reached the result: %s", b)
	}
	passA := 0
	for _, c := range calls() {
		for _, a := range c.args {
			if strings.Contains(a, contentCanary) {
				t.Errorf("an openssl argument holds message bytes: %v", c.args)
			}
		}
		if !contains(c.args, "-signer") {
			continue
		}
		passA++
		i := len(c.args) - 1
		for i > 0 && c.args[i] != "-out" {
			i--
		}
		if c.args[i] != "-out" || c.args[i+1] != "/dev/null" {
			t.Errorf("pass A %v: want -out /dev/null", c.args)
		}
	}
	if passA != 1 {
		t.Errorf("recorded %d pass A calls, want 1", passA)
	}
}

// TestSMIME_OpaqueBadBERUnsupported proves DR1G.3 rule 2 and DR1G.16
// item 2: CMS bytes that the BER reader does not accept give verdict
// unsupported with no signer, never a wrong verdict, and no text.
// openssl reads none of them: the verdict comes from Go.
//
// arch: DR1G.3, D10.3
func TestSMIME_OpaqueBadBERUnsupported(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	der := p.signOpaque(good, []byte(opaqueBody))
	stream := p.signOpaque(good, []byte(opaqueBody), "-stream")

	indefPrim := frames(t, tparse(t, der))
	indefPrim.oct.indef = true
	deep := frames(t, tparse(t, der))
	n := &tnode{tag: 5}
	for i := 0; i < 28; i++ {
		n = &tnode{tag: tagSequence, cons: true, kids: []*tnode{n}}
	}
	deep.sd.kids[3].kids = append(deep.sd.kids[3].kids, n)
	noContent := frames(t, tparse(t, der))
	noContent.encap.kids = noContent.encap.kids[:1]

	cases := map[string][]byte{
		"truncated DER":     der[:len(der)-1],
		"BER no end marker": stream[:len(stream)-2],
		"trailing byte":     append(append([]byte{}, der...), 0),
		"indefinite OCTET":  indefPrim.ci.encode(),
		"depth over 32":     deep.ci.encode(),
		"not CMS":           []byte("hello, this is not CMS"),
		"empty CMS":         nil,
		"no eContent":       noContent.ci.encode(),
	}
	for name, cms := range cases {
		t.Run(name, func(t *testing.T) {
			raw := opaqueMessage(alice, cms)
			bin, calls := recordOpenssl(t, p)
			s := Check(context.Background(), raw, alice, Config{SMIMECAFile: p.caFile, OpensslPath: bin})
			if s == nil || s.Type != TypeSMIME || s.Verdict != VerdictUnsupported || s.Fingerprint != "" || s.Trust != "" {
				t.Fatalf("got %+v, want smime unsupported with no signer", s)
			}
			if c := calls(); len(c) != 0 {
				t.Errorf("openssl read %d messages; want none", len(c))
			}
			if ent, ok := SignedEntity(raw, TypeSMIME); ok || ent != nil {
				t.Errorf("SignedEntity = %q, %v; want no text", ent, ok)
			}
		})
	}
}

// padDigestSet gives msg with the digestAlgorithms SET of its detached
// signature rewritten to 15 SHA-256 entries and then the entries of
// the original SET. The SET is not under the signature, so the
// signature stays valid. The padding pushes the original entries past
// the first maxProbeOut bytes of the openssl structure print.
func padDigestSet(t *testing.T, msg []byte) []byte {
	t.Helper()
	sha256ID := algID(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	return rewriteDigestSet(t, msg, func(old []*tnode) []*tnode {
		var kids []*tnode
		for range 15 {
			kids = append(kids, tparse(t, sha256ID))
		}
		return append(kids, old...)
	})
}

// algID gives the DER of an AlgorithmIdentifier with the OID given and
// no parameters.
func algID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	der, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oid})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// rewriteDigestSet gives msg with the entries of the digestAlgorithms
// SET of its detached signature replaced by the result of edit.
func rewriteDigestSet(t *testing.T, msg []byte, edit func(old []*tnode) []*tnode) []byte {
	t.Helper()
	_, _, sig := signedParts(t, msg)
	_, b64 := splitEntity(sig)
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(b64)), ""))
	if err != nil {
		t.Fatalf("signature base64: %v", err)
	}
	ci := tparse(t, der)
	set := ci.kids[1].kids[0].kids[1] // ContentInfo [0] SignedData digestAlgorithms
	set.kids = edit(set.kids)
	enc := base64.StdEncoding.EncodeToString(ci.encode())
	var lines []string
	for len(enc) > 64 {
		lines, enc = append(lines, enc[:64]), enc[64:]
	}
	lines = append(lines, enc)
	old := strings.TrimRight(string(b64), "\n")
	if bytes.Count(msg, []byte(old)) != 1 {
		t.Fatal("the signature base64 is not once in the message")
	}
	return bytes.Replace(msg, []byte(old), []byte(strings.Join(lines, "\n")), 1)
}

// TestSMIME_PaddedDigestSetStillWeak proves that the weak probe fails
// closed when the 1 KiB cut of the openssl print ends inside the
// digestAlgorithms list. A SHA-1 signature with 15 SHA-256 entries
// before SHA-1 in the unsigned SET gives Weak:true and verdict partial,
// not verified (DRV.18). A SHA-256 signature padded the same way gives
// Weak:true too, because the probe cannot read the end of the list.
//
// arch: REVIEW-2026-10-12 H6, DRV.18
func TestSMIME_PaddedDigestSetStillWeak(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	cfg := Config{SMIMECAFile: p.caFile}

	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "SHA-1 after 15 SHA-256 entries", raw: padDigestSet(t, p.sign(good, alice, "hi", "-md", "sha1"))},
		{name: "SHA-256 list cut before its end", raw: padDigestSet(t, p.sign(good, alice, "hi"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Check(context.Background(), tc.raw, alice, cfg)
			if s == nil || s.Type != TypeSMIME || s.Verdict != VerdictPartial || s.Trust != TrustChainValidNoCRL ||
				!s.SignerMatchesFrom || s.Fingerprint != fp(good) || !s.Weak || s.Unsigned {
				t.Fatalf("got %+v, want verdict partial, trust %s, signer alice, weak=true", s, TrustChainValidNoCRL)
			}
			noCanary(t, s)
		})
	}
}

// TestSMIME_DigestAliasIsWeak proves that the weak probe uses an
// allow-list. openssl maps the signature algorithm OIDs sha1WithRSA
// (1.3.14.3.2.29) and sha1WithRSAEncryption to SHA-1. A SHA-1
// signature with such an OID in place of sha1 in the unsigned
// digestAlgorithms SET still verifies, so it must give Weak:true and
// verdict partial, not verified. A SET with only sha256 under a SHA-1
// signer gives verdict invalid, because openssl takes the signer
// digest from the SET. So a SET of strong names alone cannot hide a
// SHA-1 signer.
//
// arch: R16-H1, DRV.18
func TestSMIME_DigestAliasIsWeak(t *testing.T) {
	p := newSMIMEPKI(t)
	const alice = "alice@example.com"
	good := p.leaf("alice", leafOpts{email: alice})
	cfg := Config{SMIMECAFile: p.caFile}
	sha1Msg := p.sign(good, alice, "hi", "-md", "sha1")
	only := func(oid asn1.ObjectIdentifier) func([]*tnode) []*tnode {
		return func([]*tnode) []*tnode { return []*tnode{tparse(t, algID(t, oid))} }
	}

	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "sha1WithRSA in place of sha1", raw: rewriteDigestSet(t, sha1Msg, only(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}))},
		{name: "sha1WithRSAEncryption in place of sha1", raw: rewriteDigestSet(t, sha1Msg, only(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Check(context.Background(), tc.raw, alice, cfg)
			if s == nil || s.Type != TypeSMIME || s.Verdict == VerdictVerified || !s.Weak {
				t.Fatalf("got %+v, want weak=true and a verdict other than verified", s)
			}
			noCanary(t, s)
		})
	}

	t.Run("sha256 only under a SHA-1 signer fails", func(t *testing.T) {
		raw := rewriteDigestSet(t, sha1Msg, only(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}))
		s := Check(context.Background(), raw, alice, cfg)
		if s == nil || s.Type != TypeSMIME || s.Verdict != VerdictInvalid {
			t.Fatalf("got %+v, want verdict invalid", s)
		}
	})
}
