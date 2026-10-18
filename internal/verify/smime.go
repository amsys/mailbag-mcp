// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

func init() { checkSMIME = smimeCheck }

// maxSignerOut is the most pass A output that smimeCheck reads. The
// signer certificates come from the attacker, so a larger output gives
// verdict unsupported (D6.2).
const maxSignerOut = 64 << 10

// maxProbeOut is the most output of the weak algorithm probe that
// smimeCheck reads. The digestAlgorithms lines are near the start.
const maxProbeOut = 1 << 10

// maxCAFile is the largest smime_ca_file that the revocation check
// parses in Go.
const maxCAFile = 16 << 20

// smimeTimeout is the limit for all openssl calls of one message
// (D6.2). It is a variable only so that a test can make it short.
var smimeTimeout = Timeout

// errTimeout is an openssl call that the time limit stopped.
var errTimeout = errors.New("verify: openssl time limit")

// The fixed openssl argument lists (D6.2). The message goes on stdin
// only. No argument holds a byte of the message, an address or a
// header.
var (
	argsPassA = []string{"cms", "-verify", "-in", "/dev/stdin", "-noverify", "-signer", "/dev/stdout", "-out", "/dev/null"}
	argsProbe = []string{"cms", "-cmsout", "-in", "/dev/stdin", "-noout", "-print"}
)

// argsStoreProbe checks that openssl accepts -no-CApath and
// -no-CAstore (DRV.2). stdin is empty, so a build that accepts the
// flags stops at the message read with exit code 2. A build that does
// not know a flag stops at the option parse with exit code 1.
var argsStoreProbe = []string{"cms", "-verify", "-in", "/dev/stdin", "-no-CApath", "-no-CAstore", "-out", "/dev/null"}

// argsPassB gives the pass B arguments. caFile comes from accounts.toml,
// which the human writes. -no_check_time is never used. -no-CApath and
// -no-CAstore stop openssl from loading the default CA directory, the
// default store and SSL_CERT_DIR, so smime_ca_file is the only trust
// source (DRV.2).
func argsPassB(caFile string, crlCheck bool) []string {
	a := []string{"cms", "-verify", "-in", "/dev/stdin", "-CAfile", caFile, "-no-CApath", "-no-CAstore", "-purpose", "smimesign", "-out", "/dev/null"}
	if crlCheck {
		a = append(a, "-crl_check")
	}
	return a
}

// withBinary gives args with -binary added when binary is true. A
// new slice is made, so the fixed lists do not change. openssl then
// reads the signed content as it is, with no line-end change (DR1G.3).
func withBinary(args []string, binary bool) []string {
	if !binary {
		return args
	}
	return append(append(make([]string, 0, len(args)+1), args...), "-binary")
}

// oidEmailAddress is the emailAddress attribute of a certificate
// subject (PKCS #9).
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// smimeCheck gives the S/MIME result of raw (D6.2 step 3). It finds a
// multipart/signed entity with a PKCS #7 signature, or an opaque
// application/pkcs7-mime entity with smime-type signed-data, and
// checks it with openssl cms in two passes.
//
// Pass A checks the signature over the content and gives the signer
// certificate. Pass B checks the chain to smime_ca_file. The verdict
// comes from exit codes and from the certificate parsed in Go. It
// never comes from openssl error text, and openssl output never goes
// into the result or the log (I18). The result holds only enum words,
// hex and booleans (I11).
//
// It gives nil when the message has no S/MIME signature. An enveloped
// (encrypted) message gives nil, because this check does not decrypt.
//
// For a multipart/signed entity, openssl does not read the entity as
// it is. It reads a new frame of the two parts that Go found (DRV.1),
// so openssl verifies the bytes that SignedEntity gives (IRV.1). A
// split that does not give two parts gives verdict unsupported.
//
// For an opaque signed-data entity, Go reads the CMS bytes with
// opaqueContent. openssl reads a new frame of the content and the
// detached signature, with -binary, so it verifies the bytes that
// SignedEntity gives (DR1G.3, IR1G.4). CMS bytes that opaqueContent
// does not accept give verdict unsupported (D10.3). Pass A still
// writes the content to the null device (IR1G.5).
//
// A revoked or expired signer gives verdict bad, ahead of every other
// condition. A weak digest algorithm gives partial. Trust chain_valid
// with no revocation check (smime_crl_check off) is chain_valid_no_crl,
// and still counts as a chain for verdict verified (DRV.18).
//
// arch: D6.1, D6.2, D10.3, I11, I12, I18, DRV.1, DRV.2, DRV.18, IRV.1, DR1G.3, IR1G.4, IR1G.5
func smimeCheck(ctx context.Context, raw []byte, from string, cfg Config) *Signature {
	if len(raw) > MaxInput {
		return unsupportedIfSMIME(raw)
	}
	var sc smimeScan
	if err := sc.walk(ctx, raw, 0); err != nil {
		return unsupportedIfSMIME(raw)
	}
	if sc.entity == nil {
		return nil
	}
	s := &Signature{Type: TypeSMIME, Verdict: VerdictUnsupported, Unsigned: sc.unsigned()}

	// in is the message that every openssl call reads. It is always a
	// new frame of two parts that Go found (DRV.1). For an opaque
	// entity, the parts are the content and the detached signature
	// from one opaqueContent call (DR1G.3, IR1G.4). That content is
	// signed as it is, with no line-end change, so openssl reads it
	// with -binary, on this path only.
	var in []byte
	var ok, binary bool
	if sc.multipart {
		in, ok = reframe(sc.parts, sc.micalg, false)
	} else {
		var content, detached []byte
		if content, detached, ok = opaqueEntity(sc.entity); ok {
			in, ok = reframe([][]byte{content, signaturePart(detached)}, "", true)
			binary = true
		}
	}
	if !ok {
		return s
	}

	bin, ok := opensslBinary(ctx, cfg.OpensslPath)
	if !ok {
		return s
	}
	// smimeTimeout bounds each openssl call on its own; it also caps
	// this derived context when ctx has no deadline of its own or a
	// longer one. A ctx that Check already canceled stops the exec at
	// once (F-D6), the same as smimeTimeout running out.
	ctx, cancel := context.WithTimeout(ctx, smimeTimeout)
	defer cancel()

	// Pass A: signature only, signer certificates to stdout.
	out, over, rc, err := runOpenssl(ctx, bin, withBinary(argsPassA, binary), in, maxSignerOut)
	switch {
	case err != nil || over:
		return s
	case rc == 4:
		s.Verdict = VerdictInvalid
		return s
	case rc != 0:
		return s
	}
	cert := firstCert(out)
	if cert == nil {
		return s
	}
	sum := sha256.Sum256(cert.Raw)
	s.Fingerprint = hex.EncodeToString(sum[:])
	s.SignerMatchesFrom = certMatches(cert, fromAddress(from))

	trust, err := smimeTrust(ctx, bin, in, binary, cert, cfg)
	if err != nil {
		return s
	}
	s.Trust = trust

	weak, err := smimeWeak(ctx, bin, in)
	if err != nil {
		return s
	}
	s.Weak = weak

	switch {
	case s.Trust == TrustRevoked || s.Trust == TrustExpired:
		// A revoked or expired signer is bad even when the signature
		// math is correct and From matches: "valid" must never show
		// on a signer that is no longer trusted (DRV.18).
		s.Verdict = VerdictBad
	case s.Unsigned:
		s.Verdict = VerdictPartial
	case s.Weak:
		// A weak digest algorithm never reaches verified (DRV.18).
		s.Verdict = VerdictPartial
	case s.SignerMatchesFrom && (s.Trust == TrustChainValid || s.Trust == TrustChainValidNoCRL || s.Trust == TrustPinned):
		s.Verdict = VerdictVerified
	default:
		s.Verdict = VerdictValidUnknownSigner
	}
	return s
}

// smimeTrust gives the Trust word for cert, the pass A signer.
//
// expired comes from NotAfter, read in Go. A missing smime_ca_file
// gives unknown. Pass B rc 0 gives chain_valid_no_crl when
// smime_crl_check is off, because the chain was not checked against a
// CRL (DRV.18); with smime_crl_check on and the CRL pass also rc 0, it
// gives chain_valid. With smime_crl_check, revoked needs the exit-code
// pair (pass B passes, pass B with -crl_check fails) and a CRL in
// smime_ca_file, from the issuer of cert, that lists the serial of
// cert. A CRL pass that fails for any other reason, for example no
// CRL in the file, gives unknown. An openssl that does not accept
// -no-CApath and -no-CAstore gives unknown, so trust fails closed
// (DRV.2). binary adds -binary to each pass B call, for the opaque
// path (DR1G.3).
func smimeTrust(ctx context.Context, bin string, entity []byte, binary bool, cert *x509.Certificate, cfg Config) (string, error) {
	if time.Now().After(cert.NotAfter) {
		return TrustExpired, nil
	}
	if cfg.SMIMECAFile == "" {
		return TrustUnknown, nil
	}
	if !opensslStoreFlags(ctx, bin) {
		if ctx.Err() != nil {
			return "", errTimeout
		}
		return TrustUnknown, nil
	}
	_, _, rc, err := runOpenssl(ctx, bin, withBinary(argsPassB(cfg.SMIMECAFile, false), binary), entity, 0)
	if err != nil {
		return "", err
	}
	if rc != 0 {
		return TrustUnknown, nil
	}
	if !cfg.SMIMECRLCheck {
		return TrustChainValidNoCRL, nil
	}
	_, _, rcCRL, err := runOpenssl(ctx, bin, withBinary(argsPassB(cfg.SMIMECAFile, true), binary), entity, 0)
	switch {
	case err != nil:
		return "", err
	case rcCRL == 0:
		return TrustChainValid, nil
	case crlLists(cfg.SMIMECAFile, cert):
		return TrustRevoked, nil
	}
	return TrustUnknown, nil
}

// crlLists is true when caFile holds a CRL from the issuer of cert
// that lists the serial of cert. Go reads the CRL only to tell a
// revoked certificate from a CRL check that failed for another
// reason. openssl has already checked the CRL signature in pass B.
func crlLists(caFile string, cert *x509.Certificate) bool {
	fi, err := os.Stat(caFile)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxCAFile {
		return false
	}
	data, err := os.ReadFile(caFile) //nolint:gosec // G304: the CA file path comes from the human's accounts.toml; the code reads only a regular file up to a size limit
	if err != nil {
		return false
	}
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return false
		}
		if blk.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(blk.Bytes)
		if err != nil || !bytes.Equal(crl.RawIssuer, cert.RawIssuer) {
			continue
		}
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber != nil && e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return true
			}
		}
	}
}

// strongDigests is the allow-list of the weak probe: the openssl print
// names of the digest algorithms that are not weak (DRV.18).
var strongDigests = map[string]bool{
	"sha224": true, "sha256": true, "sha384": true, "sha512": true,
	"sha3-224": true, "sha3-256": true, "sha3-384": true, "sha3-512": true,
}

// smimeWeak is true when the digestAlgorithms of the signed data hold
// a name that is not in strongDigests. A deny-list is not sufficient:
// openssl maps other OIDs, for example sha1WithRSA, to SHA-1
// (REVIEW-2026-10-16 H1). openssl takes the signer digest from this
// SET, so a SHA-1 signer always has an entry here. smimeWeak reads
// only the first maxProbeOut bytes of the structure print, then stops
// openssl. The SET is not under the signature, so a sender can pad it
// past the cut. smimeWeak is also true when the read output has no
// digestAlgorithms line, or when the list does not end with the next
// field, encapContentInfo:, before the cut (REVIEW-2026-10-12 H6,
// DRV.18).
func smimeWeak(ctx context.Context, bin string, entity []byte) (bool, error) {
	out, _, _, err := runOpenssl(ctx, bin, argsProbe, entity, maxProbeOut)
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(out), "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "digestAlgorithms:" {
			continue
		}
		for _, d := range lines[i+1:] {
			f := strings.Fields(d)
			if len(f) < 2 || (f[0] != "algorithm:" && f[0] != "parameter:") {
				return strings.TrimSpace(d) != "encapContentInfo:", nil
			}
			if f[0] == "algorithm:" && !strongDigests[f[1]] {
				return true, nil
			}
		}
		return true, nil
	}
	return true, nil
}

// firstCert gives the first certificate in the PEM output of pass A,
// or nil.
func firstCert(out []byte) *x509.Certificate {
	for {
		var blk *pem.Block
		blk, out = pem.Decode(out)
		if blk == nil {
			return nil
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil
		}
		return c
	}
}

// certMatches is true when cert names addr: an rfc822Name of the
// subject alternative name, or, when the certificate has none, the
// emailAddress attribute of the subject. The local part compares as
// bytes and the domain with no case.
func certMatches(cert *x509.Certificate, addr string) bool {
	names := cert.EmailAddresses
	if len(names) == 0 {
		for _, n := range cert.Subject.Names {
			if v, ok := n.Value.(string); ok && n.Type.Equal(oidEmailAddress) {
				names = append(names, v)
			}
		}
	}
	for _, n := range names {
		if sameAddress(n, addr) {
			return true
		}
	}
	return false
}

// sameAddress compares two addresses: the local part as bytes, the
// domain with no case.
func sameAddress(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	ia, ib := strings.LastIndexByte(a, '@'), strings.LastIndexByte(b, '@')
	if ia <= 0 || ib <= 0 {
		return false
	}
	return a[:ia] == b[:ib] && strings.EqualFold(a[ia+1:], b[ib+1:])
}

// opensslOK caches, for each binary path, whether it reports an
// OpenSSL 3.x version.
var opensslOK sync.Map

// opensslBinary gives the openssl binary to run and true, or false
// when there is none that this check can use: no binary on PATH, a
// relative openssl_path, or a version that is not OpenSSL 3.x. Each
// case gives verdict unsupported (D6.2, D10.3). No Go CMS module is a
// fallback.
//
// ctx bounds the version probe. When ctx ends before the probe does
// (a shutdown, or a canceled check), the result is false and nothing
// goes into opensslOK, so a later call probes again (R1E-fix2-judge.md
// finding 4).
func opensslBinary(ctx context.Context, configured string) (string, bool) {
	bin := configured
	if bin == "" {
		p, err := exec.LookPath("openssl")
		if err != nil {
			return "", false
		}
		bin = p
	}
	if !filepath.IsAbs(bin) {
		return "", false
	}
	if v, ok := opensslOK.Load(bin); ok {
		return bin, v.(bool)
	}
	probeCtx, cancel := context.WithTimeout(ctx, smimeTimeout)
	defer cancel()
	out, _, rc, err := runOpenssl(probeCtx, bin, []string{"version"}, nil, 256)
	ok := err == nil && rc == 0 && bytes.HasPrefix(out, []byte("OpenSSL 3."))
	if ctx.Err() != nil {
		return bin, false // canceled: this result says nothing about bin
	}
	opensslOK.Store(bin, ok)
	return bin, ok
}

// opensslStoreOK caches, for each binary path, whether it accepts
// -no-CApath and -no-CAstore.
var opensslStoreOK sync.Map

// opensslStoreFlags is true when bin accepts -no-CApath and
// -no-CAstore (DRV.2). Exit code 0 or 2 means that openssl parsed the
// options. Any other result, for example exit code 1 for an unknown
// option, gives false, so trust fails closed. A probe that ctx stops
// gives false and stores nothing, the same rule as opensslBinary.
func opensslStoreFlags(ctx context.Context, bin string) bool {
	if v, ok := opensslStoreOK.Load(bin); ok {
		return v.(bool)
	}
	probeCtx, cancel := context.WithTimeout(ctx, smimeTimeout)
	defer cancel()
	_, _, rc, err := runOpenssl(probeCtx, bin, argsStoreProbe, nil, 0)
	ok := err == nil && (rc == 0 || rc == 2)
	if ctx.Err() != nil {
		return false
	}
	opensslStoreOK.Store(bin, ok)
	return ok
}

// OpensslStatus gives whether the configured openssl is usable for
// S/MIME, and, when it is not, a fixed reason word for the one
// serve-time slog line (R1E-judge.md finding 4, fix F-D3):
// "not_found" (no binary on PATH and none configured), "relative_path"
// (openssl_path is set but not absolute), "not_openssl_3" (the
// binary ran but its version is not OpenSSL 3.x, or it did not run),
// or "no_store_flags" (the binary does not accept -no-CApath and
// -no-CAstore, so every S/MIME trust is unknown, DRV.2).
// It never returns openssl output (I18); the caller logs only the
// reason word.
//
// ctx stops the version probe. A canceled probe gives "not_openssl_3"
// and stores no result (R1E-fix2-judge.md finding 4).
func OpensslStatus(ctx context.Context, cfg Config) (ok bool, reason string) {
	bin := cfg.OpensslPath
	if bin == "" {
		if _, err := exec.LookPath("openssl"); err != nil {
			return false, "not_found"
		}
	} else if !filepath.IsAbs(bin) {
		return false, "relative_path"
	}
	bin, ok = opensslBinary(ctx, cfg.OpensslPath)
	if !ok {
		return false, "not_openssl_3"
	}
	if !opensslStoreFlags(ctx, bin) {
		return false, "no_store_flags"
	}
	return true, ""
}

// runOpenssl runs bin with args, with stdin on the standard input.
// stderr goes to the null device, so no openssl text is kept (I18).
//
// It reads at most limit bytes of stdout. over is true when the
// output was longer; openssl is then stopped. A limit of 0 sends
// stdout to the null device. rc is the exit code. err is errTimeout at the time limit, or
// the start error.
func runOpenssl(ctx context.Context, bin string, args []string, stdin []byte, limit int) (out []byte, over bool, rc int, err error) {
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: bin comes from exec.LookPath("openssl"), args are fixed lists plus the smime_ca_file path from accounts.toml, there is no shell, and mail data goes to stdin only
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stderr = nil
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	var pipe io.ReadCloser
	if limit > 0 {
		p, err := cmd.StdoutPipe()
		if err != nil {
			return nil, false, 0, err
		}
		pipe = p
	}
	if err := cmd.Start(); err != nil {
		return nil, false, 0, err
	}
	if pipe != nil {
		// The ctx kill stops only bin. A child of bin (for example a
		// wrapper script) can keep stdout open, and WaitDelay acts only
		// inside Wait, so ReadAll could block past ctx. Close the read
		// end when ctx ends, so the read stops at the time limit or at
		// a shutdown (R1E-fix2-judge.md finding 4).
		readDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = pipe.Close()
			case <-readDone:
			}
		}()
		out, _ = io.ReadAll(io.LimitReader(pipe, int64(limit)+1))
		close(readDone)
		if len(out) > limit {
			over = true
			out = out[:limit]
			_ = cmd.Process.Kill()
		}
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, false, 0, errTimeout
	}
	if over {
		return out, true, -1, nil
	}
	var ee *exec.ExitError
	switch {
	case waitErr == nil:
		return out, false, 0, nil
	case errors.As(waitErr, &ee):
		return out, false, ee.ExitCode(), nil
	}
	return nil, false, 0, waitErr
}

// smimeScan is the result of one walk of the MIME tree.
type smimeScan struct {
	// entity is the full first S/MIME signed entity, header and body.
	// For an opaque entity, opaqueEntity reads the content and the
	// detached signature from it (DR1G.3).
	entity []byte

	// multipart is true when entity is a multipart/signed. parts are
	// then its two parts from splitMultipart, and micalg is its micalg
	// parameter. reframe builds the openssl input from them (DRV.1).
	multipart bool
	parts     [][]byte
	micalg    string

	// outside counts the content parts that are not in entity and
	// that hold a byte that is not white space.
	outside int
}

// unsigned is true when content sits outside the signed entity: a
// part outside it (D6.2, I17). The preamble and the epilogue of the
// signed entity are not content (ORV.8): openssl reads only the
// re-framed parts (DRV.1), and read does not show them.
func (sc *smimeScan) unsigned() bool {
	return sc.outside > 0
}

// walk reads one MIME entity ent. It checks ctx.Err() first, the same
// stop rule as pgpScan.walk (F-D6).
func (sc *smimeScan) walk(ctx context.Context, ent []byte, depth int) error {
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

	if isSMIMESigned(mt, params) {
		if sc.entity != nil {
			// A second signed entity sits outside the first one.
			sc.outside++
			return nil
		}
		if mt == "multipart/signed" {
			b := params["boundary"]
			if b == "" {
				return errStructure
			}
			_, parts, _, ok := splitMultipart(body, b)
			if !ok || len(parts) != 2 {
				return errStructure
			}
			sc.multipart, sc.parts, sc.micalg = true, parts, params["micalg"]
		}
		sc.entity = ent
		return nil
	}

	if strings.HasPrefix(mt, "multipart/") {
		b := params["boundary"]
		if b == "" {
			return errStructure
		}
		_, parts, _, ok := splitMultipart(body, b)
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
	if len(bytes.TrimSpace(body)) > 0 {
		sc.outside++
	}
	return nil
}

// isSMIMESigned is true for a multipart/signed entity with a PKCS #7
// signature, or an entity that mail.SMIMEKindOf names SMIMESigned
// (application/pkcs7-mime with smime-type signed-data, RFC 8551). The
// one predicate decides the pkcs7-mime kind (DR1G.2, IR1G.2).
func isSMIMESigned(mt string, params map[string]string) bool {
	if mt == "multipart/signed" {
		p := strings.ToLower(params["protocol"])
		return p == "application/pkcs7-signature" || p == "application/x-pkcs7-signature"
	}
	return mail.SMIMEKindOf(mt, params) == mail.SMIMESigned
}

// unsupportedIfSMIME gives verdict unsupported when raw holds an
// S/MIME signature marker, and nil when it does not. The caller uses
// it when a D6.2 limit stops the check (D10.3).
//
// It is exempt from the one-predicate rule (DR1G.18.1). It is a byte
// scan that runs only when the walk failed, and it can only give
// unsupported, never a verdict, so it fails closed.
func unsupportedIfSMIME(raw []byte) *Signature {
	low := bytes.ToLower(raw)
	if bytes.Contains(low, []byte("pkcs7-signature")) || bytes.Contains(low, []byte("signed-data")) {
		return &Signature{Type: TypeSMIME, Verdict: VerdictUnsupported}
	}
	return nil
}

// reframe gives a new multipart/signed message that holds parts[0]
// and parts[1] byte for byte, between the lines of a fresh boundary
// (DRV.1). openssl then reads the two parts that Go found, and no
// line that only openssl reads as a boundary. The boundary is 32
// random hex characters that occur in neither part. ok is false when
// parts does not hold two parts.
//
// Line ends of the frame are CRLF. With binary, they are LF: openssl
// -binary keeps each byte of a part and removes only the LF before a
// boundary line, so a CR there would become a byte of the content
// (DR1G.3).
//
// arch: DRV.1, IRV.1, DR1G.3
func reframe(parts [][]byte, micalg string, binary bool) (msg []byte, ok bool) {
	if len(parts) != 2 {
		return nil, false
	}
	var fresh string
	for {
		var r [16]byte
		if _, err := rand.Read(r[:]); err != nil {
			return nil, false
		}
		fresh = hex.EncodeToString(r[:])
		if !bytes.Contains(parts[0], []byte(fresh)) && !bytes.Contains(parts[1], []byte(fresh)) {
			break
		}
	}
	params := map[string]string{"protocol": "application/pkcs7-signature", "boundary": fresh}
	if micalg != "" {
		params["micalg"] = micalg
	}
	ct := mime.FormatMediaType("multipart/signed", params)
	if ct == "" {
		return nil, false
	}
	nl := "\r\n"
	if binary {
		nl = "\n"
	}
	var b bytes.Buffer
	b.Grow(len(parts[0]) + len(parts[1]) + 256)
	b.WriteString("MIME-Version: 1.0" + nl + "Content-Type: " + ct + nl + nl)
	b.WriteString("--" + fresh + nl)
	b.Write(parts[0])
	b.WriteString(nl + "--" + fresh + nl)
	b.Write(parts[1])
	b.WriteString(nl + "--" + fresh + "--" + nl)
	return b.Bytes(), true
}

// opaqueEntity gives the content and the detached SignedData of ent,
// an opaque signed-data entity with its header. It decodes the
// transfer encoding of the body, then calls opaqueContent. smimeCheck
// and SignedEntity both call it, so the bytes openssl verifies and the
// bytes read shows come from the same extractor (DR1G.3, IR1G.4).
//
// arch: DR1G.3, IR1G.4
func opaqueEntity(ent []byte) (content, detached []byte, ok bool) {
	hdr, body := splitEntity(ent)
	return opaqueContent(decodeCTE(body, hdr.Get("Content-Transfer-Encoding")))
}

// signaturePart gives a MIME part that holds the detached SignedData
// det in base64, the second part of the frame for an opaque entity.
// Its lines end in LF, the frame form of the opaque path (DR1G.3).
func signaturePart(det []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(det)
	var b bytes.Buffer
	b.Grow(len(enc) + len(enc)/64 + 128)
	b.WriteString("Content-Type: application/pkcs7-signature; name=smime.p7s\n" +
		"Content-Transfer-Encoding: base64\n\n")
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n")
	return b.Bytes()
}
