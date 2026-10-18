// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// debugTestPassword is the password of the "carol" test user. No
// other text in this package holds it, so finding it in a debug
// stream means the writer leaked the login.
const debugTestPassword = "kfhs-pw-91x" //nolint:gosec // G101: a test value, not a real credential

// selfSigned makes a certificate for 127.0.0.1 and writes the PEM of
// it to a file. It gives the server TLS setting and the path of the
// PEM, which is what the tls_ca field of an account holds.
func selfSigned(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mailbag test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}, path
}

// TestTLS_CustomCA checks C27: a private server signed by a CA that
// the system does not know still works, through the tls_ca field, and
// the STARTTLS path of a port that is not 993 carries the login.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestTLS_CustomCA(t *testing.T) {
	// Arrange
	serverTLS, caPath := selfSigned(t)
	addr := memServerWith(t, serverTLS, false)
	acct := config.Account{Alias: "priv", IMAP: addr, TLSCA: caPath}

	// Act
	c, err := DialAccount(context.Background(), acct, Credential{Username: "bob", Password: "pw"}, nil)

	// Assert
	if err != nil {
		t.Fatalf("DialAccount with tls_ca: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Noop().Wait(); err != nil {
		t.Fatalf("NOOP after login: %v", err)
	}
}

// TestTLS_CustomCAMissingFails checks that the same server is refused
// with no tls_ca. That proves verification is really on: without it
// the previous test would pass for the wrong reason.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestTLS_CustomCAMissingFails(t *testing.T) {
	// Arrange
	serverTLS, _ := selfSigned(t)
	addr := memServerWith(t, serverTLS, false)
	acct := config.Account{Alias: "priv", IMAP: addr}

	// Act
	c, err := DialAccount(context.Background(), acct, Credential{Username: "bob", Password: "pw"}, nil)

	// Assert
	if err == nil {
		_ = c.Close()
		t.Fatal("the dial worked with an unknown CA, want a verification failure")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error = %v, want it to name the certificate", err)
	}
}

// TestTLS_NoInsecureOption checks C27 from the other side: no file in
// this package may offer a way to skip certificate verification. A
// setting like that is one config line away from a silent
// man-in-the-middle, so the package must not hold one at all.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestTLS_NoInsecureOption(t *testing.T) {
	// Arrange
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v, %d files", err, len(files))
	}

	// Act & Assert
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue // a test never ships
		}
		checked++
		body, err := os.ReadFile(name) //nolint:gosec // G304: the path comes from the test, not from a user
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if bytes.Contains(body, []byte("InsecureSkipVerify")) {
			t.Errorf("%s holds InsecureSkipVerify; §3.10 allows no such switch", name)
		}
		if bytes.Contains(body, []byte("DialInsecure")) {
			t.Errorf("%s dials without TLS; §3.10 allows TLS or STARTTLS only", name)
		}
	}
	if checked == 0 {
		t.Fatal("no package file was read, so this test proves nothing")
	}
}

// TestTLS_ConfigHasNoSkipAndPinsVersion checks the built setting, not
// only the source text.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestTLS_ConfigHasNoSkipAndPinsVersion(t *testing.T) {
	// Arrange
	_, caPath := selfSigned(t)

	// Act
	cfg, err := tlsConfig("mail.example.com", caPath)

	// Assert
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is on")
	}
	if cfg.ServerName != "mail.example.com" {
		t.Errorf("ServerName = %q, want the host", cfg.ServerName)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs is nil, want the CA from tls_ca")
	}
	if _, err := tlsConfig("h", filepath.Join(t.TempDir(), "gone.pem")); err == nil {
		t.Error("a missing tls_ca file gave no error")
	}
}

// TestDial_AddrRules checks the port rules of §3.10: 993 means TLS
// from the start, no port at all means 993.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestDial_AddrRules(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{in: "imap.example.com", wantHost: "imap.example.com", wantPort: "993"},
		{in: "imap.example.com:143", wantHost: "imap.example.com", wantPort: "143"},
		{in: "[2001:db8::1]:993", wantHost: "2001:db8::1", wantPort: "993"},
		{in: " imap.example.com ", wantHost: "imap.example.com", wantPort: "993"},
		{in: "", wantErr: true},
		{in: ":143", wantErr: true},
	}
	for _, c := range cases {
		host, port, err := splitAddr(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("splitAddr(%q) gave no error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitAddr(%q): %v", c.in, err)
			continue
		}
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("splitAddr(%q) = %q, %q; want %q, %q", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

// TestSplitHostPort checks the one shared host:port split that
// splitAddr (imap, default port 993) and splitSMTPAddr (smtp,
// default port 465) both call, so the two copies DRV.16c found stay
// one function.
//
// arch: DRV.16c
func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in          string
		defaultPort string
		wantHost    string
		wantPort    string
		wantErr     bool
	}{
		{in: "mail.example.com", defaultPort: "993", wantHost: "mail.example.com", wantPort: "993"},
		{in: "mail.example.com:143", defaultPort: "993", wantHost: "mail.example.com", wantPort: "143"},
		{in: "mail.example.com", defaultPort: "465", wantHost: "mail.example.com", wantPort: "465"},
		{in: "[2001:db8::1]:587", defaultPort: "465", wantHost: "2001:db8::1", wantPort: "587"},
		{in: " mail.example.com ", defaultPort: "993", wantHost: "mail.example.com", wantPort: "993"},
		{in: "", defaultPort: "993", wantErr: true},
		{in: ":143", defaultPort: "993", wantErr: true},
	}
	for _, c := range cases {
		host, port, err := splitHostPort(c.in, c.defaultPort, "imap")
		if c.wantErr {
			if err == nil {
				t.Errorf("splitHostPort(%q) gave no error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitHostPort(%q): %v", c.in, err)
			continue
		}
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("splitHostPort(%q) = %q, %q; want %q, %q", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

// TestDial_AuthErrorIsTyped checks that a wrong password gives an
// AuthError, which the pool must never retry.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestDial_AuthErrorIsTyped(t *testing.T) {
	// Arrange
	serverTLS, caPath := selfSigned(t)
	addr := memServerWith(t, serverTLS, false)
	acct := config.Account{Alias: "priv", IMAP: addr, TLSCA: caPath}

	// Act
	_, err := DialAccount(context.Background(), acct, Credential{Username: "bob", Password: "wrong"}, nil)

	// Assert
	var authErr *AuthError
	if err == nil {
		t.Fatal("a wrong password gave no error")
	}
	if !errors.As(err, &authErr) {
		t.Fatalf("error = %v (%T), want an *AuthError", err, err)
	}
	if !strings.Contains(authErr.Error(), "login failed") {
		t.Errorf("error text = %q, want it to say the login failed", authErr.Error())
	}
}

// TestDial_ContextAlreadyDone checks that a dead context stops the
// dial before any socket is opened.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestDial_ContextAlreadyDone(t *testing.T) {
	// Arrange
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	_, err := DialAccount(ctx, config.Account{IMAP: "127.0.0.1:1"}, Credential{}, nil)

	// Assert
	if err == nil {
		t.Fatal("the dial ran with a cancelled context")
	}
}

// TestDebugWriter_DropsAuth checks B15: the go-imap DebugWriter shows
// the login exchange, so our writer drops every byte until the login
// is over. It then checks the same rule on a real dial: the password
// must not reach the debug stream, while the traffic after the login
// must.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestDebugWriter_DropsAuth(t *testing.T) {
	// Arrange
	var buf bytes.Buffer
	d := newDebugWriter(&buf)

	// Act
	n, err := d.Write([]byte("a001 LOGIN bob hunter2\r\n"))

	// Assert
	if err != nil || n != len("a001 LOGIN bob hunter2\r\n") {
		t.Fatalf("Write = %d, %v; want the full length and no error", n, err)
	}
	if buf.Len() != 0 {
		t.Fatalf("the writer passed %q before the login was over", buf.String())
	}
	d.Open()
	if _, err := d.Write([]byte("a002 SELECT INBOX\r\n")); err != nil {
		t.Fatalf("Write after Open: %v", err)
	}
	if !strings.Contains(buf.String(), "SELECT INBOX") {
		t.Errorf("after Open the writer passed %q, want the command", buf.String())
	}

	// Arrange: the same rule on a real connection.
	serverTLS, caPath := selfSigned(t)
	addr := memServerWith(t, serverTLS, false)
	acct := config.Account{Alias: "priv", IMAP: addr, TLSCA: caPath}
	wire := &syncBuf{}

	// Act
	c, err := DialAccount(context.Background(), acct, Credential{Username: "carol", Password: debugTestPassword}, wire)
	if err != nil {
		t.Fatalf("DialAccount: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Noop().Wait(); err != nil {
		t.Fatalf("NOOP: %v", err)
	}

	// Assert
	got := wire.String()
	if strings.Contains(got, debugTestPassword) {
		t.Errorf("the debug stream holds the password: %q", got)
	}
	if strings.Contains(strings.ToUpper(got), "LOGIN ") || strings.Contains(strings.ToUpper(got), "AUTHENTICATE ") {
		t.Errorf("the debug stream holds the login command: %q", got)
	}
	if !strings.Contains(strings.ToUpper(got), "NOOP") {
		t.Errorf("the debug stream holds no traffic after the login: %q", got)
	}
}

// TestDial_LoginDeadlineStopsAQuietServer checks that a server that
// takes the connection and then answers nothing does not hold the
// dial for ever. The dialer timeout covers the connect only, so the
// login needs the context as well.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestDial_LoginDeadlineStopsAQuietServer(t *testing.T) {
	// Arrange: a listener that accepts and then says nothing at all.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	acct := config.Account{Alias: "quiet", IMAP: ln.Addr().String()}

	// Act
	done := make(chan error, 1)
	go func() {
		_, err := DialAccount(ctx, acct, Credential{Username: "bob", Password: "pw"}, nil)
		done <- err
	}()

	// Assert
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the dial worked against a server that never answered")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dial is still waiting; the context did not stop it")
	}
}

// TestTLS_ImplicitOn993 checks the other half of the §3.10 port rule:
// port 993 means TLS from the first byte, with no STARTTLS command.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestTLS_ImplicitOn993(t *testing.T) {
	// Arrange
	serverTLS, caPath := selfSigned(t)
	addr := memServerWith(t, serverTLS, true)
	cfg, err := tlsConfig("127.0.0.1", caPath)
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Act
	c, err := handshake(context.Background(), raw, tlsPort, cfg, &imapclient.Options{TLSConfig: cfg})

	// Assert
	if err != nil {
		t.Fatalf("handshake on port 993: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := login(c, Credential{Username: "bob", Password: "pw"}); err != nil {
		t.Fatalf("login over implicit TLS: %v", err)
	}
}

// TestDial_LimitStopsAQuietServer checks that DialAccount applies
// DialTimeout itself, now that the pool puts no limit around the dial.
// The caller context has no deadline here, so only DialTimeout can
// stop the dial.
// arch: DRV.10
func TestDial_LimitStopsAQuietServer(t *testing.T) {
	// Arrange: a listener that accepts and then says nothing at all.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
		}
	}()
	saved := DialTimeout
	DialTimeout = 200 * time.Millisecond
	t.Cleanup(func() { DialTimeout = saved })
	acct := config.Account{Alias: "quiet", IMAP: ln.Addr().String()}

	// Act
	done := make(chan error, 1)
	go func() {
		_, err := DialAccount(context.Background(), acct, Credential{Username: "bob", Password: "pw"}, nil)
		done <- err
	}()

	// Assert
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the dial worked against a server that never answered")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dial is still waiting; DialTimeout did not stop it")
	}
}
