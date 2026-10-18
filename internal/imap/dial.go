// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// tlsPort is the implicit-TLS port. Any other port means STARTTLS
// (§3.10).
const tlsPort = "993"

// Credential is the login for one account. Token wins over Password:
// an OAuth account has no password.
//
// arch: T4.2, §3.10, §3.6, B14
type Credential struct {
	Username string
	Password string
	Token    string
}

// AuthError marks a login failure. A wrong password or a rejected
// token does not get better on a second try (§3.10). The pool itself
// does not read it. The account layer (tools.Factory) does: after an
// AuthError it refuses a new login for that alias with the same
// credential for 10 minutes, and a changed secret in the store ends
// the refusal at once (DRV.10, ORV.6).
//
// arch: T4.2, §3.10, DRV.10
type AuthError struct {
	Err error
}

func (e *AuthError) Error() string { return "imap: login failed: " + e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

// DialTimeout is the limit on the network part of one dial: TCP, TLS,
// the greeting and the login. DialAccount applies it. A credential
// read before the dial keeps its own limit and is not part of this
// one (DRV.10). It is a variable so a test can make it short.
var DialTimeout = dialTimeout

// DialAccount opens one IMAP connection for acct and logs in. The
// caller gives the credential, so a redial after an expired token
// reads a new token first (B14).
//
// TLS rules of §3.10: port 993 means TLS from the start, any other
// port means STARTTLS and fails when the server does not offer it.
// There is no option that turns verification off. acct.TLSCA adds one
// CA for this account only.
//
// The whole dial, from TCP to the end of the login, must end inside
// DialTimeout (DRV.10).
//
// arch: T4.2, §3.10, C26, C27, B14, B15, DRV.10
func DialAccount(ctx context.Context, acct config.Account, cred Credential, debug io.Writer) (*imapclient.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// cancel runs after stop below (defers run last in, first out), so
	// the end of this limit never closes a connection that the dial
	// gave back.
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	host, port, err := splitAddr(acct.IMAP)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := tlsConfig(host, acct.TLSCA)
	if err != nil {
		return nil, err
	}

	opts := &imapclient.Options{TLSConfig: tlsCfg}
	var dw *debugWriter
	if debug != nil {
		dw = newDebugWriter(debug)
		opts.DebugWriter = dw
	}

	// We open the socket ourselves instead of calling DialTLS or
	// DialStartTLS. go-imap gives a command no context, and it waits
	// its own 30 s for an answer, so a server that takes the
	// connection and then goes quiet holds the dial far past the
	// caller deadline. With the socket in hand, ctx closes it and
	// every step after it fails at once (C25).
	addr := net.JoinHostPort(host, port)
	raw, err := (&net.Dialer{Timeout: DialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("imap: dial %s: %w", addr, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop() // a pooled connection must outlive the dial context

	c, err := handshake(ctx, raw, port, tlsCfg, opts)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("imap: dial %s: %w", addr, err)
	}

	loginErr := login(c, cred)
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = c.Close()
		return nil, ctxErr // a deadline, not a wrong password
	}
	if loginErr != nil {
		_ = c.Close()
		return nil, loginErr
	}
	if dw != nil {
		dw.Open() // B15: the login is over, debug may show the traffic
	}
	return c, nil
}

// handshake puts TLS on the socket and gives the IMAP client. Port
// 993 means TLS from the start; any other port means STARTTLS, and
// the client fails when the server does not offer it (§3.10).
func handshake(ctx context.Context, raw net.Conn, port string, tlsCfg *tls.Config, opts *imapclient.Options) (*imapclient.Client, error) {
	if port != tlsPort {
		return imapclient.NewStartTLS(raw, opts)
	}
	cfg := tlsCfg.Clone()
	cfg.NextProtos = []string{"imap"}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return imapclient.New(conn, opts), nil
}

// login picks the mechanism the server offers. XOAUTH2 comes first
// when the account has a token. For a password account PLAIN comes
// first, then LOGIN, then the plain IMAP LOGIN command (§3.10, §3.6).
func login(c *imapclient.Client, cred Credential) error {
	caps := c.Caps()
	var err error
	switch {
	case cred.Token != "":
		err = c.Authenticate(NewXOAUTH2(cred.Username, cred.Token))
	case hasAuth(caps, sasl.Plain):
		err = c.Authenticate(sasl.NewPlainClient("", cred.Username, cred.Password))
	case hasAuth(caps, sasl.Login):
		err = c.Authenticate(NewLOGIN(cred.Username, cred.Password))
	default:
		err = c.Login(cred.Username, cred.Password).Wait()
	}
	if err != nil {
		return &AuthError{Err: err}
	}
	return nil
}

// hasAuth reports whether the server offers the SASL mechanism.
func hasAuth(caps imap.CapSet, mech string) bool {
	for _, m := range caps.AuthMechanisms() {
		if strings.EqualFold(m, mech) {
			return true
		}
	}
	return false
}

// splitAddr reads "host", "host:port" or "[v6]:port" and gives the
// host and the port. With no port it gives the implicit-TLS port.
func splitAddr(addr string) (host, port string, err error) {
	return splitHostPort(addr, tlsPort, "imap")
}

// splitHostPort reads "host", "host:port" or "[v6]:port" and gives
// the host and the port. With no port it gives defaultPort. label
// names the protocol ("imap" or "smtp") in the error text. This is
// the one split that splitAddr (imap) and splitSMTPAddr (smtp) both
// use (DRV.16c).
func splitHostPort(addr, defaultPort, label string) (host, port string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", fmt.Errorf("%s: the account has no %s server address", label, label)
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return strings.Trim(addr, "[]"), defaultPort, nil
	}
	if host == "" {
		return "", "", fmt.Errorf("%s: address %q has no host", label, addr)
	}
	return host, port, nil
}

// tlsConfig builds the TLS settings of §3.10. There is no switch that
// skips verification (C27). A caPath adds one CA on top of the system
// roots; it never replaces them, so a normal server still works.
func tlsConfig(host, caPath string) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if caPath == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caPath) //nolint:gosec // G304: caPath is the tls_ca value of the operator config
	if err != nil {
		return nil, fmt.Errorf("imap: read tls_ca: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("imap: tls_ca %s holds no certificate", caPath)
	}
	cfg.RootCAs = roots
	return cfg, nil
}
