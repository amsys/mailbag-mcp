// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// smtpTestPassword is the password of the SMTP test user. No other
// text in this package holds it, so finding it anywhere else means a
// leak.
const smtpTestPassword = "smtp-pw-73q" //nolint:gosec // G101: a test value, not a real credential

// smtpOpts configures one run of the in-process SMTP server. go-smtp
// ships no memory server, so this file builds a Backend and a Session
// of its own and serves them on 127.0.0.1 with a free port, the same
// way go-smtp's own server_test.go does.
//
// arch: T5.1, §3.11, M1, M2, M3, M11, §10.7
type smtpOpts struct {
	// mechs are the SASL mechanisms the server advertises. A nil
	// value means PLAIN and LOGIN.
	mechs []string

	// noSTARTTLS leaves Server.TLSConfig empty, so the server
	// advertises no STARTTLS.
	noSTARTTLS bool

	// implicitTLS wraps the listener in TLS, like port 465.
	implicitTLS bool

	// maxBytes is the SIZE limit. 0 advertises SIZE with no number,
	// which means no limit.
	maxBytes int64

	// mailErr and dataErr are the errors the session gives back for
	// MAIL FROM and for DATA.
	mailErr, dataErr error

	// authErr is the error the session gives back for a password
	// login attempt, in place of accepting it.
	authErr error

	// refuseTokens are the XOAUTH2 tokens the server refuses. It
	// answers the way Outlook does: a 334 challenge first, then
	// 535 5.7.8 after the empty client response.
	refuseTokens []string
}

// smtpFixture holds the running server and the client TLS settings
// that reach it.
type smtpFixture struct {
	addr   string
	be     *smtpBackend
	client *tls.Config
}

// newSMTPFixture starts one server and gives the fixture. The server
// stops when the test ends.
func newSMTPFixture(t *testing.T, opts smtpOpts) *smtpFixture {
	t.Helper()
	if opts.mechs == nil {
		opts.mechs = []string{sasl.Plain, sasl.Login}
	}
	serverTLS, caPath := selfSigned(t)
	clientTLS, err := tlsConfig("127.0.0.1", caPath)
	if err != nil {
		t.Fatalf("client tls: %v", err)
	}

	be := &smtpBackend{opts: opts}
	srv := smtp.NewServer(be)
	srv.Domain = "127.0.0.1"
	srv.MaxMessageBytes = opts.maxBytes
	srv.ErrorLog = smtpDiscardLogger{}
	if !opts.noSTARTTLS {
		srv.TLSConfig = serverTLS
	}
	// A plain listener with no STARTTLS must still advertise AUTH, or
	// the STARTTLS test would pass for the wrong reason.
	srv.AllowInsecureAuth = opts.noSTARTTLS

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if opts.implicitTLS {
		ln = tls.NewListener(ln, serverTLS)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return &smtpFixture{addr: ln.Addr().String(), be: be, client: clientTLS}
}

// send runs one send against the fixture.
func (f *smtpFixture) send(t *testing.T, implicitTLS bool, cred Credential, p SendParams) error {
	t.Helper()
	return smtpSend(context.Background(), f.addr, implicitTLS, f.client, cred, p)
}

// smtpDiscardLogger drops the SMTP server log. A refused command is the point
// of several cases here, and its stack trace only hides the failure.
type smtpDiscardLogger struct{}

func (smtpDiscardLogger) Printf(string, ...interface{}) {}
func (smtpDiscardLogger) Println(...interface{})        {}

// smtpBackend records every command the client sent.
type smtpBackend struct {
	mu        sync.Mutex
	opts      smtpOpts
	mails     []string
	rcpts     []string
	data      [][]byte
	dataCalls int
	authMechs []string
	authUser  string
	authPass  string
	authToken string
}

func (b *smtpBackend) NewSession(*smtp.Conn) (smtp.Session, error) {
	return &smtpSession{be: b}, nil
}

func (b *smtpBackend) snapshot() smtpBackend {
	b.mu.Lock()
	defer b.mu.Unlock()
	return smtpBackend{
		mails:     append([]string(nil), b.mails...),
		rcpts:     append([]string(nil), b.rcpts...),
		data:      append([][]byte(nil), b.data...),
		dataCalls: b.dataCalls,
		authMechs: append([]string(nil), b.authMechs...),
		authUser:  b.authUser,
		authPass:  b.authPass,
		authToken: b.authToken,
	}
}

// smtpSession answers one connection. It is both a Session and an
// AuthSession, so the test picks the advertised mechanisms.
type smtpSession struct{ be *smtpBackend }

func (s *smtpSession) Reset()        {}
func (s *smtpSession) Logout() error { return nil }

func (s *smtpSession) AuthMechanisms() []string { return s.be.opts.mechs }

func (s *smtpSession) Auth(mech string) (sasl.Server, error) {
	s.be.mu.Lock()
	s.be.authMechs = append(s.be.authMechs, mech)
	s.be.mu.Unlock()
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(_, username, password string) error {
			if err := s.be.opts.authErr; err != nil {
				return err
			}
			s.be.mu.Lock()
			s.be.authUser, s.be.authPass = username, password
			s.be.mu.Unlock()
			return nil
		}), nil
	case sasl.Login:
		return &smtpLoginServer{be: s.be}, nil
	case XOAUTH2:
		return &smtpXOAUTH2Server{be: s.be}, nil
	}
	return nil, smtp.ErrAuthUnknownMechanism
}

func (s *smtpSession) Mail(from string, _ *smtp.MailOptions) error {
	if err := s.be.opts.mailErr; err != nil {
		return err
	}
	s.be.mu.Lock()
	s.be.mails = append(s.be.mails, from)
	s.be.mu.Unlock()
	return nil
}

func (s *smtpSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.be.mu.Lock()
	s.be.rcpts = append(s.be.rcpts, to)
	s.be.mu.Unlock()
	return nil
}

func (s *smtpSession) Data(r io.Reader) error {
	// go-smtp asks the backend to read r before Data returns, even
	// when the backend refuses the message.
	body, readErr := io.ReadAll(r)
	s.be.mu.Lock()
	s.be.dataCalls++
	if readErr == nil {
		s.be.data = append(s.be.data, body)
	}
	s.be.mu.Unlock()
	if err := s.be.opts.dataErr; err != nil {
		return err
	}
	return readErr
}

// smtpLoginServer is the LOGIN half of the server. go-sasl has a
// LOGIN client but no LOGIN server, so the test brings one.
type smtpLoginServer struct {
	be   *smtpBackend
	step int
	user string
}

func (s *smtpLoginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.step {
	case 0:
		s.user = string(response)
		s.step++
		return []byte("Password:"), false, nil
	case 1:
		s.step++
		s.be.mu.Lock()
		s.be.authUser, s.be.authPass = s.user, string(response)
		s.be.mu.Unlock()
		return nil, true, nil
	}
	return nil, false, errors.New("login: unexpected client response")
}

// smtpXOAUTH2Server accepts the XOAUTH2 initial response and records
// the token. A token in opts.refuseTokens gets a 334 challenge and
// then a 535 5.7.8 reply.
type smtpXOAUTH2Server struct {
	be      *smtpBackend
	refused bool
}

func (s *smtpXOAUTH2Server) Next(response []byte) (challenge []byte, done bool, err error) {
	if s.refused {
		return nil, false, &smtp.SMTPError{
			Code:         535,
			EnhancedCode: smtp.EnhancedCode{5, 7, 8},
			Message:      "Authentication unsuccessful",
		}
	}
	text := string(response)
	const mark = "auth=Bearer "
	i := strings.Index(text, mark)
	if i < 0 {
		return nil, false, errors.New("xoauth2: no bearer token")
	}
	token := text[i+len(mark):]
	token = strings.TrimRight(token, "\x01")
	for _, bad := range s.be.opts.refuseTokens {
		if token == bad {
			s.refused = true
			return []byte(`{"status":"401","schemes":"bearer"}`), false, nil
		}
	}
	s.be.mu.Lock()
	s.be.authToken = token
	s.be.mu.Unlock()
	return nil, true, nil
}

// smtpTestMessage is a small RFC 822 message with CRLF line ends.
var smtpTestMessage = []byte("From: alice@example.com\r\n" +
	"To: bob@example.com\r\n" +
	"Subject: hello\r\n" +
	"\r\n" +
	"body\r\n")

// smtpTestParams gives the standard envelope for a case.
func smtpTestParams() SendParams {
	return SendParams{
		From: "alice@example.com",
		To:   []string{"bob@example.com"},
		Raw:  smtpTestMessage,
	}
}

// TestSMTP_RequiresSTARTTLS checks M1: port 465 carries TLS from the
// first byte, every other port needs STARTTLS, and a server with no
// STARTTLS gets no login and no message.
// arch: T5.1, §3.11, M1, M2, M3, M11, §10.7
func TestSMTP_RequiresSTARTTLS(t *testing.T) {
	t.Parallel()

	t.Run("the port picks the transport", func(t *testing.T) {
		// Arrange
		cases := []struct {
			addr     string
			wantPort string
			wantTLS  bool
		}{
			{"mail.example.com:465", "465", true},
			{"mail.example.com:587", "587", false},
			{"mail.example.com:25", "25", false},
			{"mail.example.com", "465", true},
			{"[::1]:587", "587", false},
		}

		for _, c := range cases {
			// Act
			_, port, err := splitSMTPAddr(c.addr)

			// Assert
			if err != nil {
				t.Fatalf("splitSMTPAddr(%q): %v", c.addr, err)
			}
			if port != c.wantPort {
				t.Errorf("%q: port = %q, want %q", c.addr, port, c.wantPort)
			}
			if got := smtpImplicitTLS(port); got != c.wantTLS {
				t.Errorf("%q: implicit TLS = %v, want %v", c.addr, got, c.wantTLS)
			}
		}
	})

	t.Run("no STARTTLS means no login and no message", func(t *testing.T) {
		// Arrange
		f := newSMTPFixture(t, smtpOpts{noSTARTTLS: true})
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

		// Act
		err := f.send(t, false, cred, smtpTestParams())

		// Assert
		if err == nil {
			t.Fatal("send: want an error, got nil")
		}
		if !strings.Contains(err.Error(), "STARTTLS") {
			t.Errorf("error = %v, want it to name STARTTLS", err)
		}
		got := f.be.snapshot()
		if len(got.authMechs) != 0 {
			t.Errorf("the client authenticated with %v over clear text", got.authMechs)
		}
		if len(got.mails) != 0 {
			t.Errorf("mails = %v, want none", got.mails)
		}
	})

	t.Run("STARTTLS carries the message", func(t *testing.T) {
		// Arrange
		f := newSMTPFixture(t, smtpOpts{})
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

		// Act
		err := f.send(t, false, cred, smtpTestParams())

		// Assert
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		got := f.be.snapshot()
		if len(got.mails) != 1 || got.mails[0] != "alice@example.com" {
			t.Errorf("mails = %v, want [alice@example.com]", got.mails)
		}
		if len(got.rcpts) != 1 || got.rcpts[0] != "bob@example.com" {
			t.Errorf("rcpts = %v, want [bob@example.com]", got.rcpts)
		}
		if len(got.data) != 1 || !strings.Contains(string(got.data[0]), "Subject: hello") {
			t.Errorf("data = %q, want the test message", got.data)
		}
	})

	t.Run("port 465 carries the message over implicit TLS", func(t *testing.T) {
		// Arrange
		f := newSMTPFixture(t, smtpOpts{implicitTLS: true})
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

		// Act
		err := f.send(t, true, cred, smtpTestParams())

		// Assert
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		got := f.be.snapshot()
		if len(got.data) != 1 {
			t.Fatalf("data = %d messages, want 1", len(got.data))
		}
		if got.authPass != smtpTestPassword {
			t.Errorf("the server got password %q, want the test password", got.authPass)
		}
	})

	t.Run("the debug stream shows no password", func(t *testing.T) {
		// Arrange
		f := newSMTPFixture(t, smtpOpts{})
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}
		var debug bytes.Buffer
		p := smtpTestParams()
		p.Debug = &debug

		// Act
		err := f.send(t, false, cred, p)

		// Assert
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		text := debug.String()
		if strings.Contains(text, smtpTestPassword) {
			t.Error("the debug stream holds the password")
		}
		if strings.Contains(text, base64.StdEncoding.EncodeToString([]byte(smtpTestPassword))) {
			t.Error("the debug stream holds the password in base64")
		}
		if !strings.Contains(text, "MAIL FROM") {
			t.Errorf("the debug stream shows no traffic after the login: %q", text)
		}
	})

	t.Run("a clear-text server on the implicit-TLS path fails", func(t *testing.T) {
		// Arrange: the server speaks no TLS, the client expects TLS
		// from the first byte.
		f := newSMTPFixture(t, smtpOpts{noSTARTTLS: true})
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

		// Act
		err := f.send(t, true, cred, smtpTestParams())

		// Assert
		if err == nil {
			t.Fatal("send: want a TLS handshake error, got nil")
		}
		if len(f.be.snapshot().mails) != 0 {
			t.Error("the client sent MAIL FROM over clear text")
		}
	})
}

// TestSMTP_AuthFallback checks M2: PLAIN first, LOGIN when the server
// offers no PLAIN, XOAUTH2 for a token account, and a clear error
// when the server offers neither password mechanism.
// arch: T5.1, §3.11, M1, M2, M3, M11, §10.7
func TestSMTP_AuthFallback(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		mechs    []string
		cred     Credential
		wantMech string
		wantErr  string
	}{
		{
			name:     "PLAIN and LOGIN together pick PLAIN",
			mechs:    []string{sasl.Plain, sasl.Login},
			cred:     Credential{Username: "alice@example.com", Password: smtpTestPassword},
			wantMech: sasl.Plain,
		},
		{
			name:     "LOGIN only picks LOGIN",
			mechs:    []string{sasl.Login},
			cred:     Credential{Username: "alice@example.com", Password: smtpTestPassword},
			wantMech: sasl.Login,
		},
		{
			name:     "PLAIN only picks PLAIN",
			mechs:    []string{sasl.Plain},
			cred:     Credential{Username: "alice@example.com", Password: smtpTestPassword},
			wantMech: sasl.Plain,
		},
		{
			name:     "a token account picks XOAUTH2",
			mechs:    []string{XOAUTH2, sasl.Plain},
			cred:     Credential{Username: "alice@example.com", Token: "tok123"},
			wantMech: XOAUTH2,
		},
		{
			name:    "no password mechanism is an error, not clear text",
			mechs:   []string{"CRAM-MD5"},
			cred:    Credential{Username: "alice@example.com", Password: smtpTestPassword},
			wantErr: "neither PLAIN nor LOGIN",
		},
		{
			name:    "a token account needs XOAUTH2",
			mechs:   []string{sasl.Plain},
			cred:    Credential{Username: "alice@example.com", Token: "tok123"},
			wantErr: "does not offer XOAUTH2",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Arrange
			f := newSMTPFixture(t, smtpOpts{mechs: c.mechs})

			// Act
			err := f.send(t, false, c.cred, smtpTestParams())

			// Assert
			got := f.be.snapshot()
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("send: want an error naming %q, got nil", c.wantErr)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("error = %v, want it to name %q", err, c.wantErr)
				}
				if len(got.mails) != 0 {
					t.Errorf("mails = %v, want none after a login failure", got.mails)
				}
				return
			}
			if err != nil {
				t.Fatalf("send: %v", err)
			}
			if len(got.authMechs) != 1 || got.authMechs[0] != c.wantMech {
				t.Fatalf("mechanisms = %v, want [%s]", got.authMechs, c.wantMech)
			}
			switch c.wantMech {
			case XOAUTH2:
				if got.authToken != c.cred.Token {
					t.Errorf("token = %q, want %q", got.authToken, c.cred.Token)
				}
			default:
				if got.authUser != c.cred.Username || got.authPass != c.cred.Password {
					t.Errorf("login = %q/%q, want %q/<the test password>",
						got.authUser, got.authPass, c.cred.Username)
				}
			}
			if len(got.data) != 1 {
				t.Errorf("data = %d messages, want 1", len(got.data))
			}
		})
	}
}

// TestSMTP_Error57139Text checks T6.4: a 535 5.7.139 login failure
// maps to a text naming the tenant SMTP AUTH setting and the
// administrator consent, not a raw SMTP code (B13, DS6.5, DS6.6,
// §3.11).
// arch: T6.4, DS6.5, DS6.6, §3.11, B13
func TestSMTP_Error57139Text(t *testing.T) {
	t.Parallel()

	f := newSMTPFixture(t, smtpOpts{authErr: &smtp.SMTPError{
		Code:         535,
		EnhancedCode: smtp.EnhancedCode{5, 7, 139},
		Message:      "5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for this tenant.",
	}})
	cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

	err := f.send(t, false, cred, smtpTestParams())

	if err == nil {
		t.Fatal("send: want an error, got nil")
	}
	if strings.Contains(err.Error(), "5.7.139") || strings.Contains(err.Error(), "535") {
		t.Errorf("error = %v, want the tenant text, not the raw SMTP code", err)
	}
	if !strings.Contains(err.Error(), "SMTP AUTH") {
		t.Errorf("error = %v, want it to name the tenant SMTP AUTH setting", err)
	}
	if !strings.Contains(err.Error(), "administrator") {
		t.Errorf("error = %v, want it to name the administrator consent", err)
	}
	if len(f.be.snapshot().mails) != 0 {
		t.Error("the client sent MAIL FROM after a login failure")
	}
}

// TestSMTP_AuthRefusalIsTyped checks the refusal type of DS11.20 G1:
// a 5xx reply to AUTH gives *SMTPAuthError with the code and the
// enhanced code in the text; a 454 reply gives a plain error; no
// refusal sends MAIL FROM.
//
// arch: DS11.14, IS11.7, G6
func TestSMTP_AuthRefusalIsTyped(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		authErr   error
		wantTyped bool
		wantCode  int
		wantText  string
	}{
		{
			name:      "535 5.7.8 is a typed refusal",
			authErr:   &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Bad credentials"},
			wantTyped: true,
			wantCode:  535,
			wantText:  "smtp: login failed: 535 5.7.8 Bad credentials",
		},
		{
			name:      "535 5.7.139 is a typed refusal with the tenant text",
			authErr:   &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 139}, Message: "Authentication unsuccessful"},
			wantTyped: true,
			wantCode:  535,
			wantText:  tenantAuthOffText,
		},
		{
			name:      "454 is returned as it is",
			authErr:   errors.New("try again later"),
			wantTyped: false,
			wantText:  "smtp: login failed: SMTP error 454: try again later",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// Arrange
			f := newSMTPFixture(t, smtpOpts{authErr: c.authErr})
			cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

			// Act
			err := f.send(t, false, cred, smtpTestParams())

			// Assert
			if err == nil {
				t.Fatal("send: want an error, got nil")
			}
			var authErr *SMTPAuthError
			if got := errors.As(err, &authErr); got != c.wantTyped {
				t.Fatalf("errors.As(%v, *SMTPAuthError) = %v, want %v", err, got, c.wantTyped)
			}
			if c.wantTyped && authErr.Code != c.wantCode {
				t.Errorf("Code = %d, want %d", authErr.Code, c.wantCode)
			}
			if err.Error() != c.wantText {
				t.Errorf("error = %q, want %q", err.Error(), c.wantText)
			}
			if got := f.be.snapshot(); len(got.mails) != 0 || got.dataCalls != 0 {
				t.Errorf("mails = %v, data calls = %d after a refused login, want none", got.mails, got.dataCalls)
			}
		})
	}
}

// TestSMTP_SizeLimit checks M11: the 25 MB cap of our own, and the
// SIZE limit of the server, both refuse before the message goes out.
// arch: T5.1, §3.11, M1, M2, M3, M11, §10.7
func TestSMTP_SizeLimit(t *testing.T) {
	t.Parallel()

	t.Run("over the server SIZE limit refuses before MAIL FROM", func(t *testing.T) {
		// Arrange
		f := newSMTPFixture(t, smtpOpts{maxBytes: 1000})
		p := smtpTestParams()
		p.Raw = append(p.Raw, []byte(strings.Repeat("x", 2000))...)
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

		// Act
		err := f.send(t, false, cred, p)

		// Assert
		if err == nil {
			t.Fatal("send: want a size error, got nil")
		}
		for _, want := range []string{fmt.Sprint(len(p.Raw)), "1000"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %v, want it to name %s", err, want)
			}
		}
		got := f.be.snapshot()
		if len(got.mails) != 0 || got.dataCalls != 0 {
			t.Errorf("mails = %v, data calls = %d, want none of either", got.mails, got.dataCalls)
		}
	})

	t.Run("under the server SIZE limit goes out", func(t *testing.T) {
		// Arrange
		f := newSMTPFixture(t, smtpOpts{maxBytes: 10000})
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

		// Act
		err := f.send(t, false, cred, smtpTestParams())

		// Assert
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		if len(f.be.snapshot().data) != 1 {
			t.Error("the server got no message")
		}
	})

	t.Run("over the 25 MB cap refuses before the dial", func(t *testing.T) {
		// Arrange: port 1 refuses every connection, so a dial error
		// instead of a size error would show that the cap ran late.
		p := smtpTestParams()
		p.Raw = make([]byte, maxSendBytes+1)

		// Act
		err := smtpSend(context.Background(), "127.0.0.1:1", true, nil,
			Credential{Username: "alice@example.com"}, p)

		// Assert
		if err == nil {
			t.Fatal("send: want a size error, got nil")
		}
		if !strings.Contains(err.Error(), fmt.Sprint(maxSendBytes)) {
			t.Errorf("error = %v, want it to name the %d byte limit", err, maxSendBytes)
		}
		if strings.Contains(err.Error(), "dial") {
			t.Errorf("error = %v, want the cap to refuse before the dial", err)
		}
	})
}

// TestSend_NoRetry checks M3: a failure after DATA opened never sends
// the message a second time, and it says that the result is not
// known. A failure before DATA does not say that.
// arch: T5.1, §3.11, M1, M2, M3, M11, §10.7
func TestSend_NoRetry(t *testing.T) {
	t.Parallel()

	t.Run("a temporary failure at DATA is not sent again", func(t *testing.T) {
		// Arrange: 451 is the code a client library retries on.
		f := newSMTPFixture(t, smtpOpts{
			dataErr: &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Try again later",
			},
		})
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

		// Act
		err := f.send(t, false, cred, smtpTestParams())

		// Assert
		if err == nil {
			t.Fatal("send: want an error, got nil")
		}
		if !errors.Is(err, ErrDataStarted) {
			t.Errorf("error = %v, want it to wrap ErrDataStarted", err)
		}
		got := f.be.snapshot()
		if got.dataCalls != 1 {
			t.Errorf("data calls = %d, want exactly 1", got.dataCalls)
		}
		if len(got.mails) != 1 {
			t.Errorf("mails = %v, want exactly 1 transaction", got.mails)
		}
	})

	t.Run("a failure before DATA does not claim the message left", func(t *testing.T) {
		// Arrange
		f := newSMTPFixture(t, smtpOpts{
			mailErr: &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Try again later",
			},
		})
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

		// Act
		err := f.send(t, false, cred, smtpTestParams())

		// Assert
		if err == nil {
			t.Fatal("send: want an error, got nil")
		}
		if errors.Is(err, ErrDataStarted) {
			t.Errorf("error = %v, want no ErrDataStarted before DATA", err)
		}
		got := f.be.snapshot()
		if got.dataCalls != 0 {
			t.Errorf("data calls = %d, want 0", got.dataCalls)
		}
		if len(got.mails) != 0 {
			t.Errorf("mails = %v, want none", got.mails)
		}
	})

	t.Run("a good send reaches the server one time", func(t *testing.T) {
		// Arrange
		f := newSMTPFixture(t, smtpOpts{})
		cred := Credential{Username: "alice@example.com", Password: smtpTestPassword}

		// Act
		err := f.send(t, false, cred, smtpTestParams())

		// Assert
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		got := f.be.snapshot()
		if got.dataCalls != 1 || len(got.mails) != 1 {
			t.Errorf("data calls = %d, mails = %v, want one of each", got.dataCalls, got.mails)
		}
	})
}
