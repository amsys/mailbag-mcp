// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/amsys/mailbag-mcp/internal/config"
)

const (
	// smtpTLSPort is the submission port that carries TLS from the
	// first byte. Any other port means STARTTLS, and the send fails
	// when the server does not offer it. A send never falls back to
	// clear text, because that shows the password (§3.11, M1).
	smtpTLSPort = "465"

	// maxSendBytes caps one outgoing message (M11). guard.MaxAttachBytes
	// caps one file. The server SIZE limit is a second, smaller cap
	// that checkSMTPServerSize applies.
	maxSendBytes = 25 << 20
)

// ErrDataStarted marks a failure that happened after the DATA command
// opened. The message may already have left the client, so the result
// is not known and nothing sends it again. The caller shows this to
// the person instead of trying a second time (§3.11, M3).
var ErrDataStarted = errors.New("the send started and the result is not known; do not send it again")

// SMTPAuthError is a reply with a 5xx code to the AUTH command: the
// server refused the login. It is a type of its own and not
// [AuthError], because tools.Factory reads an AuthError as a refused
// IMAP login and then refuses each new IMAP login for some minutes.
// SMTP is not the sign-in path (DS11.20 G1).
//
// AUTH comes before MAIL FROM and DATA, so no byte of the message has
// left when this error comes back. The writer can therefore send once
// more with a fresh token (IS11.7).
//
// arch: DS11.14, DS11.20, IS11.7, G6
type SMTPAuthError struct {
	// Code is the SMTP reply code, for example 535.
	Code int
	// Msg is the reply text. It starts with the enhanced status code
	// when the server gave one, for example "5.7.8 Bad credentials".
	Msg string
}

// Error gives "smtp: login failed: <code> <msg>". A 535 5.7.139 reply
// gives the tenant text instead, because a raw code does not tell the
// person what to do (B13, T6.4).
func (e *SMTPAuthError) Error() string {
	if e.tenantAuthOff() {
		return tenantAuthOffText
	}
	return fmt.Sprintf("smtp: login failed: %d %s", e.Code, e.Msg)
}

// tenantAuthOff reports whether the reply is 535 5.7.139: the
// Microsoft 365 tenant has SMTP AUTH off. A fresh token cannot fix
// that, so the writer does not try again (DS11.20 G1).
func (e *SMTPAuthError) tenantAuthOff() bool {
	return e.Code == 535 && strings.Contains(e.Msg, "5.7.139")
}

// SendParams is one outgoing message for SendMail. The caller builds
// Raw and picks the envelope addresses (§3.11, §3.14).
//
// arch: T5.1, §3.11, M1, M2, M3, M11, §10.7
type SendParams struct {
	// From is the envelope sender. The caller checks that it is the
	// account address or one of acct.Identities (M13).
	From string

	// To holds every recipient: the To, Cc and Bcc addresses together,
	// with duplicates already removed by the caller (§3.11).
	To []string

	// Raw is the RFC 822 message, with CRLF line ends.
	Raw []byte

	// Debug is the wire debug writer, or nil. No byte of the login
	// reaches it (B15).
	Debug io.Writer
}

// SendMail sends one message over SMTP for acct.
//
// The port picks the transport: 465 means TLS from the first byte,
// any other port means STARTTLS and fails when the server does not
// offer it (M1). The login is XOAUTH2 for a token account, else PLAIN
// and then LOGIN (M2). The message goes out once: a failure after the
// DATA command wraps ErrDataStarted, and this function never tries
// again (M3).
//
// The caller reaches this function through WriteProvider.SendDraft in
// internal/imap/send.go. SendDraft reads Raw and the envelope from the
// stored draft first, and its wire method calls this function.
//
// arch: T5.1, §3.11, M1, M2, M3, M11, §10.7
func SendMail(ctx context.Context, acct config.Account, cred Credential, p SendParams) error {
	host, port, err := splitSMTPAddr(acct.SMTP)
	if err != nil {
		return err
	}
	tlsCfg, err := tlsConfig(host, acct.TLSCA)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(host, port)
	return smtpSend(ctx, addr, smtpImplicitTLS(port), tlsCfg, cred, p)
}

// smtpSend does the work of SendMail with the transport already
// picked. SendMail reads the transport from the port; a test drives
// both transports on the port that the listener got.
//
// arch: T5.1, §3.11, M1, M2, M3, M11, §10.7
func smtpSend(ctx context.Context, addr string, implicitTLS bool, tlsCfg *tls.Config, cred Credential, p SendParams) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkSMTPEnvelope(p); err != nil {
		return err
	}

	// We open the socket ourselves instead of calling go-smtp DialTLS
	// or DialStartTLS. Those take no context and wait their own
	// timeout, so a server that takes the connection and then goes
	// quiet holds the send far past the caller deadline. With the
	// socket in hand, ctx closes it and every step after it fails at
	// once. internal/imap/dial.go opens the IMAP socket for the same
	// reason (C25).
	raw, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", addr, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()

	var dw *debugWriter
	if p.Debug != nil {
		dw = newDebugWriter(p.Debug)
	}

	c, err := smtpHandshake(ctx, raw, implicitTLS, tlsCfg, dw)
	if err != nil {
		_ = raw.Close()
		return fmt.Errorf("smtp: %s: %w", addr, err)
	}
	defer func() { _ = c.Close() }()

	if err := smtpAuth(c, cred); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr // a deadline, not a wrong password
		}
		return err
	}
	if dw != nil {
		dw.Open() // B15: the login is over, debug may show the traffic
	}

	if err := checkSMTPServerSize(c, len(p.Raw)); err != nil {
		return err
	}
	if err := smtpDeliver(c, p); err != nil {
		return err
	}
	// The message left. A bad QUIT does not change that, so it never
	// turns a send into a failure (M3).
	_ = c.Quit()
	return nil
}

// smtpHandshake puts TLS on the socket and gives the SMTP client. An
// implicit-TLS port starts TLS at once. Any other port sends
// STARTTLS, and go-smtp fails when the server does not offer it, so
// the password never goes over clear text (§3.11, M1).
func smtpHandshake(ctx context.Context, raw net.Conn, implicitTLS bool, tlsCfg *tls.Config, dw *debugWriter) (*smtp.Client, error) {
	if !implicitTLS {
		c, err := smtp.NewClientStartTLS(raw, tlsCfg)
		if err != nil {
			return nil, err
		}
		setSMTPDebug(c, dw)
		return c, nil
	}
	conn := tls.Client(raw, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	c := smtp.NewClient(conn)
	setSMTPDebug(c, dw)
	return c, nil
}

// setSMTPDebug gives the client the debug writer. A nil dw must stay
// out of the interface field, because a typed nil pointer in an
// interface is not a nil interface and go-smtp would write to it.
func setSMTPDebug(c *smtp.Client, dw *debugWriter) {
	if dw != nil {
		c.DebugWriter = dw
	}
}

// smtpAuth logs in. XOAUTH2 comes first when the account has a token.
// For a password account PLAIN comes first, then LOGIN. An account
// with no secret sends no AUTH command, because a local relay asks
// for none (§3.11, §3.6, M2).
func smtpAuth(c *smtp.Client, cred Credential) error {
	var a sasl.Client
	switch {
	case cred.Token != "":
		if !c.SupportsAuth(XOAUTH2) {
			return errors.New("smtp: login failed: the server does not offer XOAUTH2")
		}
		a = NewXOAUTH2(cred.Username, cred.Token)
	case cred.Password == "":
		return nil
	case c.SupportsAuth(sasl.Plain):
		a = sasl.NewPlainClient("", cred.Username, cred.Password)
	case c.SupportsAuth(sasl.Login):
		a = NewLOGIN(cred.Username, cred.Password)
	default:
		return errors.New("smtp: login failed: the server offers neither PLAIN nor LOGIN")
	}
	if err := c.Auth(a); err != nil {
		var smtpErr *smtp.SMTPError
		if errors.As(err, &smtpErr) && smtpErr.Code/100 == 5 {
			return &SMTPAuthError{Code: smtpErr.Code, Msg: smtpReplyText(smtpErr)}
		}
		// A 4xx reply (454: try later) or a local error is not a
		// refused login; it goes back as it is (DS11.20 G1).
		return fmt.Errorf("smtp: login failed: %w", err)
	}
	return nil
}

// smtpReplyText gives the text of a reply with its enhanced status
// code in front, as the server sent it. go-smtp moves that code out
// of Message into EnhancedCode; SMTPAuthError keeps it in the text,
// so a reader of Msg sees 5.7.139 (DS11.20 G1).
func smtpReplyText(e *smtp.SMTPError) string {
	if e.EnhancedCode[0] <= 0 {
		return e.Message
	}
	return fmt.Sprintf("%d.%d.%d %s", e.EnhancedCode[0], e.EnhancedCode[1], e.EnhancedCode[2], e.Message)
}

// tenantAuthOffText is the text for a 535 5.7.139 login failure.
// Microsoft 365 tenants switch SMTP AUTH off by default and need an
// administrator's consent for the app before a work account can log
// in (B13, T6.4, DS6.5, DS6.6, §3.11).
const tenantAuthOffText = "smtp: login failed: this tenant's SMTP AUTH setting is off; " +
	"ask the administrator to enable SMTP AUTH for this account " +
	"and consent to the app"

// checkSMTPServerSize compares the message with the SIZE limit that the
// server gave in its EHLO answer, before MAIL FROM. A server that
// refuses at DATA has already read the whole message, and the person
// gets a code instead of a clear sentence (§3.11, M11).
func checkSMTPServerSize(c *smtp.Client, n int) error {
	limit, ok := c.MaxMessageSize()
	if !ok || limit <= 0 {
		return nil
	}
	if n > limit {
		return fmt.Errorf("smtp: the message is %d bytes; this server takes at most %d bytes", n, limit)
	}
	return nil
}

// smtpDeliver runs MAIL, RCPT and DATA one time. After Data opened, a
// failure wraps ErrDataStarted, because the message may have left
// (§3.11, M3).
func smtpDeliver(c *smtp.Client, p SendParams) error {
	if err := c.Mail(p.From, &smtp.MailOptions{Size: int64(len(p.Raw))}); err != nil {
		return fmt.Errorf("smtp: MAIL FROM: %w", err)
	}
	for _, to := range p.To {
		if err := c.Rcpt(to, nil); err != nil {
			return fmt.Errorf("smtp: RCPT TO: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := w.Write(p.Raw); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp: write message: %w: %w", err, ErrDataStarted)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: end of message: %w: %w", err, ErrDataStarted)
	}
	return nil
}

// checkSMTPEnvelope refuses a message that cannot go out. The 25 MB cap
// is ours; the server cap comes later, from EHLO (M11).
func checkSMTPEnvelope(p SendParams) error {
	if strings.TrimSpace(p.From) == "" {
		return errors.New("smtp: the message has no envelope sender")
	}
	if len(p.To) == 0 {
		return errors.New("smtp: the message has no recipient")
	}
	if len(p.Raw) == 0 {
		return errors.New("smtp: the message is empty")
	}
	if len(p.Raw) > maxSendBytes {
		return fmt.Errorf("smtp: the message is %d bytes; the limit is %d bytes", len(p.Raw), maxSendBytes)
	}
	return nil
}

// smtpImplicitTLS reports whether the port carries TLS from the first
// byte. Port 465 does. Any other port means STARTTLS (§3.11, M1).
func smtpImplicitTLS(port string) bool { return port == smtpTLSPort }

// splitSMTPAddr reads "host", "host:port" or "[v6]:port" and gives
// the host and the port. With no port it gives the implicit-TLS port,
// because TLS from the first byte is the safe default (M1). It calls
// the one split function dial.go holds (DRV.16c).
func splitSMTPAddr(addr string) (host, port string, err error) {
	return splitHostPort(addr, smtpTLSPort, "smtp")
}
