// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// keySMTP is an in-process SMTP server for the key store tests. go-smtp
// ships no memory server, so this file builds a Backend and a Session
// of its own and serves them on 127.0.0.1 with a free port, the same
// way internal/imap/smtp_test.go does. The count of mails is the
// count of DATA commands the server accepted: that is a mail that
// left, as a receiving server sees it.
type keySMTP struct {
	addr string

	mu       sync.Mutex
	accepted int
	attempts int
	dataErr  error
	// entered gets one value each time a DATA command starts, when
	// it is not nil. hold, when not nil, keeps DATA open until the
	// test closes it.
	entered chan struct{}
	hold    chan struct{}
}

func newKeySMTP(t *testing.T) *keySMTP {
	t.Helper()
	s := &keySMTP{}
	srv := smtp.NewServer(s)
	srv.Domain = "127.0.0.1"
	srv.ErrorLog = smtpQuiet{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	s.addr = ln.Addr().String()
	return s
}

func (s *keySMTP) count() (accepted, attempts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted, s.attempts
}

func (s *keySMTP) NewSession(*smtp.Conn) (smtp.Session, error) { return keySession{s}, nil }

type keySession struct{ s *keySMTP }

func (keySession) Reset()                               {}
func (keySession) Logout() error                        { return nil }
func (keySession) Mail(string, *smtp.MailOptions) error { return nil }
func (keySession) Rcpt(string, *smtp.RcptOptions) error { return nil }
func (k keySession) Data(r io.Reader) error {
	if _, err := io.ReadAll(r); err != nil {
		return err
	}
	k.s.mu.Lock()
	k.s.attempts++
	entered, hold, dataErr := k.s.entered, k.s.hold, k.s.dataErr
	k.s.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if hold != nil {
		<-hold
	}
	if dataErr != nil {
		return dataErr
	}
	k.s.mu.Lock()
	k.s.accepted++
	k.s.mu.Unlock()
	return nil
}

type smtpQuiet struct{}

func (smtpQuiet) Printf(string, ...interface{}) {}
func (smtpQuiet) Println(...interface{})        {}

// smtpWriter is the fake write provider of send_test.go with one
// change: SendDraft gives the draft to the in-process SMTP server,
// so each mail the tool sends is a real SMTP transaction.
type smtpWriter struct {
	*writeProvider
	srv *keySMTP
	// panicAfter makes SendDraft panic after the SMTP transaction.
	panicAfter bool
}

func (w *smtpWriter) SendDraft(_ context.Context, id string) (mail.SendResult, error) {
	msg := "From: me@example.test\r\nTo: you@example.test\r\nSubject: draft " + id + "\r\n\r\nbody\r\n"
	c, err := smtp.Dial(w.srv.addr)
	if err != nil {
		return mail.SendResult{}, fmt.Errorf("smtp: %w", err)
	}
	err = c.SendMail("me@example.test", []string{"you@example.test"}, strings.NewReader(msg))
	_ = c.Close()
	if err != nil {
		return mail.SendResult{}, fmt.Errorf("smtp: %w", err)
	}
	if w.panicAfter {
		panic("test panic after the mail left")
	}
	return mail.SendResult{ID: "<" + id + "@example.test>", Sent: true, SavedToSent: true}, nil
}

// smtpMail is the fake Mail of send_test.go, with OpenWriter giving
// the SMTP writer.
type smtpMail struct {
	*writeMail
	w Writer
}

func (m *smtpMail) OpenWriter(ctx context.Context, alias string) (Writer, config.Account, error) {
	_, acct, err := m.writeMail.OpenWriter(ctx, alias)
	if err != nil {
		return nil, config.Account{}, err
	}
	return m.w, acct, nil
}

// keyFixture builds a send tool whose provider sends through a new
// in-process SMTP server.
func keyFixture(t *testing.T) (*sendTool, *smtpWriter, *keySMTP) {
	t.Helper()
	h, prov := sendFixture(t, nil)
	srv := newKeySMTP(t)
	w := &smtpWriter{writeProvider: prov, srv: srv}
	h.mail = &smtpMail{writeMail: h.mail.(*writeMail), w: w}
	return h, w, srv
}

func keyIn(key string) SendIn {
	return SendIn{Account: "work", DraftID: "1700000000.7.Drafts", IdempotencyKey: key}
}

// wantMails checks the count of mails the SMTP server accepted.
func wantMails(t *testing.T, srv *keySMTP, want int) {
	t.Helper()
	if got, _ := srv.count(); got != want {
		t.Fatalf("SMTP server accepted %d mails, want %d", got, want)
	}
}

// TestSend_IdempotentKey holds I9: one idempotency key sends at most
// one mail. A repeat of a done key gives the first result and sends
// nothing. A key in flight gives a fixed error. A call that ends
// before the send releases its key. A send error is a result too,
// because the mail may have left. Each count is the count of mails the
// in-process SMTP server accepted.
//
// arch: D5.3, D8.3, I9
func TestSend_IdempotentKey(t *testing.T) {
	ctx := context.Background()

	t.Run("repeat gives the first result and sends nothing", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		first, err := h.handle(ctx, keyIn("k-1"))
		if err != nil || !first.Sent {
			t.Fatalf("first send: out %+v, err %v", first, err)
		}
		for i := 0; i < 3; i++ {
			again, err := h.handle(ctx, keyIn("k-1"))
			if err != nil {
				t.Fatalf("repeat %d: %v", i, err)
			}
			if !reflect.DeepEqual(again, first) {
				t.Fatalf("repeat %d gave %+v, want the first result %+v", i, again, first)
			}
		}
		wantMails(t, srv, 1)
	})

	t.Run("another key sends another mail", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		for _, k := range []string{"k-1", "k-2"} {
			if _, err := h.handle(ctx, keyIn(k)); err != nil {
				t.Fatalf("send %s: %v", k, err)
			}
		}
		wantMails(t, srv, 2)
	})

	// R1C-judge finding 7: the schema lists the key as required, so
	// an empty key is refused and sends nothing. The test calls run
	// and not handle, because handle gives a new key to a call that
	// has none.
	t.Run("empty key is refused", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		for _, key := range []string{"", "  "} {
			_, err := h.run(ctx, keyIn(key), nil, func(context.Context, Writer, config.Account, string, string) (string, error) {
				return confirmAccept, nil
			})
			if !errors.Is(err, errKeyEmpty) {
				t.Fatalf("key %q: err %v, want errKeyEmpty", key, err)
			}
		}
		wantMails(t, srv, 0)
	})

	t.Run("key in flight gives the fixed error", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		srv.entered = make(chan struct{}, 1)
		srv.hold = make(chan struct{})

		type result struct {
			out SendOut
			err error
		}
		done := make(chan result, 1)
		go func() {
			out, err := h.handle(ctx, keyIn("k-1"))
			done <- result{out, err}
		}()
		select {
		case <-srv.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("the first send never reached DATA")
		}

		_, err := h.handle(ctx, keyIn("k-1"))
		if !errors.Is(err, errKeyInFlight) {
			t.Fatalf("second call with a key in flight: err %v, want errKeyInFlight", err)
		}
		if strings.Contains(err.Error(), "k-1") {
			t.Fatalf("the fixed error names the key: %q", err)
		}

		srv.mu.Lock()
		srv.entered = nil
		srv.mu.Unlock()
		close(srv.hold)
		first := <-done
		if first.err != nil || !first.out.Sent {
			t.Fatalf("first send: out %+v, err %v", first.out, first.err)
		}
		again, err := h.handle(ctx, keyIn("k-1"))
		if err != nil || !reflect.DeepEqual(again, first.out) {
			t.Fatalf("repeat after the first send: out %+v, err %v; want %+v", again, err, first.out)
		}
		wantMails(t, srv, 1)
		if _, attempts := srv.count(); attempts != 1 {
			t.Fatalf("SMTP server saw %d DATA commands, want 1", attempts)
		}
	})

	t.Run("many calls at once send one mail", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := h.handle(ctx, keyIn("k-1"))
				if err != nil && !errors.Is(err, errKeyInFlight) {
					t.Errorf("call: %v", err)
				}
			}()
		}
		wg.Wait()
		wantMails(t, srv, 1)
	})

	t.Run("decline releases the key", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		for _, outcome := range []string{confirmDecline, confirmCancel} {
			out, err := h.run(ctx, keyIn("k-1"), nil, func(context.Context, Writer, config.Account, string, string) (string, error) {
				return outcome, nil
			})
			if err != nil || out.Sent || out.Note != notSentNote {
				t.Fatalf("%s: out %+v, err %v; want the fixed result not sent", outcome, out, err)
			}
		}
		wantMails(t, srv, 0)
		out, err := h.handle(ctx, keyIn("k-1"))
		if err != nil || !out.Sent {
			t.Fatalf("accept after decline: out %+v, err %v", out, err)
		}
		wantMails(t, srv, 1)
	})

	t.Run("failed confirmation releases the key", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		_, err := h.run(ctx, keyIn("k-1"), nil, func(context.Context, Writer, config.Account, string, string) (string, error) {
			return "", errors.New(notConfirmedText)
		})
		if err == nil {
			t.Fatal("a failed confirmation gave no error")
		}
		if _, err := h.handle(ctx, keyIn("k-1")); err != nil {
			t.Fatalf("send after a failed confirmation: %v", err)
		}
		wantMails(t, srv, 1)
	})

	t.Run("limit refusal releases the key", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		now := time.Now()
		h.limit.now = func() time.Time { return now }
		for i := 0; i < sendsPerWindow; i++ {
			if err := h.limit.take("work"); err != nil {
				t.Fatalf("fill the limit: %v", err)
			}
		}
		if _, err := h.handle(ctx, keyIn("k-1")); err == nil {
			t.Fatal("a send over the limit gave no error")
		}
		wantMails(t, srv, 0)
		now = now.Add(sendWindow)
		if out, err := h.handle(ctx, keyIn("k-1")); err != nil || !out.Sent {
			t.Fatalf("send after the window: out %+v, err %v", out, err)
		}
		wantMails(t, srv, 1)
	})

	t.Run("send error is the result of the key", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		srv.dataErr = &smtp.SMTPError{Code: 451, Message: "try later"}
		_, firstErr := h.handle(ctx, keyIn("k-1"))
		if firstErr == nil {
			t.Fatal("a refused DATA gave no error")
		}
		srv.mu.Lock()
		srv.dataErr = nil
		srv.mu.Unlock()
		_, err := h.handle(ctx, keyIn("k-1"))
		if err == nil || err.Error() != firstErr.Error() {
			t.Fatalf("repeat after a send error: err %v, want the first error %v", err, firstErr)
		}
		if _, attempts := srv.count(); attempts != 1 {
			t.Fatalf("SMTP server saw %d DATA commands, want 1", attempts)
		}
		wantMails(t, srv, 0)
	})

	t.Run("panic during the send keeps the key", func(t *testing.T) {
		h, w, srv := keyFixture(t)
		w.panicAfter = true
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("the send did not panic")
				}
			}()
			_, _ = h.handle(ctx, keyIn("k-1"))
		}()
		w.panicAfter = false
		_, err := h.handle(ctx, keyIn("k-1"))
		if !errors.Is(err, errSendUnknown) {
			t.Fatalf("repeat after a panic: err %v, want errSendUnknown", err)
		}
		wantMails(t, srv, 1)
	})

	t.Run("key lives 24 hours", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		now := time.Now()
		h.keys.now = func() time.Time { return now }
		if _, err := h.handle(ctx, keyIn("k-1")); err != nil {
			t.Fatalf("first send: %v", err)
		}
		now = now.Add(keyTTL - time.Second)
		if _, err := h.handle(ctx, keyIn("k-1")); err != nil {
			t.Fatalf("repeat inside 24 hours: %v", err)
		}
		wantMails(t, srv, 1)
		now = now.Add(time.Second)
		if _, err := h.handle(ctx, keyIn("k-1")); err != nil {
			t.Fatalf("send after 24 hours: %v", err)
		}
		wantMails(t, srv, 2)
	})

	t.Run("access check comes before the store", func(t *testing.T) {
		h, _, srv := keyFixture(t)
		if _, err := h.handle(ctx, keyIn("k-1")); err != nil {
			t.Fatalf("first send: %v", err)
		}
		h.mail.(*smtpMail).acct.Access = "draft"
		if _, err := h.handle(ctx, keyIn("k-1")); err == nil {
			t.Fatal("a draft account read a stored send result")
		}
		wantMails(t, srv, 1)
	})
}

// TestKeyStore_States holds the key states of D5.3 on the store
// alone: two accounts keep two keys apart, a key in flight never
// expires, and release leaves a done key done.
//
// arch: D5.3, I9
func TestKeyStore_States(t *testing.T) {
	now := time.Now()
	s := &keyStore{now: func() time.Time { return now }}

	if _, replay, err := s.begin("a", "k", "d"); replay || err != nil {
		t.Fatalf("free key: replay %v, err %v", replay, err)
	}
	if _, replay, err := s.begin("b", "k", "d"); replay || err != nil {
		t.Fatalf("same key on another account: replay %v, err %v", replay, err)
	}
	now = now.Add(2 * keyTTL)
	if _, _, err := s.begin("a", "k", "d"); !errors.Is(err, errKeyInFlight) {
		t.Fatalf("key in flight after 48 hours: err %v, want errKeyInFlight", err)
	}

	want := SendOut{Account: "a", ID: "<x@example.test>", Sent: true}
	s.finish("a", "k", want, nil)
	s.release("a", "k")
	got, replay, err := s.begin("a", "k", "d")
	if !replay || err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("done key after release: out %+v, replay %v, err %v", got, replay, err)
	}

	s.release("b", "k")
	if _, replay, err := s.begin("b", "k", "d"); replay || err != nil {
		t.Fatalf("released key: replay %v, err %v", replay, err)
	}
}
