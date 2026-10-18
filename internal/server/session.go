// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// One MCP session of the Service on one byte stream, and the reason
// that each session end gets in the log (DS11.2, IS11.2).

package server

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The reasons of a session end (DS11.2). Only endTransportError is
// logged at WARN; the others are normal ends and are logged at INFO.
// No session end is logged at ERROR (IS11.2).
const (
	endPeerClosed     = "peer-closed"
	endPeerGone       = "peer-gone"
	endShutdown       = "shutdown"
	endTransportError = "transport-error"
)

// serverClosingText is the text of the SDK's ErrServerClosing. The
// error is in an internal package of the go-sdk, so errors.Is cannot
// find it. Wait gives it when a reply could not go out because the
// peer was already gone (go-sdk v1.7.0 internal/jsonrpc2/conn.go,
// write and shuttingDown).
const serverClosingText = "server is closing"

// nopCloseWriter is the Writer half of the session transport. Its
// Close does nothing, because the Reader half is the same rwc and the
// SDK closes that one: a net.Conn must not be closed twice (R§2.5).
type nopCloseWriter struct{ io.Writer }

// Close does nothing; the Reader half closes the stream.
func (nopCloseWriter) Close() error { return nil }

// Session serves one MCP session on rwc until the peer ends it or ctx
// ends. It uses Server.Connect and ServerSession.Wait, not
// Server.Run, so the SDK writes no ERROR line for a normal end
// (DS11.16, IS11.2).
//
// The SDK does not end a session when ctx ends, so Session calls
// ss.Close on ctx end and then waits for Wait. That Close is
// graceful: a call in flight finishes first.
//
// Session returns nil for every normal end and logs it at INFO with
// its reason: peer-closed (EOF between calls), peer-gone (EOF while a
// call was in flight) or shutdown (ctx end). Any other end is a
// transport-error: Session logs it at WARN with the error and returns
// the error. Session closes rwc in every case.
//
// arch: DS11.2, DS11.16, IS11.2, D11.1
func (s *Service) Session(ctx context.Context, rwc io.ReadWriteCloser) error {
	ss, err := s.srv.Connect(ctx, &mcp.IOTransport{Reader: rwc, Writer: nopCloseWriter{rwc}}, nil)
	if err != nil {
		_ = rwc.Close()
		s.logger.Warn("session-end", "reason", endTransportError, "error", err.Error())
		return err
	}
	s.track(ss, true)
	defer s.track(ss, false)

	waited := make(chan error, 1)
	go func() { waited <- ss.Wait() }()

	var waitErr error
	shutdown := false
	select {
	case waitErr = <-waited:
	case <-ctx.Done():
		shutdown = true
		_ = ss.Close()
		waitErr = <-waited
	}

	reason := endReason(waitErr, shutdown)
	if reason == endTransportError {
		s.logger.Warn("session-end", "reason", reason, "error", waitErr.Error())
		return waitErr
	}
	s.logger.Info("session-end", "reason", reason)
	return nil
}

// endReason maps the result of ServerSession.Wait to the reason of a
// session end (DS11.2). shutdown is true when Session closed the
// session because its ctx ended; then the error of Wait does not
// matter, because closing the stream can make the read fail.
//
// arch: DS11.2, IS11.2
func endReason(waitErr error, shutdown bool) string {
	switch {
	case shutdown:
		return endShutdown
	case waitErr == nil:
		return endPeerClosed
	case errors.Is(waitErr, io.EOF), strings.Contains(waitErr.Error(), serverClosingText):
		return endPeerGone
	default:
		return endTransportError
	}
}
