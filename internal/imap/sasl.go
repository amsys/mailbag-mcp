// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package imap holds all use of the go-imap library.
package imap

import (
	"github.com/emersion/go-sasl"
)

// XOAUTH2 is the mechanism name that Outlook and Gmail use.
const XOAUTH2 = "XOAUTH2"

// xoauth2Client sends the XOAUTH2 initial response. go-sasl removed this
// mechanism, so we keep our own client. See design B12 and §3.6.
type xoauth2Client struct {
	username string
	token    string
	done     bool
}

// Start gives the mechanism name and the initial response. The format is
// "user=<user>\x01auth=Bearer <token>\x01\x01". The caller encodes it in
// base64.
func (c *xoauth2Client) Start() (string, []byte, error) {
	ir := []byte("user=" + c.username + "\x01auth=Bearer " + c.token + "\x01\x01")
	return XOAUTH2, ir, nil
}

// Next answers a server challenge. The server sends a challenge only on a
// failure. The client must answer with an empty response to get the final
// "NO" from the server.
func (c *xoauth2Client) Next(_ []byte) ([]byte, error) {
	if c.done {
		return nil, sasl.ErrUnexpectedServerChallenge
	}
	c.done = true
	return []byte{}, nil
}

// NewXOAUTH2 makes an XOAUTH2 client for IMAP and for SMTP.
func NewXOAUTH2(username, token string) sasl.Client {
	return &xoauth2Client{username: username, token: token}
}

// NewLOGIN makes a LOGIN client. It is for a server that has no PLAIN.
// go-sasl still has this mechanism, so we use it.
func NewLOGIN(username, password string) sasl.Client {
	return sasl.NewLoginClient(username, password)
}
