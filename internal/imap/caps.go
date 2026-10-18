// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file holds the capability report of T91. It sits
// apart from provider.go so a reader of the read path does not also
// read the save_sent advice text.

package imap

import (
	"context"
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// Caps reports this account's IMAP capabilities and whether INBOX
// takes a keyword the client invents, through the same login a read
// already uses. It leaves Caps.SaveSent empty: that field needs the
// account's save_sent setting and its SMTP address, which this
// read-only type does not carry. [SaveSentAdvice] fills it; the
// caller (cli.loginReport) holds the account and puts the two
// together.
//
// *Provider implements tools.CapsReporter. No fake Reader changes:
// the capability report is this one extra method, not a new Reader
// method every fake would have to grow (DR1G.17).
//
// arch: DR1G.11, DR1G.18.8, IR1G.15
func (p *Provider) Caps(ctx context.Context) (mail.Caps, error) {
	var out mail.Caps
	err := p.pool.WithRead(ctx, p.alias, func(c *Conn) error {
		caps := c.Caps()
		out.Move = caps.Has(imap.CapMove)
		out.CondStore = caps.Has(imap.CapCondStore)
		out.UIDPlus = caps.Has(imap.CapUIDPlus)
		// SELECT, not EXAMINE: many servers answer EXAMINE with
		// PERMANENTFLAGS () (RFC 3501), and modify reads the list
		// from a SELECT too (C17).
		sel, err := selectWrite(c, "INBOX")
		if err != nil {
			return err
		}
		out.Keywords = permitsKeywords(sel)
		return nil
	})
	if err != nil {
		return mail.Caps{}, err
	}
	return out, nil
}

// SaveSentAdvice gives the fixed advice line of the save_sent table
// (DR1G.18.7), built from the one decision [sentCopy] makes. The send
// path and the capability report must not restate that rule a second
// time (IR1G.15).
//
// arch: DR1G.11, DR1G.18.7, DR1G.18.8, IR1G.15
func SaveSentAdvice(saveSent, smtp string) string {
	mailbagSaves, hostKeeps := sentCopy(saveSent, smtp)
	setting := strings.ToLower(strings.TrimSpace(saveSent))
	if setting == "" {
		setting = "auto"
	}
	switch setting {
	case "always":
		return "save_sent = always: mailbag saves a copy in Sent"
	case "never":
		if hostKeeps {
			return "save_sent = never: this server keeps sent mail"
		}
		return `save_sent = never: WARNING sent mail is not kept anywhere; set save_sent = "auto"`
	default: // "auto"
		if mailbagSaves {
			return "save_sent = auto: mailbag saves a copy in Sent"
		}
		return "save_sent = auto: this server keeps sent mail, so mailbag saves no copy"
	}
}
