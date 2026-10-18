// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools holds, in identity.go, the identity pick of the draft tool
// for an account in identity mode (DI2), and the one read of the
// original that the pick, the reply and the forward share (DI2.1).
package tools

import (
	"context"
	"errors"
	"fmt"
	netmail "net/mail"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// deliveryHeaders are the headers that the read of the original asks
// for in identity mode. They tell to which address a catch-all mailbox
// got the mail (DI2.1).
var deliveryHeaders = []string{"Delivered-To", "X-Original-To"}

// errFromNotIdentity is the refusal of a from value that is not the
// account address or one of its identities (M13, DI2.2 rule 1). Its
// text is the text identityFrom has given since T5.2.
var errFromNotIdentity = errors.New("from must be the address of this account or one of its identities; the accounts tool lists them")

// picked is the result of [pickIdentity]: the identity of a draft and
// the From value the draft gets.
//
// arch: DI2.1
type picked struct {
	Identity config.Identity
	Addr     string // the address of the From header
	From     string // header value: "Name <addr>" or addr
	Reason   string // "from", "to", "cc", "delivered-to", "reply_match", "default"
}

// readOriginal reads the message that a reply or a forward answers.
// It gives nil and no error for a new draft. The read options are the
// options addReply and addForward used before DI2.1. In identity mode
// the read also asks for the delivery headers, which the pick needs
// (DI2.1). No other provider call is added.
//
// arch: DI2.0, DI2.1
func readOriginal(ctx context.Context, p Writer, in DraftIn, identityMode bool) (*mail.Message, error) {
	id, what := in.ReplyToID, "reply_to_id"
	if id == "" {
		id, what = in.ForwardID, "forward_id"
	}
	if id == "" {
		return nil, nil
	}
	opts := mail.ReadOpts{Format: "text", MaxChars: originalMaxChars}
	if identityMode {
		opts.Headers = append([]string(nil), deliveryHeaders...)
	}
	orig, err := p.Read(ctx, id, opts)
	if err != nil {
		return nil, err
	}
	if orig == nil {
		return nil, errors.New(what + " names no message")
	}
	return orig, nil
}

// pickIdentity selects the identity and the From value of a draft for
// an account in identity mode (DI2.0). The rules run in this order
// (DI2.2):
//
//  1. An explicit from must be an identity email, or, on a reply or a
//     forward, the address that rule 3 picks. Any other value is
//     refused. A display name in the value is dropped.
//  2. The first candidate address of the original that is an identity
//     email. The candidates are the To entries, the Cc entries, then
//     every Delivered-To and every X-Original-To value.
//  3. The first candidate, in the same order, that a reply_match
//     pattern of an identity matches. The From address is that
//     candidate in lower case (catch-all, DI0 R4).
//  4. The default identity of the account.
//
// The From value is always the configured name of the identity with
// the address. The name that the caller wrote is never used.
//
// orig is nil for a new draft, so rules 2 and 3 do not apply and an
// explicit from can never be a catch-all address (I6).
//
// arch: DI2.1, DI2.2, DI6.1, I6
func pickIdentity(acct config.Account, in DraftIn, orig *mail.Message) (picked, error) {
	cands := candidates(orig)
	catchID, catchAddr, catchOK := matchCatchAll(acct, cands)

	if strings.TrimSpace(in.From) != "" {
		if err := guard.ValidateAddress(in.From); err != nil {
			return picked{}, fmt.Errorf("from: %w", err)
		}
		addr, err := netAddress(in.From)
		if err != nil {
			return picked{}, fmt.Errorf("from: %w", err)
		}
		if id, ok := acct.Identity(addr); ok {
			return picked{Identity: id, Addr: addr, From: formatFrom(id.Name, addr), Reason: "from"}, nil
		}
		if catchOK && strings.EqualFold(addr, catchAddr) {
			return picked{Identity: catchID, Addr: addr, From: formatFrom(catchID.Name, addr), Reason: "from"}, nil
		}
		return picked{}, errFromNotIdentity
	}

	for _, c := range cands {
		if id, ok := acct.Identity(c.addr); ok {
			return picked{Identity: id, Addr: id.Email, From: formatFrom(id.Name, id.Email), Reason: c.reason}, nil
		}
	}
	if catchOK {
		return picked{Identity: catchID, Addr: catchAddr, From: formatFrom(catchID.Name, catchAddr), Reason: "reply_match"}, nil
	}
	id := acct.Default()
	return picked{Identity: id, Addr: id.Email, From: formatFrom(id.Name, id.Email), Reason: "default"}, nil
}

// candidate is one address of the original that can pick an identity,
// with the reason word it gives when it does.
type candidate struct {
	addr   string
	reason string
}

// candidates lists the addresses of the original that rules 2 and 3
// of DI2.2 test, in their order: To, Cc, Delivered-To, X-Original-To.
// A header value that does not parse as an address list is skipped,
// because it is sender text and cannot name an identity. A nil
// original gives no candidates.
func candidates(orig *mail.Message) []candidate {
	if orig == nil {
		return nil
	}
	var out []candidate
	for _, a := range orig.To {
		if a.Address != "" {
			out = append(out, candidate{addr: a.Address, reason: "to"})
		}
	}
	for _, a := range orig.Cc {
		if a.Address != "" {
			out = append(out, candidate{addr: a.Address, reason: "cc"})
		}
	}
	for _, name := range deliveryHeaders {
		for _, v := range orig.Headers[name] {
			list, err := mime.ParseAddressList(v)
			if err != nil {
				continue
			}
			for _, a := range list {
				if a.Address != "" {
					out = append(out, candidate{addr: a.Address, reason: "delivered-to"})
				}
			}
		}
	}
	return out
}

// matchCatchAll applies rule 3 of DI2.2: the first candidate that a
// reply_match pattern matches. It gives the identity of that pattern
// and the candidate address in lower case.
func matchCatchAll(acct config.Account, cands []candidate) (config.Identity, string, bool) {
	for _, c := range cands {
		if id, ok := acct.MatchReply(c.addr); ok {
			return id, strings.ToLower(c.addr), true
		}
	}
	return config.Identity{}, "", false
}

// formatFrom gives the From header value of an identity: the name and
// the address formatted by net/mail, or the bare address when the
// name is empty (DI2.2).
func formatFrom(name, addr string) string {
	if strings.TrimSpace(name) == "" {
		return addr
	}
	return (&netmail.Address{Name: name, Address: addr}).String()
}

// pickNote is the sentence of the draft Note that tells which identity
// a draft got, and why (DI2.3). added tells whether the draft carries
// the signature of that identity.
//
// arch: DI2.3
func pickNote(p picked, added bool) string {
	sig := "No signature."
	if added {
		sig = "Signature added."
	}
	return fmt.Sprintf("From %s: identity %s, picked by %s. %s", p.Addr, p.Identity.Email, p.Reason, sig)
}

// replyDrop is the drop list of a reply in identity mode: the own
// addresses of the account and the picked From address, so a
// catch-all address does not get a copy of its own reply (DI2.4).
//
// arch: DI2.4
func replyDrop(acct config.Account, p picked) []string {
	return append(selfAddresses(acct), p.Addr)
}
