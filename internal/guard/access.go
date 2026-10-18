// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"errors"
	"fmt"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// Level is one access level of §3.17. The three levels are ordered:
// read permits the tools that only look at a mailbox, draft permits a
// change of a mailbox, and send permits a message to leave.
//
// arch: T5.4, §3.17, D5, §10.5
type Level string

// The three levels of §3.17, as accounts.toml spells them.
const (
	LevelRead  Level = "read"
	LevelDraft Level = "draft"
	LevelSend  Level = "send"
)

// ErrAccessDenied is returned when the level of an account does not
// cover the level a tool needs (§3.17, D5). A tool must report it and
// stop. It must never do a part of the work instead. The draft tool
// needs LevelDraft and the send tool needs LevelSend (D5.1), so a
// send on a draft account fails and its draft stays in the mailbox.
//
// arch: T5.4, §3.17, D5, D5.1, §10.5
var ErrAccessDenied = errors.New("guard: the access level of the account does not permit this")

// rank gives the order of the three levels. An unknown level gets the
// rank of draft, which is the level [config.Load] gives an account
// that names none (D5). Only a hand-built [config.Account] can carry
// an unknown level: config.Load fills in "draft" and refuses any
// value that is not one of the three (config.ErrUnknownAccess).
//
// The choice of draft, and not send, is the fail-closed one: a value
// this function cannot read never permits a message to leave.
func rank(l Level) int {
	switch l {
	case LevelRead:
		return 1
	case LevelSend:
		return 3
	default:
		return 2 // draft, and every value this function cannot read
	}
}

// LevelOf gives the access level of acct, with the default of D5 for
// an account that names none.
//
// arch: T5.4, §3.17, D5
func LevelOf(acct config.Account) Level {
	switch Level(acct.Access) {
	case LevelRead:
		return LevelRead
	case LevelSend:
		return LevelSend
	default:
		return LevelDraft
	}
}

// Permits reports whether an account at level have may do work that
// needs level need.
//
// arch: T5.4, §3.17, §10.5
func Permits(have, need Level) bool {
	return rank(have) >= rank(need)
}

// Require is the first line of each tool handler (§3.17): it fails
// when the account may not do the work the tool is about to do.
//
// The check is in code and not in the instructions text, because an
// instruction is advice to a model and a check is a rule (D5). The
// extras list of accounts.toml controls the size of the tool list
// only; this function is the security control (G9).
//
// The error names the alias, the level the account has and the level
// the work needs, then the line of accounts.toml that changes it. It
// holds no address, no subject and no secret, so the call-end log and
// the tool result can both carry it (§10.5, §3.19).
//
// arch: T5.4, §3.17, §3.16, D5, G9, §10.5
func Require(acct config.Account, need Level) error {
	have := LevelOf(acct)
	if Permits(have, need) {
		return nil
	}
	alias := acct.Alias
	if alias == "" {
		alias = "this account"
	}
	return fmt.Errorf("%w: account %s has access=%s and this needs access=%s; set access = %q in accounts.toml to permit it",
		ErrAccessDenied, alias, have, need, need)
}
