// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/secrets"
)

// addAccountHint is the "how to add an account" text of the accounts
// tool result (§3.16). Appendix C repeats the same command in the
// server instructions, so a model that already read them recognises
// it.
const addAccountHint = "no account yet; add one in a terminal with `mailbag-mcp account add`"

// AccountsIn takes no input (Appendix B): the tool reads
// accounts.toml itself.
type AccountsIn struct{}

// AccountRow is one line of the accounts tool result (§3.16): email,
// provider, access and identities come straight from accounts.toml.
// State is the sign-in state that this server process holds in memory
// (DS6.9, OR1G.1, DR1G.6.2). It is empty when no login result is known
// yet.
type AccountRow struct {
	Alias      string    `json:"alias"`
	Email      string    `json:"email"`
	Provider   string    `json:"provider"`
	Access     string    `json:"access"`
	Identities []string  `json:"identities,omitempty"`
	State      AuthState `json:"state,omitempty"`
	// IdentitySettings lists the identity tables of an account in
	// identity mode (DI4). It is empty for any other account.
	IdentitySettings []IdentityRow `json:"identity_settings,omitempty"`
}

// IdentityRow is one identity of an account in identity mode (DI4).
// Signature and SignatureHTML only say whether a signature is set. The
// row never holds signature text, so a model has no copy to retype
// (I8).
type IdentityRow struct {
	Email               string   `json:"email"`
	Name                string   `json:"name,omitempty"`
	Default             bool     `json:"default"`
	Signature           bool     `json:"signature"`
	SignatureHTML       bool     `json:"signature_html"`
	SignatureOnNew      bool     `json:"signature_on_new"`
	SignatureOnReply    bool     `json:"signature_on_reply"`
	SignatureOnForward  bool     `json:"signature_on_forward"`
	ReplyAboveQuote     bool     `json:"reply_above_quote"`
	SignatureBelowQuote bool     `json:"signature_below_quote"`
	ComposeHTML         bool     `json:"compose_html"`
	ReplyMatch          []string `json:"reply_match,omitempty"`
}

// identityRows builds the identity_settings rows of a. It returns nil
// when a is not in identity mode (DI2.0).
func identityRows(a config.Account) []IdentityRow {
	if !a.IdentityMode() {
		return nil
	}
	def := a.Default().Email
	rows := make([]IdentityRow, 0, len(a.IdentityList))
	for _, id := range a.IdentityList {
		rows = append(rows, IdentityRow{
			Email:               id.Email,
			Name:                id.Name,
			Default:             strings.EqualFold(id.Email, def),
			Signature:           id.Signature != "",
			SignatureHTML:       id.SignatureHTML != "",
			SignatureOnNew:      id.OnNew,
			SignatureOnReply:    id.OnReply,
			SignatureOnForward:  id.OnForward,
			ReplyAboveQuote:     id.ReplyAboveQuote,
			SignatureBelowQuote: id.SignatureBelowQuote,
			ComposeHTML:         id.ComposeHTML,
			ReplyMatch:          id.ReplyMatch,
		})
	}
	return rows
}

// AccountsOut is the accounts tool result (§3.16).
type AccountsOut struct {
	Accounts []AccountRow `json:"accounts"`
	// Secrets is "keyring" or "file", the active secrets store (§3.4).
	Secrets string `json:"secrets"`
	// AddHint is the command that adds an account. It is set only
	// when Accounts is empty, so a model with accounts configured
	// never sees it.
	AddHint string `json:"add_hint,omitempty"`
}

// AddAccounts adds the "accounts" tool to srv (§3.16): read level, no
// arguments, ReadOnlyHint true because it only reads accounts.toml.
// states gives the in-memory sign-in state of an alias; RegisterCore
// passes [Factory.AuthState] (DR1G.18.5). A nil states leaves the
// state column empty.
//
// arch: T1.5, §3.16, §9 U7, DR1G.6, DR1G.18
func AddAccounts(srv *mcp.Server, logger *slog.Logger, states func(alias string) AuthState) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "accounts",
		Description: "List configured mail accounts: alias, provider, access level and identities, and the active secrets store. Takes no arguments.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, Wrap(logger, "accounts", DefaultTimeout, accountsHandler(states)))
}

// accountsHandler builds AccountsOut from the accounts.toml on disk
// right now (config.Load, not a cached snapshot: this tool is called
// rarely enough that a fresh read is simpler than plumbing a shared,
// refreshed *config.Config through the registry). A first run with no
// accounts.toml yet is not an error (§3.1 step 3 makes the same
// allowance at startup): it returns an empty account list and the add
// hint instead.
//
// It gives the handler as a closure over states, so each row gets the
// sign-in state that the server holds at call time (DR1G.6.2).
//
// arch: T1.5, §3.16, §9 U7, G1, DR1G.6
func accountsHandler(states func(alias string) AuthState) func(context.Context, AccountsIn) (AccountsOut, error) {
	return func(_ context.Context, _ AccountsIn) (AccountsOut, error) {
		return listAccounts(states)
	}
}

// listAccounts reads accounts.toml and builds the accounts tool
// result, with the state of each alias from states when it is not
// nil.
func listAccounts(states func(alias string) AuthState) (AccountsOut, error) {
	path, err := config.AccountsPath()
	if err != nil {
		return AccountsOut{}, err
	}

	cfg, err := config.Load(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return AccountsOut{Secrets: secrets.KindKeyring, AddHint: addAccountHint}, nil
		}
		return AccountsOut{}, err
	}

	aliases := cfg.Aliases()
	rows := make([]AccountRow, 0, len(aliases))
	for _, alias := range aliases {
		a, ok := cfg.Account(alias)
		if !ok {
			continue // cannot happen: alias came from cfg.Aliases() itself
		}
		row := AccountRow{
			Alias:      a.Alias,
			Email:      a.Email,
			Provider:   a.Provider,
			Access:     a.Access,
			Identities: a.Identities,

			IdentitySettings: identityRows(a),
		}
		if states != nil {
			row.State = states(alias)
		}
		rows = append(rows, row)
	}

	out := AccountsOut{Accounts: rows, Secrets: cfg.Secrets()}
	if len(rows) == 0 {
		out.AddHint = addAccountHint
	}
	return out, nil
}
