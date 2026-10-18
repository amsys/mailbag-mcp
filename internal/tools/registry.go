// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterCore adds the six core tools of D2.1 (accounts, folders,
// search, read, attachment, export) and the D1.2 middleware to srv.
// They are always on. It runs once, before serving starts. The write
// tools are not here: send and modify are toolsets that
// [RegisterToolsets] adds, off by default (D2.1, D2.2).
//
// The mail tools share one [Factory], so they share one IMAP pool and
// one credential cache. RegisterCore builds it and gives it back, so
// the process that serves can run the pool reaper and close every
// connection at shutdown (§3.1 steps 5 and 7). The same Factory goes
// to RegisterToolsets, so a toolset uses the same pool.
//
// arch: T1.5, T4.5, §3.16, §3.1, §9 U7, D1.2, D2.1, D2.2
func RegisterCore(srv *mcp.Server, logger *slog.Logger) *Factory {
	srv.AddReceivingMiddleware(stripOutputSchema)
	f := NewFactory(logger)
	AddAccounts(srv, logger, f.AuthState) // DR1G.18.5: the state of this Factory
	AddFolders(srv, logger, f)
	AddSearch(srv, logger, f)
	AddRead(srv, logger, f)
	AddAttachment(srv, logger, f)
	AddExport(srv, logger, f)
	return f
}

// Toolsets gives the toolset groups of D2.1: decrypt, modify and send
// in name order, then the four S9 groups unsubscribe, bulk, templates
// and gmail_settings in the order of DS9.8. Each call gives new
// values, so a caller cannot change the set that [RegisterToolsets]
// registers.
//
// The "send" toolset holds the draft and send tools (D5.1). The
// "decrypt" toolset holds the decrypt tool (D7.2). Each S9 group
// holds one tool of the same name, and each group name is a key of
// config's knownExtras, so every extras name has code (DS9.8). The
// "decrypt" group needs no gate of its own here:
// config.Config.Extras gives "decrypt" only when both [decrypt] keys
// are also true (D7.1), and Serve passes that list to
// [RegisterToolsets] and [Registry.Sync].
//
// The "send" group's Add closure captures one sendTool, built here,
// once per call of Toolsets. Every Enable of "send" on the Registry
// this call feeds gives that same tool to [addSend], so the
// idempotency key store (D5.3) and the send limit (§3.11) live as
// long as the server, not as long as one Enable (DRV.7, IRV.5). The
// closure still reads mail and logger from its own call: those two
// values never change between one server's Enable calls, so setting
// them again is free, but the tool itself — and so its state — does
// not rebuild.
//
// arch: D2.1, D2.2, D5.1, D7.1, D7.2, DRV.7, IRV.5, DS9.8, G20
func Toolsets() []ExtraGroup {
	sendState := &sendTool{}
	return []ExtraGroup{
		{
			Name:  "decrypt",
			Add:   func(srv *mcp.Server, logger *slog.Logger, f *Factory) { AddDecrypt(srv, logger, f) },
			Tools: []string{"decrypt"},
		},
		{
			Name:  "modify",
			Add:   func(srv *mcp.Server, logger *slog.Logger, f *Factory) { AddModify(srv, logger, f) },
			Tools: []string{"modify"},
		},
		{
			Name: "send",
			Add: func(srv *mcp.Server, logger *slog.Logger, f *Factory) {
				AddDraft(srv, logger, f)
				sendState.mail = f
				sendState.logger = logger
				addSend(srv, sendState)
			},
			Tools: []string{"draft", "send"},
		},
		{
			Name:  "unsubscribe",
			Add:   func(srv *mcp.Server, logger *slog.Logger, f *Factory) { AddUnsubscribe(srv, logger, f) },
			Tools: []string{"unsubscribe"},
		},
		{
			Name:  "bulk",
			Add:   func(srv *mcp.Server, logger *slog.Logger, f *Factory) { AddBulk(srv, logger, f) },
			Tools: []string{"bulk"},
		},
		{
			Name:  "templates",
			Add:   func(srv *mcp.Server, logger *slog.Logger, f *Factory) { AddTemplates(srv, logger, f) },
			Tools: []string{"templates"},
		},
		{
			Name:  "gmail_settings",
			Add:   func(srv *mcp.Server, logger *slog.Logger, f *Factory) { AddGmailSettings(srv, logger, f) },
			Tools: []string{"gmail_settings"},
		},
	}
}

// RegisterToolsets builds a Registry with every group of [Toolsets],
// all off, then enables each name in on. f is the Factory that
// [RegisterCore] returned. An unknown name in on is an error, and
// then no group is enabled: a typo must not give a half-applied set.
//
// arch: D2.1, D2.2
func RegisterToolsets(srv *mcp.Server, logger *slog.Logger, f *Factory, on []string) (*Registry, error) {
	r := NewRegistry(logger, f)
	for _, g := range Toolsets() {
		r.AddExtra(g)
	}
	if err := r.Sync(srv, on); err != nil {
		return nil, err
	}
	return r, nil
}

// ExtraGroup is one off-by-default toolset of D2.1 (send, modify, and
// later decrypt and the §3.16 extras): a name, as accounts.toml's
// extras list spells it, the function that adds its tools to a live
// server, and the tool names that function adds, so
// [Registry.Disable] knows what to remove.
//
// Add gets the Factory because send and modify need it (D2.2).
//
// arch: D2.1, D2.2
type ExtraGroup struct {
	Name  string
	Add   func(srv *mcp.Server, logger *slog.Logger, f *Factory)
	Tools []string
}

// Registry holds the extra tool groups a later stage has registered
// and which of them are on right now, so Enable and Disable can add
// or remove a whole group on a live *mcp.Server (owner decision,
// 2026-09-19: extras load at runtime; T9.4 drives this from
// accounts.toml's extras list and the SDK's own
// notifications/tools/list_changed does the rest, since AddTool and
// RemoveTools already send it).
//
// arch: T1.5, §3.16, §9 U7
type Registry struct {
	logger  *slog.Logger
	factory *Factory
	groups  map[string]ExtraGroup
	on      map[string]bool
}

// NewRegistry builds an empty Registry. logger and f are passed to
// each group's Add function; a nil logger is replaced with a discard
// logger, same as [Wrap].
func NewRegistry(logger *slog.Logger, f *Factory) *Registry {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Registry{logger: logger, factory: f, groups: map[string]ExtraGroup{}, on: map[string]bool{}}
}

// AddExtra registers g under g.Name, off by default. Calling it again
// with the same name replaces the group; it does not change whether
// that name is currently on.
func (r *Registry) AddExtra(g ExtraGroup) {
	r.groups[g.Name] = g
}

// Enable turns extra group name on for srv: it calls that group's Add
// function once. An unknown name, or a name already on, is a no-op,
// so a caller can call Enable for the whole extras list of
// accounts.toml without first checking what is already running.
func (r *Registry) Enable(srv *mcp.Server, name string) {
	g, ok := r.groups[name]
	if !ok || r.on[name] {
		return
	}
	g.Add(srv, r.logger, r.factory)
	r.on[name] = true
}

// Disable turns extra group name off for srv: mcp.Server.RemoveTools
// on every tool name that group's Add function added. An unknown
// name, or a name already off, is a no-op.
func (r *Registry) Disable(srv *mcp.Server, name string) {
	g, ok := r.groups[name]
	if !ok || !r.on[name] {
		return
	}
	srv.RemoveTools(g.Tools...)
	r.on[name] = false
}

// Sync enables and disables groups so that the set that is on equals
// want (D2.2). The SDK sends notifications/tools/list_changed for each
// tool that AddTool or RemoveTools changes. Sync checks every name
// first: an unknown name is an error, and then Sync changes nothing,
// so a bad accounts.toml keeps the old set (D2.3). A name that occurs
// two times in want counts one time.
//
// arch: D2.2, D2.3
func (r *Registry) Sync(srv *mcp.Server, want []string) error {
	wantOn := make(map[string]bool, len(want))
	for _, name := range want {
		if _, ok := r.groups[name]; !ok {
			return fmt.Errorf("tools: unknown toolset %q", name)
		}
		wantOn[name] = true
	}
	names := make([]string, 0, len(r.groups))
	for name := range r.groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if wantOn[name] {
			r.Enable(srv, name)
		} else {
			r.Disable(srv, name)
		}
	}
	return nil
}
