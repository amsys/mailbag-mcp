// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools holds, in grant.go, the session grants of the bulk
// tool (DS14.11). A grant lets later bulk calls of one MCP session on
// one account run without the question.
package tools

import (
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// grantStore keeps the bulk grants of each MCP server session, in
// memory only. A grant names one session and one account alias. It
// ends when the session ends: a reconnect gives a new session, and a
// process exit removes the store. Nothing writes a grant to disk
// (DS14.11).
//
// One tool serves every MCP call of one process, and those calls can
// run at the same time, so every read and write of the map is under
// the mutex. The zero value works.
//
// arch: DS14.11
type grantStore struct {
	mu     sync.Mutex
	grants map[*mcp.ServerSession]map[string]bool
}

// has reports whether ss holds a grant for alias.
//
// arch: DS14.11
func (g *grantStore) has(ss *mcp.ServerSession, alias string) bool {
	if ss == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.grants[ss][alias]
}

// grant keeps a grant of ss for alias. The first grant of a session
// starts a goroutine that waits for the end of the session and then
// removes each grant of that session. A nil session or an empty alias
// gets no grant.
//
// arch: DS14.11
func (g *grantStore) grant(ss *mcp.ServerSession, alias string) {
	if ss == nil || alias == "" {
		return
	}
	g.mu.Lock()
	if g.grants == nil {
		g.grants = make(map[*mcp.ServerSession]map[string]bool)
	}
	first := g.grants[ss] == nil
	if first {
		g.grants[ss] = make(map[string]bool)
	}
	g.grants[ss][alias] = true
	g.mu.Unlock()
	if first {
		go func() {
			_ = ss.Wait()
			g.end(ss)
		}()
	}
}

// end removes each grant of ss.
//
// arch: DS14.11
func (g *grantStore) end(ss *mcp.ServerSession) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.grants, ss)
}
