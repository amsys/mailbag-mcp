// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Test access to unexported state of package jmap, for the tests in
// package jmap_test (arch: DS14.15, DF.4).

package jmap

// LimitRetries gives how many requests postCapped sent again after the
// request error "limit", since the process started.
func LimitRetries() int64 { return limitRetries.Load() }

// ClientOf gives the client of p, so that a live test can send a raw
// method call.
func ClientOf(p *Provider) *Client { return p.c }
