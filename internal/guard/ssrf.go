// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The guarded HTTP client (§3.15, DS8.3) for a URL that a mail server
// gives us, such as a JMAP session URL or an unsubscribe link. The
// client resolves the host itself, refuses the bad address classes,
// and connects to the address that it checked.

package guard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// ssrfTimeout bounds the whole round trip (§3.15, T2.5, G8:
	// "10 second limit").
	ssrfTimeout = 10 * time.Second

	// MaxGuardedBody is how much of a response body a client from
	// NewHTTPClient returns before Read gives EOF (§3.15, T2.5, G8:
	// "Read 64 KB of the response at most").
	MaxGuardedBody = 64 * 1024

	// NoTimeout in HTTPOptions.Timeout sets no client time limit: the
	// request context deadline bounds the call (DS8.3).
	NoTimeout time.Duration = -1
)

// reasonPrivate is the badAddrReason class that HTTPOptions.PrivateHost
// allows for exactly one host name (DS8.3, G11).
const reasonPrivate = "private"

// cgnat is the carrier-grade NAT range (§3.15, T2.5, G8: "CGNAT
// (100.64.0.0/10)").
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// zeroPrefix is 0.0.0.0/8, "this network" (finding 7: distinct from
// the single unspecified address 0.0.0.0).
var zeroPrefix = netip.MustParsePrefix("0.0.0.0/8")

// siteLocalPrefix is the deprecated IPv6 site-local range (finding 7:
// not covered by IsPrivate or IsLinkLocalUnicast).
var siteLocalPrefix = netip.MustParsePrefix("fec0::/10")

// IPv6 forms that carry a real IPv4 address in their low bits. A dial
// check that only looks at the IPv6 shape misses a loopback or
// private target hiding behind one of these (finding 7).
var (
	nat64Prefix      = netip.MustParsePrefix("64:ff9b::/96")   // NAT64
	nat64LocalPrefix = netip.MustParsePrefix("64:ff9b:1::/48") // NAT64, RFC 8215 local-use (DRV.17)
	v4CompatPrefix   = netip.MustParsePrefix("::/96")          // IPv4-compatible
	sixToFourPrefix  = netip.MustParsePrefix("2002::/16")      // 6to4
)

// teredoPrefix is the Teredo tunneling range (DRV.17): refused
// outright, unlike the NAT64 forms above, because it does not carry
// a plain embedded IPv4 target worth decoding.
var teredoPrefix = netip.MustParsePrefix("2001::/32")

// rfc2544Prefix is the IPv4 benchmarking range RFC 2544 reserves
// (DRV.17).
var rfc2544Prefix = netip.MustParsePrefix("198.18.0.0/15")

// limitedBroadcast is the IPv4 limited broadcast address (DRV.17).
var limitedBroadcast = netip.MustParseAddr("255.255.255.255")

// errRedirectRefused is refuseRedirect's error (§3.15, T2.5, G8:
// "Follow no redirect").
var errRedirectRefused = errors.New("guard: redirect refused")

// ErrTruncated is the error a guarded response body's Read wraps once
// the real body held more than the cap of its client (finding 13: the
// cap used to end the body with a plain io.EOF, so a caller could not
// tell a cut response from a short one). Read returns it wrapped as
// "guard: response body truncated at <cap> bytes", so the text names
// the cap and errors.Is still finds it (DS78.11 G7). http.Client wraps
// every response body it hands back when it has a Timeout, but that
// wrapper passes a non-EOF, non-timeout Read error through unchanged,
// so ErrTruncated still reaches the caller through errors.Is, unlike a
// Truncated() method on the concrete body type, which the wrapper
// hides.
var ErrTruncated = errors.New("guard: response body truncated")

// HTTPOptions tune the guarded client for one caller (DS8.3). The zero
// value gives the client of T2.5: a 64 KiB body, 10 s, no private
// address, the system roots and the system resolver.
//
// arch: DS8.3, DS78.11 G4, G11
type HTTPOptions struct {
	// MaxBody caps the response body. 0 means MaxGuardedBody.
	MaxBody int64
	// Timeout bounds the whole round trip. 0 means 10 s. NoTimeout
	// means that the request context deadline bounds the call.
	Timeout time.Duration
	// PrivateHost is the one host name that may resolve to a private
	// address (netip.Addr.IsPrivate). "" means none. Loopback,
	// link-local, multicast, unspecified, CGNAT and the DRV.17 ranges
	// stay refused for it too (owner decision 2026-10-09 at the run
	// gate, G11).
	PrivateHost string
	// RootCAs are the roots that verify the server certificate. nil
	// means the system roots.
	RootCAs *x509.CertPool
	// LookupNetIP resolves a host name. nil means
	// net.DefaultResolver.LookupNetIP. A test sets it to map a name to
	// an address without DNS.
	LookupNetIP func(ctx context.Context, host string) ([]netip.Addr, error)
	// Base replaces the real transport and its checked dial. nil means
	// the real transport. Only a test sets it, to serve an httptest
	// handler in process. A client with Base set is not guarded
	// (IsGuarded is false), and RootCAs, LookupNetIP and PrivateHost
	// have no effect on it. The scheme check, the body cap and the
	// redirect refusal still apply.
	Base http.RoundTripper
}

// NewHTTPClient returns an http.Client for a URL a mail server gives
// us, such as a JMAP session URL or an unsubscribe link (§3.15
// "Network guard"). It is NewHTTPClientFor(HTTPOptions{}). It:
//
//   - resolves the host itself, checks every address, and connects to
//     the address that it checked, so a DNS answer that changes
//     between the check and the connect cannot pass (G8, DNS
//     rebinding);
//   - refuses a loopback, private, link-local, CGNAT, multicast,
//     unspecified, 0.0.0.0/8, site-local, Teredo, RFC 2544
//     benchmarking (198.18.0.0/15) or limited-broadcast
//     (255.255.255.255) address, after netip.Addr.Unmap(), and
//     refuses one of the bad classes hiding in the low bits of a
//     NAT64, NAT64 local-use, IPv4-compatible or 6to4 IPv6 address
//     (DRV.17);
//   - sets Proxy to nil, because a proxied dial would let the check
//     see the proxy's address instead of the real target;
//   - accepts only the "https" scheme;
//   - refuses every redirect;
//   - stops after 10 seconds;
//   - caps a response body at 64 KiB, and reports the cut with
//     ErrTruncated (from Read, and so from io.ReadAll) rather than
//     ending the body with a plain io.EOF.
//
// arch: T2.5, §3.15, G8, DS8.3
func NewHTTPClient() *http.Client {
	return NewHTTPClientFor(HTTPOptions{})
}

// NewHTTPClientFor returns the guarded client of NewHTTPClient with
// the body cap, the time limit, the one private host, the roots and
// the resolver that o gives (DS8.3). Every check of NewHTTPClient
// stays.
//
// arch: DS8.3, DS78.11 G4, G11
func NewHTTPClientFor(o HTTPOptions) *http.Client {
	return newHTTPClient(o, nil)
}

// dialFunc has the signature of net.Dialer.DialContext.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// newHTTPClient builds the client of NewHTTPClientFor. dial opens the
// socket to the checked IP address; nil means a plain net.Dialer. The
// tests of this package give a dial that records the address and opens
// no socket to it.
func newHTTPClient(o HTTPOptions, dial dialFunc) *http.Client {
	maxBody := o.MaxBody
	if maxBody <= 0 {
		maxBody = MaxGuardedBody
	}
	timeout := o.Timeout
	switch {
	case timeout == NoTimeout:
		timeout = 0 // http.Client: zero means no time limit.
	case timeout <= 0:
		timeout = ssrfTimeout
	}
	g := guardedTransport{next: o.Base, maxBody: maxBody}
	if o.Base == nil {
		lookup := o.LookupNetIP
		if lookup == nil {
			lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			}
		}
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		d := &checkedDialer{lookup: lookup, privateHost: o.PrivateHost, dial: dial}
		t := &http.Transport{
			Proxy:       nil,
			DialContext: d.DialContext,
		}
		if o.RootCAs != nil {
			t.TLSClientConfig = &tls.Config{RootCAs: o.RootCAs}
		}
		g.next = t
		g.checked = true
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     g,
		CheckRedirect: refuseRedirect,
	}
}

// IsGuarded reports whether c was built by NewHTTPClient or
// NewHTTPClientFor with Base == nil, and still refuses redirects. A
// test uses it to prove that a production constructor holds the
// guarded client (DS8.3, DS78.11 G4).
//
// arch: DS8.3, DS78.11 G4
func IsGuarded(c *http.Client) bool {
	if c == nil || c.CheckRedirect == nil {
		return false
	}
	g, ok := c.Transport.(guardedTransport)
	if !ok || !g.checked {
		return false
	}
	if _, ok := g.next.(*http.Transport); !ok {
		return false
	}
	// Only refuseRedirect can return errRedirectRefused, because the
	// sentinel is not exported.
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "redirect.invalid"}}
	return errors.Is(c.CheckRedirect(req, []*http.Request{req}), errRedirectRefused)
}

// refuseRedirect is the http.Client.CheckRedirect NewHTTPClient
// installs (§3.15, T2.5, G8: "Follow no redirect").
//
// arch: T2.5, §3.15, G8
func refuseRedirect(*http.Request, []*http.Request) error {
	return errRedirectRefused
}

// guardedTransport wraps an http.Transport to add the two checks a
// dialer cannot make: the URL scheme, and the response body size
// (§3.15, T2.5, G8).
//
// arch: T2.5, §3.15, G8, DS8.3
type guardedTransport struct {
	next http.RoundTripper
	// maxBody caps the response body. 0 means MaxGuardedBody.
	maxBody int64
	// checked is true when next is the *http.Transport with the
	// checked dial, that is when HTTPOptions.Base was nil (IsGuarded).
	checked bool
}

func (g guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("guard: scheme %q is not https", req.URL.Scheme)
	}
	resp, err := g.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	limit := g.maxBody
	if limit <= 0 {
		limit = MaxGuardedBody
	}
	resp.Body = &limitedBody{raw: resp.Body, closer: resp.Body, limit: limit, remaining: limit}
	return resp, nil
}

// CloseIdleConnections passes the call on to next. http.Client calls
// it only on a transport that has the method, so without it the idle
// sockets below the guard stay open (R16-L25).
func (g guardedTransport) CloseIdleConnections() {
	if c, ok := g.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// limitedBody caps Read at limit while still closing the real body it
// wraps. Once the cap is spent, Read returns ErrTruncated (wrapped with
// the cap) instead of io.EOF if the real body held more data, so a
// caller can tell a cut response from a short one even through
// http.Client's own body wrapper, which passes a non-EOF, non-timeout
// Read error through unchanged (finding 13: a truncated body used to
// fail silently).
//
// arch: T2.5, §3.15, G8, DS8.3
type limitedBody struct {
	raw         io.Reader
	closer      io.Closer
	limit       int64
	remaining   int64
	checkedTail bool
	truncated   bool
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		// The cap is spent. Read one more byte straight from the
		// real body, once, to learn whether there was more data
		// past the cap; that byte is discarded either way, so the
		// caller still sees exactly limit bytes.
		if !b.checkedTail {
			b.checkedTail = true
			var tail [1]byte
			if n, _ := b.raw.Read(tail[:]); n > 0 {
				b.truncated = true
			}
		}
		if b.truncated {
			return 0, fmt.Errorf("%w at %d bytes", ErrTruncated, b.limit)
		}
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.raw.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *limitedBody) Close() error { return b.closer.Close() }

// Truncated reports whether the response body held more than limit
// bytes. It needs the concrete *limitedBody type, which http.Client's
// own body wrapper hides from a caller of NewHTTPClient (finding 13);
// such a caller sees ErrTruncated from Read instead.
func (b *limitedBody) Truncated() bool { return b.truncated }

// checkedDialer is the DialContext of the guarded transport (DS8.3).
// It resolves the host through lookup, checks every address, drops the
// refused ones, and dials the first allowed address by IP. So the
// connect goes to the address that was checked, which closes the gap
// between check and connect (G8, DNS rebinding).
//
// arch: DS8.3, G8, G11
type checkedDialer struct {
	lookup      func(ctx context.Context, host string) ([]netip.Addr, error)
	privateHost string
	dial        dialFunc
}

// DialContext resolves, checks and dials one "host:port" address.
func (d *checkedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("guard: %w", err)
	}
	// Only a host that equals PrivateHost gets the private allowance.
	// Another name, or an IP literal, that leads to the same private
	// address does not (G11: that host only).
	allowPrivate := d.privateHost != "" && strings.EqualFold(host, d.privateHost)
	prefix := "guard: " + host + ": "
	var addrs []netip.Addr
	if literal, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{literal}
		prefix = "guard: "
	} else {
		addrs, err = d.lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("guard: resolve %s: %w", host, err)
		}
	}
	var refused error
	for _, addr := range addrs {
		addr = addr.Unmap()
		if cerr := checkAddr(addr, allowPrivate); cerr != nil {
			if refused == nil {
				refused = errors.New(prefix + cerr.Error())
			}
			continue
		}
		return d.dial(ctx, network, net.JoinHostPort(addr.String(), port))
	}
	if refused == nil {
		refused = fmt.Errorf("guard: %s has no address", host)
	}
	return nil, refused
}

// checkAddr returns an error that names the class of an address the
// guarded dial must refuse, or nil when the address is allowed. With
// allowPrivate, the class "private" passes. Every other class, and a
// private address hidden in an IPv6 form, stays refused (DS8.3, G11).
//
// arch: T2.5, §3.15, G8, DS8.3, G11
func checkAddr(addr netip.Addr, allowPrivate bool) error {
	if reason := badAddrReason(addr); reason != "" && (reason != reasonPrivate || !allowPrivate) {
		return fmt.Errorf("%s is a %s address", addr, reason)
	}
	if siteLocalPrefix.Contains(addr) {
		return fmt.Errorf("%s is a site-local address", addr)
	}
	// An IPv6 address can smuggle a loopback, private or otherwise
	// bad IPv4 target in its low bits (NAT64, IPv4-compatible, 6to4).
	// Check the embedded address too, not just the IPv6 shape
	// (finding 7).
	if embedded, ok := embeddedIPv4(addr); ok {
		if reason := badAddrReason(embedded); reason != "" {
			return fmt.Errorf("%s embeds %s, a %s address", addr, embedded, reason)
		}
	}
	return nil
}

// badAddrReason returns the class name of an address checkAddr must
// refuse, or "" when the address is allowed.
func badAddrReason(addr netip.Addr) string {
	switch {
	case addr.IsLoopback():
		return "loopback"
	case addr.IsPrivate():
		return reasonPrivate
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return "link-local"
	case addr.IsMulticast():
		return "multicast"
	case addr.IsUnspecified():
		return "unspecified"
	case addr.Is4() && cgnat.Contains(addr):
		return "CGNAT"
	case addr.Is4() && zeroPrefix.Contains(addr):
		return "0.0.0.0/8"
	case addr.Is4() && rfc2544Prefix.Contains(addr):
		return "198.18.0.0/15 (RFC 2544 benchmarking)"
	case addr.Is4() && addr == limitedBroadcast:
		return "broadcast"
	case addr.Is6() && teredoPrefix.Contains(addr):
		return "Teredo"
	}
	return ""
}

// embeddedIPv4 extracts the IPv4 address hidden in an IPv6 address
// that uses one of the embedding forms §3.15/finding 7 and DRV.17
// name: NAT64 (64:ff9b::/96), NAT64 local-use (64:ff9b:1::/48),
// IPv4-compatible (::/96) and 6to4 (2002::/16). It reports ok=false
// for any other address.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64Prefix.Contains(addr), v4CompatPrefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case nat64LocalPrefix.Contains(addr):
		// RFC 6052 §2.2, the /48 row: v4 bits 0-15 sit at bytes
		// 6-7, then a zero "u" byte at 8, then v4 bits 16-31 at
		// bytes 9-10.
		return netip.AddrFrom4([4]byte{b[6], b[7], b[9], b[10]}), true
	case sixToFourPrefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}
