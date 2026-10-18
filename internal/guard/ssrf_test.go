// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the guarded HTTP client (§3.15, T2.5, DS8.3): the address
// classes, the checked dial, the one private host, the body cap, the
// time limit, the redirect refusal and IsGuarded. No test opens a
// socket to an address other than a loopback httptest server.

package guard

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// roundTripFunc adapts a function to http.RoundTripper, so a test can
// stand in for the real transport without a network dial.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestSSRF_DialGuard checks the address check of checkedDialer, the
// dialer of NewHTTPClient, against the address classes §3.15 names:
// loopback, private, a mapped IPv6 form of one of those, and
// link-local. It also checks CGNAT, multicast and unspecified, and
// one ordinary public address that must pass.
//
// arch: T2.5, §3.15, G8
func TestSSRF_DialGuard(t *testing.T) {
	cases := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"loopback_v4", "127.0.0.1:443", true},
		{"loopback_v6", "[::1]:443", true},
		{"loopback_mapped_v6", "[::ffff:127.0.0.1]:443", true},
		{"private_10", "10.0.0.5:443", true},
		{"private_192", "192.168.1.1:443", true},
		{"private_172", "172.16.0.1:443", true},
		{"link_local_v4", "169.254.1.1:443", true},
		{"link_local_v6", "[fe80::1]:443", true},
		{"cgnat", "100.64.0.1:443", true},
		{"multicast", "224.0.0.1:443", true},
		{"unspecified_v4", "0.0.0.0:443", true},
		{"unspecified_v6", "[::]:443", true},
		{"public", "93.184.216.34:443", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := dialLiteral(c.address)
			if c.wantErr && err == nil {
				t.Fatalf("dialLiteral(%q): want an error, got nil", c.address)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("dialLiteral(%q): want no error, got %v", c.address, err)
			}
		})
	}
}

// TestSSRF_NoProxy checks that the transport NewHTTPClient builds has
// Proxy set to nil, so a dial cannot go to a proxy instead of the
// checked address (§3.15, T2.5, G8).
//
// arch: T2.5, §3.15, G8
func TestSSRF_NoProxy(t *testing.T) {
	client := NewHTTPClient()
	guarded, ok := client.Transport.(guardedTransport)
	if !ok {
		t.Fatalf("client.Transport is a %T, want guardedTransport", client.Transport)
	}
	transport, ok := guarded.next.(*http.Transport)
	if !ok {
		t.Fatalf("guardedTransport.next is a %T, want *http.Transport", guarded.next)
	}
	if transport.Proxy != nil {
		t.Fatal("Transport.Proxy is set; a proxied dial would defeat the address check")
	}
}

// TestSSRF_Timeout checks the 10 second limit of §3.15.
//
// arch: T2.5, §3.15, G8
func TestSSRF_Timeout(t *testing.T) {
	if got := NewHTTPClient().Timeout; got != 10*time.Second {
		t.Fatalf("client.Timeout = %v, want 10s", got)
	}
}

// TestSSRF_RedirectRefused checks that every redirect is refused, not
// followed (§3.15, T2.5, G8).
//
// arch: T2.5, §3.15, G8
func TestSSRF_RedirectRefused(t *testing.T) {
	if err := refuseRedirect(nil, nil); !errors.Is(err, errRedirectRefused) {
		t.Fatalf("refuseRedirect() = %v, want errRedirectRefused", err)
	}
	if NewHTTPClient().CheckRedirect == nil {
		t.Fatal("client.CheckRedirect is nil; the default client follows redirects")
	}
}

// TestSSRF_HTTPSOnly checks that guardedTransport refuses a non-https
// scheme before it ever reaches the dialer (§3.15, T2.5, G8).
//
// arch: T2.5, §3.15, G8
func TestSSRF_HTTPSOnly(t *testing.T) {
	called := false
	g := guardedTransport{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("must not be called for a non-https scheme")
	})}
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	if _, err := g.RoundTrip(req); err == nil {
		t.Fatal("RoundTrip(http://...) = nil error, want a scheme refusal")
	}
	if called {
		t.Fatal("the wrapped transport dialed a non-https request")
	}
}

// TestSSRF_EmbeddedIPv4 checks that checkedDialer extracts and
// refuses a loopback or otherwise bad IPv4 address hidden in the low
// bits of a NAT64, IPv4-compatible or 6to4 IPv6 address, and that it
// refuses 0.0.0.0/8 and the deprecated IPv6 site-local range
// directly. A public 6to4 address must still pass (finding 7).
//
// arch: T2.5, §3.15, G8
func TestSSRF_EmbeddedIPv4(t *testing.T) {
	cases := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"nat64_loopback", "[64:ff9b::7f00:1]:443", true},
		{"nat64_metadata", "[64:ff9b::a9fe:a9fe]:443", true},
		{"ipv4_compatible_loopback", "[::7f00:1]:443", true},
		{"sixtofour_loopback", "[2002:7f00:1::]:443", true},
		{"sixtofour_public", "[2002:5db8:d822::]:443", false},
		{"this_network", "0.1.2.3:443", true},
		{"site_local", "[fec0::1]:443", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := dialLiteral(c.address)
			if c.wantErr && err == nil {
				t.Fatalf("dialLiteral(%q): want an error, got nil", c.address)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("dialLiteral(%q): want no error, got %v", c.address, err)
			}
		})
	}
}

// TestSSRF_ClientRefusesLoopback checks the whole client, not just
// checkedDialer in isolation: a real dial through NewHTTPClient to a
// loopback server must be refused. TestSSRF_DialGuard alone cannot
// catch a NewHTTPClient that stopped wiring the checked dial in
// (finding 9).
//
// arch: T2.5, §3.15, G8
func TestSSRF_ClientRefusesLoopback(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_, err := NewHTTPClient().Get(ts.URL)
	if err == nil {
		t.Fatal("NewHTTPClient().Get(loopback server) = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error = %v, want it to name a loopback refusal", err)
	}
}

// TestSSRF_TruncationSignalled checks that a caller can tell a
// response cut at MaxGuardedBody from one that ended on its own
// (finding 13: the cap used to truncate silently).
//
// arch: T2.5, §3.15, G8
func TestSSRF_TruncationSignalled(t *testing.T) {
	type truncater interface{ Truncated() bool }

	roundTrip := func(body string) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}
	}
	newRequest := func(t *testing.T) *http.Request {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		return req
	}

	t.Run("cut_body_reports_truncated", func(t *testing.T) {
		big := strings.Repeat("a", MaxGuardedBody+1000)
		g := guardedTransport{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return roundTrip(big), nil
		})}
		resp, err := g.RoundTrip(newRequest(t))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		got, err := io.ReadAll(resp.Body)
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("ReadAll err = %v, want ErrTruncated", err)
		}
		if len(got) != MaxGuardedBody {
			t.Fatalf("read %d bytes, want %d (MaxGuardedBody)", len(got), MaxGuardedBody)
		}
		tb, ok := resp.Body.(truncater)
		if !ok {
			t.Fatalf("resp.Body is a %T, want one with a Truncated() method", resp.Body)
		}
		if !tb.Truncated() {
			t.Fatal("Truncated() = false, want true for a body cut at MaxGuardedBody")
		}
	})

	t.Run("short_body_not_truncated", func(t *testing.T) {
		small := "hello"
		g := guardedTransport{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return roundTrip(small), nil
		})}
		resp, err := g.RoundTrip(newRequest(t))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if string(got) != small {
			t.Fatalf("got %q, want %q", got, small)
		}
		tb, ok := resp.Body.(truncater)
		if !ok {
			t.Fatalf("resp.Body is a %T, want one with a Truncated() method", resp.Body)
		}
		if tb.Truncated() {
			t.Fatal("Truncated() = true, want false for a body under the cap")
		}
	})

	// through_http_client_wrapping is the judge's finding 13
	// reproduction: NewHTTPClient always sets a non-zero Timeout, so
	// net/http's own Client.send wraps resp.Body in an unexported
	// cancelTimerBody before any caller sees it. A Truncated() method on
	// the concrete limitedBody type is then unreachable by type
	// assertion, because resp.Body is the wrapper, not limitedBody. This
	// reproduces that wrapping without the network guard (a loopback
	// dial would be refused before the body is ever read) by giving
	// http.Client the same non-zero Timeout and a guardedTransport, the
	// way NewHTTPClient does.
	t.Run("through_http_client_wrapping", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("a", MaxGuardedBody+1000)))
		}))
		defer ts.Close()

		client := &http.Client{
			Timeout:   ssrfTimeout,
			Transport: guardedTransport{next: ts.Client().Transport},
		}
		resp, err := client.Get(ts.URL)
		if err != nil {
			t.Fatalf("client.Get: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		got, err := io.ReadAll(resp.Body)
		if len(got) != MaxGuardedBody {
			t.Fatalf("read %d bytes, want %d (MaxGuardedBody)", len(got), MaxGuardedBody)
		}
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("ReadAll err = %v, want ErrTruncated even once http.Client has wrapped the body (finding 13)", err)
		}
	})
}

// TestSSRF_BodyCap checks that a response body reads at most
// MaxGuardedBody bytes (§3.15, T2.5, G8: "Read 64 KB of the response
// at most").
//
// arch: T2.5, §3.15, G8
func TestSSRF_BodyCap(t *testing.T) {
	big := strings.Repeat("a", MaxGuardedBody+1000)
	g := guardedTransport{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(big)),
		}, nil
	})}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	resp, err := g.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("ReadAll err = %v, want ErrTruncated", err)
	}
	if len(got) != MaxGuardedBody {
		t.Fatalf("read %d bytes, want %d (MaxGuardedBody)", len(got), MaxGuardedBody)
	}
}

// TestCheckDialAddr_Gaps checks the five address gaps DRV.17 found:
// the RFC 8215 local-use NAT64 range (64:ff9b:1::/48, which can embed
// a loopback or other bad IPv4 target the same way 64:ff9b::/96
// does), Teredo (2001::/32), the RFC 2544 benchmarking range
// (198.18.0.0/15) and the limited broadcast address
// (255.255.255.255). A NAT64 address that embeds an ordinary public
// IPv4 target must still pass.
//
// arch: DRV.17
func TestCheckDialAddr_Gaps(t *testing.T) {
	cases := []struct {
		name    string
		address string
		wantErr bool
	}{
		// 64:ff9b:1::/48 embedding 127.0.0.1 (RFC 6052 §2.2 /48
		// layout: v4 bytes at IPv6 bytes 6-7 and 9-10).
		{"nat64_local_loopback", "[64:ff9b:1:7f00:0:100:0:0]:443", true},
		// Same prefix embedding the public address 93.184.216.34.
		{"nat64_local_public", "[64:ff9b:1:5db8:d8:2200:0:0]:443", false},
		{"teredo", "[2001:0:4136:e378:8000:63bf:3fff:fdd2]:443", true},
		{"rfc2544_low", "198.18.0.1:443", true},
		{"rfc2544_high", "198.19.255.254:443", true},
		{"broadcast", "255.255.255.255:443", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := dialLiteral(c.address)
			if c.wantErr && err == nil {
				t.Fatalf("dialLiteral(%q): want an error, got nil", c.address)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("dialLiteral(%q): want no error, got %v", c.address, err)
			}
		})
	}
}

// dialLiteral gives address, an IP literal "host:port", to
// checkedDialer.DialContext with no private allowance. It gives the
// refusal of the dialer, or nil when the dialer reached the socket
// dial. The resolver has no answers, so a host that is not an IP
// literal fails too.
//
// arch: T2.5, §3.15, G8
func dialLiteral(address string) error {
	rd := &recordingDial{}
	d := &checkedDialer{lookup: newFakeResolver().lookup, dial: rd.dial}
	_, err := d.DialContext(context.Background(), "tcp", address)
	if errors.Is(err, errFakeDial) {
		return nil
	}
	return err
}

// errFakeDial is what recordingDial returns when it has no target, so
// a test sees that the dial was reached without a socket being opened.
var errFakeDial = errors.New("test: fake dial, no socket opened")

// fakeResolver stands in for net.DefaultResolver.LookupNetIP. It maps
// a host name to a list of answers: call n gets answers[min(n,
// len-1)], so a test can make a name change its answer between calls
// (DNS rebinding). It counts the calls for each name.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	calls   map[string]int
	err     error
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{answers: map[string][][]netip.Addr{}, calls: map[string]int{}}
}

// set gives host one fixed answer.
func (r *fakeResolver) set(host string, addrs ...string) *fakeResolver {
	return r.sequence(host, addrs)
}

// sequence gives host one answer for each call; the last answer
// repeats.
func (r *fakeResolver) sequence(host string, answers ...[]string) *fakeResolver {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range answers {
		var addrs []netip.Addr
		for _, s := range a {
			addrs = append(addrs, netip.MustParseAddr(s))
		}
		r.answers[host] = append(r.answers[host], addrs)
	}
	return r
}

func (r *fakeResolver) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.calls[host]
	r.calls[host]++
	if r.err != nil {
		return nil, r.err
	}
	answers, ok := r.answers[host]
	if !ok {
		return nil, fmt.Errorf("test: no answer for %q", host)
	}
	return answers[min(n, len(answers)-1)], nil
}

func (r *fakeResolver) count(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

// recordingDial stands in for the socket dial of the checked dialer.
// It records each address the dialer asks for. With to == "" it opens
// no socket and returns errFakeDial; else it opens the socket to `to`,
// a loopback httptest server that plays the checked address.
type recordingDial struct {
	mu    sync.Mutex
	addrs []string
	to    string
}

func (d *recordingDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	if d.to == "" {
		return nil, errFakeDial
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.to)
}

func (d *recordingDial) got() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.addrs)
}

// serveInProcess is an HTTPOptions.Base that serves h in process, with
// no socket (DS78.11 G4).
func serveInProcess(h http.Handler) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Result(), nil
	})
}

// TestNewHTTPClientFor_PrivateHostOnlyThatHost checks the LAN rule of
// G11: the PrivateHost name may resolve to a private address, and the
// client then dials that address and completes the TLS round trip
// with the RootCAs it was given. Another name that resolves to a
// private address, the private address as an IP literal, and the same
// name on a client without PrivateHost are refused before any dial.
//
// arch: DS8.3, DS78.9, IS8.1, G11
func TestNewHTTPClientFor_PrivateHostOnlyThatHost(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())

	// httptest's certificate names example.com, so the TLS check of
	// the name passes against the RootCAs above.
	res := newFakeResolver().
		set("example.com", "10.0.0.5").
		set("other.example.com", "10.0.0.6").
		set("ula.example.com", "fd00::5")
	dial := &recordingDial{to: ts.Listener.Addr().String()}
	c := newHTTPClient(HTTPOptions{
		PrivateHost: "example.com",
		RootCAs:     roots,
		LookupNetIP: res.lookup,
	}, dial.dial)
	defer c.CloseIdleConnections()

	resp, err := c.Get("https://example.com/")
	if err != nil {
		t.Fatalf("Get(PrivateHost) = %v, want the round trip to pass", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(body) != "ok" {
		t.Fatalf("body = %q, %v; want \"ok\", nil", body, err)
	}
	if got, want := dial.got(), []string{"10.0.0.5:443"}; !slices.Equal(got, want) {
		t.Fatalf("dialed %v, want %v (the checked private address of PrivateHost)", got, want)
	}

	for _, u := range []string{
		"https://other.example.com/", // another name, private answer
		"https://ula.example.com/",   // another name, IPv6 ULA answer
		"https://10.0.0.5/",          // the allowed address, as a literal
	} {
		_, err := c.Get(u)
		if err == nil || !strings.Contains(err.Error(), "private") {
			t.Fatalf("Get(%s) = %v, want a private address refusal", u, err)
		}
	}
	if got := dial.got(); len(got) != 1 {
		t.Fatalf("dialed %v, want no dial after the PrivateHost one", got)
	}

	// The same name on a client with no PrivateHost is refused: the
	// allowance comes only from the option (fail closed).
	plainDial := &recordingDial{to: ts.Listener.Addr().String()}
	plain := newHTTPClient(HTTPOptions{RootCAs: roots, LookupNetIP: res.lookup}, plainDial.dial)
	defer plain.CloseIdleConnections()
	if _, err := plain.Get("https://example.com/"); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("Get without PrivateHost = %v, want a private address refusal", err)
	}
	if got := plainDial.got(); len(got) != 0 {
		t.Fatalf("dialed %v without PrivateHost, want no dial", got)
	}
}

// TestNewHTTPClientFor_PrivateHostStillRefusesLoopback checks that
// PrivateHost allows the private class only: loopback, link-local,
// multicast, unspecified, 0.0.0.0/8, CGNAT, the DRV.17 ranges,
// site-local, and a bad address hidden in an IPv6 form (a private one
// too) stay refused for that host, and no dial happens.
//
// arch: DS8.3, DS78.9, IS8.1, G11
func TestNewHTTPClientFor_PrivateHostStillRefusesLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"::ffff:127.0.0.1", "loopback"},
		{"169.254.169.254", "link-local"},
		{"fe80::1", "link-local"},
		{"ff02::1", "link-local"},
		{"239.1.2.3", "multicast"},
		{"0.0.0.0", "unspecified"},
		{"::", "unspecified"},
		{"0.1.2.3", "0.0.0.0/8"},
		{"100.64.0.1", "CGNAT"},
		{"198.18.0.1", "RFC 2544"},
		{"255.255.255.255", "broadcast"},
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo"},
		{"fec0::1", "site-local"},
		{"64:ff9b::7f00:1", "loopback"},
		{"64:ff9b::a00:5", "private"},
		{"2002:a00:5::", "private"},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			res := newFakeResolver().set("mail.lan", tc.addr)
			dial := &recordingDial{}
			c := newHTTPClient(HTTPOptions{PrivateHost: "mail.lan", LookupNetIP: res.lookup}, dial.dial)
			defer c.CloseIdleConnections()
			_, err := c.Get("https://mail.lan/")
			if err == nil || errors.Is(err, errFakeDial) {
				t.Fatalf("Get = %v, want a refusal before the dial", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Get = %v, want it to name %q", err, tc.want)
			}
			if got := dial.got(); len(got) != 0 {
				t.Fatalf("dialed %v, want no dial", got)
			}
		})
	}
}

// TestNewHTTPClientFor_MaxBody checks the per-client body cap of
// DS8.3 through the whole client, with Base serving the body in
// process: a body at the cap reads whole, one byte more is cut at the
// cap with ErrTruncated whose text names the cap (DS78.11 G7), an
// answer above 64 KiB passes a larger cap (T176), and MaxBody 0 keeps
// the 64 KiB default.
//
// arch: DS8.3, DS78.9, IS8.1, G11
func TestNewHTTPClientFor_MaxBody(t *testing.T) {
	cases := []struct {
		name      string
		maxBody   int64
		size      int
		wantLen   int
		truncated bool
		wantText  string
	}{
		{"at_cap", 1000, 1000, 1000, false, ""},
		{"over_cap", 1000, 1001, 1000, true, "guard: response body truncated at 1000 bytes"},
		{"answer_above_64KiB", 8 << 20, 200 << 10, 200 << 10, false, ""},
		{"default_cap", 0, MaxGuardedBody + 1, MaxGuardedBody, true, "guard: response body truncated at 65536 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Repeat("a", tc.size)
			c := NewHTTPClientFor(HTTPOptions{
				MaxBody: tc.maxBody,
				Base: serveInProcess(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = io.WriteString(w, body)
				})),
			})
			resp, err := c.Get("https://jmap.example.test/api")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			got, err := io.ReadAll(resp.Body)
			if len(got) != tc.wantLen {
				t.Fatalf("read %d bytes, want %d", len(got), tc.wantLen)
			}
			if !tc.truncated {
				if err != nil {
					t.Fatalf("ReadAll err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrTruncated) {
				t.Fatalf("ReadAll err = %v, want ErrTruncated", err)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("ReadAll err = %q, want it to hold %q", err, tc.wantText)
			}
		})
	}
}

// TestNewHTTPClientFor_DialsCheckedIPOnly checks that the dialer
// resolves the host once, drops every refused answer, and dials the
// first allowed answer as an IP literal with the URL's port. A name
// whose answer changes after the check (DNS rebinding) is still
// dialed at the checked address, because no second lookup happens
// (G8). An IP literal needs no lookup. When every answer is refused,
// when the lookup fails, or when it gives no answer, no dial happens.
//
// arch: DS8.3, DS78.9, IS8.1, G11
func TestNewHTTPClientFor_DialsCheckedIPOnly(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		res         *fakeResolver
		privateHost string
		wantDial    []string
		wantErr     string // when wantDial is empty
		wantLookups int
	}{
		{
			name:        "first_allowed_answer",
			url:         "https://example.com/",
			res:         newFakeResolver().set("example.com", "127.0.0.1", "10.0.0.9", "93.184.216.34", "93.184.216.35"),
			wantDial:    []string{"93.184.216.34:443"},
			wantLookups: 1,
		},
		{
			name: "rebinding_answer_not_used",
			url:  "https://example.com/",
			res: newFakeResolver().sequence("example.com",
				[]string{"93.184.216.34"}, []string{"127.0.0.1"}),
			wantDial:    []string{"93.184.216.34:443"},
			wantLookups: 1,
		},
		{
			name:        "private_host_skips_loopback",
			url:         "https://example.com/",
			res:         newFakeResolver().set("example.com", "127.0.0.1", "10.0.0.5"),
			privateHost: "example.com",
			wantDial:    []string{"10.0.0.5:443"},
			wantLookups: 1,
		},
		{
			name:        "port_kept",
			url:         "https://example.com:8443/",
			res:         newFakeResolver().set("example.com", "93.184.216.34"),
			wantDial:    []string{"93.184.216.34:8443"},
			wantLookups: 1,
		},
		{
			name:        "mapped_answer_unmapped",
			url:         "https://example.com/",
			res:         newFakeResolver().set("example.com", "::ffff:93.184.216.34"),
			wantDial:    []string{"93.184.216.34:443"},
			wantLookups: 1,
		},
		{
			name:        "ipv6_answer",
			url:         "https://example.com/",
			res:         newFakeResolver().set("example.com", "2606:2800:220:1:248:1893:25c8:1946"),
			wantDial:    []string{"[2606:2800:220:1:248:1893:25c8:1946]:443"},
			wantLookups: 1,
		},
		{
			name:        "ip_literal_no_lookup",
			url:         "https://93.184.216.34/",
			res:         newFakeResolver(),
			wantDial:    []string{"93.184.216.34:443"},
			wantLookups: 0,
		},
		{
			name:        "every_answer_refused",
			url:         "https://example.com/",
			res:         newFakeResolver().set("example.com", "127.0.0.1", "10.0.0.9"),
			wantErr:     "guard: example.com: 127.0.0.1 is a loopback address",
			wantLookups: 1,
		},
		{
			name:        "no_answer",
			url:         "https://example.com/",
			res:         newFakeResolver().set("example.com"),
			wantErr:     "guard: example.com has no address",
			wantLookups: 1,
		},
		{
			name:        "lookup_fails",
			url:         "https://example.com/",
			res:         &fakeResolver{answers: map[string][][]netip.Addr{}, calls: map[string]int{}, err: errors.New("test: no such host")},
			wantErr:     "guard: resolve example.com",
			wantLookups: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dial := &recordingDial{}
			c := newHTTPClient(HTTPOptions{PrivateHost: tc.privateHost, LookupNetIP: tc.res.lookup}, dial.dial)
			defer c.CloseIdleConnections()
			_, err := c.Get(tc.url)
			if got := dial.got(); !slices.Equal(got, tc.wantDial) {
				t.Fatalf("dialed %v, want %v", got, tc.wantDial)
			}
			if len(tc.wantDial) > 0 {
				if !errors.Is(err, errFakeDial) {
					t.Fatalf("Get = %v, want the fake dial's error", err)
				}
				for _, a := range tc.wantDial {
					if _, perr := netip.ParseAddrPort(a); perr != nil {
						t.Fatalf("dialed %q, want an IP literal: %v", a, perr)
					}
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Get = %v, want it to hold %q", err, tc.wantErr)
			}
			host := strings.TrimSuffix(strings.TrimPrefix(tc.url, "https://"), "/")
			host, _, _ = strings.Cut(host, ":")
			if got := tc.res.count(host); got != tc.wantLookups {
				t.Fatalf("lookups of %q = %d, want %d", host, got, tc.wantLookups)
			}
		})
	}
}

// TestNewHTTPClient_Unchanged checks that NewHTTPClient is
// NewHTTPClientFor(HTTPOptions{}) and keeps the client of T2.5: 10 s,
// no proxy, the system roots, the checked dial, redirects refused,
// IsGuarded true, and a 64 KiB body cap that signals the cut with
// ErrTruncated, whose text now names the cap (DS78.11 G7).
//
// arch: DS8.3, DS78.9, IS8.1, G11
func TestNewHTTPClient_Unchanged(t *testing.T) {
	for name, c := range map[string]*http.Client{
		"NewHTTPClient":                   NewHTTPClient(),
		"NewHTTPClientFor(HTTPOptions{})": NewHTTPClientFor(HTTPOptions{}),
	} {
		t.Run(name, func(t *testing.T) {
			if c.Timeout != 10*time.Second {
				t.Fatalf("Timeout = %v, want 10s", c.Timeout)
			}
			if !errors.Is(c.CheckRedirect(nil, nil), errRedirectRefused) {
				t.Fatal("CheckRedirect does not refuse")
			}
			if !IsGuarded(c) {
				t.Fatal("IsGuarded = false, want true")
			}
			g, ok := c.Transport.(guardedTransport)
			if !ok {
				t.Fatalf("Transport is a %T, want guardedTransport", c.Transport)
			}
			if g.maxBody != MaxGuardedBody || MaxGuardedBody != 64*1024 {
				t.Fatalf("maxBody = %d, MaxGuardedBody = %d, want 65536", g.maxBody, MaxGuardedBody)
			}
			tr, ok := g.next.(*http.Transport)
			if !ok {
				t.Fatalf("next is a %T, want *http.Transport", g.next)
			}
			if tr.Proxy != nil || tr.DialContext == nil || tr.TLSClientConfig != nil {
				t.Fatalf("transport: Proxy set %v, DialContext set %v, TLSClientConfig %v; want nil, set, nil",
					tr.Proxy != nil, tr.DialContext != nil, tr.TLSClientConfig)
			}

			// The default cap on this client's own guardedTransport.
			g.next = roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(strings.Repeat("a", MaxGuardedBody+1))),
				}, nil
			})
			req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
			if err != nil {
				t.Fatalf("http.NewRequest: %v", err)
			}
			resp, err := g.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			got, err := io.ReadAll(resp.Body)
			if len(got) != MaxGuardedBody || !errors.Is(err, ErrTruncated) {
				t.Fatalf("read %d bytes, err %v; want %d and ErrTruncated", len(got), err, MaxGuardedBody)
			}
			if err.Error() != "guard: response body truncated at 65536 bytes" {
				t.Fatalf("err = %q, want the text that names the 64 KiB cap", err)
			}
		})
	}
	if ErrTruncated.Error() != "guard: response body truncated" {
		t.Fatalf("ErrTruncated = %q, want \"guard: response body truncated\"", ErrTruncated)
	}
}

// TestNewHTTPClientFor_Timeout checks the Timeout option: 0 keeps
// 10 s, NoTimeout leaves the limit to the request context, a positive
// value is used as it is, and any other negative value fails closed to
// 10 s.
//
// arch: DS8.3, DS78.9, IS8.1, G11
func TestNewHTTPClientFor_Timeout(t *testing.T) {
	cases := []struct {
		in, want time.Duration
	}{
		{0, 10 * time.Second},
		{NoTimeout, 0},
		{3 * time.Second, 3 * time.Second},
		{-5, 10 * time.Second},
	}
	for _, tc := range cases {
		if got := NewHTTPClientFor(HTTPOptions{Timeout: tc.in}).Timeout; got != tc.want {
			t.Fatalf("Timeout %v: client Timeout = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestIsGuarded checks that IsGuarded is true only for a client built
// here with Base == nil that still refuses redirects (DS78.11 G4).
//
// arch: DS8.3, DS78.9, IS8.1, G11
func TestIsGuarded(t *testing.T) {
	full := NewHTTPClientFor(HTTPOptions{
		MaxBody:     8 << 20,
		Timeout:     NoTimeout,
		PrivateHost: "mail.lan",
		RootCAs:     x509.NewCertPool(),
		LookupNetIP: newFakeResolver().lookup,
	})
	copied := *full
	followsRedirects := *full
	followsRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	noRedirectCheck := *full
	noRedirectCheck.CheckRedirect = nil
	otherTransport := *full
	otherTransport.Transport = http.DefaultTransport

	cases := []struct {
		name string
		c    *http.Client
		want bool
	}{
		{"NewHTTPClient", NewHTTPClient(), true},
		{"NewHTTPClientFor_all_options", full, true},
		{"copy_of_guarded", &copied, true},
		{"with_Base", NewHTTPClientFor(HTTPOptions{Base: serveInProcess(http.NotFoundHandler())}), false},
		{"nil", nil, false},
		{"zero_client", &http.Client{}, false},
		{"default_client", http.DefaultClient, false},
		{"redirects_followed", &followsRedirects, false},
		{"redirect_check_removed", &noRedirectCheck, false},
		{"transport_replaced", &otherTransport, false},
	}
	for _, tc := range cases {
		if got := IsGuarded(tc.c); got != tc.want {
			t.Errorf("IsGuarded(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestNewHTTPClientFor_BaseKeepsChecks checks that a client with Base
// (the test seam of DS78.11 G4) still refuses a scheme other than
// https before Base runs, and still refuses a redirect.
//
// arch: DS8.3, DS78.9, IS8.1, G11
func TestNewHTTPClientFor_BaseKeepsChecks(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	c := NewHTTPClientFor(HTTPOptions{Base: serveInProcess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		http.Redirect(w, r, "https://elsewhere.example.test/", http.StatusFound)
	}))})

	if _, err := c.Get("http://jmap.example.test/"); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("Get(http://) = %v, want a scheme refusal", err)
	}
	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 0 {
		t.Fatalf("Base ran %d times for an http URL, want 0", n)
	}

	resp, err := c.Get("https://jmap.example.test/")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, errRedirectRefused) {
		t.Fatalf("Get(redirect) = %v, want errRedirectRefused", err)
	}
}

// idleCounter is a RoundTripper that counts CloseIdleConnections.
type idleCounter struct{ closed int }

func (c *idleCounter) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not used")
}

func (c *idleCounter) CloseIdleConnections() { c.closed++ }

// TestGuardedTransport_ForwardsCloseIdle checks that CloseIdleConnections
// on a guarded client reaches the transport below the guard. Without
// it, http.Client drops the call and the idle sockets of an old JMAP
// client stay open.
//
// arch: G8, R16-L25
func TestGuardedTransport_ForwardsCloseIdle(t *testing.T) {
	base := &idleCounter{}
	c := NewHTTPClientFor(HTTPOptions{Base: base})
	c.CloseIdleConnections()
	if base.closed != 1 {
		t.Errorf("CloseIdleConnections reached the base %d times, want 1", base.closed)
	}
}
