//go:build linux

package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/config"
	"nvelox/core/metrics"
	"nvelox/proxy"
)

// Tests of PROXY protocol v2 on the HTTP listeners (accept_proxy_from):
// plain HTTP and HTTPS, HTTP/1.1 and HTTP/2, on the event loops and on
// net/http.

// relayHeader is the PROXY v2 header a relay sends for client (an
// "ip:port"; "" gives a LOCAL header), signed with key when it is set.
func relayHeader(t *testing.T, client string, key []byte) []byte {
	t.Helper()
	h := &proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
	if client != "" {
		src, err := net.ResolveTCPAddr("tcp", client)
		if err != nil {
			t.Fatal(err)
		}
		h.Command, h.TransportProtocol = proxyproto.PROXY, proxyproto.TCPv4
		h.SourceAddr, h.DestinationAddr = src, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
		if key != nil {
			if err := proxy.SignHeader(h, key, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	var b bytes.Buffer
	if _, err := h.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// relaySite is a site reached through relays in cidr (the tests' own
// address, 127.0.0.1, is one or not), plain or TLS.
func relaySite(t *testing.T, be *rawBackend, useTLS bool, cidr string, key []byte, mutate func(*ListenerConfig)) *HTTPServer {
	t.Helper()
	var keys [][]byte
	if key != nil {
		keys = [][]byte{key}
	}
	trust := proxy.NewTrust([]string{cidr}, keys)
	if useTLS {
		s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
		s.Listener.ProxyTrust = trust
		s.Listener.Timeouts.ReadHeader = "500ms"
		return s
	}
	// The listener is complete before the site is built from it.
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", ProxyTrust: trust}
	l.Timeouts.ReadHeader = "500ms"
	if mutate != nil {
		mutate(l)
	}
	return fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
}

func startRelayGroup(t *testing.T, s *HTTPServer, useTLS, fast bool) string {
	t.Helper()
	if useTLS {
		return startTLSGroup(t, s, fast)
	}
	return startTestGroup(t, s, fast)
}

// viaRelay opens a connection as a relay does: the header first, in the
// pieces given (one write each), then TLS when asked for, then the request.
// It returns the response, or the error that ended the connection.
func viaRelay(t *testing.T, addr string, useTLS bool, header [][]byte, request string) (*http.Response, string, error) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	for i, p := range header {
		if i > 0 {
			time.Sleep(20 * time.Millisecond)
		}
		if _, err := raw.Write(p); err != nil {
			return nil, "", err
		}
	}
	var c net.Conn = raw
	if useTLS {
		tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"http/1.1"}})
		if err := tc.Handshake(); err != nil {
			return nil, "", err
		}
		c = tc
	}
	if _, err := io.WriteString(c, request); err != nil {
		return nil, "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return nil, "", err
	}
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body), nil
}

const relayGet = "GET /ok HTTP/1.1\r\nHost: example.test\r\n\r\n"

// A trusted relay's header names the client for everything that looks at
// the peer; a relay that sends none, a broken one or a badly signed one is
// cut off; a LOCAL header makes the relay itself the client; anyone else's
// header is not looked at. The same on every path.
func TestProxyHeader_OnHTTPListeners(t *testing.T) {
	quietLog(t)
	key := []byte("0123456789abcdef0123456789abcdef-test-key")
	for _, useTLS := range []bool{false, true} {
		for _, fast := range []bool{true, false} {
			name := map[bool]string{false: "http", true: "https"}[useTLS] + map[bool]string{false: "/net-http", true: "/loops"}[fast]
			t.Run(name, func(t *testing.T) {
				be := newRawBackend(t)
				addr := startRelayGroup(t, relaySite(t, be, useTLS, "127.0.0.0/8", nil, nil), useTLS, fast)
				good := relayHeader(t, "203.0.113.7:4444", nil)

				// The header and the request in one go, and the header a
				// few bytes at a time.
				for _, pieces := range [][][]byte{{good}, {good[:5], good[5:13], good[13:17], good[17:]}} {
					resp, _, err := viaRelay(t, addr, useTLS, pieces, relayGet)
					if err != nil || resp.StatusCode != 200 {
						t.Fatalf("with a header in %d pieces: %v, %v", len(pieces), err, resp)
					}
					if req := be.last(); req.Header.Get("X-Forwarded-For") != "203.0.113.7" || req.Header.Get("X-Real-Ip") != "203.0.113.7" {
						t.Fatalf("the backend saw X-Forwarded-For %q, X-Real-Ip %q, want the client the relay named", req.Header.Get("X-Forwarded-For"), req.Header.Get("X-Real-Ip"))
					}
				}

				// LOCAL: the relay speaks for itself.
				if resp, _, err := viaRelay(t, addr, useTLS, [][]byte{relayHeader(t, "", nil)}, relayGet); err != nil || resp.StatusCode != 200 {
					t.Fatalf("LOCAL header: %v, %v", err, resp)
				}
				if got := be.last().Header.Get("X-Real-Ip"); got != "127.0.0.1" {
					t.Fatalf("LOCAL header: X-Real-Ip %q, want the relay", got)
				}

				// No header, and a broken one: no answer, and nothing
				// reaches the backend.
				before := be.count()
				bad := append([]byte(nil), good...)
				bad[12] = 0x31 // version 3
				for what, pieces := range map[string][][]byte{"no header": nil, "a broken header": {bad}, "half a header": {good[:14]}} {
					if resp, body, err := viaRelay(t, addr, useTLS, pieces, relayGet); err == nil {
						t.Fatalf("%s: answered %d %q, want the connection cut", what, resp.StatusCode, trunc(body))
					}
				}
				if be.count() != before {
					t.Fatalf("%d requests reached the backend from refused connections", be.count()-before)
				}
			})
		}
	}

	// Signed headers.
	for _, fast := range []bool{true, false} {
		be := newRawBackend(t)
		addr := startRelayGroup(t, relaySite(t, be, false, "127.0.0.0/8", key, nil), false, fast)
		if resp, _, err := viaRelay(t, addr, false, [][]byte{relayHeader(t, "203.0.113.7:4444", key)}, relayGet); err != nil || resp.StatusCode != 200 {
			t.Fatalf("fast=%v signed header: %v, %v", fast, err, resp)
		}
		for what, hdr := range map[string][]byte{"unsigned": relayHeader(t, "203.0.113.7:4444", nil), "signed with another key": relayHeader(t, "203.0.113.7:4444", []byte("another-key-another-key-another-key-0000"))} {
			if resp, _, err := viaRelay(t, addr, false, [][]byte{hdr}, relayGet); err == nil {
				t.Fatalf("fast=%v %s: answered %d, want the connection cut", fast, what, resp.StatusCode)
			}
		}
	}

	// A peer that is no relay: its header is garbage, as it always was.
	for _, fast := range []bool{true, false} {
		be := newRawBackend(t)
		addr := startRelayGroup(t, relaySite(t, be, false, "10.0.0.0/8", nil, nil), false, fast)
		if resp, _, err := viaRelay(t, addr, false, nil, relayGet); err != nil || resp.StatusCode != 200 {
			t.Fatalf("fast=%v direct client: %v, %v", fast, err, resp)
		}
		if resp, _, err := viaRelay(t, addr, false, [][]byte{relayHeader(t, "203.0.113.7:4444", nil)}, relayGet); err == nil && resp.StatusCode != 400 {
			t.Fatalf("fast=%v header from a peer that is no relay: status %d, want 400", fast, resp.StatusCode)
		}
		if be.count() != 1 {
			t.Fatalf("fast=%v the backend got %d requests, want 1", fast, be.count())
		}
	}
}

// The client a relay names is the one the access rules see, and the one
// trusted_proxies is checked against; a connection handed to net/http keeps
// it.
func TestProxyHeader_ClientIsThePeer(t *testing.T) {
	quietLog(t)
	for _, fast := range []bool{true, false} {
		be := newRawBackend(t)
		s := relaySite(t, be, false, "127.0.0.0/8", nil, func(l *ListenerConfig) {
			l.IPDenylist = []string{"198.51.100.0/24"}
			l.TrustedProxies = []string{"203.0.113.7/32"}
		})
		addr := startRelayGroup(t, s, false, fast)
		do := func(client, extra string) (*http.Response, *http.Request) {
			t.Helper()
			resp, _, err := viaRelay(t, addr, false, [][]byte{relayHeader(t, client, nil)}, "GET /ok HTTP/1.1\r\nHost: example.test\r\n"+extra+"\r\n")
			if err != nil {
				t.Fatalf("fast=%v client %s: %v", fast, client, err)
			}
			return resp, be.last()
		}
		// Denied by its own address, not the relay's.
		if resp, _ := do("198.51.100.9:1000", ""); resp.StatusCode != 403 {
			t.Fatalf("fast=%v denied client: status %d, want 403", fast, resp.StatusCode)
		}
		// A client that is itself a trusted proxy: its X-Forwarded-For is
		// believed and extended. Another client's is replaced.
		if _, req := do("203.0.113.7:1000", "X-Forwarded-For: 192.0.2.55\r\n"); req.Header.Get("X-Forwarded-For") != "192.0.2.55, 203.0.113.7" {
			t.Fatalf("fast=%v through a trusted proxy: X-Forwarded-For %q", fast, req.Header.Get("X-Forwarded-For"))
		}
		if _, req := do("203.0.113.99:1000", "X-Forwarded-For: 192.0.2.55\r\n"); req.Header.Get("X-Forwarded-For") != "203.0.113.99" {
			t.Fatalf("fast=%v from a client that is no trusted proxy: X-Forwarded-For %q", fast, req.Header.Get("X-Forwarded-For"))
		}
		// Handed over to net/http (a chunked request body): the client
		// stays the one the relay named.
		resp, _, err := viaRelay(t, addr, false, [][]byte{relayHeader(t, "203.0.113.50:1000", nil)},
			"POST /ok HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("fast=%v handed over: %v, %v", fast, err, resp)
		}
		if got := be.last().Header.Get("X-Real-Ip"); got != "203.0.113.50" {
			t.Fatalf("fast=%v handed over: X-Real-Ip %q", fast, got)
		}
	}
}

// HTTP/2 behind a relay: the header comes before the TLS handshake, and
// every stream's client is the one it names.
func TestProxyHeader_HTTP2(t *testing.T) {
	quietLog(t)
	for _, fast := range []bool{true, false} {
		be := newRawBackend(t)
		addr := startRelayGroup(t, relaySite(t, be, true, "127.0.0.0/8", nil, nil), true, fast)
		hdr := relayHeader(t, "203.0.113.7:4444", nil)
		tr := &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				raw, err := net.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				if _, err := raw.Write(hdr); err != nil {
					return nil, err
				}
				tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"h2", "http/1.1"}})
				if err := tc.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				return tc, nil
			},
		}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		for i := 0; i < 3; i++ {
			resp, err := client.Get("https://example.test/ok")
			if err != nil {
				t.Fatalf("fast=%v: %v", fast, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || resp.ProtoMajor != 2 {
				t.Fatalf("fast=%v: status %d over %s", fast, resp.StatusCode, resp.Proto)
			}
			if got := be.last().Header.Get("X-Real-Ip"); got != "203.0.113.7" {
				t.Fatalf("fast=%v: X-Real-Ip %q, want the client the relay named", fast, got)
			}
		}
	}
}

// A relay that starts a header and stops is cut off at the read-header
// limit.
func TestProxyHeader_SlowHeader(t *testing.T) {
	quietLog(t)
	for _, useTLS := range []bool{false, true} {
		for _, fast := range []bool{true, false} {
			be := newRawBackend(t)
			addr := startRelayGroup(t, relaySite(t, be, useTLS, "127.0.0.0/8", nil, nil), useTLS, fast)
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			c.Write(relayHeader(t, "203.0.113.7:4444", nil)[:10])
			c.SetReadDeadline(time.Now().Add(8 * time.Second))
			start := time.Now()
			_, err = c.Read(make([]byte, 1))
			c.Close()
			if err == nil || strings.Contains(err.Error(), "i/o timeout") {
				t.Fatalf("tls=%v fast=%v: the connection was not closed (%v)", useTLS, fast, err)
			}
			if d := time.Since(start); d < 400*time.Millisecond || d > 6*time.Second {
				t.Fatalf("tls=%v fast=%v: closed after %v, want about 500ms", useTLS, fast, d)
			}
		}
	}
}

// A reload that changes the relay list applies to new connections.
func TestProxyHeader_ReloadSwapsTrust(t *testing.T) {
	quietLog(t)
	be := newRawBackend(t)
	g := startFastGroup(t, relaySite(t, be, false, "127.0.0.0/8", nil, nil))
	addr := g.BoundAddr().String()
	hdr := relayHeader(t, "203.0.113.7:4444", nil)
	if resp, _, err := viaRelay(t, addr, false, [][]byte{hdr}, relayGet); err != nil || resp.StatusCode != 200 {
		t.Fatalf("before the reload: %v, %v", err, resp)
	}
	// The same listener without relays: the test's address is a plain
	// client now, and its header is garbage.
	if err := g.ReplaceSites([]*HTTPServer{relaySite(t, be, false, "10.0.0.0/8", nil, nil)}); err != nil {
		t.Fatal(err)
	}
	if resp, _, err := viaRelay(t, addr, false, nil, relayGet); err != nil || resp.StatusCode != 200 {
		t.Fatalf("after the reload, a direct request: %v, %v", err, resp)
	}
	if resp, _, err := viaRelay(t, addr, false, [][]byte{hdr}, relayGet); err == nil && resp.StatusCode != 400 {
		t.Fatalf("after the reload, a header: status %d, want 400", resp.StatusCode)
	}
}

// What a relay did wrong is counted by its reason, on every path; a relay
// that sent nothing (a TCP health check, a spare connection) is closed
// like any silent client, without a count.
func TestProxyHeader_RefusalsCounted(t *testing.T) {
	quietLog(t)
	key := []byte("0123456789abcdef0123456789abcdef-test-key")
	hdr := relayHeader(t, "203.0.113.7:4444", nil) // unsigned
	// The magic, then a TCP-over-IPv4 header 4 bytes long: too short for
	// its addresses.
	broken := append(append([]byte{}, proxy.V2Signature...), 0x21, 0x11, 0x00, 0x04, 1, 2, 3, 4)
	reasons := []string{proxyRejectMissing, proxyRejectMalformed, proxyRejectSignature, proxyRejectTimeout}
	cases := []struct {
		name  string
		send  []byte
		leave bool   // the relay closes after sending; else it waits to be closed
		want  string // the reason counted; "": none
	}{
		{"nothing, then gone", nil, true, ""},
		{"nothing to the limit", nil, false, ""},
		{"a request and no header", []byte(relayGet), false, proxyRejectMissing},
		{"half a header, then gone", hdr[:20], true, proxyRejectMalformed},
		{"half a header to the limit", hdr[:20], false, proxyRejectTimeout},
		{"a header that does not parse", broken, false, proxyRejectMalformed},
		{"an unsigned header", hdr, false, proxyRejectSignature},
	}
	for _, useTLS := range []bool{false, true} {
		for _, fast := range []bool{true, false} {
			name := map[bool]string{false: "http", true: "https"}[useTLS] + map[bool]string{false: "/net-http", true: "/loops"}[fast]
			t.Run(name, func(t *testing.T) {
				be := newRawBackend(t)
				s := relaySite(t, be, useTLS, "127.0.0.0/8", key, nil)
				addr := startRelayGroup(t, s, useTLS, fast)
				counts := func() (out [4]uint64) {
					for i, r := range reasons {
						out[i] = metrics.Default.GetCounter("nvelox_proxy_header_rejected_total", map[string]string{"listener": s.Listener.Name, "reason": r}).Get()
					}
					return out
				}
				for _, tc := range cases {
					before := counts()
					c, err := net.Dial("tcp", addr)
					if err != nil {
						t.Fatal(err)
					}
					if len(tc.send) > 0 {
						if _, err := c.Write(tc.send); err != nil {
							t.Fatal(err)
						}
					}
					if tc.leave {
						c.Close()
					} else {
						// The listener closes it: at once, or at the
						// read-header limit (500 ms).
						c.SetReadDeadline(time.Now().Add(8 * time.Second))
						_, err := io.Copy(io.Discard, c)
						c.Close()
						if err != nil && strings.Contains(err.Error(), "i/o timeout") {
							t.Fatalf("%s: the connection was not closed", tc.name)
						}
					}
					var want [4]uint64
					for i, r := range reasons {
						want[i] = before[i]
						if r == tc.want {
							want[i]++
						}
					}
					// The count is in before the listener closes; a relay
					// that left first is noticed a moment later.
					deadline := time.Now().Add(3 * time.Second)
					for counts() != want && time.Now().Before(deadline) {
						time.Sleep(10 * time.Millisecond)
					}
					if tc.want == "" {
						time.Sleep(150 * time.Millisecond) // nothing may arrive late either
					}
					if got := counts(); got != want {
						t.Errorf("%s: refusals by %v went from %v to %v, want %v", tc.name, reasons, before, got, want)
					}
				}
			})
		}
	}
}
