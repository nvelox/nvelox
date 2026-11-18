//go:build linux

package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/proxy"

	"github.com/pires/go-proxyproto"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// PROXY protocol v2 to HTTP backends (send_proxy_v2): the tests run a
// backend that insists on a header at the start of every connection, and
// check on every path (the event loops, net/http, HTTP/2, HTTP/3) whom the
// header names, that a backend connection serves one client connection
// only, and that it ends with it.

// proxyBackend is an HTTP/1.1 server that requires a PROXY protocol v2
// header at the start of every connection, as a server set up for
// send_proxy_v2 does. Its answer to a request says which of its connections
// the request came on and whom that connection's header named.
type proxyBackend struct {
	t   *testing.T
	ln  net.Listener
	tls *tls.Config // set: TLS follows the header
	key []byte      // set: the header must carry a signature made with it

	mu    sync.Mutex
	conns []*proxyBackendConn
	bad   []string // connections refused, with the reason
	// gate, when set, makes the answers to /hold wait until it is closed;
	// held counts the requests that wait.
	gate chan struct{}
	held int
}

type proxyBackendConn struct {
	local    bool   // a LOCAL header
	src, dst string // what a PROXY header named
	stream   bool   // it named a stream (TCP) client
	signed   uint64 // the time its signature carries (unix seconds); 0: not signed
	requests int
	closed   bool
}

func newProxyBackend(t *testing.T, tlsCfg *tls.Config, key []byte) *proxyBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &proxyBackend{t: t, ln: ln, tls: tlsCfg, key: key}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(c)
		}
	}()
	return b
}

func (b *proxyBackend) addr() string { return b.ln.Addr().String() }

func (b *proxyBackend) refuse(c net.Conn, why string) {
	b.mu.Lock()
	b.bad = append(b.bad, why)
	b.mu.Unlock()
	c.Close()
}

// bufConn reads through the reader that took the header.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (b *proxyBackend) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr, err := proxyproto.Read(br)
	if err != nil {
		b.refuse(c, "no PROXY header: "+err.Error())
		return
	}
	c.SetReadDeadline(time.Time{})
	rec := &proxyBackendConn{}
	if hdr.Command == proxyproto.LOCAL {
		rec.local = true
	} else {
		rec.src, rec.dst = hdr.SourceAddr.String(), hdr.DestinationAddr.String()
		rec.stream = hdr.TransportProtocol.IsStream()
		if b.key != nil {
			if err := proxy.Verify(hdr, [][]byte{b.key}, nil, time.Now()); err != nil {
				b.refuse(c, "signature: "+err.Error())
				return
			}
		}
		if tlvs, err := hdr.TLVs(); err == nil {
			for _, tlv := range tlvs {
				if tlv.Type == proxy.SignatureTLV && len(tlv.Value) >= 9 {
					rec.signed = binary.BigEndian.Uint64(tlv.Value[1:9])
				}
			}
		}
	}
	b.mu.Lock()
	n := len(b.conns)
	b.conns = append(b.conns, rec)
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		rec.closed = true
		b.mu.Unlock()
	}()
	var rw net.Conn = &bufConn{Conn: c, r: br}
	if b.tls != nil {
		tc := tls.Server(rw, b.tls)
		if err := tc.Handshake(); err != nil {
			b.mu.Lock()
			b.bad = append(b.bad, "TLS handshake after the header: "+err.Error())
			b.mu.Unlock()
			return
		}
		rw, br = tc, bufio.NewReader(tc)
	}
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		io.Copy(io.Discard, req.Body)
		b.mu.Lock()
		rec.requests++
		b.mu.Unlock()
		if req.URL.Path == "/hold" {
			b.mu.Lock()
			gate := b.gate
			b.held++
			b.mu.Unlock()
			if gate != nil {
				<-gate
			}
			b.mu.Lock()
			b.held--
			b.mu.Unlock()
		}
		body := fmt.Sprintf("conn=%d src=%s dst=%s path=%s", n, rec.src, rec.dst, req.URL.Path)
		if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			// The upgraded stream starts with the same answer, on a line,
			// then echoes.
			io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"+body+"\n")
			io.Copy(rw, br)
			return
		}
		fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}
}

// noneRefused fails the test when the backend got a connection without a
// valid header.
func (b *proxyBackend) noneRefused() {
	b.t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.bad) > 0 {
		b.t.Errorf("the backend refused %d connections: %v", len(b.bad), b.bad)
	}
}

// open counts the backend's connections that are not closed.
func (b *proxyBackend) open() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, c := range b.conns {
		if !c.closed {
			n++
		}
	}
	return n
}

func (b *proxyBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.conns)
}

// waitOpen waits until the backend has want open connections.
func (b *proxyBackend) waitOpen(what string, want int) {
	b.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for b.open() != want {
		if time.Now().After(deadline) {
			b.t.Fatalf("%s: the backend has %d open connections, want %d", what, b.open(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// hold makes the answers to /hold wait; release lets them go.
func (b *proxyBackend) hold()    { b.mu.Lock(); b.gate = make(chan struct{}); b.mu.Unlock() }
func (b *proxyBackend) release() { b.mu.Lock(); close(b.gate); b.gate = nil; b.mu.Unlock() }

// waitHeld waits until want requests wait for the gate at the same time.
func (b *proxyBackend) waitHeld(want int) {
	b.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b.mu.Lock()
		held := b.held
		b.mu.Unlock()
		if held == want {
			return
		}
		if time.Now().After(deadline) {
			b.t.Fatalf("%d requests wait at the backend, want %d at once", held, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// proxyAnswer is a proxyBackend's answer, taken apart.
type proxyAnswer struct {
	conn     int
	src, dst string
}

func parseProxyAnswer(t *testing.T, body string) proxyAnswer {
	t.Helper()
	var a proxyAnswer
	var path string
	// src and dst are empty for a LOCAL header: Sscanf then fails, on purpose.
	if _, err := fmt.Sscanf(body, "conn=%d src=%s dst=%s path=%s", &a.conn, &a.src, &a.dst, &path); err != nil {
		t.Fatalf("backend answer %q: %v", body, err)
	}
	return a
}

// kaClient is an HTTP/1.1 client that keeps its one connection.
type kaClient struct {
	t  *testing.T
	c  net.Conn
	br *bufio.Reader
}

func dialKA(t *testing.T, addr string, tlsCfg *tls.Config) *kaClient {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		tc := tls.Client(c, tlsCfg)
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		c = tc
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(20 * time.Second))
	return &kaClient{t: t, c: c, br: bufio.NewReader(c)}
}

// local is the client's own address, as the proxy sees it.
func (k *kaClient) local() string { return k.c.LocalAddr().String() }

func (k *kaClient) get(path string) (int, string) {
	k.t.Helper()
	if _, err := io.WriteString(k.c, "GET "+path+" HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		k.t.Fatal(err)
	}
	resp, err := http.ReadResponse(k.br, nil)
	if err != nil {
		k.t.Fatalf("GET %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(body)
}

func (k *kaClient) answer(path string) proxyAnswer {
	k.t.Helper()
	code, body := k.get(path)
	if code != 200 {
		k.t.Fatalf("GET %s: %d %q", path, code, body)
	}
	return parseProxyAnswer(k.t, body)
}

var h1TLS = &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"http/1.1"}}

func paths(fast bool) string {
	if fast {
		return "event loops"
	}
	return "net/http"
}

// Every connection to the backend starts with the header of the one client
// connection it serves: that client's requests reuse it, another client's
// never do, and it is closed when its client goes. HTTP and HTTPS
// listeners, on the event loops and on net/http.
func TestSendProxy_OwnConnections(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		for _, fast := range []bool{true, false} {
			name := fmt.Sprintf("tls=%v/%s", useTLS, paths(fast))
			t.Run(name, func(t *testing.T) {
				be := newProxyBackend(t, nil, nil)
				backend := &config.Backend{Servers: []string{be.addr()}, SendProxyV2: true}
				var addr string
				var ctls *tls.Config
				if useTLS {
					addr = startTLSGroup(t, tlsSite(t, backend), fast)
					ctls = h1TLS
				} else {
					addr = startTestGroup(t, fastTestSite(&ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}, backend), fast)
				}

				a := dialKA(t, addr, ctls)
				for i := 0; i < 3; i++ {
					got := a.answer("/a")
					if got.conn != 0 || got.src != a.local() || got.dst != addr {
						t.Fatalf("client A, request %d: %+v, want connection 0 naming %s -> %s", i, got, a.local(), addr)
					}
				}
				b := dialKA(t, addr, ctls)
				if got := b.answer("/b"); got.conn != 1 || got.src != b.local() || got.dst != addr {
					t.Fatalf("client B: %+v, want connection 1 naming %s -> %s", got, b.local(), addr)
				}
				// Each goes on with its own.
				if got := a.answer("/a"); got.conn != 0 {
					t.Errorf("client A after B: on connection %d", got.conn)
				}
				if got := b.answer("/b"); got.conn != 1 {
					t.Errorf("client B again: on connection %d", got.conn)
				}
				if n := be.count(); n != 2 {
					t.Errorf("the backend saw %d connections, want 2", n)
				}
				// A's backend connection ends with A.
				a.c.Close()
				be.waitOpen("after client A left", 1)
				b.c.Close()
				be.waitOpen("after client B left", 0)
				be.noneRefused()
			})
		}
	}
}

// The client is the one a trusted relay named, when one did: its address
// goes into the header to the backend.
func TestSendProxy_RelayedClient(t *testing.T) {
	const client = "203.0.113.9:4321"
	for _, useTLS := range []bool{false, true} {
		for _, fast := range []bool{true, false} {
			t.Run(fmt.Sprintf("tls=%v/%s", useTLS, paths(fast)), func(t *testing.T) {
				be := newProxyBackend(t, nil, nil)
				backend := &config.Backend{Servers: []string{be.addr()}, SendProxyV2: true}
				trust := proxy.NewTrust([]string{"127.0.0.0/8"}, nil)
				var s *HTTPServer
				if useTLS {
					s = tlsSite(t, backend)
					s.Listener.ProxyTrust = trust
				} else {
					s = fastTestSite(&ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", ProxyTrust: trust}, backend)
				}
				addr := startRelayGroup(t, s, useTLS, fast)
				resp, body, err := viaRelay(t, addr, useTLS, [][]byte{relayHeader(t, client, nil)}, relayGet)
				if err != nil || resp.StatusCode != 200 {
					t.Fatalf("request through the relay: %v, %v", resp, err)
				}
				if got := parseProxyAnswer(t, body); got.src != client || got.dst != addr {
					t.Errorf("the backend was told %s -> %s, want %s -> %s", got.src, got.dst, client, addr)
				}
				be.noneRefused()
			})
		}
	}
}

// With send_proxy_key_file the header is signed, and a backend that checks
// the signature accepts it; signed with another key, the backend refuses
// the connection and the request fails as a backend failure.
func TestSendProxy_Signed(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	other := []byte("fedcba9876543210fedcba9876543210")
	for _, fast := range []bool{true, false} {
		t.Run(paths(fast), func(t *testing.T) {
			be := newProxyBackend(t, nil, key)
			site := func(k []byte) string {
				l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
				return startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}, SendProxyV2: true, SendProxyKey: k}), fast)
			}
			good := dialKA(t, site(key), nil)
			if got := good.answer("/"); got.src != good.local() {
				t.Errorf("signed header: the backend was told %s, want %s", got.src, good.local())
			}
			be.noneRefused()

			bad := dialKA(t, site(other), nil)
			if code, _ := bad.get("/"); code != http.StatusBadGateway {
				t.Errorf("header signed with another key: status %d, want 502", code)
			}
			be.mu.Lock()
			refused := len(be.bad)
			be.mu.Unlock()
			if refused == 0 {
				t.Errorf("the backend did not refuse the header signed with another key")
			}
		})
	}
}

// A TLS connection the loops hand over to net/http (its site compresses)
// brings its client with it: a send_proxy_v2 backend is told that client,
// on the connection's own backend connections, closed with it.
func TestSendProxy_HandedOverTLS(t *testing.T) {
	be := newProxyBackend(t, nil, nil)
	cert, key := genCertWithCN(t, t.TempDir(), "example.test")
	l := &ListenerConfig{Name: "tls-site", Addr: "127.0.0.1:0", Protocol: "https", TLS: &config.TLSConfig{Cert: cert, Key: key}}
	l.Compression.Enabled = true
	addr := startTLSGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}, SendProxyV2: true}), true)
	c := dialKA(t, addr, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"http/1.1"}})
	for i := 0; i < 2; i++ {
		if got := c.answer("/"); got.conn != 0 || got.src != c.local() || got.dst != addr {
			t.Fatalf("request %d: %+v, want connection 0 naming %s -> %s", i, got, c.local(), addr)
		}
	}
	c.c.Close()
	be.waitOpen("after the client left", 0)
	be.noneRefused()
}

// A signed header carries the time it was signed at, and is only good for
// some seconds: every connection gets one signed when it is opened, not the
// one of the client's earlier connection.
func TestSendProxy_EveryConnectionIsSignedWhenItOpens(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for _, fast := range []bool{true, false} {
		t.Run(paths(fast), func(t *testing.T) {
			first, second := newProxyBackend(t, nil, key), newProxyBackend(t, nil, key)
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
			be := &config.Backend{Servers: []string{first.addr(), second.addr()}, SendProxyV2: true, SendProxyKey: key}
			c := dialKA(t, startTestGroup(t, fastTestSite(l, be), fast), nil)
			c.answer("/")
			time.Sleep(1100 * time.Millisecond)
			c.answer("/")
			var at []uint64
			for _, b := range []*proxyBackend{first, second} {
				b.mu.Lock()
				for _, rec := range b.conns {
					at = append(at, rec.signed)
				}
				b.mu.Unlock()
			}
			if len(at) != 2 || at[0] == 0 || at[1] == 0 || at[0] == at[1] {
				t.Errorf("the headers of the client's two backend connections, opened more than a second apart, were signed at %v: want two times", at)
			}
		})
	}
}

// A backend_tls backend gets the header before the TLS handshake.
func TestSendProxy_BackendTLS(t *testing.T) {
	certFile, keyFile := genCertWithCN(t, t.TempDir(), tlsBackendName)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, fast := range []bool{true, false} {
		t.Run(paths(fast), func(t *testing.T) {
			be := newProxyBackend(t, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}, nil)
			s := tlsBackendSite([]string{be.addr()}, config.BackendTLSConfig{CACert: certFile, ServerName: tlsBackendName}, config.Backend{SendProxyV2: true})
			addr := startTestGroup(t, s, fast)
			a := dialKA(t, addr, nil)
			for i := 0; i < 2; i++ {
				if got := a.answer("/"); got.conn != 0 || got.src != a.local() || got.dst != addr {
					t.Fatalf("request %d: %+v, want connection 0 naming %s -> %s", i, got, a.local(), addr)
				}
			}
			a.c.Close()
			be.waitOpen("after the client left", 0)
			be.noneRefused()
		})
	}
}

// A client connection with one request at a time keeps ownConnsMin idle
// backend connections in all: with six servers taking turns, the two it
// has not used the longest are closed.
func TestSendProxy_IdleFloor(t *testing.T) {
	for _, fast := range []bool{true, false} {
		t.Run(paths(fast), func(t *testing.T) {
			var bes []*proxyBackend
			var servers []string
			for i := 0; i < ownConnsMin+2; i++ {
				b := newProxyBackend(t, nil, nil)
				bes = append(bes, b)
				servers = append(servers, b.addr())
			}
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
			addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: servers, SendProxyV2: true}), fast)
			a := dialKA(t, addr, nil)
			for i := 0; i < len(bes); i++ {
				a.answer("/")
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				open, total := 0, 0
				for _, b := range bes {
					open += b.open()
					total += b.count()
				}
				if total == len(bes) && open == ownConnsMin {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%d backend connections opened, %d still open; want %d and %d", total, open, len(bes), ownConnsMin)
				}
				time.Sleep(5 * time.Millisecond)
			}
			// One round more: every server is asked once again, on its kept
			// connection or a new one, never on two at a time.
			for i := 0; i < len(bes); i++ {
				a.answer("/")
			}
			a.c.Close()
			for _, b := range bes {
				b.waitOpen("after the client left", 0)
				b.noneRefused()
			}
		})
	}
}

// How many idle backend connections a client connection keeps follows what
// it uses. Twelve requests at once on an HTTP/2 connection need twelve
// backend connections. Served by the loops, all twelve are kept: the same
// twelve requests again open none. (Once the last seconds hold no such
// load the ones above the few a client always keeps are closed: the loops'
// own test, TestEng_OwnConnectionsFollowUse.) Handed to net/http's
// handlers, the client keeps the fixed few: the second twelve open the
// rest again.
func TestSendProxy_IdleFollowsUse(t *testing.T) {
	const burst = 12
	for _, handlers := range []bool{false, true} {
		name := "served by the loops"
		if handlers {
			name = "handed to net/http's handlers"
		}
		t.Run(name, func(t *testing.T) {
			be := newProxyBackend(t, nil, nil)
			s := h2Site(t, be.addr(), func(l *ListenerConfig, b *config.Backend) {
				b.SendProxyV2 = true
				l.Compression.Enabled = handlers
			})
			addr := startTLSGroup(t, s, true)
			hc := dialH2(t, addr)
			local := hc.c.LocalAddr().String()
			atOnce := func() {
				t.Helper()
				be.hold()
				ids := make([]uint32, burst)
				for i := range ids {
					ids[i] = hc.start(h2Fields("GET", "/hold"), true)
				}
				be.waitHeld(burst)
				be.release()
				hc.wait(ids...)
				for _, id := range ids {
					r := hc.stream(id)
					if r.status != 200 {
						t.Fatalf("stream %d: status %d", id, r.status)
					}
					if got := parseProxyAnswer(t, string(r.body)); got.src != local {
						t.Fatalf("stream %d: the backend was told %s, want %s", id, got.src, local)
					}
				}
			}
			atOnce()
			if n := be.count(); n != burst {
				t.Fatalf("%d requests at once opened %d backend connections", burst, n)
			}
			if handlers {
				be.waitOpen("after the first twelve", ownConnsMin)
				atOnce()
				if n, want := be.count(), 2*burst-ownConnsMin; n != want {
					t.Errorf("the second twelve: %d backend connections opened in all, want %d (%d kept)", n, want, ownConnsMin)
				}
				be.waitOpen("after the second twelve", ownConnsMin)
			} else {
				if n := be.open(); n != burst {
					t.Fatalf("after the first twelve %d backend connections are open, want all %d kept", n, burst)
				}
				atOnce()
				if n := be.count(); n != burst {
					t.Errorf("the second twelve: %d backend connections opened in all, want the first %d used again", n, burst)
				}
			}
			hc.c.Close()
			be.waitOpen("after the client left", 0)
			be.noneRefused()
		})
	}
}

// HTTP/2: the streams of a connection share its backend connections, each
// of which begins with that client's header. Requests the loops serve and
// requests they hand to net/http's handlers (a site with compression).
func TestSendProxy_HTTP2(t *testing.T) {
	for _, handlers := range []bool{false, true} {
		name := "served by the loops"
		if handlers {
			name = "handed to net/http's handlers"
		}
		t.Run(name, func(t *testing.T) {
			be := newProxyBackend(t, nil, nil)
			s := h2Site(t, be.addr(), func(l *ListenerConfig, b *config.Backend) {
				b.SendProxyV2 = true
				l.Compression.Enabled = handlers
			})
			addr := startTLSGroup(t, s, true)
			hc := dialH2(t, addr)
			local := hc.c.LocalAddr().String()
			for i := 0; i < 3; i++ {
				r := hc.do(h2Fields("GET", "/one"), nil)
				if r.status != 200 {
					t.Fatalf("request %d: status %d", i, r.status)
				}
				if got := parseProxyAnswer(t, string(r.body)); got.conn != 0 || got.src != local || got.dst != addr {
					t.Fatalf("request %d: %+v, want connection 0 naming %s -> %s", i, got, local, addr)
				}
			}
			// Two requests at once need two backend connections; both name
			// the client.
			id1 := hc.start(h2Fields("GET", "/two"), true)
			id2 := hc.start(h2Fields("GET", "/three"), true)
			hc.wait(id1, id2)
			for _, id := range []uint32{id1, id2} {
				r := hc.stream(id)
				if r.status != 200 {
					t.Fatalf("stream %d: status %d", id, r.status)
				}
				if got := parseProxyAnswer(t, string(r.body)); got.src != local {
					t.Errorf("stream %d: the backend was told %s, want %s", id, got.src, local)
				}
			}
			// Another client's connection never uses them.
			other := dialH2(t, addr)
			r := other.do(h2Fields("GET", "/other"), nil)
			if got := parseProxyAnswer(t, string(r.body)); got.src != other.c.LocalAddr().String() {
				t.Errorf("second client: the backend was told %s, want %s", got.src, other.c.LocalAddr())
			}
			other.c.Close()
			hc.c.Close()
			be.waitOpen("after both clients left", 0)
			be.noneRefused()
		})
	}
}

// A WebSocket upgrade goes to net/http, on a backend connection that begins
// with the same client's header; the connections the client had on the
// event loops are closed when it leaves them, and the tunnel's ends with
// the client.
func TestSendProxy_WebSocket(t *testing.T) {
	for _, fast := range []bool{true, false} {
		t.Run(paths(fast), func(t *testing.T) {
			be := newProxyBackend(t, nil, nil)
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
			addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}, SendProxyV2: true}), fast)
			a := dialKA(t, addr, nil)
			if got := a.answer("/first"); got.conn != 0 || got.src != a.local() {
				t.Fatalf("first request: %+v", got)
			}
			io.WriteString(a.c, "GET /ws HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
			resp, err := http.ReadResponse(a.br, nil)
			if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade: %v, %v", resp, err)
			}
			line, err := a.br.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if got := parseProxyAnswer(t, strings.TrimSpace(line)); got.src != a.local() || got.dst != addr {
				t.Errorf("the tunnel's backend connection names %s -> %s, want %s -> %s", got.src, got.dst, a.local(), addr)
			}
			msg := "ping through the tunnel"
			io.WriteString(a.c, msg)
			echo := make([]byte, len(msg))
			if _, err := io.ReadFull(a.br, echo); err != nil || string(echo) != msg {
				t.Fatalf("echo %q, %v", echo, err)
			}
			// Only the tunnel's connection is open now.
			be.waitOpen("while the tunnel is open", 1)
			a.c.Close()
			be.waitOpen("after the client left", 0)
			be.noneRefused()
		})
	}
}

// HTTP/3: the header names the client's UDP address, as a stream client.
// On the loops, for requests they serve and for requests they hand to
// net/http's handlers (a site with compression).
func TestSendProxy_HTTP3(t *testing.T) {
	onBothH3Servers(t, func(t *testing.T) { sendProxyOverHTTP3(t, false) })
	t.Run("the loops' handlers", func(t *testing.T) { h3ServedBy(t, true); sendProxyOverHTTP3(t, true) })
}

func sendProxyOverHTTP3(t *testing.T, handlers bool) {
	pki := newCAPKI(t, "h3-proxy-ca")
	be := newProxyBackend(t, nil, nil)
	l := &ListenerConfig{Name: "h3", Addr: ":0", Protocol: "https", HTTP3: true,
		TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
	l.Compression.Enabled = handlers
	site := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}, SendProxyV2: true})
	addr := freeAddr(t)
	startGroup(t, addr, site)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), nil)
	if err != nil {
		t.Fatal(err)
	}
	cc := (&http3.Transport{}).NewClientConn(conn)
	_, port, _ := net.SplitHostPort(addr)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d %q", i, resp.StatusCode, body)
		}
		got := parseProxyAnswer(t, string(body))
		_, srcPort, _ := net.SplitHostPort(got.src)
		_, wantPort, _ := net.SplitHostPort(conn.LocalAddr().String())
		_, dstPort, _ := net.SplitHostPort(got.dst)
		if got.conn != 0 || srcPort != wantPort || dstPort != port {
			t.Fatalf("request %d: %+v, want connection 0, the client's port %s, the listener's port %s", i, got, wantPort, port)
		}
	}
	be.mu.Lock()
	stream := be.conns[0].stream
	be.mu.Unlock()
	if !stream {
		t.Errorf("the header named a datagram client: a backend's connection is a stream")
	}
	conn.CloseWithError(0, "")
	be.waitOpen("after the QUIC connection closed", 0)
	be.noneRefused()
}

// A request that reaches the proxy without a client connection on record
// is not sent to a send_proxy_v2 backend: it is answered 502.
func TestSendProxy_NoClientConnection(t *testing.T) {
	be := newProxyBackend(t, nil, nil)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}, SendProxyV2: true})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status %d, want 502", rec.Code)
	}
	if n := be.count(); n != 0 {
		t.Errorf("the backend got %d connections", n)
	}
	be.noneRefused()
}

// The header, by what it is made from.
func TestBackendProxyHeader(t *testing.T) {
	tcp := func(s string) *net.TCPAddr {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	cases := []struct {
		name     string
		src, dst net.Addr
		proto    proxyproto.AddressFamilyAndProtocol
		wantSrc  string
		wantDst  string
		wantErr  bool
	}{
		{name: "IPv4", src: tcp("198.51.100.7:5000"), dst: tcp("192.0.2.1:443"), proto: proxyproto.TCPv4, wantSrc: "198.51.100.7:5000", wantDst: "192.0.2.1:443"},
		{name: "IPv6", src: tcp("[2001:db8::7]:5000"), dst: tcp("[2001:db8::1]:443"), proto: proxyproto.TCPv6, wantSrc: "[2001:db8::7]:5000", wantDst: "[2001:db8::1]:443"},
		{name: "an IPv4 client named over an IPv6 connection", src: tcp("198.51.100.7:5000"), dst: tcp("[2001:db8::1]:443"), proto: proxyproto.TCPv6, wantSrc: "198.51.100.7:5000", wantDst: "[2001:db8::1]:443"},
		{name: "a QUIC client", src: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 5000}, dst: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, proto: proxyproto.TCPv4, wantSrc: "198.51.100.7:5000", wantDst: "192.0.2.1:443"},
		{name: "a QUIC socket bound to all addresses", src: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 5000}, dst: &net.UDPAddr{IP: net.IPv6unspecified, Port: 443}, proto: proxyproto.TCPv4, wantSrc: "198.51.100.7:5000", wantDst: "0.0.0.0:443"},
		{name: "no client address", src: nil, dst: tcp("192.0.2.1:443"), wantErr: true},
		{name: "a typed nil address", src: (*net.TCPAddr)(nil), dst: tcp("192.0.2.1:443"), wantErr: true},
		{name: "another kind of address", src: &net.UnixAddr{Name: "/x", Net: "unix"}, dst: tcp("192.0.2.1:443"), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := backendProxyHeader(tc.src, tc.dst, nil, time.Time{})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("a header was made: %x", raw)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			h, err := proxyproto.Read(bufio.NewReader(strings.NewReader(string(raw))))
			if err != nil {
				t.Fatal(err)
			}
			if h.Command != proxyproto.PROXY || h.TransportProtocol != tc.proto {
				t.Errorf("command %v, protocol %v; want PROXY, %v", h.Command, h.TransportProtocol, tc.proto)
			}
			src, dst := h.SourceAddr.(*net.TCPAddr), h.DestinationAddr.(*net.TCPAddr)
			if !src.IP.Equal(tcp(tc.wantSrc).IP) || src.Port != tcp(tc.wantSrc).Port || !dst.IP.Equal(tcp(tc.wantDst).IP) || dst.Port != tcp(tc.wantDst).Port {
				t.Errorf("names %v -> %v, want %s -> %s", src, dst, tc.wantSrc, tc.wantDst)
			}
		})
	}
	// Signed: the receiver's check passes with the key, fails with another.
	key := []byte("0123456789abcdef0123456789abcdef")
	raw, err := backendProxyHeader(tcp("198.51.100.7:5000"), tcp("[2001:db8::1]:443"), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h, err := proxyproto.Read(bufio.NewReader(strings.NewReader(string(raw))))
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Verify(h, [][]byte{key}, nil, time.Now()); err != nil {
		t.Errorf("signature: %v", err)
	}
	if err := proxy.Verify(h, [][]byte{[]byte("another key of thirty-two bytes!")}, nil, time.Now()); err == nil {
		t.Errorf("the signature passed with another key")
	}
}
