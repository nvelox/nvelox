package httpproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/core/sticky"
	"nvelox/lb"
)

// Shared helpers for the regression tests of the HTTP-path security fixes
// (sec_*_test.go).

// secOpts are the optional collaborators of a test site.
type secOpts struct {
	backend *config.Backend // Name and Servers are filled in
	ph      PassiveHealthI
	cb      CircuitBreakerI
	cl      ConnLimiterI
	store   *sticky.Store
}

// secSite builds a site "edge" whose backend "be" is servers, served by a
// BindGroup behind an httptest server. It returns the site and the
// proxy's address.
func secSite(t *testing.T, l *ListenerConfig, servers []string, o secOpts) (*HTTPServer, string) {
	t.Helper()
	s := secNewSite(t, l, servers, o)
	g := NewBindGroup(":0", "http")
	g.AddSite(s)
	ts := httptest.NewServer(g)
	t.Cleanup(ts.Close)
	return s, ts.Listener.Addr().String()
}

// secNewSite builds the site without serving it.
func secNewSite(t *testing.T, l *ListenerConfig, servers []string, o secOpts) *HTTPServer {
	t.Helper()
	be := o.backend
	if be == nil {
		be = &config.Backend{}
	}
	be.Name, be.Servers = "be", servers
	if l.Name == "" {
		l.Name = "edge"
	}
	l.Protocol, l.Backend = "http", "be"
	var ph map[string]PassiveHealthI
	if o.ph != nil {
		ph = map[string]PassiveHealthI{"be": o.ph}
	}
	var cbs map[string]CircuitBreakerI
	if o.cb != nil {
		cbs = map[string]CircuitBreakerI{"be": o.cb}
	}
	var cls map[string]ConnLimiterI
	if o.cl != nil {
		cls = map[string]ConnLimiterI{"be": o.cl}
	}
	var stores map[string]*sticky.Store
	if o.store != nil {
		stores = map[string]*sticky.Store{"be": o.store}
	}
	s := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin(servers)},
		map[string]*config.Backend{"be": be}, nil, cls, ph, stores, cbs)
	t.Cleanup(s.Close)
	return s
}

// secHost returns the host:port of an httptest server.
func secHost(ts *httptest.Server) string { return ts.Listener.Addr().String() }

// secRaw writes payload on a fresh connection to addr and returns all it
// reads until EOF or wait elapses, and whether the proxy closed the
// connection (EOF) before then.
func secRaw(t *testing.T, addr, payload string, wait time.Duration) (string, bool) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, wait)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(wait))
	b, err := io.ReadAll(c)
	return string(b), err == nil
}

// secGet is a minimal request with Connection: close.
func secGet(path, extra string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: edge.test\r\n" + extra + "Connection: close\r\n\r\n"
}

// secStatus returns the status line of a raw response.
func secStatus(resp string) string {
	if i := strings.Index(resp, "\r\n"); i >= 0 {
		return resp[:i]
	}
	return resp
}

// secBody returns the body of a raw response.
func secBody(resp string) string {
	if i := strings.Index(resp, "\r\n\r\n"); i >= 0 {
		return resp[i+4:]
	}
	return ""
}

// secPassive counts passive-health reports.
type secPassive struct {
	mu        sync.Mutex
	failures  map[string]int
	successes map[string]int
}

func newSecPassive() *secPassive {
	return &secPassive{failures: map[string]int{}, successes: map[string]int{}}
}

func (p *secPassive) RecordFailure(s string) { p.mu.Lock(); p.failures[s]++; p.mu.Unlock() }
func (p *secPassive) RecordSuccess(s string) { p.mu.Lock(); p.successes[s]++; p.mu.Unlock() }

func (p *secPassive) counts(s string) (failures, successes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failures[s], p.successes[s]
}

func (p *secPassive) totalFailures() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, v := range p.failures {
		n += v
	}
	return n
}

// secAccessLog points the access log at a temp file for the test.
func secAccessLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("debug", path, ""); err != nil {
		t.Fatalf("logging init: %v", err)
	}
	t.Cleanup(func() { _ = logging.Init("debug", "", "") })
	return path
}

// secLogLines waits until the access log has at least n lines and returns
// them (the line is written when the handler returns, which can be just
// after the client got its response).
func secLogLines(t *testing.T, path string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, _ := os.ReadFile(path)
		text := strings.TrimRight(string(data), "\n")
		var lines []string
		if text != "" {
			lines = strings.Split(text, "\n")
		}
		if len(lines) >= n || time.Now().After(deadline) {
			return lines
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// secWSBackend is a WebSocket echo backend that records each upgrade
// request and the first bytes it receives after the handshake.
type secWSBackend struct {
	addr   string
	reqs   chan *http.Request
	first  chan string
	closed chan struct{}
}

func secStartWSBackend(t *testing.T) *secWSBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	b := &secWSBackend{
		addr:   ln.Addr().String(),
		reqs:   make(chan *http.Request, 8),
		first:  make(chan string, 8),
		closed: make(chan struct{}, 8),
	}
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

func (b *secWSBackend) serve(c net.Conn) {
	defer func() {
		c.Close()
		b.closed <- struct{}{}
	}()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	b.reqs <- req
	io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	buf := make([]byte, 4096)
	firstSent := false
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if !firstSent {
				b.first <- string(buf[:n])
				firstSent = true
			}
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// secUpgrade sends a WebSocket upgrade (plus extra request headers) and
// returns the connection, its reader and the response.
func secUpgrade(t *testing.T, addr, extra string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, wsTestTimeout)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(wsTestTimeout))
	io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: edge.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+extra+"\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	return conn, br, resp
}

// secExpectEOF waits up to d for the proxy to close conn.
func secExpectEOF(t *testing.T, conn net.Conn, br *bufio.Reader, d time.Duration, what string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(d))
	for {
		_, err := br.ReadByte()
		if err == io.EOF {
			return
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("%s: connection still open after %v", what, d)
			}
			return // reset: closed as well
		}
	}
}

// newRR is a round-robin balancer over servers.
func newRR(servers ...string) lb.Balancer { return lb.NewRoundRobin(servers) }
