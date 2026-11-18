//go:build linux

package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"

	"golang.org/x/sys/unix"
)

// rawBackend is a keep-alive HTTP/1.1 backend that records every request it
// gets and answers by path with exact bytes.
type rawBackend struct {
	t     *testing.T
	ln    net.Listener
	mu    sync.Mutex
	reqs  []*http.Request
	conns int
}

func newRawBackend(t *testing.T) *rawBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &rawBackend{t: t, ln: ln}
	go b.serve()
	t.Cleanup(func() { ln.Close() })
	return b
}

func (b *rawBackend) addr() string { return b.ln.Addr().String() }

func (b *rawBackend) serve() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		b.conns++
		b.mu.Unlock()
		go b.serveConn(c)
	}
}

func (b *rawBackend) last() *http.Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.reqs) == 0 {
		return nil
	}
	return b.reqs[len(b.reqs)-1]
}

func (b *rawBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.reqs)
}

func (b *rawBackend) connCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conns
}

func (b *rawBackend) serveConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.URL.Path == "/early" {
			// Refuses the body without reading it.
			b.mu.Lock()
			b.reqs = append(b.reqs, req)
			b.mu.Unlock()
			io.WriteString(c, "HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope")
			return
		}
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.Header.Set("X-Test-Body-Len", strconv.Itoa(len(body)))
		req.Header.Set("X-Test-Body-Sum", fmt.Sprintf("%x", crc32.ChecksumIEEE(body)))
		b.mu.Lock()
		b.reqs = append(b.reqs, req)
		b.mu.Unlock()
		if !b.answer(c, req) {
			return
		}
	}
}

// answer writes the response for req; false closes the connection.
func (b *rawBackend) answer(c net.Conn, req *http.Request) bool {
	p := req.URL.Path
	w := func(s string) { io.WriteString(c, s) }
	switch {
	case p == "/chunked":
		w("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n")
	case p == "/trailer":
		w("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTrailer: X-Sum\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 42\r\n\r\n")
	case p == "/close":
		w("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil the end")
		return false
	case p == "/sniff":
		body := "<html><body>hi</body></html>"
		w("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
	case p == "/sniff-gz":
		w("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\nabcd")
	case p == "/304":
		w("HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n")
	case p == "/204":
		w("HTTP/1.1 204 No Content\r\nX-A: b\r\nContent-Length: 0\r\n\r\n")
	case p == "/103":
		w("HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")
	case p == "/hop":
		w("HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nUpgrade: foo\r\nX-Keep: yes\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")
	case p == "/big":
		body := strings.Repeat("0123456789abcdef", 200<<10/16)
		w("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
	case p == "/bigchunked":
		w("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		for i := 0; i < 50; i++ {
			chunk := strings.Repeat(string(rune('a'+i%26)), 4000+i)
			w(fmt.Sprintf("%x\r\n%s\r\n", len(chunk), chunk))
		}
		w("0\r\n\r\n")
	case p == "/headers":
		w("HTTP/1.1 200 OK\r\nServer: rawbe\r\nDate: Mon, 02 Jan 2006 15:04:05 GMT\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Multi: one\r\nX-Multi: two\r\nX-Remove-Me: 1\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")
	case p == "/502":
		w("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\n\r\nbad")
	case p == "/503":
		w("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy")
	case p == "/101":
		w("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		return false
	case p == "/malformed":
		w("HTTP/1.1 2x0 OK\r\n\r\n")
		return false
	case p == "/reset":
		return false
	case p == "/stale":
		// Answers, then closes the connection without saying so.
		w("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nstale")
		return false
	case strings.HasPrefix(p, "/sleep/"):
		d, _ := time.ParseDuration(strings.TrimPrefix(p, "/sleep/"))
		time.Sleep(d)
		w("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nslept")
	case p == "/http10":
		w("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\n1.0!")
		return false
	case p == "/excess":
		w("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nokEXTRA")
		return false
	case p == "/empty":
		w("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	default:
		body := "hello " + req.Method + " " + req.URL.RequestURI()
		if req.Method == http.MethodHead {
			w("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n")
		} else {
			w("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
		}
	}
	return true
}

// fastTestSite builds a site for listener l with one backend "be" on the
// given servers.
func fastTestSite(l *ListenerConfig, be *config.Backend) *HTTPServer {
	if l.Backend == "" {
		l.Backend = "be"
	}
	if be.Name == "" {
		be.Name = "be"
	}
	backends := map[string]*config.Backend{be.Name: be}
	balancers := map[string]lb.Balancer{be.Name: lb.NewRoundRobin(be.Servers)}
	return NewHTTPServer(l, balancers, backends, nil, nil, nil, nil, nil)
}

// startTestGroup starts a one-site bind group on 127.0.0.1:0, through the
// fast path or net/http, and returns its address.
func startTestGroup(t *testing.T, s *HTTPServer, fast bool) string {
	t.Helper()
	fastPathOff.Store(!fast)
	defer fastPathOff.Store(false)
	g := NewBindGroup("127.0.0.1:0", "http")
	g.AddSite(s)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if fast != (g.fast != nil) {
		t.Fatalf("fast path = %v, want %v", g.fast != nil, fast)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		g.Stop(ctx)
	})
	return g.BoundAddr().String()
}

// exchange sends raw request bytes on a new connection and reads n
// responses.
func exchange(t *testing.T, addr string, raw string, methods ...string) []*http.Response {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	var out []*http.Response
	for _, m := range methods {
		resp, err := http.ReadResponse(br, &http.Request{Method: m})
		if err != nil {
			t.Fatalf("reading response %d: %v", len(out)+1, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading body %d: %v", len(out)+1, err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		out = append(out, resp)
	}
	return out
}

func readBody(r *http.Response) string {
	b, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(b))
	return string(b)
}

// normHeader drops what legitimately differs between the two paths.
func normHeader(h http.Header) http.Header {
	out := h.Clone()
	out.Del("Date")
	return out
}

// TestFastPath_MatchesNetHTTP sends the same requests through the fast path
// and through the net/http path and compares what the client gets and what
// the backend gets.
func TestFastPath_MatchesNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	type tc struct {
		name, raw, method string
	}
	get := func(path string, extra ...string) string {
		return "GET " + path + " HTTP/1.1\r\nHost: example.test\r\n" + strings.Join(extra, "") + "\r\n"
	}
	cases := []tc{
		{"plain", get("/ok"), "GET"},
		{"query", get("/q?a=1&b=%20x&c"), "GET"},
		{"empty query", get("/q?"), "GET"},
		{"encoded path", get("/a%2Fb/c%20d"), "GET"},
		{"dot segments", get("/a/./b/../c"), "GET"},
		{"double slash", get("//admin//x"), "GET"},
		{"sub-delims", get("/a!b$c&d'e(f)g*h+i,j;k=l:m@n"), "GET"},
		{"head", "HEAD /ok HTTP/1.1\r\nHost: example.test\r\n\r\n", "HEAD"},
		{"delete", "DELETE /ok HTTP/1.1\r\nHost: example.test\r\n\r\n", "DELETE"},
		{"options", "OPTIONS /ok HTTP/1.1\r\nHost: example.test\r\n\r\n", "OPTIONS"},
		{"custom method", "PURGE /ok HTTP/1.1\r\nHost: example.test\r\n\r\n", "PURGE"},
		{"chunked", get("/chunked"), "GET"},
		{"trailer", get("/trailer", "TE: trailers\r\n"), "GET"},
		{"close delimited", get("/close"), "GET"},
		{"sniff", get("/sniff"), "GET"},
		{"no sniff with encoding", get("/sniff-gz"), "GET"},
		{"304", get("/304"), "GET"},
		{"204", get("/204"), "GET"},
		{"hop by hop", get("/hop"), "GET"},
		{"big", get("/big"), "GET"},
		{"big chunked", get("/bigchunked"), "GET"},
		{"backend headers", get("/headers"), "GET"},
		{"502 passthrough", get("/502"), "GET"},
		{"101 refused", get("/101"), "GET"},
		{"malformed backend", get("/malformed"), "GET"},
		{"backend reset", get("/reset"), "GET"},
		{"http/1.0 backend", get("/http10"), "GET"},
		{"empty body", get("/empty"), "GET"},
		{"client hop headers", get("/ok", "Connection: keep-alive, X-Drop\r\nX-Drop: 1\r\nKeep-Alive: 300\r\nProxy-Authorization: x\r\nTE: gzip\r\nX-Keep: 1\r\n"), "GET"},
		{"forged forwarding", get("/ok", "X-Forwarded-For: 1.2.3.4\r\nX-Real-IP: 1.2.3.4\r\nX-Forwarded-Proto: https\r\nForwarded: for=1.2.3.4\r\nX-Forwarded-Host: evil\r\nTrue-Client-IP: 1.2.3.4\r\nCF-Connecting-IP: 1.2.3.4\r\n"), "GET"},
		{"user agents", get("/ok", "User-Agent: first\r\nUser-Agent: second\r\n"), "GET"},
		{"no user agent", get("/ok"), "GET"},
		{"cl zero get", get("/ok", "Content-Length: 0\r\n"), "GET"},
		{"mixed case names", get("/ok", "x-lower: v\r\nX-UPPER: V\r\naccept: */*\r\n"), "GET"},
		{"ows values", get("/ok", "X-Space:   padded value  \r\nX-Tab:\tv\t\r\n"), "GET"},
		{"obs-text value", get("/ok", "X-Utf8: caf\xc3\xa9\r\n"), "GET"},
		{"idempotency", "POST /ok HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\nIdempotency-Key: k\r\n\r\n", "POST"},
	}
	run := func(fast bool) (map[string]*http.Response, map[string]*http.Request) {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		addr := startTestGroup(t, s, fast)
		resps := map[string]*http.Response{}
		reqs := map[string]*http.Request{}
		for _, c := range cases {
			before := be.count()
			r := exchange(t, addr, c.raw, c.method)[0]
			resps[c.name] = r
			if be.count() > before {
				reqs[c.name] = be.last()
			}
		}
		return resps, reqs
	}
	slowResps, slowReqs := run(false)
	fastResps, fastReqs := run(true)
	for _, c := range cases {
		s, f := slowResps[c.name], fastResps[c.name]
		if s.StatusCode != f.StatusCode {
			t.Errorf("%s: status slow %d, fast %d", c.name, s.StatusCode, f.StatusCode)
			continue
		}
		sb, fb := readBody(s), readBody(f)
		if sb != fb {
			t.Errorf("%s: body differs:\n slow %q\n fast %q", c.name, trunc(sb), trunc(fb))
		}
		sh, fh := normHeader(s.Header), normHeader(f.Header)
		if c.name == "close delimited" || c.name == "chunked" || c.name == "trailer" || c.name == "big chunked" {
			// net/http re-chunks too; the length it may compute for a short
			// body is not asserted.
			sh.Del("Content-Length")
			fh.Del("Content-Length")
		}
		if !reflect.DeepEqual(sh, fh) {
			t.Errorf("%s: headers differ:\n slow %v\n fast %v", c.name, sh, fh)
		}
		if !reflect.DeepEqual(s.Trailer, f.Trailer) {
			t.Errorf("%s: trailers differ: slow %v, fast %v", c.name, s.Trailer, f.Trailer)
		}
		sr, fr := slowReqs[c.name], fastReqs[c.name]
		if (sr == nil) != (fr == nil) {
			t.Errorf("%s: backend saw the request: slow %v, fast %v", c.name, sr != nil, fr != nil)
			continue
		}
		if sr == nil {
			continue
		}
		if sr.Method != fr.Method || sr.RequestURI != fr.RequestURI || sr.Host != fr.Host || sr.Proto != fr.Proto {
			t.Errorf("%s: backend request line differs: slow %s %s %s host %s, fast %s %s %s host %s", c.name,
				sr.Method, sr.RequestURI, sr.Proto, sr.Host, fr.Method, fr.RequestURI, fr.Proto, fr.Host)
		}
		if !reflect.DeepEqual(sr.Header, fr.Header) {
			t.Errorf("%s: backend headers differ:\n slow %v\n fast %v", c.name, sr.Header, fr.Header)
		}
		if !reflect.DeepEqual(sr.TransferEncoding, fr.TransferEncoding) || sr.ContentLength != fr.ContentLength {
			t.Errorf("%s: backend framing differs: slow %v/%d, fast %v/%d", c.name, sr.TransferEncoding, sr.ContentLength, fr.TransferEncoding, fr.ContentLength)
		}
	}
}

func trunc(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// TestFastPath_KeepAliveAndPipelining: several requests on one connection,
// pipelined in one write, answered in order over pooled backend connections.
func TestFastPath_KeepAliveAndPipelining(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)
	raw := ""
	var methods []string
	for i := 0; i < 20; i++ {
		raw += fmt.Sprintf("GET /p%d HTTP/1.1\r\nHost: x\r\n\r\n", i)
		methods = append(methods, "GET")
	}
	resps := exchange(t, addr, raw, methods...)
	for i, r := range resps {
		if want := fmt.Sprintf("hello GET /p%d", i); readBody(r) != want {
			t.Fatalf("response %d: %q, want %q", i, readBody(r), want)
		}
	}
	if n := be.connCount(); n != 1 {
		t.Errorf("backend connections = %d, want 1 (keep-alive pool)", n)
	}
}

// TestFastPath_HandoffServesTheRest: a request the fast path does not
// handle (a body) goes to net/http with everything after it.
func TestFastPath_HandoffServesTheRest(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)
	raw := "GET /first HTTP/1.1\r\nHost: x\r\n\r\n" +
		"POST /second HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" +
		"GET /third HTTP/1.1\r\nHost: x\r\n\r\n"
	resps := exchange(t, addr, raw, "GET", "POST", "GET")
	for i, want := range []string{"hello GET /first", "hello POST /second", "hello GET /third"} {
		if got := readBody(resps[i]); got != want {
			t.Errorf("response %d: %q, want %q", i, got, want)
		}
	}
}

// TestFastPath_StaleBackendConnRetried: a backend that closes a keep-alive
// connection after answering: the next request on that pooled connection is
// sent again on a fresh one, as Go's transport does.
func TestFastPath_StaleBackendConnRetried(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)
	for i := 0; i < 5; i++ {
		r := exchange(t, addr, "GET /stale HTTP/1.1\r\nHost: x\r\n\r\n", "GET")[0]
		if r.StatusCode != 200 || readBody(r) != "stale" {
			t.Fatalf("request %d: %d %q", i, r.StatusCode, readBody(r))
		}
	}
}

// deadTCPAddr returns a TCP address that refuses connections for as long
// as the test runs: its port is bound, so that no listener of the test is
// given it, and nothing listens on it. (The port of a listener that was
// just closed is free for the next one to take, and then it answers.)
func deadTCPAddr(t *testing.T) string {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(sa.(*unix.SockaddrInet4).Port))
}

// TestFastPath_RetryOnConnectFailure: a dead server is retried on the next
// one when the backend's retry policy allows it, and counted as a failure.
func TestFastPath_RetryOnConnectFailure(t *testing.T) {
	be := newRawBackend(t)
	deadAddr := deadTCPAddr(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{deadAddr, be.addr()}, Retry: config.RetryConfig{Attempts: 2}})
	ph := &countingHealth{}
	s.PassiveHealth = map[string]PassiveHealthI{"be": ph}
	addr := startTestGroup(t, s, true)
	for i := 0; i < 4; i++ {
		r := exchange(t, addr, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", "GET")[0]
		if r.StatusCode != 200 {
			t.Fatalf("request %d: status %d", i, r.StatusCode)
		}
	}
	if ph.failures() == 0 {
		t.Error("connect failures were not reported to passive health")
	}
}

type countingHealth struct {
	mu   sync.Mutex
	fail map[string]int
	succ map[string]int
}

func (h *countingHealth) RecordFailure(s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fail == nil {
		h.fail = map[string]int{}
	}
	h.fail[s]++
}

func (h *countingHealth) RecordSuccess(s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.succ == nil {
		h.succ = map[string]int{}
	}
	h.succ[s]++
}

func (h *countingHealth) failures() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, v := range h.fail {
		n += v
	}
	return n
}

// TestFastPath_ResponseHeaderTimeout: a backend slower than its
// response_header timeout is answered 504.
func TestFastPath_ResponseHeaderTimeout(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}, Timeouts: config.TimeoutConfig{ResponseHeader: "200ms"}})
	addr := startTestGroup(t, s, true)
	start := time.Now()
	r := exchange(t, addr, "GET /sleep/1s HTTP/1.1\r\nHost: x\r\n\r\n", "GET")[0]
	if r.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status %d, want 504", r.StatusCode)
	}
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Fatalf("took %v", d)
	}
	// The connection is usable afterwards.
	r = exchange(t, addr, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", "GET")[0]
	if r.StatusCode != 200 {
		t.Fatalf("after timeout: status %d", r.StatusCode)
	}
}

// TestFastPath_HeaderTimeout: a client that does not finish its request
// head in read_header is disconnected.
func TestFastPath_HeaderTimeout(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Timeouts: config.TimeoutConfig{ReadHeader: "300ms", Idle: "400ms"}}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /ok HTTP/1.1\r\nHost: x\r\n")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("got data, want the connection closed")
	}
	if d := time.Since(start); d < 200*time.Millisecond || d > 1500*time.Millisecond {
		t.Fatalf("closed after %v, want ~300ms", d)
	}

	// Idle: a keep-alive connection with no next request closes after idle.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	io.WriteString(c2, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(c2)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	start = time.Now()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("got data, want the idle connection closed")
	}
	if d := time.Since(start); d < 300*time.Millisecond || d > 1500*time.Millisecond {
		t.Fatalf("idle close after %v, want ~400ms", d)
	}
}

// TestFastPath_ClientGoneLogs499: a client that disconnects before the
// backend answers is logged 499.
func TestFastPath_ClientGoneLogs499(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("warning", path, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("warning", "", "") })
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET /sleep/500ms HTTP/1.1\r\nHost: x\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	c.Close()
	lines := secLogLines(t, path, 1)
	if len(lines) != 1 || !strings.Contains(lines[0], `"GET /sleep/500ms HTTP/1.1" 499 0 `) {
		t.Fatalf("access log: %q", lines)
	}
}

// TestFastPath_AccessLogMatchesNetHTTP: the same request logs the same line
// (but its duration) through both paths.
func TestFastPath_AccessLogMatchesNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	logLine := func(fast bool, raw string) string {
		path := filepath.Join(t.TempDir(), "access.log")
		if err := logging.Init("warning", path, ""); err != nil {
			t.Fatal(err)
		}
		defer logging.Init("warning", "", "")
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", RequestID: config.RequestIDConfig{Enabled: true, TrustInbound: true}}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		addr := startTestGroup(t, s, fast)
		exchange(t, addr, raw, "GET")
		lines := secLogLines(t, path, 1)
		if len(lines) != 1 {
			t.Fatalf("lines: %q", lines)
		}
		// drop the duration and a generated request id
		f := strings.Fields(lines[0])
		for i := range f {
			if strings.HasSuffix(f[i], "ms") {
				f[i] = "DUR"
			}
			if strings.HasPrefix(f[i], "rid=") && len(f[i]) == 4+32 {
				f[i] = "rid=GENERATED"
			}
		}
		return strings.Join(f, " ")
	}
	for _, raw := range []string{
		"GET /a/./b/%2e%2e/c%20d?q=1 HTTP/1.1\r\nHost: Example.Test:8080\r\nUser-Agent: UA \"quoted\" \\ back\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Dest: image\r\nX-Request-ID: 0123abcd\r\n\r\n",
		"GET /plain HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /404-route HTTP/1.1\r\nHost: h\r\nUser-Agent: " + strings.Repeat("x", 600) + "\r\n\r\n",
	} {
		slow, fast := logLine(false, raw), logLine(true, raw)
		if slow != fast {
			t.Errorf("access log differs:\n slow %s\n fast %s", slow, fast)
		}
	}
}

// TestFastPath_GatesMatchNetHTTP: the access gates answer the same.
func TestFastPath_GatesMatchNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	type gate struct {
		name  string
		setup func(l *ListenerConfig, b *config.Backend)
		after func(s *HTTPServer)
	}
	gates := []gate{
		{"denylist", func(l *ListenerConfig, b *config.Backend) { l.IPDenylist = []string{"127.0.0.0/8"} }, nil},
		{"allowlist", func(l *ListenerConfig, b *config.Backend) { l.IPAllowlist = []string{"10.0.0.0/8"} }, nil},
		{"no backend", func(l *ListenerConfig, b *config.Backend) {}, func(s *HTTPServer) { s.router.defaultBackend = "" }},
		{"unknown backend", func(l *ListenerConfig, b *config.Backend) {}, func(s *HTTPServer) { s.router.defaultBackend = "nope" }},
		{"rate limited", func(l *ListenerConfig, b *config.Backend) {}, func(s *HTTPServer) { s.RateLimiter = denyAll{} }},
		{"acl deny with status", func(l *ListenerConfig, b *config.Backend) {
			l.ACL = []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/x"}, Action: "deny", Status: 404}}
		}, nil},
		{"acl header and method", func(l *ListenerConfig, b *config.Backend) {
			l.ACL = []config.ACLRule{{Match: config.ACLMatch{Method: []string{"get"}, Headers: map[string]string{"X-Token": "bad"}}, Action: "deny"}}
		}, nil},
		{"acl host header is not a header", func(l *ListenerConfig, b *config.Backend) {
			l.ACL = []config.ACLRule{{Match: config.ACLMatch{Headers: map[string]string{"Host": "h"}}, Action: "deny"}}
		}, nil},
		{"acl allow then deny all", func(l *ListenerConfig, b *config.Backend) {
			l.ACL = []config.ACLRule{
				{Match: config.ACLMatch{SourceIP: []string{"10.0.0.0/8"}}, Action: "allow"},
				{Match: config.ACLMatch{PathRegex: "^/"}, Action: "deny", Status: 451},
			}
		}, nil},
		{"acl params form", func(l *ListenerConfig, b *config.Backend) {
			l.ACL = []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/x;"}, Action: "deny"}}
		}, nil},
		{"error page", func(l *ListenerConfig, b *config.Backend) {
			p := filepath.Join(t.TempDir(), "403.html")
			os.WriteFile(p, []byte("<p>custom</p>"), 0o644)
			l.IPDenylist = []string{"127.0.0.0/8"}
			l.ErrorPages = map[int]string{403: p}
		}, nil},
	}
	for _, g := range gates {
		var got [2]*http.Response
		for i, fast := range []bool{false, true} {
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
			b := &config.Backend{Servers: []string{be.addr()}}
			g.setup(l, b)
			s := fastTestSite(l, b)
			if g.after != nil {
				g.after(s)
			}
			addr := startTestGroup(t, s, fast)
			got[i] = exchange(t, addr, "GET /x;a=1 HTTP/1.1\r\nHost: h\r\nX-Token: bad\r\n\r\n", "GET")[0]
		}
		if got[0].StatusCode != got[1].StatusCode || readBody(got[0]) != readBody(got[1]) {
			t.Errorf("%s: slow %d, fast %d", g.name, got[0].StatusCode, got[1].StatusCode)
		}
		sh, fh := normHeader(got[0].Header), normHeader(got[1].Header)
		sh.Del("Content-Length")
		fh.Del("Content-Length")
		if !reflect.DeepEqual(sh, fh) {
			t.Errorf("%s: headers differ:\n slow %v\n fast %v", g.name, sh, fh)
		}
	}
}

type denyAll struct{}

func (denyAll) Allow() bool { return false }

// TestFastPath_HeaderRules: listener and route header rules apply to the
// request and the response as on the net/http path.
func TestFastPath_HeaderRules(t *testing.T) {
	be := newRawBackend(t)
	var got [2]*http.Response
	var upstream [2]*http.Request
	for i, fast := range []bool{false, true} {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http",
			Headers: config.HeadersConfig{
				RequestAdd:     map[string]string{"X-Added": "a", "X-Two": "2"},
				RequestSet:     map[string]string{"X-Set": "s", "user-agent": "rule-ua", "Host": "ignored"},
				RequestRemove:  []string{"X-Gone", "X-Real-IP"},
				ResponseAdd:    map[string]string{"X-Resp-Added": "r"},
				ResponseSet:    map[string]string{"Server": "nvelox-test"},
				ResponseRemove: []string{"X-Remove-Me"},
			},
			Routes: []config.RouteConfig{{
				Match:   config.RouteMatch{PathPrefix: "/headers"},
				Backend: "be",
				Headers: config.HeadersConfig{RequestSet: map[string]string{"X-Route": "yes"}, ResponseAdd: map[string]string{"X-Route-Resp": "1"}},
			}},
		}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		addr := startTestGroup(t, s, fast)
		got[i] = exchange(t, addr, "GET /headers HTTP/1.1\r\nHost: h\r\nX-Gone: 1\r\nX-Set: client\r\nUser-Agent: client-ua\r\n\r\n", "GET")[0]
		upstream[i] = be.last()
	}
	if sh, fh := normHeader(got[0].Header), normHeader(got[1].Header); !reflect.DeepEqual(sh, fh) {
		t.Errorf("response headers differ:\n slow %v\n fast %v", sh, fh)
	}
	if !reflect.DeepEqual(upstream[0].Header, upstream[1].Header) || upstream[0].Host != upstream[1].Host {
		t.Errorf("upstream headers differ:\n slow %v\n fast %v", upstream[0].Header, upstream[1].Header)
	}
}

// TestFastPath_TrustedProxyChain: behind a trusted proxy, the client comes
// from X-Forwarded-For and the chain is extended, as on the net/http path.
func TestFastPath_TrustedProxyChain(t *testing.T) {
	be := newRawBackend(t)
	for _, xff := range []string{
		"X-Forwarded-For: 203.0.113.7\r\n",
		"X-Forwarded-For: 198.51.100.1, 127.0.0.5\r\nX-Forwarded-For: 127.0.0.9\r\n",
		"X-Forwarded-For: garbage, 203.0.113.9\r\n",
		"X-Forwarded-For: [2001:db8::1]:443\r\nX-Real-IP: 192.0.2.1\r\n",
		"X-Real-IP: 192.0.2.44\r\nX-Forwarded-Proto: https\r\nForwarded: for=x\r\nX-Forwarded-Host: fh\r\n",
		"X-Forwarded-For: ::ffff:198.51.100.2\r\n",
	} {
		var upstream [2]*http.Request
		for i, fast := range []bool{false, true} {
			path := filepath.Join(t.TempDir(), "access.log")
			if err := logging.Init("warning", path, ""); err != nil {
				t.Fatal(err)
			}
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", TrustedProxies: []string{"127.0.0.0/8"}}
			s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
			addr := startTestGroup(t, s, fast)
			exchange(t, addr, "GET /ok HTTP/1.1\r\nHost: h\r\n"+xff+"\r\n", "GET")
			upstream[i] = be.last()
			lines := secLogLines(t, path, 1)
			if i == 1 {
				// compare client IP field of both runs below
			}
			upstream[i].Header.Set("X-Test-Log-Client", strings.Fields(lines[0])[0])
		}
		logging.Init("warning", "", "")
		if !reflect.DeepEqual(upstream[0].Header, upstream[1].Header) {
			t.Errorf("%q: upstream headers differ:\n slow %v\n fast %v", xff, upstream[0].Header, upstream[1].Header)
		}
	}
}

// TestFastPath_Shutdown: Stop lets an in-flight request finish and closes
// idle connections.
func TestFastPath_Shutdown(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	fastPathOff.Store(false)
	g := NewBindGroup("127.0.0.1:0", "http")
	g.AddSite(s)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	addr := g.BoundAddr().String()
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	busy, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	io.WriteString(busy, "GET /sleep/400ms HTTP/1.1\r\nHost: x\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- g.Stop(ctx)
	}()
	busy.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(busy), nil)
	if err != nil {
		t.Fatalf("in-flight request: %v", err)
	}
	if resp.StatusCode != 200 || !resp.Close {
		t.Errorf("in-flight response: %d, close %v", resp.StatusCode, resp.Close)
	}
	if err := <-done; err != nil {
		t.Errorf("Stop: %v", err)
	}
	idle.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := idle.Read(make([]byte, 1)); err == nil {
		t.Error("idle connection still open after Stop")
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("still accepting after Stop")
	}
}

// TestFastPath_ManyConcurrent: many clients, several loops, big and small
// bodies, all intact.
func TestFastPath_ManyConcurrent(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)
	bigWant := strings.Repeat("0123456789abcdef", 200<<10/16)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			br := bufio.NewReader(c)
			for i := 0; i < 30; i++ {
				p := fmt.Sprintf("/w%d/%d", w, i)
				if i%5 == 0 {
					p = "/big"
				}
				fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", p)
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					errs <- err
					return
				}
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					errs <- err
					return
				}
				want := "hello GET " + p
				if p == "/big" {
					want = bigWant
				}
				if string(body) != want {
					errs <- fmt.Errorf("%s: body %d bytes, want %d", p, len(body), len(want))
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// Every header a client can claim something about itself or the request
// with (untrustedForwardingHeaders) is taken off a request that does not
// come from a trusted proxy, in any spelling of its name, and kept on one
// that does: by the event loops, which know these names themselves, as by
// net/http.
func TestFastPath_UntrustedForwardingClaimsMatchNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	for _, trusted := range []bool{false, true} {
		bothPaths(t, func(t *testing.T, fast bool) {
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
			if trusted {
				l.TrustedProxies = []string{"127.0.0.0/8"}
			}
			addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}}), fast)
			for _, h := range untrustedForwardingHeaders {
				for _, name := range []string{h, strings.ToLower(h), strings.ToUpper(h)} {
					exchange(t, addr, "GET /claims HTTP/1.1\r\nHost: h\r\n"+name+": claimed\r\nX-Kept: yes\r\n\r\n", "GET")
					got := be.last().Header
					if kept := got.Get(h) == "claimed"; kept != trusted || got.Get("X-Kept") != "yes" {
						t.Errorf("%s sent as %q, peer trusted %v: the backend got %q (and X-Kept %q)", h, name, trusted, got.Get(h), got.Get("X-Kept"))
					}
				}
			}
		})
	}
}

// startTLSGroup starts a one-site HTTPS bind group on 127.0.0.1:0 through
// the fast path or net/http.
func startTLSGroup(t *testing.T, s *HTTPServer, fast bool) string {
	t.Helper()
	fastPathOff.Store(!fast)
	defer fastPathOff.Store(false)
	g := NewBindGroup("127.0.0.1:0", "https")
	g.AddSite(s)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if fast != (g.fast != nil) {
		t.Fatalf("fast path = %v, want %v", g.fast != nil, fast)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		g.Stop(ctx)
	})
	return g.BoundAddr().String()
}

func tlsSite(t *testing.T, be *config.Backend) *HTTPServer {
	cert, key := genCertWithCN(t, t.TempDir(), "example.test")
	l := &ListenerConfig{Name: "tls-site", Addr: "127.0.0.1:0", Protocol: "https",
		TLS: &config.TLSConfig{Cert: cert, Key: key}}
	return fastTestSite(l, be)
}

// tlsExchange sends raw request bytes over TLS (HTTP/1.1 ALPN) and reads
// the responses.
func tlsExchange(t *testing.T, addr, raw string, methods ...string) []*http.Response {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	var out []*http.Response
	for _, m := range methods {
		resp, err := http.ReadResponse(br, &http.Request{Method: m})
		if err != nil {
			t.Fatalf("reading response %d: %v", len(out)+1, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading body %d: %v", len(out)+1, err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		out = append(out, resp)
	}
	return out
}

// TestFastTLS_MatchesNetHTTP: HTTPS through the fast path answers like
// net/http, and the backend sees the same request (X-Forwarded-Proto https).
func TestFastTLS_MatchesNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	paths := []string{"/ok", "/chunked", "/trailer", "/close", "/sniff", "/304", "/204", "/hop", "/big", "/bigchunked", "/headers", "/101", "/q?x=1"}
	type result struct {
		resp *http.Response
		req  *http.Request
	}
	run := func(fast bool) map[string]result {
		s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
		addr := startTLSGroup(t, s, fast)
		out := map[string]result{}
		for _, p := range paths {
			r := tlsExchange(t, addr, "GET "+p+" HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-Proto: http\r\n\r\n", "GET")[0]
			out[p] = result{r, be.last()}
		}
		return out
	}
	slow, fast := run(false), run(true)
	for _, p := range paths {
		s, f := slow[p], fast[p]
		if s.resp.StatusCode != f.resp.StatusCode || readBody(s.resp) != readBody(f.resp) {
			t.Errorf("%s: slow %d %q, fast %d %q", p, s.resp.StatusCode, trunc(readBody(s.resp)), f.resp.StatusCode, trunc(readBody(f.resp)))
		}
		sh, fh := normHeader(s.resp.Header), normHeader(f.resp.Header)
		sh.Del("Content-Length")
		fh.Del("Content-Length")
		if !reflect.DeepEqual(sh, fh) {
			t.Errorf("%s: headers differ:\n slow %v\n fast %v", p, sh, fh)
		}
		if !reflect.DeepEqual(s.req.Header, f.req.Header) {
			t.Errorf("%s: backend headers differ:\n slow %v\n fast %v", p, s.req.Header, f.req.Header)
		}
		if f.req.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("%s: X-Forwarded-Proto %q", p, f.req.Header.Get("X-Forwarded-Proto"))
		}
	}
}

// TestFastTLS_PipelinedAndHandoff: many requests on one TLS connection,
// then a request with a body (net/http takes the connection over, TLS state
// included), then more requests.
func TestFastTLS_PipelinedAndHandoff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("warning", path, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("warning", "", "") })
	be := newRawBackend(t)
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	raw := ""
	var methods, want []string
	for i := 0; i < 10; i++ {
		raw += fmt.Sprintf("GET /p%d HTTP/1.1\r\nHost: example.test\r\n\r\n", i)
		methods = append(methods, "GET")
		want = append(want, fmt.Sprintf("hello GET /p%d", i))
	}
	raw += "POST /form HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
	methods = append(methods, "POST")
	want = append(want, "hello POST /form")
	raw += "GET /after HTTP/1.1\r\nHost: example.test\r\n\r\n"
	methods = append(methods, "GET")
	want = append(want, "hello GET /after")
	resps := tlsExchange(t, addr, raw, methods...)
	for i, r := range resps {
		if got := readBody(r); got != want[i] {
			t.Errorf("response %d: %q, want %q", i, got, want[i])
		}
	}
	if p := be.last().Header.Get("X-Forwarded-Proto"); p != "https" {
		t.Errorf("after the handoff: X-Forwarded-Proto %q, want https", p)
	}
	lines := secLogLines(t, path, 12)
	for _, l := range lines {
		if !strings.Contains(l, "scheme=https") {
			t.Errorf("access log line without scheme=https: %s", l)
		}
	}
}

// TestFastTLS_HTTP2AndPlaintext: an h2 client is served by net/http's
// HTTP/2 server; plaintext HTTP on the TLS port gets net/http's 400.
func TestFastTLS_HTTP2AndPlaintext(t *testing.T) {
	be := newRawBackend(t)
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "example.test"}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + addr + "/h2")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 || string(body) != "hello GET /h2" {
		t.Fatalf("h2: proto %s body %q", resp.Proto, body)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(c)
	if !strings.Contains(string(got), "Client sent an HTTP request to an HTTPS server") {
		t.Fatalf("plaintext on the TLS port: %q", got)
	}
}

// TestFastTLS_ManyConcurrent: many TLS clients, big and small bodies.
func TestFastTLS_ManyConcurrent(t *testing.T) {
	be := newRawBackend(t)
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	bigWant := strings.Repeat("0123456789abcdef", 200<<10/16)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			br := bufio.NewReader(c)
			for i := 0; i < 25; i++ {
				p := fmt.Sprintf("/w%d/%d", w, i)
				if i%4 == 0 {
					p = "/big"
				}
				fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", p)
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					errs <- err
					return
				}
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					errs <- err
					return
				}
				want := "hello GET " + p
				if p == "/big" {
					want = bigWant
				}
				if string(body) != want {
					errs <- fmt.Errorf("%s: body %d bytes, want %d", p, len(body), len(want))
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestFastPath_CloseDelimitedFINWithData: a backend whose last bytes and FIN
// arrive together; the end of the body must be seen (no new edge comes for
// it).
func TestFastPath_CloseDelimitedFINWithData(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)
	for i := 0; i < 200; i++ {
		r := exchange(t, addr, "GET /close HTTP/1.1\r\nHost: x\r\n\r\nGET /ok HTTP/1.1\r\nHost: x\r\n\r\n", "GET", "GET")
		if readBody(r[0]) != "until the end" || readBody(r[1]) != "hello GET /ok" {
			t.Fatalf("round %d: %q / %q", i, readBody(r[0]), readBody(r[1]))
		}
	}
}

// TestFastPath_RequestBodies: Content-Length bodies, sent whole, in pieces,
// pipelined, big; the backend gets exactly what net/http would send it.
func TestFastPath_RequestBodies(t *testing.T) {
	be := newRawBackend(t)
	big := strings.Repeat("0123456789", 300<<10/10)
	type sent struct{ body, sum, cl string }
	run := func(fast bool) []sent {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		addr := startTestGroup(t, s, fast)
		var out []sent
		record := func(r *http.Response) {
			req := be.last()
			out = append(out, sent{readBody(r), req.Header.Get("X-Test-Body-Sum"), req.Header.Get("Content-Length") + "/" + req.Header.Get("X-Test-Body-Len")})
		}
		// whole, then pipelined with a GET
		for _, r := range exchange(t, addr, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: x\r\n\r\n", "POST", "GET")[:1] {
			record(r)
		}
		// PUT, big body
		record(exchange(t, addr, "PUT /big HTTP/1.1\r\nHost: x\r\nContent-Length: "+strconv.Itoa(len(big))+"\r\n\r\n"+big, "PUT")[0])
		// in pieces, slowly
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, "POST /slow HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\nhel")
		time.Sleep(50 * time.Millisecond)
		io.WriteString(c, "lo, ")
		time.Sleep(50 * time.Millisecond)
		io.WriteString(c, "world")
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		record(resp)
		return out
	}
	slow, fast := run(false), run(true)
	if !reflect.DeepEqual(slow, fast) {
		t.Fatalf("bodies differ:\n slow %v\n fast %v", trunc(fmt.Sprint(slow)), trunc(fmt.Sprint(fast)))
	}
	if fast[1].cl != strconv.Itoa(len(big))+"/"+strconv.Itoa(len(big)) {
		t.Fatalf("big body: %s", fast[1].cl)
	}
}

// TestFastPath_RequestBodyStall: a client that stops sending its body gets
// 408 after the read limit, and the connection closes.
func TestFastPath_RequestBodyStall(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Timeouts: config.TimeoutConfig{Read: "300ms"}}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestTimeout || !resp.Close {
		t.Fatalf("status %d close %v, want 408 and close", resp.StatusCode, resp.Close)
	}
	if d := time.Since(start); d < 200*time.Millisecond || d > 2*time.Second {
		t.Fatalf("answered after %v", d)
	}
}

// TestFastPath_EarlyResponse: a backend that answers before reading the
// body: its response reaches the client, which is then closed.
func TestFastPath_EarlyResponse(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /early HTTP/1.1\r\nHost: x\r\nContent-Length: 4000000\r\n\r\n")
	go func() {
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for i := 0; i < 60; i++ {
			c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	}()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 413 || readBody(resp) != "nope" || !resp.Close {
		t.Fatalf("status %d body %q close %v", resp.StatusCode, readBody(resp), resp.Close)
	}
}

// TestFastPath_BodyRetriedOnlyBeforeSent: a connect failure is retried with
// the body (nothing of it was sent).
func TestFastPath_BodyRetriedOnlyBeforeSent(t *testing.T) {
	be := newRawBackend(t)
	deadAddr := deadTCPAddr(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{deadAddr, be.addr()}, Retry: config.RetryConfig{Attempts: 2}})
	addr := startTestGroup(t, s, true)
	for i := 0; i < 4; i++ {
		r := exchange(t, addr, "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc", "POST")[0]
		if r.StatusCode != 200 || be.last().Header.Get("X-Test-Body-Len") != "3" {
			t.Fatalf("request %d: %d, body len %s", i, r.StatusCode, be.last().Header.Get("X-Test-Body-Len"))
		}
	}
}

// TestFastPath_MaxBodySizeGoesToNetHTTP: a body over max_body_size is
// answered by net/http, as before.
func TestFastPath_MaxBodySizeGoesToNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	var got [2]int
	for i, fast := range []bool{false, true} {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", MaxBodySize: "4B"}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		addr := startTestGroup(t, s, fast)
		got[i] = exchange(t, addr, "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789", "POST")[0].StatusCode
	}
	if got[0] != got[1] {
		t.Fatalf("slow %d, fast %d", got[0], got[1])
	}
}

// TestFastPath_RequestIDNotCarriedOver: on one connection, a request of a
// site without request ids is not logged with the id of the request before
// it, which was another site's.
func TestFastPath_RequestIDNotCarriedOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("warning", path, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("warning", "", "") })
	be := newRawBackend(t)
	withIDs := &ListenerConfig{Name: "with-ids", Addr: "127.0.0.1:0", Protocol: "http", ServerNames: []string{"ids.test"}}
	withIDs.RequestID.Enabled = true
	without := &ListenerConfig{Name: "without-ids", Addr: "127.0.0.1:0", Protocol: "http", ServerNames: []string{"plain.test"}}
	fastPathOff.Store(false)
	g := NewBindGroup("127.0.0.1:0", "http")
	g.AddSite(fastTestSite(withIDs, &config.Backend{Servers: []string{be.addr()}}))
	g.AddSite(fastTestSite(without, &config.Backend{Servers: []string{be.addr()}}))
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		g.Stop(ctx)
	})
	if g.fast == nil {
		t.Fatal("fast path not enabled")
	}
	resps := exchange(t, g.BoundAddr().String(),
		"GET /a HTTP/1.1\r\nHost: ids.test\r\n\r\nGET /b HTTP/1.1\r\nHost: plain.test\r\n\r\n", "GET", "GET")
	if resps[0].Header.Get("X-Request-Id") == "" || resps[1].Header.Get("X-Request-Id") != "" {
		t.Fatalf("X-Request-Id: %q, then %q", resps[0].Header.Get("X-Request-Id"), resps[1].Header.Get("X-Request-Id"))
	}
	lines := secLogLines(t, path, 2)
	if len(lines) != 2 || !strings.Contains(lines[0], "rid="+resps[0].Header.Get("X-Request-Id")+" ") || !strings.Contains(lines[1], " rid=- ") {
		t.Errorf("access log:\n%s", strings.Join(lines, "\n"))
	}
}
