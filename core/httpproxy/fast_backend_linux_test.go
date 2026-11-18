//go:build linux

package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
)

// Tests of backend response heads past what an event loop parses itself
// (maxLoopResponseHead, maxFastHeaders fields, the loop's list of Connection
// names). They are parsed on a goroutine: relayed exactly as the net/http
// path relays them, and without keeping the loop from its other
// connections.

// scriptBackend answers each request with the bytes its script gives for
// the request's path.
type scriptBackend struct {
	ln     net.Listener
	script func(path string) (raw string, closeAfter bool)

	mu      sync.Mutex
	conns   int
	served  map[string]int
	written chan string // a path, once its response is fully written
}

func newScriptBackend(t *testing.T, script func(path string) (string, bool)) *scriptBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &scriptBackend{ln: ln, script: script, served: map[string]int{}, written: make(chan string, 64)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns++
			b.mu.Unlock()
			go b.serve(c)
		}
	}()
	return b
}

func (b *scriptBackend) addr() string { return b.ln.Addr().String() }

func (b *scriptBackend) connCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conns
}

func (b *scriptBackend) servedCount(path string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.served[path]
}

func (b *scriptBackend) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		path := req.URL.Path
		if !strings.HasPrefix(path, "/early") {
			io.Copy(io.Discard, req.Body) // "/early…" answers without reading the body
		}
		raw, closeAfter := b.script(path)
		if _, err := io.WriteString(c, raw); err != nil {
			return
		}
		b.mu.Lock()
		b.served[path]++
		b.mu.Unlock()
		select {
		case b.written <- path:
		default:
		}
		if closeAfter {
			return
		}
	}
}

// bhFields is n header fields "<prefix>-<i>: v<i>".
func bhFields(prefix string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s-%d: v%d\r\n", prefix, i, i)
	}
	return b.String()
}

// bhNames is a Connection value naming "<prefix>-<i>" for i < n, in mixed
// case.
func bhNames(prefix string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		name := fmt.Sprintf("%s-%d", prefix, i)
		switch i % 3 {
		case 1:
			name = strings.ToLower(name)
		case 2:
			name = strings.ToUpper(name)
		}
		b.WriteString(name)
	}
	return b.String()
}

func bhLinks(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "Link: </a%d.css>; rel=preload\r\n", i)
	}
	return b.String()
}

// bigHeadScript holds the responses of the tests below, by path.
func bigHeadScript() func(string) (string, bool) {
	const end = "Content-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
	many := "HTTP/1.1 200 OK\r\n" + bhFields("X-F", 300)
	m := map[string]string{
		"/ok":          "HTTP/1.1 200 OK\r\n" + end,
		"/many":        many + end,
		"/large":       "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("v", 200<<10) + "\r\n" + end,
		"/huge":        "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("v", 3<<20) + "\r\n" + end,
		"/names":       "HTTP/1.1 200 OK\r\nConnection: " + bhNames("X-Hop", 40) + "\r\n" + bhFields("X-Hop", 40) + bhFields("X-Keep", 5) + end,
		"/names-many":  "HTTP/1.1 200 OK\r\nConnection: " + bhNames("X-Hop", 40000) + "\r\n" + bhFields("X-Hop", 40000) + bhFields("X-Keep", 3) + end,
		"/fields-40k":  "HTTP/1.1 200 OK\r\n" + bhFields("X-F", 40000) + end,
		"/chunked":     many + "Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n",
		"/trailer":     many + "Content-Type: text/plain\r\nTrailer: X-Sum\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 42\r\n\r\n",
		"/close":       many + "Content-Type: text/plain\r\n\r\nuntil the end",
		"/close-large": "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("v", 200<<10) + "\r\nContent-Type: text/plain\r\n\r\nuntil the end",
		"/204":         "HTTP/1.1 204 No Content\r\n" + bhFields("X-F", 300) + "\r\n",
		"/304":         "HTTP/1.1 304 Not Modified\r\n" + bhFields("X-F", 300) + "ETag: \"x\"\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n",
		"/head":        many + "Content-Type: text/plain\r\nContent-Length: 100\r\n\r\n",
		"/sniff":       many + "Content-Length: 28\r\n\r\n<html><body>hi</body></html>",
		"/103-big-small": "HTTP/1.1 103 Early Hints\r\n" + bhLinks(200) + "\r\n" +
			"HTTP/1.1 200 OK\r\n" + end,
		"/103-small-big": "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n" +
			many + end,
		"/103-big-big": "HTTP/1.1 103 Early Hints\r\n" + bhLinks(200) + "\r\n" +
			many + end,
		"/bare-lf":        strings.ReplaceAll(many+"Content-Type: text/plain\r\nContent-Length: 2\r\n\r\n", "\r\n", "\n") + "ok",
		"/bad-after-many": many + "Bad@Name: x\r\n" + end,
		"/space-name":     many + "Bad Name: x\r\n" + end,
		"/503-many":       "HTTP/1.1 503 Service Unavailable\r\n" + bhFields("X-F", 300) + "Content-Length: 4\r\n\r\nbusy",
		"/early-many":     "HTTP/1.1 413 Request Entity Too Large\r\n" + bhFields("X-F", 300) + "Content-Length: 4\r\nConnection: close\r\n\r\nnope",
		"/early-open":     "HTTP/1.1 413 Request Entity Too Large\r\n" + bhFields("X-F", 300) + "Content-Length: 4\r\n\r\nnope",
	}
	return func(path string) (string, bool) {
		raw, ok := m[path]
		if !ok {
			raw = m["/ok"]
		}
		return raw, strings.HasPrefix(path, "/close") || path == "/bad-after-many" || path == "/early-many"
	}
}

func bhGet(path string, extra ...string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: example.test\r\n" + strings.Join(extra, "") + "\r\n"
}

// Response heads past a loop's limits reach the client exactly as the
// net/http path relays them.
func TestBigHeads_MatchNetHTTP(t *testing.T) {
	// Without header rules the client's head is built straight from the
	// parsed fields; with rules, through the list the rules work on.
	t.Run("no rules", func(t *testing.T) { bigHeadsMatchNetHTTP(t, config.HeadersConfig{}) })
	t.Run("header rules", func(t *testing.T) {
		bigHeadsMatchNetHTTP(t, config.HeadersConfig{
			ResponseAdd: map[string]string{"X-Added": "1"},
			ResponseSet: map[string]string{"X-F-5": "set", "X-Keep-0": "set"},
			// (Not Content-Type: for a body without a length net/http
			// then sniffs a type or not, as its own flush timer falls.)
			ResponseRemove: []string{"X-F-7", "X-Keep-1"},
		})
	})
}

func bigHeadsMatchNetHTTP(t *testing.T, rules config.HeadersConfig) {
	quietLog(t)
	be := newScriptBackend(t, bigHeadScript())
	type tc struct {
		name, raw string
		methods   []string // one per response read (an informational one counts)
	}
	g1 := []string{"GET"}
	cases := []tc{
		{"many fields", bhGet("/many"), g1},
		{"large field", bhGet("/large"), g1},
		{"connection names", bhGet("/names"), g1},
		{"40000 connection names, 40000 fields", bhGet("/names-many"), g1},
		{"40000 fields", bhGet("/fields-40k"), g1},
		{"chunked", bhGet("/chunked"), g1},
		{"trailer", bhGet("/trailer", "TE: trailers\r\n"), g1},
		{"close delimited", bhGet("/close"), g1},
		{"close delimited, large", bhGet("/close-large"), g1},
		{"204", bhGet("/204"), g1},
		{"304", bhGet("/304"), g1},
		{"head", "HEAD /head HTTP/1.1\r\nHost: example.test\r\n\r\n", []string{"HEAD"}},
		{"sniff", bhGet("/sniff"), g1},
		{"103 big, then small", bhGet("/103-big-small"), []string{"GET", "GET"}},
		{"103 small, then big", bhGet("/103-small-big"), []string{"GET", "GET"}},
		{"103 big, then big", bhGet("/103-big-big"), []string{"GET", "GET"}},
		{"bare LF", bhGet("/bare-lf"), g1},
		{"malformed after many", bhGet("/bad-after-many"), g1},
		{"name with a space", bhGet("/space-name"), g1},
	}
	run := func(fast bool) map[string][]*http.Response {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Headers: rules}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		addr := startTestGroup(t, s, fast)
		out := map[string][]*http.Response{}
		for _, c := range cases {
			out[c.name] = exchange(t, addr, c.raw, c.methods...)
		}
		return out
	}
	slow, fast := run(false), run(true)
	for _, c := range cases {
		for i := range c.methods {
			s, f := slow[c.name][i], fast[c.name][i]
			if s.StatusCode != f.StatusCode {
				t.Errorf("%s (response %d): status slow %d, fast %d", c.name, i+1, s.StatusCode, f.StatusCode)
				continue
			}
			if sb, fb := readBody(s), readBody(f); sb != fb {
				t.Errorf("%s (response %d): body differs:\n slow %q\n fast %q", c.name, i+1, trunc(sb), trunc(fb))
			}
			sh, fh := normHeader(s.Header), normHeader(f.Header)
			if s.StatusCode == http.StatusEarlyHints {
				// The hints themselves: the net/http path also repeats
				// nvelox's own fields on an informational response.
				sh, fh = http.Header{"Link": sh["Link"]}, http.Header{"Link": fh["Link"]}
			}
			if strings.HasPrefix(c.name, "close delimited") || c.name == "chunked" || c.name == "trailer" {
				sh.Del("Content-Length")
				fh.Del("Content-Length")
			}
			if !reflect.DeepEqual(sh, fh) {
				t.Errorf("%s (response %d): headers differ: slow %d names, fast %d names\n slow %s\n fast %s", c.name, i+1, len(sh), len(fh), trunc(fmt.Sprint(sh)), trunc(fmt.Sprint(fh)))
			}
			if !reflect.DeepEqual(s.Trailer, f.Trailer) {
				t.Errorf("%s (response %d): trailers differ: slow %v, fast %v", c.name, i+1, s.Trailer, f.Trailer)
			}
		}
	}
	// What the cases are meant to exercise did reach the client.
	if r := fast["many fields"][0]; r.Header.Get("X-F-299") != "v299" {
		t.Errorf("many fields: X-F-299 = %q", r.Header.Get("X-F-299"))
	}
	if r := fast["connection names"][0]; r.Header.Get("X-Hop-7") != "" || r.Header.Get("X-Keep-4") != "v4" {
		t.Errorf("connection names: X-Hop-7 = %q (want dropped), X-Keep-4 = %q", r.Header.Get("X-Hop-7"), r.Header.Get("X-Keep-4"))
	}
	if r := fast["40000 connection names, 40000 fields"][0]; r.Header.Get("X-Hop-39999") != "" || r.Header.Get("X-Keep-2") != "v2" {
		t.Errorf("40000 names: X-Hop-39999 = %q (want dropped), X-Keep-2 = %q", r.Header.Get("X-Hop-39999"), r.Header.Get("X-Keep-2"))
	}
	if r := fast["malformed after many"][0]; r.StatusCode != http.StatusBadGateway {
		t.Errorf("malformed after many: status %d, want 502", r.StatusCode)
	}
}

// The same over TLS: a head built off the loop goes out through the TLS
// writer.
func TestBigHeads_TLSMatchNetHTTP(t *testing.T) {
	quietLog(t)
	be := newScriptBackend(t, bigHeadScript())
	paths := []string{"/many", "/large", "/huge", "/close", "/close-large", "/chunked", "/names"}
	run := func(fast bool) map[string]*http.Response {
		s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
		addr := startTLSGroup(t, s, fast)
		out := map[string]*http.Response{}
		for _, p := range paths {
			out[p] = tlsExchange(t, addr, bhGet(p), "GET")[0]
		}
		return out
	}
	slow, fast := run(false), run(true)
	for _, p := range paths {
		s, f := slow[p], fast[p]
		if s.StatusCode != f.StatusCode || readBody(s) != readBody(f) {
			t.Errorf("%s: slow %d %q, fast %d %q", p, s.StatusCode, trunc(readBody(s)), f.StatusCode, trunc(readBody(f)))
		}
		sh, fh := normHeader(s.Header), normHeader(f.Header)
		if strings.HasPrefix(p, "/close") || p == "/chunked" {
			sh.Del("Content-Length")
			fh.Del("Content-Length")
		}
		if !reflect.DeepEqual(sh, fh) {
			t.Errorf("%s: headers differ: slow %d names, fast %d names", p, len(sh), len(fh))
		}
	}
	if got := len(fast["/huge"].Header.Get("X-Big")); got != 3<<20 {
		t.Errorf("/huge over TLS: X-Big has %d bytes, want %d", got, 3<<20)
	}
}

// After an informational response that was parsed off the loop, the
// response_header limit runs on for the response the backend still owes.
func TestBigHead_LimitRunsOnAfterInformational(t *testing.T) {
	quietLog(t)
	be := newScriptBackend(t, func(string) (string, bool) {
		return "HTTP/1.1 103 Early Hints\r\n" + bhLinks(200) + "\r\n", false // and then nothing
	})
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}, Timeouts: config.TimeoutConfig{ResponseHeader: "400ms"}})
	addr := startTestGroup(t, s, true)
	start := time.Now()
	rs := exchange(t, addr, bhGet("/hints"), "GET", "GET")
	if rs[0].StatusCode != http.StatusEarlyHints || len(rs[0].Header["Link"]) != 200 {
		t.Fatalf("first response: status %d with %d links", rs[0].StatusCode, len(rs[0].Header["Link"]))
	}
	if rs[1].StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("after the hints: status %d, want 504", rs[1].StatusCode)
	}
	if d := time.Since(start); d < 350*time.Millisecond || d > 8*time.Second {
		t.Fatalf("answered after %v, want about 400ms", d)
	}
}

// A backend connection goes back to the pool after a head past the limits,
// and the client's connection goes on: requests before and after it share
// both.
func TestBigHead_ConnectionsReused(t *testing.T) {
	quietLog(t)
	be := newScriptBackend(t, bigHeadScript())
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	addr := startTestGroup(t, s, true)
	raw := bhGet("/ok") + bhGet("/many") + bhGet("/large") + bhGet("/204") + bhGet("/ok") + bhGet("/103-big-big") + bhGet("/ok")
	rs := exchange(t, addr, raw, "GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET")
	want := []int{200, 200, 200, 204, 200, 103, 200, 200}
	for i, r := range rs {
		if r.StatusCode != want[i] {
			t.Fatalf("response %d: status %d, want %d", i+1, r.StatusCode, want[i])
		}
	}
	if rs[1].Header.Get("X-F-299") != "v299" || len(rs[2].Header.Get("X-Big")) != 200<<10 || len(rs[5].Header["Link"]) != 200 || rs[6].Header.Get("X-F-0") != "v0" {
		t.Fatalf("a response lost fields: X-F-299 %q, X-Big %d bytes, %d links, X-F-0 %q",
			rs[1].Header.Get("X-F-299"), len(rs[2].Header.Get("X-Big")), len(rs[5].Header["Link"]), rs[6].Header.Get("X-F-0"))
	}
	if n := be.connCount(); n != 1 {
		t.Fatalf("backend connections: %d, want 1 (reused)", n)
	}
}

// A status that is retried is retried when its head is past the limits.
func TestBigHead_RetryOnStatus(t *testing.T) {
	quietLog(t)
	bad := newScriptBackend(t, func(string) (string, bool) { return bigHeadScript()("/503-many") })
	good := newScriptBackend(t, bigHeadScript())
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	be := &config.Backend{Servers: []string{bad.addr(), good.addr()}, Retry: config.RetryConfig{Attempts: 2, On: "503"}}
	run := func(fast bool) (status int, field string) {
		s := fastTestSite(l, be)
		addr := startTestGroup(t, s, fast)
		// Both servers are tried in turn: whichever comes first, the
		// client gets the good one's answer.
		for i := 0; i < 4; i++ {
			r := exchange(t, addr, bhGet("/many"), "GET")[0]
			status, field = r.StatusCode, r.Header.Get("X-F-299")
			if status != 200 {
				return
			}
		}
		return
	}
	if st, f := run(true); st != 200 || f != "v299" {
		t.Fatalf("fast path: status %d X-F-299 %q, want 200 from the second server", st, f)
	}
	if bad.servedCount("/many") == 0 {
		t.Fatal("the failing server was never tried")
	}
	if st, f := run(false); st != 200 || f != "v299" {
		t.Fatalf("net/http path: status %d X-F-299 %q", st, f)
	}
}

// ---- response heads and bodies read as net/http reads them ----

// exchangeLoose is exchange for responses that may be cut: it returns the
// status, the header, what arrived of the body and whether the body was
// complete.
func exchangeLoose(t *testing.T, addr, raw, method string) (status int, hdr http.Header, body string, complete bool) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	io.WriteString(c, raw)
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		return 0, nil, "", false
	}
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b), err == nil
}

// Backend responses that are unusual, old-fashioned or malformed reach the
// client through the fast path exactly as through the net/http path.
func TestBackendResponses_MatchNetHTTP(t *testing.T) {
	quietLog(t)
	const ct = "Content-Type: text/plain\r\n"
	ext := ";" + strings.Repeat("e", 4000)
	responses := map[string]string{
		"/pragma":           "HTTP/1.1 200 OK\r\nPragma: no-cache\r\n" + ct + "Content-Length: 2\r\n\r\nok",
		"/pragma-cc":        "HTTP/1.1 200 OK\r\nPragma: no-cache\r\nCache-Control: max-age=60\r\n" + ct + "Content-Length: 2\r\n\r\nok",
		"/pragma-named":     "HTTP/1.1 200 OK\r\nPragma: no-cache\r\nConnection: cache-control\r\n" + ct + "Content-Length: 2\r\n\r\nok",
		"/close/http10-te":  "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n" + ct + "\r\n5\r\nhello\r\n0\r\n\r\n",
		"/status-spaces":    "HTTP/1.1   200 OK\r\n" + ct + "Content-Length: 2\r\n\r\nok",
		"/close/proto-20":   "HTTP/2.0 200 OK\r\n" + ct + "Content-Length: 2\r\n\r\nok",
		"/close/proto-09":   "HTTP/0.9 200 OK\r\n" + ct + "Content-Length: 2\r\n\r\nok",
		"/cl-twice":         "HTTP/1.1 200 OK\r\n" + ct + "Content-Length: 2\r\nContent-Length: 2\r\n\r\nok",
		"/close/cl-differ":  "HTTP/1.1 200 OK\r\n" + ct + "Content-Length: 2\r\nContent-Length: 02\r\n\r\nok",
		"/head-cl-twice":    "HTTP/1.1 200 OK\r\n" + ct + "Content-Length: 7\r\nContent-Length: 7\r\n\r\n",
		"/head-cl-19":       "HTTP/1.1 200 OK\r\n" + ct + "Content-Length: 9223372036854775807\r\n\r\n",
		"/ce-empty-first":   "HTTP/1.1 200 OK\r\nContent-Encoding: \r\nContent-Encoding: identity\r\nContent-Length: 28\r\n\r\n<html><body>hi</body></html>",
		"/head-trailer":     "HTTP/1.1 200 OK\r\n" + ct + "Trailer: X-Sum\r\nTransfer-Encoding: chunked\r\n\r\n",
		"/fold":             "HTTP/1.1 200 OK\r\nX-Fold: a\r\n b\r\n\t  c  \r\n \r\nSet-Cookie: k=v;\r\n\tPath=/\r\n" + ct + "Content-Length: 2\r\n\r\nok",
		"/close/fold-nocol": "HTTP/1.1 200 OK\r\nX-A\r\n : b\r\n" + ct + "Content-Length: 2\r\n\r\nok",
		"/close/te-fold":    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n \r\n" + ct + "\r\n2\r\nok\r\n0\r\n\r\n",
		"/close/te-twice":   "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n" + ct + "\r\n2\r\nok\r\n0\r\n\r\n",
		"/close/trailer-cl": "HTTP/1.1 200 OK\r\nTrailer: X-Sum, Content-Length\r\nTransfer-Encoding: chunked\r\n" + ct + "\r\n2\r\nok\r\n0\r\nX-Sum: 1\r\n\r\n",
		"/tiny-chunks":      "HTTP/1.1 200 OK\r\n" + ct + "Transfer-Encoding: chunked\r\n\r\n" + strings.Repeat("1\r\nx\r\n", 5000) + "0\r\n\r\n",
		"/close/chunk-ext":  "HTTP/1.1 200 OK\r\n" + ct + "Transfer-Encoding: chunked\r\n\r\n" + strings.Repeat("1"+ext+"\r\nx\r\n", 8) + "0\r\n\r\n",
		"/chunk-ext-ok":     "HTTP/1.1 200 OK\r\n" + ct + "Transfer-Encoding: chunked\r\n\r\n" + strings.Repeat("1"+ext+"\r\nx\r\n", 3) + "0\r\n\r\n",
	}
	be := newScriptBackend(t, func(path string) (string, bool) {
		return responses[path], strings.HasPrefix(path, "/close/")
	})
	type outcome struct {
		status   int
		hdr      http.Header
		body     string
		complete bool
	}
	run := func(fast bool) map[string]outcome {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
		addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}}), fast)
		out := map[string]outcome{}
		for path := range responses {
			method := "GET"
			if strings.HasPrefix(path, "/head-") {
				method = "HEAD"
			}
			st, h, b, ok := exchangeLoose(t, addr, method+" "+path+" HTTP/1.1\r\nHost: example.test\r\nTE: trailers\r\n\r\n", method)
			out[path] = outcome{st, h, b, ok}
		}
		return out
	}
	slow, fast := run(false), run(true)
	for path := range responses {
		s, f := slow[path], fast[path]
		if s.status != f.status || s.body != f.body || s.complete != f.complete {
			t.Errorf("%s: slow status %d body %q complete %v; fast status %d body %q complete %v", path, s.status, trunc(s.body), s.complete, f.status, trunc(f.body), f.complete)
			continue
		}
		if s.hdr == nil {
			continue
		}
		sh, fh := normHeader(s.hdr), normHeader(f.hdr)
		for _, h := range []http.Header{sh, fh} {
			if h.Get("Transfer-Encoding") != "" || strings.Contains(path, "chunk") || strings.Contains(path, "http10") {
				h.Del("Content-Length") // net/http may compute one for a short streamed body
			}
		}
		if !reflect.DeepEqual(sh, fh) {
			t.Errorf("%s: headers differ:\n slow %v\n fast %v", path, sh, fh)
		}
	}
	// What the cases are about did happen (on both paths, by the above).
	for path, want := range map[string]func(o outcome) bool{
		"/pragma":          func(o outcome) bool { return o.hdr.Get("Cache-Control") == "no-cache" },
		"/pragma-cc":       func(o outcome) bool { return o.hdr.Get("Cache-Control") == "max-age=60" },
		"/close/http10-te": func(o outcome) bool { return o.body == "5\r\nhello\r\n0\r\n\r\n" },
		"/status-spaces":   func(o outcome) bool { return o.status == 200 && o.body == "ok" },
		"/close/proto-20":  func(o outcome) bool { return o.status == 200 && o.body == "ok" },
		"/head-cl-twice":   func(o outcome) bool { return len(o.hdr["Content-Length"]) == 1 },
		"/head-trailer":    func(o outcome) bool { return o.hdr.Get("Trailer") != "" },
		"/fold": func(o outcome) bool {
			return o.hdr.Get("X-Fold") == "a b c" && o.hdr.Get("Set-Cookie") == "k=v; Path=/"
		},
		"/close/fold-nocol": func(o outcome) bool { return o.status == 502 },
		"/close/te-fold":    func(o outcome) bool { return o.status == 502 },
		"/close/te-twice":   func(o outcome) bool { return o.status == 502 },
		"/close/trailer-cl": func(o outcome) bool { return o.status == 502 },
		"/close/cl-differ":  func(o outcome) bool { return o.status == 502 },
		"/tiny-chunks":      func(o outcome) bool { return o.body == strings.Repeat("x", 5000) && o.complete },
		"/close/chunk-ext":  func(o outcome) bool { return !o.complete },
		"/chunk-ext-ok":     func(o outcome) bool { return o.body == "xxx" && o.complete },
	} {
		if !want(fast[path]) {
			t.Errorf("%s: fast path gave status %d body %q complete %v header %v", path, fast[path].status, trunc(fast[path].body), fast[path].complete, fast[path].hdr)
		}
	}
}

// A chunked body that comes in very small chunks goes to the client in few
// large ones: what one read brought is one chunk, and one write. (A write
// per chunk let a backend keep a loop busy at a byte per system call.)
func TestTinyChunksGoOutCoalesced(t *testing.T) {
	quietLog(t)
	const n = 200000
	be := newScriptBackend(t, func(string) (string, bool) {
		return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + strings.Repeat("1\r\nx\r\n", n) + "0\r\n\r\n", false
	})
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}}), true)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	io.WriteString(c, bhGet("/tiny"))
	br := bufio.NewReader(c)
	// The head, then the chunks as they are on the wire.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	chunks, data := 0, 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("after %d chunks: %v", chunks, err)
		}
		var size int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "%x", &size); err != nil {
			t.Fatalf("chunk line %q: %v", line, err)
		}
		if size == 0 {
			break
		}
		if _, err := io.CopyN(io.Discard, br, int64(size)+2); err != nil {
			t.Fatal(err)
		}
		chunks++
		data += size
	}
	if data != n {
		t.Fatalf("%d bytes of data, want %d", data, n)
	}
	// 1.2 MB from the backend in reads of at most 64 KiB: a few dozen
	// chunks, however the reads fell.
	if chunks > n/100 {
		t.Fatalf("the client got %d chunks for the backend's %d", chunks, n)
	}
}
