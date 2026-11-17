//go:build linux

package httpproxy

// HTTP/3 served by the event loops, with quic-go's HTTP/3 client.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/lb"

	"github.com/nvelox/ngx/h3"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2/hpack"
)

// h3ServedBy has the groups a test starts serve HTTP/3 from the event
// loops (true) or with the quic-go server, and puts back what was set when
// the test, and with it its groups, is over.
func h3ServedBy(t *testing.T, loops bool) {
	t.Helper()
	old := h3OnLoops
	h3OnLoops = loops
	t.Cleanup(func() { h3OnLoops = old })
}

// quicGoPath: the test is about the quic-go server of HTTP/3, which serves
// it where there are no event loops.
func quicGoPath(t *testing.T) { t.Helper(); h3ServedBy(t, false) }

// onBothH3Servers runs a test of HTTP/3 against each of its two servers.
func onBothH3Servers(t *testing.T, test func(t *testing.T)) {
	t.Run("the quic-go server", func(t *testing.T) { h3ServedBy(t, false); test(t) })
	t.Run("the loops", func(t *testing.T) { h3ServedBy(t, true); test(t) })
}

// A group that is simply started serves its HTTP/3 from the event loops,
// and has no quic-go server beside them; a test that asks for the quic-go
// server gets that one alone.
func TestH3Loops_AreTheDefault(t *testing.T) {
	pki := newCAPKI(t, "h3-loops-ca")
	g := startGroup(t, freeAddr(t), h3Site(t, pki, h3RawBackend))
	if g.h3loops == nil || g.http3Server != nil {
		t.Errorf("a group started as it is: HTTP/3 on the loops %v, a quic-go server %v; want the loops alone", g.h3loops != nil, g.http3Server != nil)
	}
	t.Run("the quic-go server when asked for", func(t *testing.T) {
		quicGoPath(t)
		g := startGroup(t, freeAddr(t), h3Site(t, pki, h3RawBackend))
		if g.h3loops != nil || g.http3Server == nil {
			t.Errorf("HTTP/3 on the loops %v, a quic-go server %v; want the quic-go server alone", g.h3loops != nil, g.http3Server != nil)
		}
	})
}

// startH3Loops starts a group whose HTTP/3 the event loops serve, with one
// site in front of a backend that runs handler, and returns its address.
func startH3Loops(t *testing.T, handler http.HandlerFunc, tweak ...func(*ListenerConfig)) (string, *BindGroup, *caPKI) {
	t.Helper()
	h3ServedBy(t, true)
	pki := newCAPKI(t, "h3-loops-ca")
	site := h3Site(t, pki, handler, tweak...)
	addr := freeAddr(t)
	g := startGroup(t, addr, site)
	if g.h3loops == nil {
		t.Fatal("the group's HTTP/3 is not on the event loops")
	}
	return addr, g, pki
}

// h3Client opens an HTTP/3 connection to addr.
func h3Client(t *testing.T, addr string, pki *caPKI) (*http3.ClientConn, *quic.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	return (&http3.Transport{}).NewClientConn(conn), conn
}

type h3Result struct {
	status int
	header http.Header
	body   []byte
	proto  string
}

func h3Do(ctx context.Context, cc *http3.ClientConn, method, url string, body io.Reader, hdr ...string) (*h3Result, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &h3Result{status: resp.StatusCode, header: resp.Header, body: b, proto: resp.Proto}, nil
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// A GET: the backend's answer comes back over HTTP/3, with the fields
// nvelox adds, and the backend is told who asked and how.
func TestH3Loops_Get(t *testing.T) {
	var gotXFF, gotProto, gotHost atomic.Value
	addr, _, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		gotXFF.Store(r.Header.Get("X-Forwarded-For"))
		gotProto.Store(r.Header.Get("X-Forwarded-Proto"))
		gotHost.Store(r.Host)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Backend", "yes")
		io.WriteString(w, "hello over HTTP/3")
	})
	cc, _ := h3Client(t, addr, pki)
	r, err := h3Do(testCtx(t), cc, "GET", "https://localhost/hello?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.status != 200 || string(r.body) != "hello over HTTP/3" || r.proto != "HTTP/3.0" {
		t.Fatalf("status %d, body %q, proto %s", r.status, r.body, r.proto)
	}
	for name, want := range map[string]string{"Content-Type": "text/plain; charset=utf-8", "X-Backend": "yes", "X-Content-Type-Options": "nosniff"} {
		if got := r.header.Get(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if r.header.Get("Date") == "" {
		t.Error("no Date field")
	}
	if xff, _ := gotXFF.Load().(string); xff != "127.0.0.1" {
		t.Errorf("the backend's X-Forwarded-For: %q, want 127.0.0.1", xff)
	}
	if p, _ := gotProto.Load().(string); p != "https" {
		t.Errorf("the backend's X-Forwarded-Proto: %q, want https", p)
	}
	if h, _ := gotHost.Load().(string); h != "localhost" {
		t.Errorf("the backend's Host: %q, want localhost", h)
	}
}

// Bodies in both directions, larger than the windows: a POST comes back
// whole, and so does a long answer.
func TestH3Loops_Bodies(t *testing.T) {
	addr, _, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo":
			b, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(b)
		case "/sum", "/late":
			if r.URL.Path == "/late" {
				time.Sleep(300 * time.Millisecond) // the backend reads late
			}
			h := sha256.New()
			n, _ := io.Copy(h, r.Body)
			fmt.Fprintf(w, "%d %x", n, h.Sum(nil))
		case "/long":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(bytes.Repeat([]byte("0123456789abcdef"), 5<<20/16))
		}
	})
	cc, _ := h3Client(t, addr, pki)
	ctx := testCtx(t)
	body := make([]byte, 3<<20)
	for i := range body {
		body[i] = byte(i * 13)
	}
	r, err := h3Do(ctx, cc, "POST", "https://localhost/echo", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if r.status != 200 || !bytes.Equal(r.body, body) {
		t.Fatalf("echo: status %d, %d bytes back of %d (equal: %v)", r.status, len(r.body), len(body), bytes.Equal(r.body, body))
	}
	r, err = h3Do(ctx, cc, "PUT", "https://localhost/sum", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%d %x", len(body), sha256.Sum256(body)); string(r.body) != want {
		t.Errorf("sum: %q, want %q", r.body, want)
	}
	large := bytes.Repeat(body, 4)
	r, err = h3Do(ctx, cc, "POST", "https://localhost/late", bytes.NewReader(large))
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%d %x", len(large), sha256.Sum256(large)); string(r.body) != want {
		t.Errorf("a body its backend reads late: %q, want %q", r.body, want)
	}
	r, err = h3Do(ctx, cc, "GET", "https://localhost/long", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.body) != 5<<20 || !bytes.Equal(r.body[:16], []byte("0123456789abcdef")) {
		t.Errorf("long: %d bytes, want %d", len(r.body), 5<<20)
	}
}

// A client that comes back resumes its session on the loops, and without
// early data: the server's session ticket offers none, and a request sent
// as soon as the client may send is served once, on a connection that did
// not use 0-RTT (the check of TestHTTP3_NoZeroRTT).
func TestH3Loops_NoZeroRTT(t *testing.T) {
	var posts atomic.Int64
	addr, _, pki := startH3Loops(t, countPosts(&posts))
	noZeroRTT(t, addr, pki, &posts)
}

// client_auth per site over HTTP/3 on the loops, on new connections and on
// resumed ones (the checks of TestHTTP3_ClientAuth).
func TestH3Loops_ClientAuth(t *testing.T) {
	h3ServedBy(t, true)
	clientAuthOverHTTP3(t, func(addr string, sites ...*HTTPServer) {
		if g := startGroup(t, addr, sites...); g.h3loops == nil {
			t.Fatal("the group's HTTP/3 is not on the event loops")
		}
	})
}

// A client that moves, over HTTP/3. A request that begins after the move
// is the new address's: in the forwarding headers of a request the loops
// serve and of one net/http's handlers serve, and in the PROXY header of a
// backend connection opened for it, on either path. A backend connection
// that was opened before the move stays as it is.
func TestH3Loops_ClientMoves(t *testing.T) {
	h3ServedBy(t, true)
	pki := newCAPKI(t, "h3-loops-ca")
	var mu sync.Mutex
	told := map[string]string{} // by Host: the X-Forwarded-For of the last request
	record := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		told[r.Host] = r.Header.Get("X-Forwarded-For")
		mu.Unlock()
		io.WriteString(w, "ok")
	}
	xff := func(host string) string {
		mu.Lock()
		defer mu.Unlock()
		return told[host]
	}
	tlsCfg := &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}
	// The loops serve "localhost"; net/http's handlers serve "b.test"
	// (compression); "c.test" and "a.test" are the same two with a
	// send_proxy_v2 backend.
	fast := h3Site(t, pki, record)
	fast.Listener.Name, fast.Listener.DefaultServer = "fast", true
	slow := h3HandlerSite(t, pki, record)
	slow.Listener.Name, slow.Listener.ServerNames = "slow", []string{"b.test"}
	fastBE, slowBE := newProxyBackend(t, nil, nil), newProxyBackend(t, nil, nil)
	fastPP := fastTestSite(&ListenerConfig{Name: "fast-pp", Addr: ":0", Protocol: "https", HTTP3: true,
		ServerNames: []string{"c.test"}, TLS: tlsCfg}, &config.Backend{Servers: []string{fastBE.addr()}, SendProxyV2: true})
	lp := &ListenerConfig{Name: "slow-pp", Addr: ":0", Protocol: "https", HTTP3: true,
		ServerNames: []string{"a.test"}, TLS: tlsCfg}
	lp.Compression.Enabled = true
	slowPP := fastTestSite(lp, &config.Backend{Servers: []string{slowBE.addr()}, SendProxyV2: true})
	addr := freeAddr(t)
	g := startGroup(t, addr, fast, slow, fastPP, slowPP)
	if g.h3loops == nil {
		t.Fatal("the group's HTTP/3 is not on the event loops")
	}

	ctx := testCtx(t)
	pc := newRovingConn(t)
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	conn, err := quic.Dial(ctx, pc, raddr, h3ClientTLS(pki), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	cc := (&http3.Transport{}).NewClientConn(conn)
	get := func(url string) string {
		t.Helper()
		r, err := h3Do(ctx, cc, "GET", url, nil)
		if err != nil || r.status != 200 {
			t.Fatalf("GET %s: %v, %+v", url, err, r)
		}
		return string(r.body)
	}
	home := pc.LocalAddr().String()

	// Before the move: everyone is told of the first address.
	get("https://localhost/")
	get("https://b.test/")
	if a, b := xff("localhost"), xff("b.test"); a != "127.0.0.1" || b != "127.0.0.1" {
		t.Fatalf("before the move the backends were told %q (loops) and %q (handlers), want 127.0.0.1", a, b)
	}
	if got := parseProxyAnswer(t, get("https://c.test/")); got.conn != 0 || got.src != home {
		t.Fatalf("before the move, on the loops: %+v, want the backend's connection 0 naming %s", got, home)
	}

	// The client is at 127.0.0.2 from here on. The request that brings the
	// news began before the server knew.
	away := pc.moveTo(t, "127.0.0.2").LocalAddr().String()
	get("https://localhost/")
	waitCount(t, "moves of the connection", g.h3loops.moves.Load, 1)

	get("https://localhost/")
	get("https://b.test/")
	if a, b := xff("localhost"), xff("b.test"); a != "127.0.0.2" || b != "127.0.0.2" {
		t.Errorf("after the move the backends were told %q (loops) and %q (handlers), want 127.0.0.2", a, b)
	}
	// The backend connection that was open is used as it is, while it is
	// free; one opened now names the new address.
	if got := parseProxyAnswer(t, get("https://c.test/")); got.conn != 0 || got.src != home {
		t.Errorf("after the move, the open backend connection: %+v, want connection 0 still naming %s", got, home)
	}
	fastBE.hold()
	held := make(chan string, 1)
	go func() {
		r, err := h3Do(ctx, cc, "GET", "https://c.test/hold", nil)
		if err != nil {
			held <- err.Error()
			return
		}
		held <- string(r.body)
	}()
	fastBE.waitHeld(1)
	if got := parseProxyAnswer(t, get("https://c.test/")); got.conn != 1 || got.src != away {
		t.Errorf("after the move, a new backend connection on the loops: %+v, want connection 1 naming %s", got, away)
	}
	fastBE.release()
	if got := parseProxyAnswer(t, <-held); got.conn != 0 {
		t.Errorf("the held request: %+v, want connection 0", got)
	}
	// The handlers' first connection to their backend is opened only now.
	if got := parseProxyAnswer(t, get("https://a.test/")); got.conn != 0 || got.src != away {
		t.Errorf("after the move, a new backend connection of the handlers: %+v, want connection 0 naming %s", got, away)
	}
	fastBE.noneRefused()
	slowBE.noneRefused()
}

// A client that moves on purpose, over HTTP/3: from one network to the
// next and the next. For each move it needs a connection ID of the
// server's it has not used, and the server one of the client's (it holds
// four of them, as the quic-go server does: with the two a server holds
// when it says nothing, a client like this one could move once). After
// each move the backend is told the client's new address.
func TestH3Loops_ClientMovesOnPurpose(t *testing.T) {
	var told atomic.Value
	addr, g, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		told.Store(r.Header.Get("X-Forwarded-For"))
		io.WriteString(w, "ok")
	})
	ctx := testCtx(t)
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	tr, _ := newTransport(t)
	conn, err := tr.Dial(ctx, raddr, h3ClientTLS(pki), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	cc := (&http3.Transport{}).NewClientConn(conn)
	get := func(what string) {
		t.Helper()
		if r, err := h3Do(ctx, cc, "GET", "https://localhost/", nil); err != nil || r.status != 200 {
			t.Fatalf("%s: %v, %+v", what, err, r)
		}
	}
	get("before any move")
	if xff, _ := told.Load().(string); xff != "127.0.0.1" {
		t.Fatalf("before any move the backend was told %q", xff)
	}
	for i, ip := range []string{"127.0.0.2", "127.0.0.3", "127.0.0.4"} {
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
		if err != nil {
			t.Fatal(err)
		}
		ntr := &quic.Transport{Conn: pc}
		defer func() { ntr.Close(); pc.Close() }()
		path, err := conn.AddPath(ntr)
		if err != nil {
			t.Fatal(err)
		}
		probe, stop := context.WithTimeout(ctx, 10*time.Second)
		err = path.Probe(probe)
		stop()
		if err != nil {
			t.Fatalf("move %d, to %s: the client's probe of its new path was not answered: %v", i+1, ip, err)
		}
		if err := path.Switch(); err != nil {
			t.Fatal(err)
		}
		get("the request that follows move " + itoa(i+1))
		waitCount(t, "moves of the connection", g.h3loops.moves.Load, int64(i+1))
		get("after move " + itoa(i+1))
		if xff, _ := told.Load().(string); xff != ip {
			t.Errorf("after move %d the backend was told %q, want %s", i+1, xff, ip)
		}
	}
}

// lockedBuffer is a log's writer that a test reads while handlers write.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// h3Answer reads the frames of a response from str until a HEADERS frame
// with a status has arrived and returns that status; body, when not nil,
// collects the DATA frames that come before the stream ends (the final
// answer is then read to its end).
func h3Answer(t *testing.T, str *quic.Stream, pending *[]byte, body *[]byte) string {
	t.Helper()
	tmp := make([]byte, 4096)
	status := ""
	for {
		for {
			typ, length, n := h3.FrameHeader(*pending)
			if n == 0 || uint64(len(*pending)-n) < length {
				break
			}
			payload := (*pending)[n : n+int(length)]
			*pending = (*pending)[n+int(length):]
			switch typ {
			case h3.FrameHeaders:
				var scratch []byte
				h3.DecodeFields(payload, &scratch, 1<<20, func(name, value []byte) error {
					if string(name) == ":status" {
						status = string(value)
					}
					return nil
				})
				if body == nil {
					return status
				}
			case h3.FrameData:
				if body != nil {
					*body = append(*body, payload...)
				}
			}
		}
		n, err := str.Read(tmp)
		*pending = append(*pending, tmp[:n]...)
		if err != nil && n == 0 {
			if err != io.EOF || status == "" {
				t.Fatalf("the answer ended with %v after status %q", err, status)
			}
			return status
		}
	}
}

// What only net/http's handlers do, over HTTP/3 on the loops. Expect:
// 100-continue: the client is told to go on, with an interim response,
// when the request's body is first read, and gets the answer after it has
// sent the body. A handler that fails: its stream is reset, the failure is
// logged with its stack, and the connection serves the next request. A
// backend that breaks off its answer (the proxy's handler gives up with
// http.ErrAbortHandler): the stream is reset too, and nothing is logged as
// a failure of the handler.
func TestH3Loops_HandlersExpectAndFailures(t *testing.T) {
	h3ServedBy(t, true)
	pki := newCAPKI(t, "h3-loops-ca")
	site := h3HandlerSite(t, pki, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo":
			b, _ := io.ReadAll(r.Body)
			w.Write(b)
		case "/cut":
			// Half an answer, then the connection is gone.
			w.Header().Set("Content-Length", "100000")
			w.Write(make([]byte, 1000))
			w.(http.Flusher).Flush()
			if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
				c.Close()
			}
		default:
			io.WriteString(w, "from a handler: "+r.URL.Path)
		}
	})
	// The log of the handlers' failures, and a handler that fails when the
	// test says so.
	logged := &lockedBuffer{}
	log.SetOutput(logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	var fail atomic.Bool
	probe := func(point string) {
		if point == "handler" && fail.CompareAndSwap(true, false) {
			panic("test: the handler failed")
		}
	}
	loopPanicProbe.Store(&probe)
	t.Cleanup(func() { loopPanicProbe.Store(nil) })
	addr := freeAddr(t)
	g := startGroup(t, addr, site)
	if g.h3loops == nil {
		t.Fatal("the group's HTTP/3 is not on the event loops")
	}
	ctx := testCtx(t)

	// Expect: 100-continue.
	conn := rawH3(t, addr, pki)
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	str.SetDeadline(time.Now().Add(10 * time.Second))
	str.Write(h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/echo",
		"expect", "100-continue", "content-length", "5"))
	var pending, body []byte
	if status := h3Answer(t, str, &pending, nil); status != "100" {
		t.Fatalf("before the body was sent the client was answered %q, want the interim 100", status)
	}
	str.Write(h3DataFrame([]byte("hello")))
	str.Close()
	if status := h3Answer(t, str, &pending, &body); status != "200" || string(body) != "hello" {
		t.Errorf("after the body: status %q, body %q; want 200 and the body back", status, body)
	}

	// A handler that fails, then a backend that breaks off its answer; a
	// request after each.
	cc, _ := h3Client(t, addr, pki)
	fine := func(what string) {
		t.Helper()
		r, err := h3Do(ctx, cc, "GET", "https://localhost/next", nil)
		if err != nil || r.status != 200 || string(r.body) != "from a handler: /next" {
			t.Fatalf("the request %s: %v, %+v", what, err, r)
		}
	}
	fine("before any failure")
	fail.Store(true)
	var reset *http3.Error
	if r, err := h3Do(ctx, cc, "GET", "https://localhost/fails", nil); !errors.As(err, &reset) || uint64(reset.ErrorCode) != uint64(h3.ErrInternal) || !reset.Remote {
		t.Errorf("a handler that fails: %+v, %v; want the stream reset by the server with H3_INTERNAL_ERROR", r, err)
	}
	fine("after a handler failed")
	if n := strings.Count(logged.String(), "panic serving"); n != 1 || !strings.Contains(logged.String(), "test: the handler failed") || !strings.Contains(logged.String(), "http3: panic serving") {
		t.Errorf("the log after a handler failed (%d entries): %q", n, logged.String())
	}
	if r, err := h3Do(ctx, cc, "GET", "https://localhost/cut", nil); err == nil {
		t.Errorf("a backend that broke off its answer: the client got %d bytes with status %d and no error", len(r.body), r.status)
	}
	fine("after a backend broke off its answer")
	if n := strings.Count(logged.String(), "panic serving"); n != 1 {
		t.Errorf("a backend that broke off its answer was logged as a failure of the handler: %q", logged.String())
	}
}

// The rules a request is held to before anything serves it, over HTTP/3:
// those of the HTTP/2 connections, on a site the loops serve and on one
// whose requests all go to net/http's handlers. A request that breaks one
// has its stream reset as malformed (H3_MESSAGE_ERROR); one that breaks it
// with its head alone never reaches a backend; and the connection serves
// the next.
func TestH3Loops_RequestRules(t *testing.T) {
	head := func(fields ...string) [][]byte { return [][]byte{h3HeadersFrame(fields...)} }
	with := func(base []string, more ...string) []string { return append(append([]string{}, base...), more...) }
	post := []string{":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw"}
	type rule struct {
		name  string
		parts [][]byte
	}
	for _, kind := range []string{"a site the loops serve", "a site of the handlers"} {
		t.Run(kind, func(t *testing.T) {
			var seen atomic.Int64
			backend := func(w http.ResponseWriter, r *http.Request) {
				seen.Add(1)
				h3RawBackend(w, r)
			}
			var addr string
			var pki *caPKI
			if kind == "a site the loops serve" {
				addr, _, pki = startH3Loops(t, backend)
			} else {
				h3ServedBy(t, true)
				pki = newCAPKI(t, "h3-loops-ca")
				addr = freeAddr(t)
				if g := startGroup(t, addr, h3HandlerSite(t, pki, backend)); g.h3loops == nil {
					t.Fatal("the group's HTTP/3 is not on the event loops")
				}
			}
			conn := rawH3(t, addr, pki)
			refused := func(rules []rule) {
				t.Helper()
				for _, r := range rules {
					status, _, err := rawExchange(t, conn, r.parts...)
					if got := streamCode(err); status != "" || got != int64(h3.ErrMessage) {
						t.Errorf("%s: status %q, stream error %#x (%v); want no answer and H3_MESSAGE_ERROR (%#x)", r.name, status, got, err, uint64(h3.ErrMessage))
					}
				}
			}
			// Broken by the head alone.
			refused([]rule{
				{"a :protocol field", head(with(h3GetFields, ":protocol", "websocket")...)},
				{"an extended CONNECT", head(":method", "CONNECT", ":protocol", "websocket", ":scheme", "https", ":authority", "localhost", ":path", "/ws")},
				{"a CONNECT with a path", head(":method", "CONNECT", ":authority", "localhost:443", ":path", "/x")},
				{"a CONNECT with a scheme", head(":method", "CONNECT", ":authority", "localhost:443", ":scheme", "https")},
				{"no :method", head(":scheme", "https", ":authority", "localhost", ":path", "/raw")},
				{"no :scheme", head(":method", "GET", ":authority", "localhost", ":path", "/raw")},
				{"a scheme that is not the web's", head(":method", "GET", ":scheme", "ftp", ":authority", "localhost", ":path", "/raw")},
				{"user information in :authority", head(":method", "GET", ":scheme", "https", ":authority", "user@localhost", ":path", "/raw")},
				{"user information in Host", head(":method", "GET", ":scheme", "https", ":path", "/raw", "host", "user@localhost")},
				{"a :path without a slash", head(":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "raw")},
				{"a :path net/url does not take", head(":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/%zz")},
				{"two different Content-Lengths", [][]byte{h3HeadersFrame(with(post, "content-length", "3", "content-length", "4")...), h3DataFrame([]byte("abc"))}},
			})
			if n := seen.Load(); n != 0 {
				t.Errorf("%d of the requests that broke a rule with their head reached the backend", n)
			}
			// Broken behind the head, in a request that announces trailers
			// (which makes it one for the handlers on either site): a body
			// longer than its Content-Length, and a trailer that may not be
			// one.
			refused([]rule{
				{"a body longer than it said, trailers announced", [][]byte{h3HeadersFrame(with(post, "trailer", "x-sum", "content-length", "3")...), h3DataFrame([]byte("0123456789"))}},
				{"a trailer that may not be one", [][]byte{h3HeadersFrame(with(post, "trailer", "x-sum")...), h3DataFrame([]byte("abc")), h3HeadersFrame("content-length", "3")}},
			})
			// The same shapes within the rules are served.
			for _, r := range []struct {
				rule
				want string
			}{
				{rule{"the same Content-Length twice", [][]byte{h3HeadersFrame(with(post, "content-length", "3", "content-length", "3")...), h3DataFrame([]byte("abc"))}}, "POST /raw 3"},
				{rule{"announced trailers", [][]byte{h3HeadersFrame(with(post, "trailer", "x-sum")...), h3DataFrame([]byte("abc")), h3HeadersFrame("x-sum", "6")}}, "POST /raw 3"},
				{rule{"a trailer that was not announced", [][]byte{h3HeadersFrame(post...), h3DataFrame([]byte("abc")), h3HeadersFrame("content-length", "3")}}, "POST /raw 3"},
				{rule{"a plain request", head(h3GetFields...)}, "GET /raw 0"},
			} {
				if status, body, err := rawExchange(t, conn, r.parts...); err != nil || status != "200" || string(body) != r.want {
					t.Errorf("%s: status %q, body %q, err %v; want 200 and %q", r.name, status, body, err, r.want)
				}
			}
		})
	}
}

// h3Handlers returns, for the group's HTTP/3 connections together: how many
// handlers run, how many requests wait for one, and how many streams are
// open.
func h3Handlers(g *BindGroup) (running, waiting, streams int) {
	var r, w, s atomic.Int64
	var wg sync.WaitGroup
	for _, l := range g.fast.group.Loops() {
		wg.Add(1)
		l.Post(func() {
			defer wg.Done()
			for c := g.fast.h3lists[l.ID()]; c != nil; c = c.lnext {
				r.Add(int64(c.handlers))
				w.Add(int64(len(c.unstarted)))
				s.Add(int64(len(c.streams)))
			}
		})
	}
	wg.Wait()
	return int(r.Load()), int(w.Load()), int(s.Load())
}

// A client that gives its requests up before they are answered. A handler
// that has begun goes on until it notices, so a connection runs only as
// many at a time as it has streams, a hundred; requests beyond that wait
// for one. A request given up while it waits never gets a handler, the
// others get theirs when the handlers before them are over, and nothing of
// either stays behind. A client that has more than four hundred requests
// waiting gives up what it asks for: it is cut off (H3_EXCESSIVE_LOAD).
func TestH3Loops_RequestsGivenUp(t *testing.T) {
	h3ServedBy(t, true)
	pki := newCAPKI(t, "h3-loops-ca")
	site := h3HandlerSite(t, pki, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "from a handler: "+r.URL.Path)
	})
	// Handlers that do not notice at once that their request is gone: each
	// waits where it begins until the test lets it go.
	var started atomic.Int64
	var gate atomic.Pointer[chan struct{}]
	probe := func(point string) {
		if point != "handler" {
			return
		}
		started.Add(1)
		if hold := gate.Load(); hold != nil {
			<-*hold
		}
	}
	loopPanicProbe.Store(&probe)
	t.Cleanup(func() { loopPanicProbe.Store(nil) })
	addr := freeAddr(t)
	g := startGroup(t, addr, site)
	if g.h3loops == nil {
		t.Fatal("the group's HTTP/3 is not on the event loops")
	}
	ctx := testCtx(t)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				running, waiting, streams := h3Handlers(g)
				t.Fatalf("waited in vain for %s: %d handlers have begun, %d run, %d requests wait, %d streams are open", what, started.Load(), running, waiting, streams)
			}
		}
	}
	// get sends a whole request on a new stream; nil: the connection is over.
	get := func(conn *quic.Conn, path string) *quic.Stream {
		str, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return nil
		}
		str.SetDeadline(time.Now().Add(10 * time.Second))
		str.Write(h3HeadersFrame(":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", path))
		str.Close()
		return str
	}
	giveUp := func(strs []*quic.Stream) {
		for _, str := range strs {
			str.CancelRead(quic.StreamErrorCode(h3.ErrRequestCancelled))
		}
	}

	conn := rawH3(t, addr, pki)
	for round := 1; round <= 3; round++ {
		hold := make(chan struct{})
		gate.Store(&hold)
		let := sync.OnceFunc(func() { close(hold) })
		t.Cleanup(let)
		before := started.Load()
		// A hundred requests whose handlers have begun, given up.
		first := make([]*quic.Stream, 100)
		for i := range first {
			if first[i] = get(conn, fmt.Sprintf("/first/%d/%d", round, i)); first[i] == nil {
				t.Fatalf("round %d: the connection ended at request %d", round, i)
			}
		}
		waitFor("a hundred handlers to begin", func() bool { return started.Load() == before+100 })
		giveUp(first)
		// A hundred more: their streams are the client's to open, since the
		// first hundred's are over, but the handlers of those are not.
		second := make([]*quic.Stream, 100)
		for i := range second {
			if second[i] = get(conn, fmt.Sprintf("/second/%d/%d", round, i)); second[i] == nil {
				t.Fatalf("round %d: the connection ended at request %d of the second hundred", round, i)
			}
		}
		waitFor("the second hundred to wait for a handler", func() bool {
			running, waiting, streams := h3Handlers(g)
			return running == 100 && waiting == 100 && streams == 100
		})
		if n := started.Load() - before; n != 100 {
			t.Fatalf("round %d: %d handlers have begun while a hundred run, want none past those", round, n)
		}
		// Half of those that wait are given up as well; then the handlers
		// notice.
		giveUp(second[:50])
		waitFor("fifty of the waiting requests to be given up", func() bool {
			_, _, streams := h3Handlers(g)
			return streams == 50
		})
		let()
		for i, str := range second[50:] {
			var pending, body []byte
			want := fmt.Sprintf("from a handler: /second/%d/%d", round, 50+i)
			if status := h3Answer(t, str, &pending, &body); status != "200" || string(body) != want {
				t.Fatalf("round %d: a request that waited for a handler was answered %q, %q; want 200 and %q", round, status, body, want)
			}
		}
		waitFor("the connection to be done with all of it", func() bool {
			running, waiting, streams := h3Handlers(g)
			return running == 0 && waiting == 0 && streams == 0
		})
		if n := started.Load() - before; n != 150 {
			t.Errorf("round %d: %d handlers began, want 150: a hundred, and the fifty that waited and were not given up", round, n)
		}
	}

	// More than four hundred requests waiting, all given up.
	hold := make(chan struct{})
	gate.Store(&hold)
	t.Cleanup(func() { close(hold) })
	before := started.Load()
	greedy := rawH3(t, addr, pki)
	first := make([]*quic.Stream, 100)
	for i := range first {
		if first[i] = get(greedy, fmt.Sprintf("/greedy/%d", i)); first[i] == nil {
			t.Fatalf("the connection ended at request %d", i)
		}
	}
	waitFor("a hundred handlers to begin", func() bool { return started.Load() == before+100 })
	giveUp(first)
	sent := 0
	for ; sent < 600; sent++ {
		str := get(greedy, fmt.Sprintf("/greedy/more/%d", sent))
		if str == nil {
			break
		}
		giveUp([]*quic.Stream{str})
	}
	if code := connCode(t, greedy); code != int64(h3.ErrExcessiveLoad) {
		t.Errorf("after %d requests given up while they waited for a handler the connection ended with %#x, want H3_EXCESSIVE_LOAD (%#x)", sent, code, uint64(h3.ErrExcessiveLoad))
	}
	if sent <= 400 {
		t.Errorf("the client was cut off after %d requests that waited, want it to have more than 400 of them", sent)
	}
	if n := started.Load() - before; n != 100 {
		t.Errorf("%d handlers began for that client, want the hundred that ran", n)
	}
	// The connection of the other client is none the worse.
	gate.Store(nil)
	after := get(conn, "/after")
	if after == nil {
		t.Fatal("the first client's connection is over")
	}
	var pending, body []byte
	if status := h3Answer(t, after, &pending, &body); status != "200" || string(body) != "from a handler: /after" {
		t.Errorf("the first client's next request was answered %q, %q", status, body)
	}
}

// h3Held returns how many bytes the group's HTTP/3 connections hold that
// their clients sent and nothing has taken yet.
func h3Held(g *BindGroup) uint64 {
	var total atomic.Uint64
	var wg sync.WaitGroup
	for _, l := range g.fast.group.Loops() {
		wg.Add(1)
		l.Post(func() {
			defer wg.Done()
			for c := g.fast.h3lists[l.ID()]; c != nil; c = c.lnext {
				total.Add(c.q.Unconsumed())
			}
		})
	}
	wg.Wait()
	return total.Load()
}

// h3FirstWindowsOnly keeps a connection's receive windows at their first
// size for the test: the configuration's smallest limits, which are that
// size. A window otherwise grows while a backend takes a body as fast as
// it arrives, and how far it got before the backend stopped reading
// depends on the machine; with these limits "the window" is one number.
func h3FirstWindowsOnly(t *testing.T) {
	t.Helper()
	useHTTP3Limits(t, config.HTTP3Config{MaxStreamReceiveWindow: "1MB", MaxConnectionReceiveWindow: "1MB"})
	if l := http3Limits(); l.MaxStreamReceiveWindow != h3StreamWindow || l.MaxConnectionReceiveWindow != h3ConnWindow {
		t.Fatalf("the limits are %d and %d, want the first windows %d and %d", l.MaxStreamReceiveWindow, l.MaxConnectionReceiveWindow, h3StreamWindow, h3ConnWindow)
	}
}

// A request body its backend does not take backs up in nvelox, as far as
// the client's windows allow and no further; when the backend takes it,
// the client gets the room back, all of it: the body arrives whole, and
// nothing is left counted against the connection.
func TestH3Loops_BodyRoomGivenBack(t *testing.T) {
	h3ServedBy(t, true)
	h3FirstWindowsOnly(t)
	upSendBuffer = 64 << 10 // nvelox's socket to the backend takes little too
	t.Cleanup(func() { upSendBuffer = 0 })
	pki := newCAPKI(t, "h3-loops-ca")
	release := make(chan struct{})
	var letGo sync.Once
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		fmt.Fprintf(w, "%d %x", n, h.Sum(nil))
	}))
	// A backend whose socket takes little that is not read (but more than
	// one loopback segment: below that TCP itself slows to a crawl).
	backend.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetReadBuffer(128 << 10)
		}
		return ctx
	}
	backend.Start()
	t.Cleanup(backend.Close)
	t.Cleanup(func() { letGo.Do(func() { close(release) }) }) // first: the handler returns, then the server closes
	target := strings.TrimPrefix(backend.URL, "http://")
	l := &ListenerConfig{Name: "h3", Addr: ":0", Protocol: "https", Backend: "be", HTTP3: true,
		TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
	site := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})},
		map[string]*config.Backend{"be": {Name: "be", Servers: []string{target}}}, nil, nil, nil, nil, nil)
	addr := freeAddr(t)
	g := startGroup(t, addr, site)

	cc, _ := h3Client(t, addr, pki)
	ctx := testCtx(t)
	body := make([]byte, 6<<20)
	for i := range body {
		body[i] = byte(i * 31)
	}
	type res struct {
		r   *h3Result
		err error
	}
	done := make(chan res, 1)
	go func() {
		r, err := h3Do(ctx, cc, "POST", "https://localhost/held", bytes.NewReader(body))
		done <- res{r, err}
	}()
	// The body backs up: nvelox holds a good part of a window of it...
	deadline := time.Now().Add(15 * time.Second)
	for h3Held(g) < 256<<10 {
		select {
		case got := <-done:
			t.Fatalf("the request ended while its backend was not reading: %+v, %v", got.r, got.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("nvelox holds %d bytes of the body: it did not back up", h3Held(g))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// ... and never more than the windows the client was given.
	time.Sleep(200 * time.Millisecond)
	if held := h3Held(g); held > h3ConnWindow {
		t.Errorf("nvelox holds %d bytes of a body nobody reads, more than the connection's window of %d", held, h3ConnWindow)
	}
	letGo.Do(func() { close(release) })
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if want := fmt.Sprintf("%d %x", len(body), sha256.Sum256(body)); string(got.r.body) != want {
		t.Errorf("the body arrived as %q, want %q", got.r.body, want)
	}
	if held := h3Held(g); held != 0 {
		t.Errorf("after the request %d bytes are still counted against the client's windows", held)
	}
}

// The same for a request net/http's handlers serve. The client gets the
// room of its body back as the handler reads it, at once, also when all was
// quiet before: a client that waits for room sends nothing that an answer
// could ride on. And a handler that answers without reading the body (here
// a request the site's rules refuse) gives back the room of what it left
// unread.
func TestH3Loops_HandlersBodyRoomGivenBack(t *testing.T) {
	h3ServedBy(t, true)
	h3FirstWindowsOnly(t)
	pki := newCAPKI(t, "h3-loops-ca")
	release := make(chan struct{})
	var letGo sync.Once
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		fmt.Fprintf(w, "%d %x", n, h.Sum(nil))
	}))
	backend.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetReadBuffer(128 << 10)
		}
		return ctx
	}
	backend.Start()
	t.Cleanup(backend.Close)
	t.Cleanup(func() { letGo.Do(func() { close(release) }) }) // first: the handler returns, then the server closes
	target := strings.TrimPrefix(backend.URL, "http://")
	l := &ListenerConfig{Name: "h3", Addr: ":0", Protocol: "https", Backend: "be", HTTP3: true,
		TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
	l.Compression.Enabled = true // every request is one for the handlers
	l.ACL = []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/denied"}, Action: "deny"}}
	site := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})},
		map[string]*config.Backend{"be": {Name: "be", Servers: []string{target}}}, nil, nil, nil, nil, nil)
	// A handler can be held where it begins.
	var gate atomic.Pointer[chan struct{}]
	probe := func(point string) {
		if hold := gate.Load(); point == "handler" && hold != nil {
			<-*hold
		}
	}
	loopPanicProbe.Store(&probe)
	t.Cleanup(func() { loopPanicProbe.Store(nil) })
	addr := freeAddr(t)
	g := startGroup(t, addr, site)
	if g.h3loops == nil {
		t.Fatal("the group's HTTP/3 is not on the event loops")
	}
	type res struct {
		r   *h3Result
		err error
	}
	post := func(cc *http3.ClientConn, path string, body []byte) chan res {
		done := make(chan res, 1)
		go func() {
			r, err := h3Do(testCtx(t), cc, "POST", "https://localhost"+path, bytes.NewReader(body))
			done <- res{r, err}
		}()
		return done
	}
	// settled waits until nvelox holds at least floor bytes of request
	// bodies and that has not changed for 300 ms: whatever can move has
	// moved, and the connection is quiet.
	settled := func(done chan res, floor uint64) uint64 {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		var held uint64
		for same := 0; same < 30; {
			select {
			case got := <-done:
				t.Fatalf("the request ended while nothing was reading its body: %+v, %v", got.r, got.err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("nvelox holds %d bytes of the body, want %d at least, and unchanging", h3Held(g), floor)
			}
			time.Sleep(10 * time.Millisecond)
			if now := h3Held(g); now == held && now >= floor {
				same++
			} else {
				held, same = now, 0
			}
		}
		return held
	}

	// A body its backend does not take: more than the sockets between
	// nvelox and the backend hold.
	cc, _ := h3Client(t, addr, pki)
	body := make([]byte, 16<<20)
	for i := range body {
		body[i] = byte(i * 31)
	}
	done := post(cc, "/held", body)
	if held := settled(done, 256<<10); held > h3ConnWindow {
		t.Errorf("nvelox holds %d bytes of a body nobody reads, more than the connection's window of %d", held, h3ConnWindow)
	}
	letGo.Do(func() { close(release) })
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if want := fmt.Sprintf("%d %x", len(body), sha256.Sum256(body)); string(got.r.body) != want {
			t.Errorf("the body arrived as %q, want %q", got.r.body, want)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the request did not end after its backend began to read: the client, which waited for room, was not given it")
	}
	if held := h3Held(g); held != 0 {
		t.Errorf("after the request %d bytes are still counted against the client's windows", held)
	}

	// A request that is refused without a look at its body, which is there
	// by the time its handler begins.
	hold := make(chan struct{})
	gate.Store(&hold)
	let := sync.OnceFunc(func() { close(hold) })
	t.Cleanup(let)
	done = post(cc, "/denied", body[:600<<10])
	settled(done, 512<<10)
	gate.Store(nil)
	let()
	if got := <-done; got.err != nil || got.r.status != http.StatusForbidden {
		t.Fatalf("a request the site's rules refuse: %+v, %v; want 403", got.r, got.err)
	}
	for deadline := time.Now().Add(5 * time.Second); h3Held(g) != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("after a handler that left its request's body unread, %d bytes are still counted against the client's windows", h3Held(g))
		}
	}
	// The connection has its window whole: a body as large as that goes through.
	if got := <-post(cc, "/again", body[:h3ConnWindow]); got.err != nil || got.r.status != 200 || !strings.HasPrefix(string(got.r.body), fmt.Sprintf("%d ", h3ConnWindow)) {
		t.Errorf("a body of the window's size after that: %+v, %v", got.r, got.err)
	}
}

// A client that does not read one of its downloads still gets its other
// requests answered on the same connection: the download is held back by
// the client's own limit for that stream, and holds up nothing else. When
// the client reads it after all, it arrives whole.
func TestH3Loops_DownloadNotReadHoldsUpNoOther(t *testing.T) {
	const size = 64 << 20
	addr, _, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/big" {
			io.WriteString(w, "answer to "+r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := make([]byte, 64<<10)
		for sent := 0; sent < size; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	ctx := testCtx(t)
	// A client that lets a stream send 256 KiB ahead of what it has read,
	// and all streams together much more.
	conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), &quic.Config{
		InitialStreamReceiveWindow: 256 << 10, MaxStreamReceiveWindow: 256 << 10,
		InitialConnectionReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	cc := (&http3.Transport{}).NewClientConn(conn)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/big", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("the download: %v, %+v", err, resp)
	}
	defer resp.Body.Close()
	// Time for the server to send what the client's limit allows, and to
	// take from its backend what it holds at the most.
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 20; i++ {
		short, cancel := context.WithTimeout(ctx, 5*time.Second)
		path := fmt.Sprintf("/small/%d", i)
		r, err := h3Do(short, cc, "GET", "https://localhost"+path, nil)
		cancel()
		if err != nil || r.status != 200 || string(r.body) != "answer to "+path {
			t.Fatalf("request %d beside a download the client does not read: %v, %+v", i, err, r)
		}
	}
	if n, err := io.Copy(io.Discard, resp.Body); err != nil || n != size {
		t.Errorf("the download, read after all: %d bytes of %d, %v", n, size, err)
	}
}

// A client that lets the server send a byte at a time (its limits begin at
// one byte for a stream and three for all streams, and rise as it reads)
// gets the server's settings whole and its requests answered, by the loops
// and by net/http's handlers; and when a response whose end the client's
// limits held back is out at last, its stream is over for the server too.
func TestH3Loops_ClientWithTinyLimits(t *testing.T) {
	answer := bytes.Repeat([]byte("0123456789abcdef"), 100<<10/16)
	backend := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			w.Write(answer)
		}
	}
	for _, kind := range []string{"a site the loops serve", "a site of the handlers"} {
		t.Run(kind, func(t *testing.T) {
			var addr string
			var g *BindGroup
			var pki *caPKI
			if kind == "a site the loops serve" {
				addr, g, pki = startH3Loops(t, backend)
			} else {
				h3ServedBy(t, true)
				pki = newCAPKI(t, "h3-loops-ca")
				addr = freeAddr(t)
				if g = startGroup(t, addr, h3HandlerSite(t, pki, backend)); g.h3loops == nil {
					t.Fatal("the group's HTTP/3 is not on the event loops")
				}
			}
			ctx := testCtx(t)
			conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), &quic.Config{InitialStreamReceiveWindow: 1, InitialConnectionReceiveWindow: 3})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.CloseWithError(0, "") })
			cc := (&http3.Transport{}).NewClientConn(conn)
			select {
			case <-cc.ReceivedSettings():
			case <-time.After(10 * time.Second):
				t.Fatal("the server's settings did not arrive: what the client's limits held back at first was not sent later")
			}
			// A response without a body first: its end is all there is to
			// hold back.
			if r, err := h3Do(ctx, cc, "HEAD", "https://localhost/", nil); err != nil || r.status != 200 {
				t.Fatalf("a HEAD request of a client with tiny limits: %v, %+v", err, r)
			}
			r, err := h3Do(ctx, cc, "GET", "https://localhost/", nil)
			if err != nil || r.status != 200 || !bytes.Equal(r.body, answer) {
				t.Fatalf("a GET request of a client with tiny limits: %v, status and length %v", err, r != nil && r.status == 200 && len(r.body) == len(answer))
			}
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
				running, waiting, streams := h3Handlers(g)
				if running == 0 && waiting == 0 && streams == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("after the client has its answers the server still has %d streams open (%d handlers run, %d requests wait)", streams, running, waiting)
				}
			}
		})
	}
}

// A client that takes nothing of a response for the listener's write limit
// has that stream reset (H3_INTERNAL_ERROR), not before the limit, by the
// loops and by net/http's handlers alike; its connection serves the next
// request.
func TestH3Loops_ClientThatTakesNothing(t *testing.T) {
	backend := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/big" {
			io.WriteString(w, "answer to "+r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := make([]byte, 64<<10)
		for i := 0; i < 256; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}
	for _, kind := range []string{"a site the loops serve", "a site of the handlers"} {
		t.Run(kind, func(t *testing.T) {
			h3ServedBy(t, true)
			pki := newCAPKI(t, "h3-loops-ca")
			site := h3Site(t, pki, backend)
			if kind != "a site the loops serve" {
				site = h3HandlerSite(t, pki, backend)
			}
			site.Listener.Timeouts.Write = "400ms"
			addr := freeAddr(t)
			if g := startGroup(t, addr, site); g.h3loops == nil {
				t.Fatal("the group's HTTP/3 is not on the event loops")
			}
			ctx := testCtx(t)
			conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), &quic.Config{
				InitialStreamReceiveWindow: 256 << 10, MaxStreamReceiveWindow: 256 << 10,
				InitialConnectionReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 8 << 20})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.CloseWithError(0, "") })
			own, err := conn.OpenUniStream()
			if err != nil {
				t.Fatal(err)
			}
			own.Write([]byte{h3.StreamControl, h3.FrameSettings, 0})
			str, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			str.Write(h3HeadersFrame(":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/big"))
			str.Close()
			// The answer has begun, and a moment later the stream is still
			// good: one byte is read, which gives the server no room.
			one := make([]byte, 1)
			str.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(str, one); err != nil {
				t.Fatalf("the answer's first byte: %v", err)
			}
			time.Sleep(150 * time.Millisecond)
			if _, err := io.ReadFull(str, one); err != nil {
				t.Fatalf("150 ms after the answer began, well within the write limit, the stream ended: %v", err)
			}
			// Past the limit it is reset; what was not read is gone with it.
			time.Sleep(1500 * time.Millisecond)
			str.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = io.ReadAll(str)
			if got := streamCode(err); got != int64(h3.ErrInternal) {
				t.Errorf("a stream whose client took nothing for the write limit ended with %v (stream error %#x), want H3_INTERNAL_ERROR (%#x)", err, got, uint64(h3.ErrInternal))
			}
			if status, body, err := rawExchange(t, conn, h3HeadersFrame(":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/next")); err != nil || status != "200" || string(body) != "answer to /next" {
				t.Errorf("the next request on the connection: status %q, body %q, err %v", status, body, err)
			}
		})
	}
}

// serverControl returns the server's control stream on conn, read as far
// as its type.
func serverControl(t *testing.T, conn *quic.Conn) *quic.ReceiveStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		str, err := conn.AcceptUniStream(ctx)
		if err != nil {
			t.Fatalf("the server's streams: %v", err)
		}
		var typ [1]byte
		if _, err := io.ReadFull(str, typ[:]); err != nil {
			t.Fatalf("the type of a stream of the server's: %v", err)
		}
		if typ[0] == h3.StreamControl {
			return str
		}
	}
	t.Fatal("no control stream among the server's first three streams")
	return nil
}

// controlFrame reads the next frame of the server's control stream and
// returns its type, 0 with the error when none came in time.
func controlFrame(str *quic.ReceiveStream, within time.Duration) (uint64, error) {
	str.SetReadDeadline(time.Now().Add(within))
	var buf []byte
	one := make([]byte, 1)
	for {
		if typ, length, n := h3.FrameHeader(buf); n > 0 && uint64(len(buf)-n) >= length {
			return typ, nil
		}
		if _, err := io.ReadFull(str, one); err != nil {
			return 0, err
		}
		buf = append(buf, one[0])
	}
}

// A stop while a download is under way, at a moment when the connection
// holds as much to send as it may: the client is told all the same that no
// more requests are served (GOAWAY), and the download goes on until the
// client ends it.
func TestH3Loops_StopDuringADownload(t *testing.T) {
	addr, g, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := make([]byte, 64<<10)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	ctx := testCtx(t)
	// A client whose limits are far away: what holds the download back is
	// the path, not the client.
	conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), &quic.Config{
		InitialStreamReceiveWindow: 16 << 20, MaxStreamReceiveWindow: 16 << 20,
		InitialConnectionReceiveWindow: 32 << 20, MaxConnectionReceiveWindow: 32 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	own, err := conn.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	own.Write([]byte{h3.StreamControl, h3.FrameSettings, 0})
	control := serverControl(t, conn)
	if typ, err := controlFrame(control, 5*time.Second); err != nil || typ != h3.FrameSettings {
		t.Fatalf("the server's control stream begins with frame %#x (%v), want its settings", typ, err)
	}
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	str.Write(h3HeadersFrame(":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/big"))
	str.Close()
	var read atomic.Int64
	go func() {
		buf := make([]byte, 256<<10)
		for {
			n, err := str.Read(buf)
			read.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	more := func(what string, n int64) {
		t.Helper()
		from := read.Load()
		for deadline := time.Now().Add(10 * time.Second); read.Load() < from+n; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d bytes of the download arrived in 10 s, want %d", what, read.Load()-from, n)
			}
		}
	}
	more("before the stop", 4<<20)
	stopped := stopGroup(g)
	if typ, err := controlFrame(control, 3*time.Second); err != nil || typ != h3.FrameGoAway {
		t.Errorf("after the stop the server's control stream brought frame %#x (%v), want GOAWAY", typ, err)
	}
	more("after the stop", 4<<20)
	select {
	case err := <-stopped:
		t.Fatalf("the group stopped (%v) while a download was under way", err)
	default:
	}
	str.CancelRead(quic.StreamErrorCode(h3.ErrRequestCancelled))
	select {
	case <-stopped:
	case <-time.After(8 * time.Second):
		t.Error("the group did not stop within 8 s of its last request being given up")
	}
}

// h3DatagramSizes returns the sizes of the datagrams the group's HTTP/3
// connections send now, one for each connection.
func h3DatagramSizes(g *BindGroup) []int {
	var mu sync.Mutex
	var sizes []int
	var wg sync.WaitGroup
	for _, l := range g.fast.group.Loops() {
		wg.Add(1)
		l.Post(func() {
			defer wg.Done()
			for c := g.fast.h3lists[l.ID()]; c != nil; c = c.lnext {
				mu.Lock()
				sizes = append(sizes, c.q.DatagramSize())
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return sizes
}

// A download finds out that its path carries larger datagrams than every
// path must, and is sent in those: here the loopback path, to a client
// that takes 1,452 bytes. A connection that only answers small requests
// stays with the size every path carries. Either way the answers are what
// the backend sent.
func TestH3Loops_LargerDatagrams(t *testing.T) {
	big := make([]byte, 4<<20)
	for i := range big {
		big[i] = byte(i * 7)
	}
	addr, g, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(big)
			return
		}
		io.WriteString(w, "answer to "+r.URL.Path)
	})
	ctx := testCtx(t)
	// Small requests first.
	cc, _ := h3Client(t, addr, pki)
	for i := 0; i < 50; i++ {
		path := fmt.Sprintf("/small/%d", i)
		if r, err := h3Do(ctx, cc, "GET", "https://localhost"+path, nil); err != nil || r.status != 200 || string(r.body) != "answer to "+path {
			t.Fatalf("%s: %v, %+v", path, err, r)
		}
	}
	if sizes := h3DatagramSizes(g); len(sizes) != 1 || sizes[0] != 1200 {
		t.Fatalf("after fifty small answers the connection sends datagrams of %v bytes, want 1200", sizes)
	}
	// Then a download on the same connection.
	r, err := h3Do(ctx, cc, "GET", "https://localhost/big", nil)
	if err != nil || r.status != 200 || !bytes.Equal(r.body, big) {
		t.Fatalf("the download: %v, status and length %v", err, r != nil && r.status == 200 && len(r.body) == len(big))
	}
	if sizes := h3DatagramSizes(g); len(sizes) != 1 || sizes[0] != quicSendSize {
		t.Errorf("after a download of 4 MiB the connection sends datagrams of %v bytes, want %d", sizes, quicSendSize)
	}
	// And small requests behind it, in whatever size.
	if r, err := h3Do(ctx, cc, "GET", "https://localhost/after", nil); err != nil || r.status != 200 || string(r.body) != "answer to /after" {
		t.Errorf("a request after the download: %v, %+v", err, r)
	}
}

// Many requests at once on one connection, each answered with its own
// answer.
func TestH3Loops_ManyAtOnce(t *testing.T) {
	addr, _, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		io.WriteString(w, "answer to "+r.URL.Path)
	})
	cc, _ := h3Client(t, addr, pki)
	ctx := testCtx(t)
	var wg sync.WaitGroup
	for round := 0; round < 3; round++ {
		for i := 0; i < 60; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				path := fmt.Sprintf("/r%d/%d", round, i)
				r, err := h3Do(ctx, cc, "GET", "https://localhost"+path, nil)
				if err != nil {
					t.Errorf("%s: %v", path, err)
					return
				}
				if r.status != 200 || string(r.body) != "answer to "+path {
					t.Errorf("%s: status %d, body %q", path, r.status, r.body)
				}
			}(i)
		}
		wg.Wait()
	}
}

// A backend that hangs up without an answer: nvelox's own page, with its
// status.
func TestH3Loops_ErrorPage(t *testing.T) {
	addr, _, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
			c.Close()
		}
	})
	cc, _ := h3Client(t, addr, pki)
	r, err := h3Do(testCtx(t), cc, "GET", "https://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.status != http.StatusBadGateway || !strings.Contains(r.header.Get("Content-Type"), "text/html") || len(r.body) == 0 {
		t.Errorf("status %d, Content-Type %q, %d bytes; want nvelox's 502 page", r.status, r.header.Get("Content-Type"), len(r.body))
	}
}

// A client that gives a request up: its backend connection is closed, and
// the connection serves the next request.
func TestH3Loops_ClientGivesUp(t *testing.T) {
	arrived := make(chan struct{}, 1)
	gone := make(chan struct{}, 1)
	addr, _, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/slow" {
			io.WriteString(w, "ok")
			return
		}
		arrived <- struct{}{}
		select {
		case <-r.Context().Done():
			gone <- struct{}{}
		case <-time.After(20 * time.Second):
		}
	})
	cc, _ := h3Client(t, addr, pki)
	ctx, cancel := context.WithCancel(testCtx(t))
	errc := make(chan error, 1)
	go func() {
		_, err := h3Do(ctx, cc, "GET", "https://localhost/slow", nil)
		errc <- err
	}()
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never reached the backend")
	}
	cancel()
	if err := <-errc; err == nil {
		t.Error("the request that was given up succeeded")
	}
	select {
	case <-gone:
	case <-time.After(10 * time.Second):
		t.Error("the backend was not told that the client gave up")
	}
	r, err := h3Do(testCtx(t), cc, "GET", "https://localhost/next", nil)
	if err != nil || r.status != 200 || string(r.body) != "ok" {
		t.Errorf("the next request: %v, %+v", err, r)
	}
}

// A stop of the group lets a request in flight finish, tells the client
// to send no more, and is over once the answer is delivered.
func TestH3Loops_StopLetsRequestsFinish(t *testing.T) {
	release := make(chan struct{})
	var letGo sync.Once
	arrived := make(chan struct{}, 1)
	answer := strings.Repeat("answered in full\n", 8192)
	addr, g, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			arrived <- struct{}{}
			<-release
		}
		io.WriteString(w, answer)
	})
	t.Cleanup(func() { letGo.Do(func() { close(release) }) })
	cc, _ := h3Client(t, addr, pki)
	ctx := testCtx(t)
	if r, err := h3Do(ctx, cc, "GET", "https://localhost/warm", nil); err != nil || r.status != 200 {
		t.Fatalf("warm-up: %v", err)
	}
	type res struct {
		r   *h3Result
		err error
	}
	inFlight := make(chan res, 1)
	go func() {
		r, err := h3Do(ctx, cc, "GET", "https://localhost/slow", nil)
		inFlight <- res{r, err}
	}()
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never reached the backend")
	}
	stopped := stopGroup(g)
	select {
	case err := <-stopped:
		t.Fatalf("the group stopped (%v) while a request was being answered", err)
	case <-time.After(500 * time.Millisecond):
	}
	began := time.Now()
	letGo.Do(func() { close(release) })
	got := <-inFlight
	if got.err != nil || got.r.status != 200 || string(got.r.body) != answer {
		t.Fatalf("the request in flight: %v", got.err)
	}
	select {
	case <-stopped:
	case <-time.After(8 * time.Second):
		t.Fatal("the group did not stop within 8 s of its last request being answered")
	}
	if d := time.Since(began); d > 3*time.Second {
		t.Errorf("the group stopped %v after its last request was answered", d)
	}
}

// ---- requests written by hand, frame by frame ----

// rawH3 opens a QUIC connection that speaks HTTP/3 as far as the test
// writes it: its control stream with an empty SETTINGS frame is sent.
func rawH3(t *testing.T, addr string, pki *caPKI) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	ctrl.Write([]byte{h3.StreamControl, h3.FrameSettings, 0})
	return conn
}

// slowH3 is rawH3 with a client that takes a byte of a stream at a time
// until it reads it (and three of all its streams together). It reads the
// server's own streams as they come, so that what the server says there
// (its settings) does not use up what the connection may send for good.
func slowH3(t *testing.T, addr string, pki *caPKI) *quic.Conn {
	t.Helper()
	ctx := testCtx(t)
	conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), &quic.Config{InitialStreamReceiveWindow: 1, InitialConnectionReceiveWindow: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	go func() {
		for {
			str, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go io.Copy(io.Discard, str)
		}
	}()
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	ctrl.Write([]byte{h3.StreamControl, h3.FrameSettings, 0})
	return conn
}

// h3HeadersFrame returns a HEADERS frame with the given fields.
func h3HeadersFrame(fields ...string) []byte {
	sec := h3.AppendPrefix(nil)
	for i := 0; i+1 < len(fields); i += 2 {
		sec = h3.AppendField(sec, []byte(fields[i]), []byte(fields[i+1]))
	}
	return append(h3.AppendFrameHeader(nil, h3.FrameHeaders, uint64(len(sec))), sec...)
}

func h3DataFrame(p []byte) []byte {
	return append(h3.AppendFrameHeader(nil, h3.FrameData, uint64(len(p))), p...)
}

var h3GetFields = []string{":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/raw"}

// rawExchange writes parts on a new request stream, ends it, and returns
// the answer: its status ("" when the stream brought none) with the body,
// or the error the stream ended with.
func rawExchange(t *testing.T, conn *quic.Conn, parts ...[]byte) (status string, body []byte, err error) {
	t.Helper()
	str, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	str.SetDeadline(time.Now().Add(10 * time.Second))
	for _, p := range parts {
		str.Write(p)
	}
	str.Close()
	return rawAnswer(t, str)
}

// rawAnswer reads a request stream to its end and returns the answer it
// brought, as rawExchange does.
func rawAnswer(t *testing.T, str *quic.Stream) (status string, body []byte, err error) {
	t.Helper()
	raw, err := io.ReadAll(str)
	for len(raw) > 0 {
		typ, length, n := h3.FrameHeader(raw)
		if n == 0 || uint64(len(raw)-n) < length {
			t.Fatalf("the answer ends in the middle of a frame (% x)", raw)
		}
		payload := raw[n : n+int(length)]
		raw = raw[n+int(length):]
		switch typ {
		case h3.FrameHeaders:
			var scratch []byte
			h3.DecodeFields(payload, &scratch, 1<<20, func(name, value []byte) error {
				if string(name) == ":status" && status == "" {
					status = string(value)
				}
				return nil
			})
		case h3.FrameData:
			body = append(body, payload...)
		}
	}
	return status, body, err
}

// streamCode returns the code a stream error carries, -1 for another
// error.
func streamCode(err error) int64 {
	for err != nil {
		if e, ok := err.(*quic.StreamError); ok {
			return int64(e.ErrorCode)
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return -1
}

// connCode waits for the connection to end and returns the application
// error code it was closed with, -1 when it did not end that way.
func connCode(t *testing.T, conn *quic.Conn) int64 {
	t.Helper()
	select {
	case <-conn.Context().Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the connection was not closed")
	}
	var appErr *quic.ApplicationError
	if asAppError(context.Cause(conn.Context()), &appErr) && appErr.Remote {
		return int64(appErr.ErrorCode)
	}
	return -1
}

func h3RawBackend(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	fmt.Fprintf(w, "%s %s %d", r.Method, r.URL.Path, len(b))
}

// Requests as they arrive on the wire, in the shapes a client may give
// them: the head and the stream's end together or apart, a body in several
// frames, frames of a kind the server does not know in between.
func TestH3Loops_RequestShapes(t *testing.T) {
	addr, _, pki := startH3Loops(t, h3RawBackend)
	conn := rawH3(t, addr, pki)
	post := []string{":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw", "content-length", "10"}
	unknown := append(h3.AppendFrameHeader(nil, 0x21+0x1f*7, 5), "grease"[:5]...)
	for name, tc := range map[string]struct {
		parts []([]byte)
		want  string
	}{
		"a GET":                                 {[][]byte{h3HeadersFrame(h3GetFields...)}, "GET /raw 0"},
		"a POST, its body in one frame":         {[][]byte{h3HeadersFrame(post...), h3DataFrame([]byte("0123456789"))}, "POST /raw 10"},
		"a POST, its body in three frames":      {[][]byte{h3HeadersFrame(post...), h3DataFrame([]byte("012")), h3DataFrame(nil), h3DataFrame([]byte("3456789"))}, "POST /raw 10"},
		"frames of an unknown kind in between":  {[][]byte{unknown, h3HeadersFrame(post...), unknown, h3DataFrame([]byte("0123456789")), unknown}, "POST /raw 10"},
		"a POST followed by trailers":           {[][]byte{h3HeadersFrame(post...), h3DataFrame([]byte("0123456789")), h3HeadersFrame("x-checksum", "abc")}, "POST /raw 10"},
		"a GET whose bytes come one at a time":  {bytewise(h3HeadersFrame(h3GetFields...)), "GET /raw 0"},
		"a POST whose bytes come one at a time": {bytewise(append(h3HeadersFrame(post...), h3DataFrame([]byte("0123456789"))...)), "POST /raw 10"},
	} {
		status, body, err := rawExchange(t, conn, tc.parts...)
		if err != nil || status != "200" || string(body) != tc.want {
			t.Errorf("%s: status %q, body %q, err %v; want 200 and %q", name, status, body, err, tc.want)
		}
	}
}

// A client sends the end of a request without a body right behind its
// head, but not always in the same packet. Such a request is served like
// any other. When nothing follows the head for a while, the request starts
// as one a body may follow, which a handler serves.
func TestH3Loops_EndBehindTheHead(t *testing.T) {
	addr, _, pki := startH3Loops(t, h3RawBackend)
	conn := rawH3(t, addr, pki)
	for _, tc := range []struct {
		pause time.Duration
		want  string
		code  int64
	}{
		{0, "200", -1},
		{2 * time.Millisecond, "200", -1},
		{5 * h3DecideWait, "200", -1}, // served by a handler, which waits for a body that does not come
	} {
		str, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		str.SetDeadline(time.Now().Add(10 * time.Second))
		str.Write(h3HeadersFrame(h3GetFields...))
		time.Sleep(tc.pause)
		str.Close()
		raw, err := io.ReadAll(str)
		status := ""
		if _, length, n := h3.FrameHeader(raw); n > 0 && len(raw) >= n+int(length) {
			var scratch []byte
			h3.DecodeFields(raw[n:n+int(length)], &scratch, 1<<20, func(name, value []byte) error {
				if string(name) == ":status" {
					status = string(value)
				}
				return nil
			})
		}
		if status != tc.want || streamCode(err) != tc.code {
			t.Errorf("the end %v behind the head: status %q, stream error %#x (%v); want %q and %#x", tc.pause, status, streamCode(err), err, tc.want, tc.code)
		}
	}
}

func bytewise(p []byte) [][]byte {
	out := make([][]byte, len(p))
	for i := range p {
		out[i] = p[i : i+1]
	}
	return out
}

// What breaks the rules of a request ends that request (the stream is
// reset) and leaves the connection to its other requests.
func TestH3Loops_BadRequestsEndTheirStream(t *testing.T) {
	addr, _, pki := startH3Loops(t, h3RawBackend)
	conn := rawH3(t, addr, pki)
	post := h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw", "content-length", "1")
	for name, tc := range map[string]struct {
		parts []([]byte)
		code  h3.Error
	}{
		"no :path":                        {[][]byte{h3HeadersFrame(":method", "GET", ":scheme", "https", ":authority", "localhost")}, h3.ErrMessage},
		"an upper-case field name":        {[][]byte{h3HeadersFrame(append(append([]string{}, h3GetFields...), "X-Upper", "1")...)}, h3.ErrMessage},
		"a pseudo-header after a field":   {[][]byte{h3HeadersFrame("x-first", "1", ":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/")}, h3.ErrMessage},
		"a body longer than it said":      {[][]byte{h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw", "content-length", "3"), h3DataFrame([]byte("0123456789"))}, h3.ErrMessage},
		"a pseudo-header in the trailers": {[][]byte{h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw", "content-length", "1"), h3DataFrame([]byte("0")), h3HeadersFrame(":path", "/x")}, h3.ErrMessage},
		"trailers that announce more than the server takes": {[][]byte{post, h3DataFrame([]byte("a")),
			append(h3.AppendFrameHeader(nil, h3.FrameHeaders, http3MaxHeaderBytes+1), 0, 0)}, h3.ErrExcessiveLoad},
		// (A body of no announced length: the request is not answered
		// before its stream ends.)
		"trailers that are more than the server takes once decoded": {[][]byte{h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw"),
			h3DataFrame([]byte("a")), h3HeadersFrame(h3PadFields(http3MaxHeaderBytes+1, 140)...)}, h3.ErrExcessiveLoad},
		"a stream that ends before a head": {nil, h3.ErrRequestIncomplete},
	} {
		status, _, err := rawExchange(t, conn, tc.parts...)
		if got := streamCode(err); status != "" || got != int64(tc.code) {
			t.Errorf("%s: status %q, stream error %#x (%v); want no answer and %#x", name, status, got, err, uint64(tc.code))
		}
	}
	// The connection is as good as before.
	if status, body, err := rawExchange(t, conn, h3HeadersFrame(h3GetFields...)); err != nil || status != "200" || string(body) != "GET /raw 0" {
		t.Errorf("a request after those: status %q, body %q, err %v", status, body, err)
	}
}

// What the tests of the quic-go path say of a request's head holds with
// the loops serving HTTP/3: the limit and its answer, on HTTP/3 alone, and
// streams that announce a large head and go quiet. (Trailers that announce
// too much end their request with a reset that says so; the quic-go path
// leaves the answer to its handler.)
func TestH3Loops_RequestHeaderLimit(t *testing.T) {
	h3ServedBy(t, true)
	testH3RequestHeaderLimit(t)
}

func TestH3Loops_HeadersFrameReservation(t *testing.T) {
	h3ServedBy(t, true)
	testH3HeadersFrameReservation(t, func(err error) bool { return streamCode(err) == int64(h3.ErrExcessiveLoad) })
}

// h3SizedFields returns the fields of a GET request whose field section is
// size bytes as HTTP/3 counts it (the names, the values and 32 bytes for
// each field), padded with fields of about per bytes.
func h3SizedFields(size, per int) []string {
	fields := append([]string{}, h3GetFields...)
	n := 0
	for i := 0; i+1 < len(fields); i += 2 {
		n += len(fields[i]) + len(fields[i+1]) + 32
	}
	return append(fields, h3PadFields(size-n, per)...)
}

// h3PadFields returns fields of about per bytes each that come to size
// bytes as HTTP/3 counts them.
func h3PadFields(size, per int) (fields []string) {
	for i, n := 0, 0; n < size; i++ {
		name := fmt.Sprintf("x-pad-%03d", i)
		field := per
		if left := size - n; left < 2*per {
			field = left // the last one takes what is left
		}
		fields = append(fields, name, strings.Repeat("a", field-len(name)-32))
		n += field
	}
	return fields
}

// A request head of more than 64 KiB is answered 431: by the size HTTP/3
// defines (names, values and 32 bytes a field, all fields in one count),
// when the head is decoded, and at the frame's header already when the
// frame announces more. The client is asked to send no more of the
// request, and its connection goes on.
func TestH3Loops_HeadLimit(t *testing.T) {
	addr, g, pki := startH3Loops(t, h3RawBackend)
	conn := rawH3(t, addr, pki)
	const limit = http3MaxHeaderBytes
	// released: no request stream is left on the loops (one that was
	// answered is let go of with its answer).
	released := func(when string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			_, _, n := h3Handlers(g)
			if n == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d request streams are still kept", when, n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	served := func(when string) {
		t.Helper()
		if status, body, err := rawExchange(t, conn, h3HeadersFrame(h3GetFields...)); err != nil || status != "200" || string(body) != "GET /raw 0" {
			t.Fatalf("a request %s: status %q, body %q, err %v", when, status, body, err)
		}
	}
	// 24 KiB of fields and a trailer field that takes the section one byte
	// past the limit.
	trailer := h3SizedFields(limit-40<<10, 4<<10)
	trailer = append(trailer, "trailer", strings.Repeat("x", 40<<10+1-len("trailer")-32))
	// A path of 70,000 bytes in Huffman code is 43,750 as sent: the head is
	// too large before its last pseudo-header field is taken.
	longPath := h3.AppendField(h3.AppendField(h3.AppendField(h3.AppendPrefix(nil), []byte(":method"), []byte("GET")),
		[]byte(":scheme"), []byte("https")), []byte(":authority"), []byte("localhost"))
	coded := hpack.AppendHuffmanString(nil, "/"+strings.Repeat("a", 70000-1))
	longPath = append(longPath, 0x51, 0x80|0x7f) // a literal with the name of static entry 1 (:path), its value in Huffman code
	for n := len(coded) - 0x7f; ; n >>= 7 {
		if n < 0x80 {
			longPath = append(longPath, byte(n))
			break
		}
		longPath = append(longPath, byte(n)|0x80)
	}
	longPath = append(h3.AppendFrameHeader(nil, h3.FrameHeaders, uint64(len(longPath)+len(coded))), append(longPath, coded...)...)
	for _, tc := range []struct {
		name   string
		fields []string
		frame  []byte
		want   string
	}{
		{"a head of exactly the limit", h3SizedFields(limit, 4<<10), nil, "200"},
		{"one byte more", h3SizedFields(limit+1, 4<<10), nil, "431"},
		{"small fields: less than the limit as sent, more as counted", h3SizedFields(limit+1, 140), nil, "431"},
		{"a trailer field counts like any other", trailer, nil, "431"},
		{"a path too long by itself, compressed", nil, longPath, "431"},
	} {
		frame := tc.frame
		if frame == nil {
			frame = h3HeadersFrame(tc.fields...)
		}
		if len(frame) > limit {
			t.Fatalf("%s: the frame is %d bytes; the test wants one the server reads to its end", tc.name, len(frame))
		}
		status, body, err := rawExchange(t, conn, frame)
		if err != nil || status != tc.want {
			t.Errorf("%s: status %q, err %v (stream error %#x); want %s", tc.name, status, err, streamCode(err), tc.want)
		}
		if tc.want == "200" && string(body) != "GET /raw 0" || tc.want == "431" && !bytes.Contains(body, []byte("431")) {
			t.Errorf("%s: body %q", tc.name, body)
		}
		served("after " + tc.name)
		released("after " + tc.name)
	}

	// A frame that announces more than the limit is answered at its header:
	// two bytes of it are sent, and the stream is not ended.
	announce := h3.AppendFrameHeader(nil, h3.FrameHeaders, limit+1)
	junk := bytes.Repeat([]byte{0xff}, limit+1) // no field section
	str, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	str.SetDeadline(time.Now().Add(10 * time.Second))
	began := time.Now()
	str.Write(append(append([]byte{}, announce...), junk[:2]...))
	status, body, err := rawAnswer(t, str)
	if err != nil || status != "431" || !bytes.Contains(body, []byte("431")) {
		t.Fatalf("a frame that announces %d bytes: status %q, body %q, err %v; want 431", limit+1, status, body, err)
	}
	if took := time.Since(began); took > 3*time.Second {
		t.Errorf("the answer to a frame that announces too much took %v: it waited for the frame", took)
	}
	// The client was asked to send no more, because it is too much.
	var werr error
	for i := 0; i < 300 && werr == nil; i++ {
		_, werr = str.Write(junk[:1000])
		time.Sleep(10 * time.Millisecond)
	}
	if got := streamCode(werr); got != int64(h3.ErrExcessiveLoad) {
		t.Errorf("writing on after the answer: %v (stream error %#x), want the client asked to stop with %#x", werr, got, uint64(h3.ErrExcessiveLoad))
	}
	served("after a frame that announced too much")
	released("after a frame that announced too much")

	// A client that sends all of it all the same, and takes the answer a
	// byte at a time: what arrives behind the frame's header is dropped,
	// not read as frames of the request.
	slow := slowH3(t, addr, pki)
	if str, err = slow.OpenStreamSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	str.SetDeadline(time.Now().Add(20 * time.Second))
	all := append(append(append([]byte{}, announce...), junk...), h3DataFrame([]byte("and a body"))...)
	wrote := make(chan struct{})
	go func() {
		defer close(wrote)
		str.Write(all) // ends early when the server's request to stop arrives
		str.Close()
	}()
	time.Sleep(300 * time.Millisecond) // the server has what was sent, and most of its answer still
	if status, body, err = rawAnswer(t, str); err != nil || status != "431" || !bytes.Contains(body, []byte("431")) {
		t.Fatalf("a client that sends the whole frame and reads slowly: status %q, body %q, err %v; want 431", status, body, err)
	}
	<-wrote
	str2, err := slow.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("the connection of that client is over: %v", err)
	}
	str2.SetDeadline(time.Now().Add(20 * time.Second))
	str2.Write(h3HeadersFrame(h3GetFields...))
	str2.Close()
	if status, body, err = rawAnswer(t, str2); err != nil || status != "200" || string(body) != "GET /raw 0" {
		t.Errorf("a request of that client after it: status %q, body %q, err %v", status, body, err)
	}
}

// A request's head is to be complete within the time the listener gives a
// head (read_header), as on HTTP/1.1 and HTTP/2: a stream that is opened
// and left with half a head is answered 408 and ended, while the other
// requests of its connection are served. Once the head is here that time
// is no longer what counts: a slow answer and a body sent late are not cut
// short.
func TestH3Loops_HeadNotInTime(t *testing.T) {
	addr, g, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(900 * time.Millisecond)
		}
		h3RawBackend(w, r)
	}, func(l *ListenerConfig) { l.Timeouts = config.TimeoutConfig{ReadHeader: "300ms"} })
	conn := rawH3(t, addr, pki)
	frame := h3HeadersFrame(h3GetFields...)

	type answer struct {
		status string
		body   []byte
		err    error
		took   time.Duration
		stop   int64 // the code the server asked the client to stop with (-1: it did not)
	}
	began := time.Now()
	run := func(send func(str *quic.Stream)) chan answer {
		out := make(chan answer, 1)
		str, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		str.SetDeadline(time.Now().Add(10 * time.Second))
		go func() {
			send(str)
			status, body, err := rawAnswer(t, str)
			took := time.Since(began)
			var werr error
			for i := 0; i < 100 && werr == nil; i++ {
				_, werr = str.Write([]byte("more"))
				time.Sleep(5 * time.Millisecond)
			}
			out <- answer{status, body, err, took, streamCode(werr)}
		}()
		return out
	}
	// Half a head, and nothing more; and a frame's header cut in two.
	half := run(func(str *quic.Stream) { str.Write(frame[:len(frame)/2]) })
	cut := run(func(str *quic.Stream) { str.Write(frame[:1]) })
	// A head that is whole, in front of a backend that takes three times
	// the head's time; and one whose body follows after twice that time.
	slow := run(func(str *quic.Stream) {
		str.Write(h3HeadersFrame(":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/slow"))
		str.Close()
	})
	late := run(func(str *quic.Stream) {
		str.Write(h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw", "content-length", "10"))
		time.Sleep(600 * time.Millisecond)
		str.Write(h3DataFrame([]byte("0123456789")))
		str.Close()
	})
	// Meanwhile the connection serves.
	if status, body, err := rawExchange(t, conn, frame); err != nil || status != "200" || string(body) != "GET /raw 0" {
		t.Errorf("a request beside the unfinished ones: status %q, body %q, err %v", status, body, err)
	}
	for name, ch := range map[string]chan answer{"half a head": half, "a frame header cut in two": cut} {
		a := <-ch
		if a.stop != int64(h3.ErrNoError) {
			t.Errorf("%s: writing on after the answer: stream error %#x, want the client asked to stop without an error (%#x)", name, a.stop, uint64(h3.ErrNoError))
		}
		if a.err != nil || a.status != "408" || !bytes.Contains(a.body, []byte("408")) {
			t.Errorf("%s: status %q, body %q, err %v (stream error %#x); want 408", name, a.status, a.body, a.err, streamCode(a.err))
		}
		if a.took < 250*time.Millisecond || a.took > 3*time.Second {
			t.Errorf("%s: answered after %v, want it at the listener's 300 ms for a head", name, a.took)
		}
	}
	if a := <-slow; a.err != nil || a.status != "200" || string(a.body) != "GET /slow 0" {
		t.Errorf("a whole head and a backend that takes 900 ms: status %q, body %q, err %v; the head's time is not the answer's", a.status, a.body, a.err)
	}
	if a := <-late; a.err != nil || a.status != "200" || string(a.body) != "POST /raw 10" {
		t.Errorf("a whole head and a body 600 ms later: status %q, body %q, err %v; the head's time is not the body's", a.status, a.body, a.err)
	}
	// None of the five streams is kept.
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _, n := h3Handlers(g)
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d request streams are still kept after their answers", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An answer that is complete is the client's, whatever becomes of the
// rest of its request: a client that ends its own side of the stream with
// a reset while the answer is still on its way to it (its window is small)
// gets all of the answer. Here a 502 for a backend that is down, to a
// request whose body is not sent yet.
func TestH3Loops_AnswerOutlivesTheRequestsReset(t *testing.T) {
	h3ServedBy(t, true)
	pki := newCAPKI(t, "h3-loops-ca")
	dead := deadTCPAddr(t)
	l := &ListenerConfig{Name: "h3", Addr: ":0", Protocol: "https", Backend: "be", HTTP3: true,
		TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
	site := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{dead})},
		map[string]*config.Backend{"be": {Name: "be", Servers: []string{dead}}}, nil, nil, nil, nil, nil)
	addr := freeAddr(t)
	g := startGroup(t, addr, site)
	if g.h3loops == nil {
		t.Fatal("the group's HTTP/3 is not on the event loops")
	}
	conn := slowH3(t, addr, pki)
	str, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	str.SetDeadline(time.Now().Add(20 * time.Second))
	str.Write(h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw", "content-length", "100000"))
	str.Write(append(h3.AppendFrameHeader(nil, h3.FrameData, 100000), make([]byte, 1000)...))
	// The answer is made, and all but its first byte waits for the client.
	streams := func() int { _, _, n := h3Handlers(g); return n }
	deadline := time.Now().Add(5 * time.Second)
	for streams() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	str.CancelWrite(quic.StreamErrorCode(h3.ErrRequestCancelled))
	time.Sleep(200 * time.Millisecond) // the server has the reset
	status, body, err := rawAnswer(t, str)
	if err != nil || status != "502" || len(body) == 0 {
		t.Errorf("status %q, %d bytes of body, err %v (stream error %#x); want all of the 502", status, len(body), err, streamCode(err))
	}
}

// A client that takes nothing of such an answer does not keep its stream:
// after the time given for it the stream is reset, and the connection
// serves on.
func TestH3Loops_LocalAnswerNotTaken(t *testing.T) {
	old := h3LocalAnswerLimit
	h3LocalAnswerLimit = 300 * time.Millisecond
	t.Cleanup(func() { h3LocalAnswerLimit = old })
	addr, g, pki := startH3Loops(t, h3RawBackend)
	// A client whose streams take one byte until it reads, and which does
	// not read this one.
	conn := slowH3(t, addr, pki)
	str, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	str.Write(append(h3.AppendFrameHeader(nil, h3.FrameHeaders, http3MaxHeaderBytes+1), 0, 0))
	streams := func() int { _, _, n := h3Handlers(g); return n }
	deadline := time.Now().Add(5 * time.Second)
	for streams() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := streams(); n != 1 {
		t.Fatalf("%d streams on the loops, want the one whose answer waits for its client", n)
	}
	began := time.Now()
	for streams() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n, took := streams(), time.Since(began); n != 0 || took < 200*time.Millisecond {
		t.Fatalf("%d streams after %v: want the stream given up at the 300 ms a client has to take such an answer", n, took)
	}
	// What the client then reads of it ends with a reset.
	str.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(str); streamCode(err) != int64(h3.ErrInternal) {
		t.Errorf("reading the answer late: %v (stream error %#x), want the stream reset with %#x", err, streamCode(err), uint64(h3.ErrInternal))
	}
	// The connection serves on.
	str2, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("the connection is over: %v", err)
	}
	str2.SetDeadline(time.Now().Add(10 * time.Second))
	str2.Write(h3HeadersFrame(h3GetFields...))
	str2.Close()
	if status, body, err := rawAnswer(t, str2); err != nil || status != "200" || string(body) != "GET /raw 0" {
		t.Errorf("a request after it: status %q, body %q, err %v", status, body, err)
	}
}

// Nothing is set aside for what a HEADERS frame announces: two hundred
// streams that announce the largest head the server takes and send two
// bytes of it cost what they sent and a small buffer each, not the size
// they named.
func TestH3Loops_NothingSetAsideForAnAnnouncedHead(t *testing.T) {
	addr, _, pki := startH3Loops(t, h3RawBackend)
	const perConn = h3MaxStreams
	conns := []*quic.Conn{rawH3(t, addr, pki), rawH3(t, addr, pki)}
	// The connections serve first: what they hold themselves is part of
	// what is there before.
	for _, conn := range conns {
		if status, _, err := rawExchange(t, conn, h3HeadersFrame(h3GetFields...)); err != nil || status != "200" {
			t.Fatalf("status %q, err %v", status, err)
		}
	}
	before := liveHeap()
	quiet := append(h3.AppendFrameHeader(nil, h3.FrameHeaders, http3MaxHeaderBytes), 0, 0)
	n := 0
	for _, conn := range conns {
		for i := 0; i < perConn; i++ {
			str, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				t.Fatalf("stream %d: %v", n, err)
			}
			if _, err := str.Write(quiet); err != nil {
				t.Fatalf("stream %d: %v", n, err)
			}
			n++
		}
	}
	time.Sleep(300 * time.Millisecond) // the server has them
	grown := liveHeap() - before
	t.Logf("%d streams that announce %d bytes each: heap grown by %d KiB", n, http3MaxHeaderBytes, grown>>10)
	if bound := int64(n) * 16 << 10; grown > bound {
		t.Errorf("%d streams that sent %d bytes each made the heap grow by %d KiB; with nothing set aside for what they announce it stays below %d KiB (%d KiB would be the announced sizes)",
			n, len(quiet), grown>>10, bound>>10, n*http3MaxHeaderBytes>>10)
	}
}

// A body that ends short of its Content-Length is answered 400, as on
// HTTP/1.1 and HTTP/2.
func TestH3Loops_BodyShorterThanDeclared(t *testing.T) {
	addr, _, pki := startH3Loops(t, h3RawBackend)
	conn := rawH3(t, addr, pki)
	status, _, err := rawExchange(t, conn,
		h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw", "content-length", "10"),
		h3DataFrame([]byte("012")))
	if err != nil || status != "400" {
		t.Errorf("status %q, err %v; want 400", status, err)
	}
}

// What breaks the rules of the connection ends the connection, with the
// error the protocol names for it.
func TestH3Loops_ConnectionErrors(t *testing.T) {
	addr, _, pki := startH3Loops(t, h3RawBackend)
	for name, tc := range map[string]struct {
		do   func(conn *quic.Conn)
		code h3.Error
	}{
		"a DATA frame before the head": {func(conn *quic.Conn) {
			str, _ := conn.OpenStreamSync(context.Background())
			str.Write(h3DataFrame([]byte("x")))
		}, h3.ErrFrameUnexpected},
		"a frame of the control stream on a request stream": {func(conn *quic.Conn) {
			str, _ := conn.OpenStreamSync(context.Background())
			str.Write([]byte{h3.FrameSettings, 0})
		}, h3.ErrFrameUnexpected},
		"a frame cut short by the end of its stream": {func(conn *quic.Conn) {
			str, _ := conn.OpenStreamSync(context.Background())
			f := h3HeadersFrame(h3GetFields...)
			str.Write(f[:len(f)-3])
			str.Close()
		}, h3.ErrFrame},
		"a field section that cannot be decoded": {func(conn *quic.Conn) {
			str, _ := conn.OpenStreamSync(context.Background())
			str.Write(append(h3.AppendFrameHeader(nil, h3.FrameHeaders, 3), 0, 0, 0xff))
			str.Close()
		}, h3.ErrQPACKDecompression},
		"a second control stream": {func(conn *quic.Conn) {
			s, _ := conn.OpenUniStream()
			s.Write([]byte{h3.StreamControl, h3.FrameSettings, 0})
		}, h3.ErrStreamCreation},
		"a second SETTINGS frame": {func(conn *quic.Conn) {
			// rawH3's control stream is not reachable here: a fresh
			// connection's own, with two SETTINGS frames.
		}, 0},
		"a push stream from the client": {func(conn *quic.Conn) {
			s, _ := conn.OpenUniStream()
			s.Write([]byte{h3.StreamPush, 0})
		}, h3.ErrStreamCreation},
	} {
		if tc.code == 0 {
			continue
		}
		conn := rawH3(t, addr, pki)
		tc.do(conn)
		if got := connCode(t, conn); got != int64(tc.code) {
			t.Errorf("%s: the connection ended with %#x, want %#x", name, got, uint64(tc.code))
		}
	}
	// The control stream: a first frame that is not SETTINGS, SETTINGS
	// twice, and the stream closed.
	for name, tc := range map[string]struct {
		ctrl  []byte
		close bool
		code  h3.Error
	}{
		"a control stream that does not begin with SETTINGS": {[]byte{h3.StreamControl, h3.FrameGoAway, 1, 0}, false, h3.ErrMissingSettings},
		"a second SETTINGS frame":                            {[]byte{h3.StreamControl, h3.FrameSettings, 0, h3.FrameSettings, 0}, false, h3.ErrFrameUnexpected},
		"the control stream closed":                          {[]byte{h3.StreamControl, h3.FrameSettings, 0}, true, h3.ErrClosedCriticalStream},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), nil)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		ctrl, _ := conn.OpenUniStream()
		ctrl.Write(tc.ctrl)
		if tc.close {
			ctrl.Close()
		}
		if got := connCode(t, conn); got != int64(tc.code) {
			t.Errorf("%s: the connection ended with %#x, want %#x", name, got, uint64(tc.code))
		}
		conn.CloseWithError(0, "")
	}
}

// h3HandlerSite is a site whose requests all go to net/http's handlers (it
// compresses responses), in front of a backend that runs handler.
func h3HandlerSite(t *testing.T, pki *caPKI, handler http.HandlerFunc) *HTTPServer {
	t.Helper()
	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)
	target := strings.TrimPrefix(backend.URL, "http://")
	l := &ListenerConfig{Name: "h3", Addr: ":0", Protocol: "https", Backend: "be", HTTP3: true,
		TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
	l.Compression.Enabled = true
	return NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})},
		map[string]*config.Backend{"be": {Name: "be", Servers: []string{target}}}, nil, nil, nil, nil, nil)
}

// A request the loops do not serve themselves goes to net/http's
// handlers, as on HTTP/2: here a body of unknown length (no
// Content-Length, the stream's end behind the body), on a site the loops
// serve otherwise.
func TestH3Loops_BodyOfUnknownLength(t *testing.T) {
	addr, _, pki := startH3Loops(t, h3RawBackend)
	conn := rawH3(t, addr, pki)
	status, body, err := rawExchange(t, conn,
		h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw"),
		h3DataFrame([]byte("0123456789")), h3DataFrame([]byte("abcdef")))
	if err != nil || status != "200" || string(body) != "POST /raw 16" {
		t.Errorf("status %q, body %q, err %v; want 200 and \"POST /raw 16\"", status, body, err)
	}
	if status, _, err := rawExchange(t, conn, h3HeadersFrame(h3GetFields...)); err != nil || status != "200" {
		t.Errorf("a request after it: status %q, err %v", status, err)
	}
}

// A site whose requests all go to the handlers, over HTTP/3 on the loops:
// requests with and without bodies, large ones in both directions, many at
// once, a request with trailers, and what the backend is told of the
// client.
func TestH3Loops_Handlers(t *testing.T) {
	h3ServedBy(t, true)
	pki := newCAPKI(t, "h3-loops-ca")
	var sawProto atomic.Value
	site := h3HandlerSite(t, pki, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo":
			b, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(b)
		case "/long":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(bytes.Repeat([]byte("0123456789abcdef"), 4<<20/16))
		default:
			sawProto.Store(r.Header.Get("X-Forwarded-Proto") + " " + r.Header.Get("X-Forwarded-For"))
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "from a handler: "+r.URL.Path)
		}
	})
	addr := freeAddr(t)
	g := startGroup(t, addr, site)
	if g.h3loops == nil {
		t.Fatal("the group's HTTP/3 is not on the event loops")
	}
	cc, _ := h3Client(t, addr, pki)
	ctx := testCtx(t)

	r, err := h3Do(ctx, cc, "GET", "https://localhost/hello", nil)
	if err != nil || r.status != 200 || string(r.body) != "from a handler: /hello" || r.proto != "HTTP/3.0" {
		t.Fatalf("GET: %v, %+v", err, r)
	}
	if got, _ := sawProto.Load().(string); got != "https 127.0.0.1" {
		t.Errorf("the backend was told %q of the client, want \"https 127.0.0.1\"", got)
	}
	body := make([]byte, 3<<20)
	for i := range body {
		body[i] = byte(i * 17)
	}
	r, err = h3Do(ctx, cc, "POST", "https://localhost/echo", bytes.NewReader(body))
	if err != nil || r.status != 200 || !bytes.Equal(r.body, body) {
		t.Fatalf("a 3 MiB POST: %v, status and length %v", err, r != nil && len(r.body) == len(body))
	}
	r, err = h3Do(ctx, cc, "GET", "https://localhost/long", nil)
	if err != nil || len(r.body) != 4<<20 {
		t.Fatalf("a 4 MiB answer: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/many/%d", i)
			r, err := h3Do(ctx, cc, "GET", "https://localhost"+path, nil)
			if err != nil || r.status != 200 || string(r.body) != "from a handler: "+path {
				t.Errorf("%s: %v, %+v", path, err, r)
			}
		}(i)
	}
	wg.Wait()

	// A request that announces trailers and sends them is served. (The
	// proxy does not pass a request's trailers on to its backend, on any
	// version of HTTP.)
	conn := rawH3(t, addr, pki)
	status, echoed, err := rawExchange(t, conn,
		h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/echo", "trailer", "x-checksum"),
		h3DataFrame([]byte("with trailers")), h3HeadersFrame("x-checksum", "abc123"))
	if err != nil || status != "200" || string(echoed) != "with trailers" {
		t.Errorf("a request with trailers: status %q, body %q, err %v", status, echoed, err)
	}
}

// A connection without a request for the listener's idle timeout is told
// that no more requests are served and is closed.
func TestH3Loops_IdleConnectionCloses(t *testing.T) {
	h3ServedBy(t, true)
	pki := newCAPKI(t, "h3-loops-ca")
	site := h3Site(t, pki, h3RawBackend)
	site.Listener.Timeouts.Idle = "300ms"
	addr := freeAddr(t)
	startGroup(t, addr, site)
	conn := rawH3(t, addr, pki)
	if status, _, err := rawExchange(t, conn, h3HeadersFrame(h3GetFields...)); err != nil || status != "200" {
		t.Fatalf("status %q, err %v", status, err)
	}
	began := time.Now()
	if got := connCode(t, conn); got != int64(h3.ErrNoError) {
		t.Errorf("the idle connection ended with %#x, want H3_NO_ERROR", got)
	}
	if d := time.Since(began); d < 200*time.Millisecond || d > 3*time.Second {
		t.Errorf("the idle connection was closed after %v, want about 300ms", d)
	}
}

// A client that is gone never acknowledges its last answer nor closes its
// connection. A stop does not wait for it until its limit: without a
// request in flight a connection is given the time to deliver its last
// answer and is then closed; one whose last answer is older than that is
// closed at once.
func TestH3Loops_StopDoesNotWaitForClientsThatAreGone(t *testing.T) {
	for _, tc := range []struct {
		name     string
		idleFor  time.Duration
		min, max time.Duration
	}{
		{"the last answer just went out", 0, 0, 4 * time.Second},
		{"the last answer is old", h3StopLinger + 300*time.Millisecond, 0, h3StopLinger / 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, g, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			pc := &silentConn{PacketConn: udp}
			raddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			ctx := testCtx(t)
			conn, err := quic.Dial(ctx, pc, raddr, h3ClientTLS(pki), nil)
			if err != nil {
				t.Fatal(err)
			}
			cc := (&http3.Transport{}).NewClientConn(conn)
			if r, err := h3Do(ctx, cc, "GET", "https://localhost/", nil); err != nil || r.status != 200 {
				t.Fatalf("request: %v", err)
			}
			pc.silent.Store(true) // before the client has acknowledged the answer, most of the time
			time.Sleep(tc.idleFor)
			began := time.Now()
			select {
			case <-stopGroup(g):
			case <-time.After(9 * time.Second):
				t.Fatal("the group waited for its limit")
			}
			if d := time.Since(began); d > tc.max || d < tc.min {
				t.Errorf("the stop took %v, want between %v and %v", d, tc.min, tc.max)
			} else {
				t.Logf("the stop took %v", d)
			}
		})
	}
}

// A failure in the code that serves one HTTP/3 connection ends that
// connection and nothing else: its loop goes on, the other connections are
// served, and nothing of the failed one stays on the books. Once in the
// code that reads a request's frames, once in the code that takes the
// backend's answer.
func TestH3Loops_PanicContained(t *testing.T) {
	addr, g, pki := startH3Loops(t, h3RawBackend)
	var at atomic.Pointer[string]
	probe := func(point string) {
		if want := at.Load(); want != nil && *want == point && at.CompareAndSwap(want, nil) {
			panic("test: panic at " + point)
		}
	}
	loopPanicProbe.Store(&probe)
	t.Cleanup(func() { loopPanicProbe.Store(nil) })
	// Several bystanders, so that some share the failing one's loop.
	var others []*quic.Conn
	for i := 0; i < 5; i++ {
		conn := rawH3(t, addr, pki)
		if status, _, err := rawExchange(t, conn, h3HeadersFrame(h3GetFields...)); err != nil || status != "200" {
			t.Fatalf("bystander %d: status %q, err %v", i, status, err)
		}
		others = append(others, conn)
	}
	for _, point := range []string{"h3-frame", "response", "bridge"} {
		// The request that fails: for "bridge" one that net/http's handlers
		// serve (a body of unknown length), whose every step on the loop goes
		// through the bridge.
		request := [][]byte{h3HeadersFrame(h3GetFields...)}
		if point == "bridge" {
			request = [][]byte{h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw"), h3DataFrame([]byte("0123456789"))}
		}
		victim := rawH3(t, addr, pki)
		waitCount(t, "connections before the failure", g.h3loops.conns.Load, int64(len(others)+1))
		before := loopPanics.Load()
		at.Store(&point)
		str, err := victim.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range request {
			str.Write(part)
		}
		str.Close()
		waitCount(t, "connections after a failure at "+point, g.h3loops.conns.Load, int64(len(others)))
		if got := loopPanics.Load() - before; got != 1 {
			t.Errorf("at %s: %d panics recorded, want 1", point, got)
		}
		str.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if raw, _ := io.ReadAll(str); len(raw) != 0 {
			t.Errorf("at %s: the failed connection's request was answered (% x)", point, raw)
		}
		for i, conn := range others {
			if status, _, err := rawExchange(t, conn, h3HeadersFrame(h3GetFields...)); err != nil || status != "200" {
				t.Errorf("at %s: bystander %d afterwards: status %q, err %v", point, i, status, err)
			}
		}
		if n := g.fast.active.Load(); n != int64(len(others)) {
			t.Errorf("at %s: the server counts %d connections, want %d", point, n, len(others))
		}
	}
}
