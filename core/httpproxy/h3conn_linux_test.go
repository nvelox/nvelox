//go:build linux

package httpproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// A group that stops gives back its ports, the UDP one of HTTP/3 on the
// loops too: a new group can bind them at once.
func TestH3Loops_StopGivesThePortsBack(t *testing.T) {
	addr, g, _ := startH3Loops(t, h3RawBackend)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("the UDP port of the stopped group's HTTP/3: %v", err)
	}
	pc.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the TCP port of the stopped group: %v", err)
	}
	ln.Close()
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
	// The server follows the client once it has proven that it receives
	// there: from then on the requests that begin name the new address.
	for start := time.Now(); ; time.Sleep(10 * time.Millisecond) {
		if get("https://localhost/"); xff("localhost") == "127.0.0.2" {
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatalf("ten seconds after the client moved its requests still name %q", xff("localhost"))
		}
	}

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
