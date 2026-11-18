package httpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/lb"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// h3HeaderLimit is the largest header section an HTTP/3 request may carry.
const h3HeaderLimit = 64 << 10

// h3Site builds a real site (NewHTTPServer) with HTTP/3 on, whose backend
// runs handler.
func h3Site(t *testing.T, pki *caPKI, handler http.HandlerFunc, tweak ...func(*ListenerConfig)) *HTTPServer {
	t.Helper()
	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)
	target := strings.TrimPrefix(backend.URL, "http://")
	backends := map[string]*config.Backend{"be": {Name: "be", Servers: []string{target}}}
	balancers := map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})}
	l := &ListenerConfig{Name: "h3", Addr: ":0", Protocol: "https", Backend: "be", HTTP3: true,
		TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
	for _, f := range tweak {
		f(l)
	}
	return NewHTTPServer(l, balancers, backends, nil, nil, nil, nil, nil)
}

// h3ClientTLS is the TLS config of a QUIC client of a test site.
func h3ClientTLS(pki *caPKI) *tls.Config {
	return &tls.Config{RootCAs: pki.pool, ServerName: "localhost", NextProtos: []string{http3.NextProtoH3}}
}

// sessionCache is a client session cache that also hands out every session
// stored in it.
type sessionCache struct {
	tls.ClientSessionCache
	stored chan *tls.ClientSessionState
}

func (c *sessionCache) Put(key string, cs *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, cs)
	if cs == nil {
		return
	}
	select {
	case c.stored <- cs:
	default:
	}
}

// quic-go accepts 0-RTT unless it is told not to, and a request that arrives
// as early data can be replayed. A client resumes a connection with the
// server's session ticket and sends a POST without waiting for the handshake,
// as a 0-RTT client does: the ticket must not offer early data, the
// connection must not use it, and the POST is served once, after the
// handshake.
func TestHTTP3_NoZeroRTT(t *testing.T) {
	quicGoPath(t) // the loops: TestH3Loops_NoZeroRTT
	pki := newCAPKI(t, "h3-0rtt-ca")
	var posts atomic.Int64
	addr := freeAddr(t)
	startGroup(t, addr, h3Site(t, pki, countPosts(&posts)))
	noZeroRTT(t, addr, pki, &posts)
}

// countPosts is a backend that answers "served" and counts the POSTs it
// gets.
func countPosts(posts *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		io.WriteString(w, "served")
	}
}

// noZeroRTT is the check of TestHTTP3_NoZeroRTT against the HTTP/3 site at
// addr, whose backend is countPosts(posts).
func noZeroRTT(t *testing.T, addr string, pki *caPKI, posts *atomic.Int64) {
	t.Helper()
	cache := &sessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(1), stored: make(chan *tls.ClientSessionState, 4)}
	tlsConf := h3ClientTLS(pki)
	tlsConf.ClientSessionCache = cache
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr := &http3.Transport{}

	// First connection: a full handshake, one request, and the session
	// ticket the server sends once the handshake is done.
	first, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	defer first.CloseWithError(0, "")
	get, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	resp, err := tr.NewClientConn(first).RoundTrip(get)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request: status %d", resp.StatusCode)
	}
	var ticket *tls.ClientSessionState
	select {
	case ticket = <-cache.stored:
	case <-ctx.Done():
		t.Fatal("the server sent no session ticket")
	}
	first.CloseWithError(0, "")
	_, session, err := ticket.ResumptionState()
	if err != nil || session == nil {
		t.Fatalf("session ticket: state %v, err %v", session, err)
	}
	if session.EarlyData {
		t.Error("the session ticket offers 0-RTT")
	}

	// Second connection: resumed with the ticket. The POST goes out as soon
	// as the client may send, which is before the handshake completes when
	// the server takes early data.
	second, err := quic.DialAddrEarly(ctx, addr, tlsConf, nil)
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	defer second.CloseWithError(0, "")
	str, err := tr.NewClientConn(second).OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("request stream: %v", err)
	}
	post, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/orders", nil)
	if err := str.SendRequestHeader(post); err != nil {
		t.Fatalf("POST: %v", err)
	}
	str.Close()
	resp, err = str.ReadResponse()
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "served" {
		t.Fatalf("POST: status %d, body %q", resp.StatusCode, body)
	}
	select {
	case <-second.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("the handshake of the second connection did not complete")
	}
	state := second.ConnectionState()
	if !state.TLS.DidResume {
		t.Error("the second connection did not resume the session: the ticket went unused")
	}
	if state.Used0RTT {
		t.Error("the second connection used 0-RTT")
	}
	if n := posts.Load(); n != 1 {
		t.Errorf("the backend got the POST %d times, want once", n)
	}
}

// liveHeap returns the size of the heap after a collection.
func liveHeap() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// quic-go reserves the length a HEADERS frame announces before the frame's
// bytes arrive, for the header section of a request and for its trailers, so
// a request stream that announces the largest block the server accepts and
// then goes quiet holds that much memory. Streams that announce 1 MiB (the
// largest block under net/http's default limit) and send two bytes of it
// must be refused at the frame header, and the heap must not grow by more
// than the HTTP/3 limit allows per stream.
func TestHTTP3_HeadersFrameReservation(t *testing.T) {
	quicGoPath(t)
	testH3HeadersFrameReservation(t, func(err error) bool { return err == nil })
}

// testH3HeadersFrameReservation is the test for whatever serves HTTP/3.
// trailersRefused says how a request ends whose trailers announce too
// much: the quic-go path lets its handler finish the answer.
func testH3HeadersFrameReservation(t *testing.T, trailersRefused func(error) bool) {
	const (
		conns     = 2
		perConn   = 100     // request streams a connection may have open at once (quic-go's default)
		announced = 1 << 20 // http.DefaultMaxHeaderBytes
	)
	pki := newCAPKI(t, "h3-mem-ca")

	// The header of a HEADERS frame of 1 MiB, and two bytes of that frame.
	quiet := quicvarint.Append(nil, 0x01)
	quiet = quicvarint.Append(quiet, announced)
	quiet = append(quiet, 0, 0)
	// A request whose body has begun, which makes the next HEADERS frame its
	// trailers: a HEADERS frame of 8 bytes (":method POST", ":scheme https"
	// and ":path /" by their index in QPACK's static table, ":authority x"
	// as a literal) and a DATA frame of one byte.
	request := []byte{0x01, 0x08, 0x00, 0x00, 0xd4, 0xd7, 0xc1, 0x50, 0x01, 'x', 0x00, 0x01, '.'}

	for _, tc := range []struct {
		name  string
		start []byte // what a stream sends ahead of the quiet frame
	}{
		{"request headers", nil},
		{"trailers", request},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A listener of its own: when it stops, everything the streams
			// of this case held is released.
			site := h3Site(t, pki, func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) })
			addr := freeAddr(t)
			startGroup(t, addr, site)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// The connections come first: what they hold themselves is part
			// of the baseline.
			var clients []*quic.Conn
			for range conns {
				c, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), nil)
				if err != nil {
					t.Fatalf("connection %d: %v", len(clients), err)
				}
				defer c.CloseWithError(0, "")
				clients = append(clients, c)
			}
			before := liveHeap()

			sent := append(append([]byte{}, tc.start...), quiet...)
			var streams []*quic.Stream
			for _, c := range clients {
				for range perConn {
					str, err := c.OpenStream()
					if err != nil {
						t.Fatalf("stream %d: %v", len(streams), err)
					}
					if _, err := str.Write(sent); err != nil {
						t.Fatalf("stream %d: %v", len(streams), err)
					}
					streams = append(streams, str)
				}
			}

			// A server that refuses the frame at its header answers and ends
			// the stream without waiting for more. One that reserved the
			// block is still waiting for the rest of it when the deadline
			// passes.
			deadline := time.Now().Add(10 * time.Second)
			refused := 0
			for _, str := range streams {
				str.SetReadDeadline(deadline)
				if _, err := io.Copy(io.Discard, str); err == nil || tc.start != nil && trailersRefused(err) {
					refused++
				}
			}
			grown := liveHeap() - before
			t.Logf("%d of %d streams refused, heap grown by %d KiB", refused, len(streams), grown>>10)

			if refused != len(streams) {
				t.Errorf("%d of %d streams that announced a %d-byte HEADERS frame were refused; the server waits for the frames of the others",
					refused, len(streams), announced)
			}
			// Twice the limit per stream leaves room for everything else a
			// stream and its connection cost.
			if bound := int64(len(streams)) * h3HeaderLimit * 2; grown > bound {
				t.Errorf("%d bytes sent on %d streams made the heap grow by %d MiB; at %d KiB per stream it stays below %d MiB",
					len(streams)*len(sent), len(streams), grown>>20, h3HeaderLimit>>10, bound>>20)
			}
		})
	}
}

// padSize is the size of the X-Pad-* fields of h, counted as RFC 9114,
// section 4.2.2 counts a field section: the name and value lengths plus 32
// bytes per field.
func padSize(h http.Header) int {
	n := 0
	for name, values := range h {
		if !strings.HasPrefix(name, "X-Pad-") {
			continue
		}
		for _, v := range values {
			n += len(name) + len(v) + 32
		}
	}
	return n
}

// padHeader returns X-Pad-* fields of about 4 KiB each whose padSize is n.
func padHeader(n int) http.Header {
	const field = 4 << 10
	h := http.Header{}
	for i := 0; n > 0; i++ {
		size := field
		if n < 2*field {
			size = n // the last field takes what is left
		}
		name := fmt.Sprintf("X-Pad-%03d", i)
		h[name] = []string{strings.Repeat("a", size-len(name)-32)}
		n -= size
	}
	return h
}

// advertisedHeaderLimit connects to an HTTP/3 server and returns the
// SETTINGS_MAX_FIELD_SECTION_SIZE it announces (false: none).
func advertisedHeaderLimit(t *testing.T, addr string, tlsConf *tls.Config) (uint64, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		t.Fatalf("connection: %v", err)
	}
	defer conn.CloseWithError(0, "")
	for {
		// The control stream is the unidirectional stream of type 0. It
		// starts with a SETTINGS frame (type 4): identifier and value pairs.
		str, err := conn.AcceptUniStream(ctx)
		if err != nil {
			t.Fatalf("no control stream from the server: %v", err)
		}
		str.SetReadDeadline(time.Now().Add(20 * time.Second))
		r := quicvarint.NewReader(str)
		if streamType, err := quicvarint.Read(r); err != nil || streamType != 0 {
			continue
		}
		frameType, err := quicvarint.Read(r)
		if err != nil || frameType != 4 {
			t.Fatalf("control stream: first frame of type %d (%v), want SETTINGS", frameType, err)
		}
		length, err := quicvarint.Read(r)
		if err != nil || length > 1<<10 {
			t.Fatalf("control stream: SETTINGS frame of %d bytes (%v)", length, err)
		}
		settings := make([]byte, length)
		if _, err := io.ReadFull(r, settings); err != nil {
			t.Fatalf("control stream: SETTINGS frame: %v", err)
		}
		for len(settings) > 0 {
			id, n, err := quicvarint.Parse(settings)
			if err != nil {
				t.Fatalf("control stream: SETTINGS frame: %v", err)
			}
			value, m, err := quicvarint.Parse(settings[n:])
			if err != nil {
				t.Fatalf("control stream: SETTINGS frame: %v", err)
			}
			if id == 0x06 {
				return value, true
			}
			settings = settings[n+m:]
		}
		return 0, false
	}
}

// An HTTP/3 request whose header section is larger than 64 KiB is answered
// 431, a smaller one is served, and the server announces that limit. HTTP/1.1
// and HTTP/2 on the same listener keep net/http's limit of 1 MiB and serve
// the same header sections.
func TestHTTP3_RequestHeaderLimit(t *testing.T) { quicGoPath(t); testH3RequestHeaderLimit(t) }

// testH3RequestHeaderLimit is the test for whatever serves HTTP/3.
func testH3RequestHeaderLimit(t *testing.T) {
	pki := newCAPKI(t, "h3-limit-ca")
	// The backend answers with the size of the padding fields it received.
	site := h3Site(t, pki, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, padSize(r.Header))
	})
	addr := freeAddr(t)
	startGroup(t, addr, site)

	clientTLS := func() *tls.Config { return &tls.Config{RootCAs: pki.pool, ServerName: "localhost"} }
	h1 := &http.Transport{TLSClientConfig: clientTLS(), TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	defer h1.CloseIdleConnections()
	h2 := &http.Transport{TLSClientConfig: clientTLS(), ForceAttemptHTTP2: true}
	defer h2.CloseIdleConnections()
	h3 := &http3.Transport{TLSClientConfig: clientTLS()}
	defer h3.Close()

	// The client adds a few fields of its own (:path, user-agent, ...), well
	// under 1 KiB in all. The compressed block of "just above" is smaller
	// than the limit and is refused once decoded; that of "far above" is
	// larger and is refused at the frame header.
	const (
		below     = h3HeaderLimit - 1<<10
		justAbove = h3HeaderLimit + 1
		farAbove  = 4 * h3HeaderLimit
	)
	for _, tc := range []struct {
		name  string
		rt    http.RoundTripper
		proto int
		size  int // padSize of the request's header section
		want  int
	}{
		{"http3 below the limit", h3, 3, below, http.StatusOK},
		{"http3 just above the limit", h3, 3, justAbove, http.StatusRequestHeaderFieldsTooLarge},
		{"http3 far above the limit", h3, 3, farAbove, http.StatusRequestHeaderFieldsTooLarge},
		{"http1 just above the http3 limit", h1, 1, justAbove, http.StatusOK},
		{"http1 far above the http3 limit", h1, 1, farAbove, http.StatusOK},
		{"http2 just above the http3 limit", h2, 2, justAbove, http.StatusOK},
		{"http2 far above the http3 limit", h2, 2, farAbove, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
			req.Header = padHeader(tc.size)
			resp, err := (&http.Client{Transport: tc.rt, Timeout: 20 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.ProtoMajor != tc.proto {
				t.Fatalf("answered over %s, want HTTP/%d", resp.Proto, tc.proto)
			}
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
			if tc.want == http.StatusOK && string(body) != strconv.Itoa(tc.size) {
				t.Fatalf("the backend received %q bytes of the %d-byte header section", body, tc.size)
			}
		})
	}

	// A client can tell the limit before it sends: the server's SETTINGS
	// frame carries it.
	if limit, sent := advertisedHeaderLimit(t, addr, h3ClientTLS(pki)); !sent || limit != h3HeaderLimit {
		t.Errorf("the server announces a header limit of %d bytes (announced: %v), want %d", limit, sent, h3HeaderLimit)
	}
}
