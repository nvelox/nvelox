package httpproxy

// A proxied response body is copied through a pooled buffer (buffer.go).
// These tests run on the net/http path, where that copy is made: responses
// served side by side never show each other's bytes, a response does not
// allocate its copy buffer, and buffering.response_buffer still selects its
// own buffer size.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// reuseCopyBuffer is the size of the buffer a response body is copied
// through unless the listener sets buffering.response_buffer.
const reuseCopyBuffer = 32 << 10

// reuseTimeout bounds every wait of these tests.
const reuseTimeout = 60 * time.Second

// reuseBody returns bytes [off, off+n) of the body of response id. The
// bytes depend on the id and on their position, so a piece of another
// response, or of another place in the same one, does not pass for them.
func reuseBody(id uint32, off, n int) []byte {
	out := make([]byte, 0, n+16)
	for w := uint64(off / 8); len(out) < off%8+n; w++ {
		x := (uint64(id)+1)*0x9E3779B97F4A7C15 ^ (w+1)*0xBF58476D1CE4E5B9
		x ^= x >> 31
		x *= 0x94D049BB133111EB
		x ^= x >> 29
		out = binary.BigEndian.AppendUint64(out, x)
	}
	return out[off%8 : off%8+n]
}

// reuseDiff describes the first byte of got that differs from the start of
// the body of response id ("" when got is that start).
func reuseDiff(id uint32, got []byte) string {
	want := reuseBody(id, 0, len(got))
	if bytes.Equal(got, want) {
		return ""
	}
	i := 0
	for got[i] == want[i] {
		i++
	}
	end := min(i+16, len(got))
	return fmt.Sprintf("byte %d of %d is wrong: got % x, want % x", i, len(got), got[i:end], want[i:end])
}

// reuseAccessLog sends the access log of a test with many requests to a
// file instead of the test output.
func reuseAccessLog(tb testing.TB) {
	tb.Helper()
	if err := logging.Init("debug", filepath.Join(tb.TempDir(), "access.log"), ""); err != nil {
		tb.Fatalf("logging init: %v", err)
	}
	tb.Cleanup(func() { _ = logging.Init("debug", "", "") })
}

// reuseScribble stands between a site and the server's own ResponseWriter.
// As soon as the server's Write has returned it overwrites the copy buffer
// the bytes came in, which is the worst the next response can do to that
// buffer. A server that still held the slice would send the client these
// bytes in place of its response.
type reuseScribble struct {
	http.ResponseWriter
	scribbled *atomic.Int64 // counts the buffers overwritten
}

func (w *reuseScribble) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	// Of the slices a site that only proxies writes, the copy buffer alone
	// has this capacity; anything else (an error page) is left as it is.
	if cap(p) == reuseCopyBuffer {
		for i := range p {
			p[i] = 0xEE
		}
		w.scribbled.Add(1)
	}
	return n, err
}

// Unwrap lets http.ResponseController reach the server's writer.
func (w *reuseScribble) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func reuseScribbled(h http.Handler, scribbled *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(&reuseScribble{w, scribbled}, r)
	})
}

// reuseStreamRead is how much of an endless response a client reads before
// it leaves.
const reuseStreamRead = 20000

// reuseBackend answers GET /?id=N&size=N&piece=N&mode=M with the body of
// response id (reuseBody). piece > 0 sends it in flushed pieces of that
// size, without a Content-Length. The modes:
//
//	""        all size bytes
//	"cut"     half of the size bytes, then the connection is dropped
//	"stream"  bytes without end, until the request is cancelled
type reuseBackend struct {
	*httptest.Server
	requests atomic.Int64
	streams  sync.WaitGroup // the "stream" responses still being sent
}

func newReuseBackend(t *testing.T) *reuseBackend {
	t.Helper()
	b := &reuseBackend{}
	b.Server = httptest.NewServer(http.HandlerFunc(b.serve))
	t.Cleanup(b.Close)
	return b
}

func (b *reuseBackend) serve(w http.ResponseWriter, r *http.Request) {
	b.requests.Add(1)
	q := r.URL.Query()
	n, _ := strconv.ParseUint(q.Get("id"), 10, 32)
	id := uint32(n)
	size, _ := strconv.Atoi(q.Get("size"))
	piece, _ := strconv.Atoi(q.Get("piece"))
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/plain")

	if q.Get("mode") == "stream" {
		b.streams.Add(1)
		defer b.streams.Done()
		// A write that waits for a client that will never read again ends
		// with the test at the latest.
		_ = rc.SetWriteDeadline(time.Now().Add(reuseTimeout))
		const step = 16 << 10
		for off := 0; r.Context().Err() == nil; off += step {
			if _, err := w.Write(reuseBody(id, off, step)); err != nil {
				return
			}
			_ = rc.Flush()
		}
		return
	}

	send := size
	if q.Get("mode") == "cut" {
		send = size / 2
	}
	body := reuseBody(id, 0, send)
	if piece == 0 {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Write(body)
	} else {
		for len(body) > 0 {
			k := min(piece, len(body))
			w.Write(body[:k])
			_ = rc.Flush()
			body = body[k:]
		}
	}
	if send < size {
		_ = rc.Flush()
		panic(http.ErrAbortHandler) // drops the connection, the body unfinished
	}
}

// waitStreams waits until every "stream" response has ended: the proxy
// noticed that the client left and let go of the backend.
func (b *reuseBackend) waitStreams(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		b.streams.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(reuseTimeout):
		t.Error("the backend is still sending to clients that left")
	}
}

// reuseFront serves h over proto ("http1", "http2" or "http3") and returns a
// client for it and its base URL.
func reuseFront(t *testing.T, proto string, h http.Handler) (*http.Client, string) {
	t.Helper()
	if proto != "http3" {
		ts := httptest.NewUnstartedServer(h)
		if proto == "http2" {
			ts.EnableHTTP2 = true
			ts.StartTLS()
		} else {
			ts.Start()
		}
		t.Cleanup(ts.Close)
		return ts.Client(), ts.URL
	}

	pki := newCAPKI(t, "reuse-ca")
	cert, err := tls.LoadX509KeyPair(pki.srvCert, pki.srvKey)
	if err != nil {
		t.Fatalf("server certificate: %v", err)
	}
	host, _, _ := net.SplitHostPort(freeAddr(t))
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	// Generous QUIC timeouts: the test machine may be busy.
	qconf := &quic.Config{HandshakeIdleTimeout: reuseTimeout, MaxIdleTimeout: 2 * reuseTimeout}
	srv := &http3.Server{
		Handler:    h,
		TLSConfig:  http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		QUICConfig: qconf,
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
	})
	tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.pool}, QUICConfig: qconf}
	t.Cleanup(func() { _ = tr.Close() })
	return &http.Client{Transport: tr}, "https://" + pc.LocalAddr().String()
}

// reuseCase is one request of the isolation test and how its response ends.
type reuseCase struct {
	id    uint32
	size  int
	piece int
	mode  string // see reuseBackend
}

// reuseCases returns n requests: bodies from nothing to several buffers,
// most of them ending in the middle of a buffer, whole or in pieces, some
// cut by the backend halfway and (streams) some left by the client.
func reuseCases(n int, streams bool) []reuseCase {
	sizes := []int{0, 1, 13, 1500, 4096, 32767, 32768, 32769, 40000, 65536, 100003, 262147}
	pieces := []int{997, 4099, 16000, 33000, 70001}
	cases := make([]reuseCase, n)
	for i := range cases {
		c := reuseCase{id: uint32(i + 1), size: sizes[(i/6+i)%len(sizes)]}
		switch i % 6 {
		case 2:
			c.piece = pieces[(i/6)%len(pieces)]
		case 4:
			c.mode, c.size = "cut", 20000+4999*(i%29)
			if (i/6)%2 == 1 {
				c.piece = 6000
			}
		case 5:
			if streams {
				c.mode = "stream"
			}
		}
		cases[i] = c
	}
	return cases
}

// reuseTally counts how the responses of an isolation run ended.
type reuseTally struct {
	whole    atomic.Int64 // received in full
	cut      atomic.Int64 // cut by the backend
	cutQuiet atomic.Int64 // of those: ended at the client without an error
	left     atomic.Int64 // left by the client in the middle of the body
}

// run requests c over an HTTP/major client and checks every byte of the
// response that arrives.
func (c reuseCase) run(client *http.Client, base string, major int, tally *reuseTally) error {
	ctx, cancel := context.WithTimeout(context.Background(), reuseTimeout)
	defer cancel()
	url := fmt.Sprintf("%s/?id=%d&size=%d&piece=%d&mode=%s", base, c.id, c.size, c.piece, c.mode)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		if c.mode == "cut" {
			// The cut reached the client before the response headers did.
			tally.cut.Add(1)
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != major {
		return fmt.Errorf("answered over %s", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	switch c.mode {
	case "stream":
		got := make([]byte, reuseStreamRead)
		if _, err := io.ReadFull(resp.Body, got); err != nil {
			return fmt.Errorf("reading the first %d bytes: %v", len(got), err)
		}
		if d := reuseDiff(c.id, got); d != "" {
			return fmt.Errorf("%s", d)
		}
		cancel() // the client leaves while the body is still coming
		tally.left.Add(1)
	case "cut":
		got, err := io.ReadAll(resp.Body)
		sent := c.size / 2
		if len(got) > sent {
			return fmt.Errorf("%d bytes of a response the backend cut after %d", len(got), sent)
		}
		if d := reuseDiff(c.id, got); d != "" {
			return fmt.Errorf("%s", d)
		}
		if err == nil {
			// net/http's own servers abort a response whose backend failed
			// in the middle of the body. Over HTTP/3 it ends short, without
			// an error.
			if major != 3 {
				return fmt.Errorf("a response the backend cut after %d of %d bytes ended without an error (%d bytes)", sent, c.size, len(got))
			}
			tally.cutQuiet.Add(1)
		}
		tally.cut.Add(1)
	default:
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("after %d of %d bytes: %v", len(got), c.size, err)
		}
		if len(got) != c.size {
			return fmt.Errorf("%d bytes, want %d", len(got), c.size)
		}
		if d := reuseDiff(c.id, got); d != "" {
			return fmt.Errorf("%s", d)
		}
		tally.whole.Add(1)
	}
	return nil
}

// reuseIsolation sends a few hundred requests through one site at once, over
// proto, and checks that every client got its own bytes: all of them, or the
// part that was relayed before the backend cut the response or the client
// left. cached: the site has a response cache, every whole response is asked
// for a second time and must then come out of the cache unchanged.
func reuseIsolation(t *testing.T, proto string, l *ListenerConfig, cached bool) {
	reuseAccessLog(t)
	backend := newReuseBackend(t)
	site := secNewSite(t, l, []string{secHost(backend.Server)}, secOpts{})
	g := NewBindGroup(":0", "http")
	g.AddSite(site)
	// With a cache and compression the server is written the compressor's
	// own slices, never a copy buffer: nothing to scribble on.
	var h http.Handler = g
	var scribbled atomic.Int64
	if !cached {
		h = reuseScribbled(g, &scribbled)
	}
	client, base := reuseFront(t, proto, h)
	major := map[string]int{"http1": 1, "http2": 2, "http3": 3}[proto]

	// A cache would buffer the endless responses up to its entry size.
	cases := reuseCases(192, !cached)
	todo := make(chan reuseCase, len(cases))
	whole := 0
	for _, c := range cases {
		todo <- c
		if c.mode == "" {
			whole++
		}
	}
	close(todo)
	var tally reuseTally
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range todo {
				if err := c.run(client, base, major, &tally); err != nil {
					t.Errorf("response %d (size %d, piece %d, mode %q): %v", c.id, c.size, c.piece, c.mode, err)
				}
			}
		}()
	}
	wg.Wait()
	backend.waitStreams(t)
	t.Logf("%d whole responses, %d cut by the backend (%d of them ended without an error), %d left by the client",
		tally.whole.Load(), tally.cut.Load(), tally.cutQuiet.Load(), tally.left.Load())
	if got := int(tally.whole.Load()); got != whole {
		t.Errorf("%d of %d whole responses arrived intact", got, whole)
	}
	if !cached && scribbled.Load() == 0 {
		t.Errorf("no body write came in a %d-byte copy buffer: nothing was overwritten, the run proves nothing", reuseCopyBuffer)
	}
	if !cached || t.Failed() {
		return
	}

	served := backend.requests.Load()
	for _, c := range cases {
		if c.mode != "" {
			continue
		}
		if err := c.run(client, base, major, &tally); err != nil {
			t.Errorf("response %d (size %d, piece %d) from the cache: %v", c.id, c.size, c.piece, err)
		}
	}
	if n := backend.requests.Load() - served; n != 0 {
		t.Errorf("%d of the %d repeated requests reached the backend, want all of them answered from the cache", n, whole)
	}
}

// TestProxy_ConcurrentResponsesKeepTheirBytes: the copy buffer of a response
// goes back to a pool that every site shares, and on to the next response.
// No response may show bytes of another one, whichever server writes it,
// whether it completes, the backend cuts it or the client leaves.
func TestProxy_ConcurrentResponsesKeepTheirBytes(t *testing.T) {
	for _, proto := range []string{"http1", "http2", "http3"} {
		t.Run(proto, func(t *testing.T) {
			reuseIsolation(t, proto, &ListenerConfig{}, false)
		})
	}
	// The cache and the compressor both take the copy buffer's bytes on
	// their way to the client.
	t.Run("http1 with cache and gzip", func(t *testing.T) {
		l := &ListenerConfig{
			Cache:       config.CacheConfig{Enabled: true, MaxSize: "64MB"},
			Compression: config.CompressionConfig{Enabled: true},
		}
		reuseIsolation(t, "http1", l, true)
	})
}

// TestProxy_WritersCopyWhatTheyKeep: the response cache and the compressor
// hold on to body bytes after their Write has returned. They must hold
// copies: the slice they were given is a copy buffer, and the next read
// (of this response or of another one) overwrites it.
func TestProxy_WritersCopyWhatTheyKeep(t *testing.T) {
	body := reuseBody(7, 0, 100000)
	// feed writes body to w the way ReverseProxy does: through one buffer,
	// overwritten after every Write.
	feed := func(t *testing.T, w io.Writer) {
		t.Helper()
		buf := make([]byte, reuseCopyBuffer)
		for off := 0; off < len(body); {
			n := copy(buf, body[off:])
			if _, err := w.Write(buf[:n]); err != nil {
				t.Fatalf("write: %v", err)
			}
			off += n
			for i := range buf {
				buf[i] = 0xEE
			}
		}
	}

	t.Run("cache", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cw := newCacheWriter(rec, 1<<20)
		cw.capture = true
		feed(t, cw)
		if !cw.complete() || !bytes.Equal(cw.body.Bytes(), body) {
			t.Errorf("the cache writer holds %d bytes that are not the %d-byte body it was written", cw.body.Len(), len(body))
		}
		if !bytes.Equal(rec.Body.Bytes(), body) {
			t.Error("the cache writer passed on other bytes than it was written")
		}
	})
	t.Run("gzip", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "text/plain")
		cw := newCompressWriter(rec, config.CompressionConfig{Enabled: true})
		feed(t, cw)
		cw.Close()
		if enc := rec.Header().Get("Content-Encoding"); enc != "gzip" {
			t.Fatalf("Content-Encoding %q, want gzip", enc)
		}
		zr, err := gzip.NewReader(rec.Body)
		if err != nil {
			t.Fatalf("gzip: %v", err)
		}
		got, err := io.ReadAll(zr)
		if err != nil || !bytes.Equal(got, body) {
			t.Errorf("the compressor produced %d bytes (err %v) that are not the %d-byte body it was written", len(got), err, len(body))
		}
	})
}

// reuseWrites records the size of every body write a site makes. It holds
// the first one until the backend has written the whole body (hold), so
// that every read after it finds as much as its buffer takes.
type reuseWrites struct {
	http.ResponseWriter
	hold  <-chan struct{}
	sizes []int
}

func (w *reuseWrites) Write(p []byte) (int, error) {
	if w.hold != nil {
		select {
		case <-w.hold:
		case <-time.After(reuseTimeout):
		}
		w.hold = nil
	}
	w.sizes = append(w.sizes, len(p))
	return w.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the server's writer.
func (w *reuseWrites) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// TestProxy_ResponseBufferSelectsItsSize: a listener's
// buffering.response_buffer is the size of the buffer its response bodies
// are copied through, smaller or larger than the 32 KiB of a listener
// without one. The body is read, and written to the client, in pieces of at
// most that size.
func TestProxy_ResponseBufferSelectsItsSize(t *testing.T) {
	// The whole body fits the socket buffers between the backend and the
	// proxy: the backend can write it before the proxy reads on.
	body := reuseBody(1, 0, 48<<10)
	for _, tc := range []struct {
		name, buffer string
		want         int
	}{
		{"8KB", "8KB", 8 << 10},
		{"40KB", "40KB", 40 << 10},
		{"unset", "", reuseCopyBuffer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			written := make(chan struct{}, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				w.Write(body)
				_ = http.NewResponseController(w).Flush()
				written <- struct{}{}
			}))
			t.Cleanup(backend.Close)
			l := &ListenerConfig{Buffering: config.BufferingConfig{ResponseBuffer: tc.buffer}}
			site := secNewSite(t, l, []string{secHost(backend)}, secOpts{})
			if tc.buffer != "" {
				if site.BufferPool == nil {
					t.Fatalf("response_buffer %s: the site has no buffer pool of its own", tc.buffer)
				}
				if n := len(site.BufferPool.Get()); n != tc.want {
					t.Fatalf("response_buffer %s: the site's pool hands out %d-byte buffers, want %d", tc.buffer, n, tc.want)
				}
			}
			g := NewBindGroup(":0", "http")
			g.AddSite(site)
			sizes := make(chan []int, 1)
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rw := &reuseWrites{ResponseWriter: w, hold: written}
				g.ServeHTTP(rw, r)
				sizes <- rw.sizes
			}))
			t.Cleanup(front.Close)

			// A read finds a full buffer only if the kernel has delivered
			// that much by then: a few responses are enough to see one.
			const tries = 5
			for try := 1; ; try++ {
				resp, err := front.Client().Get(front.URL + "/")
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				got, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || !bytes.Equal(got, body) {
					t.Fatalf("got %d bytes (err %v) that are not the %d-byte body", len(got), err, len(body))
				}
				var writes []int
				select {
				case writes = <-sizes:
				case <-time.After(reuseTimeout):
					t.Fatal("the request did not end")
				}
				largest := slices.Max(writes)
				if largest > tc.want {
					t.Fatalf("a body write of %d bytes: the body was copied through a buffer larger than %d bytes (writes %v)", largest, tc.want, writes)
				}
				if largest == tc.want {
					return
				}
				if try == tries {
					t.Fatalf("the largest body write in %d responses was %d bytes: the body was not copied through a %d-byte buffer (last writes %v)", tries, largest, tc.want, writes)
				}
			}
		})
	}
}

// reuseRaw is one site on the net/http path between a client and a backend
// that allocate nothing per request. What a round trip allocates is what
// net/http and the site allocate for one proxied response.
type reuseRaw struct {
	conn net.Conn
	br   *bufio.Reader
	req  []byte
	size int // of the response body
}

var (
	reuseStatusOK = []byte("HTTP/1.1 200 OK\r\n")
	reuseLength   = []byte("Content-Length: ")
)

// newReuseRaw starts a backend that answers every request with a body of
// size bytes, a site with listener l in front of it, and one client
// connection to the site.
func newReuseRaw(tb testing.TB, l *ListenerConfig, size int) *reuseRaw {
	tb.Helper()
	reuseAccessLog(tb)
	answer := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(size) + "\r\n\r\n")
	answer = append(answer, bytes.Repeat([]byte{'x'}, size)...)
	var mu sync.Mutex
	var taken []net.Conn
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http reads the first request of a connection. From then on
		// the connection is served here, with no allocation per request.
		c, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		mu.Lock()
		taken = append(taken, c)
		mu.Unlock()
		for {
			if _, err := c.Write(answer); err != nil {
				return
			}
			if err := reuseSkipHead(rw.Reader); err != nil {
				return
			}
		}
	}))
	tb.Cleanup(func() {
		backend.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range taken {
			c.Close()
		}
	})

	servers := []string{secHost(backend)}
	l.Name, l.Protocol, l.Backend = "edge", "http", "be"
	site := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin(servers)},
		map[string]*config.Backend{"be": {Name: "be", Servers: servers}}, nil, nil, nil, nil, nil)
	tb.Cleanup(site.Close)
	g := NewBindGroup(":0", "http")
	g.AddSite(site)
	front := httptest.NewServer(g)
	tb.Cleanup(front.Close)

	conn, err := net.Dial("tcp", secHost(front))
	if err != nil {
		tb.Fatalf("dial the site: %v", err)
	}
	tb.Cleanup(func() { conn.Close() })
	return &reuseRaw{
		conn: conn,
		br:   bufio.NewReader(conn),
		req:  []byte("GET /item HTTP/1.1\r\nHost: edge.test\r\n\r\n"),
		size: size,
	}
}

// reuseSkipHead reads the head of one request without a body off br.
func reuseSkipHead(br *bufio.Reader) error {
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return err
		}
		if len(line) <= 2 { // the empty line that ends the head
			return nil
		}
	}
}

// roundTrip sends one request and reads its response, without allocating.
func (e *reuseRaw) roundTrip() error {
	_ = e.conn.SetDeadline(time.Now().Add(reuseTimeout))
	if _, err := e.conn.Write(e.req); err != nil {
		return err
	}
	line, err := e.br.ReadSlice('\n')
	if err != nil {
		return err
	}
	if !bytes.Equal(line, reuseStatusOK) {
		return fmt.Errorf("status line %q", line)
	}
	length := -1
	for {
		if line, err = e.br.ReadSlice('\n'); err != nil {
			return err
		}
		if len(line) <= 2 {
			break
		}
		if v, ok := bytes.CutPrefix(line, reuseLength); ok {
			length = 0
			for _, d := range bytes.TrimSpace(v) {
				length = length*10 + int(d-'0')
			}
		}
	}
	if length != e.size {
		return fmt.Errorf("a response of %d bytes, want %d", length, e.size)
	}
	_, err = e.br.Discard(length)
	return err
}

// TestProxy_ResponseDoesNotAllocateItsCopyBuffer: without a buffer pool
// ReverseProxy allocates the 32 KiB buffer it copies a body through for
// every response, more than everything else a proxied response allocates.
// With the buffer pooled, a response allocates less than that one buffer.
func TestProxy_ResponseDoesNotAllocateItsCopyBuffer(t *testing.T) {
	for _, size := range []int{1 << 10, 64 << 10} {
		t.Run(fmt.Sprintf("%dKiB", size>>10), func(t *testing.T) {
			e := newReuseRaw(t, &ListenerConfig{}, size)
			// Connections, pools and whatever else is set up once.
			for range 200 {
				if err := e.roundTrip(); err != nil {
					t.Fatalf("round trip: %v", err)
				}
			}
			const responses = 500
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for range responses {
				if err := e.roundTrip(); err != nil {
					t.Fatalf("round trip: %v", err)
				}
			}
			runtime.ReadMemStats(&after)
			perResponse := (after.TotalAlloc - before.TotalAlloc) / responses
			t.Logf("a proxied %d-byte response allocates %d B in %d allocations",
				size, perResponse, (after.Mallocs-before.Mallocs)/responses)
			if perResponse >= reuseCopyBuffer {
				t.Errorf("a proxied response allocates %d B, want less than its %d B copy buffer: the buffer is allocated for every response",
					perResponse, reuseCopyBuffer)
			}
		})
	}
}

// BenchmarkProxyResponse is one proxied response on the net/http path:
// client -> net/http server -> site -> ReverseProxy -> backend. The client
// and the backend allocate nothing, so B/op and allocs/op are those of the
// proxy.
func BenchmarkProxyResponse(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			e := newReuseRaw(b, &ListenerConfig{}, size)
			for range 200 {
				if err := e.roundTrip(); err != nil {
					b.Fatalf("round trip: %v", err)
				}
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := e.roundTrip(); err != nil {
					b.Fatalf("round trip: %v", err)
				}
			}
		})
	}
}
