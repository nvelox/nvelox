//go:build linux

package httpproxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/nvelox/ngx/h2"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"

	"nvelox/config"
)

// allocsBackend answers every read with resp, on raw sockets (it allocates
// nothing per request).
func allocsBackend(t *testing.T, resp []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				raw, err := c.(*net.TCPConn).SyscallConn()
				if err != nil {
					return
				}
				buf := make([]byte, 4096)
				raw.Control(func(fd uintptr) { unix.SetNonblock(int(fd), false) })
				raw.Control(func(fd uintptr) {
					for {
						n, err := unix.Read(int(fd), buf)
						if err == unix.EINTR {
							continue
						}
						if n <= 0 || err != nil {
							return
						}
						if _, err := unix.Write(int(fd), resp); err != nil {
							return
						}
					}
				})
			}(c)
		}
	}()
	return ln.Addr().String()
}

// A request on an HTTP/2 connection allocates no more than the same
// request over HTTPS with HTTP/1.1: the frames, the header block and the
// stream are all in buffers that are reused. (What is left on both is
// crypto/tls's, in the proxy and in this test's client.)
func TestH2_AllocationsPerRequest(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates")
	}
	quietLog(t)
	be := allocsBackend(t, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"))
	s := tlsSite(t, &config.Backend{Servers: []string{be}})
	addr := startTLSGroup(t, s, true)
	dial := func(proto string) *tls.Conn {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{proto}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(60 * time.Second))
		return c
	}
	measure := func(requests func(n int)) float64 {
		requests(3000)
		const n = 20000
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		requests(n)
		runtime.ReadMemStats(&after)
		return float64(after.Mallocs-before.Mallocs) / n
	}
	in := make([]byte, 16384)

	// HTTPS, HTTP/1.1.
	c1 := dial("http/1.1")
	req1 := []byte("GET /x HTTP/1.1\r\nHost: example.test\r\nUser-Agent: t\r\n\r\n")
	h1 := measure(func(n int) {
		for i := 0; i < n; i++ {
			if _, err := c1.Write(req1); err != nil {
				t.Fatal(err)
			}
			got := 0
			for !bytes.HasSuffix(in[:got], []byte("hello")) {
				m, err := c1.Read(in[got:])
				if err != nil {
					t.Fatalf("HTTP/1.1 request %d: %v", i, err)
				}
				got += m
			}
		}
	})

	// HTTP/2: one request at a time, each a HEADERS frame written from one
	// buffer whose stream id is changed in place.
	c2 := dial("h2")
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/x"}, {"user-agent", "t"}} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	var setup bytes.Buffer
	fr := http2.NewFramer(&setup, nil)
	setup.WriteString(http2.ClientPreface)
	fr.WriteSettings()
	fr.WriteWindowUpdate(0, 1<<30)
	if _, err := c2.Write(setup.Bytes()); err != nil {
		t.Fatal(err)
	}
	// The first block of a connection puts its fields in the table; later
	// ones name them by index, as a client's do.
	first := append([]byte(nil), hb.Bytes()...)
	hb.Reset()
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/x"}, {"user-agent", "t"}} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	block := append([]byte(nil), hb.Bytes()...)
	frame := h2.AppendFrameHeader(nil, len(block), h2.FrameHeaders, h2.FlagEndStream|h2.FlagEndHeaders, 1)
	frame = append(frame, block...)
	id := uint32(1)
	send := func(payload []byte) {
		if _, err := c2.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	// wait reads frames until stream id ends.
	buffered := 0
	wait := func(id uint32) {
		for {
			for buffered >= h2.FrameHeaderLen {
				fh := h2.ReadFrameHeader(in)
				total := h2.FrameHeaderLen + int(fh.Length)
				if buffered < total {
					break
				}
				done := fh.StreamID == id && (fh.Type == h2.FrameData || fh.Type == h2.FrameHeaders) && fh.Flags&h2.FlagEndStream != 0
				if fh.Type == h2.FrameRSTStream || fh.Type == h2.FrameGoAway {
					t.Fatalf("stream %d: frame type %d on stream %d", id, fh.Type, fh.StreamID)
				}
				buffered = copy(in, in[total:buffered])
				if done {
					return
				}
			}
			m, err := c2.Read(in[buffered:])
			if err != nil {
				if err == io.EOF {
					t.Fatalf("stream %d: connection closed", id)
				}
				t.Fatalf("stream %d: %v", id, err)
			}
			buffered += m
		}
	}
	fh1 := h2.AppendFrameHeader(nil, len(first), h2.FrameHeaders, h2.FlagEndStream|h2.FlagEndHeaders, id)
	send(append(fh1, first...))
	wait(id)
	h2a := measure(func(n int) {
		for i := 0; i < n; i++ {
			id += 2
			frame[5], frame[6], frame[7], frame[8] = byte(id>>24), byte(id>>16), byte(id>>8), byte(id)
			send(frame)
			wait(id)
		}
	})
	t.Logf("allocations per request: HTTPS with HTTP/1.1 %.3f, HTTP/2 %.3f", h1, h2a)
	if h2a > h1+0.05 {
		t.Errorf("HTTP/2: %.3f allocations per request, HTTP/1.1 over TLS %.3f", h2a, h1)
	}
}
