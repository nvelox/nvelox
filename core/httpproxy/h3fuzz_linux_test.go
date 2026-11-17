//go:build linux

package httpproxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/h3"
	"nvelox/lb"

	"github.com/quic-go/quic-go"
)

var (
	h3FuzzOnce sync.Once
	h3FuzzAddr string
)

// h3FuzzStep encodes one step of FuzzH3Connection's input: a stream to
// open and the bytes to write on it.
func h3FuzzStep(op byte, p []byte) []byte {
	return append([]byte{op<<4 | byte(len(p)>>8), byte(len(p))}, p...)
}

// FuzzH3Connection writes arbitrary bytes on the streams of an HTTP/3
// connection to a running bind group whose HTTP/3 the event loops serve.
// Whatever they are, no code of the loops panics, and the group goes on
// serving.
//
// The input is a list of steps, two bytes and what follows them: the first
// four bits say what stream the bytes go on (bit 0: a unidirectional one,
// else a request stream; bit 1: the stream is ended behind them; bit 2: it
// is reset behind them), the next twelve how many bytes there are.
func FuzzH3Connection(f *testing.F) {
	join := func(steps ...[]byte) (all []byte) {
		for _, s := range steps {
			all = append(all, s...)
		}
		return all
	}
	get := h3HeadersFrame(h3GetFields...)
	post := h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw", "content-length", "5")
	// Requests as they should be, with the client's own streams around them.
	f.Add(h3FuzzStep(2, get))
	f.Add(join(h3FuzzStep(2, append(append([]byte{}, post...), h3DataFrame([]byte("hello"))...))))
	f.Add(join(h3FuzzStep(1, []byte{h3.StreamControl, h3.FrameSettings, 0}), h3FuzzStep(1, []byte{h3.StreamQPACKEncoder}), h3FuzzStep(1, []byte{h3.StreamQPACKDecoder}), h3FuzzStep(2, get)))
	// A body of unknown length with trailers (a request for the handlers).
	f.Add(h3FuzzStep(2, join(h3HeadersFrame(":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/raw", "trailer", "x-sum"), h3DataFrame([]byte("abc")), h3HeadersFrame("x-sum", "6"))))
	// Heads cut short, streams reset, frames out of place and of no kind.
	f.Add(join(h3FuzzStep(0, post[:len(post)/2]), h3FuzzStep(6, get), h3FuzzStep(4, post)))
	f.Add(join(h3FuzzStep(2, h3DataFrame([]byte("a body before any head"))), h3FuzzStep(2, append(append([]byte{}, get...), get...))))
	f.Add(h3FuzzStep(2, []byte{0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))
	f.Add(h3FuzzStep(2, []byte{0x40, 0x40, 0x21, 0x03, 1, 2, 3, 0x01, 0x00}))
	// The client's own streams misused.
	f.Add(join(h3FuzzStep(3, []byte{h3.StreamControl, h3.FrameGoAway, 1, 0}), h3FuzzStep(2, get)))
	f.Add(join(h3FuzzStep(1, []byte{h3.StreamControl, h3.FrameSettings, 4, 0x06, 0x40, 0x64, 0x21}), h3FuzzStep(1, []byte{h3.StreamControl, h3.FrameSettings, 0}), h3FuzzStep(2, get)))
	f.Add(join(h3FuzzStep(1, []byte{h3.StreamQPACKEncoder, 0x3f, 0xe1, 0x1f, 0xc0, 0x80}), h3FuzzStep(5, []byte{h3.StreamQPACKDecoder, 0x80, 0x01}), h3FuzzStep(1, []byte{0x21, 1, 2, 3}), h3FuzzStep(1, []byte{0x01}), h3FuzzStep(2, get)))

	f.Fuzz(func(t *testing.T, data []byte) {
		h3FuzzOnce.Do(func() {
			// One group for the whole run. (Its first test's cleanup would stop
			// it; it lives as long as the process, and so does its backend.)
			backend := httptest.NewServer(http.HandlerFunc(h3RawBackend))
			target := strings.TrimPrefix(backend.URL, "http://")
			dir, err := os.MkdirTemp("", "h3fuzz")
			if err != nil {
				t.Fatal(err)
			}
			cert, key := genCertWithCN(t, dir, "localhost")
			l := &ListenerConfig{Name: "h3", Addr: ":0", Protocol: "https", Backend: "be", HTTP3: true,
				TLS: &config.TLSConfig{Cert: cert, Key: key}}
			site := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})},
				map[string]*config.Backend{"be": {Name: "be", Servers: []string{target}}}, nil, nil, nil, nil, nil)
			h3FuzzAddr = freeAddr(t)
			g := NewBindGroup(h3FuzzAddr, "https")
			g.AddSite(site)
			old := h3OnLoops
			h3OnLoops = true
			err = g.Start()
			h3OnLoops = old // the group has its loops; other tests of this process choose for themselves
			if err != nil {
				t.Fatal(err)
			}
			if g.h3loops == nil {
				t.Fatal("the group's HTTP/3 is not on the event loops")
			}
		})
		input := data
		before := loopPanics.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, h3FuzzAddr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"h3"}}, nil)
		if err != nil {
			t.Fatalf("the group no longer accepts: %v", err)
		}
		defer conn.CloseWithError(0, "")
		for n := 0; len(data) >= 2 && n < 16; n++ {
			op, size := data[0]>>4, int(data[0]&0x0f)<<8|int(data[1])
			data = data[2:]
			size = min(size, len(data))
			p := data[:size]
			data = data[size:]
			if op&1 == 0 {
				str, err := conn.OpenStream()
				if err != nil {
					break // no more streams, or the server has closed the connection
				}
				str.SetWriteDeadline(time.Now().Add(time.Second))
				str.Write(p)
				switch {
				case op&4 != 0:
					str.CancelWrite(quic.StreamErrorCode(h3.ErrRequestCancelled))
					str.CancelRead(quic.StreamErrorCode(h3.ErrRequestCancelled))
				case op&2 != 0:
					str.Close()
				}
				continue
			}
			str, err := conn.OpenUniStream()
			if err != nil {
				continue
			}
			str.SetWriteDeadline(time.Now().Add(time.Second))
			str.Write(p)
			switch {
			case op&4 != 0:
				str.CancelWrite(quic.StreamErrorCode(h3.ErrRequestCancelled))
			case op&2 != 0:
				str.Close()
			}
		}
		// A request behind them all: when it is answered, or the connection
		// is over, the server has dealt with what came before it.
		if str, err := conn.OpenStream(); err == nil {
			str.SetDeadline(time.Now().Add(300 * time.Millisecond))
			str.Write(get)
			str.Close()
			io.Copy(io.Discard, str)
		}
		if n := loopPanics.Load() - before; n != 0 {
			t.Fatalf("%d panic(s) on the loops for input %x", n, input)
		}
	})
}
