//go:build linux

package httpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"nvelox/config"
	"nvelox/core/h2"
)

// fuzzFields turns fuzz input into a field list: each field is a length
// byte and a name, then a length byte and a value.
func fuzzFields(data []byte) [][2]string {
	var out [][2]string
	next := func() (string, bool) {
		if len(data) == 0 {
			return "", false
		}
		n := int(data[0])
		data = data[1:]
		if n > len(data) {
			n = len(data)
		}
		s := string(data[:n])
		data = data[n:]
		return s, true
	}
	for len(out) < 200 {
		name, ok := next()
		if !ok {
			break
		}
		value, _ := next()
		out = append(out, [2]string{name, value})
	}
	return out
}

// FuzzH2Block: a header block is kept, refused or cut short by h2Block
// exactly as by golang.org/x/net's reader (the code Go's server reads
// header blocks with), field for field; and what is kept can be handed to
// the request builders whatever it is.
func FuzzH2Block(f *testing.F) {
	seed := func(fields ...[2]string) {
		var b []byte
		for _, fl := range fields {
			b = append(append(append(append(b, byte(len(fl[0]))), fl[0]...), byte(len(fl[1]))), fl[1]...)
		}
		f.Add(b, true)
		f.Add(b, false)
	}
	seed([2]string{":method", "GET"}, [2]string{":scheme", "https"}, [2]string{":authority", "example.test"}, [2]string{":path", "/a?b=c"}, [2]string{"user-agent", "x"})
	seed([2]string{":method", "POST"}, [2]string{":scheme", "http"}, [2]string{":path", "/"}, [2]string{"host", "h"}, [2]string{"content-length", "3"}, [2]string{"cookie", "a=1"}, [2]string{"cookie", "b=2"})
	seed([2]string{":method", "GET"}, [2]string{"x", "y"}, [2]string{":path", "/"})
	seed([2]string{":status", "200"}, [2]string{":method", "GET"})
	seed([2]string{":method", "GET"}, [2]string{":method", "GET"}, [2]string{"X-Upper", "v"}, [2]string{"te", "trailers"}, [2]string{"trailer", "a, b"})
	seed([2]string{":method", "CONNECT"}, [2]string{":authority", "h:443"}, [2]string{"connection", "close"}, [2]string{"x", "a\x00b"})
	f.Fuzz(func(t *testing.T, data []byte, endStream bool) {
		fields := fuzzFields(data)
		var hb bytes.Buffer
		enc := hpack.NewEncoder(&hb)
		for _, fl := range fields {
			enc.WriteField(hpack.HeaderField{Name: fl[0], Value: fl[1]})
		}
		block := hb.Bytes()

		// x/net's reader.
		var wire bytes.Buffer
		fr := http2.NewFramer(&wire, &wire)
		fr.SetMaxReadFrameSize(1 << 24)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		fr.MaxHeaderListSize = h2MaxHeaderList
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block, EndStream: endStream, EndHeaders: true}); err != nil {
			t.Skip()
		}
		want := "ok"
		var wantFields []hpack.HeaderField
		frame, err := fr.ReadFrame()
		switch err.(type) {
		case nil:
			mh := frame.(*http2.MetaHeadersFrame)
			wantFields = mh.Fields
			if mh.Truncated {
				want = "truncated"
			}
		case http2.StreamError:
			want = "stream error"
		case http2.ConnectionError:
			want = "connection error"
		default:
			t.Fatalf("x/net: %v", err)
		}

		// The loops' reader.
		var d h2.Decoder
		d.MaxString = h2MaxHeaderList
		d.Reset()
		var blk h2Block
		blk.reset()
		got := "ok"
		err = d.Write(block, func(name, value []byte, _ bool) error { blk.add(name, value); return nil })
		if err == nil {
			err = d.Close()
		}
		_, pseudosOK := blk.pseudos()
		switch {
		case err != nil:
			got = "connection error"
		case blk.invalid || !pseudosOK:
			got = "stream error"
		case blk.truncated:
			got = "truncated"
		}
		if got != want {
			t.Fatalf("fields %q: x/net %s, loops %s", fields, want, got)
		}
		if got == "ok" || got == "truncated" {
			if len(blk.fields) != len(wantFields) {
				t.Fatalf("fields %q: x/net kept %d, loops %d", fields, len(wantFields), len(blk.fields))
			}
			for i, w := range wantFields {
				if string(blk.fieldName(i)) != w.Name || string(blk.fieldValue(i)) != w.Value {
					t.Fatalf("field %d: x/net %q=%q, loops %q=%q", i, w.Name, w.Value, blk.fieldName(i), blk.fieldValue(i))
				}
			}
		}
		if got != "ok" {
			return
		}
		// The request builders take any list that got this far.
		var req reqHead
		if blk.fastRequest(&req, endStream) {
			if req.host < 0 || len(req.method) == 0 || len(req.path) == 0 || req.path[0] != '/' {
				t.Fatalf("fields %q: a request for the loops without a host, method or path", fields)
			}
			if endStream != (req.contentLength <= 0) {
				t.Fatalf("fields %q: endStream %v with Content-Length %d on the loops", fields, endStream, req.contentLength)
			}
		}
		b := &h2Bridge{endStream: endStream, arena: blk.arena, fields: blk.fields, ctx: context.Background(),
			h: &h2BridgeHost{c: &h2conn{remote: "192.0.2.1:1234", fs: &fastServer{g: &BindGroup{httpServer: &http.Server{Handler: http.NotFoundHandler()}}}}}}
		b.cond.L = &b.mu
		// (The loop refuses some of these lists before a handler's request
		// is built; building it must be safe for any of them all the same.)
		b.request()
	})
}

var (
	h2FuzzOnce sync.Once
	h2FuzzAddr string
)

// FuzzH2Connection writes arbitrary bytes, after the client's preface, to an
// HTTP/2 connection of a running bind group. Whatever they are, no code of
// the loops panics, and the group goes on serving.
func FuzzH2Connection(f *testing.F) {
	var seed bytes.Buffer
	fr := http2.NewFramer(&seed, nil)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, fl := range h2Fields("GET", "/ok", [2]string{"cookie", "a=1"}, [2]string{"cookie", "b=2"}) {
		enc.WriteField(hpack.HeaderField{Name: fl[0], Value: fl[1]})
	}
	get := append([]byte(nil), hb.Bytes()...)
	hb.Reset()
	for _, fl := range [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/p"}, {"content-length", "5"}} {
		enc.WriteField(hpack.HeaderField{Name: fl[0], Value: fl[1]})
	}
	post := append([]byte(nil), hb.Bytes()...)
	add := func(build func()) {
		seed.Reset()
		build()
		f.Add(append([]byte(nil), seed.Bytes()...))
	}
	add(func() {
		fr.WriteSettings()
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: get, EndStream: true, EndHeaders: true})
	})
	add(func() {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 100})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: post, EndHeaders: true})
		fr.WriteDataPadded(1, false, []byte("ab"), []byte{0, 0, 0})
		fr.WritePing(false, [8]byte{1})
		fr.WriteWindowUpdate(1, 1000)
		fr.WriteData(1, true, []byte("cde"))
	})
	add(func() {
		fr.WriteSettings()
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: get[:4], EndStream: true, PadLength: 3, Priority: http2.PriorityParam{StreamDep: 3, Weight: 9}})
		fr.WriteContinuation(1, false, get[4:9])
		fr.WriteContinuation(1, true, get[9:])
		fr.WritePriority(3, http2.PriorityParam{StreamDep: 1})
		fr.WriteRSTStream(1, http2.ErrCodeCancel)
		fr.WriteGoAway(1, http2.ErrCodeNo, []byte("bye"))
	})
	add(func() {
		fr.WriteSettings()
		fr.WriteSettingsAck()
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: post, EndHeaders: true})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: get[4:], EndStream: true, EndHeaders: true})
		fr.WriteRawFrame(http2.FrameType(0x42), 0xff, 7, []byte("unknown"))
		fr.WriteWindowUpdate(0, 1<<30)
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		h2FuzzOnce.Do(func() {
			// One group for the whole run. (Its first test's cleanup would stop
			// it; it lives as long as the process.)
			be := allocsBackend(t, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			dir, err := os.MkdirTemp("", "h2fuzz")
			if err != nil {
				t.Fatal(err)
			}
			cert, key := genCertWithCN(t, dir, "example.test")
			l := &ListenerConfig{Name: "tls-site", Addr: "127.0.0.1:0", Protocol: "https", TLS: &config.TLSConfig{Cert: cert, Key: key}}
			g := NewBindGroup("127.0.0.1:0", "https")
			g.AddSite(fastTestSite(l, &config.Backend{Servers: []string{be}}))
			if err := g.Start(); err != nil {
				t.Fatal(err)
			}
			h2FuzzAddr = g.BoundAddr().String()
		})
		before := loopPanics.Load()
		c, err := tls.Dial("tcp", h2FuzzAddr, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"h2"}})
		if err != nil {
			t.Fatalf("the group no longer accepts: %v", err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte(http2.ClientPreface))
		c.Write(data)
		// Whatever the server answers. The client ends its side, so the
		// server closes once it has served what it was sent.
		c.CloseWrite()
		c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		io.Copy(io.Discard, c)
		c.Close()
		if n := loopPanics.Load() - before; n != 0 {
			t.Fatalf("%d panic(s) on the loops for input %x", n, data)
		}
	})
}
