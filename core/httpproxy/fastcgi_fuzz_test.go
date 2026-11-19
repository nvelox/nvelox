package httpproxy

import (
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
)

// fcgiReply is what the fake FastCGI upstream answers: the CGI output
// (headers, a blank line, the body) in STDOUT records, or, raw, the bytes
// it writes in place of any record. Before the STDOUT records it can send
// stderr, in a STDERR record, and then wait for wait to close (at most 5 s).
type fcgiReply struct {
	raw    bool
	out    []byte
	stderr []byte
	wait   <-chan struct{}
}

func writeFCGIRecord(w io.Writer, typ byte, id uint16, content []byte) error {
	h := [8]byte{1, typ}
	binary.BigEndian.PutUint16(h[2:4], id)
	binary.BigEndian.PutUint16(h[4:6], uint16(len(content)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(content)
	return err
}

// serveFakeFCGI answers every request on ln with the reply current holds,
// once the request's records are read (to its empty STDIN record).
func serveFakeFCGI(ln net.Listener, current *atomic.Pointer[fcgiReply]) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var id uint16
			for {
				var h [8]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				typ, n, pad := h[1], int(binary.BigEndian.Uint16(h[4:6])), int(h[6])
				id = binary.BigEndian.Uint16(h[2:4])
				if _, err := io.CopyN(io.Discard, c, int64(n+pad)); err != nil {
					return
				}
				if typ == 5 && n == 0 { // the end of STDIN
					break
				}
			}
			r := current.Load()
			if r.raw {
				_, _ = c.Write(r.out)
				return
			}
			if r.stderr != nil && writeFCGIRecord(c, 7, id, r.stderr) != nil {
				return
			}
			if r.wait != nil {
				select {
				case <-r.wait:
				case <-time.After(5 * time.Second):
				}
			}
			for out := r.out; ; {
				n := min(len(out), 65535)
				if writeFCGIRecord(c, 6, id, out[:n]) != nil || n == 0 {
					break
				}
				out = out[n:]
			}
			_ = writeFCGIRecord(c, 3, id, make([]byte, 8)) // END_REQUEST
		}()
	}
}

// fakeFCGIUpstream starts the fake FastCGI upstream and returns the route
// config that reaches it (a document root holding index.php) and the reply
// it gives.
func fakeFCGIUpstream(tb testing.TB) (config.FastCGIConfig, *atomic.Pointer[fcgiReply]) {
	tb.Helper()
	root := tb.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php"), 0o644); err != nil {
		tb.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { ln.Close() })
	current := new(atomic.Pointer[fcgiReply])
	current.Store(&fcgiReply{})
	go serveFakeFCGI(ln, current)
	return config.FastCGIConfig{Pass: ln.Addr().String(), DocumentRoot: root}, current
}

// FuzzFastCGIResponse: whatever a FastCGI upstream answers, in records or
// in raw bytes, nvelox's FastCGI handler returns, answers the client with a
// valid status, and panics nowhere: the FastCGI client reads the response
// on a goroutine of its own, where a panic would end the process.
func FuzzFastCGIResponse(f *testing.F) {
	if err := logging.Init("error", "", ""); err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = logging.Init("info", "", "") })
	cfg, current := fakeFCGIUpstream(f)

	var stdout = func(s string) []byte {
		var b []byte
		rec := func(typ byte, c []byte) {
			h := [8]byte{1, typ, 0, 1}
			binary.BigEndian.PutUint16(h[4:6], uint16(len(c)))
			b = append(append(b, h[:]...), c...)
		}
		rec(6, []byte(s))
		rec(6, nil)
		rec(3, make([]byte, 8))
		return b
	}
	for _, s := range []string{
		"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
		"Status: 099 Odd\r\n\r\n", "Status: 1000\r\n\r\n", "Status: abc\r\n\r\n", "Status: \r\n\r\n", "Status: 2\r\n\r\n",
		"Content-Type: text/html\r\nLocation: /x\r\n\r\n", "X: a\r\n b\r\n\r\n", "X-Bad Name: v\r\n\r\nbody",
		"no blank line", "", "\r\n\r\n", "Status: 204\r\nContent-Length: 5\r\n\r\nhello",
	} {
		f.Add(false, []byte(s))
		f.Add(true, stdout(s))
	}
	f.Add(true, []byte{})
	f.Add(true, []byte{1, 6, 0, 1, 0xff, 0xff, 0, 0, 'x'})
	f.Add(true, []byte{1, 3, 0, 1, 0, 8, 0, 0})
	f.Add(true, []byte{1, 7, 0, 1, 0, 3, 0, 0, 'e', 'r', 'r', 1, 6, 0, 1, 0, 0, 0, 0, 1, 3, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, raw bool, out []byte) {
		current.Store(&fcgiReply{raw: raw, out: out})
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			ServeFastCGI(rec, httptest.NewRequest("GET", "/index.php", nil), cfg, nil)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("the FastCGI handler has not returned after 10 s (raw=%v, %q)", raw, out)
		}
		if rec.Code < 200 || rec.Code > 599 {
			t.Fatalf("the client was answered %d (raw=%v, %q)", rec.Code, raw, out)
		}
	})
}
