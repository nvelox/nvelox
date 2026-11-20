package httpproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
)

// TestFastCGI_ClientGoneClosesTheUpstream: an upstream that sends the head
// and part of the body, then neither sends more nor closes. When the
// client's request ends (the client went away), nvelox closes the
// upstream's connection and the handler returns; before, the request, its
// goroutines and both connections were held until the upstream closed.
func TestFastCGI_ClientGoneClosesTheUpstream(t *testing.T) {
	if err := logging.Init("error", "", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("info", "", "") })
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	headSent := make(chan struct{})
	upstreamClosed := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var id uint16
		for { // the request's records, to its empty STDIN record
			var h [8]byte
			if _, err := io.ReadFull(c, h[:]); err != nil {
				return
			}
			typ, n, pad := h[1], int(binary.BigEndian.Uint16(h[4:6])), int(h[6])
			id = binary.BigEndian.Uint16(h[2:4])
			if _, err := io.CopyN(io.Discard, c, int64(n+pad)); err != nil {
				return
			}
			if typ == 5 && n == 0 {
				break
			}
		}
		if err := writeFCGIRecord(c, 6, id, []byte("Content-Type: text/plain\r\n\r\npart")); err != nil {
			return
		}
		close(headSent)
		// Stall: nothing more, no end. A read returns once nvelox closes.
		done := make(chan struct{})
		go func() {
			var b [1]byte
			_, _ = c.Read(b[:])
			close(done)
		}()
		select {
		case <-done:
			close(upstreamClosed)
		case <-release:
		}
	}()
	cfg := config.FastCGIConfig{Pass: ln.Addr().String(), DocumentRoot: root}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("GET", "/index.php", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		ServeFastCGI(rec, r, cfg, nil)
	}()
	select {
	case <-headSent:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream never got the request")
	}
	time.Sleep(100 * time.Millisecond)
	cancel() // the client goes away
	select {
	case <-upstreamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("the client went away 3 s ago and the upstream's connection is still open")
	}
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("the client went away and the FastCGI handler has not returned")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want the 200 the upstream's head gave", rec.Code)
	}
}

// TestFastCGI_ClientGoneWhileTheUpstreamTakesNoBody: an upstream that
// accepts and reads nothing (a hostile one, or PHP-FPM with every worker
// busy), and a client that sends a 1 GiB body (more than any socket
// buffers hold). The request writer blocks
// once the socket buffers are full. When the client's request ends, nvelox
// closes the upstream's connection, which frees the writer, and the
// handler returns; before, the handler, its goroutines and both
// connections waited for the upstream for ever.
func TestFastCGI_ClientGoneWhileTheUpstreamTakesNoBody(t *testing.T) {
	if err := logging.Init("error", "", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("info", "", "") })
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c // read nothing, close nothing (until the test ends)
	}()
	t.Cleanup(func() {
		select {
		case c := <-accepted:
			c.Close()
		default:
		}
	})
	cfg := config.FastCGIConfig{Pass: ln.Addr().String(), DocumentRoot: root}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const size = 1 << 30
	r := httptest.NewRequest("POST", "/index.php", io.LimitReader(xs{}, size)).WithContext(ctx)
	r.ContentLength = size
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		ServeFastCGI(httptest.NewRecorder(), r, cfg, nil)
	}()
	time.Sleep(500 * time.Millisecond) // the writer fills the socket buffers and blocks
	select {
	case <-returned:
		t.Fatal("the handler returned before the client went away: the upstream took the body after all")
	default:
	}
	cancel() // the client goes away
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("the client went away 3 s ago and the FastCGI handler still waits on an upstream that takes no body")
	}
}

// xs reads as an endless run of 'x'.
type xs struct{}

func (xs) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// TestFastCGI_SendTimeout: a FastCGI server that takes nothing of the
// request body for the route's timeouts.send ends the exchange, and the
// client gets a 504 from nvelox (the server had not begun to answer); an
// upload the server keeps taking is not cut, however long the body.
func TestFastCGI_SendTimeout(t *testing.T) {
	if err := logging.Init("error", "", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("info", "", "") })

	t.Run("takes nothing", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php"), 0o644); err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		accepted := make(chan net.Conn, 1)
		go func() {
			if c, err := ln.Accept(); err == nil {
				accepted <- c // read nothing
			}
		}()
		t.Cleanup(func() {
			select {
			case c := <-accepted:
				c.Close()
			default:
			}
		})
		cfg := config.FastCGIConfig{Pass: ln.Addr().String(), DocumentRoot: root}
		cfg.Timeouts.Send = "300ms"
		const size = 1 << 30
		r := httptest.NewRequest("POST", "/index.php", io.LimitReader(xs{}, size))
		r.ContentLength = size
		start := time.Now()
		rec := serveFCGI(t, cfg, r)
		if rec.Code != http.StatusGatewayTimeout {
			t.Fatalf("a server that takes none of the body: %d, want 504", rec.Code)
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Fatalf("504 after %v, want soon after the 300ms send timeout", took)
		}
	})

	t.Run("takes it slowly", func(t *testing.T) {
		cfg, current := fakeFCGIUpstream(t)
		cfg.Timeouts.Send = "300ms"
		current.Store(&fcgiReply{out: []byte("Content-Type: text/plain\r\n\r\ngot it")})
		// 600ms of body, a byte every 200ms: each piece is taken at once.
		r := httptest.NewRequest("POST", "/index.php", &slowBody{n: 3, gap: 200 * time.Millisecond})
		if rec := serveFCGI(t, cfg, r); rec.Code != http.StatusOK || rec.Body.String() != "got it" {
			t.Fatalf("an upload slower than the send timeout that the server takes: %d %q, want 200", rec.Code, rec.Body.String())
		}
	})
}

// scriptedConn is a FastCGI upstream's connection for fcgiSendConn: each
// write takes as much as takes says, in turn (all of it once the list is
// used up), and fails with a timeout when that is less than it was given.
// fail, when set, fails every write at once. deadlines holds the write
// deadline each write had.
type scriptedConn struct {
	net.Conn
	takes     []int
	fail      error
	deadline  time.Time
	deadlines []time.Time
	taken     []byte
}

func (c *scriptedConn) SetWriteDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	c.deadlines = append(c.deadlines, c.deadline)
	if c.fail != nil {
		return 0, c.fail
	}
	n := len(p)
	if len(c.takes) > 0 {
		n = min(n, c.takes[0])
		c.takes = c.takes[1:]
	}
	c.taken = append(c.taken, p[:n]...)
	if n < len(p) {
		return n, os.ErrDeadlineExceeded
	}
	return n, nil
}

// TestFastCGI_SendConn: the send timeout is a pause in what the upstream
// takes. A write it takes some of before each deadline goes on, with the
// limit counted again from each try; one it takes nothing of for the limit
// fails, and the exchange is ended once.
func TestFastCGI_SendConn(t *testing.T) {
	const limit = time.Minute
	t.Run("keeps taking", func(t *testing.T) {
		sc := &scriptedConn{takes: []int{3, 3, 3}}
		stalls := 0
		c := &fcgiSendConn{Conn: sc, limit: limit, stalled: func() { stalls++ }}
		before := time.Now()
		n, err := c.Write([]byte("0123456789"))
		after := time.Now()
		if err != nil || n != 10 || string(sc.taken) != "0123456789" || stalls != 0 {
			t.Fatalf("an upstream that takes some of each try: wrote %d, %v; it took %q; %d stalls", n, err, sc.taken, stalls)
		}
		if len(sc.deadlines) != 4 {
			t.Fatalf("%d tries, want 4", len(sc.deadlines))
		}
		for i, d := range sc.deadlines {
			if d.Before(before.Add(limit)) || d.After(after.Add(limit)) {
				t.Errorf("try %d: deadline %v, want the limit from the try (%v to %v)", i, d, before.Add(limit), after.Add(limit))
			}
		}
	})
	t.Run("takes nothing", func(t *testing.T) {
		sc := &scriptedConn{takes: []int{4, 0, 0}}
		stalls := 0
		c := &fcgiSendConn{Conn: sc, limit: limit, stalled: func() { stalls++ }}
		if n, err := c.Write([]byte("0123456789")); n != 4 || !errors.Is(err, os.ErrDeadlineExceeded) || stalls != 1 {
			t.Fatalf("an upstream that stops taking: wrote %d, %v; %d stalls, want 4, a timeout and 1", n, err, stalls)
		}
		if _, err := c.Write([]byte("x")); err == nil || stalls != 1 {
			t.Fatalf("the next write: %v, %d stalls; want a timeout, and the exchange ended once", err, stalls)
		}
	})
	t.Run("another error", func(t *testing.T) {
		sc := &scriptedConn{fail: io.ErrClosedPipe}
		stalls := 0
		c := &fcgiSendConn{Conn: sc, limit: limit, stalled: func() { stalls++ }}
		if n, err := c.Write([]byte("0123456789")); n != 0 || err != io.ErrClosedPipe || stalls != 0 || len(sc.deadlines) != 1 {
			t.Fatalf("a write that fails at once: %d, %v, %d stalls, %d tries", n, err, stalls, len(sc.deadlines))
		}
	})
}
