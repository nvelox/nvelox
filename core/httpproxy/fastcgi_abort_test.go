package httpproxy

import (
	"context"
	"encoding/binary"
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
