//go:build linux

package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"

	"nvelox/config"
	"nvelox/core/logging"
)

// Tests of the fast path under clients and backends that misbehave: output
// a client does not take, informational floods, hand-overs with data in
// flight, and connection reuse.

// smallRcvDial dials addr with a 4 KiB receive buffer, set before the
// connect so that the advertised window stays small.
func smallRcvDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096) })
		return serr
	}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func quietLog(t *testing.T) {
	t.Helper()
	if err := logging.Init("error", filepath.Join(t.TempDir(), "access.log"), filepath.Join(t.TempDir(), "error.log")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("warning", "", "") })
}

// startFastGroup is startTestGroup (fast path) returning the group.
func startFastGroup(t *testing.T, s *HTTPServer) *BindGroup {
	t.Helper()
	g := NewBindGroup("127.0.0.1:0", "http")
	g.AddSite(s)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if g.fast == nil {
		t.Fatal("fast path not enabled")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		g.Stop(ctx)
	})
	return g
}

type fastConnStats struct {
	conns, pending int
}

// connStats reads, on the loops, the live connections of g's fast server.
func connStats(g *BindGroup) fastConnStats {
	fs := g.fast
	var mu sync.Mutex
	var st fastConnStats
	var wg sync.WaitGroup
	for _, l := range fs.group.Loops() {
		wg.Add(1)
		l.Post(func() {
			defer wg.Done()
			mu.Lock()
			defer mu.Unlock()
			for c := fs.lists[l.ID()].head; c != nil; c = c.lnext {
				st.conns++
				st.pending += len(c.pending)
			}
		})
	}
	wg.Wait()
	return st
}

// A client pipelines requests the fast path answers itself (an ACL deny)
// and reads nothing. Like net/http, the next request waits until the last
// response is out: what is held stays one response, and the write limit
// closes the connection.
func TestFastPath_PipelinedAnswersWaitForTheClient(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http",
		Timeouts: config.TimeoutConfig{Write: "300ms", Read: "300ms"},
		ACL:      []config.ACLRule{{Action: "deny", Match: config.ACLMatch{PathPrefix: "/deny"}}}}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	page := bytes.Repeat([]byte("x"), 64<<10)
	s.ErrorPages = map[int][]byte{403: page}
	quietLog(t)
	g := startFastGroup(t, s)
	c := smallRcvDial(t, g.BoundAddr().String())
	payload := strings.Repeat("GET /deny HTTP/1.1\r\nHost: x\r\n\r\n", 1000)
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	go io.WriteString(c, payload)
	time.Sleep(200 * time.Millisecond)
	if st := connStats(g); st.pending > 2*len(page) {
		t.Fatalf("%d bytes of responses held for a client that reads nothing (one response is %d)", st.pending, len(page))
	}
	deadline := time.Now().Add(5 * time.Second)
	for connStats(g).conns > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("connection still open long after the 300ms write limit: %+v", connStats(g))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A client that pipelines and then reads gets every answer, in order.
func TestFastPath_PipelinedAnswersAllServed(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http",
		ACL: []config.ACLRule{{Action: "deny", Match: config.ACLMatch{PathPrefix: "/deny"}}}}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	quietLog(t)
	g := startFastGroup(t, s)
	c := smallRcvDial(t, g.BoundAddr().String())
	const n = 300
	var raw strings.Builder
	for i := 0; i < n; i++ {
		if i%3 == 0 {
			fmt.Fprintf(&raw, "GET /ok/%d HTTP/1.1\r\nHost: x\r\n\r\n", i)
		} else {
			raw.WriteString("GET /deny HTTP/1.1\r\nHost: x\r\n\r\n")
		}
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	go io.WriteString(c, raw.String())
	time.Sleep(300 * time.Millisecond) // let the output back up first
	br := bufio.NewReader(c)
	for i := 0; i < n; i++ {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		want := http.StatusForbidden
		if i%3 == 0 {
			want = http.StatusOK
			if string(body) != fmt.Sprintf("hello GET /ok/%d", i) {
				t.Fatalf("response %d: body %q", i, body)
			}
		}
		if resp.StatusCode != want {
			t.Fatalf("response %d: status %d, want %d", i, resp.StatusCode, want)
		}
	}
}

// appendBuf grows geometrically past the largest pool class: appending in
// small pieces is linear, not quadratic.
func TestAppendBufGrowsGeometrically(t *testing.T) {
	var b []byte
	piece := bytes.Repeat([]byte("y"), 1500)
	grows := 0
	for i := 0; i < (4<<20)/len(piece); i++ {
		c := cap(b)
		appendBuf(&b, piece)
		if cap(b) != c {
			grows++
		}
	}
	if len(b) != (4<<20)/len(piece)*len(piece) {
		t.Fatalf("len %d", len(b))
	}
	if grows > 12 {
		t.Fatalf("%d reallocations for 4 MiB in 1500-byte pieces", grows)
	}
	releaseBuf(&b)
}

// informationalBackend answers one request with hints 1xx responses of
// hintSize bytes each (split into the given write sizes), then a 200.
func informationalBackend(t *testing.T, hints, hintSize int, split int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		bc, err := ln.Accept()
		if err != nil {
			return
		}
		defer bc.Close()
		if _, err := http.ReadRequest(bufio.NewReader(bc)); err != nil {
			return
		}
		link := "Link: </" + strings.Repeat("a", max(0, hintSize-40)) + ">; rel=preload\r\n"
		var out bytes.Buffer
		for i := 0; i < hints; i++ {
			out.WriteString("HTTP/1.1 103 Early Hints\r\n" + link + "\r\n")
		}
		out.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")
		b := out.Bytes()
		for len(b) > 0 {
			n := min(split, len(b))
			bc.SetWriteDeadline(time.Now().Add(20 * time.Second))
			if _, err := bc.Write(b[:n]); err != nil {
				return
			}
			b = b[n:]
			time.Sleep(time.Millisecond)
		}
		time.Sleep(10 * time.Second)
	}()
	return ln.Addr().String()
}

// A backend floods informational responses while the client reads
// nothing: they wait in the backend's socket, not in the proxy.
func TestFastPath_InformationalBackpressure(t *testing.T) {
	addr := informationalBackend(t, 5000, 4000, 64<<10)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{addr}})
	quietLog(t)
	g := startFastGroup(t, s)
	c := smallRcvDial(t, g.BoundAddr().String())
	io.WriteString(c, "GET /x HTTP/1.1\r\nHost: x\r\n\r\n")
	time.Sleep(2 * time.Second)
	if st := connStats(g); st.pending > 256<<10 {
		t.Fatalf("%d bytes of 1xx responses held for a client that reads nothing", st.pending)
	}
}

// Every informational response reaches the client exactly once, whatever
// the read boundaries, including after the client was slow (the paused
// head parser resumes from what it buffered).
func TestFastPath_InformationalOnceEach(t *testing.T) {
	for _, tc := range []struct {
		name               string
		hints, size, split int
		slowClient         bool
	}{
		{"split mid-head", 3, 200, 7, false},
		{"one write", 3, 200, 1 << 20, false},
		{"slow client", 60, 4000, 1 << 20, true},
		{"slow client, split", 60, 4000, 333, true},
		{"many tiny ones in one write", 2000, 40, 1 << 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := informationalBackend(t, tc.hints, tc.size, tc.split)
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
			s := fastTestSite(l, &config.Backend{Servers: []string{addr}})
			quietLog(t)
			g := startFastGroup(t, s)
			c := smallRcvDial(t, g.BoundAddr().String())
			c.SetDeadline(time.Now().Add(15 * time.Second))
			io.WriteString(c, "GET /x HTTP/1.1\r\nHost: x\r\n\r\n")
			if tc.slowClient {
				time.Sleep(500 * time.Millisecond)
			}
			br := bufio.NewReader(c)
			got := 0
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					t.Fatalf("after %d hints: %v", got, err)
				}
				if strings.HasPrefix(line, "HTTP/1.1 103 ") {
					got++
					continue
				}
				if strings.HasPrefix(line, "HTTP/1.1 200 ") {
					break
				}
			}
			if got != tc.hints {
				t.Fatalf("client got %d informational responses, backend sent %d", got, tc.hints)
			}
			resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(strings.NewReader("HTTP/1.1 200 OK\r\n"), br)), nil)
			if err != nil {
				t.Fatal(err)
			}
			if b, _ := io.ReadAll(resp.Body); string(b) != "ok" {
				t.Fatalf("final body %q", b)
			}
		})
	}
}

// An HTTPS request the fast path hands to net/http, sent in one burst with
// more records behind it: the ciphertext read before the hand-over is not
// lost (it would fail with "bad record MAC").
func TestFastTLS_HandoffKeepsCiphertextInFlight(t *testing.T) {
	be := newRawBackend(t)
	type upload struct {
		name     string
		compress bool
		raw      func(body string) string
	}
	for _, up := range []upload{
		{"chunked upload", false, func(b string) string {
			return "POST /up HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n" + fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(b), b)
		}},
		{"site served by net/http", true, func(b string) string {
			return fmt.Sprintf("POST /up HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\n\r\n%s", len(b), b)
		}},
	} {
		for _, size := range []int{40 << 10, 300 << 10} {
			s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
			if up.compress {
				s.Listener.Compression.Enabled = true
				s.Compression.Enabled = true
			}
			addr := startTLSGroup(t, s, true)
			raw := up.raw(strings.Repeat("x", size))
			for i := 0; i < 8; i++ {
				c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"http/1.1"}})
				if err != nil {
					t.Fatal(err)
				}
				c.SetDeadline(time.Now().Add(10 * time.Second))
				go io.WriteString(c, raw)
				resp, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil {
					c.Close()
					t.Fatalf("%s, %d bytes, round %d: %v", up.name, size, i, err)
				}
				b, _ := io.ReadAll(resp.Body)
				c.Close()
				if resp.StatusCode != 200 || string(b) != "hello POST /up" {
					t.Fatalf("%s, %d bytes, round %d: status %d body %q", up.name, size, i, resp.StatusCode, trunc(string(b)))
				}
			}
		}
	}
}

// A HEAD leaves its backend connection idle in the pool; the next request
// on it gets an early answer (the backend refuses its body). That answer is
// framed as a response to the new request, not to the HEAD.
func TestFastPath_EarlyResponseAfterHead(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	g := startFastGroup(t, s)
	c, err := net.Dial("tcp", g.BoundAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	io.WriteString(c, "HEAD /ok HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(br, &http.Request{Method: "HEAD"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	io.WriteString(c, "POST /early HTTP/1.1\r\nHost: x\r\nContent-Length: 4000000\r\n\r\n")
	go func() {
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for i := 0; i < 60; i++ {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	}()
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 413 || string(b) != "nope" {
		t.Fatalf("early response after a HEAD: status %d body %q", resp.StatusCode, b)
	}
}

// Idle backend connections are kept per site and backend: a site never
// gets another site's connection, even to the same address, and the
// sweep drops pools that emptied.
func TestFastPath_IdlePoolsPerSiteAndBackend(t *testing.T) {
	g, err := ngx.NewGroup(1)
	if err != nil {
		t.Fatal(err)
	}
	l := g.Loops()[0]
	done := make(chan string, 1)
	l.Post(func() {
		fl := &fastLoop{l: l, pools: make(map[poolKey]*upPool), addrs: make(map[string]unix.Sockaddr)}
		fl.sweep.fl = fl
		fl.sweep.F = &fl.sweep
		a, b := &HTTPServer{}, &HTTPServer{}
		ka := poolKey{site: a, backend: "be", target: "127.0.0.1:9"}
		u := &uconn{fl: fl, fd: -1, key: ka.target, pool: ka}
		u.timer.F = u
		fl.putIdle(u)
		switch {
		case fl.takeIdle(poolKey{site: b, backend: "be", target: ka.target}) != nil:
			done <- "another site took the idle connection"
		case fl.takeIdle(poolKey{site: a, backend: "other", target: ka.target}) != nil:
			done <- "another backend took the idle connection"
		case fl.takeIdle(ka) != u:
			done <- "its own site did not get the idle connection back"
		default:
			fl.sweep.OnTimer()
			fl.l.Stop(&fl.sweep.Timer)
			if len(fl.pools) != 0 {
				done <- fmt.Sprintf("%d empty pools left after the sweep", len(fl.pools))
				return
			}
			done <- ""
		}
	})
	select {
	case msg := <-done:
		if msg != "" {
			t.Fatal(msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not run the check")
	}
}

// Forwarding headers from a trusted peer reach the backend exactly as on
// the net/http path, including an empty first X-Real-IP or
// X-Forwarded-Proto and forwarding headers its Connection header names.
func TestFastPath_TrustedForwardingEdgeCases(t *testing.T) {
	be := newRawBackend(t)
	for _, hdrs := range []string{
		"X-Real-IP: \r\nX-Real-IP: 192.0.2.5\r\nX-Forwarded-Proto: \r\nX-Forwarded-Proto: https\r\n",
		"Connection: X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, Forwarded, X-Forwarded-Host\r\nX-Forwarded-For: 203.0.113.7\r\nX-Real-IP: 192.0.2.6\r\nX-Forwarded-Proto: https\r\nForwarded: for=y\r\nX-Forwarded-Host: fh\r\n",
		"Connection: X-Forwarded-For\r\nX-Forwarded-For: 203.0.113.8\r\nX-Forwarded-For: 127.0.0.4\r\n",
		"X-Forwarded-For: \r\nX-Forwarded-For: 203.0.113.9\r\n",
		"X-Forwarded-For: \r\n",
		"X-Forwarded-For: 203.0.113.10\r\nX-Forwarded-For: \r\n",
	} {
		var upstream [2]*http.Request
		for i, fast := range []bool{false, true} {
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", TrustedProxies: []string{"127.0.0.0/8"}}
			s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
			addr := startTestGroup(t, s, fast)
			exchange(t, addr, "GET /ok HTTP/1.1\r\nHost: h\r\n"+hdrs+"\r\n", "GET")
			upstream[i] = be.last()
		}
		for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Proto", "Forwarded", "X-Forwarded-Host"} {
			slow, fast := upstream[0].Header.Values(h), upstream[1].Header.Values(h)
			if strings.Join(slow, "|") != strings.Join(fast, "|") {
				t.Errorf("%q: %s: net/http path %q, fast path %q", hdrs, h, slow, fast)
			}
		}
	}
}

// writeLimitCloses waits until g has no connection left, or fails.
func writeLimitCloses(t *testing.T, g *BindGroup, within time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		st := connStats(g)
		if st.conns == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: connection still open after %v: %+v", what, within, st)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Output waiting for a client that reads nothing is cut by the write limit,
// also while the request body is still coming (or stalled, or complete):
// the body's own read limit does not replace it.
func TestFastPath_WriteLimitWhileBodyInFlight(t *testing.T) {
	for _, tc := range []struct {
		name, read string
		rest       int // body bytes sent once the output backed up
	}{
		{"body stalls", "300ms", 0},
		{"body completes", "5s", 990},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := informationalBackend(t, 5000, 4000, 64<<10)
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http",
				Timeouts: config.TimeoutConfig{Write: "300ms", Read: tc.read}}
			s := fastTestSite(l, &config.Backend{Servers: []string{addr}})
			quietLog(t)
			g := startFastGroup(t, s)
			c := smallRcvDial(t, g.BoundAddr().String())
			io.WriteString(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n"+strings.Repeat("b", 10))
			until := time.Now().Add(3 * time.Second)
			for {
				st := connStats(g)
				if st.conns == 0 {
					return // already cut (a slow run can miss the backed-up moment)
				}
				if st.pending > 0 {
					break
				}
				if time.Now().After(until) {
					t.Fatalf("1xx output never backed up: %+v", st)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if tc.rest > 0 {
				io.WriteString(c, strings.Repeat("b", tc.rest))
			}
			writeLimitCloses(t, g, 4*time.Second, tc.name)
		})
	}
}

// A client that trickles its body and reads nothing is cut by the write
// limit once its output backs up, although body bytes keep coming.
func TestFastPath_WriteLimitBeatsTricklingBody(t *testing.T) {
	addr := informationalBackend(t, 5000, 4000, 64<<10)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http",
		Timeouts: config.TimeoutConfig{Write: "300ms", Read: "5s"}}
	s := fastTestSite(l, &config.Backend{Servers: []string{addr}})
	quietLog(t)
	g := startFastGroup(t, s)
	c := smallRcvDial(t, g.BoundAddr().String())
	io.WriteString(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				if _, err := c.Write([]byte("b")); err != nil {
					return
				}
			}
		}
	}()
	writeLimitCloses(t, g, 4*time.Second, "trickling body")
}

// slowBodyBackend reads a request body slowly (512 KiB every 10 ms through
// a small receive buffer) and answers with the number of bytes it got.
func slowBodyBackend(t *testing.T) string {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 32<<10) })
		return serr
	}}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			bc, err := ln.Accept()
			if err != nil {
				return
			}
			go func(bc net.Conn) {
				defer bc.Close()
				req, err := http.ReadRequest(bufio.NewReaderSize(bc, 16<<10))
				if err != nil {
					return
				}
				buf := make([]byte, 512<<10)
				var n int
				for {
					m, err := io.ReadFull(req.Body, buf)
					n += m
					if err != nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				got := fmt.Sprint(n)
				fmt.Fprintf(bc, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(got), got)
			}(bc)
		}
	}()
	return ln.Addr().String()
}

// The request body's read limit times the client, not the backend: an
// upload the backend takes longer to read than the limit, from a client
// that never stalls, completes.
func TestFastPath_SlowBackendUploadOutlivesReadLimit(t *testing.T) {
	quietLog(t)
	const size = 96 << 20 // more than the kernel buffers on the way hold
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http",
		Timeouts: config.TimeoutConfig{Read: "300ms"}}
	s := fastTestSite(l, &config.Backend{Servers: []string{slowBodyBackend(t)}})
	g := startFastGroup(t, s)
	c, err := net.Dial("tcp", g.BoundAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", size)
	time.Sleep(50 * time.Millisecond) // a pause first: the read limit gets armed
	go func() {
		chunk := bytes.Repeat([]byte("b"), 64<<10)
		for i := 0; i < size/len(chunk); i++ {
			c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	}()
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != fmt.Sprint(size) {
		t.Fatalf("status %d body %q", resp.StatusCode, trunc(string(b)))
	}
}

// earlyStreamBackend answers before reading the body: a chunked response
// of n pieces, gap apart.
func earlyStreamBackend(t *testing.T, n int, gap time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			bc, err := ln.Accept()
			if err != nil {
				return
			}
			go func(bc net.Conn) {
				defer bc.Close()
				br := bufio.NewReader(bc)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				io.WriteString(bc, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
				for i := 0; i < n; i++ {
					time.Sleep(gap)
					if _, err := io.WriteString(bc, "5\r\nchunk\r\n"); err != nil {
						return
					}
				}
				io.WriteString(bc, "0\r\n\r\n")
				bc.SetReadDeadline(time.Now().Add(5 * time.Second))
				io.Copy(io.Discard, br)
			}(bc)
		}
	}()
	return ln.Addr().String()
}

// An answer the backend starts before the request body is in is not cut by
// the body's read limit: the body is not read any more.
func TestFastPath_EarlyResponseOutlivesReadLimit(t *testing.T) {
	quietLog(t)
	for _, complete := range []bool{true, false} {
		t.Run(fmt.Sprintf("body complete=%v", complete), func(t *testing.T) {
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http",
				Timeouts: config.TimeoutConfig{Read: "300ms", Write: "5s"}}
			s := fastTestSite(l, &config.Backend{Servers: []string{earlyStreamBackend(t, 15, 100*time.Millisecond)}})
			g := startFastGroup(t, s)
			c, err := net.Dial("tcp", g.BoundAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			io.WriteString(c, "POST /s HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\n0123456789")
			time.Sleep(150 * time.Millisecond)
			if complete {
				io.WriteString(c, "abcdefghij")
			}
			c.SetReadDeadline(time.Now().Add(6 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil || string(b) != strings.Repeat("chunk", 15) {
				t.Fatalf("got %d bytes, err %v", len(b), err)
			}
		})
	}
}

// Clients that reset in the middle of their upload: each request is logged
// once, the server's count of live connections goes back to zero, and a
// graceful stop is not held up.
func TestFastPath_ResetMidUploadAccounting(t *testing.T) {
	be := newRawBackend(t)
	dir := t.TempDir()
	if err := logging.Init("info", filepath.Join(dir, "access.log"), filepath.Join(dir, "error.log")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("warning", "", "") })
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	g := NewBindGroup("127.0.0.1:0", "http")
	g.AddSite(s)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if g.fast == nil {
		t.Fatal("fast path not enabled")
	}
	const rounds = 5
	for i := 0; i < rounds; i++ {
		c, err := net.Dial("tcp", g.BoundAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n"+strings.Repeat("b", 1000))
		time.Sleep(200 * time.Millisecond) // the request is at the backend, more body awaited
		c.(*net.TCPConn).SetLinger(0)
		c.Close()
	}
	time.Sleep(500 * time.Millisecond)
	active := g.fast.active.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	err := g.Stop(ctx)
	took := time.Since(start)
	logging.Init("warning", "", "")
	al, _ := os.ReadFile(filepath.Join(dir, "access.log"))
	if lines := strings.Count(string(al), "POST /up"); active != 0 || lines != rounds || err != nil || took > 2*time.Second {
		t.Fatalf("live connections %d (want 0), %d log lines (want %d), Stop: %v after %v\n%s", active, lines, rounds, err, took, al)
	}
}

// A response that is still being sent when the request is over (here the
// 400 for a body the client cut short with its FIN) reaches the client in
// full: the closing connection drains the client's input, and sees its
// EOF, only once its output is out.
func TestFastPath_HalfClosedClientGetsWholeResponse(t *testing.T) {
	be := newRawBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	page := bytes.Repeat([]byte("x"), 4<<20) // more than the socket takes at once
	s.ErrorPages = map[int][]byte{400: page}
	quietLog(t)
	g := startFastGroup(t, s)
	for i := 0; i < 3; i++ {
		c := smallRcvDial(t, g.BoundAddr().String())
		io.WriteString(c, "POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n0123456789")
		time.Sleep(100 * time.Millisecond) // the body is awaited
		c.(*net.TCPConn).CloseWrite()      // cut short: 400, larger than the socket takes
		time.Sleep(200 * time.Millisecond)
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		b, err := io.ReadAll(resp.Body)
		if resp.StatusCode != 400 || err != nil || len(b) != len(page) {
			t.Fatalf("round %d: status %d, got %d of %d bytes, err %v", i, resp.StatusCode, len(b), len(page), err)
		}
	}
}

// After a 1xx (103 Early Hints) the final response keeps the headers nvelox
// puts on every response, on both paths: net/http's ReverseProxy clears the
// response headers once it has forwarded a 1xx.
func TestHeadersSurviveInformational(t *testing.T) {
	be := newRawBackend(t)
	for _, fast := range []bool{false, true} {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http",
			RequestID: config.RequestIDConfig{Enabled: true}}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		addr := startTestGroup(t, s, fast)
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(c, "GET /103 HTTP/1.1\r\nHost: x\r\n\r\n")
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil) // the 103
		if err == nil && resp.StatusCode == 103 {
			resp, err = http.ReadResponse(br, nil)
		}
		c.Close()
		if err != nil {
			t.Fatalf("fast=%v: %v", fast, err)
		}
		if resp.StatusCode != 200 || resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("X-Request-Id") == "" {
			t.Fatalf("fast=%v: status %d, headers %v", fast, resp.StatusCode, resp.Header)
		}
	}
}

// A client that ends in the middle of a request head gets net/http's 400,
// on both paths.
func TestPartialHeadThenEOFGets400(t *testing.T) {
	be := newRawBackend(t)
	for _, fast := range []bool{false, true} {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		addr := startTestGroup(t, s, fast)
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nX-Partial")
		time.Sleep(50 * time.Millisecond)
		c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		c.Close()
		if !strings.HasPrefix(string(b), "HTTP/1.1 400 ") {
			t.Fatalf("fast=%v: got %q", fast, trunc(string(b)))
		}
	}
}

// An empty Host reaches the backend as net/http's Transport sends it: the
// backend's own address.
func TestEmptyHostForwardedAsNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	var hosts [2]string
	for i, fast := range []bool{false, true} {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		addr := startTestGroup(t, s, fast)
		exchange(t, addr, "GET /ok HTTP/1.1\r\nHost: \r\n\r\n", "GET")
		hosts[i] = be.last().Host
	}
	if hosts[0] != hosts[1] || hosts[1] != be.addr() {
		t.Fatalf("Host at the backend: net/http path %q, fast path %q (backend %s)", hosts[0], hosts[1], be.addr())
	}
}

// A backend that cuts its response body is logged the way net/http's
// ReverseProxy logs it, on both paths.
func TestCutBackendBodyLogged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			bc, err := ln.Accept()
			if err != nil {
				return
			}
			go func(bc net.Conn) {
				defer bc.Close()
				if _, err := http.ReadRequest(bufio.NewReader(bc)); err != nil {
					return
				}
				io.WriteString(bc, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\nhalf")
			}(bc)
		}
	}()
	var buf syncBuf
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for _, fast := range []bool{false, true} {
		buf.reset()
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
		s := fastTestSite(l, &config.Backend{Servers: []string{ln.Addr().String()}})
		addr := startTestGroup(t, s, fast)
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(c, "GET /x HTTP/1.1\r\nHost: x\r\n\r\n")
		io.ReadAll(c)
		c.Close()
		deadline := time.Now().Add(3 * time.Second)
		for !strings.Contains(buf.String(), "httputil: ReverseProxy read error during body copy: unexpected EOF") {
			if time.Now().After(deadline) {
				t.Fatalf("fast=%v: log %q", fast, buf.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuf) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}
