//go:build linux

package integration

// L4 half-close regression suite.
//
// Production bug (tunnel gateway, :80/:443 L4 listeners with zero_copy +
// send_proxy_v2): when the BACKEND closed first right after writing a
// response, nvelox dropped the bytes it had already read from the backend but
// not yet written to the (slower) client, then closed the client — a 90,104
// byte HTTP/1.1 "Connection: close" response reached curl as 41-52 KB.
//
// Required (standard L4 proxy) semantics, exercised below for every listener
// flavour (plain TCP, TLS passthrough over plain TCP, TLS-terminating) with
// zero_copy on/off and send_proxy_v2 on/off:
//
//  1. When one side reaches EOF, everything already read from it is written
//     to the other side.
//  2. Then only the WRITE direction toward the other side is half-closed.
//  3. The opposite direction keeps flowing until it ends too (or times out).
//  4. Only a real error / RST aborts the other side immediately.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"

	"github.com/pires/go-proxyproto"
)

// hcTransport is how the client reaches the backend through nvelox.
type hcTransport int

const (
	hcPlainTCP       hcTransport = iota // L4 TCP listener, plaintext end to end
	hcTLSPassthrough                    // L4 TCP listener, TLS end to end (client <-> backend), like :443 on the gateway
	hcTLSTerminate                      // nvelox TLS listener (protocol tcp + tls cert), plaintext to the backend
)

func (tr hcTransport) String() string {
	switch tr {
	case hcPlainTCP:
		return "tcp"
	case hcTLSPassthrough:
		return "tls-passthrough"
	case hcTLSTerminate:
		return "tls-terminate"
	}
	return "unknown"
}

type hcMode struct {
	transport hcTransport
	zeroCopy  bool
	proxyV2   bool
}

func (m hcMode) String() string {
	return fmt.Sprintf("%s/zero_copy=%v/proxy_v2=%v", m.transport, m.zeroCopy, m.proxyV2)
}

func allHalfCloseModes() []hcMode {
	var modes []hcMode
	for _, tr := range []hcTransport{hcPlainTCP, hcTLSPassthrough, hcTLSTerminate} {
		for _, zc := range []bool{true, false} {
			for _, pv2 := range []bool{false, true} {
				modes = append(modes, hcMode{transport: tr, zeroCopy: zc, proxyV2: pv2})
			}
		}
	}
	return modes
}

// hcPayload returns n deterministic, position-dependent bytes so a dropped or
// reordered chunk can never compare equal.
func hcPayload(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + byte((i*7+i/251+int(seed))%26)
	}
	return b
}

// bufferedConn lets a backend read a PROXY header through a bufio.Reader and
// then hand the SAME buffered stream to tls.Server.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// hcBackend is one accepted backend-side connection, normalised so the test
// handlers don't care about TLS / PROXY framing.
type hcBackend struct {
	raw  net.Conn  // the TCP conn (for CloseWrite / RST)
	conn net.Conn  // raw, or the tls.Server on top of it
	r    io.Reader // reads payload (after any PROXY header)
}

// startHCBackend accepts connections and, per connection, strips/validates
// the PROXY v2 header (when expected), terminates TLS (passthrough mode) and
// runs handle. Handler failures are reported on the returned channel.
func startHCBackend(t *testing.T, m hcMode, tlsCfg *tls.Config, handle func(b *hcBackend) error) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	errs := make(chan error, 16)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				defer raw.Close()
				br := bufio.NewReaderSize(raw, 64*1024)
				// waitForPort's readiness probe connects to the proxy and hangs up
				// at once; the proxy still dials us for it (and, with
				// send_proxy_v2, forwards the PROXY header and then the probe's
				// FIN). Such a connection carries no payload — ignore it instead
				// of reporting noise.
				probe := func() bool {
					raw.SetReadDeadline(time.Now().Add(5 * time.Second))
					_, perr := br.Peek(1)
					raw.SetReadDeadline(time.Time{})
					return perr != nil
				}
				if probe() {
					return
				}
				if m.proxyV2 {
					raw.SetReadDeadline(time.Now().Add(5 * time.Second))
					hdr, err := proxyproto.Read(br)
					raw.SetReadDeadline(time.Time{})
					if err != nil || hdr == nil {
						errs <- fmt.Errorf("backend: expected PROXY v2 header: %v", err)
						return
					}
					src, ok := hdr.SourceAddr.(*net.TCPAddr)
					if !ok || !src.IP.IsLoopback() || src.Port == 0 {
						errs <- fmt.Errorf("backend: PROXY v2 source %v is not the test client", hdr.SourceAddr)
						return
					}
					if probe() {
						return
					}
				}
				b := &hcBackend{raw: raw, conn: raw, r: br}
				if m.transport == hcTLSPassthrough {
					tc := tls.Server(&bufferedConn{Conn: raw, r: br}, tlsCfg)
					if err := tc.Handshake(); err != nil {
						errs <- fmt.Errorf("backend: TLS handshake: %v", err)
						return
					}
					b.conn, b.r = tc, tc
				}
				if err := handle(b); err != nil {
					errs <- err
				}
			}(raw)
		}
	}()
	return ln.Addr().String(), errs
}

// startHCProxy starts an nvelox engine with one L4 TCP listener in front of
// backendAddr, configured for the mode. idle is the listener idle timeout
// ("" = default).
func startHCProxy(t *testing.T, m hcMode, backendAddr, certFile, keyFile, idle string) string {
	t.Helper()
	proxyPort := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "error"},
		Backends: []config.Backend{{
			Name:        "hc-pool",
			Balance:     "roundrobin",
			Servers:     []string{backendAddr},
			SendProxyV2: m.proxyV2,
		}},
	}
	l := &core.ListenerConfig{
		Name:     "hc-test",
		Addr:     addr,
		Protocol: "tcp",
		ZeroCopy: m.zeroCopy,
		Backend:  "hc-pool",
		Port:     proxyPort,
		Timeouts: config.TimeoutConfig{Idle: idle},
	}
	if m.transport == hcTLSTerminate {
		l.TLS = &config.TLSConfig{Cert: certFile, Key: keyFile}
	}
	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{l}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := engine.Start(ctx); err != nil {
			t.Logf("engine stopped: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("engine did not stop within 5s")
		}
	})
	waitForPort(t, proxyPort)
	return addr
}

// dialHC connects to the proxy as a deliberately SLOW client: a tiny receive
// buffer so nvelox cannot park the whole response in kernel socket buffers
// and has to hold it (and honour back-pressure) itself.
func dialHC(t *testing.T, m hcMode, proxyAddr string) (conn net.Conn, raw *net.TCPConn) {
	t.Helper()
	d := net.Dialer{
		Timeout: 2 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	c, err := d.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	raw = c.(*net.TCPConn)
	t.Cleanup(func() { raw.Close() })
	if m.transport == hcPlainTCP {
		return raw, raw
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	tc.SetDeadline(time.Time{})
	return tc, raw
}

// clientCloseWrite half-closes the client's write side: close_notify (TLS)
// plus a TCP FIN, so the L4 proxy really sees EOF from the client.
func clientCloseWrite(conn net.Conn, raw *net.TCPConn) error {
	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.CloseWrite(); err != nil {
			return err
		}
	}
	return raw.CloseWrite()
}

// slowReadAll reads until EOF in small throttled chunks. It fails (returns
// the bytes so far + error) on any error other than a clean EOF, or when no
// progress / EOF happens within stall.
func slowReadAll(conn net.Conn, chunk int, pause, stall time.Duration) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, chunk)
	for {
		conn.SetReadDeadline(time.Now().Add(stall))
		n, err := conn.Read(buf)
		out.Write(buf[:n])
		if err == io.EOF {
			return out.Bytes(), nil
		}
		if err != nil {
			return out.Bytes(), err
		}
		if pause > 0 {
			time.Sleep(pause)
		}
	}
}

func readHTTPRequestHead(r io.Reader) error {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("backend: reading request head: %w", err)
		}
		if line == "\r\n" {
			return nil
		}
	}
}

func drainErrs(t *testing.T, errs <-chan error) {
	t.Helper()
	for {
		select {
		case err := <-errs:
			t.Error(err)
		default:
			return
		}
	}
}

// loopbackAbsorb measures how many bytes the kernel alone buffers between a
// loopback server socket and a non-reading client created like dialHC's (tiny
// SO_RCVBUF). Hosts differ wildly (stock tcp_wmem default 16 KiB vs tuned
// hosts with 12 MiB+), and while the proxy's whole response still fits in
// kernel buffers a proxy that discards its OWN pending bytes on close can
// look correct. Sizing one case past this guarantees the proxy itself is
// holding undelivered bytes when the backend's FIN arrives — exactly the
// production condition (a remote client with a small, slow-growing window).
func loopbackAbsorb(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	m := hcMode{transport: hcPlainTCP}
	_, cl := dialHC(t, m, ln.Addr().String())
	defer cl.Close()
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	buf := make([]byte, 64*1024)
	total := 0
	for total < 256<<20 {
		s.SetWriteDeadline(time.Now().Add(150 * time.Millisecond))
		n, err := s.Write(buf)
		total += n
		if err != nil {
			break
		}
	}
	return total
}

// TestL4HalfClose_BackendClosesFirst is the production regression: the backend
// writes a large Connection: close response and closes immediately; a slow
// client must still receive EVERY byte, then a clean EOF.
func TestL4HalfClose_BackendClosesFirst(t *testing.T) {
	tmp := t.TempDir()
	certFile, keyFile := generateTestCert(t, tmp)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	backendTLS := &tls.Config{Certificates: []tls.Certificate{cert}}

	// 90,104 B = the exact production response; 8 MiB = a large body; the
	// third size overflows this host's kernel loopback buffering by 3 MiB so
	// the proxy must be holding undelivered bytes itself at backend EOF.
	absorb := loopbackAbsorb(t)
	t.Logf("kernel absorbs %d bytes toward a non-reading client on this host", absorb)
	sizes := []int{90104, 8 << 20, absorb + 3<<20}
	if testing.Short() {
		sizes = []int{90104, absorb + 3<<20}
	}
	for _, m := range allHalfCloseModes() {
		for _, size := range sizes {
			m, size := m, size
			t.Run(fmt.Sprintf("%s/body=%d", m, size), func(t *testing.T) {
				body := hcPayload(size, byte(size))
				head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", size)
				want := append([]byte(head), body...)

				backendDone := make(chan struct{}, 1)
				backendAddr, errs := startHCBackend(t, m, backendTLS, func(b *hcBackend) error {
					defer func() { backendDone <- struct{}{} }()
					if err := readHTTPRequestHead(b.r); err != nil {
						return err
					}
					if _, err := b.conn.Write(want); err != nil {
						return fmt.Errorf("backend write: %w", err)
					}
					// Close IMMEDIATELY after the last write: the FIN races the
					// data still queued inside nvelox for the slow client.
					return b.conn.Close()
				})
				proxyAddr := startHCProxy(t, m, backendAddr, certFile, keyFile, "")

				conn, _ := dialHC(t, m, proxyAddr)
				if _, err := io.WriteString(conn, "GET /big HTTP/1.1\r\nHost: hc.test\r\nConnection: close\r\n\r\n"); err != nil {
					t.Fatalf("client write: %v", err)
				}
				// Don't read a byte until the backend has written everything
				// AND closed (bounded: a proxy with real back-pressure may keep
				// the backend's write blocked until we start reading).
				select {
				case <-backendDone:
				case <-time.After(1500 * time.Millisecond):
				}
				time.Sleep(100 * time.Millisecond)

				got, err := slowReadAll(conn, 16*1024, 300*time.Microsecond, 5*time.Second)
				if err != nil {
					t.Fatalf("client read failed after %d/%d bytes: %v", len(got), len(want), err)
				}
				if len(got) != len(want) {
					t.Fatalf("client got %d bytes, want %d (response truncated by the proxy)", len(got), len(want))
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("client got %d bytes but the content differs (corrupted/reordered stream)", len(got))
				}
				drainErrs(t, errs)
			})
		}
	}
}

// TestL4HalfClose_ClientClosesWriteFirst is the reverse direction: the client
// sends a whole request and half-closes (shutdown SHUT_WR). The backend must
// receive the entire request followed by EOF and must still be able to send
// its full answer back to the client.
func TestL4HalfClose_ClientClosesWriteFirst(t *testing.T) {
	tmp := t.TempDir()
	certFile, keyFile := generateTestCert(t, tmp)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	backendTLS := &tls.Config{Certificates: []tls.Certificate{cert}}

	const reqSize = 1 << 20
	const respSize = 512 * 1024
	for _, m := range allHalfCloseModes() {
		m := m
		t.Run(m.String(), func(t *testing.T) {
			req := hcPayload(reqSize, 3)
			resp := hcPayload(respSize, 11)

			backendAddr, errs := startHCBackend(t, m, backendTLS, func(b *hcBackend) error {
				b.raw.SetReadDeadline(time.Now().Add(10 * time.Second))
				got, err := io.ReadAll(b.r) // only returns once the proxy propagates the client's EOF
				b.raw.SetReadDeadline(time.Time{})
				if err != nil {
					return fmt.Errorf("backend: reading request until EOF: %v (got %d/%d bytes)", err, len(got), reqSize)
				}
				if !bytes.Equal(got, req) {
					return fmt.Errorf("backend: got %d request bytes, want %d identical bytes", len(got), reqSize)
				}
				if _, err := b.conn.Write(resp); err != nil {
					return fmt.Errorf("backend: writing response after client half-close: %w", err)
				}
				return b.conn.Close()
			})
			proxyAddr := startHCProxy(t, m, backendAddr, certFile, keyFile, "")

			conn, raw := dialHC(t, m, proxyAddr)
			if _, err := conn.Write(req); err != nil {
				t.Fatalf("client write: %v", err)
			}
			if err := clientCloseWrite(conn, raw); err != nil {
				t.Fatalf("client half-close: %v", err)
			}
			got, err := slowReadAll(conn, 16*1024, 0, 5*time.Second)
			if err != nil {
				t.Fatalf("client read failed after %d/%d response bytes: %v", len(got), respSize, err)
			}
			if !bytes.Equal(got, resp) {
				t.Fatalf("client got %d response bytes, want %d identical bytes", len(got), respSize)
			}
			// give the backend goroutine a moment to report
			time.Sleep(50 * time.Millisecond)
			drainErrs(t, errs)
		})
	}
}

// TestL4HalfClose_BackendResetAbortsClient: a real error (RST) from the
// backend must NOT be dressed up as a graceful half-close that leaves the
// client hanging — the client must see the connection end promptly.
func TestL4HalfClose_BackendResetAbortsClient(t *testing.T) {
	tmp := t.TempDir()
	certFile, keyFile := generateTestCert(t, tmp)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	backendTLS := &tls.Config{Certificates: []tls.Certificate{cert}}

	for _, m := range allHalfCloseModes() {
		m := m
		t.Run(m.String(), func(t *testing.T) {
			backendAddr, _ := startHCBackend(t, m, backendTLS, func(b *hcBackend) error {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(b.r, buf); err != nil {
					return err
				}
				// RST: SO_LINGER 0 + close.
				b.raw.(*net.TCPConn).SetLinger(0)
				return b.raw.Close()
			})
			proxyAddr := startHCProxy(t, m, backendAddr, certFile, keyFile, "")
			conn, _ := dialHC(t, m, proxyAddr)
			if _, err := io.WriteString(conn, "hello"); err != nil {
				t.Fatalf("client write: %v", err)
			}
			start := time.Now()
			_, err := slowReadAll(conn, 4096, 0, 3*time.Second)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("client still connected %v after the backend reset", time.Since(start))
			}
		})
	}
}

// TestL4HalfClose_HalfClosedIdleTimeout: once the backend has finished and the
// client got its EOF, a client that never closes its side must not pin the
// session forever — the listener idle timeout still applies to the remaining
// direction. Observed from the backend: the proxy must eventually close the
// backend connection.
func TestL4HalfClose_HalfClosedIdleTimeout(t *testing.T) {
	m := hcMode{transport: hcPlainTCP}
	backendClosed := make(chan time.Duration, 1)
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
				hi := make([]byte, 2)
				if _, err := io.ReadFull(c, hi); err != nil {
					return // readiness probe
				}
				io.WriteString(c, "bye")
				c.(*net.TCPConn).CloseWrite() // backend done writing; keeps reading
				start := time.Now()
				io.Copy(io.Discard, c) // returns when the proxy closes/half-closes toward us
				backendClosed <- time.Since(start)
			}(c)
		}
	}()
	proxyAddr := startHCProxy(t, m, ln.Addr().String(), "", "", "400ms")
	conn, _ := dialHC(t, m, proxyAddr)
	if _, err := io.WriteString(conn, "hi"); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got, err := slowReadAll(conn, 64, 0, 3*time.Second)
	if err != nil || string(got) != "bye" {
		t.Fatalf("client: got %q, err %v; want \"bye\" then EOF", got, err)
	}
	// The client neither writes nor closes: idle (400ms) must end the session.
	select {
	case d := <-backendClosed:
		if d > 3*time.Second {
			t.Fatalf("backend side released after %v, want ~idle timeout", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("half-closed session never timed out (idle timeout not applied to the remaining direction)")
	}
}

// TestL4HalfClose_TrustedRelayProxyHeader covers the production listener
// shape (accept_proxy_from + send_proxy_v2): a trusted peer-region relay sends
// its inbound PROXY-v2 header, the request, then half-closes. nvelox must
// strip that header, forward the REAL client in its own PROXY-v2 header, keep
// payload bytes that arrived in the same segment, and still deliver the whole
// response after both half-closes.
func TestL4HalfClose_TrustedRelayProxyHeader(t *testing.T) {
	realClient := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4242}
	req := hcPayload(300*1024, 5)
	resp := hcPayload(2<<20, 9)

	type seen struct {
		src  net.Addr
		body []byte
		err  error
	}
	seenCh := make(chan seen, 4)
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
				br := bufio.NewReader(c)
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				hdr, err := proxyproto.Read(br)
				if err != nil {
					return // readiness probe
				}
				body, err := io.ReadAll(br)
				if len(body) == 0 && err == nil {
					return // readiness probe (header + FIN only)
				}
				seenCh <- seen{src: hdr.SourceAddr, body: body, err: err}
				c.Write(resp)
			}(c)
		}
	}()

	proxyPort := getFreePort(t)
	cfg := &config.Config{
		Version:  "2",
		Logging:  config.LoggingConfig{Level: "error"},
		Backends: []config.Backend{{Name: "relay-pool", Balance: "roundrobin", Servers: []string{ln.Addr().String()}, SendProxyV2: true}},
		Listeners: []config.Listener{{
			Name: "relay-in", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort), Protocol: "tcp", ZeroCopy: true,
			Backend: "relay-pool", AcceptProxyFrom: []string{"127.0.0.1/32"},
		}},
	}
	listeners, err := core.ExpandListeners(cfg.Listeners)
	if err != nil {
		t.Fatal(err)
	}
	engine := core.NewEngine(cfg)
	engine.Listeners = listeners
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { engine.Start(ctx); close(stopped) }()
	t.Cleanup(func() { cancel(); <-stopped })
	waitForPort(t, proxyPort)

	conn, raw := dialHC(t, hcMode{transport: hcPlainTCP}, fmt.Sprintf("127.0.0.1:%d", proxyPort))
	var first bytes.Buffer
	proxyproto.HeaderProxyFromAddrs(2, realClient, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: proxyPort}).WriteTo(&first)
	first.Write(req[:1000]) // payload in the same write as the inbound header
	if _, err := conn.Write(first.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(req[1000:]); err != nil {
		t.Fatal(err)
	}
	if err := clientCloseWrite(conn, raw); err != nil {
		t.Fatal(err)
	}
	got, err := slowReadAll(conn, 16*1024, 0, 5*time.Second)
	if err != nil || !bytes.Equal(got, resp) {
		t.Fatalf("client got %d/%d response bytes, err=%v", len(got), len(resp), err)
	}
	select {
	case s := <-seenCh:
		if s.err != nil || !bytes.Equal(s.body, req) {
			t.Fatalf("backend got %d/%d request bytes, err=%v", len(s.body), len(req), s.err)
		}
		if s.src.String() != realClient.String() {
			t.Fatalf("backend PROXY v2 source = %v, want the real client %v", s.src, realClient)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never saw the request")
	}
}
