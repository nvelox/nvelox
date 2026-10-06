//go:build linux

// Linux-specific: these tests pin down Linux TCP behaviour (half-close,
// RST on close with unread input, SIOCOUTQ).

package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/pires/go-proxyproto"
)

// tcpPair returns the two ends of a fresh loopback TCP connection.
func tcpPair(t *testing.T) (dialed, accepted *net.TCPConn) {
	t.Helper()
	return tcpPairRcvBuf(t, 0)
}

// tcpPairRcvBuf is tcpPair with SO_RCVBUF on the dialed end set BEFORE
// connect (a slow client). Shrinking it after the handshake would shrink an
// already-advertised window and stall loopback in zero-window probing.
func tcpPairRcvBuf(t *testing.T, rcvBuf int) (dialed, accepted *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	dialer := net.Dialer{}
	if rcvBuf > 0 {
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvBuf)
			})
		}
	}
	d, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { d.Close(); r.c.Close() })
	return d.(*net.TCPConn), r.c.(*net.TCPConn)
}

// relayFixture wires test-client <-> [relayL4] <-> test-backend over real
// loopback TCP so CloseWrite / RST behave exactly as in production.
type relayFixture struct {
	client  *net.TCPConn // the test's client end
	backend *net.TCPConn // the test's backend end
	done    chan relayResult
}

func startRelay(t *testing.T, idle time.Duration) *relayFixture {
	t.Helper()
	return startRelayRcvBuf(t, idle, 0)
}

func startRelayRcvBuf(t *testing.T, idle time.Duration, clientRcvBuf int) *relayFixture {
	t.Helper()
	cl, proxyClientSide := tcpPairRcvBuf(t, clientRcvBuf)
	proxyBackendSide, be := tcpPair(t)
	f := &relayFixture{client: cl, backend: be, done: make(chan relayResult, 1)}
	go func() { f.done <- relayL4(proxyClientSide, proxyBackendSide, idle) }()
	return f
}

func (f *relayFixture) wait(t *testing.T, within time.Duration) relayResult {
	t.Helper()
	select {
	case r := <-f.done:
		return r
	case <-time.After(within):
		t.Fatalf("relay still running after %v", within)
		return relayResult{}
	}
}

func readAllWithin(t *testing.T, c net.Conn, d time.Duration) ([]byte, error) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	return io.ReadAll(c)
}

// Backend FIN first: every byte is delivered, then the client sees EOF, and
// the client->backend direction is STILL open (the backend keeps reading).
func TestRelayL4_BackendFINFirst_HalfClosesOnly(t *testing.T) {
	f := startRelay(t, 0)
	body := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	go func() {
		f.backend.Write(body)
		f.backend.CloseWrite()
	}()
	time.Sleep(100 * time.Millisecond) // the client is slow to start reading
	got, err := readAllWithin(t, f.client, 5*time.Second)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("client got %d/%d bytes, err=%v", len(got), len(body), err)
	}
	// Half-close only: the client can still talk to the backend afterwards.
	if _, err := f.client.Write([]byte("still-here")); err != nil {
		t.Fatalf("client write after backend FIN: %v", err)
	}
	f.client.CloseWrite()
	tail, err := readAllWithin(t, f.backend, 2*time.Second)
	if err != nil || string(tail) != "still-here" {
		t.Fatalf("backend got %q (err %v) after its own FIN, want \"still-here\" then EOF", tail, err)
	}
	r := f.wait(t, 2*time.Second)
	if r.Err != nil || r.BackendToClient != int64(len(body)) || r.ClientToBackend != int64(len("still-here")) {
		t.Fatalf("relay result = %+v", r)
	}
}

// A direction that is quiet for longer than idle must NOT kill the session
// while the other direction keeps moving bytes.
func TestRelayL4_IdleCountsBothDirections(t *testing.T) {
	const idle = 500 * time.Millisecond
	f := startRelay(t, idle)
	got := make(chan []byte, 1)
	go func() {
		b, _ := readAllWithin(t, f.backend, 5*time.Second)
		got <- b
	}()
	// client->backend trickles for ~2.4x idle (one byte every idle/5);
	// backend->client stays silent the whole time.
	for i := 0; i < 12; i++ {
		if _, err := f.client.Write([]byte{'x'}); err != nil {
			t.Fatalf("trickle write %d: %v (session killed while active)", i, err)
		}
		time.Sleep(idle / 5)
	}
	f.client.CloseWrite()
	if b := <-got; len(b) != 12 {
		t.Fatalf("backend got %d trickled bytes, want 12", len(b))
	}
	// The backend side may still answer after the client's half-close.
	f.backend.Write([]byte("ok"))
	f.backend.CloseWrite()
	if b, err := readAllWithin(t, f.client, 2*time.Second); err != nil || string(b) != "ok" {
		t.Fatalf("client got %q err %v, want \"ok\"", b, err)
	}
	if r := f.wait(t, 2*time.Second); r.Err != nil {
		t.Fatalf("clean session ended with %v", r.Err)
	}
}

// The half-closed state is bounded by the idle timeout: the backend finished,
// the client got EOF but never closes — the session must be released.
func TestRelayL4_HalfClosedIdleTimeout(t *testing.T) {
	const idle = 250 * time.Millisecond
	f := startRelay(t, idle)
	f.backend.Write([]byte("bye"))
	f.backend.CloseWrite()
	if b, err := readAllWithin(t, f.client, 2*time.Second); err != nil || string(b) != "bye" {
		t.Fatalf("client got %q err %v", b, err)
	}
	start := time.Now()
	r := f.wait(t, 3*time.Second)
	if !isTimeout(r.Err) {
		t.Fatalf("relay ended with %v, want an idle timeout", r.Err)
	}
	if el := time.Since(start); el > idle+time.Second {
		t.Fatalf("half-closed session lingered %v (idle %v)", el, idle)
	}
}

// idle = 0 disables the timeout entirely (explicit "0" in config).
func TestRelayL4_IdleDisabled(t *testing.T) {
	f := startRelay(t, 0)
	time.Sleep(300 * time.Millisecond)
	select {
	case r := <-f.done:
		t.Fatalf("relay ended without traffic and without idle timeout: %+v", r)
	default:
	}
	f.client.Close()
	f.backend.Close()
	f.wait(t, 2*time.Second)
}

// A client that stops reading (zero window) must not pin a session forever
// once the other direction is finished: the stalled write hits the idle
// timeout and the session is aborted.
func TestRelayL4_StalledWriterAborts(t *testing.T) {
	const idle = 300 * time.Millisecond
	f := startRelayRcvBuf(t, idle, 4096)
	f.client.CloseWrite() // client -> backend is done
	go func() {
		chunk := make([]byte, 1<<20)
		for {
			f.backend.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := f.backend.Write(chunk); err != nil {
				return
			}
		}
	}()
	r := f.wait(t, 10*time.Second)
	if r.Err == nil {
		t.Fatalf("stalled session ended cleanly?: %+v", r)
	}
}

// sendQueueLen returns the bytes c's kernel still holds unacknowledged
// (SIOCOUTQ: unsent + unacked, including a pending FIN).
func sendQueueLen(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var n int32
	var ierr syscall.Errno
	rc.Control(func(fd uintptr) {
		_, _, ierr = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCOUTQ, uintptr(unsafe.Pointer(&n)))
	})
	if ierr != 0 {
		t.Fatalf("SIOCOUTQ: %v", ierr)
	}
	return int(n)
}

// The backend sends its whole response + FIN and closes while the client is
// still sending: the backend's socket answers the client's later bytes with
// an RST, so nvelox's writes toward it fail (EPIPE/ECONNRESET). That must NOT
// cut the response nvelox already holds for the client.
func TestRelayL4_ClientKeepsSendingAfterBackendClosed(t *testing.T) {
	f := startRelayRcvBuf(t, 0, 4096)
	// Small enough that the backend's kernel can hand ALL of it (and the FIN)
	// to nvelox while the client reads nothing — even with stock 16 KiB/128 KiB
	// socket buffer defaults — yet far more than the client's 4 KiB window, so
	// most of it is still inside nvelox when the client sends more. (Bytes
	// still in the BACKEND's own send queue would be discarded by the
	// backend's kernel when it resets; no proxy can deliver those.)
	resp := bytes.Repeat([]byte("R"), 48*1024)
	req := []byte("REQ")
	backendClosed := make(chan error, 1)
	go func() {
		b := make([]byte, len(req))
		if _, err := io.ReadFull(f.backend, b); err != nil {
			backendClosed <- err
			return
		}
		f.backend.Write(resp)
		f.backend.CloseWrite()
		deadline := time.Now().Add(3 * time.Second)
		for q := sendQueueLen(t, f.backend); q > 0; q = sendQueueLen(t, f.backend) {
			if time.Now().After(deadline) {
				backendClosed <- fmt.Errorf("backend send queue never drained into nvelox (%d bytes left)", q)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		backendClosed <- f.backend.Close() // full close: later client bytes get an RST
	}()
	f.client.Write(req)
	if err := <-backendClosed; err != nil {
		t.Fatalf("backend: %v", err)
	}
	// Keep sending while NOT reading yet: the first bytes reach the closed
	// backend, which resets; later writes fail inside nvelox.
	for i := 0; i < 20; i++ {
		f.client.Write(bytes.Repeat([]byte("x"), 1024))
		time.Sleep(5 * time.Millisecond)
	}
	got, err := readAllWithin(t, f.client, 5*time.Second)
	if err != nil || len(got) != len(resp) {
		t.Fatalf("client got %d/%d response bytes, err=%v", len(got), len(resp), err)
	}
	f.client.Close()
	f.wait(t, 2*time.Second)
}

// A backend RST aborts the client side immediately (no hang).
func TestRelayL4_BackendResetAborts(t *testing.T) {
	f := startRelay(t, 0)
	f.client.Write([]byte("hi"))
	b := make([]byte, 2)
	io.ReadFull(f.backend, b)
	f.backend.SetLinger(0)
	f.backend.Close()
	r := f.wait(t, 2*time.Second)
	if r.Err == nil || !(errors.Is(r.Err, syscall.ECONNRESET) || errors.Is(r.Err, syscall.EPIPE)) {
		t.Fatalf("relay error = %v, want a reset", r.Err)
	}
	if _, err := readAllWithin(t, f.client, 2*time.Second); isTimeout(err) {
		t.Fatal("client not released after backend reset")
	}
}

func TestReadInboundProxyV2(t *testing.T) {
	realClient := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4242}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}
	var hdr bytes.Buffer
	if _, err := proxyproto.HeaderProxyFromAddrs(2, realClient, dst).WriteTo(&hdr); err != nil {
		t.Fatal(err)
	}

	t.Run("header split across writes, payload kept", func(t *testing.T) {
		a, b := tcpPair(t)
		go func() {
			raw := hdr.Bytes()
			a.Write(raw[:5])
			time.Sleep(20 * time.Millisecond)
			a.Write(append(append([]byte{}, raw[5:]...), "payload"...))
		}()
		src, pending, err := readInboundProxyV2(b, b.RemoteAddr(), time.Second)
		if err != nil || src.String() != realClient.String() || string(pending) != "payload" {
			t.Fatalf("src=%v pending=%q err=%v", src, pending, err)
		}
	})
	t.Run("raw stream falls back to peer, bytes intact", func(t *testing.T) {
		a, b := tcpPair(t)
		a.Write([]byte("\x16\x03\x01hello"))
		src, pending, err := readInboundProxyV2(b, b.RemoteAddr(), time.Second)
		if err != nil || src.String() != b.RemoteAddr().String() || string(pending) != "\x16\x03\x01hello" {
			t.Fatalf("src=%v pending=%q err=%v", src, pending, err)
		}
	})
	t.Run("incomplete header times out to peer, bytes intact", func(t *testing.T) {
		a, b := tcpPair(t)
		a.Write(hdr.Bytes()[:10])
		src, pending, err := readInboundProxyV2(b, b.RemoteAddr(), 100*time.Millisecond)
		if err != nil || src.String() != b.RemoteAddr().String() || !bytes.Equal(pending, hdr.Bytes()[:10]) {
			t.Fatalf("src=%v pending=%q err=%v", src, pending, err)
		}
		// The read deadline must be cleared for the relay afterwards.
		go a.Write([]byte("z"))
		one := make([]byte, 1)
		if _, err := b.Read(one); err != nil {
			t.Fatalf("conn unusable after header wait: %v", err)
		}
	})
}
