//go:build linux

package core

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nvelox/ngx/relay"

	"nvelox/config"
	"nvelox/core/logging"
)

// The relay tests of relay_test.go, run through an engine whose plain TCP
// listener is served by the event loops (l4fast.go, with the relay of the
// ngx module).

type l4Fixture struct {
	client  *net.TCPConn
	backend *net.TCPConn
	logPath string
}

func startL4Fast(t *testing.T, idle string, clientRcvBuf int) *l4Fixture {
	t.Helper()
	if !l4FastEnabled() {
		t.Skip("event-loop relay off")
	}
	logPath := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("warning", logPath, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logging.Init("warning", "", "") })
	beLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { beLn.Close() })
	addr := stFreeTCPAddr(t)
	cfg := &config.Config{
		Listeners: []config.Listener{{Name: "l4", Bind: addr, Protocol: "tcp", Backend: "be", Timeouts: config.TimeoutConfig{Idle: idle}}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{beLn.Addr().String()}}},
	}
	e := stStart(t, cfg, nil)
	if len(e.l4Fast) != 1 {
		t.Fatalf("listener not on the event loops (%d)", len(e.l4Fast))
	}
	dialer := net.Dialer{}
	if clientRcvBuf > 0 {
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, clientRcvBuf)
			})
		}
	}
	c, err := dialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	beLn.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	b, err := beLn.Accept()
	if err != nil {
		t.Fatalf("backend accept: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return &l4Fixture{client: c.(*net.TCPConn), backend: b.(*net.TCPConn), logPath: logPath}
}

// ended waits for the session's L4 access record and returns it.
func (f *l4Fixture) ended(t *testing.T, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		data, _ := os.ReadFile(f.logPath)
		if s := strings.TrimSpace(string(data)); s != "" {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("session still running after %v", within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *l4Fixture) running(t *testing.T) bool {
	t.Helper()
	data, _ := os.ReadFile(f.logPath)
	return strings.TrimSpace(string(data)) == ""
}

func TestL4Fast_BackendFINFirst_HalfClosesOnly(t *testing.T) {
	f := startL4Fast(t, "0", 0)
	body := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	go func() {
		f.backend.Write(body)
		f.backend.CloseWrite()
	}()
	time.Sleep(100 * time.Millisecond)
	got, err := readAllWithin(t, f.client, 5*time.Second)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("client got %d/%d bytes, err=%v", len(got), len(body), err)
	}
	if _, err := f.client.Write([]byte("still-here")); err != nil {
		t.Fatalf("client write after backend FIN: %v", err)
	}
	f.client.CloseWrite()
	tail, err := readAllWithin(t, f.backend, 2*time.Second)
	if err != nil || string(tail) != "still-here" {
		t.Fatalf("backend got %q (err %v), want \"still-here\" then EOF", tail, err)
	}
	if rec := f.ended(t, 2*time.Second); !strings.Contains(rec, " l4 tcp/") || !strings.Contains(rec, " ok ") {
		t.Fatalf("access record %q", rec)
	}
}

func TestL4Fast_IdleCountsBothDirections(t *testing.T) {
	const idle = 500 * time.Millisecond
	f := startL4Fast(t, "500ms", 0)
	got := make(chan []byte, 1)
	go func() {
		b, _ := readAllWithin(t, f.backend, 5*time.Second)
		got <- b
	}()
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
	f.backend.Write([]byte("ok"))
	f.backend.CloseWrite()
	if b, err := readAllWithin(t, f.client, 2*time.Second); err != nil || string(b) != "ok" {
		t.Fatalf("client got %q err %v, want \"ok\"", b, err)
	}
	f.ended(t, 2*time.Second)
}

func TestL4Fast_HalfClosedIdleTimeout(t *testing.T) {
	f := startL4Fast(t, "250ms", 0)
	f.backend.Write([]byte("bye"))
	f.backend.CloseWrite()
	if b, err := readAllWithin(t, f.client, 2*time.Second); err != nil || string(b) != "bye" {
		t.Fatalf("client got %q err %v", b, err)
	}
	start := time.Now()
	f.ended(t, 3*time.Second)
	if el := time.Since(start); el > 250*time.Millisecond+time.Second {
		t.Fatalf("half-closed session lingered %v", el)
	}
}

func TestL4Fast_IdleDisabled(t *testing.T) {
	f := startL4Fast(t, "0", 0)
	time.Sleep(300 * time.Millisecond)
	if !f.running(t) {
		t.Fatal("session ended without traffic and without idle timeout")
	}
	f.client.Close()
	f.backend.Close()
	f.ended(t, 2*time.Second)
}

func TestL4Fast_StalledWriterAborts(t *testing.T) {
	f := startL4Fast(t, "300ms", 4096)
	f.client.CloseWrite()
	go func() {
		chunk := make([]byte, 1<<20)
		for {
			f.backend.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := f.backend.Write(chunk); err != nil {
				return
			}
		}
	}()
	f.ended(t, 10*time.Second)
}

// A client that reads nothing does not keep its session by sending a byte
// now and then: what the session holds for it (output that waits, the
// kernel's buffers, a place among the backend's connections) is given up
// when it has not taken that output for the idle time, as a write that
// times out ends a session of the goroutine relay.
func TestL4Fast_PeerThatReadsNothingButSendsIsCutOff(t *testing.T) {
	const idle = 400 * time.Millisecond
	f := startL4Fast(t, "400ms", 4096)
	go io.Copy(io.Discard, f.backend) // the backend takes what the client sends
	go func() {
		chunk := make([]byte, 1<<20)
		for {
			f.backend.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := f.backend.Write(chunk); err != nil {
				return
			}
		}
	}()
	start := time.Now()
	for {
		// Five times in every idle period: the session is not idle.
		if _, err := f.client.Write([]byte{'x'}); err != nil {
			break
		}
		if time.Since(start) > 6*time.Second {
			t.Fatalf("a client that reads nothing kept its session for %v by sending a byte now and then", time.Since(start).Round(time.Millisecond))
		}
		time.Sleep(idle / 5)
	}
	f.ended(t, 2*time.Second)
}

// Output that the client takes in time does not end the session, however
// often it has to wait: the idle time is for each piece that waits, from
// when it began to wait, and is over when the client has taken it. (A
// piece waits until the client's socket has room again, which the kernel
// says when a third of its buffer is free: megabytes on a tuned host.)
func TestL4Fast_ReaderThatPausesKeepsItsSession(t *testing.T) {
	const idle = 500 * time.Millisecond
	f := startL4Fast(t, "500ms", 0)
	const size = 64 << 20
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		chunk := make([]byte, 1<<20)
		for sent := 0; sent < size; sent += len(chunk) {
			f.backend.SetWriteDeadline(time.Now().Add(20 * time.Second))
			if _, err := f.backend.Write(chunk); err != nil {
				return
			}
		}
		// Then a byte now and then: the session is not idle.
		for {
			select {
			case <-stop:
				return
			case <-time.After(idle / 10):
			}
			if _, err := f.backend.Write([]byte{'.'}); err != nil {
				return
			}
		}
	}()
	// The client reads four megabytes, pauses for a fifth of the idle
	// time, and so on: output waits for it again and again, never long.
	buf := make([]byte, 64<<10)
	start := time.Now()
	got, burst := 0, 0
	for got < size {
		f.client.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := f.client.Read(buf)
		if err != nil {
			t.Fatalf("after %d of %d bytes and %v: %v (a session whose output is taken was ended)", got, size, time.Since(start).Round(time.Millisecond), err)
		}
		got += n
		if burst += n; burst >= 4<<20 {
			burst = 0
			time.Sleep(idle / 5)
		}
	}
	if el := time.Since(start); el < 3*idle {
		t.Fatalf("the client read everything in %v: the test needs it to take more than three idle periods", el)
	}
	// Nothing waits any more, for three idle periods and more: the wait
	// that is over counts for nothing.
	for until := time.Now().Add(3*idle + idle/2); time.Now().Before(until); {
		f.client.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := f.client.Read(buf); err != nil {
			t.Fatalf("%v after the last of the output was taken: %v", time.Since(start).Round(time.Millisecond), err)
		}
	}
	if !f.running(t) {
		t.Fatal("the session ended")
	}
}

func TestL4Fast_ClientKeepsSendingAfterBackendClosed(t *testing.T) {
	f := startL4Fast(t, "0", 4096)
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
				backendClosed <- io.ErrShortWrite
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		backendClosed <- f.backend.Close()
	}()
	f.client.Write(req)
	if err := <-backendClosed; err != nil {
		t.Fatalf("backend: %v", err)
	}
	for i := 0; i < 20; i++ {
		f.client.Write(bytes.Repeat([]byte("x"), 1024))
		time.Sleep(5 * time.Millisecond)
	}
	got, err := readAllWithin(t, f.client, 5*time.Second)
	if err != nil || len(got) != len(resp) {
		t.Fatalf("client got %d/%d response bytes, err=%v", len(got), len(resp), err)
	}
	f.client.Close()
	f.ended(t, 2*time.Second)
}

func TestL4Fast_BackendResetAborts(t *testing.T) {
	f := startL4Fast(t, "0", 0)
	f.client.Write([]byte("hi"))
	b := make([]byte, 2)
	io.ReadFull(f.backend, b)
	f.backend.SetLinger(0)
	f.backend.Close()
	f.ended(t, 2*time.Second)
	if _, err := readAllWithin(t, f.client, 2*time.Second); isTimeout(err) {
		t.Fatal("client not released after backend reset")
	}
}

func TestL4Fast_DeadBackendNoRoute(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("warning", logPath, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logging.Init("warning", "", "") })
	dead := stFreeTCPAddr(t)
	addr := stFreeTCPAddr(t)
	cfg := &config.Config{
		Listeners: []config.Listener{{Name: "l4", Bind: addr, Protocol: "tcp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{dead}}},
	}
	stStart(t, cfg, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("client not closed after a failed dial: %v", err)
	}
	f := &l4Fixture{logPath: logPath}
	if rec := f.ended(t, 2*time.Second); !strings.Contains(rec, " no_route ") {
		t.Fatalf("access record %q", rec)
	}
}

// A client the listener refuses is listed for the dynamic denylist only
// while it is checked: nothing is left behind (the engine's open-session
// set, its connection count) and its access record says why.
func TestL4Fast_RefusedClientLeavesNoSession(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("warning", logPath, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logging.Init("warning", "", "") })
	beLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { beLn.Close() })
	addr := stFreeTCPAddr(t)
	cfg := &config.Config{
		Listeners: []config.Listener{{Name: "l4", Bind: addr, Protocol: "tcp", Backend: "be", IPDenylist: []string{"127.0.0.0/8"}}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{beLn.Addr().String()}}},
	}
	e := stStart(t, cfg, nil)
	if len(e.l4Fast) != 1 {
		t.Fatalf("listener not on the event loops (%d)", len(e.l4Fast))
	}
	for i := 0; i < 20; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Fatalf("refused client not closed: %v", err)
		}
		c.Close()
	}
	f := &l4Fixture{logPath: logPath}
	if rec := f.ended(t, 2*time.Second); !strings.Contains(rec, " "+l4StatusRefused+" ") {
		t.Fatalf("access record %q", rec)
	}
	n := 0
	e.l4Conns.Range(func(any, any) bool { n++; return true })
	if n != 0 {
		t.Fatalf("%d refused sessions still listed", n)
	}
}

// The L4 error-log lines name the backend address in a dial error and the
// client's address with its port, as the goroutine relay's do.
func TestL4Fast_LogLinesNameAddresses(t *testing.T) {
	dir := t.TempDir()
	errPath := filepath.Join(dir, "error.log")
	if err := logging.Init("info", filepath.Join(dir, "access.log"), errPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logging.Init("warning", "", "") })
	dead := stFreeTCPAddr(t)
	addr := stFreeTCPAddr(t)
	cfg := &config.Config{
		Listeners: []config.Listener{{Name: "l4", Bind: addr, Protocol: "tcp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{dead}}},
	}
	e := stStart(t, cfg, nil)
	if len(e.l4Fast) != 1 {
		t.Fatalf("listener not on the event loops (%d)", len(e.l4Fast))
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	local := c.LocalAddr().String()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	c.Read(make([]byte, 1))
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, _ := os.ReadFile(errPath)
		s := string(b)
		if strings.Contains(s, "Backend TCP dial failed: dial tcp "+dead+": connect: connection refused") && strings.Contains(s, "[CONN] Closed "+local+" ") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("error log lacks the addresses (want %s and %s):\n%s", dead, local, s)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A session with more to relay than one turn (relay.TCPRound) gives way to
// the loop's other sessions and goes on after them: a long transfer in both
// directions at once arrives whole and in order.
func TestL4Fast_LongRelayTakesTurns(t *testing.T) {
	f := startL4Fast(t, "0", 0)
	pattern := func(n int, seed byte) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*7) ^ seed
		}
		return b
	}
	down, up := pattern(24*relay.TCPRound+12345, 0x5a), pattern(8*relay.TCPRound+321, 0xa5)
	go func() {
		f.backend.Write(down)
		f.backend.CloseWrite()
	}()
	go func() {
		f.client.Write(up)
		f.client.CloseWrite()
	}()
	gotUp := make(chan []byte, 1)
	go func() {
		b, _ := readAllWithin(t, f.backend, 30*time.Second)
		gotUp <- b
	}()
	gotDown, err := readAllWithin(t, f.client, 30*time.Second)
	if err != nil || !bytes.Equal(gotDown, down) {
		t.Fatalf("to the client: %d of %d bytes, err=%v", len(gotDown), len(down), err)
	}
	if b := <-gotUp; !bytes.Equal(b, up) {
		t.Fatalf("to the backend: %d of %d bytes", len(b), len(up))
	}
	if rec := f.ended(t, 5*time.Second); !strings.Contains(rec, " ok ") {
		t.Fatalf("access record %q", rec)
	}
}

// A session that is over is not among the engine's connections any more:
// the engine stops without waiting for it, whether the session was relayed
// or never reached its backend.
func TestL4Fast_EndedSessionsAreNotWaitedFor(t *testing.T) {
	if !l4FastEnabled() {
		t.Skip("event-loop relay off")
	}
	quiet := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("warning", quiet, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logging.Init("warning", "", "") })
	beLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { beLn.Close() })
	go func() {
		for {
			c, err := beLn.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	addr, deadAddr := stFreeTCPAddr(t), stFreeTCPAddr(t)
	cfg := &config.Config{Version: "2",
		Listeners: []config.Listener{
			{Name: "l4", Bind: addr, Protocol: "tcp", Backend: "be"},
			{Name: "l4-dead", Bind: deadAddr, Protocol: "tcp", Backend: "gone"}},
		Backends: []config.Backend{
			{Name: "be", Servers: []string{beLn.Addr().String()}},
			{Name: "gone", Servers: []string{stFreeTCPAddr(t)}}},
	}
	exp, err := ExpandListeners(cfg.Listeners)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(cfg)
	e.Listeners = exp
	e.DrainTimeout = 6 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Start(ctx) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	waitTCP(t, addr)
	waitTCP(t, deadAddr)
	// A session that is relayed and ended by its client, and one whose
	// backend is not there.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("ping"))
	if _, err := io.ReadFull(c, make([]byte, 4)); err != nil {
		t.Fatalf("the echo through the relay: %v", err)
	}
	c.Close()
	d, err := net.Dial("tcp", deadAddr)
	if err != nil {
		t.Fatal(err)
	}
	d.SetReadDeadline(time.Now().Add(5 * time.Second))
	d.Read(make([]byte, 1))
	d.Close()
	// Both are over when the engine lists no connection.
	listed := func() (n int) {
		e.l4Conns.Range(func(any, any) bool { n++; return true })
		return n
	}
	for deadline := time.Now().Add(5 * time.Second); listed() != 0; {
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions still listed after their connections were closed", listed())
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	cancel()
	select {
	case <-done:
		stopped = true
	case <-time.After(15 * time.Second):
		t.Fatal("the engine did not stop")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the engine took %v to stop with no session open: sessions that were over were still counted", took.Round(time.Millisecond))
	}
}
