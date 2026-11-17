package core

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"nvelox/config"
)

// The UDP listener sockets read by goroutines (udpsock.go): what that path
// does on its own account. What it shares with the event loops is tested
// through stUDPEngines.

// stSocketsOnly runs the test on the socket path, whatever the platform has.
func stSocketsOnly(t *testing.T) {
	t.Helper()
	udpFastOff.Store(true)
	t.Cleanup(func() { udpFastOff.Store(false) })
}

// stOnlyCtx returns the one live session of e.
func stOnlyCtx(t *testing.T, e *Engine) *ConnContext {
	t.Helper()
	var all []*ConnContext
	stHandler(e).sessions.Range(func(_, v any) bool {
		all = append(all, v.(*ConnContext))
		return true
	})
	if len(all) != 1 {
		t.Fatalf("%d sessions, want the one", len(all))
	}
	return all[0]
}

// A session whose client stays silent for the read timeout ends and gives
// its slot back, although its backend answered (so the backend's own idle
// timeout is a minute away); the same client starts a new session with its
// next datagram. A client that keeps sending keeps its session.
func TestUDPSock_SilentClientEndsAndComesBack(t *testing.T) {
	stSocketsOnly(t)
	be, _ := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "u", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, func(e *Engine) { e.udpClientReadTimeout = 400 * time.Millisecond })
	h := stHandler(e)

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echo := func(msg string) {
		t.Helper()
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != msg {
			t.Fatalf("echo of %q: %q, %v", msg, buf[:n], err)
		}
	}

	// A client that sends every 100 ms keeps the one session for a second.
	echo("first")
	first := stOnlyCtx(t, e)
	for i := 0; i < 10; i++ {
		time.Sleep(100 * time.Millisecond)
		echo("again")
	}
	if got := stOnlyCtx(t, e); got != first {
		t.Fatal("the session of a client that kept sending was replaced")
	}

	// Silent: the session ends and its slot is free.
	start := time.Now()
	waitFor(t, "the silent client's session to end", func() bool { return len(stUDPSessions(e)) == 0 })
	if d := time.Since(start); d < 250*time.Millisecond || d > 2*time.Second {
		t.Fatalf("the session ended after %v of silence, want about the read timeout (400ms)", d)
	}
	if total, _ := h.udpSessions.count(netip.Addr{}); total != 0 {
		t.Fatalf("%d session slots held after the session ended", total)
	}

	// The same client (same source port) is served again, by a new session.
	echo("back")
	if got := stOnlyCtx(t, e); got == first {
		t.Fatal("the ended session is in use again")
	}
}

// Stopping a socket ends its sessions: their slots are free and their
// backend sockets closed. A second stop does nothing.
func TestUDPSock_StopEndsSessions(t *testing.T) {
	stSocketsOnly(t)
	be, _ := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "u", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	h := stHandler(e)
	for _, src := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"} {
		if d, err := stUDPExchange(src, addr, []byte("hello"), 2*time.Second); err != nil || string(d) != "hello" {
			t.Fatalf("exchange from %s: %q, %v", src, d, err)
		}
	}
	if total, _ := h.udpSessions.count(netip.Addr{}); total != 3 {
		t.Fatalf("%d sessions, want 3", total)
	}
	if len(e.udpSocks) != 1 {
		t.Fatalf("%d listener sockets, want 1", len(e.udpSocks))
	}
	e.udpSocks[0].stop()
	if total, _ := h.udpSessions.count(netip.Addr{}); total != 0 {
		t.Fatalf("%d session slots held after the socket stopped", total)
	}
	if n := len(stUDPSessions(e)); n != 0 {
		t.Fatalf("%d sessions after the socket stopped", n)
	}
	e.udpSocks[0].stop()
}

// An IPv4 client of a listener bound to the IPv6 wildcard address is served,
// and named by its IPv4 address, on both UDP paths.
func TestUDP_WildcardListenerIPv4Client(t *testing.T) {
	stUDPEngines(t, udpTestUDP_WildcardListenerIPv4Client)
}

func udpTestUDP_WildcardListenerIPv4Client(t *testing.T) {
	probe, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		t.Skipf("no IPv6 wildcard socket here: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	be, _ := stUDPBackend(t, stEchoReply)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "any", Bind: net.JoinHostPort("::", strconv.Itoa(port)), Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	d, err := stUDPExchange("127.0.0.1", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), []byte("over v4"), 2*time.Second)
	if err != nil || string(d) != "over v4" {
		t.Fatalf("exchange: %q, %v", d, err)
	}
	ss := stUDPSessions(e)
	if len(ss) != 1 || ss[0].RealClientIP != "127.0.0.1" {
		t.Fatalf("sessions %+v, want one of client 127.0.0.1", ss)
	}
}

// An empty datagram on a session that already has its backend is not
// relayed either, and the session goes on.
func TestUDP_EmptyDatagramOnALiveSession(t *testing.T) {
	stUDPEngines(t, udpTestUDP_EmptyDatagramOnALiveSession)
}

func udpTestUDP_EmptyDatagramOnALiveSession(t *testing.T) {
	be, got := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "u", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 64)
	c.Write([]byte("one"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "one" {
		t.Fatalf("first exchange: %q, %v", buf[:n], err)
	}
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "one" {
		t.Fatalf("backend got %q (ok=%v)", d, ok)
	}
	if _, err := c.Write(nil); err != nil {
		t.Fatal(err)
	}
	if d, ok := stWaitGot(got, 300*time.Millisecond); ok {
		t.Fatalf("an empty datagram reached the backend: %q", d)
	}
	c.Write([]byte("two"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "two" {
		t.Fatalf("after the empty datagram: %q, %v", buf[:n], err)
	}
	if n := len(stUDPSessions(e)); n != 1 {
		t.Fatalf("%d sessions, want the one", n)
	}
}

// A client whose session was closed is served again with its next datagram,
// by a new session, on both UDP paths.
func TestUDP_ClosedSessionClientComesBack(t *testing.T) {
	stUDPEngines(t, udpTestUDP_ClosedSessionClientComesBack)
}

func udpTestUDP_ClosedSessionClientComesBack(t *testing.T) {
	be, _ := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "u", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echo := func(msg string) {
		t.Helper()
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != msg {
			t.Fatalf("echo of %q: %q, %v", msg, buf[:n], err)
		}
	}
	echo("one")
	ss := stUDPSessions(e)
	if len(ss) != 1 {
		t.Fatalf("%d sessions, want the one", len(ss))
	}
	ss[0].Close()
	waitFor(t, "the closed session to be gone", func() bool { return len(stUDPSessions(e)) == 0 })
	echo("two")
	if n := len(stUDPSessions(e)); n != 1 {
		t.Fatalf("%d sessions after the client came back, want 1", n)
	}
}

// A session that is closed once more after its client has started a new one
// (a reply reader that ends late) does not take the new session away.
func TestUDPSock_LateCloseOfAnOldSessionLeavesTheNewOne(t *testing.T) {
	stSocketsOnly(t)
	be, _ := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "u", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	h := stHandler(e)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echo := func(msg string) {
		t.Helper()
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != msg {
			t.Fatalf("echo of %q: %q, %v", msg, buf[:n], err)
		}
	}
	echo("one")
	old := stUDPSessions(e)
	if len(old) != 1 {
		t.Fatalf("%d sessions, want the one", len(old))
	}
	old[0].Close()
	waitFor(t, "the closed session to be gone", func() bool { return len(stUDPSessions(e)) == 0 })
	echo("two")
	second := stOnlyCtx(t, e)

	old[0].Close() // the old session, closed again
	echo("three")
	if got := stOnlyCtx(t, e); got != second {
		t.Fatal("the client's new session was replaced after the old one was closed again")
	}
	if total, _ := h.udpSessions.count(netip.Addr{}); total != 1 {
		t.Fatalf("%d session slots held, want 1", total)
	}
}
