package core

import (
	"net"
	"testing"
	"time"

	"nvelox/config"
)

// UDP behaviour that both engines share and no other test pins down.

// An empty datagram starts a session and is not relayed, and neither is an
// empty reply.
func TestUDP_EmptyDatagrams(t *testing.T) { stUDPEngines(t, udpTestUDP_EmptyDatagrams) }

func udpTestUDP_EmptyDatagrams(t *testing.T) {
	be, got := stUDPBackend(t, func(d []byte) []byte {
		if string(d) == "answer with nothing" {
			return []byte{}
		}
		return d
	})
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "empty", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(nil); err != nil {
		t.Fatal(err)
	}
	if d, ok := stWaitGot(got, 300*time.Millisecond); ok {
		t.Fatalf("an empty datagram reached the backend: %q", d)
	}
	waitFor(t, "the empty datagram's session", func() bool { return len(stUDPSessions(e)) == 1 })

	// The same session relays what follows.
	c.Write([]byte("answer with nothing"))
	if d, ok := stWaitGot(got, 2*time.Second); !ok || string(d) != "answer with nothing" {
		t.Fatalf("backend got %q (ok=%v)", d, ok)
	}
	buf := make([]byte, 64)
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("the backend's empty reply was relayed (%d bytes)", n)
	}
	// The session is still the same one, and relays the next exchange.
	c.Write([]byte("echo me"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "echo me" {
		t.Fatalf("after the empty reply: %q, %v", buf[:n], err)
	}
	if n := len(stUDPSessions(e)); n != 1 {
		t.Fatalf("%d sessions, want the one", n)
	}
}

// A backend that goes away: its port answers with a refusal, and the
// session ends with it instead of waiting out its idle time.
func TestUDP_BackendPortClosed(t *testing.T) { stUDPEngines(t, udpTestUDP_BackendPortClosed) }

func udpTestUDP_BackendPortClosed(t *testing.T) {
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "down", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{backend.LocalAddr().String()}}},
	}, nil)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The session is there once the backend has its first datagram.
	c.Write([]byte("one"))
	buf := make([]byte, 16)
	backend.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := backend.ReadFromUDP(buf); err != nil || string(buf[:n]) != "one" {
		t.Fatalf("backend got %q, %v", buf[:n], err)
	}
	if n := len(stUDPSessions(e)); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
	// The backend goes away; the next datagram is refused.
	backend.Close()
	c.Write([]byte("two"))
	waitFor(t, "the session to end after the backend's refusal", func() bool { return len(stUDPSessions(e)) == 0 })
	if total, _ := stHandler(e).udpSessions.count(addrKey(net.ParseIP("127.0.0.1"))); total != 0 {
		t.Fatalf("%d session slots still held", total)
	}
}

// A relay's datagram that is all header (no payload) reaches the backend as
// an empty datagram.
func TestUDP_RelayedEmptyPayload(t *testing.T) { stUDPEngines(t, udpTestUDP_RelayedEmptyPayload) }

func udpTestUDP_RelayedEmptyPayload(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-empty", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(stUDPDatagramWithProxy(t, "198.51.100.30:4000", addr, []byte("first")))
	if d, ok := stWaitGot(got, 2*time.Second); !ok || string(d) != "first" {
		t.Fatalf("backend got %q (ok=%v), want the payload", d, ok)
	}
	c.Write(stUDPDatagramWithProxy(t, "198.51.100.30:4000", addr, nil))
	if d, ok := stWaitGot(got, 2*time.Second); !ok || len(d) != 0 {
		t.Fatalf("backend got %q (ok=%v), want an empty datagram", d, ok)
	}
}
