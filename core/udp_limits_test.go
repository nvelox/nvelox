package core

// H9 / M1: UDP sessions are bounded (global and per-client caps, a short TTL
// for sessions the backend never answered), a failure inside OnOpen never
// closes synchronously (that deadlocked the nbio poller), and a trusted
// relay's datagram without a PROXY v2 header is dropped.

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"nvelox/config"
)

// H9b regression: with no healthy backend server, OnOpen used to close the new
// client conn synchronously while nbio held the UDP listener's mutex — the
// poller deadlocked on the first such datagram and every UDP listener on it
// stayed dead until a restart. Now: refuse that client, and serve the next
// one once a server is back.
func TestUDP_NoHealthyServerDoesNotWedgePoller(t *testing.T) {
	echo, _ := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "u", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{echo}}},
	}, nil)

	if reply, err := stUDPExchange("127.0.0.1", addr, []byte("ping-1"), 2*time.Second); err != nil || string(reply) != "ping-1" {
		t.Fatalf("control round trip: reply=%q err=%v", reply, err)
	}

	bal := e.Balancers["be"]
	bal.UpdateStatus(echo, false) // health check marks the only server down
	if reply, err := stUDPExchange("127.0.0.1", addr, []byte("ping-2"), 500*time.Millisecond); err == nil {
		t.Fatalf("no healthy server: got a reply %q", reply)
	}

	bal.UpdateStatus(echo, true) // server back
	for i := 0; i < 3; i++ {
		reply, err := stUDPExchange("127.0.0.1", addr, []byte("ping-3"), 2*time.Second)
		if err != nil || string(reply) != "ping-3" {
			t.Fatalf("new client after the server came back: reply=%q err=%v (poller wedged?)", reply, err)
		}
	}
	// The refused session released everything it took: 4 live sessions
	// remain (ping-1 and the three ping-3 ones).
	h := stHandler(e)
	lo := netip.MustParseAddr("127.0.0.1")
	waitFor(t, "the refused session's slot released", func() bool {
		total, forIP := h.udpSessions.count(lo)
		return total == 4 && forIP == 4
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// H9a: a global session cap and a per-client-IP cap; a refused source gets
// nothing, and its datagram never reaches the backend.
func TestUDP_SessionLimits(t *testing.T) {
	be, got := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "u", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, func(e *Engine) {
		e.udpMaxSessions = 3
		e.udpMaxSessionsPerIP = 2
	})
	h := stHandler(e)

	exchange := func(src, payload string) bool {
		reply, err := stUDPExchange(src, addr, []byte(payload), 700*time.Millisecond)
		return err == nil && string(reply) == payload
	}
	if !exchange("127.0.0.1", "a1") || !exchange("127.0.0.1", "a2") {
		t.Fatal("first two sessions from 127.0.0.1 must be served")
	}
	stDrain(got)
	if exchange("127.0.0.1", "a3") {
		t.Fatal("third session from 127.0.0.1 exceeds the per-client cap (2) but was served")
	}
	if d, ok := stWaitGot(got, 200*time.Millisecond); ok {
		t.Fatalf("refused session reached the backend: %q", d)
	}
	if !exchange("127.0.0.2", "b1") {
		t.Fatal("another client must still be served below the global cap")
	}
	stDrain(got)
	if exchange("127.0.0.3", "c1") {
		t.Fatal("fourth session exceeds the global cap (3) but was served")
	}
	if d, ok := stWaitGot(got, 200*time.Millisecond); ok {
		t.Fatalf("refused session reached the backend: %q", d)
	}
	total, forA := h.udpSessions.count(netip.MustParseAddr("127.0.0.1"))
	if total != 3 || forA != 2 {
		t.Fatalf("session counts: total=%d for 127.0.0.1=%d, want 3 and 2", total, forA)
	}
}

// H9a: a session whose backend never answers ends after the no-reply TTL and
// frees its slot; one the backend answered keeps the idle timeout.
func TestUDP_NoReplyTTL(t *testing.T) {
	sink, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "u", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{sink}}},
	}, func(e *Engine) {
		e.udpNoReplyTimeout = 300 * time.Millisecond
		e.udpMaxSessions = 1
	})
	h := stHandler(e)

	start := time.Now()
	stUDPExchange("127.0.0.1", addr, []byte("one-shot"), 50*time.Millisecond)
	if _, ok := stWaitGot(got, time.Second); !ok {
		t.Fatal("backend never got the datagram")
	}
	if total, _ := h.udpSessions.count(netip.Addr{}); total != 1 {
		t.Fatalf("live sessions = %d, want 1", total)
	}
	waitFor(t, "no-reply session to expire", func() bool { total, _ := h.udpSessions.count(netip.Addr{}); return total == 0 })
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("session lived %v, want about the no-reply TTL", d)
	}
	// The slot is free again (cap 1): a new source is served.
	stUDPExchange("127.0.0.2", addr, []byte("next"), 50*time.Millisecond)
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "next" {
		t.Fatalf("new session after expiry: backend got %q (ok=%v)", d, ok)
	}
}

// A backend reply up to the max UDP payload is relayed whole (the read buffer
// is now borrowed from a pool per reply instead of held per session).
func TestUDP_LargeReplyRelayedWhole(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789abcdef"), 60000/16)
	be, _ := stUDPBackend(t, func([]byte) []byte { return big })
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "u", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	for i := 0; i < 3; i++ {
		reply, err := stUDPExchange("127.0.0.1", addr, []byte("q"), 2*time.Second)
		if err != nil || !bytes.Equal(reply, big) {
			t.Fatalf("reply %d: %d bytes (err=%v), want %d intact", i, len(reply), err, len(big))
		}
	}
}

// M1: on a listener with accept_proxy_from, a datagram from a trusted relay
// must name its client in a PROXY v2 header; one without (or with a LOCAL /
// malformed header, or naming another client than the session's) is dropped
// instead of being forwarded with no client to check or log.
func TestUDP_TrustedRelayDatagramWithoutHeaderDropped(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)

	raddr, _ := net.ResolveUDPAddr("udp", addr)
	relay, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	send := func(b []byte) {
		t.Helper()
		if _, err := relay.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	expectNothing := func(what string) {
		t.Helper()
		if d, ok := stWaitGot(got, 300*time.Millisecond); ok {
			t.Fatalf("%s was forwarded: %q", what, d)
		}
	}

	send([]byte("raw-first"))
	expectNothing("raw datagram from a trusted relay")
	local := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x20, 0x00, 0x00, 0x00}
	send(append(local, []byte("local-cmd")...))
	expectNothing("LOCAL-header datagram")

	send(stUDPDatagramWithProxy(t, "198.51.100.10:7000", addr, []byte("with-header")))
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "with-header" {
		t.Fatalf("datagram with a valid header: backend got %q (ok=%v)", d, ok)
	}
	send([]byte("raw-later"))
	expectNothing("raw datagram on an established relay session")
	send(stUDPDatagramWithProxy(t, "198.51.100.99:7000", addr, []byte("other-client")))
	expectNothing("datagram naming another client than the session's")
	send(stUDPDatagramWithProxy(t, "198.51.100.10:7000", addr, []byte("same-client")))
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "same-client" {
		t.Fatalf("next datagram of the session: backend got %q (ok=%v)", d, ok)
	}
}

// Behind a trusted relay the per-client cap counts the client the PROXY header
// names, not the relay (all relayed clients share the relay's address).
func TestUDP_TrustedRelayPerClientCap(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, func(e *Engine) { e.udpMaxSessionsPerIP = 1 })

	relayed := func(client, payload string) {
		t.Helper()
		stUDPExchange("127.0.0.1", addr, stUDPDatagramWithProxy(t, client, addr, []byte(payload)), 50*time.Millisecond)
	}
	relayed("198.51.100.20:1000", "x-1")
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "x-1" {
		t.Fatalf("first session of client X: backend got %q (ok=%v)", d, ok)
	}
	relayed("198.51.100.20:1001", "x-2") // same client IP, new relay socket
	if d, ok := stWaitGot(got, 300*time.Millisecond); ok {
		t.Fatalf("second session of client X over the per-client cap was forwarded: %q", d)
	}
	relayed("198.51.100.21:1000", "y-1") // another client through the same relay address
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "y-1" {
		t.Fatalf("client Y behind the same relay: backend got %q (ok=%v)", d, ok)
	}
}

func TestUDPSessionLimiter(t *testing.T) {
	s := newUDPSessionLimiter(3, 2)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	for i, want := range []string{"", "", udpDropSourceLimit} {
		if got := s.acquire(a); got != want {
			t.Fatalf("acquire %d for a: %q, want %q", i, got, want)
		}
	}
	if got := s.acquire(netip.Addr{}); got != "" { // an address that cannot be keyed
		t.Fatalf("acquire without ip: %q", got)
	}
	if got := s.acquire(b); got != udpDropSessionLimit {
		t.Fatalf("acquire over the global cap: %q", got)
	}
	s.release(netip.Addr{})
	if got := s.acquire(b); got != "" {
		t.Fatalf("acquire for b after a release: %q", got)
	}
	s.release(a)
	s.release(a)
	s.release(b)
	if total, forA := s.count(a); total != 0 || forA != 0 {
		t.Fatalf("after release: total=%d a=%d", total, forA)
	}
	if len(s.perIP) != 0 {
		t.Fatalf("per-IP map not emptied: %v", s.perIP)
	}
	// IPv4-mapped addresses fold onto the IPv4 key.
	if addrKey(net.ParseIP("::ffff:192.0.2.1")) != a || addrKey(nil).IsValid() {
		t.Fatal("addrKey normalisation")
	}
}

// TestUDP_ForgedRelaySourcesHoldNothing (H5): datagrams from a trusted relay
// address without a valid PROXY header — what a source forged to look like
// the relay sends — used to open sessions that held a session slot and a
// backend max_connections slot for udpNoReplyTimeout (10 s) before their
// header was checked. They now end at the first datagram and hold nothing,
// so a real relayed client still gets in at once.
func TestUDP_ForgedRelaySourcesHoldNothing(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}, MaxConnections: 1}},
	}, func(e *Engine) { e.udpMaxSessions = 2 })

	raddr, _ := net.ResolveUDPAddr("udp", addr)
	for i := 0; i < 5; i++ {
		forged, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := forged.Write([]byte("no-header")); err != nil {
			t.Fatal(err)
		}
		forged.Close()
	}
	if d, ok := stWaitGot(got, 300*time.Millisecond); ok {
		t.Fatalf("a datagram without a header was forwarded: %q", d)
	}
	stUDPExchange("127.0.0.1", addr, stUDPDatagramWithProxy(t, "198.51.100.30:4000", addr, []byte("real-client")), 50*time.Millisecond)
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "real-client" {
		t.Fatalf("relayed client after forged relay datagrams: backend got %q (ok=%v); the forged sessions still hold the caps", d, ok)
	}
}
