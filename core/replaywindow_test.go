package core

// accept_proxy_replay_window through a running engine: a relay's header
// that carries a counter (signature version 2) is taken once per relay
// socket. A copy is dropped and counted as replayed, also once the session
// it began has ended; a copy from another port of the relay fails its
// signature; with "required" a header without a counter is refused.

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/config"
	"nvelox/proxy"
)

// signedUDPDatagramV2 is a datagram of the relay socket at relayPort: a
// header naming client for dst, signed with key in version 2 with counter,
// then payload.
func signedUDPDatagramV2(t *testing.T, key []byte, client, dst string, payload []byte, relayPort uint16, counter uint64) []byte {
	t.Helper()
	plain := stUDPDatagramWithProxy(t, client, dst, nil)
	signed, err := proxy.SignedHeaderBytesFrom(plain, key, payload, time.Now(), relayPort, counter)
	if err != nil {
		t.Fatal(err)
	}
	return append(signed, payload...)
}

// stRelaySocket is a socket of a relay sending to addr, and its port.
func stRelaySocket(t *testing.T, addr string) (*net.UDPConn, uint16) {
	t.Helper()
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, ra)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func stSend(t *testing.T, c *net.UDPConn, d []byte) {
	t.Helper()
	if _, err := c.Write(d); err != nil {
		t.Fatal(err)
	}
}

func TestReplayWindow_UDP(t *testing.T) { stUDPEngines(t, udpTestReplayWindow_UDP) }

func udpTestReplayWindow_UDP(t *testing.T) {
	be, got := stUDPBackend(t, nil) // no answers: a session ends after the no-reply timeout
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "replay-udp", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, func(e *Engine) { e.udpNoReplyTimeout = 300 * time.Millisecond })
	h := stHandler(e)
	replayed := e.Metrics.GetCounter("nvelox_udp_dropped_total", map[string]string{"reason": udpDropReplayed})
	badSig := e.Metrics.GetCounter("nvelox_udp_dropped_total", map[string]string{"reason": udpDropBadSignature})
	notForwarded := func(what string) {
		t.Helper()
		if b, ok := stWaitGot(got, 300*time.Millisecond); ok {
			t.Fatalf("%s was forwarded: %q", what, b)
		}
	}

	relay, port := stRelaySocket(t, addr)
	first := signedUDPDatagramV2(t, sigKeyA, "198.51.100.50:4000", addr, []byte("first"), port, 1000)
	stSend(t, relay, first)
	if b, ok := stWaitGot(got, time.Second); !ok || string(b) != "first" {
		t.Fatalf("the relay's datagram: backend got %q (ok=%v)", b, ok)
	}

	// A copy in the session the datagram began.
	before := replayed.Get()
	stSend(t, relay, first)
	notForwarded("a copy in its session")
	waitFor(t, "the copy counted as replayed", func() bool { return replayed.Get() == before+1 })

	// Once that session is over a copy would begin a new one: the relay
	// socket's window refuses it all the same.
	waitFor(t, "the session to end", func() bool { total, _ := h.udpSessions.count(netip.Addr{}); return total == 0 })
	stSend(t, relay, first)
	notForwarded("a copy after its session ended")
	waitFor(t, "the copy after the session counted as replayed", func() bool { return replayed.Get() == before+2 })

	// From another port the signature does not hold.
	beforeSig := badSig.Get()
	other, _ := stRelaySocket(t, addr)
	stSend(t, other, first)
	notForwarded("a copy from another port")
	waitFor(t, "the copy from another port counted as bad_signature", func() bool { return badSig.Get() == beforeSig+1 })

	// The relay's next datagrams pass, one of them out of order within the
	// window.
	for _, c := range []struct {
		counter uint64
		payload string
	}{{1002, "third"}, {1001, "second"}} {
		stSend(t, relay, signedUDPDatagramV2(t, sigKeyA, "198.51.100.50:4000", addr, []byte(c.payload), port, c.counter))
		if b, ok := stWaitGot(got, time.Second); !ok || string(b) != c.payload {
			t.Fatalf("counter %d: backend got %q (ok=%v), want %q", c.counter, b, ok, c.payload)
		}
	}
	if n := replayed.Get() - before; n != 2 {
		t.Errorf("%d datagrams counted as replayed, want 2", n)
	}
}

// With accept_proxy_replay_window: required, a header without a counter
// (signature version 1) is refused; with one it is taken.
func TestReplayWindow_RequiredUDP(t *testing.T) { stUDPEngines(t, udpTestReplayWindow_RequiredUDP) }

func udpTestReplayWindow_RequiredUDP(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "replay-required", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}, AcceptProxyReplayWindow: "required"}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	badSig := e.Metrics.GetCounter("nvelox_udp_dropped_total", map[string]string{"reason": udpDropBadSignature})
	before := badSig.Get()
	v1, _ := stRelaySocket(t, addr)
	stSend(t, v1, signedUDPDatagram(t, sigKeyA, "198.51.100.51:4000", addr, []byte("version 1")))
	if b, ok := stWaitGot(got, 300*time.Millisecond); ok {
		t.Fatalf("a header without a counter was forwarded: %q", b)
	}
	waitFor(t, "the header without a counter counted as bad_signature", func() bool { return badSig.Get() == before+1 })
	v2, port := stRelaySocket(t, addr)
	stSend(t, v2, signedUDPDatagramV2(t, sigKeyA, "198.51.100.51:4000", addr, []byte("version 2"), port, 7))
	if b, ok := stWaitGot(got, time.Second); !ok || string(b) != "version 2" {
		t.Fatalf("a header with a counter: backend got %q (ok=%v)", b, ok)
	}
}

// A reload that sets accept_proxy_replay_window: required holds for a
// running listener from its next datagram on, and one that sets it back
// takes headers without a counter again.
func TestReplayWindow_ReloadToRequired(t *testing.T) {
	stUDPEngines(t, udpTestReplayWindow_ReloadToRequired)
}

func udpTestReplayWindow_ReloadToRequired(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	mk := func(window string) *config.Config {
		return &config.Config{Version: "2",
			Listeners: []config.Listener{{Name: "replay-reload", Bind: addr, Protocol: "udp", Backend: "be",
				AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}, AcceptProxyReplayWindow: window}},
			Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
		}
	}
	e := stStart(t, mk(""), nil)
	v1 := func(client, payload string) bool {
		t.Helper()
		sock, _ := stRelaySocket(t, addr)
		stSend(t, sock, signedUDPDatagram(t, sigKeyA, client, addr, []byte(payload)))
		b, ok := stWaitGot(got, 500*time.Millisecond)
		if ok && string(b) != payload {
			t.Fatalf("backend got %q, want %q", b, payload)
		}
		return ok
	}
	if !v1("198.51.100.60:4000", "before") {
		t.Fatal("when_present: a header without a counter was not forwarded")
	}
	if err := e.Reload(mk("required")); err != nil {
		t.Fatal(err)
	}
	if v1("198.51.100.61:4000", "required") {
		t.Fatal("after a reload to required: a header without a counter was forwarded")
	}
	sock, port := stRelaySocket(t, addr)
	stSend(t, sock, signedUDPDatagramV2(t, sigKeyA, "198.51.100.62:4000", addr, []byte("counted"), port, 9))
	if b, ok := stWaitGot(got, time.Second); !ok || string(b) != "counted" {
		t.Fatalf("after a reload to required: a header with a counter: backend got %q (ok=%v)", b, ok)
	}
	if err := e.Reload(mk("when_present")); err != nil {
		t.Fatal(err)
	}
	if !v1("198.51.100.63:4000", "after") {
		t.Fatal("after a reload back to when_present: a header without a counter was not forwarded")
	}
}

// signedTCPHeaderV2 writes a header naming client, signed with key in
// version 2 for the relay connection's port port.
func signedTCPHeaderV2(t *testing.T, c net.Conn, key []byte, client string, port uint16) {
	t.Helper()
	src, err := net.ResolveTCPAddr("tcp", client)
	if err != nil {
		t.Fatal(err)
	}
	h := proxyproto.HeaderProxyFromAddrs(2, src, c.RemoteAddr())
	if err := proxy.SignHeaderFrom(h, key, time.Now(), port); err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteTo(c); err != nil {
		t.Fatal(err)
	}
}

// A relay connection's header in version 2 holds for that connection's
// port only; with "required" one in version 1 is refused.
func TestReplayWindow_TCP(t *testing.T) {
	t.Run("when_present", func(t *testing.T) { replayWindowTCP(t, false) })
	t.Run("required", func(t *testing.T) { replayWindowTCP(t, true) })
}

func replayWindowTCP(t *testing.T, required bool) {
	echo, accepted := stTCPEchoBackend(t)
	addr := stFreeTCPAddr(t)
	l := config.Listener{Name: "replay-tcp", Bind: addr, Protocol: "tcp", Backend: "be",
		AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}}
	if required {
		l.AcceptProxyReplayWindow = "required"
	}
	stStart(t, &config.Config{Listeners: []config.Listener{l}, Backends: []config.Backend{{Name: "be", Servers: []string{echo}}}}, nil)
	dial := func() net.Conn {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	portOfConn := func(c net.Conn) uint16 { return uint16(c.LocalAddr().(*net.TCPAddr).Port) }

	ok := dial()
	signedTCPHeaderV2(t, ok, sigKeyA, "198.51.100.52:4000", portOfConn(ok))
	if err := stEcho(ok, "hello"); err != nil {
		t.Fatalf("required %v: a version 2 header for the connection's port: %v", required, err)
	}
	before := accepted.Load()
	wrong := dial()
	signedTCPHeaderV2(t, wrong, sigKeyA, "198.51.100.53:4000", portOfConn(wrong)+1)
	stRefused(t, wrong, "hello")
	if n := accepted.Load(); n != before {
		t.Fatalf("required %v: a header signed for another port reached the backend", required)
	}
	v1 := dial()
	signedTCPHeader(t, v1, sigKeyA, "198.51.100.54:4000")
	if required {
		stRefused(t, v1, "hello")
		if n := accepted.Load(); n != before {
			t.Fatalf("required: a version 1 header reached the backend")
		}
	} else if err := stEcho(v1, "hello"); err != nil {
		t.Fatalf("when_present: a version 1 header: %v", err)
	}
}

// The windows of the relay sockets: kept while a session uses them and for
// relayWindowKeep after the last one ended, then removed, or begun anew by
// the next session; removed oldest first, a bounded number per call.
func TestRelayWindows(t *testing.T) {
	if relayWindowKeep < 2*proxy.SignatureWindow {
		t.Fatalf("windows are kept %v, less than the %v a header can pass its time check after it was taken", relayWindowKeep, 2*proxy.SignatureWindow)
	}
	var ws relayWindows
	a := netip.MustParseAddrPort("192.0.2.1:4000")
	b := netip.MustParseAddrPort("192.0.2.1:4001")
	keep := int64(relayWindowKeep)
	now := 1_000 * int64(time.Second)

	w := ws.attach(a, now)
	if !w.Take(10) || w.Take(10) {
		t.Fatal("a counter is taken once")
	}
	ws.detach(w, now)
	// The next session of the socket, within relayWindowKeep: the same
	// window, which a session uses again.
	w2 := ws.attach(a, now+keep)
	if w2 != w || w2.Take(10) {
		t.Fatal("a session that begins within relayWindowKeep of the last one's end has a new window")
	}
	// Two sessions at once (one ending as the next begins): the window is
	// kept while either uses it, also when the entry of its end at now
	// comes up.
	w3 := ws.attach(a, now+keep)
	ws.attach(netip.MustParseAddrPort("192.0.2.9:1"), now+keep+1)
	if ws.m[a] != w || w.sessions != 2 {
		t.Fatalf("a window in use: in the table %v, sessions %d, want 2", ws.m[a] == w, w.sessions)
	}
	ws.detach(w2, now+keep+1)
	end := now + keep + 2
	ws.detach(w3, end)

	// Exactly relayWindowKeep after its last session ended a header it
	// took may still pass: kept. Past that: removed, and the socket's next
	// session begins with an empty window.
	ws.attach(netip.MustParseAddrPort("192.0.2.9:2"), end+keep)
	if ws.m[a] != w {
		t.Fatal("a window removed exactly relayWindowKeep after its last session ended: a header it took may still pass")
	}
	ws.attach(netip.MustParseAddrPort("192.0.2.9:3"), end+keep+1)
	if _, ok := ws.m[a]; ok {
		t.Fatal("a window unused for more than relayWindowKeep was not removed")
	}
	if w4 := ws.attach(a, end+keep+1); w4 == w || !w4.Take(10) {
		t.Fatal("the next session after the removal does not begin with an empty window")
	}

	// A window that is not in use while it is waiting: begun anew when a
	// session comes for it past relayWindowKeep.
	wb := ws.attach(b, end)
	wb.Take(77)
	ws.detach(wb, end)
	wb.ended -= 2 * keep // as if it had waited, without the removal running
	if again := ws.attach(b, end); again != wb || !again.Take(77) {
		t.Fatal("a window unused for more than relayWindowKeep still holds its counters")
	}

	// A window used again after its last session ended has a later end:
	// the entry of the earlier one, when it comes up, leaves it.
	c := netip.MustParseAddrPort("192.0.2.1:4002")
	wc := ws.attach(c, end)
	ws.detach(wc, end)
	ws.attach(c, end+1)
	ws.detach(wc, end+keep)
	ws.attach(netip.MustParseAddrPort("192.0.2.9:4"), end+keep+1)
	if ws.m[c] != wc {
		t.Fatal("a window used again was removed when the entry of its earlier end came up")
	}

	// Removal is bounded per call, oldest first.
	var many relayWindows
	for i := range 3 * relayWindowExpireMax {
		x := many.attach(netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(i+1)), 0)
		many.detach(x, int64(i))
	}
	late := 10 * keep
	many.attach(netip.MustParseAddrPort("198.51.100.2:1"), late)
	if n := len(many.m); n != 2*relayWindowExpireMax+1 {
		t.Fatalf("%d windows left after one call, want %d", n, 2*relayWindowExpireMax+1)
	}
	if _, ok := many.m[netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), 1)]; ok {
		t.Error("the oldest window was not the first removed")
	}
	for range 2 {
		many.attach(netip.MustParseAddrPort("198.51.100.2:1"), late)
	}
	if n := len(many.m); n != 1 {
		t.Errorf("%d windows left after three calls, want 1", n)
	}
}
