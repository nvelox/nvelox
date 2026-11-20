package core

// accept_proxy_replay_window through a running engine: a relay's header
// that carries a counter (signature version 2) is taken once per relay
// socket. A copy is dropped and counted as replayed, also once the session
// it began has ended; a copy from another port of the relay fails its
// signature; with "required" a header without a counter is refused.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/config"
	"nvelox/proxy"
)

// signedUDPDatagramV2 is a datagram with the ends ends (a relay socket's,
// stRelaySocket): a header naming client for dst, signed with key in
// version 2 with counter, then payload.
func signedUDPDatagramV2(t *testing.T, key []byte, client, dst string, payload []byte, ends proxy.Ends, counter uint64) []byte {
	t.Helper()
	plain := stUDPDatagramWithProxy(t, client, dst, nil)
	signed, err := proxy.SignedHeaderBytesFrom(plain, key, payload, time.Now(), ends, counter)
	if err != nil {
		t.Fatal(err)
	}
	return append(signed, payload...)
}

// stRelaySocket is a socket of a relay sending to addr, and the ends of its
// datagrams.
func stRelaySocket(t *testing.T, addr string) (*net.UDPConn, proxy.Ends) {
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
	return c, proxy.RelayEnds(c.LocalAddr(), c.RemoteAddr())
}

// stDatagramEnds are the ends of datagram d as the backend at to saw it.
func stDatagramEnds(d stDatagram, to string) proxy.Ends {
	return proxy.Ends{Relay: d.from.AddrPort(), Receiver: netip.MustParseAddrPort(to)}
}

// stOtherRelayPort is e from the next port of the relay: the ends of a copy
// sent from another of its sockets.
func stOtherRelayPort(e proxy.Ends) proxy.Ends {
	e.Relay = netip.AddrPortFrom(e.Relay.Addr(), e.Relay.Port()+1)
	return e
}

// stDatagram is a datagram a backend got, and the address it came from.
type stDatagram struct {
	data []byte
	from *net.UDPAddr
}

// stUDPBackendFrom is stUDPBackend without answers, and with the address
// of each datagram.
func stUDPBackendFrom(t *testing.T) (addr string, got chan stDatagram) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	got = make(chan stDatagram, 1024)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case got <- stDatagram{append([]byte(nil), buf[:n]...), from}:
			default:
			}
		}
	}()
	return c.LocalAddr().String(), got
}

// stSignedDatagram splits a datagram nvelox sent with a header into the
// header and the payload.
func stSignedDatagram(t *testing.T, d stDatagram) (*proxyproto.Header, []byte) {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(d.data))
	h, err := proxyproto.Read(r)
	if err != nil {
		t.Fatalf("a datagram without a header: %v", err)
	}
	payload, _ := io.ReadAll(r)
	return h, payload
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

	relay, ends := stRelaySocket(t, addr)
	first := signedUDPDatagramV2(t, sigKeyA, "198.51.100.50:4000", addr, []byte("first"), ends, 1000)
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
		stSend(t, relay, signedUDPDatagramV2(t, sigKeyA, "198.51.100.50:4000", addr, []byte(c.payload), ends, c.counter))
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
	v2, ends := stRelaySocket(t, addr)
	stSend(t, v2, signedUDPDatagramV2(t, sigKeyA, "198.51.100.51:4000", addr, []byte("version 2"), ends, 7))
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
	sock, ends := stRelaySocket(t, addr)
	stSend(t, sock, signedUDPDatagramV2(t, sigKeyA, "198.51.100.62:4000", addr, []byte("counted"), ends, 9))
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

// stHeader is the PROXY header a backend read at the start of a
// connection, and the connection's ends as the backend saw them.
type stHeader struct {
	h    *proxyproto.Header
	ends proxy.Ends
}

// stHeaderBackend is a TCP backend that reads the header of each
// connection.
func stHeaderBackend(t *testing.T) (string, chan stHeader) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan stHeader, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				h, err := proxyproto.Read(bufio.NewReader(c))
				if err == nil {
					got <- stHeader{h, proxy.ReceiverEnds(c.LocalAddr(), c.RemoteAddr())}
				}
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String(), got
}

// What the goroutine paths send is signed in version 2 too, for the port
// of nvelox's connection to the backend: a relay's connection passed on,
// and a TLS listener's.
func TestSignedProxy_SendersBehindRelayAndTLS(t *testing.T) {
	pki := newSTPKI(t, "sigsend")
	be, got := stHeaderBackend(t)
	relayAddr, tlsAddr := stFreeTCPAddr(t), stFreeTCPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{
			{Name: "relayed-in", Bind: relayAddr, Protocol: "tcp", Backend: "be",
				AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyB}},
			{Name: "tls-in", Bind: tlsAddr, Protocol: "tcp", Backend: "be",
				TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}},
		},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}, SendProxyV2: true, SendProxyKey: sigKeyA}},
	}, nil)
	check := func(what, client string) {
		t.Helper()
		select {
		case sh := <-got:
			if _, counted, err := proxy.VerifyFrom(sh.h, [][]byte{sigKeyA}, nil, time.Now(), sh.ends); err != nil || !counted {
				t.Fatalf("%s: counted %v, %v", what, counted, err)
			}
			if _, _, err := proxy.VerifyFrom(sh.h, [][]byte{sigKeyA}, nil, time.Now(), stOtherRelayPort(sh.ends)); err == nil {
				t.Fatalf("%s: the header passes for another port", what)
			}
			if client != "" && sh.h.SourceAddr.String() != client {
				t.Errorf("%s: names %v, want %s", what, sh.h.SourceAddr, client)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: the backend got no header", what)
		}
	}

	c, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	signedTCPHeaderV2(t, c, sigKeyB, "198.51.100.80:4000", proxy.RelayEnds(c.LocalAddr(), c.RemoteAddr()))
	c.Write([]byte("hello"))
	check("a relay's connection", "198.51.100.80:4000")

	raw, err := net.Dial("tcp", tlsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"})
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte("hello"))
	check("a TLS listener's connection", "")
}

// signedTCPHeaderV2 writes a header naming client, signed with key in
// version 2 for a relay connection with the ends ends.
func signedTCPHeaderV2(t *testing.T, c net.Conn, key []byte, client string, ends proxy.Ends) {
	t.Helper()
	src, err := net.ResolveTCPAddr("tcp", client)
	if err != nil {
		t.Fatal(err)
	}
	h := proxyproto.HeaderProxyFromAddrs(2, src, c.RemoteAddr())
	if err := proxy.SignHeaderFrom(h, key, time.Now(), ends); err != nil {
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
	endsOf := func(c net.Conn) proxy.Ends { return proxy.RelayEnds(c.LocalAddr(), c.RemoteAddr()) }

	ok := dial()
	signedTCPHeaderV2(t, ok, sigKeyA, "198.51.100.52:4000", endsOf(ok))
	if err := stEcho(ok, "hello"); err != nil {
		t.Fatalf("required %v: a version 2 header for the connection's port: %v", required, err)
	}
	before := accepted.Load()
	wrong := dial()
	signedTCPHeaderV2(t, wrong, sigKeyA, "198.51.100.53:4000", stOtherRelayPort(endsOf(wrong)))
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
	if relayWindowExpireMax < 1 || relayWindowExpireMax > 256 {
		t.Fatalf("one call removes up to %d windows: want a few, so that no datagram waits for many", relayWindowExpireMax)
	}
	const made = 192
	peer := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(i+1))
	}
	var many relayWindows
	for i := range made {
		many.detach(many.attach(peer(i), 0), int64(i))
	}
	late := 10 * keep
	z := netip.MustParseAddrPort("198.51.100.2:1")
	many.attach(z, late)
	if want := made + 1 - min(made, relayWindowExpireMax); len(many.m) != want {
		t.Fatalf("%d windows left after one call, want %d", len(many.m), want)
	}
	if _, ok := many.m[peer(0)]; ok {
		t.Error("the oldest window was not the first removed")
	}
	for range made {
		many.attach(z, late)
	}
	if n := len(many.m); n != 1 {
		t.Errorf("%d windows left, want 1", n)
	}
}

// A flood of sessions through one relay socket that are refused at once
// (each ends as it begins): the list of windows to expire holds one entry
// for the window, not one per session, and the window still goes
// relayWindowKeep after the last session ended. Before, every end added an
// entry kept for relayWindowKeep: memory followed the session rate.
func TestRelayWindows_OneEntryPerWindow(t *testing.T) {
	var ws relayWindows
	keep := int64(relayWindowKeep)
	a := netip.MustParseAddrPort("192.0.2.1:4000")
	now := 1_000 * int64(time.Second)
	const sessions = 100_000
	for i := range int64(sessions) {
		ws.detach(ws.attach(a, now+i), now+i)
	}
	if n := len(ws.idle); n != 1 {
		t.Fatalf("%d entries in the list after %d sessions of one relay socket, want 1", n, sessions)
	}
	last := now + sessions - 1
	ws.attach(netip.MustParseAddrPort("192.0.2.9:1"), last+keep)
	if _, ok := ws.m[a]; !ok {
		t.Fatal("the window was removed less than relayWindowKeep after its last session ended")
	}
	ws.attach(netip.MustParseAddrPort("192.0.2.9:2"), last+keep+1)
	if _, ok := ws.m[a]; ok {
		t.Fatal("the window was not removed relayWindowKeep after its last session ended")
	}

	// A window in use when its entry comes up stays, and is queued again
	// when its last session ends.
	b := netip.MustParseAddrPort("192.0.2.1:4001")
	t0 := 10_000 * int64(time.Second)
	wb := ws.attach(b, t0)
	ws.detach(wb, t0)
	wb = ws.attach(b, t0+1)
	ws.attach(netip.MustParseAddrPort("192.0.2.9:3"), t0+keep+1)
	if ws.m[b] != wb {
		t.Fatal("a window in use was removed when its entry came up")
	}
	ws.detach(wb, t0+keep+2)
	ws.attach(netip.MustParseAddrPort("192.0.2.9:4"), t0+2*keep+3)
	if _, ok := ws.m[b]; ok {
		t.Fatal("a window whose entry came up while in use was never removed after its last session ended")
	}
}
