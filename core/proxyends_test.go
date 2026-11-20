package core

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/proxy"
)

// stRelaySocketFrom is stRelaySocket from the address ip: a socket of a
// relay at ip sending to addr, and the ends of its datagrams.
func stRelaySocketFrom(t *testing.T, ip, addr string) (*net.UDPConn, proxy.Ends) {
	t.Helper()
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)}, ra)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, proxy.RelayEnds(c.LocalAddr(), c.RemoteAddr())
}

// A signed header (version 2) is bound to both ends of its datagram: on a
// UDP listener bound to every address, a relay's datagram passes on the
// address it was signed for; one signed for another of the listener's
// addresses, or for another trusted address than the one it comes from,
// is refused.
func TestSignedProxy_BothEndsUDP(t *testing.T) { stUDPEngines(t, udpTestSignedProxy_BothEndsUDP) }

func udpTestSignedProxy_BothEndsUDP(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	_, port, _ := net.SplitHostPort(stFreeUDPAddr(t))
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "ends-udp", Bind: "0.0.0.0:" + port, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}, AcceptProxyReplayWindow: "required"}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	badSig := e.Metrics.GetCounter("nvelox_udp_dropped_total", map[string]string{"reason": udpDropBadSignature})
	two := "127.0.0.2:" + port
	refused := func(what string, c *net.UDPConn, d []byte) {
		t.Helper()
		before := badSig.Get()
		stSend(t, c, d)
		if b, ok := stWaitGot(got, 300*time.Millisecond); ok {
			t.Fatalf("%s was forwarded: %q", what, b)
		}
		waitFor(t, what+" counted as bad_signature", func() bool { return badSig.Get() == before+1 })
	}

	relay, ends := stRelaySocketFrom(t, "127.0.0.1", two)
	stSend(t, relay, signedUDPDatagramV2(t, sigKeyA, "198.51.100.70:4000", two, []byte("to two"), ends, 2000))
	if b, ok := stWaitGot(got, time.Second); !ok || string(b) != "to two" {
		t.Fatalf("a datagram signed for the address it was sent to: backend got %q (ok=%v)", b, ok)
	}

	// Sent to 127.0.0.1, signed for 127.0.0.2.
	toOne, oneEnds := stRelaySocketFrom(t, "127.0.0.1", "127.0.0.1:"+port)
	oneEnds.Receiver = netip.MustParseAddrPort(two)
	refused("a datagram signed for another address of the listener", toOne,
		signedUDPDatagramV2(t, sigKeyA, "198.51.100.71:4000", two, []byte("to one"), oneEnds, 3000))

	// Sent from 127.0.0.3, signed for 127.0.0.1 (and the same port).
	three, threeEnds := stRelaySocketFrom(t, "127.0.0.3", two)
	asOne := threeEnds
	asOne.Relay = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), threeEnds.Relay.Port())
	refused("a datagram signed for another trusted address", three,
		signedUDPDatagramV2(t, sigKeyA, "198.51.100.72:4000", two, []byte("from three"), asOne, 4000))

	// From 127.0.0.3, signed for its own ends: it passes.
	stSend(t, three, signedUDPDatagramV2(t, sigKeyA, "198.51.100.73:4000", two, []byte("from three, its own"), threeEnds, 5000))
	if b, ok := stWaitGot(got, time.Second); !ok || string(b) != "from three, its own" {
		t.Fatalf("a datagram of 127.0.0.3 signed for its ends: backend got %q (ok=%v)", b, ok)
	}
}

// The same over TCP: on a listener bound to every address, a header
// signed for its connection's ends passes; one signed for another of the
// listener's addresses, or for another trusted address, is refused.
func TestSignedProxy_BothEndsTCP(t *testing.T) {
	echo, accepted := stTCPEchoBackend(t)
	_, port, _ := net.SplitHostPort(stFreeTCPAddr(t))
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "ends-tcp", Bind: "0.0.0.0:" + port, Protocol: "tcp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
	}, nil)
	two := "127.0.0.2:" + port
	dialFrom := func(ip, to string) net.Conn {
		t.Helper()
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}, Timeout: 3 * time.Second}
		c, err := d.Dial("tcp", to)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	endsOf := func(c net.Conn) proxy.Ends { return proxy.RelayEnds(c.LocalAddr(), c.RemoteAddr()) }

	ok := dialFrom("127.0.0.1", two)
	signedTCPHeaderV2(t, ok, sigKeyA, "198.51.100.74:4000", endsOf(ok))
	if err := stEcho(ok, "hello"); err != nil {
		t.Fatalf("a header signed for its connection to %s: %v", two, err)
	}
	before := accepted.Load()

	toOne := dialFrom("127.0.0.1", "127.0.0.1:"+port)
	e := endsOf(toOne)
	e.Receiver = netip.MustParseAddrPort(two)
	signedTCPHeaderV2(t, toOne, sigKeyA, "198.51.100.75:4000", e)
	stRefused(t, toOne, "hello")

	three := dialFrom("127.0.0.3", two)
	e = endsOf(three)
	e.Relay = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), e.Relay.Port())
	signedTCPHeaderV2(t, three, sigKeyA, "198.51.100.76:4000", e)
	stRefused(t, three, "hello")

	if n := accepted.Load(); n != before {
		t.Fatalf("%d connections with a header signed for other ends reached the backend", n-before)
	}
}
