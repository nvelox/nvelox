package core

import (
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/config"
)

// A relay's header names a datagram's client by an IP address. One for a
// stream, and one whose source is a socket path, name none: their
// datagrams are dropped like any without a header.
func TestUDP_RelayHeaderMustNameADatagramClientByAddress(t *testing.T) {
	stUDPEngines(t, udpTestUDP_RelayHeaderMustNameADatagramClientByAddress)
}

func udpTestUDP_RelayHeaderMustNameADatagramClientByAddress(t *testing.T) {
	be, got := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be", AcceptProxyFrom: []string{"127.0.0.0/8"}}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	dropped := stDropped(e, udpDropNoProxyHeader)

	stream, err := (&proxyproto.Header{Version: 2, Command: proxyproto.PROXY, TransportProtocol: proxyproto.TCPv4,
		SourceAddr:      &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 7000},
		DestinationAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}}).Format()
	if err != nil {
		t.Fatal(err)
	}
	path, err := (&proxyproto.Header{Version: 2, Command: proxyproto.PROXY, TransportProtocol: proxyproto.UnixDatagram,
		SourceAddr:      &net.UnixAddr{Name: "/run/relay", Net: "unixgram"},
		DestinationAddr: &net.UnixAddr{Name: "/run/nvelox", Net: "unixgram"}}).Format()
	if err != nil {
		t.Fatal(err)
	}
	for name, hdr := range map[string][]byte{"a stream header": stream, "a header with a socket path": path} {
		if reply, err := stUDPExchange("127.0.0.1", addr, append(append([]byte(nil), hdr...), "payload"...), 400*time.Millisecond); err == nil {
			t.Errorf("%s: the relay got a reply: %q", name, reply)
		}
		if d, ok := stWaitGot(got, 200*time.Millisecond); ok {
			t.Errorf("%s: its datagram reached the backend: %q", name, d)
		}
	}
	if n := dropped(); n != 2 {
		t.Errorf("%d datagrams counted as dropped for want of a usable header, want 2", n)
	}
	if n := len(stUDPSessions(e)); n != 0 {
		t.Errorf("%d sessions are left of them", n)
	}
	// A header that does name a datagram client is served.
	if reply, err := stUDPExchange("127.0.0.1", addr, stUDPDatagramWithProxy(t, "198.51.100.21:7000", addr, []byte("ping")), 2*time.Second); err != nil || string(reply) != "ping" {
		t.Fatalf("a relayed client named by a datagram header: reply %q, %v", reply, err)
	}
}
