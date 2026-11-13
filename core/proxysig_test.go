package core

// Signed PROXY v2 headers (accept_proxy_key_file / send_proxy_key_file)
// through a running engine: a receiver with keys takes only headers signed
// with one of them; a sender with a key signs every header it writes.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/config"
	"nvelox/proxy"
)

var (
	sigKeyA = []byte("signing-key-A-0123456789abcdef0123456789")
	sigKeyB = []byte("signing-key-B-0123456789abcdef0123456789")
)

func signedUDPDatagram(t *testing.T, key []byte, client, dst string, payload []byte) []byte {
	t.Helper()
	plain := stUDPDatagramWithProxy(t, client, dst, nil)
	signed, err := proxy.SignedHeaderBytes(plain, key, payload, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return append(signed, payload...)
}

func signedTCPHeader(t *testing.T, c net.Conn, key []byte, client string) {
	t.Helper()
	src, err := net.ResolveTCPAddr("tcp", client)
	if err != nil {
		t.Fatal(err)
	}
	h := proxyproto.HeaderProxyFromAddrs(2, src, c.RemoteAddr())
	if err := proxy.SignHeader(h, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteTo(c); err != nil {
		t.Fatal(err)
	}
}

func TestSignedProxy_UDPReceiver(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyB, sigKeyA}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	send := func(d []byte) {
		t.Helper()
		stUDPExchange("127.0.0.1", addr, d, 30*time.Millisecond)
	}
	orig := signedUDPDatagram(t, sigKeyA, "198.51.100.42:4000", addr, []byte("original"))
	swapped := append(append([]byte{}, orig[:len(orig)-len("original")]...), "replaced"...)
	for name, d := range map[string][]byte{
		"unsigned header": stUDPDatagramWithProxy(t, "198.51.100.40:4000", addr, []byte("forged")),
		"another key":     signedUDPDatagram(t, []byte("not-a-configured-key-0123456789abcdef"), "198.51.100.41:4000", addr, []byte("forged")),
		"payload swapped": swapped,
	} {
		send(d)
		if b, ok := stWaitGot(got, 300*time.Millisecond); ok {
			t.Fatalf("%s: forwarded %q", name, b)
		}
	}
	send(signedUDPDatagram(t, sigKeyA, "198.51.100.43:4000", addr, []byte("signed")))
	if b, ok := stWaitGot(got, time.Second); !ok || string(b) != "signed" {
		t.Fatalf("signed datagram: backend got %q (ok=%v)", b, ok)
	}
}

func TestSignedProxy_TCPReceiver(t *testing.T) {
	echo, accepted := stTCPEchoBackend(t)
	addr := stFreeTCPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-tcp", Bind: addr, Protocol: "tcp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
	}, nil)
	dial := func() net.Conn {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	unsigned := dial()
	stTCPProxyHeader(t, unsigned, "198.51.100.50:4000")
	stRefused(t, unsigned, "hello")
	wrong := dial()
	signedTCPHeader(t, wrong, sigKeyB, "198.51.100.51:4000")
	stRefused(t, wrong, "hello")
	if n := accepted.Load(); n != 0 {
		t.Fatalf("unsigned or wrongly signed headers reached the backend (%d)", n)
	}
	ok := dial()
	signedTCPHeader(t, ok, sigKeyA, "198.51.100.52:4000")
	if err := stEcho(ok, "hello"); err != nil {
		t.Fatalf("signed header: %v", err)
	}
	// A trusted peer without a header is itself the client (no forgery).
	if err := stEcho(dial(), "hello"); err != nil {
		t.Fatalf("relay without a header: %v", err)
	}
}

func TestSignedProxy_TLSReceiver(t *testing.T) {
	pki := newSTPKI(t, "sigtls")
	echo, accepted := stTCPEchoBackend(t)
	addr := stFreeTCPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-tls", Bind: addr, Protocol: "tcp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA},
			TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
	}, nil)
	handshake := func(sign func(net.Conn)) error {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		sign(raw)
		tc := tls.Client(raw, &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"})
		tc.SetDeadline(time.Now().Add(3 * time.Second))
		if err := tc.Handshake(); err != nil {
			return err
		}
		return stEcho(tc, "hello")
	}
	if err := handshake(func(c net.Conn) { stTCPProxyHeader(t, c, "198.51.100.60:4000") }); err == nil {
		t.Fatal("unsigned header: TLS session worked")
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("unsigned header reached the backend (%d)", n)
	}
	if err := handshake(func(c net.Conn) { signedTCPHeader(t, c, sigKeyA, "198.51.100.61:4000") }); err != nil {
		t.Fatalf("signed header: %v", err)
	}
}

// TestSignedProxy_Senders: with send_proxy_key_file the header nvelox writes
// to a TCP backend, and to a UDP backend with every datagram, verifies with
// the key (over the datagram for UDP).
func TestSignedProxy_Senders(t *testing.T) {
	// TCP: a raw backend that reads and keeps the header.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	hdrCh := make(chan *proxyproto.Header, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		h, err := proxyproto.Read(bufio.NewReader(c))
		if err == nil {
			hdrCh <- h
		}
		io.Copy(io.Discard, c)
	}()
	udpBE, udpGot := stUDPBackend(t, nil)
	tcpAddr, udpAddr := stFreeTCPAddr(t), stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{
			{Name: "tcp-in", Bind: tcpAddr, Protocol: "tcp", Backend: "tcp-be"},
			{Name: "udp-in", Bind: udpAddr, Protocol: "udp", Backend: "udp-be"},
		},
		Backends: []config.Backend{
			{Name: "tcp-be", Servers: []string{ln.Addr().String()}, SendProxyV2: true, SendProxyKey: sigKeyA},
			{Name: "udp-be", Servers: []string{udpBE}, SendProxyV2: true, SendProxyKey: sigKeyA},
		},
	}, nil)
	c, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("payload"))
	select {
	case h := <-hdrCh:
		if err := proxy.Verify(h, [][]byte{sigKeyA}, nil, time.Now()); err != nil {
			t.Fatalf("TCP header: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TCP backend got no header")
	}
	stUDPExchange("127.0.0.1", udpAddr, []byte("datagram-1"), 30*time.Millisecond)
	d, ok := stWaitGot(udpGot, time.Second)
	if !ok {
		t.Fatal("UDP backend got nothing")
	}
	r := bufio.NewReader(bytes.NewReader(d))
	h, err := proxyproto.Read(r)
	if err != nil {
		t.Fatalf("UDP datagram without a header: %v", err)
	}
	payload, _ := io.ReadAll(r)
	if string(payload) != "datagram-1" {
		t.Fatalf("UDP payload %q", payload)
	}
	if err := proxy.Verify(h, [][]byte{sigKeyA}, payload, time.Now()); err != nil {
		t.Fatalf("UDP header: %v", err)
	}
	if err := proxy.Verify(h, [][]byte{sigKeyA}, []byte("other"), time.Now()); err == nil {
		t.Fatal("UDP signature does not cover the payload")
	}
}

// TestSignedProxy_KeyRotationByReload: a reload re-reads accept_proxy_key_file
// for running L4 listeners, so a key can be rotated without a restart.
func TestSignedProxy_KeyRotationByReload(t *testing.T) {
	echo, _ := stTCPEchoBackend(t)
	addr := stFreeTCPAddr(t)
	mk := func(keys ...[]byte) *config.Config {
		return &config.Config{
			Listeners: []config.Listener{{Name: "relay-tcp", Bind: addr, Protocol: "tcp", Backend: "be",
				AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: keys}},
			Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
		}
	}
	e := stStart(t, mk(sigKeyA), nil)
	try := func(key []byte) error {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		signedTCPHeader(t, c, key, "198.51.100.70:4000")
		return stEcho(c, "hello")
	}
	if err := try(sigKeyB); err == nil {
		t.Fatal("key B before the rotation: accepted")
	}
	if err := e.Reload(mk(sigKeyA, sigKeyB)); err != nil {
		t.Fatal(err)
	}
	if err := try(sigKeyB); err != nil {
		t.Fatalf("key B after the reload: %v", err)
	}
	if err := e.Reload(mk(sigKeyB)); err != nil {
		t.Fatal(err)
	}
	if err := try(sigKeyA); err == nil {
		t.Fatal("key A after it was removed: accepted")
	}
}

// TestSignedProxy_ReloadChangingTrustKeepsIt: a reload swaps the PROXY keys
// of a running listener only while its accept_proxy_from is unchanged. A
// reload that drops both the key file and accept_proxy_from must not leave
// the old relay range trusted with no key: the listener keeps its trust and
// keys (a trust change needs a restart), so an unsigned header is still
// dropped.
func TestSignedProxy_ReloadChangingTrustKeepsIt(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	signedCfg := &config.Config{
		Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}
	e := stStart(t, signedCfg, nil)
	if err := e.Reload(&config.Config{Version: "2",
		Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}); err != nil {
		t.Fatal(err)
	}
	stUDPExchange("127.0.0.1", addr, stUDPDatagramWithProxy(t, "198.51.100.91:4000", addr, []byte("unsigned")), 300*time.Millisecond)
	if d, ok := stWaitGot(got, 300*time.Millisecond); ok {
		t.Fatalf("after the reload an unsigned header was trusted: the backend got %q", d)
	}
}

// TestSignedProxy_TransportMustMatch: a signed header names the transport
// it was made for. A signed stream (TCP) header replayed as a datagram —
// with an empty payload its signature would otherwise verify — admits no
// client, and a datagram header at the start of a TCP connection is refused.
func TestSignedProxy_TransportMustMatch(t *testing.T) {
	udpBE, _ := stUDPBackend(t, nil)
	echo, _ := stTCPEchoBackend(t)
	udpAddr, tcpAddr := stFreeUDPAddr(t), stFreeTCPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{
			{Name: "relay-udp", Bind: udpAddr, Protocol: "udp", Backend: "udp-be",
				AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}},
			{Name: "relay-tcp", Bind: tcpAddr, Protocol: "tcp", Backend: "tcp-be",
				AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}},
		},
		Backends: []config.Backend{{Name: "udp-be", Servers: []string{udpBE}}, {Name: "tcp-be", Servers: []string{echo}}},
	}, nil)

	// A stream header, signed, sent as a whole datagram.
	stream := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("198.51.100.92"), Port: 4000}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9})
	if err := proxy.SignHeader(stream, sigKeyA, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := stream.Format()
	if err != nil {
		t.Fatal(err)
	}
	stUDPExchange("127.0.0.1", udpAddr, raw, 300*time.Millisecond)
	admitted := false
	stHandler(e).sessions.Range(func(_, v any) bool {
		ctx := v.(*ConnContext)
		ctx.Mu.Lock()
		if ctx.ClientResolved && ctx.RealClientIP == "198.51.100.92" {
			admitted = true
		}
		ctx.Mu.Unlock()
		return true
	})
	if admitted {
		t.Fatal("a signed stream header replayed as a datagram admitted its client")
	}

	// A datagram header, signed, at the start of a TCP connection.
	dgram, err := proxy.SignedHeaderBytes(stUDPDatagramWithProxy(t, "198.51.100.93:4000", tcpAddr, nil), sigKeyA, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(dgram)
	stRefused(t, c, "hello")
}

// TestSignedProxy_UDPSenderUsesTheCurrentKey: a reload that rotates a
// backend's send_proxy_key_file applies to the datagrams of UDP sessions
// already running, so the old key can be retired on the receivers.
func TestSignedProxy_UDPSenderUsesTheCurrentKey(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	mk := func(key []byte) *config.Config {
		return &config.Config{Version: "2",
			Listeners: []config.Listener{{Name: "udp-in", Bind: addr, Protocol: "udp", Backend: "udp-be"}},
			Backends:  []config.Backend{{Name: "udp-be", Servers: []string{be}, SendProxyV2: true, SendProxyKey: key}},
		}
	}
	e := stStart(t, mk(sigKeyA), nil)
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	signedWith := func(payload string) [][]byte {
		c.Write([]byte(payload))
		d, ok := stWaitGot(got, 2*time.Second)
		if !ok {
			t.Fatalf("backend got nothing for %q", payload)
		}
		r := bufio.NewReader(bytes.NewReader(d))
		h, err := proxyproto.Read(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r)
		var keys [][]byte
		for _, k := range [][]byte{sigKeyA, sigKeyB} {
			if proxy.Verify(h, [][]byte{k}, body, time.Now()) == nil {
				keys = append(keys, k)
			}
		}
		return keys
	}
	if k := signedWith("before"); len(k) != 1 || !bytes.Equal(k[0], sigKeyA) {
		t.Fatalf("before the reload: signed with %q", k)
	}
	if err := e.Reload(mk(sigKeyB)); err != nil {
		t.Fatal(err)
	}
	if k := signedWith("after"); len(k) != 1 || !bytes.Equal(k[0], sigKeyB) {
		t.Fatalf("same session after the reload: signed with %q, want key B", k)
	}
}
