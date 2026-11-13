package core

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/denylist"
)

// dcWSBackend is a minimal WebSocket backend: it answers each upgrade with a
// 101 and echoes what follows.
func dcWSBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
					"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
				io.Copy(c, br)
			}()
		}
	}()
	return ln.Addr().String()
}

// dcDial connects to addr from the loopback address src.
func dcDial(t *testing.T, src, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s from %s: %v", addr, src, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// dcUpgrade opens a WebSocket tunnel through the proxy at addr from src.
func dcUpgrade(t *testing.T, src, addr string) net.Conn {
	t.Helper()
	c := dcDial(t, src, addr)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: edge.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	// Read the 101 byte by byte so nothing after it is buffered away.
	var head []byte
	b := make([]byte, 1)
	for len(head) < 4 || string(head[len(head)-4:]) != "\r\n\r\n" {
		if _, err := c.Read(b); err != nil {
			t.Fatalf("upgrade from %s: %v (read %q)", src, err, head)
		}
		head = append(head, b[0])
	}
	if string(head[:12]) != "HTTP/1.1 101" {
		t.Fatalf("upgrade from %s: %q", src, head)
	}
	c.SetDeadline(time.Time{})
	return c
}

// dcExpectClosed waits up to 2 s for the proxy to close c.
func dcExpectClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("%s still open 2 s after its client was blocked", what)
		}
		return
	}
}

// TestDenylistAddClosesOpenConnections: adding a client to the dynamic
// denylist ends what it has open — an L4 TCP connection (direct, behind a
// trusted relay that named it, and over TLS), a UDP session and a WebSocket
// tunnel — and leaves another client's open. (The denylist is otherwise
// checked only when a connection, session or request starts.)
func TestDenylistAddClosesOpenConnections(t *testing.T) {
	const blockedIP, otherIP, relayIP = "127.0.0.71", "127.0.0.72", "127.0.0.73"
	const relayedBlocked, relayedOther = "203.0.113.71", "203.0.113.72"
	pki := newSTPKI(t, "denyclose")
	tcpBackend, _ := stTCPEchoBackend(t)
	udpBackend, _ := stUDPBackend(t, stEchoReply)
	tcpAddr, udpAddr, httpAddr := stFreeTCPAddr(t), stFreeUDPAddr(t), stFreeTCPAddr(t)
	relayAddr, tlsAddr := stFreeTCPAddr(t), stFreeTCPAddr(t)
	cfg := &config.Config{
		Listeners: []config.Listener{
			{Name: "tcp", Bind: tcpAddr, Protocol: "tcp", Backend: "tcpb"},
			{Name: "relay", Bind: relayAddr, Protocol: "tcp", Backend: "tcpb", AcceptProxyFrom: []string{relayIP + "/32"}},
			{Name: "tls", Bind: tlsAddr, Protocol: "tcp", Backend: "tcpb",
				TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}},
			{Name: "udp", Bind: udpAddr, Protocol: "udp", Backend: "udpb"},
			{Name: "web", Bind: httpAddr, Protocol: "http", Backend: "wsb"},
		},
		Backends: []config.Backend{
			{Name: "tcpb", Servers: []string{tcpBackend}},
			{Name: "udpb", Servers: []string{udpBackend}},
			{Name: "wsb", Servers: []string{dcWSBackend(t)}},
		},
	}
	e := stStart(t, cfg, nil)

	// What each client has open.
	tcpBlocked, tcpOther := dcDial(t, blockedIP, tcpAddr), dcDial(t, otherIP, tcpAddr)
	relayBlocked, relayOther := dcDial(t, relayIP, relayAddr), dcDial(t, relayIP, relayAddr)
	stTCPProxyHeader(t, relayBlocked, relayedBlocked+":5000")
	stTCPProxyHeader(t, relayOther, relayedOther+":5000")
	tlsDial := func(src string) net.Conn {
		d := &tls.Dialer{NetDialer: &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second},
			Config: &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"}}
		c, err := d.Dial("tcp", tlsAddr)
		if err != nil {
			t.Fatalf("TLS dial from %s: %v", src, err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	tlsBlocked, tlsOther := tlsDial(blockedIP), tlsDial(otherIP)
	wsBlocked, wsOther := dcUpgrade(t, blockedIP, httpAddr), dcUpgrade(t, otherIP, httpAddr)
	for _, c := range []net.Conn{tcpBlocked, tcpOther, relayBlocked, relayOther, tlsBlocked, tlsOther, wsBlocked, wsOther} {
		if err := stEcho(c, "before"); err != nil {
			t.Fatalf("echo before the block: %v", err)
		}
	}
	raddr, _ := net.ResolveUDPAddr("udp", udpAddr)
	udpBlocked, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(blockedIP)}, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpBlocked.Close()
	udpOther, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(otherIP)}, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpOther.Close()
	udpEcho := func(c *net.UDPConn, msg string) bool {
		c.Write([]byte(msg))
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		return err == nil && string(buf[:n]) == msg
	}
	if !udpEcho(udpBlocked, "before") || !udpEcho(udpOther, "before") {
		t.Fatal("UDP sessions not established")
	}

	for _, ip := range []string{blockedIP, relayedBlocked} {
		if _, err := denylist.Default.Add(ip, time.Minute); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { denylist.Default.Remove(ip) })
	}

	dcExpectClosed(t, tcpBlocked, "L4 TCP connection")
	dcExpectClosed(t, relayBlocked, "relayed L4 TCP connection of the blocked client")
	dcExpectClosed(t, tlsBlocked, "L4 TLS connection")
	dcExpectClosed(t, wsBlocked, "WebSocket tunnel")
	// The UDP session ends; a datagram from the same socket then starts a new
	// session, which the denylist refuses.
	h := stHandler(e)
	deadline := time.Now().Add(2 * time.Second)
	for {
		open := false
		h.sessions.Range(func(_, v any) bool {
			ctx := v.(*ConnContext)
			ctx.Mu.Lock()
			if !ctx.IsBackend && !ctx.closed && ctx.RealClientIP == blockedIP {
				open = true
			}
			ctx.Mu.Unlock()
			return !open
		})
		if !open {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("UDP session still open 2 s after its client was blocked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if udpEcho(udpBlocked, "after") {
		t.Fatal("blocked client's datagram still relayed")
	}

	// The other client is untouched.
	for _, c := range []net.Conn{tcpOther, relayOther, tlsOther, wsOther} {
		if err := stEcho(c, "after"); err != nil {
			t.Fatalf("other client's connection: %v", err)
		}
	}
	if !udpEcho(udpOther, "after") {
		t.Fatal("other client's UDP session broken")
	}
}
