package core

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/config"
	"nvelox/proxy"
)

// A backend that wants the PROXY v2 header with every datagram
// (send_proxy_v2) never gets a datagram without it: where the backend
// expects the header, a client could put one of its own first and so name
// any source. A session whose header cannot be built is refused, and a
// session that a reload leaves without the header its backend now wants
// ends.

// stReadProxied takes a datagram a backend received apart: the PROXY v2
// header in front of it (nil when it has none) and what follows.
func stReadProxied(t *testing.T, d []byte) (*proxyproto.Header, []byte) {
	t.Helper()
	if !bytes.HasPrefix(d, proxy.V2Signature) {
		return nil, d
	}
	r := bufio.NewReader(bytes.NewReader(d))
	h, err := proxyproto.Read(r)
	if err != nil {
		t.Fatalf("the backend's datagram starts like a PROXY v2 header and is none: %v (%x)", err, d)
	}
	body, _ := io.ReadAll(r)
	return h, body
}

func stDropped(e *Engine, reason string) func() int64 {
	c := e.Metrics.GetCounter("nvelox_udp_dropped_total", map[string]string{"reason": reason})
	before := c.Get()
	return func() int64 { return int64(c.Get() - before) }
}

// A relay names an IPv6 client to a listener bound to an IPv4 address. The
// header has no family for the pair: it goes as IPv6, the listener's address
// in its IPv4-mapped form, and the session is served like any other. The
// same relay's IPv4 clients go on with an IPv4 header.
func TestUDP_ClientAndListenerOfTwoFamiliesGoAsIPv6(t *testing.T) {
	stUDPEngines(t, udpTestUDP_ClientAndListenerOfTwoFamiliesGoAsIPv6)
}

func udpTestUDP_ClientAndListenerOfTwoFamiliesGoAsIPv6(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be", AcceptProxyFrom: []string{"127.0.0.0/8"}}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}, SendProxyV2: true}},
	}, nil)
	refused := stDropped(e, udpDropNoBackendHeader)
	_, port, _ := net.SplitHostPort(addr)

	stUDPExchange("127.0.0.1", addr, stUDPDatagramWithProxy(t, "198.51.100.10:7000", addr, []byte("over v4")), 50*time.Millisecond)
	d, ok := stWaitGot(got, 2*time.Second)
	if !ok {
		t.Fatal("the backend got nothing of the relay's IPv4 client")
	}
	if h, body := stReadProxied(t, d); h == nil || h.TransportProtocol != proxyproto.UDPv4 || h.SourceAddr.String() != "198.51.100.10:7000" || string(body) != "over v4" {
		t.Fatalf("the backend got %q; want an IPv4 header naming 198.51.100.10:7000, then the payload", d)
	}

	stUDPExchange("127.0.0.1", addr, stUDPDatagramWithProxy(t, "[2001:db8::7]:7000", "[2001:db8::1]:443", []byte("over v6")), 50*time.Millisecond)
	d, ok = stWaitGot(got, 2*time.Second)
	if !ok {
		t.Fatal("the backend got nothing of the relay's IPv6 client")
	}
	h, body := stReadProxied(t, d)
	if h == nil || h.TransportProtocol != proxyproto.UDPv6 || h.SourceAddr.String() != "[2001:db8::7]:7000" || string(body) != "over v6" {
		t.Fatalf("the backend got %q; want an IPv6 header naming [2001:db8::7]:7000, then the payload", d)
	}
	// The listener's own address, the one the relay sent to, in its
	// IPv4-mapped form (to Go the same address).
	if ua, ok := h.DestinationAddr.(*net.UDPAddr); !ok || len(ua.IP) != net.IPv6len || ua.IP.String() != "127.0.0.1" || strconv.Itoa(ua.Port) != port {
		t.Errorf("the header's destination is %v; want the listener's address 127.0.0.1:%s as ::ffff:127.0.0.1", h.DestinationAddr, port)
	}
	if n := refused(); n != 0 {
		t.Errorf("%d sessions refused for want of a header, want none", n)
	}
}

// A reload turns send_proxy_v2 on while a session is open. The session has
// no header: it ends, and what the backend gets from then on has one. The
// same the other way round.
func TestUDP_ReloadThatChangesSendProxyEndsOpenSessions(t *testing.T) {
	stUDPEngines(t, udpTestUDP_ReloadThatChangesSendProxyEndsOpenSessions)
}

func udpTestUDP_ReloadThatChangesSendProxyEndsOpenSessions(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	mk := func(send bool) *config.Config {
		return &config.Config{Version: "2",
			Listeners: []config.Listener{{Name: "udp-in", Bind: addr, Protocol: "udp", Backend: "udp-be"}},
			Backends:  []config.Backend{{Name: "udp-be", Servers: []string{be}, SendProxyV2: send}},
		}
	}
	e := stStart(t, mk(false), nil)
	ended := stDropped(e, udpDropHeaderChanged)
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("before"))
	if d, ok := stWaitGot(got, 2*time.Second); !ok || string(d) != "before" {
		t.Fatalf("before the reload the backend got %q (%v)", d, ok)
	}

	// arrive sends until the backend has a datagram, and returns every
	// datagram the backend got meanwhile.
	arrive := func(payload string) [][]byte {
		t.Helper()
		var all [][]byte
		deadline := time.Now().Add(3 * time.Second)
		for len(all) == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("the backend got nothing of %q", payload)
			}
			c.Write([]byte(payload))
			for {
				d, ok := stWaitGot(got, 150*time.Millisecond)
				if !ok {
					break
				}
				all = append(all, d)
			}
		}
		return all
	}

	if err := e.Reload(mk(true)); err != nil {
		t.Fatal(err)
	}
	for _, d := range arrive("the header is wanted now") {
		h, body := stReadProxied(t, d)
		if h == nil {
			t.Fatalf("after the reload turned send_proxy_v2 on, the backend got a datagram without the header: %q", d)
		}
		if h.SourceAddr.String() != c.LocalAddr().String() || string(body) != "the header is wanted now" {
			t.Errorf("the header names %s, then %q; want %s, then the payload", h.SourceAddr, body, c.LocalAddr())
		}
	}
	if n := ended(); n != 1 {
		t.Errorf("%d sessions ended for the change, want 1", n)
	}

	if err := e.Reload(mk(false)); err != nil {
		t.Fatal(err)
	}
	for _, d := range arrive("no header is wanted now") {
		if h, _ := stReadProxied(t, d); h != nil || string(d) != "no header is wanted now" {
			t.Fatalf("after the reload turned send_proxy_v2 off, the backend got %q", d)
		}
	}
	if n := ended(); n != 2 {
		t.Errorf("%d sessions ended for the two changes, want 2", n)
	}
}

// A listener on every address has one socket for both families. A client
// that is the peer itself always gets its header there: an IPv4 client's
// names the listener's side as an IPv4 address too (the socket's own
// address, every address, has no family that could differ).
func TestUDP_DirectClientsOfBothFamiliesGetTheirHeader(t *testing.T) {
	stUDPEngines(t, udpTestUDP_DirectClientsOfBothFamiliesGetTheirHeader)
}

func udpTestUDP_DirectClientsOfBothFamiliesGetTheirHeader(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	probe.Close()
	be, got := stUDPBackend(t, nil)
	_, port, _ := net.SplitHostPort(stFreeUDPAddr(t))
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "wild-udp", Bind: ":" + port, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}, SendProxyV2: true}},
	}, nil)
	refused := stDropped(e, udpDropNoBackendHeader)
	for _, host := range []string{"::1", "127.0.0.1"} {
		stUDPExchange(host, net.JoinHostPort(host, port), []byte("from "+host), 50*time.Millisecond)
		d, ok := stWaitGot(got, 2*time.Second)
		if !ok {
			t.Fatalf("the backend got nothing of the client %s", host)
		}
		h, body := stReadProxied(t, d)
		if h == nil || string(body) != "from "+host {
			t.Fatalf("client %s: the backend got %q; want a header, then the payload", host, d)
		}
		src, _ := h.SourceAddr.(*net.UDPAddr)
		dst, _ := h.DestinationAddr.(*net.UDPAddr)
		if src == nil || dst == nil || !src.IP.Equal(net.ParseIP(host)) || (src.IP.To4() != nil) != (dst.IP.To4() != nil) || fmt.Sprint(dst.Port) != port {
			t.Errorf("client %s: the header names %v -> %v; want the client, and the listener's port in the client's family", host, h.SourceAddr, h.DestinationAddr)
		}
	}
	if n := refused(); n != 0 {
		t.Errorf("%d sessions refused for want of a header", n)
	}
}

// A session whose backend is never reached (its server's name is not
// found) has its line in the access log, and the line says so.
func TestUDP_SessionWithoutABackendIsRecordedAsNoRoute(t *testing.T) {
	stUDPEngines(t, func(t *testing.T) {
		lines := stAccessLog(t)
		addr := stFreeUDPAddr(t)
		stStart(t, &config.Config{
			Listeners: []config.Listener{{Name: "udp-in", Bind: addr, Protocol: "udp", Backend: "nowhere"}},
			Backends:  []config.Backend{{Name: "nowhere", Servers: []string{"no-such-host.invalid:9"}}},
		}, nil)
		stUDPExchange("127.0.0.1", addr, []byte("anyone"), 50*time.Millisecond)
		waitFor(t, "the session's line in the access log", func() bool {
			l := lines()
			return stLinesOf(l, "127.0.0.1", "no_route")+stLinesOf(l, "127.0.0.1", "ok") > 0
		})
		if l := lines(); stLinesOf(l, "127.0.0.1", "no_route") != 1 || stLinesOf(l, "127.0.0.1", "ok") != 0 {
			t.Errorf("the access log of a session whose backend was not reached: %q; want one line that says no_route", l)
		}
	})
}

// A session that is over is not among the engine's connections any more:
// nvelox stops without waiting for it.
func TestUDP_EndedSessionsAreNotWaitedFor(t *testing.T) {
	stUDPEngines(t, func(t *testing.T) {
		be, _ := stUDPBackend(t, stEchoReply)
		addr := stFreeUDPAddr(t)
		cfg := &config.Config{Version: "2",
			Listeners: []config.Listener{{Name: "udp-in", Bind: addr, Protocol: "udp", Backend: "be"}},
			Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
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
		select {
		case <-e.Ready():
		case err := <-done:
			stopped = true
			t.Fatalf("the engine did not start: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("the engine did not start")
		}
		var reply []byte
		for deadline := time.Now().Add(5 * time.Second); ; {
			if reply, err = stUDPExchange("127.0.0.1", addr, []byte("ping"), 500*time.Millisecond); err == nil || time.Now().After(deadline) {
				break
			}
		}
		if err != nil || string(reply) != "ping" {
			t.Fatalf("the echo through the listener: %q, %v", reply, err)
		}
		sessions := stUDPSessions(e)
		if len(sessions) == 0 {
			t.Fatal("no session")
		}
		for _, s := range sessions {
			s.Close()
		}
		waitFor(t, "the sessions to be over", func() bool { return len(stUDPSessions(e)) == 0 })
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
	})
}
