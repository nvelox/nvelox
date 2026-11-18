//go:build linux

package core

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nvelox/ngx"
	"github.com/nvelox/ngx/relay"
	"golang.org/x/sys/unix"

	"nvelox/config"
	"nvelox/proxy"
)

// Tests of UDP on the event loops (udpfast.go and the relay of the ngx
// module). What UDP listeners do, on either engine, is tested by the tests
// that run through stUDPEngines.

func udpFastOf(t *testing.T, e *Engine) *udpFast {
	t.Helper()
	e.reloadMu.Lock()
	u := e.udpFast
	e.reloadMu.Unlock()
	if u == nil || u.relay == nil {
		t.Fatal("the udp listeners are not on the event loops")
	}
	return u
}

// perLoopSessions returns how many live sessions each loop holds.
func perLoopSessions(u *udpFast) []int {
	out := make([]int, len(ngx.Default().Loops()))
	var mu sync.Mutex
	u.relay.Each(func(s *relay.UDPSession) {
		mu.Lock()
		out[s.Loop()]++
		mu.Unlock()
	})
	return out
}

// Every datagram of a client reaches the socket, and so the loop, that holds
// its session: thousands of clients have one session each however often
// they send, and every reply finds its client.
func TestUDPFast_OneSessionPerClient(t *testing.T) {
	be, _ := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	const clients = 1200
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "many", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, func(e *Engine) { e.udpMaxSessionsPerIP = clients + 10 })
	u := udpFastOf(t, e)
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	conns := make([]*net.UDPConn, clients)
	for i := range conns {
		c, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		conns[i] = c
	}
	buf := make([]byte, 64)
	for round := 0; round < 3; round++ {
		// In small groups: the test's one backend socket would drop a
		// burst of thousands.
		for from := 0; from < clients; from += 100 {
			for i := from; i < from+100; i++ {
				fmt.Fprintf(conns[i], "c%d-r%d", i, round)
			}
			for i := from; i < from+100; i++ {
				conns[i].SetReadDeadline(time.Now().Add(3 * time.Second))
				n, err := conns[i].Read(buf)
				if want := fmt.Sprintf("c%d-r%d", i, round); err != nil || string(buf[:n]) != want {
					t.Fatalf("client %d, round %d: got %q, %v; want %q", i, round, buf[:n], err, want)
				}
			}
		}
	}
	if total, _ := stHandler(e).udpSessions.count(netip.Addr{}); total != clients {
		t.Fatalf("%d sessions for %d clients", total, clients)
	}
	per := perLoopSessions(u)
	sum, used := 0, 0
	for _, n := range per {
		sum += n
		if n > 0 {
			used++
		}
	}
	if sum != clients {
		t.Fatalf("the loops hold %d sessions (%v), want %d", sum, per, clients)
	}
	if len(per) > 1 && used < 2 {
		t.Fatalf("%d clients all landed on one of %d loops: %v", clients, len(per), per)
	}
}

// A single port has one socket per loop; a range with at least as many
// ports as loops has one socket per port.
func TestUDPFast_SocketsPerPort(t *testing.T) {
	loops := len(ngx.Default().Loops())
	be, _ := stUDPBackend(t, stEchoReply)
	_, port, _ := net.SplitHostPort(stFreeUDPAddr(t))
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "one", Bind: "127.0.0.1:" + port, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	if n := udpFastOf(t, e).relay.Sockets(); n != loops {
		t.Fatalf("a single port has %d sockets on %d loops", n, loops)
	}

	// A free range of loops+2 ports.
	ports := loops + 2
	var first int
	for try := 0; ; try++ {
		if try == 50 {
			t.Skip("no free port range found")
		}
		_, p, _ := net.SplitHostPort(stFreeUDPAddr(t))
		fmt.Sscan(p, &first)
		free := first+ports < 65535
		for i := 0; free && i < ports; i++ {
			c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: first + i})
			if err != nil {
				free = false
			} else {
				c.Close()
			}
		}
		if free {
			break
		}
	}
	e2 := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "range", Bind: fmt.Sprintf("127.0.0.1:%d-%d", first, first+ports-1), Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	u := udpFastOf(t, e2)
	if n := u.relay.Sockets(); n != ports {
		t.Fatalf("a range of %d ports has %d sockets on %d loops", ports, n, loops)
	}
	// Every port of the range answers.
	for i := 0; i < ports; i++ {
		reply, err := stUDPExchange("127.0.0.1", fmt.Sprintf("127.0.0.1:%d", first+i), []byte("ping"), 2*time.Second)
		if err != nil || string(reply) != "ping" {
			t.Fatalf("port %d of the range: reply %q, %v", first+i, reply, err)
		}
	}
}

// A port another nvelox already serves is refused at start, although the
// sockets share their port (SO_REUSEPORT lets a second process of the same
// user bind it, which would then take a part of the datagrams).
func TestUDPFast_PortInUseRefused(t *testing.T) {
	be, _ := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	cfg := func() *config.Config {
		return &config.Config{
			Listeners: []config.Listener{{Name: "first", Bind: addr, Protocol: "udp", Backend: "be"}},
			Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
		}
	}
	stStart(t, cfg(), nil)

	second := cfg()
	exp, err := ExpandListeners(second.Listeners)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(second)
	e.Listeners = exp
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Start(ctx) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("Start: %v, want address already in use", err)
		}
	case <-e.Ready():
		t.Fatal("a second engine started on a port in use")
	case <-time.After(5 * time.Second):
		t.Fatal("neither failed nor started")
	}
	// The first one still answers.
	if reply, err := stUDPExchange("127.0.0.1", addr, []byte("still"), 2*time.Second); err != nil || string(reply) != "still" {
		t.Fatalf("the first engine after the refused start: %q, %v", reply, err)
	}
}

// A wildcard listener is one dual-stack port: IPv4 and IPv6 clients are
// served, and an IPv4 client is known by its IPv4 address.
func TestUDPFast_DualStackWildcard(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	probe.Close()
	be, _ := stUDPBackend(t, stEchoReply)
	_, port, _ := net.SplitHostPort(stFreeUDPAddr(t))
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "wild", Bind: ":" + port, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	for _, host := range []string{"127.0.0.1", "::1"} {
		c, err := net.Dial("udp", net.JoinHostPort(host, port))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("hello " + host))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != "hello "+host {
			t.Fatalf("client %s: reply %q, %v", host, buf[:n], err)
		}
	}
	seen := map[string]bool{}
	for _, s := range stUDPSessions(e) {
		seen[s.RealClientIP] = true
	}
	if !seen["127.0.0.1"] || !seen["::1"] || len(seen) != 2 {
		t.Fatalf("clients known as %v, want 127.0.0.1 and ::1", seen)
	}
}

// One client's datagrams keep their order through the receive batches and
// the replies' batches.
func TestUDPFast_OrderKept(t *testing.T) {
	be, _ := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "order", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 64)
	seq := 0
	for burst := 0; burst < 40; burst++ {
		for i := 0; i < 50; i++ {
			fmt.Fprintf(c, "%06d", seq+i)
		}
		for i := 0; i < 50; i++ {
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := c.Read(buf)
			if want := fmt.Sprintf("%06d", seq+i); err != nil || string(buf[:n]) != want {
				t.Fatalf("reply %d: got %q, %v; want %q", seq+i, buf[:n], err, want)
			}
		}
		seq += 50
	}
}

// Datagrams that arrive while a backend's host name is looked up are kept
// apart and sent one by one, in order, once the backend socket is open.
func TestUDPFast_DatagramsWaitApart(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	_, bport, _ := net.SplitHostPort(be)
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "named", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{"localhost:" + bport}}},
	}, nil)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const n = 8
	for i := 0; i < n; i++ {
		fmt.Fprintf(c, "datagram-%d", i)
	}
	for i := 0; i < n; i++ {
		d, ok := stWaitGot(got, 3*time.Second)
		if want := fmt.Sprintf("datagram-%d", i); !ok || string(d) != want {
			t.Fatalf("the backend's datagram %d is %q (ok=%v), want %q", i, d, ok, want)
		}
	}
}

// Relaying a datagram and its reply allocates nothing: the engine's work per
// datagram stays out of the garbage collector's way.
func TestUDPFast_NoAllocationPerDatagram(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates")
	}
	// The backend and the client use raw sockets, so that only the engine
	// could allocate.
	bfd, bport := rawUDPSocket(t)
	stop := make(chan struct{})
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		buf := make([]byte, 2048)
		connected := false
		for {
			var n int
			var err error
			if !connected {
				// The one session's first datagram: answer its socket only
				// from here on (reading a sender's address allocates).
				var from unix.Sockaddr
				if n, from, err = unix.Recvfrom(bfd, buf, 0); err == nil {
					if err = unix.Connect(bfd, from); err == nil {
						connected = true
					}
				}
			} else {
				n, err = unix.Read(bfd, buf)
			}
			if err != nil {
				select {
				case <-stop:
					return
				default:
					continue // the receive timeout, or a signal
				}
			}
			unix.Write(bfd, buf[:n])
		}
	}()
	defer func() { close(stop); <-backendDone }()
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Logging:   config.LoggingConfig{Level: "error"},
		Listeners: []config.Listener{{Name: "alloc", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{fmt.Sprintf("127.0.0.1:%d", bport)}}},
	}, nil)
	ua, _ := net.ResolveUDPAddr("udp", addr)
	cfd, _ := rawUDPSocket(t)
	if err := unix.Connect(cfd, &unix.SockaddrInet4{Port: ua.Port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	out, in := bytes.Repeat([]byte("x"), 512), make([]byte, 2048)
	roundTrips := func(n int) {
		for i := 0; i < n; i++ {
			if _, err := unix.Write(cfd, out); err != nil {
				t.Fatal(err)
			}
			for {
				_, err := unix.Read(cfd, in)
				if err == unix.EINTR {
					continue // the runtime's preemption signal
				}
				if err != nil {
					t.Fatalf("no reply to datagram %d: %v", i, err)
				}
				break
			}
		}
	}
	roundTrips(2000) // the session, its sockets, the loops' buffers
	const n = 20000
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	roundTrips(n)
	runtime.ReadMemStats(&after)
	if per := float64(after.Mallocs-before.Mallocs) / n; per > 0.05 {
		t.Fatalf("%.3f allocations per round trip (%d in %d), want none", per, after.Mallocs-before.Mallocs, n)
	}
}

// rawUDPSocket is a blocking UDP socket on 127.0.0.1 with a 2 s receive
// timeout, closed with the test.
func rawUDPSocket(t *testing.T) (fd, port int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	tv := unix.Timeval{Sec: 2}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	return fd, sa.(*unix.SockaddrInet4).Port
}

// FuzzUDPInbound feeds the PROXY v2 header of a relay's datagram arbitrary
// bytes.
func FuzzUDPInbound(f *testing.F) {
	var seed bytes.Buffer
	proxy.WriteProxyHeaderV2(&seed, &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 4000}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53})
	seed.WriteString("payload")
	f.Add(seed.Bytes())
	f.Add([]byte("\r\n\r\n\x00\r\nQUIT\n\x21\x12\x00\x0c"))
	f.Add([]byte("plain"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		hdr, consumed, isProxy := parseInboundProxyV2DatagramHeader(data)
		if consumed < 0 || consumed > len(data) {
			t.Fatalf("consumed %d of %d bytes", consumed, len(data))
		}
		if hdr != nil && (!isProxy || hdr.SourceAddr == nil) {
			t.Fatalf("a header without a source: isProxy=%v", isProxy)
		}
		if !isProxy && consumed != 0 {
			t.Fatalf("no header, yet %d bytes consumed", consumed)
		}
	})
}
