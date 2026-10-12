//go:build linux

package core

import (
	"context"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"nvelox/config"
)

// A backend UDP socket fragments rather than drops a datagram over a later hop's
// MTU: Don't Fragment is off (PMTUDISC_DONT) on the socket a UDP session dials to
// its backend. Runs the real path: engine, UDP listener, send_proxy_v2 backend,
// a 1,400 B datagram (the payload that was lost through the FIN edge).
func TestUDPBackendSocketDFOff(t *testing.T) {
	for _, tc := range []struct {
		name  string
		host  string
		level int
		opt   int
		want  int
	}{
		{"ipv4", "127.0.0.1", syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT},
		{"ipv6", "::1", syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IPV6_PMTUDISC_DONT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(tc.host)})
			if err != nil {
				if tc.name == "ipv6" {
					t.Skipf("no IPv6 loopback: %v", err)
				}
				t.Fatal(err)
			}
			defer backend.Close()

			probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(tc.host)})
			if err != nil {
				t.Fatal(err)
			}
			port := probe.LocalAddr().(*net.UDPAddr).Port
			probe.Close()

			e := NewEngine(&config.Config{Backends: []config.Backend{{
				Name: "be", Servers: []string{backend.LocalAddr().String()}, SendProxyV2: true,
			}}})
			e.DrainTimeout = 2 * time.Second
			e.Listeners = []*ListenerConfig{{
				Name: "udp", Protocol: "udp", Addr: net.JoinHostPort(tc.host, strconv.Itoa(port)), Port: port, Backend: "be",
			}}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { _ = e.Start(ctx); close(done) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("engine did not stop")
				}
			}()

			client, err := net.Dial("udp", net.JoinHostPort(tc.host, strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			// Resend until the backend sees one: the listener may not be up yet.
			payload := make([]byte, 1400)
			buf := make([]byte, 65535)
			deadline := time.Now().Add(5 * time.Second)
			for {
				if time.Now().After(deadline) {
					t.Fatal("the backend never received a datagram")
				}
				_, _ = client.Write(payload)
				backend.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				if _, _, err := backend.ReadFromUDP(buf); err == nil {
					break
				}
			}

			// Start assigns e.UDPPool under reloadMu; taking it orders this read after.
			e.reloadMu.Lock()
			pool := e.UDPPool
			e.reloadMu.Unlock()
			pool.mu.RLock()
			var conns []net.Conn
			for _, s := range pool.sessions {
				conns = append(conns, s.BackendConn)
			}
			pool.mu.RUnlock()
			if len(conns) != 1 {
				t.Fatalf("%d backend sessions, want 1", len(conns))
			}
			uc, ok := conns[0].(*net.UDPConn)
			if !ok {
				t.Fatalf("backend conn is %T, want *net.UDPConn", conns[0])
			}
			raw, err := uc.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var v int
			var gerr error
			if err := raw.Control(func(fd uintptr) {
				v, gerr = syscall.GetsockoptInt(int(fd), tc.level, tc.opt)
			}); err != nil {
				t.Fatal(err)
			}
			if gerr != nil || v != tc.want {
				t.Fatalf("MTU_DISCOVER = %d (%v), want PMTUDISC_DONT (%d)", v, gerr, tc.want)
			}
		})
	}
}
