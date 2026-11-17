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
func TestUDPBackendSocketDFOff(t *testing.T) { stUDPEngines(t, udpTestUDPBackendSocketDFOff) }

func udpTestUDPBackendSocketDFOff(t *testing.T) {
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

			var sessions []stUDPSession
			for _, s := range stUDPSessions(e) {
				if s.HasBackend {
					sessions = append(sessions, s)
				}
			}
			if len(sessions) != 1 {
				t.Fatalf("%d sessions with a backend socket, want 1", len(sessions))
			}
			v, gerr := sessions[0].BackendSockopt(tc.level, tc.opt)
			if gerr != nil || v != tc.want {
				t.Fatalf("MTU_DISCOVER = %d (%v), want PMTUDISC_DONT (%d)", v, gerr, tc.want)
			}
		})
	}
}
