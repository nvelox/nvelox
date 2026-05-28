package integration

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
)

// startUDPCaptureServer starts a UDP listener that records the first
// datagram it receives. Useful for asserting the wire-level format
// (e.g. whether a PROXY v2 header was prepended) without echo semantics.
func startUDPCaptureServer(t *testing.T) (addr string, received chan []byte) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	received = make(chan []byte, 4)
	go func() {
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			select {
			case received <- cp:
			default:
			}
		}
	}()
	return conn.LocalAddr().String(), received
}

// TestUDPSendProxyV2 verifies that with send_proxy_v2: true on the
// backend, datagrams arrive at the UDP backend prefixed with a valid
// PROXY v2 header carrying the original client address.
func TestUDPSendProxyV2(t *testing.T) {
	backendAddr, capture := startUDPCaptureServer(t)
	proxyPort := getFreeUDPPort(t)

	cfg := &config.Config{
		Server:  config.ServerConfig{},
		Logging: config.LoggingConfig{Level: "debug"},
		Backends: []config.Backend{{
			Name:        "udp-pp-backend",
			Servers:     []string{backendAddr},
			SendProxyV2: true,
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name:     "udp-pp",
		Protocol: "udp",
		Addr:     fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Port:     proxyPort,
		Backend:  "udp-pp-backend",
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = engine.Start(ctx) }()
	time.Sleep(500 * time.Millisecond)

	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	payload := []byte("hello-quic-or-similar")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-capture:
		// Validate PROXY v2 signature.
		sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
		if !bytes.HasPrefix(got, sig) {
			t.Fatalf("expected PROXY v2 signature, got % x...", got[:min(16, len(got))])
		}
		// verCmd byte at index 12 must be 0x21 (v2 + PROXY)
		if got[12] != 0x21 {
			t.Errorf("verCmd: got 0x%02x, want 0x21", got[12])
		}
		// famProto byte at index 13: high nibble 0x1 = INET, low nibble 0x2 = DGRAM
		if got[13] != 0x12 {
			t.Errorf("famProto: got 0x%02x, want 0x12 (INET/DGRAM)", got[13])
		}
		// addr block length at [14:16] = 12 for IPv4
		if got[14] != 0x00 || got[15] != 0x0C {
			t.Errorf("addr len: got 0x%02x%02x, want 0x000C", got[14], got[15])
		}
		// Original payload must follow the 28-byte header.
		if !bytes.Equal(got[28:], payload) {
			t.Errorf("payload mismatch:\n  got:  %q\n  want: %q", got[28:], payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never received a datagram")
	}
}

// TestUDPNoSendProxyV2 confirms that with send_proxy_v2 absent (default
// false), datagrams arrive raw — i.e. we did not regress the existing
// UDP forwarding path.
func TestUDPNoSendProxyV2(t *testing.T) {
	backendAddr, capture := startUDPCaptureServer(t)
	proxyPort := getFreeUDPPort(t)

	cfg := &config.Config{
		Server:  config.ServerConfig{},
		Logging: config.LoggingConfig{Level: "debug"},
		Backends: []config.Backend{{
			Name:    "udp-plain-backend",
			Servers: []string{backendAddr},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name:     "udp-plain",
		Protocol: "udp",
		Addr:     fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Port:     proxyPort,
		Backend:  "udp-plain-backend",
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = engine.Start(ctx) }()
	time.Sleep(500 * time.Millisecond)

	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	payload := []byte("plain-bytes")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-capture:
		if !bytes.Equal(got, payload) {
			t.Errorf("payload mismatch:\n  got:  %q\n  want: %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never received a datagram")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
