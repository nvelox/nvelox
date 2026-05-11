package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
	"nvelox/core/logging"
)

func init() {
	logging.Init("debug", "", "")
}

func startEchoServer(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}

	go func() {
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return l.Addr().String()
}

func getFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForPort(t *testing.T, port int) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for port %d", port)
}

func TestEndToEndTCP(t *testing.T) {
	// 1. Start Mock Backend
	backendAddr := startEchoServer(t)

	// 2. Setup Config
	proxyPort := getFreePort(t)
	// We need to release the port so nvelox can bind to it.
	// However, there is a race condition here. Ideally we bind to 0 in config,
	// but Config struct expects Port int.
	// We accept the small risk of race for this test.

	cfg := &config.Config{
		Server: config.ServerConfig{
			// No LogLevel here
		},
		Logging: config.LoggingConfig{
			Level: "debug",
		},
		Backends: []config.Backend{
			{
				Name:    "backend1",
				Servers: []string{backendAddr},
			},
		},
	}

	// 3. Start Engine
	engine := core.NewEngine(cfg)
	// Manually populate Listeners as main.go does
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "tcp-test",
			Protocol:       "tcp",
			Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Port:           proxyPort,
			Backend:         "backend1",
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// Engine.Start blocks
		if err := engine.Start(ctx); err != nil {
			// This might log error when context is canceled, which is fine
			t.Logf("Engine stopped/error: %v", err)
		}
	}()

	// Wait for proxy to bind
	waitForPort(t, proxyPort)

	// 4. Test Connection
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	msg := "Hello Nvelox Integration"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(buf[:n]) != msg {
		t.Errorf("Expected %q, got %q", msg, string(buf[:n]))
	}
}

func startUDPEchoServer(t *testing.T) string {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to start udp echo server: %v", err)
	}

	go func() {
		defer conn.Close()
		buf := make([]byte, 2048)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], remoteAddr)
		}
	}()
	return conn.LocalAddr().String()
}

func getFreeUDPPort(t *testing.T) int {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestEndToEndUDP(t *testing.T) {
	// t.Skip("UDP not yet supported in NBIO engine")
	backendAddr := startUDPEchoServer(t)
	proxyPort := getFreeUDPPort(t)

	cfg := &config.Config{
		Server: config.ServerConfig{},
		Logging: config.LoggingConfig{
			Level: "debug",
		},
		Backends: []config.Backend{
			{
				Name:    "backend-udp",
				Servers: []string{backendAddr},
			},
		},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "udp-test",
			Protocol:       "udp",
			Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Port:           proxyPort,
			Backend:         "backend-udp",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := engine.Start(ctx); err != nil {
			t.Logf("Engine stopped/error: %v", err)
		}
	}()

	// Wait a bit for UDP bind (no easy way to dial check like TCP)
	time.Sleep(500 * time.Millisecond)

	// Test Connection
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer conn.Close()

	msg := "Hello Nvelox UDP"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(buf[:n]) != msg {
		t.Errorf("Expected %q, got %q", msg, string(buf[:n]))
	}
}

func TestEndToEndMixed(t *testing.T) {
	// 1. Start Backends
	tcpBackendAddr := startEchoServer(t)
	udpBackendAddr := startUDPEchoServer(t)

	// 2. Get Free Ports
	tcpPort := getFreePort(t)
	udpPort := getFreeUDPPort(t)

	// 3. Configure
	cfg := &config.Config{
		Backends: []config.Backend{
			{Name: "backend-tcp", Balance: "roundrobin", Servers: []string{tcpBackendAddr}},
			{Name: "backend-udp", Balance: "roundrobin", Servers: []string{udpBackendAddr}},
		},
	}
	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{Name: "mix-tcp", Protocol: "tcp", Addr: fmt.Sprintf("127.0.0.1:%d", tcpPort), Port: tcpPort, Backend:         "backend-tcp"},
		{Name: "mix-udp", Protocol: "udp", Addr: fmt.Sprintf("127.0.0.1:%d", udpPort), Port: udpPort, Backend:         "backend-udp"},
	}

	// 4. Start
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)

	waitForPort(t, tcpPort)            // Wait for TCP at least
	time.Sleep(500 * time.Millisecond) // Wait for UDP

	// 5. Verify TCP
	c1, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	if err != nil {
		t.Fatal(err)
	}
	c1.Write([]byte("tcp-mix"))
	b1 := make([]byte, 1024)
	n1, err := c1.Read(b1)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1[:n1]) != "tcp-mix" {
		t.Error("TCP mix mismatch")
	}
	c1.Close()

	// 6. Verify UDP
	c2, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		t.Fatal(err)
	}
	c2.Write([]byte("udp-mix"))
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	b2 := make([]byte, 1024)
	n2, err := c2.Read(b2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b2[:n2]) != "udp-mix" {
		t.Error("UDP mix mismatch")
	}
	c2.Close()
}
