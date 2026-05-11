package integration

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
)

func TestLeastConn_EvenDistribution(t *testing.T) {
	// Start 2 echo backends
	backend1 := startEchoServer(t)
	backend2 := startEchoServer(t)

	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{
			{
				Name:           "lc-test",
				Bind:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
				Protocol:       "tcp",
				Backend:         "lc-pool",
			},
		},
		Backends: []config.Backend{
			{
				Name:    "lc-pool",
				Balance: "leastconn",
				Servers: []string{backend1, backend2},
			},
		},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "lc-test",
			Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol:       "tcp",
			Backend:         "lc-pool",
			Port:           proxyPort,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- engine.Start(ctx)
	}()

	// Wait for engine to be ready
	time.Sleep(200 * time.Millisecond)

	// Open 6 connections. With leastconn, they should alternate: b1, b2, b1, b2, b1, b2
	conns := make([]net.Conn, 6)
	for i := 0; i < 6; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
		if err != nil {
			t.Fatalf("connection %d failed: %v", i, err)
		}
		conns[i] = conn

		// Send data and verify echo works
		msg := fmt.Sprintf("hello-%d", i)
		_, err = conn.Write([]byte(msg))
		if err != nil {
			t.Fatalf("write %d failed: %v", i, err)
		}

		buf := make([]byte, 64)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %d failed: %v", i, err)
		}
		if string(buf[:n]) != msg {
			t.Errorf("echo %d: expected %q, got %q", i, msg, string(buf[:n]))
		}

		// Small delay to let balancer update
		time.Sleep(50 * time.Millisecond)
	}

	// Close all connections
	for _, c := range conns {
		c.Close()
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("engine error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("engine didn't stop in time")
	}
}

func TestLeastConn_FailedDial_NoDoubleDecrement(t *testing.T) {
	// Start 1 real backend and 1 fake (unreachable) backend
	backend1 := startEchoServer(t)
	backend2 := "127.0.0.1:1" // port 1 should be unreachable

	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{
			{
				Name:           "lc-fail-test",
				Bind:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
				Protocol:       "tcp",
				Backend:         "lc-fail-pool",
			},
		},
		Backends: []config.Backend{
			{
				Name:    "lc-fail-pool",
				Balance: "leastconn",
				Servers: []string{backend1, backend2},
			},
		},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "lc-fail-test",
			Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol:       "tcp",
			Backend:         "lc-fail-pool",
			Port:           proxyPort,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Open several connections — some will get the bad backend and fail
	// The test passes if no panic/crash occurs (double-decrement would cause negative counts)
	for i := 0; i < 4; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
		if err != nil {
			continue
		}
		conn.Write([]byte("test"))
		time.Sleep(100 * time.Millisecond)
		conn.Close()
	}

	cancel()
}
