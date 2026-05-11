package integration

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
)

func TestRateLimit_RejectsExcess(t *testing.T) {
	backend := startEchoServer(t)
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{
			{
				Name:           "rl-test",
				Bind:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
				Protocol:       "tcp",
				Backend:         "rl-pool",
				RateLimit: config.RateLimitConfig{
					ConnectionsPerSecond: 5,
					Burst:                3,
				},
			},
		},
		Backends: []config.Backend{
			{
				Name:    "rl-pool",
				Balance: "roundrobin",
				Servers: []string{backend},
			},
		},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "rl-test",
			Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol:       "tcp",
			Backend:         "rl-pool",
			Port:           proxyPort,
			RateLimit: config.RateLimitConfig{
				ConnectionsPerSecond: 5,
				Burst:                3,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Open 10 connections rapidly — burst=3, so first 3 should succeed,
	// remaining should mostly be rejected
	var accepted atomic.Int64
	var rejected atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 1*time.Second)
			if err != nil {
				rejected.Add(1)
				return
			}
			defer conn.Close()

			// Try to write and read — if rate limited, conn will be closed immediately
			_, err = conn.Write([]byte("test"))
			if err != nil {
				rejected.Add(1)
				return
			}

			buf := make([]byte, 64)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, err = conn.Read(buf)
			if err != nil {
				rejected.Add(1)
				return
			}

			accepted.Add(1)
		}()
	}
	wg.Wait()

	a := accepted.Load()
	r := rejected.Load()

	// With burst=3 and rate=5/s, we expect 3-5 accepted and the rest rejected
	if a < 2 || a > 7 {
		t.Errorf("expected 2-7 accepted connections, got accepted=%d rejected=%d", a, r)
	}
	if r == 0 {
		t.Error("expected some connections to be rejected, but none were")
	}

	cancel()
}
