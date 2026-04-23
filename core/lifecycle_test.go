package core

import (
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
)

func init() {
	logging.Init("debug", "", "")
}

func TestEngine_Reload(t *testing.T) {
	cfg := &config.Config{
		Version: "2",
		Backends: []config.Backend{
			{Name: "be1", Balance: "roundrobin", Servers: []string{"10.0.0.1:80"}},
		},
	}

	engine := NewEngine(cfg)
	engine.initBackends()

	// Verify initial state
	if _, ok := engine.Balancers["be1"]; !ok {
		t.Fatal("expected balancer be1 after init")
	}

	// Reload with new config (different backend)
	newCfg := &config.Config{
		Version: "2",
		Backends: []config.Backend{
			{Name: "be1", Balance: "roundrobin", Servers: []string{"10.0.0.1:80", "10.0.0.2:80"}},
			{Name: "be2", Balance: "leastconn", Servers: []string{"10.0.0.3:80"}},
		},
	}

	engine.Reload(newCfg)

	if _, ok := engine.Balancers["be2"]; !ok {
		t.Error("expected balancer be2 after reload")
	}
	if len(engine.Backends) != 2 {
		t.Errorf("expected 2 backends after reload, got %d", len(engine.Backends))
	}
}

func TestEngine_GracefulDrain(t *testing.T) {
	cfg := &config.Config{Version: "2"}
	engine := NewEngine(cfg)
	engine.DrainTimeout = 1 * time.Second

	// Simulate active connections
	engine.ActiveConns.Add(2)

	// Release one immediately, one after delay
	go func() {
		engine.ActiveConns.Done()
	}()
	go func() {
		time.Sleep(100 * time.Millisecond)
		engine.ActiveConns.Done()
	}()

	// Wait for drain
	start := time.Now()
	done := make(chan struct{})
	go func() {
		engine.ActiveConns.Wait()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed > 500*time.Millisecond {
			t.Errorf("drain took too long: %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("drain timed out")
	}
}

func TestTimeoutConfig_Defaults(t *testing.T) {
	tc := config.TimeoutConfig{}

	if tc.ParseConnect() != 10*time.Second {
		t.Errorf("expected default connect timeout 10s, got %v", tc.ParseConnect())
	}
	if tc.ParseRead() != 0 {
		t.Errorf("expected default read timeout 0, got %v", tc.ParseRead())
	}
}

func TestTimeoutConfig_Custom(t *testing.T) {
	tc := config.TimeoutConfig{
		Connect: "5s",
		Read:    "30s",
		Write:   "15s",
		Idle:    "60s",
	}

	if tc.ParseConnect() != 5*time.Second {
		t.Errorf("expected connect 5s, got %v", tc.ParseConnect())
	}
	if tc.ParseRead() != 30*time.Second {
		t.Errorf("expected read 30s, got %v", tc.ParseRead())
	}
	if tc.ParseWrite() != 15*time.Second {
		t.Errorf("expected write 15s, got %v", tc.ParseWrite())
	}
	if tc.ParseIdle() != 60*time.Second {
		t.Errorf("expected idle 60s, got %v", tc.ParseIdle())
	}
}

func TestTimeoutConfig_InvalidFallback(t *testing.T) {
	tc := config.TimeoutConfig{Connect: "not-a-duration"}

	if tc.ParseConnect() != 10*time.Second {
		t.Errorf("expected fallback 10s for invalid connect, got %v", tc.ParseConnect())
	}
}
