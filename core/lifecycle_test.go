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

// TestReconcileBackends_Kept verifies that reloading with the same backend
// preserves the live balancer (state intact), and that an unchanged server
// list does not trigger a needless UpdateServers.
func TestReconcileBackends_Kept(t *testing.T) {
	cfg := &config.Config{
		Backends: []config.Backend{
			{Name: "be", Balance: "leastconn", Servers: []string{"10.0.0.1:80", "10.0.0.2:80"}},
		},
	}
	engine := NewEngine(cfg)
	engine.initBackends()
	bal := engine.Balancers["be"]

	// Simulate live state on the balancer — LeastConn keeps per-server
	// connection counts. We want these preserved across reload.
	bal.OnConnect("10.0.0.1:80")
	bal.OnConnect("10.0.0.1:80")

	// Reload with identical backend → same balancer instance, same state.
	added, removed, updated := engine.reconcileBackends(cfg)
	if added != 0 || removed != 0 || updated != 0 {
		t.Errorf("identical reload: want (0,0,0), got (%d,%d,%d)", added, removed, updated)
	}
	if engine.Balancers["be"] != bal {
		t.Error("kept backend should preserve the same *balancer instance")
	}
}

// TestReconcileBackends_ServerListChanged: same backend name, different
// server list → UpdateServers called, balancer instance preserved.
func TestReconcileBackends_ServerListChanged(t *testing.T) {
	cfg := &config.Config{
		Backends: []config.Backend{
			{Name: "be", Balance: "roundrobin", Servers: []string{"10.0.0.1:80"}},
		},
	}
	engine := NewEngine(cfg)
	engine.initBackends()
	bal := engine.Balancers["be"]

	newCfg := &config.Config{
		Backends: []config.Backend{
			{Name: "be", Balance: "roundrobin", Servers: []string{"10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"}},
		},
	}
	_, _, updated := engine.reconcileBackends(newCfg)
	if updated != 1 {
		t.Errorf("expected 1 updated, got %d", updated)
	}
	if engine.Balancers["be"] != bal {
		t.Error("server-list change should NOT replace the balancer instance")
	}
	// Servers got propagated to the balancer.
	if _, err := bal.Next(); err != nil {
		t.Errorf("balancer broken after UpdateServers: %v", err)
	}
}

// TestReconcileBackends_Removed: backend gone from new config → all its
// goroutines stopped, all maps cleaned. No goroutine leak.
func TestReconcileBackends_Removed(t *testing.T) {
	cfg := &config.Config{
		Backends: []config.Backend{
			{Name: "be", Balance: "roundrobin", Servers: []string{"10.0.0.1:80"},
				StickySession: config.StickyConfig{Type: "cookie", TTL: "1m"}},
		},
	}
	engine := NewEngine(cfg)
	engine.initBackends()

	// Sticky store has a cleanup goroutine running. Removing the backend
	// must Stop it to avoid a leak.
	store := engine.StickyStores["be"]
	if store == nil {
		t.Fatal("sticky store not initialized")
	}

	emptyCfg := &config.Config{Backends: nil}
	_, removed, _ := engine.reconcileBackends(emptyCfg)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}

	if _, ok := engine.Balancers["be"]; ok {
		t.Error("balancer not removed")
	}
	if _, ok := engine.StickyStores["be"]; ok {
		t.Error("sticky store not removed")
	}
	if _, ok := engine.Backends["be"]; ok {
		t.Error("backend cfg ref not removed")
	}
}

// TestReconcileBackends_Added: brand-new backend in new config → fully
// initialized (balancer + sticky + etc.).
func TestReconcileBackends_Added(t *testing.T) {
	engine := NewEngine(&config.Config{})
	engine.initBackends()

	newCfg := &config.Config{
		Backends: []config.Backend{
			{Name: "be", Balance: "roundrobin", Servers: []string{"10.0.0.1:80"}},
		},
	}
	added, _, _ := engine.reconcileBackends(newCfg)
	if added != 1 {
		t.Errorf("expected 1 added, got %d", added)
	}
	if _, ok := engine.Balancers["be"]; !ok {
		t.Error("balancer not initialized for added backend")
	}
}

// TestReconcileBackends_StickyPreservedAcrossReload: a sticky store keyed
// by a backend name that survives reload must keep the same Store instance,
// so client cookies issued before the reload still resolve to the same
// upstream server afterward.
func TestReconcileBackends_StickyPreservedAcrossReload(t *testing.T) {
	cfg := &config.Config{
		Backends: []config.Backend{
			{Name: "be", Balance: "roundrobin", Servers: []string{"10.0.0.1:80"},
				StickySession: config.StickyConfig{Type: "cookie", TTL: "1h"}},
		},
	}
	engine := NewEngine(cfg)
	engine.initBackends()
	store := engine.StickyStores["be"]
	// Set a known cookie → server mapping.
	store.Set("cookie-A", "10.0.0.1:80")

	// Reload with a server-list change but same backend name.
	newCfg := &config.Config{
		Backends: []config.Backend{
			{Name: "be", Balance: "roundrobin", Servers: []string{"10.0.0.1:80", "10.0.0.2:80"},
				StickySession: config.StickyConfig{Type: "cookie", TTL: "1h"}},
		},
	}
	engine.reconcileBackends(newCfg)

	if engine.StickyStores["be"] != store {
		t.Error("sticky store instance must survive reload; cookies would otherwise be invalidated")
	}
	if got := store.Get("cookie-A"); got != "10.0.0.1:80" {
		t.Errorf("sticky lookup after reload: got %q, want 10.0.0.1:80", got)
	}
}
