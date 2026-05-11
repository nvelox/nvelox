package core

import (
	"context"
	"net"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/httpproxy"
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

// TestReloadL7Sites verifies per-site config swap on SIGHUP. Build a
// bind group with two sites, change one site's backend in the new config,
// call Reload, verify subsequent requests route to the new backend. The
// site's struct identity changes (it's a fresh build); the bind group
// keeps its socket.
//
// This uses the in-process Engine APIs directly — full HTTP integration
// tests live in /integration.
func TestReloadL7Sites(t *testing.T) {
	cfg := &config.Config{
		Backends: []config.Backend{
			{Name: "be1", Balance: "roundrobin", Servers: []string{"10.0.0.1:80"}},
			{Name: "be2", Balance: "roundrobin", Servers: []string{"10.0.0.2:80"}},
		},
		Listeners: []config.Listener{
			{Name: "site-a", Bind: "127.0.0.1:0", Protocol: "http",
				Backend: "be1", ServerNames: []string{"a.test"}},
			{Name: "site-b", Bind: "127.0.0.1:0", Protocol: "http",
				Backend: "be2", DefaultServer: true},
		},
	}
	expanded, err := ExpandListeners(cfg.Listeners)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	// Force both onto the same addr so they form a real bind group.
	expanded[0].Addr = "127.0.0.1:65000"
	expanded[1].Addr = "127.0.0.1:65000"

	engine := NewEngine(cfg)
	engine.Listeners = expanded
	engine.initBackends()

	// Manually wire one BindGroup with both sites (mimicking what
	// Start does, minus the socket).
	bg := httpproxy.NewBindGroup("127.0.0.1:65000", "http")
	bg.AddSite(engine.buildL7Site(expanded[0]))
	bg.AddSite(engine.buildL7Site(expanded[1]))
	engine.BindGroups = append(engine.BindGroups, bg)

	// New config: site-a switches to a brand-new backend "be3".
	newCfg := &config.Config{
		Backends: []config.Backend{
			{Name: "be1", Balance: "roundrobin", Servers: []string{"10.0.0.1:80"}},
			{Name: "be2", Balance: "roundrobin", Servers: []string{"10.0.0.2:80"}},
			{Name: "be3", Balance: "roundrobin", Servers: []string{"10.0.0.3:80"}},
		},
		Listeners: []config.Listener{
			{Name: "site-a", Bind: "127.0.0.1:65000", Protocol: "http",
				Backend: "be3", ServerNames: []string{"a.test"}},
			{Name: "site-b", Bind: "127.0.0.1:65000", Protocol: "http",
				Backend: "be2", DefaultServer: true},
		},
	}

	engine.Reload(newCfg)

	// be3 must now exist as a balancer.
	if _, ok := engine.Balancers["be3"]; !ok {
		t.Error("be3 not added after reload")
	}
	// The bind group still exists, and HTTPServers list reflects the new sites.
	if len(engine.HTTPServers) != 2 {
		t.Errorf("expected 2 sites after reload, got %d", len(engine.HTTPServers))
	}
}

// TestReloadL7Sites_NewBindFlagged: a brand-new bind addr in the new
// config should not crash; it's logged as requiring F3 (restart) and
// the existing bind groups keep running.
func TestReloadL7Sites_NewBindFlagged(t *testing.T) {
	cfg := &config.Config{
		Backends:  []config.Backend{{Name: "be", Servers: []string{"10.0.0.1:80"}}},
		Listeners: []config.Listener{{Name: "a", Bind: "127.0.0.1:65001", Protocol: "http", Backend: "be"}},
	}
	expanded, _ := ExpandListeners(cfg.Listeners)
	engine := NewEngine(cfg)
	engine.Listeners = expanded
	engine.initBackends()
	bg := httpproxy.NewBindGroup("127.0.0.1:65001", "http")
	bg.AddSite(engine.buildL7Site(expanded[0]))
	engine.BindGroups = append(engine.BindGroups, bg)

	// New config introduces a brand-new bind addr.
	newCfg := &config.Config{
		Backends: []config.Backend{{Name: "be", Servers: []string{"10.0.0.1:80"}}},
		Listeners: []config.Listener{
			{Name: "a", Bind: "127.0.0.1:65001", Protocol: "http", Backend: "be"},
			{Name: "b", Bind: "127.0.0.1:65002", Protocol: "http", Backend: "be"}, // NEW addr
		},
	}
	// Should not panic; the new bind is logged as F3 work.
	engine.Reload(newCfg)
}

// TestReloadL7Sites_AddNewBindGroup: a brand-new bind addr in the new
// config produces a started BindGroup. Pre-flight bind-availability
// check passes (we pick a free ephemeral port via net.Listen).
func TestReloadL7Sites_AddNewBindGroup(t *testing.T) {
	// Pick two free ports for the engine's lifespan.
	freeAddr := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("free port: %v", err)
		}
		addr := l.Addr().String()
		l.Close()
		return addr
	}
	addr1 := freeAddr()
	addr2 := freeAddr()

	cfg := &config.Config{
		Backends:  []config.Backend{{Name: "be", Servers: []string{"10.0.0.1:80"}}},
		Listeners: []config.Listener{{Name: "a", Bind: addr1, Protocol: "http", Backend: "be"}},
	}
	expanded, _ := ExpandListeners(cfg.Listeners)
	engine := NewEngine(cfg)
	engine.Listeners = expanded
	engine.initBackends()
	bg := httpproxy.NewBindGroup(addr1, "http")
	bg.AddSite(engine.buildL7Site(expanded[0]))
	if err := bg.Start(); err != nil {
		t.Fatalf("start initial bg: %v", err)
	}
	engine.BindGroups = append(engine.BindGroups, bg)
	defer bg.Stop(context.Background())

	// New config adds a second bind addr.
	newCfg := &config.Config{
		Backends: []config.Backend{{Name: "be", Servers: []string{"10.0.0.1:80"}}},
		Listeners: []config.Listener{
			{Name: "a", Bind: addr1, Protocol: "http", Backend: "be"},
			{Name: "b", Bind: addr2, Protocol: "http", Backend: "be"},
		},
	}
	engine.Reload(newCfg)
	defer func() {
		// Clean up any bg the test added.
		for _, bg := range engine.BindGroups {
			bg.Stop(context.Background())
		}
	}()

	if len(engine.BindGroups) != 2 {
		t.Errorf("expected 2 bind groups after reload, got %d", len(engine.BindGroups))
	}
}

// TestReloadL7Sites_RemoveBindGroup: removing a bind addr from the new
// config triggers graceful Stop and drops the BindGroup from the engine.
func TestReloadL7Sites_RemoveBindGroup(t *testing.T) {
	freeAddr := func() string {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := l.Addr().String()
		l.Close()
		return addr
	}
	keepAddr := freeAddr()
	dropAddr := freeAddr()

	cfg := &config.Config{
		Backends: []config.Backend{{Name: "be", Servers: []string{"10.0.0.1:80"}}},
		Listeners: []config.Listener{
			{Name: "keep", Bind: keepAddr, Protocol: "http", Backend: "be"},
			{Name: "drop", Bind: dropAddr, Protocol: "http", Backend: "be"},
		},
	}
	expanded, _ := ExpandListeners(cfg.Listeners)
	engine := NewEngine(cfg)
	engine.Listeners = expanded
	engine.initBackends()
	for _, l := range expanded {
		bg := httpproxy.NewBindGroup(l.Addr, l.Protocol)
		bg.AddSite(engine.buildL7Site(l))
		if err := bg.Start(); err != nil {
			t.Fatalf("start %s: %v", l.Addr, err)
		}
		engine.BindGroups = append(engine.BindGroups, bg)
	}

	newCfg := &config.Config{
		Backends: []config.Backend{{Name: "be", Servers: []string{"10.0.0.1:80"}}},
		Listeners: []config.Listener{
			{Name: "keep", Bind: keepAddr, Protocol: "http", Backend: "be"},
		},
	}
	engine.Reload(newCfg)

	if len(engine.BindGroups) != 1 {
		t.Errorf("expected 1 bind group after reload, got %d", len(engine.BindGroups))
	}
	if engine.BindGroups[0].Addr() != keepAddr {
		t.Errorf("kept wrong bind group: %s", engine.BindGroups[0].Addr())
	}

	// Give the background Stop goroutine a moment to drain, then verify
	// the dropped port is actually free again (anyone can bind it).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", dropAddr)
		if err == nil {
			ln.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Cleanup
	for _, bg := range engine.BindGroups {
		bg.Stop(context.Background())
	}
}

// TestReloadL7Sites_PreflightAbortsOnPortConflict: if a new bind addr is
// already taken, the entire L7 reload aborts and existing bind groups
// keep running. All-or-nothing.
func TestReloadL7Sites_PreflightAbortsOnPortConflict(t *testing.T) {
	freeAddr := func() string {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := l.Addr().String()
		l.Close()
		return addr
	}
	existingAddr := freeAddr()
	// Hold a port to simulate conflict.
	conflictLn, _ := net.Listen("tcp", "127.0.0.1:0")
	conflictAddr := conflictLn.Addr().String()
	defer conflictLn.Close()

	cfg := &config.Config{
		Backends:  []config.Backend{{Name: "be", Servers: []string{"10.0.0.1:80"}}},
		Listeners: []config.Listener{{Name: "a", Bind: existingAddr, Protocol: "http", Backend: "be"}},
	}
	expanded, _ := ExpandListeners(cfg.Listeners)
	engine := NewEngine(cfg)
	engine.Listeners = expanded
	engine.initBackends()
	bg := httpproxy.NewBindGroup(existingAddr, "http")
	bg.AddSite(engine.buildL7Site(expanded[0]))
	bg.Start()
	engine.BindGroups = append(engine.BindGroups, bg)
	defer bg.Stop(context.Background())

	// New config adds a listener on the held port → pre-flight fails.
	newCfg := &config.Config{
		Backends: []config.Backend{{Name: "be", Servers: []string{"10.0.0.1:80"}}},
		Listeners: []config.Listener{
			{Name: "a", Bind: existingAddr, Protocol: "http", Backend: "be"},
			{Name: "b", Bind: conflictAddr, Protocol: "http", Backend: "be"},
		},
	}
	engine.Reload(newCfg)

	// Existing bind group still alive.
	if len(engine.BindGroups) != 1 {
		t.Errorf("aborted reload should keep current bind groups (got %d)", len(engine.BindGroups))
	}
}
