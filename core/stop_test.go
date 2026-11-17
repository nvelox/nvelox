package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
)

// stopEngine starts an engine with two HTTP bind addresses whose backend
// never answers, puts a request in flight on each, lets tweak change the
// running engine, stops it and returns how long the stop took.
func stopEngine(t *testing.T, shutdownTimeout string, tweak func(e *Engine, cfg config.Config)) time.Duration {
	t.Helper()
	release := make(chan struct{})
	var held atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		held.Add(1)
		<-release
	}))
	t.Cleanup(backend.Close)
	t.Cleanup(func() { close(release) }) // first: the handlers return, then the server closes

	addrs := []string{stFreeTCPAddr(t), stFreeTCPAddr(t)}
	cfg := config.Config{
		Version: "2",
		Server:  config.ServerConfig{ShutdownTimeout: shutdownTimeout},
		Listeners: []config.Listener{
			{Name: "site-a", Bind: addrs[0], Protocol: "http", Backend: "be"},
			{Name: "site-b", Bind: addrs[1], Protocol: "http", Backend: "be"},
		},
		Backends: []config.Backend{{Name: "be", Servers: []string{backend.Listener.Addr().String()}}},
	}
	exp, err := ExpandListeners(cfg.Listeners)
	if err != nil {
		t.Fatal(err)
	}
	first := cfg
	e := NewEngine(&first)
	e.Listeners = exp
	e.DrainTimeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Start(ctx) }()
	select {
	case <-e.Ready():
	case err := <-done:
		t.Fatalf("engine stopped during startup: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("engine did not start")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	for _, a := range addrs {
		go func() {
			if resp, err := client.Get("http://" + a + "/"); err == nil {
				resp.Body.Close()
			}
		}()
	}
	deadline := time.Now().Add(10 * time.Second)
	for held.Load() != int32(len(addrs)) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d requests reached the backend", held.Load(), len(addrs))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if tweak != nil {
		tweak(e, cfg)
	}

	began := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("engine did not stop")
	}
	return time.Since(began)
}

// When the engine stops, every HTTP bind address stops at the same time and
// under one limit, server.shutdown_timeout. Two addresses, each with a
// request its backend never answers: the engine has stopped after one
// limit, not after one per address, and not before the limit either (the
// requests were waited for).
func TestStop_BindGroupsShareOneLimit(t *testing.T) {
	const limit = time.Second
	d := stopEngine(t, "1s", nil)
	if d < limit-100*time.Millisecond {
		t.Errorf("the engine stopped after %v with requests in flight: it did not wait for them (server.shutdown_timeout %v)", d, limit)
	}
	if d > limit+700*time.Millisecond {
		t.Errorf("the engine took %v to stop two addresses: their limits (%v each) added up", d, limit)
	}
}

// A reload applies server.shutdown_timeout: started with a minute, reloaded
// with one second, the engine stops after the second.
func TestStop_ReloadAppliesShutdownTimeout(t *testing.T) {
	d := stopEngine(t, "1m", func(e *Engine, cfg config.Config) {
		if got := e.ShutdownTimeout(); got != time.Minute {
			t.Fatalf("before the reload the engine waits %v, want 1m", got)
		}
		cfg.Server.ShutdownTimeout = "1s"
		if err := e.Reload(&cfg); err != nil {
			t.Fatalf("reload: %v", err)
		}
	})
	if d < 900*time.Millisecond || d > 1700*time.Millisecond {
		t.Errorf("the engine took %v to stop, want the reloaded server.shutdown_timeout of 1s", d)
	}
}

// Not set, the wait is the default.
func TestStop_DefaultShutdownTimeout(t *testing.T) {
	if config.DefaultShutdownTimeout != 10*time.Second {
		t.Errorf("the default is %v, want 10s", config.DefaultShutdownTimeout)
	}
	if got := NewEngine(&config.Config{Version: "2"}).ShutdownTimeout(); got != config.DefaultShutdownTimeout {
		t.Errorf("an engine without server.shutdown_timeout waits %v, want the default %v", got, config.DefaultShutdownTimeout)
	}
}
