package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/httpproxy"
)

// server.http3 reaches the HTTP/3 servers when the engine starts, and
// again at every reload: each key that a config names, and the default of
// each that it does not.
func TestEngine_HTTP3Limits(t *testing.T) {
	t.Cleanup(func() { httpproxy.SetHTTP3Limits(config.HTTP3Config{}.Resolve()) })
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(backend.Close)
	cfg := config.Config{
		Version: "2",
		Server: config.ServerConfig{ShutdownTimeout: "1s",
			HTTP3: config.HTTP3Config{MaxHeaderSize: "32KB", MaxSendMemory: "128MB"}},
		Listeners: []config.Listener{{Name: "site", Bind: stFreeTCPAddr(t), Protocol: "http", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{backend.Listener.Addr().String()}}},
	}
	exp, err := ExpandListeners(cfg.Listeners)
	if err != nil {
		t.Fatal(err)
	}
	// Something else, so that what is found after the start is the start's.
	httpproxy.SetHTTP3Limits(config.HTTP3Limits{MaxHeaderSize: 1, MaxSendBuffer: 1, MaxStreamReceiveWindow: 1, MaxConnectionReceiveWindow: 1})
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
	want := config.HTTP3Limits{MaxHeaderSize: 32 << 10, MaxSendBuffer: 16 << 20, MaxStreamReceiveWindow: 6 << 20,
		MaxConnectionReceiveWindow: 15 << 20, MaxSendMemory: 128 << 20, SocketBuffer: 4 << 20, HandshakesPerSource: 32}
	if got := httpproxy.HTTP3Limits(); got != want {
		t.Errorf("after the start the limits in use are %+v, want %+v", got, want)
	}

	perSource := 8
	cfg.Server.HTTP3 = config.HTTP3Config{MaxSendBuffer: "4MB", MaxStreamReceiveWindow: "1MB", MaxConnectionReceiveWindow: "2MB", MaxReceiveMemory: "64MB",
		SocketBuffer: "1MB", HandshakesPerSource: &perSource}
	if err := e.Reload(&cfg); err != nil {
		t.Fatalf("reload: %v", err)
	}
	want = config.HTTP3Limits{MaxHeaderSize: 64 << 10, MaxSendBuffer: 4 << 20, MaxStreamReceiveWindow: 1 << 20,
		MaxConnectionReceiveWindow: 2 << 20, MaxReceiveMemory: 64 << 20, SocketBuffer: 1 << 20, HandshakesPerSource: 8}
	if got := httpproxy.HTTP3Limits(); got != want {
		t.Errorf("after the reload the limits in use are %+v, want %+v", got, want)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("engine did not stop")
	}
}
