package core_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
)

// TestStart_BusyPortFails: a listener, the admin API or the metrics endpoint
// whose port is taken makes Start fail. Bind groups, the admin API and
// metrics used to bind in a goroutine, so nvelox started and ran on without
// the port (one error line); now every socket is bound before Start reports
// ready, which is also what lets the process give up root after it.
func TestStart_BusyPortFails(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	addr := busy.Addr().String()
	backends := []config.Backend{{Name: "be", Servers: []string{"127.0.0.1:1"}}}
	for name, cfg := range map[string]*config.Config{
		"http listener": {Version: "2", Backends: backends,
			Listeners: []config.Listener{{Name: "web", Bind: addr, Protocol: "http", Backend: "be"}}},
		"admin API": {Version: "2", Backends: backends,
			Admin: config.AdminConfig{Enabled: true, Bind: addr, APIKey: "k"}},
		"metrics": {Version: "2", Backends: backends,
			Metrics: config.MetricsConfig{Enabled: true, Bind: addr}},
	} {
		t.Run(name, func(t *testing.T) {
			exp, err := core.ExpandListeners(cfg.Listeners)
			if err != nil {
				t.Fatal(err)
			}
			e := core.NewEngine(cfg)
			e.Listeners = exp
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- e.Start(ctx) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), addr) && !strings.Contains(err.Error(), "address already in use") {
					t.Fatalf("Start with %s on a busy port: err %v, want a bind error", name, err)
				}
			case <-e.Ready():
				t.Fatalf("Start with %s on a busy port reported ready", name)
			case <-time.After(5 * time.Second):
				t.Fatal("Start neither failed nor got ready")
			}
		})
	}
}
