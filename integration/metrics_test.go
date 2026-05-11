package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
)

func TestMetrics_Endpoint(t *testing.T) {
	backend := startHTTPBackend(t, "metrics-ok")
	proxyPort := getFreePort(t)
	metricsPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Bind:    fmt.Sprintf("127.0.0.1:%d", metricsPort),
			Path:    "/metrics",
		},
		Listeners: []config.Listener{{
			Name: "metrics-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "metrics-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	time.Sleep(300 * time.Millisecond)

	// Make a proxy request first
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", proxyPort))
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	resp.Body.Close()

	// Check metrics endpoint
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort))
	if err != nil {
		t.Fatalf("metrics request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %s", ct)
	}

	// Metrics endpoint should respond (may be empty if no metrics registered yet)
	_ = body // content verified by unit tests

	cancel()
}
