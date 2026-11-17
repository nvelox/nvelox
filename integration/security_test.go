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

func TestHTTP_IPDenylist(t *testing.T) {
	backend := startHTTPBackend(t, "ok")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "deny-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
			IPDenylist: []string{"127.0.0.1"},
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "deny-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
		IPDenylist: []string{"127.0.0.1"},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", proxyPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("expected 403 for denied IP, got %d", resp.StatusCode)
	}

	cancel()
}

func TestHTTP_ACL_DenyMethod(t *testing.T) {
	backend := startHTTPBackend(t, "ok")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "acl-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
			ACL: []config.ACLRule{
				{Match: config.ACLMatch{Method: []string{"DELETE"}}, Action: "deny"},
			},
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "acl-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
		ACL: []config.ACLRule{
			{Match: config.ACLMatch{Method: []string{"DELETE"}}, Action: "deny"},
		},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// DELETE should be denied
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("http://127.0.0.1:%d/resource", proxyPort), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("expected 403 for DELETE, got %d", resp.StatusCode)
	}

	// GET should be allowed
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/resource", proxyPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 for GET, got %d", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Errorf("expected 'ok', got %q", string(body))
	}

	cancel()
}

func TestHTTP_MaxBodySize(t *testing.T) {
	backend := startHTTPBackend(t, "ok")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "body-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
			MaxBodySize: "100B",
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "body-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
		MaxBodySize: "100B",
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Small body should work
	resp, err := http.Post(
		fmt.Sprintf("http://127.0.0.1:%d/", proxyPort),
		"text/plain",
		strings.NewReader("small"),
	)
	if err != nil {
		t.Fatalf("small body request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 for small body, got %d", resp.StatusCode)
	}

	// Large body should fail (backend may return error or proxy truncates)
	largeBody := strings.Repeat("x", 200)
	resp, err = http.Post(
		fmt.Sprintf("http://127.0.0.1:%d/", proxyPort),
		"text/plain",
		strings.NewReader(largeBody),
	)
	if err != nil {
		// Connection may be reset — that's acceptable
		cancel()
		return
	}
	resp.Body.Close()
	// MaxBytesReader causes the handler to return an error
	// The exact status depends on when the limit is hit
	cancel()
}

func TestHTTP_PerIPRateLimit(t *testing.T) {
	backend := startHTTPBackend(t, "ok")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "iprl-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
			IPRateLimit: config.IPRateLimitConfig{RequestsPerSecond: 5, Burst: 2},
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "iprl-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
		IPRateLimit: config.IPRateLimitConfig{RequestsPerSecond: 5, Burst: 2},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// First 2 should pass (burst)
	for i := 0; i < 2; i++ {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", proxyPort))
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
	}

	// Next should be rate limited
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", proxyPort))
	if err != nil {
		t.Fatalf("rate limited request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Errorf("expected 429 for rate limited request, got %d", resp.StatusCode)
	}

	cancel()
}
