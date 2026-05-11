package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
	"nvelox/core/logging"
)

func TestHTTP_AccessLogging(t *testing.T) {
	backend := startHTTPBackend(t, "log-test")
	proxyPort := getFreePort(t)

	// Setup access log to a temp file
	tmpDir := t.TempDir()
	accessLogPath := tmpDir + "/access.log"
	logging.Init("debug", accessLogPath, "")

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug", AccessLog: accessLogPath},
		Listeners: []config.Listener{{
			Name: "log-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "log-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Make a request
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/test-path", proxyPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// Give logging a moment to flush
	time.Sleep(100 * time.Millisecond)

	// Read access log
	data, err := os.ReadFile(accessLogPath)
	if err != nil {
		t.Fatalf("failed to read access log: %v", err)
	}

	logContent := string(data)
	if !strings.Contains(logContent, "GET") {
		t.Errorf("access log missing GET method, got: %s", logContent)
	}
	if !strings.Contains(logContent, "/test-path") {
		t.Errorf("access log missing /test-path, got: %s", logContent)
	}
	if !strings.Contains(logContent, "200") {
		t.Errorf("access log missing status 200, got: %s", logContent)
	}

	cancel()
}

func TestHTTP_ConfigurableTimeout(t *testing.T) {
	backend := startHTTPBackend(t, "timeout-ok")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "timeout-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
			Timeouts: config.TimeoutConfig{Connect: "2s", Read: "5s"},
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
			Timeouts: config.TimeoutConfig{Connect: "1s"},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "timeout-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
		Timeouts: config.TimeoutConfig{Connect: "2s", Read: "5s"},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Should work with valid backend
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", proxyPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
}
