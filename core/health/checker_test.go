package health

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
)

func init() {
	logging.Init("debug", "", "")
}

// mockTCPServer starts a listener and accepts connections until ctx is canceled.
// It returns the listener address.
func mockTCPServer(t *testing.T, ctx context.Context) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TCP server: %v", err)
	}

	go func() {
		defer l.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if tcpl, ok := l.(*net.TCPListener); ok {
					tcpl.SetDeadline(time.Now().Add(100 * time.Millisecond))
				}
				c, err := l.Accept()
				if err != nil {
					continue
				}
				c.Close()
			}
		}
	}()
	return l.Addr().String()
}

// mockHTTPServer starts an HTTP server and returns its address.
func mockHTTPServer(t *testing.T, handler http.Handler) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(l)
	return l.Addr().String(), func() { server.Close() }
}

func TestCheckTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := mockTCPServer(t, ctx)

	checker := NewChecker(config.HealthCheckConfig{
		Active: config.ActiveHealthCheck{
			Type: "tcp",
		},
	}, nil)

	// Test Success
	if !checker.checkTCP(addr, 100*time.Millisecond) {
		t.Errorf("checkTCP failed for active server")
	}

	// Test Failure (port closed, hopefully)
	// We just use a random high port that is likely closed
	closedAddr := "127.0.0.1:54321"
	if checker.checkTCP(closedAddr, 10*time.Millisecond) {
		t.Errorf("checkTCP succeeded for closed port")
	}
}

func TestCheckHTTP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	addr, closeFn := mockHTTPServer(t, handler)
	defer closeFn()

	checker := NewChecker(config.HealthCheckConfig{
		Active: config.ActiveHealthCheck{
			Type: "http",
			Path: "/health",
		},
	}, nil)

	// Test Success
	if !checker.checkHTTP(addr, 100*time.Millisecond) {
		t.Errorf("checkHTTP failed for active server")
	}

	// Test Failure (Wrong Path)
	checker.Config.Active.Path = "/bad"
	if checker.checkHTTP(addr, 100*time.Millisecond) {
		t.Errorf("checkHTTP succeeded for bad path (500)")
	}
}

func TestLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := mockTCPServer(t, ctx)

	backend := &config.Backend{
		Name:    "test-backend",
		Servers: []string{addr},
	}

	chkConfig := config.HealthCheckConfig{
		Active: config.ActiveHealthCheck{
			Type:     "tcp",
			Interval: "100ms",
			Timeout:  "50ms",
		},
	}

	checker := NewChecker(chkConfig, backend)

	statusCh := make(chan struct{})
	checker.OnStatusChange = func(server string, healthy bool) {
		if server == addr && healthy {
			close(statusCh)
		}
	}

	checker.Start()
	defer checker.Stop()

	// Wait for initial health check
	select {
	case <-statusCh:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for health check success")
	}

	// Verify internal state
	checker.mu.Lock()
	healthy := checker.status[addr]
	checker.mu.Unlock()

	if !healthy {
		t.Error("expected server to be marked healthy in map")
	}
}
