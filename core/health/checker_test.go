package health

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
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

// localHeaderServer answers HTTP on connections that start with a PROXY
// protocol v2 LOCAL header, as a server set up for send_proxy_v2 does: any
// other connection is closed unanswered. It counts both kinds.
type localHeaderServer struct {
	addr              string
	withHeader, other atomic.Int64
}

func startLocalHeaderServer(t *testing.T) *localHeaderServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &localHeaderServer{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				hdr := make([]byte, len(localProxyHeader))
				if _, err := io.ReadFull(c, hdr); err != nil || !bytes.Equal(hdr, localProxyHeader) {
					s.other.Add(1)
					return
				}
				s.withHeader.Add(1)
				br := bufio.NewReader(c)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					code := http.StatusOK
					if req.URL.Path != "/health" {
						code = http.StatusInternalServerError
					}
					fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code))
				}
			}()
		}
	}()
	return s
}

// The HTTP checks of a send_proxy_v2 backend start with a LOCAL PROXY
// header: the backend expects a header on every connection, and a request
// without one would fail however healthy the server is. Its TCP checks
// send nothing, like any backend's.
func TestChecks_SendProxyV2(t *testing.T) {
	srv := startLocalHeaderServer(t)
	cfg := config.HealthCheckConfig{Active: config.ActiveHealthCheck{Type: "http", Path: "/health"}}

	with := NewChecker(cfg, &config.Backend{Name: "be", Servers: []string{srv.addr}, SendProxyV2: true})
	defer with.Stop()
	for i := 0; i < 3; i++ {
		if !with.checkHTTP(srv.addr, time.Second) {
			t.Fatalf("HTTP check %d of a send_proxy_v2 backend failed", i)
		}
	}
	if n := srv.other.Load(); n != 0 {
		t.Errorf("%d connections came without the header", n)
	}
	with.Config.Active.Path = "/bad"
	if with.checkHTTP(srv.addr, time.Second) {
		t.Errorf("HTTP check passed for a path the server answers 500")
	}
	// A TCP check connects and closes: it sends nothing, no header either.
	withHeader := srv.withHeader.Load()
	if !with.checkTCP(srv.addr, time.Second) {
		t.Errorf("TCP check of a send_proxy_v2 backend failed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for srv.other.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the server did not see the TCP check's connection end without a byte")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := srv.withHeader.Load(); n != withHeader {
		t.Errorf("the TCP check sent a header")
	}
	srv.other.Store(0)

	// The same server, checked as a backend without send_proxy_v2: no
	// header is sent, and the server does not answer.
	without := NewChecker(cfg, &config.Backend{Name: "be", Servers: []string{srv.addr}})
	defer without.Stop()
	if without.checkHTTP(srv.addr, 500*time.Millisecond) {
		t.Errorf("HTTP check without a header passed against a server that requires one")
	}
	if srv.other.Load() == 0 {
		t.Errorf("the check without send_proxy_v2 sent a header")
	}
}
