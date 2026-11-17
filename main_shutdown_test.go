package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// SIGINT and SIGTERM end the context run is given. A request that is being
// answered at that moment is answered in full, and run returns (the
// process ends) only then: before, it returned at once and took the
// request with it. Nothing new is accepted meanwhile, and with the last
// request answered run returns without waiting for its limit.
func TestRun_ShutdownLetsRequestsFinish(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	var arrived atomic.Int32
	answer := strings.Repeat("answered in full\n", 4096)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			arrived.Add(1)
			<-release
		}
		_, _ = io.WriteString(w, answer)
	}))
	defer backend.Close()
	// Whatever the test's outcome, the held request is let go before the
	// backend closes (which waits for it).
	letGo := sync.OnceFunc(func() { close(release) })
	defer letGo()

	addr := freeAddr(t)
	configPath := filepath.Join(dir, "nvelox.yaml")
	cfg := fmt.Sprintf(`
version: '2'
listeners:
  - name: site
    bind: %q
    protocol: http
    backend: be
backends:
  - name: be
    servers:
      - %q
logging:
  level: error
`, addr, backend.Listener.Addr().String())
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- run([]string{"nvelox", "-config", configPath}, ctx, nil) }()

	client := &http.Client{Timeout: 20 * time.Second}
	get := func(path string) (int, string, error) {
		resp, err := client.Get("http://" + addr + path)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), err
	}
	waitFor(t, "listener up", func() bool { code, _, err := get("/warmup"); return err == nil && code == http.StatusOK })

	type result struct {
		code int
		body string
		err  error
	}
	inFlight := make(chan result, 1)
	go func() {
		code, body, err := get("/slow")
		inFlight <- result{code, body, err}
	}()
	waitFor(t, "the request reaches the backend", func() bool { return arrived.Load() == 1 })

	// The signal.
	cancel()
	select {
	case err := <-runErr:
		t.Fatalf("run returned (%v) while a request was being answered", err)
	case <-time.After(500 * time.Millisecond):
	}
	// Nothing new is accepted while the request finishes.
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Errorf("the listener still accepts connections after the signal")
	}

	began := time.Now()
	letGo()
	r := <-inFlight
	if r.err != nil || r.code != http.StatusOK || r.body != answer {
		t.Fatalf("the request in flight: status %d, %d of %d bytes, err %v", r.code, len(r.body), len(answer), r.err)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("run: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatalf("run did not return within 8 s of its last request being answered")
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Errorf("run returned %v after its last request was answered: it waited for a limit, not for the request", d)
	}
}

// server.shutdown_timeout is how long that wait may last: with half a
// second, a request its backend never answers is closed after half a
// second and run returns, where it would otherwise wait ten.
func TestRun_ShutdownTimeoutSetting(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	var arrived atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/never" {
			arrived.Add(1)
			<-release
		}
	}))
	defer backend.Close()
	defer close(release)

	addr := freeAddr(t)
	configPath := filepath.Join(dir, "nvelox.yaml")
	cfg := fmt.Sprintf(`
version: '2'
server:
  shutdown_timeout: "500ms"
listeners:
  - name: site
    bind: %q
    protocol: http
    backend: be
backends:
  - name: be
    servers:
      - %q
logging:
  level: error
`, addr, backend.Listener.Addr().String())
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- run([]string{"nvelox", "-config", configPath}, ctx, nil) }()

	client := &http.Client{Timeout: 20 * time.Second}
	waitFor(t, "listener up", func() bool {
		resp, err := client.Get("http://" + addr + "/warmup")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	ended := make(chan error, 1)
	go func() {
		resp, err := client.Get("http://" + addr + "/never")
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil && resp.StatusCode == http.StatusOK {
				ended <- nil
				return
			}
		}
		ended <- fmt.Errorf("cut")
	}()
	waitFor(t, "the request reaches the backend", func() bool { return arrived.Load() == 1 })

	began := time.Now()
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("run: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("run did not return: server.shutdown_timeout of 500ms was not applied")
	}
	if d := time.Since(began); d < 400*time.Millisecond || d > 3*time.Second {
		t.Errorf("run returned %v after the signal, want about the 500ms of server.shutdown_timeout", d)
	}
	select {
	case err := <-ended:
		if err == nil {
			t.Error("the request the backend never answered was answered")
		}
	case <-time.After(5 * time.Second):
		t.Error("the client's request did not end with the wait")
	}
}
