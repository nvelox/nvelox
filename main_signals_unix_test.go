//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRun_SignalsReopenLogs (L3): the running process reopens its log files
// on SIGUSR1 (logrotate postrotate) and on SIGHUP (before the reload). After
// a rotate renamed the files away, new lines land in fresh files at the
// configured paths instead of the renamed ones.
func TestRun_SignalsReopenLogs(t *testing.T) {
	dir := t.TempDir()
	accessPath := filepath.Join(dir, "log", "access.log")
	errorPath := filepath.Join(dir, "log", "error.log")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

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
  level: info
  access_log: %q
  error_log: %q
`, addr, backend.Listener.Addr().String(), accessPath, errorPath)
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 4)
	runErr := make(chan error, 1)
	go func() { runErr <- run([]string{"nvelox", "-config", configPath}, ctx, sigCh) }()
	defer func() {
		cancel()
		select {
		case err := <-runErr:
			if err != nil {
				t.Errorf("run: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("run did not return after cancel")
		}
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	request := func(path string) bool {
		resp, err := client.Get("http://" + addr + path)
		if err != nil {
			return false
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	contains := func(path, s string) bool {
		b, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(b), s)
	}

	waitFor(t, "listener up", func() bool { return request("/warmup") })
	waitFor(t, "first access line", func() bool { return contains(accessPath, "/warmup") })

	for round, sig := range []os.Signal{syscall.SIGUSR1, syscall.SIGHUP} {
		// Rotate like logrotate: rename both files away, then signal.
		suffix := fmt.Sprintf(".%d", round+1)
		for _, p := range []string{accessPath, errorPath} {
			if err := os.Rename(p, p+suffix); err != nil {
				t.Fatal(err)
			}
		}
		sigCh <- sig
		marker := "log files reopened"
		if sig == syscall.SIGHUP {
			marker = "Reload complete"
		}
		waitFor(t, fmt.Sprintf("fresh error log after %v", sig), func() bool { return contains(errorPath, marker) })

		path := fmt.Sprintf("/after-%d", round+1)
		if !request(path) {
			t.Fatalf("request after %v failed", sig)
		}
		waitFor(t, fmt.Sprintf("access line in the fresh access log after %v", sig), func() bool { return contains(accessPath, path) })
		if contains(accessPath+suffix, path) {
			t.Errorf("after %v the access line still went to the rotated file", sig)
		}
		for _, p := range []string{accessPath, errorPath} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if m := fi.Mode().Perm(); m&^0o640 != 0 {
				t.Errorf("reopened %s: mode %04o, want at most 0640", filepath.Base(p), m)
			}
		}
	}
}
