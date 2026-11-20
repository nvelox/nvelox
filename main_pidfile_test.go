package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// server.pid_file: the file holds this process's ID as soon as the server
// answers, and a clean stop takes it away again.
func TestRun_PidFile(t *testing.T) {
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer backend.Close()
	addr := freeAddr(t)
	pidPath := filepath.Join(dir, "nvelox.pid")
	configPath := filepath.Join(dir, "nvelox.yaml")
	cfg := fmt.Sprintf(`
version: '2'
server:
  pid_file: %q
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
`, pidPath, addr, backend.Listener.Addr().String())
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- run([]string{"nvelox", "-config", configPath}, ctx, nil) }()

	// Once a request is answered the ports are bound, and the pid file was
	// written before that.
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := client.Get("http://" + addr + "/")
		if err == nil {
			resp.Body.Close()
			break
		}
		select {
		case err := <-runErr:
			t.Fatalf("run ended before it served: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no answer within 15 s: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("the pid file while serving: %v", err)
	}
	if got, want := strings.TrimSpace(string(b)), strconv.Itoa(os.Getpid()); got != want {
		t.Fatalf("the pid file holds %q, want %q", got, want)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("run did not return within 60 s of the stop")
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("after the stop the pid file is still there (%v)", err)
	}
}

// A pid file that cannot be written stops the start with an error that
// names the setting: a supervisor told to read the file would wait for ever.
func TestRun_PidFileCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	addr := freeAddr(t)
	configPath := filepath.Join(dir, "nvelox.yaml")
	cfg := fmt.Sprintf(`
version: '2'
server:
  pid_file: %q
listeners:
  - name: site
    bind: %q
    protocol: http
    backend: be
backends:
  - name: be
    servers:
      - "127.0.0.1:1"
logging:
  level: error
`, filepath.Join(dir, "no-such-dir", "nvelox.pid"), addr)
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- run([]string{"nvelox", "-config", configPath}, ctx, nil) }()
	select {
	case err := <-runErr:
		if err == nil || !strings.Contains(err.Error(), "server.pid_file") {
			t.Fatalf("run returned %v, want an error naming server.pid_file", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run kept going with a pid file it could not write")
	}
}
