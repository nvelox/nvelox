package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

// captureStdout runs f and returns what it wrote to the standard output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	os.Stdout = old
	w.Close()
	return <-done
}

// --check accepts a config a start would accept, says so, exits 0, and
// touches nothing: no port is bound, no log file opened, no pid file
// written.
func TestRun_Check_ValidConfigTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	addr := freeAddr(t)
	pidPath := filepath.Join(dir, "nvelox.pid")
	accessLog := filepath.Join(dir, "access.log")
	configPath := filepath.Join(dir, "nvelox.yaml")
	cfg := fmt.Sprintf(`
version: '2'
server:
  pid_file: %q
  workers: 2
logging:
  level: error
  access_log: %q
listeners:
  - name: site
    bind: %q
    protocol: http
    backend: be
  - name: range
    bind: "127.0.0.1:39000-39002"
    protocol: tcp
    backend: be
backends:
  - name: be
    servers:
      - "127.0.0.1:1"
`, pidPath, accessLog, addr)
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	asked := -1
	oldSet := setSchedulerSlots
	setSchedulerSlots = func(n int) int { asked = n; return n }
	defer func() { setSchedulerSlots = oldSet }()

	// A check that went on to start the server would serve until its
	// context ends: the limit turns that into a failure instead of a test
	// that never returns.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var err error
	began := time.Now()
	out := captureStdout(t, func() {
		err = run([]string{"nvelox", "-check", "-config", configPath}, ctx, nil)
	})
	if err != nil {
		t.Fatalf("--check on a valid config: %v", err)
	}
	if d := time.Since(began); d > 10*time.Second {
		t.Fatalf("--check returned after %v: it must check and exit, not start the server", d)
	}
	if want := configPath + ": configuration is valid\n"; out != want {
		t.Fatalf("--check printed %q, want %q", out, want)
	}
	// The port is still free: nothing was bound.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("after --check the listener's address is taken: %v", err)
	}
	ln.Close()
	for _, p := range []string{pidPath, accessLog} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("--check created %s (%v)", p, err)
		}
	}
	if asked != -1 {
		t.Errorf("--check resized the scheduler to %d: it must change nothing", asked)
	}
}

// --check refuses what a start refuses, with the same words, and exits 1
// (run returns the error, main prints it and exits 1).
func TestRun_Check_Refuses(t *testing.T) {
	dir := t.TempDir()
	base := `
version: '2'
listeners:
  - name: site
    bind: "127.0.0.1:38080"
    protocol: http
    backend: be
%s
backends:
  - name: be
    servers:
      - "127.0.0.1:1"
%s
`
	cases := []struct {
		name, listener, backend string
		want                    []string
	}{
		{"a misspelled key", "    ip_denylst: []", "", []string{"unknown setting \"ip_denylst\"", "did you mean \"ip_denylist\"?"}},
		{"a setting nothing implements", "    zero_copy: true", "", []string{"zero_copy", "not implemented"}},
		{"a port range that is not one", "  - name: bad\n    bind: \"127.0.0.1:70000-70010\"\n    protocol: tcp\n    backend: be", "", []string{"bad"}},
		{"a backend_tls file that is not there", "", "    backend_tls:\n      enabled: true\n      ca_cert: " + filepath.Join(dir, "no-such-ca.pem"), []string{"backend be", "backend_tls"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(dir, "nvelox.yaml")
			if err := os.WriteFile(p, []byte(fmt.Sprintf(base, c.listener, c.backend)), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			out := captureStdout(t, func() { err = run([]string{"nvelox", "-check", "-config", p}, context.Background(), nil) })
			if err == nil {
				t.Fatalf("--check accepted the config; it printed %q", out)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the error %q does not contain %q", err, w)
				}
			}
			if strings.Contains(out, "valid") {
				t.Errorf("--check refused the config and still printed %q", out)
			}
		})
	}
}

// --check runs the checks of a start (core.Check) on the loaded config, not
// only the load: what they refuse, it refuses.
func TestRun_Check_RunsTheStartChecks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nvelox.yaml")
	cfg := "version: '2'\nlisteners:\n  - name: site\n    bind: \"127.0.0.1:38081\"\n    protocol: http\n    backend: be\nbackends:\n  - name: be\n    servers:\n      - \"127.0.0.1:1\"\n"
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	called := 0
	old := preflightConfig
	preflightConfig = func(c *config.Config) error {
		called++
		if len(c.Listeners) != 1 || c.Listeners[0].Name != "site" {
			t.Errorf("the start checks were given %+v, want the loaded config", c.Listeners)
		}
		return errors.New("refused by a check of the start")
	}
	defer func() { preflightConfig = old }()
	var err error
	out := captureStdout(t, func() { err = run([]string{"nvelox", "-check", "-config", p}, context.Background(), nil) })
	if called != 1 {
		t.Fatalf("--check ran the start checks %d times, want once", called)
	}
	if err == nil || !strings.Contains(err.Error(), "refused by a check of the start") {
		t.Fatalf("--check returned %v, want the start check's refusal", err)
	}
	if out != "" {
		t.Errorf("--check refused the config and printed %q", out)
	}
}

// server.workers: the scheduler is sized to it before the engine starts, so
// that many event loops run. Unset, nothing is resized.
func TestRun_Workers(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer backend.Close()
	for _, c := range []struct {
		name, server string
		want         int
	}{
		{"set to 3", "server:\n  workers: 3\n", 3},
		{"not set", "", -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			addr := freeAddr(t)
			configPath := filepath.Join(dir, "nvelox.yaml")
			cfg := fmt.Sprintf("version: '2'\n%slisteners:\n  - name: site\n    bind: %q\n    protocol: http\n    backend: be\nbackends:\n  - name: be\n    servers:\n      - %q\nlogging:\n  level: error\n",
				c.server, addr, backend.Listener.Addr().String())
			if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			asked := make(chan int, 4)
			oldSet := setSchedulerSlots
			setSchedulerSlots = func(n int) int { asked <- n; return n }
			defer func() { setSchedulerSlots = oldSet }()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() { runErr <- run([]string{"nvelox", "-config", configPath}, ctx, nil) }()
			client := &http.Client{Timeout: 5 * time.Second}
			deadline := time.Now().Add(15 * time.Second)
			for {
				resp, err := client.Get("http://" + addr + "/")
				if err == nil {
					resp.Body.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no answer within 15 s: %v", err)
				}
				time.Sleep(50 * time.Millisecond)
			}
			got := -1
			select {
			case got = <-asked:
			default:
			}
			if got != c.want {
				t.Errorf("the scheduler was sized to %d, want %d (-1: left alone)", got, c.want)
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
		})
	}
}
