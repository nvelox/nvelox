package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadWithServer(t *testing.T, server string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nvelox.yaml")
	yaml := "version: '2'\n" + server + `listeners:
  - name: web
    bind: "127.0.0.1:8080"
    protocol: http
    backend: be
backends:
  - name: be
    servers: ["127.0.0.1:9000"]
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// server.shutdown_timeout: how long a stop waits for the requests in flight.
// Not set it is ten seconds; set, it is a duration greater than 0.
func TestShutdownTimeout(t *testing.T) {
	cfg, err := loadWithServer(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Server.ResolveShutdownTimeout(); got != 10*time.Second {
		t.Errorf("not set: %v, want 10s", got)
	}
	for val, want := range map[string]time.Duration{"3s": 3 * time.Second, "250ms": 250 * time.Millisecond, "2m": 2 * time.Minute} {
		cfg, err := loadWithServer(t, "server:\n  shutdown_timeout: \""+val+"\"\n")
		if err != nil {
			t.Errorf("%s: %v", val, err)
			continue
		}
		if got := cfg.Server.ResolveShutdownTimeout(); got != want {
			t.Errorf("%s: resolved to %v", val, got)
		}
	}
	// Zero would have to mean either "do not wait" or "wait without a
	// limit": it is refused, like what is not a duration.
	for _, val := range []string{"0", "0s", "-1s", "soon", "10"} {
		_, err := loadWithServer(t, "server:\n  shutdown_timeout: \""+val+"\"\n")
		if err == nil || !strings.Contains(err.Error(), "server.shutdown_timeout") {
			t.Errorf("%q: Load err = %v, want an error naming server.shutdown_timeout", val, err)
		}
	}
	// A config that did not come through Load never yields a wait of zero.
	for _, val := range []string{"0s", "-5s", "soon"} {
		if got := (ServerConfig{ShutdownTimeout: val}).ResolveShutdownTimeout(); got != DefaultShutdownTimeout {
			t.Errorf("unchecked %q resolves to %v, want the default", val, got)
		}
	}
}
