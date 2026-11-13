package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nvelox.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// TestValidation_AdminRequiresAPIKey: an enabled admin API without an API key
// (missing, empty or blank) fails to load; it used to start unauthenticated
// with only a warning.
func TestValidation_AdminRequiresAPIKey(t *testing.T) {
	for name, admin := range map[string]string{
		"missing": "admin:\n  enabled: true\n  bind: \"127.0.0.1:9091\"\n",
		"empty":   "admin:\n  enabled: true\n  bind: \"127.0.0.1:9091\"\n  api_key: \"\"\n",
		"blank":   "admin:\n  enabled: true\n  bind: \"127.0.0.1:9091\"\n  api_key: \"   \"\n",
		"no bind": "admin:\n  enabled: true\n",
	} {
		_, err := loadYAML(t, "version: \"2\"\n"+admin)
		if err == nil || !strings.Contains(err.Error(), "admin.api_key is required") {
			t.Errorf("%s: want an admin.api_key error, got %v", name, err)
		}
	}

	// Disabled admin needs no key.
	if _, err := loadYAML(t, "version: \"2\"\nadmin:\n  enabled: false\n"); err != nil {
		t.Errorf("disabled admin without a key: %v", err)
	}
}

// TestValidation_AdminProductionShape: a typical production shape — admin on
// a private or VPN address with a key — still loads, and so does an
// empty bind (loopback default at runtime).
func TestValidation_AdminProductionShape(t *testing.T) {
	for _, bind := range []string{"10.20.0.10:9091", "10.40.0.2:9091", "127.0.0.1:9091", "[::1]:9091", "localhost:9091", ":9091", ""} {
		cfg, err := loadYAML(t, "version: \"2\"\nadmin:\n  enabled: true\n  bind: \""+bind+"\"\n  api_key: \"0123456789abcdef0123456789abcdef\"\n")
		if err != nil {
			t.Errorf("bind %q: %v", bind, err)
			continue
		}
		if cfg.Admin.Bind != bind {
			t.Errorf("bind %q was rewritten to %q", bind, cfg.Admin.Bind)
		}
	}
}

// TestValidation_ControlPlaneBind: a malformed admin or metrics bind fails to
// load instead of failing (or binding somewhere unexpected) at runtime.
func TestValidation_ControlPlaneBind(t *testing.T) {
	for _, bind := range []string{"9091", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:http", "127.0.0.1:70000", "a b:9091"} {
		if _, err := loadYAML(t, "version: \"2\"\nadmin:\n  enabled: true\n  bind: \""+bind+"\"\n  api_key: \"k-0123456789abcdef\"\n"); err == nil || !strings.Contains(err.Error(), "admin.bind") {
			t.Errorf("admin bind %q: want an admin.bind error, got %v", bind, err)
		}
		if _, err := loadYAML(t, "version: \"2\"\nmetrics:\n  enabled: true\n  bind: \""+bind+"\"\n"); err == nil || !strings.Contains(err.Error(), "metrics.bind") {
			t.Errorf("metrics bind %q: want a metrics.bind error, got %v", bind, err)
		}
	}
	for _, bind := range []string{"", "127.0.0.1:9090", ":9090", "10.20.0.10:9090"} {
		if _, err := loadYAML(t, "version: \"2\"\nmetrics:\n  enabled: true\n  bind: \""+bind+"\"\n"); err != nil {
			t.Errorf("metrics bind %q: %v", bind, err)
		}
	}
}
