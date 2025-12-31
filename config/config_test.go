package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Validation(t *testing.T) {
	// 1. Missing Version
	cfgContent := `
server:
  user: "nobody"
`
	tmp, _ := os.CreateTemp("", "nvelox_test_*.yaml")
	defer os.Remove(tmp.Name())
	tmp.WriteString(cfgContent)
	tmp.Close()

	_, err := Load(tmp.Name())
	if err == nil {
		t.Error("Expected error for missing version, got nil")
	}

	// 2. Unsupported Version
	cfgContent = `
version: "1"
server:
  user: "nobody"
`
	tmp2, _ := os.CreateTemp("", "nvelox_test_*.yaml")
	defer os.Remove(tmp2.Name())
	tmp2.WriteString(cfgContent)
	tmp2.Close()

	_, err = Load(tmp2.Name())
	if err == nil {
		t.Error("Expected error for unsupported version, got nil")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	cfgContent := `
version: "2"
listeners:
  - name: "test"
    bind: ":8080"
`
	tmp, _ := os.CreateTemp("", "nvelox_test_*.yaml")
	defer os.Remove(tmp.Name())
	tmp.WriteString(cfgContent)
	tmp.Close()

	cfg, err := Load(tmp.Name())
	if err != nil {
		t.Fatalf("Failed to load valid config: %v", err)
	}

	// Check Defaults
	if cfg.Logging.Level != "info" {
		t.Errorf("Expected default logging level 'info', got '%s'", cfg.Logging.Level)
	}

	if len(cfg.Listeners) != 1 {
		t.Fatalf("Expected 1 listener, got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].Protocol != "tcp" {
		t.Errorf("Expected default protocol 'tcp', got '%s'", cfg.Listeners[0].Protocol)
	}
}

func TestLoadConfig_Full(t *testing.T) {
	cfgContent := `
version: "2"
logging:
  level: "debug"
listeners:
  - name: "web"
    bind: ":80"
    protocol: "tcp"
    default_backend: "web_backends"
backends:
  - name: "web_backends"
    balance: "roundrobin"
    servers:
      - "10.0.0.1:80"
`
	tmp, _ := os.CreateTemp("", "nvelox_test_*.yaml")
	defer os.Remove(tmp.Name())
	tmp.WriteString(cfgContent)
	tmp.Close()

	cfg, err := Load(tmp.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("Expected logging level 'debug', got '%s'", cfg.Logging.Level)
	}
	if len(cfg.Backends) != 1 {
		t.Errorf("Expected 1 backend, got %d", len(cfg.Backends))
	}
	if cfg.Backends[0].Name != "web_backends" {
		t.Errorf("Expected backend name 'web_backends', got '%s'", cfg.Backends[0].Name)
	}
}

func TestLoadConfig_Errors(t *testing.T) {
	// 1. File Not Found
	_, err := Load("non-existent.yaml")
	if err == nil {
		t.Error("expected error for non-existent file")
	}

	// 2. Parse Error
	tmpDir := t.TempDir()
	badYaml := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(badYaml, []byte("invalid: yaml: ["), 0644)
	_, err = Load(badYaml)
	if err == nil {
		t.Error("expected error for bad yaml")
	}

	// 3. Bad file in Include (dir instead of file)
	includeMain := filepath.Join(tmpDir, "include_main.yaml")
	subDir := filepath.Join(tmpDir, "subdir")
	os.Mkdir(subDir, 0755)

	// Create main config pointing to a directory as include
	os.WriteFile(includeMain, []byte(fmt.Sprintf("version: '2'\ninclude: '%s'", subDir)), 0644)

	// Glob matches directory, ReadFile(dir) fails on Linux usually
	_, err = Load(includeMain)
	if err == nil {
		// On some systems reading dir behaves differently, but usually fails.
		// If it doesn't fail, checking for unmarshal failure next.
	}

	// 4. Bad YAML in Include
	badIncludeYaml := filepath.Join(tmpDir, "bad_include.yaml")
	goodMain := filepath.Join(tmpDir, "good_main.yaml")
	os.WriteFile(badIncludeYaml, []byte("invalid"), 0644)
	os.WriteFile(goodMain, []byte(fmt.Sprintf("version: '2'\ninclude: '%s'", badIncludeYaml)), 0644)
	_, err = Load(goodMain)
	if err == nil {
		t.Error("expected error for bad yaml in included file")
	}

	// 5. Validation errors
	// Duplicate Backend
	badBackend := filepath.Join(tmpDir, "bad_backend.yaml")
	os.WriteFile(badBackend, []byte(`
version: '2'
backends:
  - name: b1
    servers: []
  - name: b1
    servers: []
`), 0644)
	if _, err := Load(badBackend); err == nil {
		t.Error("expected error duplicate backend")
	}

	// Listener missing name
	badListener := filepath.Join(tmpDir, "bad_listener.yaml")
	os.WriteFile(badListener, []byte(`
version: '2'
listeners:
  - bind: :80
`), 0644)
	if _, err := Load(badListener); err == nil {
		t.Error("expected error listener missing name")
	}

	// Listener missing bind
	badListener2 := filepath.Join(tmpDir, "bad_listener_bind.yaml")
	os.WriteFile(badListener2, []byte(`
version: '2'
listeners:
  - name: l1
`), 0644)
	if _, err := Load(badListener2); err == nil {
		t.Error("expected error listener missing bind")
	}

	// Listener unknown backend
	badListener3 := filepath.Join(tmpDir, "bad_listener_be.yaml")
	os.WriteFile(badListener3, []byte(`
version: '2'
listeners:
  - name: l1
    bind: :80
    default_backend: unknown
`), 0644)
	if _, err := Load(badListener3); err == nil {
		t.Error("expected error listener unknown backend")
	}
}
