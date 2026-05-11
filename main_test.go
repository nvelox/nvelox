package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRun_Version(t *testing.T) {
	err := run([]string{"cmd", "-version"}, context.Background(), nil)
	if err != nil {
		t.Errorf("run -version failed: %v", err)
	}
}

func TestRun_BadFlags(t *testing.T) {
	err := run([]string{"cmd", "-unknown"}, context.Background(), nil)
	if err == nil {
		t.Error("run with unknown flag should fail")
	}
}

func TestRun_BadConfig(t *testing.T) {
	err := run([]string{"cmd", "-config", "non-existent.yaml"}, context.Background(), nil)
	if err == nil {
		t.Error("run with missing config should fail")
	}
}

func TestRun_Full(t *testing.T) {
	// 1. Create temporary config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.yaml")
	configContent := `
version: '2'
server:
  host: "127.0.0.1"
  port: 8080
listeners:
  - name: test-listener
    bind: "127.0.0.1:19876"
    protocol: tcp
    default_backend: backend1
backends:
  - name: backend1
    servers:
      - "127.0.0.1:9090"
logging:
  level: debug
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	// 2. Run with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 3. Expect nil error (graceful shutdown)
	err := run([]string{"cmd", "-config", configPath}, ctx, nil)
	if err != nil {
		t.Errorf("run failed: %v", err)
	}
}

func TestRun_Range(t *testing.T) {
	// Test range expansion
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "range.yaml")
	configContent := `
version: '2'
server:
  host: "127.0.0.1"
  port: 8080
listeners:
  - name: range-listener
    bind: "127.0.0.1:3000-3001"
    protocol: tcp
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := run([]string{"cmd", "-config", configPath}, ctx, nil)
	if err != nil {
		t.Errorf("run failed: %v", err)
	}
}

func TestRun_InvalidBind(t *testing.T) {
	// Test invalid bind address skipping
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")
	configContent := `
version: '2'
server:
  host: "127.0.0.1"
  port: 8080
listeners:
  - name: invalid-listener
    bind: "invalid"
    protocol: tcp
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should fail at config validation now
	err := run([]string{"cmd", "-config", configPath}, ctx, nil)
	if err == nil {
		t.Error("expected error for invalid bind address, got nil")
	}
}

func TestRun_EngineFail(t *testing.T) {
	// Test engine failure (e.g. unresolvable host)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "fail.yaml")
	configContent := `
version: '2'
listeners:
  - name: fail-listener
    bind: "127.0.0.1:-1"
    protocol: tcp
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond) // Longer timeout
	defer cancel()

	err := run([]string{"cmd", "-config", configPath}, ctx, nil)
	if err == nil {
		t.Error("run should fail due to engine start error")
	}
}
