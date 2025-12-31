package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInit(t *testing.T) {
	// Test default level
	if err := Init("invalid", "", ""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if level != WarnLevel {
		t.Errorf("expected default level WarnLevel, got %v", level)
	}

	// Test explicit levels
	levels := map[string]Level{
		"debug":   DebugLevel,
		"info":    InfoLevel,
		"warning": WarnLevel,
		"error":   ErrorLevel,
	}

	for name, want := range levels {
		if err := Init(name, "", ""); err != nil {
			t.Errorf("Init(%s) failed: %v", name, err)
		}
		if level != want {
			t.Errorf("Init(%s): expected level %v, got %v", name, want, level)
		}
	}
}

func TestFileLogging(t *testing.T) {
	tmpDir := t.TempDir()
	accessPath := filepath.Join(tmpDir, "access.log")
	errorPath := filepath.Join(tmpDir, "error.log")

	// Init with files and Debug level
	if err := Init("debug", accessPath, errorPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Write logs
	Debug("debug msg")
	Info("info msg")
	Warn("warn msg")
	Error("error msg")
	Access("access msg")

	// Check Error Log content
	content, err := os.ReadFile(errorPath)
	if err != nil {
		t.Fatalf("failed to read error log: %v", err)
	}
	s := string(content)

	if !strings.Contains(s, "[DEBUG] debug msg") {
		t.Error("error log missing debug msg")
	}
	if !strings.Contains(s, "[INFO] info msg") {
		t.Error("error log missing info msg")
	}
	if !strings.Contains(s, "[WARN] warn msg") {
		t.Error("error log missing warn msg")
	}
	if !strings.Contains(s, "[ERR] error msg") {
		t.Error("error log missing error msg")
	}

	// Check Access Log content
	content, err = os.ReadFile(accessPath)
	if err != nil {
		t.Fatalf("failed to read access log: %v", err)
	}
	s = string(content)
	if !strings.Contains(s, "access msg") {
		t.Error("access log missing access msg")
	}
}

func TestLogLevelFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	errorPath := filepath.Join(tmpDir, "filtered.log")

	// Init with Error Level
	if err := Init("error", "", errorPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	Debug("should not appear")
	Info("should not appear")
	Warn("should not appear")
	Error("should appear")

	content, err := os.ReadFile(errorPath)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}
	s := string(content)

	if strings.Contains(s, "should not appear") {
		t.Error("log contained filtered messages")
	}
	if !strings.Contains(s, "should appear") {
		t.Error("log missing error message")
	}
}
