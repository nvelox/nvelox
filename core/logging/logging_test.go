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

func TestSanitizeLogField(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"/api/v1/users", "/api/v1/users"},                                // clean ASCII fast path
		{"/path\nINJECTED", "/path\\nINJECTED"},                           // LF → \n literal
		{"/path\rINJECTED", "/path\\rINJECTED"},                           // CR → \r literal
		{"/path\tINJECTED", "/path\\tINJECTED"},                           // TAB → \t literal
		{"/path\r\nGET /secret", "/path\\r\\nGET /secret"},                // CRLF attack
		{"/path\x00\x01\x02", "/path???"},                                 // other controls → ?
		{"/path\x7f", "/path?"},                                           // DEL → ?
		{"normal text with space", "normal text with space"},              // space preserved
		{"unicode ☃ éclair", "unicode ☃ éclair"},                          // multibyte UTF-8 preserved
	}
	for _, c := range cases {
		got := SanitizeLogField(c.in)
		if got != c.want {
			t.Errorf("SanitizeLogField(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAccessHTTP_LogInjection writes an access log with CRLF-laced user input
// and verifies the output is a single line, not a forged second log entry.
func TestAccessHTTP_LogInjection(t *testing.T) {
	tmpDir := t.TempDir()
	accessPath := filepath.Join(tmpDir, "access.log")
	if err := Init("debug", accessPath, ""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Attacker-controlled path tries to inject a fake log entry.
	evilPath := "/legit\n10.0.0.1 - \"GET /admin HTTP/1.1\" 200 0 0.000ms -> backend"
	AccessHTTP("1.2.3.4", "GET", evilPath, "HTTP/1.1", 200, 0, 0.1, "upstream:80")

	content, err := os.ReadFile(accessPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// After sanitization the literal newline must have been replaced with \n.
	// The log write itself ends with one newline — so we expect exactly one
	// newline at the very end and none in the middle of the user field.
	s := strings.TrimRight(string(content), "\n")
	if strings.Contains(s, "\n") {
		t.Errorf("access log contains embedded newline (injection succeeded): %q", s)
	}
	if !strings.Contains(s, "\\n10.0.0.1") {
		t.Errorf("expected escaped '\\n10.0.0.1' in sanitized output, got: %q", s)
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
