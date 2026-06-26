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
	if got := current.Load().level; got != WarnLevel {
		t.Errorf("expected default level WarnLevel, got %v", got)
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
		if got := current.Load().level; got != want {
			t.Errorf("Init(%s): expected level %v, got %v", name, want, got)
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
		{"/api/v1/users", "/api/v1/users"},                   // clean ASCII fast path
		{"/path\nINJECTED", "/path\\nINJECTED"},              // LF → \n literal
		{"/path\rINJECTED", "/path\\rINJECTED"},              // CR → \r literal
		{"/path\tINJECTED", "/path\\tINJECTED"},              // TAB → \t literal
		{"/path\r\nGET /secret", "/path\\r\\nGET /secret"},   // CRLF attack
		{"/path\x00\x01\x02", "/path???"},                    // other controls → ?
		{"/path\x7f", "/path?"},                              // DEL → ?
		{"normal text with space", "normal text with space"}, // space preserved
		{"unicode ☃ éclair", "unicode ☃ éclair"},             // multibyte UTF-8 preserved
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

	// Attacker-controlled path AND Host header both try to inject a fake
	// log entry — both must be sanitized.
	evilPath := "/legit\n10.0.0.1 - \"GET /admin HTTP/1.1\" 200 0 0.000ms -> backend"
	evilHost := "victim.example\nINJECTED"
	AccessHTTP("1.2.3.4", evilHost, "GET", evilPath, "HTTP/1.1", 200, 0, 0.1, "upstream:80")

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

// TestAccessL4_Format locks the L4 access-line format to exactly what the
// ngris-sentinel parser (l4Re) expects: "<ip> - l4 <proto>/<port> <status> <in> <out> <durMs>ms".
func TestAccessL4_Format(t *testing.T) {
	tmpDir := t.TempDir()
	accessPath := filepath.Join(tmpDir, "access.log")
	if err := Init("debug", accessPath, ""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	AccessL4("203.0.113.5", "tcp", 7000, "no_route", 0, 0, 0.4)
	content, err := os.ReadFile(accessPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := strings.TrimRight(string(content), "\n")
	want := "203.0.113.5 - l4 tcp/7000 no_route 0 0 0.400ms"
	if got != want {
		t.Errorf("AccessL4 line = %q, want %q", got, want)
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
