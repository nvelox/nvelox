package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"nvelox/config"
)

func TestStaticHandler_ServeFile(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "test.html"), []byte("<h1>Hello</h1>"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "style.css"), []byte("body{}"), 0644)

	h := NewStaticHandler(config.StaticConfig{Root: tmpDir})

	// Serve existing file
	r := httptest.NewRequest("GET", "/test.html", nil)
	w := httptest.NewRecorder()
	if !h.ServeFile(w, r) {
		t.Error("expected file to be served")
	}
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Non-existent file
	r = httptest.NewRequest("GET", "/missing.html", nil)
	w = httptest.NewRecorder()
	if h.ServeFile(w, r) {
		t.Error("expected false for missing file")
	}
}

func TestStaticHandler_IndexFile(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte("index"), 0644)

	h := NewStaticHandler(config.StaticConfig{Root: tmpDir})

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	if !h.ServeFile(w, r) {
		t.Error("expected index.html to be served for /")
	}
}

func TestStaticHandler_DirectoryTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "safe.html"), []byte("safe"), 0644)

	h := NewStaticHandler(config.StaticConfig{Root: tmpDir})

	// Attempt directory traversal
	r := httptest.NewRequest("GET", "/../../../etc/passwd", nil)
	w := httptest.NewRecorder()
	if h.ServeFile(w, r) {
		t.Error("should not serve files outside root")
	}
}

func TestTryFiles_FindsFile(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "page.html"), []byte("page"), 0644)

	r := httptest.NewRequest("GET", "/page.html", nil)
	result := TryFiles(tmpDir, r, []string{"$uri"}, "=404")

	if result != "/page.html" {
		t.Errorf("expected /page.html, got %s", result)
	}
}

func TestTryFiles_FallsBack(t *testing.T) {
	tmpDir := t.TempDir()

	r := httptest.NewRequest("GET", "/missing", nil)
	result := TryFiles(tmpDir, r, []string{"$uri", "$uri/"}, "/index.php$is_args$args")

	if result != "/index.php" {
		t.Errorf("expected /index.php, got %s", result)
	}
}

func TestTryFiles_FallbackWithQuery(t *testing.T) {
	tmpDir := t.TempDir()

	r := httptest.NewRequest("GET", "/missing?q=test", nil)
	result := TryFiles(tmpDir, r, []string{"$uri"}, "/index.php$is_args$args")

	if result != "/index.php?q=test" {
		t.Errorf("expected /index.php?q=test, got %s", result)
	}
}

func TestTryFiles_StatusFallback(t *testing.T) {
	tmpDir := t.TempDir()

	r := httptest.NewRequest("GET", "/missing", nil)
	result := TryFiles(tmpDir, r, []string{"$uri"}, "=404")

	if result != "=404" {
		t.Errorf("expected =404, got %s", result)
	}
}

func TestSetExpires_Year(t *testing.T) {
	w := httptest.NewRecorder()
	SetExpires(w, "1y")

	cc := w.Header().Get("Cache-Control")
	if cc == "" {
		t.Error("expected Cache-Control header")
	}
	exp := w.Header().Get("Expires")
	if exp == "" {
		t.Error("expected Expires header")
	}
}

func TestSetExpires_NoCache(t *testing.T) {
	w := httptest.NewRecorder()
	SetExpires(w, "-1")

	cc := w.Header().Get("Cache-Control")
	if cc != "no-cache, no-store, must-revalidate" {
		t.Errorf("expected no-cache, got %s", cc)
	}
}

func TestSetExpires_Off(t *testing.T) {
	w := httptest.NewRecorder()
	SetExpires(w, "off")

	if w.Header().Get("Cache-Control") != "" {
		t.Error("expected no Cache-Control for 'off'")
	}
}

func TestSetExpires_Days(t *testing.T) {
	w := httptest.NewRecorder()
	SetExpires(w, "30d")

	cc := w.Header().Get("Cache-Control")
	if cc == "" {
		t.Error("expected Cache-Control")
	}
	// 30 days = 2592000 seconds
	if cc != "public, max-age=2592000" {
		t.Errorf("expected max-age=2592000, got %s", cc)
	}
}

func TestParseExpiresDuration(t *testing.T) {
	tests := []struct {
		input string
		want  int64 // seconds
	}{
		{"1y", 365 * 24 * 3600},
		{"30d", 30 * 24 * 3600},
		{"2h", 7200},
		{"10m", 600},
		{"30s", 30},
	}

	for _, tt := range tests {
		got := parseExpiresDuration(tt.input)
		if int64(got.Seconds()) != tt.want {
			t.Errorf("parseExpiresDuration(%q) = %v, want %ds", tt.input, got, tt.want)
		}
	}
}

func TestExpandTryFileVars(t *testing.T) {
	result := expandTryFileVars("/index.php$is_args$args", "/page", "?", "q=test")
	if result != "/index.php?q=test" {
		t.Errorf("expected /index.php?q=test, got %s", result)
	}

	result = expandTryFileVars("$uri", "/path", "", "")
	if result != "/path" {
		t.Errorf("expected /path, got %s", result)
	}
}

// Use http import
var _ = http.StatusOK
