package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nvelox/config"
)

func autoindexSite(t *testing.T, autoindex bool) (string, *HTTPServer) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "www")
	for name, body := range map[string]string{
		"files/a.txt":                     "a",
		"files/b.bin":                     "bb",
		"files/.env":                      "SECRET=1",
		"files/run.php":                   "<?php // source",
		"files/sub/c.txt":                 "c",
		"files/<img src=x onerror=1>.txt": "x",
		"files/with index/index.html":     "INDEX",
		"outside/secret.txt":              "outside",
	} {
		dir := root
		if strings.HasPrefix(name, "outside/") {
			dir = base
		}
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "files", "a.txt"), filepath.Join(root, "files", "link-in.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "outside"), filepath.Join(root, "files", "link-out")); err != nil {
		t.Fatal(err)
	}
	l := &ListenerConfig{Name: "web", Addr: ":0", Protocol: "http", Routes: []config.RouteConfig{
		{Match: config.RouteMatch{PathPrefix: "/"}, Static: config.StaticConfig{Root: root, Autoindex: autoindex}}}}
	return root, NewHTTPServer(l, nil, map[string]*config.Backend{}, nil, nil, nil, nil, nil)
}

// TestAutoindex_ListsWhatTheRouteServes: a directory without an index
// file is listed when the route sets autoindex, with only what the route would
// serve: no dotfiles, no scripts, no symlink out of the root. Names are
// HTML-escaped, links URL-escaped, directories first, and the page runs no
// script.
func TestAutoindex_ListsWhatTheRouteServes(t *testing.T) {
	_, s := autoindexSite(t, true)
	rec := serveRaw(s, "/files/")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("GET /files/: HTTP %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	for _, want := range []string{`href="a.txt"`, `href="b.bin"`, `href="link-in.txt"`, `href="sub/"`, `href="with%20index/"`, `href="../"`,
		"&lt;img src=x onerror=1&gt;.txt", `href="%3Cimg%20src=x%20onerror=1%3E.txt"`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}
	for _, not := range []string{".env", "run.php", "link-out", "<img src=x"} {
		if strings.Contains(body, not) {
			t.Errorf("listing shows %q", not)
		}
	}
	if strings.Index(body, `href="sub/"`) > strings.Index(body, `href="a.txt"`) {
		t.Error("directories are not listed first")
	}
	if rec := serveRaw(s, "/files/with%20index/"); rec.Body.String() != "INDEX" {
		t.Errorf("a directory with an index file: %q, want the index", rec.Body.String())
	}
	if rec := serveRaw(s, "/files/link-out/"); rec.Code != http.StatusNotFound {
		t.Errorf("symlink out of the root: HTTP %d, want 404", rec.Code)
	}
	if rec := serveRaw(s, "/files"); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/files/" {
		t.Errorf("/files: HTTP %d Location %q, want 301 to /files/", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAutoindex_OffMethodsAndCap(t *testing.T) {
	_, off := autoindexSite(t, false)
	if rec := serveRaw(off, "/files/"); rec.Code != http.StatusNotFound {
		t.Errorf("autoindex off: HTTP %d, want 404", rec.Code)
	}
	_, s := autoindexSite(t, true)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/files/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /files/: HTTP %d, want 405", rec.Code)
	}
	old := autoindexMaxEntries
	autoindexMaxEntries = 2
	defer func() { autoindexMaxEntries = old }()
	if body := serveRaw(s, "/files/").Body.String(); !strings.Contains(body, "cut at 2 entries") {
		t.Errorf("over the cap: no truncation note in %q", body)
	}
}
