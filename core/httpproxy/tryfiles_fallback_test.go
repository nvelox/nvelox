package httpproxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nvelox/config"
	"nvelox/lb"
)

// TestTryFiles_FallbackServedBySameRoute: an SPA route whose try_files
// fallback is "/" serves its own index.html, also where "/" itself is routed
// to a backend (ngris-board's layout: "/" is the landing page of the API, the
// app's deep links are static). The fallback used to go through the router
// again and reached the backend.
func TestTryFiles_FallbackServedBySameRoute(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("spa-index"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "api")
	}))
	defer backend.Close()
	target := strings.TrimPrefix(backend.URL, "http://")
	l := &ListenerConfig{Name: "web", Addr: ":0", Protocol: "http", Backend: "api", Routes: []config.RouteConfig{
		{Match: config.RouteMatch{PathRegex: `^/(docs)?$`}, Backend: "api"},
		{Match: config.RouteMatch{PathRegex: `^/(login|b/[0-9]+(/[a-z]+)?)/?$`},
			Static:   config.StaticConfig{Root: root, Index: []string{"index.html"}},
			TryFiles: config.TryFilesConfig{Files: []string{"$uri"}, Fallback: "/"}},
	}}
	s := NewHTTPServer(l, map[string]lb.Balancer{"api": lb.NewRoundRobin([]string{target})},
		map[string]*config.Backend{"api": {Name: "api", Servers: []string{target}}}, nil, nil, nil, nil, nil)

	for _, p := range []string{"/login", "/b/12", "/b/12/board/"} {
		rec := serveRaw(s, p)
		if rec.Code != http.StatusOK || rec.Body.String() != "spa-index" {
			t.Errorf("%s: HTTP %d %q, want 200 with the SPA index", p, rec.Code, rec.Body.String())
		}
	}
	if rec := serveRaw(s, "/"); rec.Body.String() != "api" {
		t.Errorf("/: %q, want the backend", rec.Body.String())
	}
}
