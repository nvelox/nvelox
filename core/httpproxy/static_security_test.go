package httpproxy

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/lb"
)

// TestStatic_NeverServesScriptSource: a .php / .phtml / .phar file is never
// sent as a file — not as a try_files fallback on a static-only route, not as
// a directory index, not in upper case, not through a symlink. With FastCGI
// on the route it runs; without, it is a 404.
func TestStatic_NeverServesScriptSource(t *testing.T) {
	root := phpDocRoot(t)
	if err := os.Symlink(filepath.Join(root, "index.php"), filepath.Join(root, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	fpm, addr := startFakeFPM(t)
	secrets := []string{"<?php", "S3CRET", "SUBSECRET", "ONLYSECRET", "UPPERSECRET"}

	example := example30Routes(root, addr)
	phpIndexFirst := example30Routes(root, addr)
	phpIndexFirst[3].Static.Index = []string{"index.php", "index.html"}
	noTryFiles := example30Routes(root, addr)
	noTryFiles[3].TryFiles = config.TryFilesConfig{}
	staticOnly := []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/"},
		Static: config.StaticConfig{Root: root, Index: []string{"index.php", "index.html"}}}}

	for _, tc := range []struct {
		name   string
		routes []config.RouteConfig
		target string
		code   int
		script string // SCRIPT_FILENAME PHP-FPM must run; "" = must not run
		body   string // expected in the response body
	}{
		// examples/30 route 2: static-only, fallback /index.php → routed to
		// the PHP route, which runs it.
		{"fallback on static-only route", example, "/sitemap.xml", 200, "index.php", ""},
		{"index.php first in index list", phpIndexFirst, "/sub/", 200, "sub/index.php", ""},
		{"directory index without try_files", noTryFiles, "/only/", 200, "only/index.php", ""},
		{"static-only route, direct", staticOnly, "/index.php", 404, "", ""},
		{"static-only route, upper case", staticOnly, "/UPPER.PHP", 404, "", ""},
		{"static-only route, symlink to a script", staticOnly, "/notes.txt", 404, "", ""},
		{"static-only route, index skips the script", staticOnly, "/sub/", 200, "", "sub index"},
		{"static-only route, index is only a script", staticOnly, "/only/", 404, "", ""},
	} {
		site := phpSite(tc.routes, nil, config.HeadersConfig{})
		before, _, _ := fpm.last()
		rec := serveRaw(site, tc.target)
		after, env, _ := fpm.last()
		for _, s := range secrets {
			if strings.Contains(rec.Body.String(), s) {
				t.Errorf("%s: GET %s leaked script source (%q): %q", tc.name, tc.target, s, rec.Body.String())
			}
		}
		if rec.Code != tc.code {
			t.Errorf("%s: GET %s → HTTP %d, want %d", tc.name, tc.target, rec.Code, tc.code)
		}
		switch {
		case tc.script == "" && after != before:
			t.Errorf("%s: GET %s ran %q", tc.name, tc.target, env["SCRIPT_FILENAME"])
		case tc.script != "" && (after == before || env["SCRIPT_FILENAME"] != filepath.Join(root, filepath.FromSlash(tc.script))):
			t.Errorf("%s: GET %s ran %q (calls %d→%d), want %s", tc.name, tc.target, env["SCRIPT_FILENAME"], before, after, tc.script)
		}
		if tc.body != "" && !strings.Contains(rec.Body.String(), tc.body) {
			t.Errorf("%s: GET %s body %q, want %q", tc.name, tc.target, rec.Body.String(), tc.body)
		}
	}
}

// TestStatic_NoContentSniffing: the static handler takes the Content-Type
// from the extension, application/octet-stream when unknown — an uploaded
// .md or extension-less file holding HTML is never served as text/html.
func TestStatic_NoContentSniffing(t *testing.T) {
	root := phpDocRoot(t)
	site := phpSite([]config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/"},
		Static: config.StaticConfig{Root: root}}}, nil, config.HeadersConfig{})

	for _, tc := range []struct{ target, want string }{
		{"/up/noext", "application/octet-stream"},
		{"/up/page.md", ""}, // whatever the mime table says, never text/html
		{"/app.css", "text/css; charset=utf-8"},
	} {
		rec := serveRaw(site, tc.target)
		ct := rec.Header().Get("Content-Type")
		if rec.Code != http.StatusOK {
			t.Errorf("%s: HTTP %d", tc.target, rec.Code)
		}
		if strings.HasPrefix(ct, "text/html") || (tc.want != "" && ct != tc.want) {
			t.Errorf("%s: Content-Type %q, want %q (never text/html)", tc.target, ct, tc.want)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options missing", tc.target)
		}
	}
}

// TestStatic_ExpiresOnlyOnCacheableResponses: a route's expires lands on
// 200/304-style answers only — never on a 404, nor on a backend error, and
// never over the backend's own Cache-Control.
func TestStatic_ExpiresOnlyOnCacheableResponses(t *testing.T) {
	root := phpDocRoot(t)
	site := phpSite([]config.RouteConfig{{Match: config.RouteMatch{PathRegex: `\.css$`},
		Static:   config.StaticConfig{Root: root},
		TryFiles: config.TryFilesConfig{Files: []string{"$uri"}, Fallback: "=404"},
		Expires:  "1y"}}, nil, config.HeadersConfig{})

	rec := serveRaw(site, "/app.css")
	if cc := rec.Header().Get("Cache-Control"); rec.Code != http.StatusOK || !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("/app.css: HTTP %d Cache-Control %q, want the route's expires", rec.Code, cc)
	}
	rec = serveRaw(site, "/missing.css")
	if rec.Code != http.StatusNotFound || rec.Header().Get("Cache-Control") != "" || rec.Header().Get("Expires") != "" {
		t.Errorf("/missing.css: HTTP %d Cache-Control %q Expires %q, want a 404 without caching headers",
			rec.Code, rec.Header().Get("Cache-Control"), rec.Header().Get("Expires"))
	}

	// Proxied route with expires.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/error":
			http.Error(w, "boom", http.StatusInternalServerError)
		case "/private":
			w.Header().Set("Cache-Control", "private, no-store")
			fmt.Fprint(w, "private")
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer backend.Close()
	target := strings.TrimPrefix(backend.URL, "http://")
	l := &ListenerConfig{Name: "edge", Addr: ":0", Protocol: "http", Routes: []config.RouteConfig{
		{Match: config.RouteMatch{PathPrefix: "/"}, Backend: "be", Expires: "1y"}}}
	proxy := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})},
		map[string]*config.Backend{"be": {Name: "be", Servers: []string{target}}}, nil, nil, nil, nil, nil)

	rec = serveRaw(proxy, "/page")
	if cc := rec.Header().Values("Cache-Control"); rec.Code != http.StatusOK || len(cc) != 1 || !strings.HasPrefix(cc[0], "public, max-age=") {
		t.Errorf("proxied /page: HTTP %d Cache-Control %q, want the route's expires once", rec.Code, cc)
	}
	rec = serveRaw(proxy, "/error")
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Cache-Control") != "" || rec.Header().Get("Expires") != "" {
		t.Errorf("proxied /error: HTTP %d Cache-Control %q Expires %q, want a 500 without caching headers",
			rec.Code, rec.Header().Get("Cache-Control"), rec.Header().Get("Expires"))
	}
	rec = serveRaw(proxy, "/private")
	if cc := rec.Header().Values("Cache-Control"); len(cc) != 1 || cc[0] != "private, no-store" || rec.Header().Get("Expires") != "" {
		t.Errorf("proxied /private: Cache-Control %q Expires %q, want the backend's private, no-store alone",
			cc, rec.Header().Get("Expires"))
	}
}

// TestExpires_ProxiedRouteKeepsUpgradeAndStreaming: on a proxied route with
// expires the response goes through the expires writer, which must pass
// Hijack (WebSocket) and Flush (streamed responses) through.
func TestExpires_ProxiedRouteKeepsUpgradeAndStreaming(t *testing.T) {
	expiresSite := func(target string) string {
		l := &ListenerConfig{Name: "edge", Addr: ":0", Protocol: "http", Routes: []config.RouteConfig{
			{Match: config.RouteMatch{PathPrefix: "/"}, Backend: "be", Expires: "1y"}}}
		s := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})},
			map[string]*config.Backend{"be": {Name: "be", Servers: []string{target}}}, nil, nil, nil, nil, nil)
		ts := httptest.NewServer(s)
		t.Cleanup(ts.Close)
		return ts.Listener.Addr().String()
	}

	ws := startWSBackend(t, nil, http.StatusSwitchingProtocols)
	conn, br, resp := wsUpgrade(t, expiresSite(ws.addr))
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WebSocket upgrade: status %d, want 101", resp.StatusCode)
	}
	assertEcho(t, conn, br)

	release := make(chan struct{})
	stream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "first\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(wsTestTimeout):
		}
		fmt.Fprint(w, "second\n")
	}))
	defer stream.Close()
	defer close(release)
	// The headers and the first chunk must arrive while the backend still
	// holds the response open: without Flush they sit in the server's buffer.
	url := "http://" + expiresSite(strings.TrimPrefix(stream.URL, "http://")) + "/events"
	first := make(chan string, 1)
	go func() {
		res, err := http.Get(url)
		if err != nil {
			first <- "error: " + err.Error()
			return
		}
		defer res.Body.Close()
		line, _ := bufio.NewReader(res.Body).ReadString('\n')
		first <- line
	}()
	select {
	case line := <-first:
		if line != "first\n" {
			t.Errorf("first streamed line = %q", line)
		}
	case <-time.After(wsTestTimeout / 2):
		t.Error("streamed response not flushed to the client while the backend held it open")
	}
}
