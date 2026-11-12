package httpproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
)

// fakeFPM is a FastCGI responder (net/http/fcgi) standing in for PHP-FPM.
// It records what nvelox sent: the non-HTTP_* params (SCRIPT_FILENAME,
// DOCUMENT_ROOT, ...) and the HTTP_* params, which net/http/fcgi turns back
// into request headers.
type fakeFPM struct {
	mu           sync.Mutex
	calls        int
	env          map[string]string
	header       http.Header
	status       string // extra "Status:" line, after net/http/fcgi's own
	cacheControl string // Cache-Control the "script" sets
}

func startFakeFPM(t *testing.T) (*fakeFPM, string) {
	t.Helper()
	f := &fakeFPM{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env := fcgi.ProcessEnv(r)
		f.mu.Lock()
		f.calls++
		f.env = env
		f.header = r.Header.Clone()
		status, cc := f.status, f.cacheControl
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		if cc != "" {
			w.Header().Set("Cache-Control", cc)
		}
		if status != "" {
			w.Header().Set("Status", status)
		}
		fmt.Fprintf(w, "FPM-RAN %s", env["SCRIPT_FILENAME"])
	}))
	t.Cleanup(func() { ln.Close() })
	return f, ln.Addr().String()
}

// last returns the call count and the params of the latest call.
func (f *fakeFPM) last() (int, map[string]string, http.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.env, f.header
}

func (f *fakeFPM) set(status, cacheControl string) {
	f.mu.Lock()
	f.status, f.cacheControl = status, cacheControl
	f.mu.Unlock()
}

// phpDocRoot builds <tmp>/www/html (the document root) and its sibling
// <tmp>/www/html-old — /var/www/html next to /var/www/html-old, the layout a
// prefix check without a separator boundary lets through.
func phpDocRoot(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "www", "html")
	files := map[string]string{
		"html/index.php":       "<?php $db_password = 'S3CRET'; // front controller\n",
		"html/private.php":     "<?php // private\n",
		"html/admin/maint.php": "<?php // admin maintenance\n",
		"html/sub/index.php":   "<?php $sub = 'SUBSECRET';\n",
		"html/sub/index.html":  "<html>sub index</html>\n",
		"html/only/index.php":  "<?php $only = 'ONLYSECRET';\n",
		"html/UPPER.PHP":       "<?php $upper = 'UPPERSECRET';\n",
		"html/up/a.txt":        "plain text\n",
		"html/up/page.md":      "<script>alert(1)</script>\n",
		"html/up/noext":        "<html><script>alert(1)</script>\n",
		"html/app.css":         "body{}\n",
		"html-old/x.php":       "<?php // sibling directory\n",
	}
	for name, body := range files {
		p := filepath.Join(base, "www", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// example30Routes are the routes of examples/30-php-fpm-fastcgi.yaml as
// shipped in v1.1.7 (d6400c3).
func example30Routes(root, fpm string) []config.RouteConfig {
	return []config.RouteConfig{
		{Match: config.RouteMatch{PathRegex: `\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map)$`},
			Static:   config.StaticConfig{Root: root},
			TryFiles: config.TryFilesConfig{Files: []string{"$uri"}, Fallback: "=404"},
			Expires:  "1y"},
		{Match: config.RouteMatch{PathRegex: `\.(xml|pdf|xlsx)$`},
			Static:   config.StaticConfig{Root: root},
			TryFiles: config.TryFilesConfig{Files: []string{"$uri"}, Fallback: "/index.php$is_args$args"},
			Expires:  "-1"},
		{Match: config.RouteMatch{PathRegex: `^/(index)\.php(/|$)`},
			FastCGI: config.FastCGIConfig{Pass: fpm, DocumentRoot: root, SplitPathInfo: `^(.+\.php)(/.*)$`}},
		{Match: config.RouteMatch{PathPrefix: "/"},
			Static:   config.StaticConfig{Root: root, Index: []string{"index.html", "index.php"}},
			TryFiles: config.TryFilesConfig{Files: []string{"$uri", "$uri/"}, Fallback: "/index.php$is_args$args"},
			FastCGI:  config.FastCGIConfig{Pass: fpm, DocumentRoot: root}},
	}
}

func phpSite(routes []config.RouteConfig, acl []config.ACLRule, headers config.HeadersConfig) *HTTPServer {
	l := &ListenerConfig{Name: "php-app", Addr: ":0", Protocol: "http", Routes: routes, ACL: acl, Headers: headers}
	return NewHTTPServer(l, nil, map[string]*config.Backend{}, nil, nil, nil, nil, nil)
}

// serveRaw runs one request through the site. httptest.NewRequest parses the
// target with http.ReadRequest, as the server does: percent-decoded, dot
// segments left in place.
func serveRaw(h http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
	return rec
}

// TestFastCGI_ScriptSelectionConfined: neither the query string nor the
// request path can make nvelox hand PHP-FPM a script the ACL denies, one in a
// sibling directory, or a file that is not an existing .php script.
func TestFastCGI_ScriptSelectionConfined(t *testing.T) {
	root := phpDocRoot(t)
	front := filepath.Join(root, "index.php")
	fpm, addr := startFakeFPM(t)
	deny := []config.ACLRule{
		{Match: config.ACLMatch{PathPrefix: "/admin"}, Action: "deny", Status: 404},
		{Match: config.ACLMatch{PathRegex: `^/private\.php$`}, Action: "deny"},
	}
	site := phpSite(example30Routes(root, addr), deny, config.HeadersConfig{})

	// A try_files fallback of /index.php$is_args$args must run the front
	// controller with the query as QUERY_STRING — never let the query pick
	// the script.
	for _, target := range []string{
		"/nope?/../admin/maint.php",
		"/nope?/../../html-old/x.php",
		"/nope?/../up/x.php/../a.txt",
		"/sitemap.xml?/../admin/maint.php",
	} {
		before, _, _ := fpm.last()
		rec := serveRaw(site, target)
		after, env, _ := fpm.last()
		if after == before {
			t.Errorf("%s: front controller not run (HTTP %d)", target, rec.Code)
			continue
		}
		if env["SCRIPT_FILENAME"] != front {
			t.Errorf("%s: SCRIPT_FILENAME = %q, want the front controller %q", target, env["SCRIPT_FILENAME"], front)
		}
	}

	// Dot segments in the request path reach the split_path_info route.
	// PHP-FPM may run the front controller at most (a path canonicalised
	// before routing lands on it) — never the admin script or one in the
	// sibling directory. Without canonicalisation the FastCGI layer answers
	// 400 itself (TestServeFastCGI_RefusesUnsafeScriptPath).
	for _, target := range []string{
		"/index.php/../admin/maint.php/x",
		"/index.php/%2e%2e/admin/maint.php/x",
		"/index.php/../../html-old/x.php/x",
	} {
		before, _, _ := fpm.last()
		rec := serveRaw(site, target)
		after, env, _ := fpm.last()
		if after != before && env["SCRIPT_FILENAME"] != front {
			t.Errorf("%s: PHP-FPM ran SCRIPT_FILENAME=%q (HTTP %d)", target, env["SCRIPT_FILENAME"], rec.Code)
		}
	}

	// A script outside the root, an ACL'd script reached through try_files,
	// a query inside a try_files candidate, and a fastcgi route without
	// document_root: PHP-FPM must not be called.
	sibling := []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/sib"},
		FastCGI: config.FastCGIConfig{Pass: addr, DocumentRoot: root, ScriptName: "/../html-old/x.php"}}}
	noDocRoot := []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/"},
		FastCGI: config.FastCGIConfig{Pass: addr}}}
	tryPHP := []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/"},
		Static:   config.StaticConfig{Root: root},
		TryFiles: config.TryFilesConfig{Files: []string{"$uri", "$uri.php"}, Fallback: "=404"},
		FastCGI:  config.FastCGIConfig{Pass: addr, DocumentRoot: root}}}
	argsCandidate := []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/"},
		Static:   config.StaticConfig{Root: root},
		TryFiles: config.TryFilesConfig{Files: []string{"$uri$is_args$args"}, Fallback: "=404"},
		FastCGI:  config.FastCGIConfig{Pass: addr, DocumentRoot: root}}}
	for _, tc := range []struct {
		site   *HTTPServer
		target string
		code   int
	}{
		{phpSite(sibling, nil, config.HeadersConfig{}), "/sib", http.StatusBadRequest},
		{phpSite(tryPHP, deny, config.HeadersConfig{}), "/private", http.StatusForbidden},
		{phpSite(argsCandidate, nil, config.HeadersConfig{}), "/nope?/../admin/maint.php", http.StatusNotFound},
		{phpSite(noDocRoot, nil, config.HeadersConfig{}), "/x.php", http.StatusInternalServerError},
	} {
		before, _, _ := fpm.last()
		rec := serveRaw(tc.site, tc.target)
		after, env, _ := fpm.last()
		if after != before {
			t.Errorf("%s: PHP-FPM ran SCRIPT_FILENAME=%q", tc.target, env["SCRIPT_FILENAME"])
		}
		if rec.Code != tc.code {
			t.Errorf("%s: HTTP %d, want %d", tc.target, rec.Code, tc.code)
		}
	}

	// Positive control: the front controller with PATH_INFO still runs.
	rec := serveRaw(site, "/index.php/some/path")
	if _, env, _ := fpm.last(); rec.Code != http.StatusOK || env["SCRIPT_FILENAME"] != front {
		t.Errorf("/index.php/some/path: HTTP %d SCRIPT_FILENAME=%q, want 200 %q", rec.Code, env["SCRIPT_FILENAME"], front)
	}
}

// TestFastCGI_OnlyExistingPHPInsideRoot: a FastCGI route hands PHP-FPM only an
// existing regular .php file that stays inside document_root with symlinks
// resolved — no other file type, no missing script for cgi.fix_pathinfo to
// walk back from, no symlink out of the root.
func TestFastCGI_OnlyExistingPHPInsideRoot(t *testing.T) {
	root := phpDocRoot(t)
	if err := os.Symlink(filepath.Join(filepath.Dir(root), "html-old", "x.php"), filepath.Join(root, "link.php")); err != nil {
		t.Fatal(err)
	}
	fpm, addr := startFakeFPM(t)
	site := phpSite([]config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/"},
		FastCGI: config.FastCGIConfig{Pass: addr, DocumentRoot: root}}}, nil, config.HeadersConfig{})

	for _, target := range []string{"/up/a.txt", "/missing.php", "/link.php", "/index.php/extra", "/up/", "/"} {
		before, _, _ := fpm.last()
		rec := serveRaw(site, target)
		after, env, _ := fpm.last()
		if after != before {
			t.Errorf("%s: PHP-FPM ran SCRIPT_FILENAME=%q", target, env["SCRIPT_FILENAME"])
		}
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: HTTP %d, want 404", target, rec.Code)
		}
	}

	rec := serveRaw(site, "/admin/maint.php")
	if _, env, _ := fpm.last(); rec.Code != http.StatusOK || env["SCRIPT_FILENAME"] != filepath.Join(root, "admin", "maint.php") {
		t.Errorf("/admin/maint.php: HTTP %d SCRIPT_FILENAME=%q, want it run", rec.Code, env["SCRIPT_FILENAME"])
	}
}

// TestFastCGI_HeaderMapping: X_Forwarded_For and friends cannot overwrite the
// HTTP_X_FORWARDED_FOR / HTTP_X_REAL_IP nvelox sets, Proxy never becomes
// HTTP_PROXY (httpoxy), and the listener / route request-header rules apply
// to FastCGI requests. Through a real server: Go's parser accepts '_' in
// header names.
func TestFastCGI_HeaderMapping(t *testing.T) {
	root := phpDocRoot(t)
	fpm, addr := startFakeFPM(t)
	routes := []config.RouteConfig{{Match: config.RouteMatch{PathRegex: `\.php$`},
		FastCGI: config.FastCGIConfig{Pass: addr, DocumentRoot: root},
		Headers: config.HeadersConfig{RequestAdd: map[string]string{"X-From-Route": "1"}}}}
	listenerRules := config.HeadersConfig{
		RequestSet:    map[string]string{"X-From-Listener": "yes"},
		RequestRemove: []string{"X-Strip-Me"},
	}
	ts := httptest.NewServer(phpSite(routes, nil, listenerRules))
	defer ts.Close()

	// Go map order decides which of two colliding params wins, so repeat.
	for i := 0; i < 64; i++ {
		req, _ := http.NewRequest("GET", ts.URL+"/index.php", nil)
		req.Header["X_Forwarded_For"] = []string{"6.6.6.6"}
		req.Header["X_Real_Ip"] = []string{"6.6.6.6"}
		req.Header["Proxy"] = []string{"http://evil.example:8080"}
		req.Header["X-Strip-Me"] = []string{"secret"}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		_, _, h := fpm.last()
		if got := h.Get("X-Forwarded-For"); got != "127.0.0.1" {
			t.Fatalf("request %d: HTTP_X_FORWARDED_FOR = %q, want 127.0.0.1", i, got)
		}
		if got := h.Get("X-Real-Ip"); got != "127.0.0.1" {
			t.Fatalf("request %d: HTTP_X_REAL_IP = %q, want 127.0.0.1", i, got)
		}
		if got := h.Get("Proxy"); got != "" {
			t.Fatalf("request %d: HTTP_PROXY = %q reached PHP", i, got)
		}
		if h.Get("X-From-Listener") != "yes" || h.Get("X-From-Route") != "1" || h.Get("X-Strip-Me") != "" {
			t.Fatalf("request %d: header rules not applied: listener=%q route=%q strip-me=%q", i,
				h.Get("X-From-Listener"), h.Get("X-From-Route"), h.Get("X-Strip-Me"))
		}
	}
}

// statusLog is a ResponseWriter that records WriteHeader codes instead of
// panicking on invalid ones as net/http does.
type statusLog struct {
	mu    sync.Mutex
	h     http.Header
	codes []int
	body  strings.Builder
}

func (s *statusLog) Header() http.Header { return s.h }

func (s *statusLog) WriteHeader(code int) {
	s.mu.Lock()
	s.codes = append(s.codes, code)
	s.mu.Unlock()
}

func (s *statusLog) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.codes) == 0 {
		s.codes = append(s.codes, http.StatusOK)
	}
	return s.body.Write(b)
}

// TestFastCGI_InvalidUpstreamStatus: an upstream Status outside 200-599 is
// answered with a 502 — the code never reaches net/http, which panics on a
// code below 100 in gofast's response goroutine and takes the whole process
// down.
func TestFastCGI_InvalidUpstreamStatus(t *testing.T) {
	root := phpDocRoot(t)
	fpm, addr := startFakeFPM(t)
	site := phpSite([]config.RouteConfig{{Match: config.RouteMatch{PathRegex: `\.php$`},
		FastCGI: config.FastCGIConfig{Pass: addr, DocumentRoot: root}}}, nil, config.HeadersConfig{})

	for _, status := range []string{"099", "100", "600"} {
		fpm.set(status, "")
		w := &statusLog{h: make(http.Header)}
		site.ServeHTTP(w, httptest.NewRequest("GET", "/index.php", nil))
		w.mu.Lock()
		codes, body := append([]int(nil), w.codes...), w.body.String()
		w.mu.Unlock()
		if len(codes) != 1 || codes[0] != http.StatusBadGateway {
			t.Errorf("Status: %s — WriteHeader calls %v, want exactly [502]", status, codes)
		}
		if strings.Contains(body, "FPM-RAN") {
			t.Errorf("Status: %s — upstream body forwarded with the 502: %q", status, body)
		}
	}

	// Through a real server: the client gets the 502 and the server keeps
	// serving.
	ts := httptest.NewServer(site)
	defer ts.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	fpm.set("099", "")
	resp, err := client.Get(ts.URL + "/index.php")
	if err != nil {
		t.Fatalf("Status 099: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Status 099: client got %d, want 502", resp.StatusCode)
	}
	fpm.set("", "")
	resp, err = client.Get(ts.URL + "/index.php")
	if err != nil {
		t.Fatalf("after Status 099: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("after Status 099: got %d, want 200", resp.StatusCode)
	}
}

// TestFastCGI_ExpiresOnlyOnCacheableResponses: a route's expires never makes
// a FastCGI error cacheable and never overrides the Cache-Control PHP chose.
func TestFastCGI_ExpiresOnlyOnCacheableResponses(t *testing.T) {
	root := phpDocRoot(t)
	fpm, addr := startFakeFPM(t)
	route := func(pass string) []config.RouteConfig {
		return []config.RouteConfig{{Match: config.RouteMatch{PathRegex: `\.php$`}, Expires: "1y",
			FastCGI: config.FastCGIConfig{Pass: pass, DocumentRoot: root}}}
	}
	site := phpSite(route(addr), nil, config.HeadersConfig{})

	fpm.set("", "private, no-store")
	rec := serveRaw(site, "/index.php")
	if cc := rec.Header().Values("Cache-Control"); rec.Code != http.StatusOK || len(cc) != 1 || cc[0] != "private, no-store" || rec.Header().Get("Expires") != "" {
		t.Errorf("PHP sent private, no-store: HTTP %d Cache-Control=%q Expires=%q", rec.Code, cc, rec.Header().Get("Expires"))
	}

	fpm.set("", "")
	rec = serveRaw(site, "/index.php")
	if cc := rec.Header().Get("Cache-Control"); rec.Code != http.StatusOK || !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("PHP sent no caching headers: HTTP %d Cache-Control=%q, want the route's expires", rec.Code, cc)
	}

	for _, tc := range []struct {
		name   string
		site   *HTTPServer
		target string
	}{
		{"missing script", site, "/missing.php"},
		{"PHP-FPM down", phpSite(route("127.0.0.1:1"), nil, config.HeadersConfig{}), "/index.php"},
	} {
		rec := serveRaw(tc.site, tc.target)
		if rec.Code < 400 || rec.Header().Get("Cache-Control") != "" || rec.Header().Get("Expires") != "" {
			t.Errorf("%s: HTTP %d Cache-Control=%q Expires=%q, want an error without caching headers",
				tc.name, rec.Code, rec.Header().Get("Cache-Control"), rec.Header().Get("Expires"))
		}
	}
}

// TestFastCGI_ParamsCannotReplaceScript (H1): a route's params cannot replace
// the script variables nvelox sets from the script it confined to
// document_root. The config load refuses such params; this route is built
// without it, so only the order in which the params are set stands between
// SCRIPT_FILENAME and the sibling directory.
func TestFastCGI_ParamsCannotReplaceScript(t *testing.T) {
	root := phpDocRoot(t)
	fpm, addr := startFakeFPM(t)
	routes := []config.RouteConfig{{Match: config.RouteMatch{PathRegex: `\.php$`},
		FastCGI: config.FastCGIConfig{Pass: addr, DocumentRoot: root, Params: map[string]string{
			"SCRIPT_FILENAME": filepath.Join(filepath.Dir(root), "html-old", "x.php"),
			"SCRIPT_NAME":     "/../html-old/x.php",
			"DOCUMENT_ROOT":   "/",
			"PATH_TRANSLATED": "/etc/passwd",
			"APP_ENV":         "prod",
		}}}}
	rec := serveRaw(phpSite(routes, nil, config.HeadersConfig{}), "/index.php")
	_, env, _ := fpm.last()
	if rec.Code != http.StatusOK || env == nil {
		t.Fatalf("HTTP %d, FPM params %v; want the front controller to run", rec.Code, env)
	}
	// SCRIPT_NAME is set last like the others, but net/http/fcgi (the fake
	// FPM) consumes it into the request and does not record it.
	want := map[string]string{
		"SCRIPT_FILENAME": filepath.Join(root, "index.php"),
		"DOCUMENT_ROOT":   root,
		"PATH_TRANSLATED": "",
		"APP_ENV":         "prod",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
}
