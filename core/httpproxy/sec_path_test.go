package httpproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
)

// H3: ACL path_prefix / path_regex and the router matched r.URL.Path as the
// client spelled it, with default allow, so "//admin/x", "/x/../admin/x",
// "/%2e/admin/x", "/./admin/x" and "/admin;x/x" went past a deny rule for
// /admin and the backend (which normalizes) served /admin/x. The path is now
// canonicalized once, before any decision, and that is also the path the
// backend receives; a deny rule also sees the form without ";params".

// secPathBackend records the paths the backend serves.
func secPathBackend(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.RawPath+"|"+r.URL.Path)
		mu.Unlock()
		io.WriteString(w, "PATH="+r.URL.Path)
	}))
	t.Cleanup(ts.Close)
	return ts, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

var secBypassPaths = []string{
	"/admin/x",
	"//admin/x",
	"/x/../admin/x",
	"/%2e/admin/x",
	"/%2E%2E/admin/x",
	"/./admin/x",
	"/admin;x/x",
	"/x/..;/admin/x",
	"/admin/./x",
	"///admin//x",
	"/admin%2fx",
}

// TestACL_PathBypassesDenied: every spelling of /admin/x is denied by a deny
// rule written as a path_prefix and as a path_regex.
func TestACL_PathBypassesDenied(t *testing.T) {
	for _, m := range []config.ACLMatch{{PathPrefix: "/admin/"}, {PathRegex: "^/admin(/|$)"}} {
		backend, seen := secPathBackend(t)
		l := &ListenerConfig{ACL: []config.ACLRule{{Match: m, Action: "deny", Status: http.StatusNotFound}}}
		_, addr := secSite(t, l, []string{secHost(backend)}, secOpts{})
		for _, p := range secBypassPaths {
			resp, _ := secRaw(t, addr, secGet(p, ""), 2*time.Second)
			if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 404") {
				t.Errorf("deny %+v: %s -> %q, want 404", m, p, secStatus(resp))
			}
		}
		if got := seen(); len(got) != 0 {
			t.Errorf("deny %+v: backend served %q", m, got)
		}
	}
}

// TestACL_AdminLockdownPattern: the production pattern — allow /admin from
// the management network, deny it (404) to everyone else — holds for every
// spelling, and still lets the management network in.
func TestACL_AdminLockdownPattern(t *testing.T) {
	backend, seen := secPathBackend(t)
	l := &ListenerConfig{
		TrustedProxies: []string{"127.0.0.1/32"},
		ACL: []config.ACLRule{
			{Match: config.ACLMatch{PathRegex: "^/admin(/|$)", SourceIP: []string{"10.10.10.0/24"}}, Action: "allow"},
			{Match: config.ACLMatch{PathRegex: "^/admin(/|$)"}, Action: "deny", Status: http.StatusNotFound},
		},
	}
	_, addr := secSite(t, l, []string{secHost(backend)}, secOpts{})
	for _, p := range secBypassPaths {
		resp, _ := secRaw(t, addr, secGet(p, "X-Forwarded-For: 203.0.113.9\r\n"), 2*time.Second)
		if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 404") {
			t.Errorf("internet client %s -> %q, want 404", p, secStatus(resp))
		}
	}
	if got := seen(); len(got) != 0 {
		t.Fatalf("backend served %q to an internet client", got)
	}
	resp, _ := secRaw(t, addr, secGet("/admin/x", "X-Forwarded-For: 10.10.10.7\r\n"), 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") || secBody(resp) != "PATH=/admin/x" {
		t.Fatalf("management client -> %q %q, want 200 PATH=/admin/x", secStatus(resp), secBody(resp))
	}
}

// TestACL_DenyAllCoversAbsoluteForm: a "deny everything" rule (path_prefix
// "/") also denies an absolute-form request without a path, whose path is
// empty (it reached the backend as "GET /"). (OPTIONS * never reaches the
// handler: net/http answers it.)
func TestACL_DenyAllCoversAbsoluteForm(t *testing.T) {
	backend, seen := secPathBackend(t)
	l := &ListenerConfig{ACL: []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/"}, Action: "deny", Status: http.StatusNotFound}}}
	_, addr := secSite(t, l, []string{secHost(backend)}, secOpts{})
	for _, req := range []string{
		"GET http://edge.test HTTP/1.1\r\nHost: edge.test\r\nConnection: close\r\n\r\n",
		"GET http://edge.test?x=1 HTTP/1.1\r\nHost: edge.test\r\nConnection: close\r\n\r\n",
	} {
		resp, _ := secRaw(t, addr, req, 2*time.Second)
		if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 404") {
			t.Errorf("%q -> %q, want 404", strings.SplitN(req, "\r\n", 2)[0], secStatus(resp))
		}
	}
	if got := seen(); len(got) != 0 {
		t.Fatalf("backend served %q", got)
	}
}

// TestPath_UpstreamGetsCanonicalPath: the backend receives the path that
// was checked (canonical, re-encoded), not the client's spelling.
func TestPath_UpstreamGetsCanonicalPath(t *testing.T) {
	backend, seen := secPathBackend(t)
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{})
	cases := map[string]string{
		"//a/./b/../c":   "|/a/c",
		"/%2e%2e/a/":     "|/a/",
		"/a%20b/%2e/c":   "|/a b/c",
		"/x;p=1/y":       "|/x;p=1/y",
		"/q?x=1&y=%zz;z": "|/q",
	}
	for in, want := range cases {
		resp, _ := secRaw(t, addr, secGet(in, ""), 2*time.Second)
		if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") {
			t.Errorf("%s -> %q", in, secStatus(resp))
			continue
		}
		got := seen()
		if len(got) == 0 || got[len(got)-1] != want {
			t.Errorf("%s: backend saw %q, want %q", in, got, want)
		}
	}
}

// TestPath_RouteMatchesCanonicalPath: routing sees the canonical path too,
// so "/static/../api/x" goes to the /api backend, not the /static one.
func TestPath_RouteMatchesCanonicalPath(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "api") }))
	defer api.Close()
	static := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "static") }))
	defer static.Close()
	l := &ListenerConfig{Routes: []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/api/"}, Backend: "api"}}}
	s := secNewSite(t, l, []string{secHost(static)}, secOpts{})
	s.Balancers["api"] = newRR(secHost(api))
	s.Backends["api"] = &config.Backend{Name: "api", Servers: []string{secHost(api)}}
	ts := httptest.NewServer(s)
	defer ts.Close()

	resp, _ := secRaw(t, secHost(ts), secGet("/static/../api/x", ""), 2*time.Second)
	if secBody(resp) != "api" {
		t.Fatalf("/static/../api/x routed to %q, want api", secBody(resp))
	}
}
