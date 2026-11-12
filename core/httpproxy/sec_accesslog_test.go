package httpproxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

// Logging: proxy errors were access-logged as 200 (the error page went to
// the raw writer, not the recorder), and every early return — IP / ACL
// denies, rate limits, redirects, cache hits, WebSocket upgrades — wrote no
// access-log line at all (AccessHTTP ran only at the end of the proxy path).
// The sentinel reads these lines. Now every response gets exactly one line
// with the status the client was sent.

type secDenyAll struct{}

func (secDenyAll) Allow() bool { return false }

// TestAccessLog_FormatUnchanged pins the line format byte for byte.
func TestAccessLog_FormatUnchanged(t *testing.T) {
	path := secAccessLog(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer backend.Close()
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{})
	secRaw(t, addr, secGet("/a/b", "User-Agent: probe/1.0\r\n"), 2*time.Second)

	lines := secLogLines(t, path, 1)
	re := regexp.MustCompile(`^127\.0\.0\.1 - edge\.test "GET /a/b HTTP/1\.1" 200 2 \d+\.\d{3}ms -> 127\.0\.0\.1:\d+ "probe/1\.0" fetch_site=- fetch_dest=- scheme=http rid=- gw=\S* site=edge$`)
	if len(lines) != 1 || !re.MatchString(lines[0]) {
		t.Fatalf("access line format changed: %q", lines)
	}
}

// TestAccessLog_ProxyErrorRealStatus: an unreachable backend is logged as
// the 502 the client got.
func TestAccessLog_ProxyErrorRealStatus(t *testing.T) {
	path := secAccessLog(t)
	_, addr := secSite(t, &ListenerConfig{}, []string{"127.0.0.1:1"}, secOpts{})
	resp, _ := secRaw(t, addr, secGet("/x", ""), 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 502") {
		t.Fatalf("client got %q, want 502", secStatus(resp))
	}
	lines := secLogLines(t, path, 1)
	if len(lines) != 1 || !strings.Contains(lines[0], `"GET /x HTTP/1.1" 502 `) || !strings.Contains(lines[0], "-> 127.0.0.1:1 ") {
		t.Fatalf("access line %q, want the 502 and the backend tried", lines)
	}
}

// TestAccessLog_EveryResponseOnce: each kind of early answer gets exactly
// one line, with its status and "-" as the backend.
func TestAccessLog_EveryResponseOnce(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer backend.Close()
	cases := []struct {
		name     string
		l        *ListenerConfig
		setup    func(*HTTPServer)
		request  string
		requests int
		want     string // substring of the LAST line
	}{
		{"acl deny", &ListenerConfig{ACL: []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/admin"}, Action: "deny", Status: 404}}},
			nil, secGet("/admin", ""), 1, `"GET /admin HTTP/1.1" 404 `},
		{"ip denylist", &ListenerConfig{IPDenylist: []string{"127.0.0.1/32"}},
			nil, secGet("/", ""), 1, `"GET / HTTP/1.1" 403 `},
		{"rate limit", &ListenerConfig{},
			func(s *HTTPServer) { s.RateLimiter = secDenyAll{} }, secGet("/", ""), 1, `"GET / HTTP/1.1" 429 `},
		{"redirect", &ListenerConfig{Routes: []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/old"}, Redirect: config.RedirectConfig{URL: "/new", Code: 301}}}},
			nil, secGet("/old", ""), 1, `"GET /old HTTP/1.1" 301 `},
		{"cache hit", &ListenerConfig{Cache: config.CacheConfig{Enabled: true, MaxSize: "1MB"}},
			nil, secGet("/c", ""), 2, `"GET /c HTTP/1.1" 200 2 `},
		{"connect", &ListenerConfig{},
			nil, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", 1, `"CONNECT / HTTP/1.1" 405 `},
		{"too large", &ListenerConfig{MaxBodySize: "4B"},
			nil, "POST /up HTTP/1.1\r\nHost: edge.test\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789", 1, `"POST /up HTTP/1.1" 413 `},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := secAccessLog(t)
			s, addr := secSite(t, c.l, []string{secHost(backend)}, secOpts{})
			if c.setup != nil {
				c.setup(s)
			}
			for i := 0; i < c.requests; i++ {
				secRaw(t, addr, c.request, 2*time.Second)
			}
			lines := secLogLines(t, path, c.requests)
			time.Sleep(50 * time.Millisecond)
			lines = secLogLines(t, path, c.requests)
			if len(lines) != c.requests {
				t.Fatalf("%d requests, %d access lines: %q", c.requests, len(lines), lines)
			}
			last := lines[len(lines)-1]
			if !strings.Contains(last, c.want) {
				t.Fatalf("access line %q, want %q", last, c.want)
			}
			if c.name != "cache hit" || c.requests > 1 {
				if c.name != "too large" && !strings.Contains(last, " -> - ") {
					t.Fatalf("access line %q: backend should be \"-\"", last)
				}
			}
		})
	}
}

// TestAccessLog_ClientGone499: a client that hangs up before the answer is
// logged as 499, not as a 200 it never got.
func TestAccessLog_ClientGone499(t *testing.T) {
	path := secAccessLog(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer backend.Close()
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET /slow HTTP/1.1\r\nHost: edge.test\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	c.Close()
	lines := secLogLines(t, path, 1)
	if len(lines) != 1 || !strings.Contains(lines[0], `"GET /slow HTTP/1.1" 499 0 `) {
		t.Fatalf("access line %q, want 499", lines)
	}
}

// TestAccessLog_WebSocketLine: an upgrade is logged once, when the tunnel
// closes, as a 101 with the bytes sent to the client through it.
func TestAccessLog_WebSocketLine(t *testing.T) {
	path := secAccessLog(t)
	b := secStartWSBackend(t)
	_, addr := secSite(t, &ListenerConfig{}, []string{b.addr}, secOpts{})
	conn, br, resp := secUpgrade(t, addr, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	assertEcho(t, conn, br) // 19 bytes each way
	conn.Close()
	lines := secLogLines(t, path, 1)
	if len(lines) != 1 || !strings.Contains(lines[0], `"GET /ws HTTP/1.1" 101 19 `) || !strings.Contains(lines[0], "-> "+b.addr+" ") {
		t.Fatalf("access line %q, want one 101 line with 19 bytes and the backend", lines)
	}
}

// TestAccessLog_FieldInjection (Low): the logged path is the escaped
// (canonical) path and a '"' or '\' in the path or User-Agent is escaped,
// so neither can close its quotes and forge the fields after it.
func TestAccessLog_FieldInjection(t *testing.T) {
	path := secAccessLog(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer backend.Close()
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{})
	ua := `ua" fetch_site=same-origin fetch_dest=document scheme=https rid=x gw=y site=z \"`
	secRaw(t, addr, secGet(`/x%22%20200%2012%201.000ms%20-%3E%20fake%20%22ua%5C`, "User-Agent: "+ua+"\r\n"), 2*time.Second)

	lines := secLogLines(t, path, 1)
	if len(lines) != 1 {
		t.Fatalf("lines %q", lines)
	}
	line := lines[0]
	if n := strings.Count(line, `"`); n != 4 {
		t.Fatalf("line has %d double quotes, want 4 (request and UA): %q", n, line)
	}
	if !strings.Contains(line, `"GET /x%22%20200%2012%201.000ms%20-%3E%20fake%20%22ua%5C HTTP/1.1" 404 `) {
		t.Fatalf("path not logged in escaped form: %q", line)
	}
	if !strings.Contains(line, `"ua\x22 fetch_site=same-origin fetch_dest=document scheme=https rid=x gw=y site=z \x5C\x22"`) {
		t.Fatalf("User-Agent not escaped: %q", line)
	}
	if !strings.HasSuffix(line, " site=edge") || strings.Count(line, " fetch_site=") != 2 {
		t.Fatalf("tail tokens wrong: %q", line)
	}
}
