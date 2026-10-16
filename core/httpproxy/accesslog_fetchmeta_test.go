package httpproxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"
)

// TestServeHTTP_AccessLogFetchMetadata drives proxied requests through ServeHTTP
// and checks the access line carries the client's Sec-Fetch-Site / Sec-Fetch-Dest
// and the scheme — read before a configured request-header removal strips them
// from the upstream request.
func TestServeHTTP_AccessLogFetchMetadata(t *testing.T) {
	var upstreamSite string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSite = r.Header.Get("Sec-Fetch-Site")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "nope")
	}))
	defer backend.Close()
	host := mustHost(t, backend.URL)

	accessPath := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("debug", accessPath, ""); err != nil {
		t.Fatalf("logging init: %v", err)
	}
	t.Cleanup(func() { _ = logging.Init("debug", "", "") })

	backends := map[string]*config.Backend{"be": {Name: "be", Servers: []string{host}}}
	balancers := map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{host})}
	l := &ListenerConfig{
		Name: "edge", Addr: ":0", Protocol: "https", Backend: "be",
		Headers: config.HeadersConfig{RequestRemove: []string{"Sec-Fetch-Site", "Sec-Fetch-Dest"}},
	}
	s := NewHTTPServer(l, balancers, backends, nil, nil, nil, nil, nil)

	// (1) A browser subresource over TLS.
	req := httptest.NewRequest("GET", "https://edge.test/.env", nil)
	req.RemoteAddr = "203.0.113.9:5000"
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/129.0 Safari/537.36")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Dest", "image")
	s.ServeHTTP(httptest.NewRecorder(), req)
	if upstreamSite != "" {
		t.Fatalf("configured removal did not strip Sec-Fetch-Site upstream (got %q)", upstreamSite)
	}

	// (2) A plain-HTTP request without Fetch Metadata.
	req2 := httptest.NewRequest("GET", "http://edge.test/.git/config", nil)
	req2.RemoteAddr = "203.0.113.9:5001"
	req2.Header.Set("User-Agent", "curl/8.5.0")
	s.ServeHTTP(httptest.NewRecorder(), req2)

	data, err := os.ReadFile(accessPath)
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 access lines, got %d: %q", len(lines), data)
	}
	if !strings.Contains(lines[0], `"GET /.env HTTP/1.1" 404 `) ||
		!strings.Contains(lines[0], `Safari/537.36" fetch_site=cross-site fetch_dest=image scheme=https rid=`) {
		t.Errorf("browser line: %q", lines[0])
	}
	if !strings.Contains(lines[1], `"GET /.git/config HTTP/1.1" 404 `) ||
		!strings.Contains(lines[1], `"curl/8.5.0" fetch_site=- fetch_dest=- scheme=http rid=`) {
		t.Errorf("plain line: %q", lines[1])
	}
	for i, line := range lines {
		if !strings.HasSuffix(line, " site=edge") {
			t.Errorf("line %d: site= is no longer the last token: %q", i, line)
		}
	}
}
