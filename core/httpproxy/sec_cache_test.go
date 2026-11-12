package httpproxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

// H8: the response cache stored an aborted GET as an empty 200 (the status
// defaulted to 200 and Put ran before the proxy error was looked at), stored
// 206 / 304 answers under the plain key, buffered without bound and stored
// entries larger than max_size (0 meant unlimited). M2: with compression on,
// a hit replayed "Content-Encoding: gzip" over the plain body.

func secCacheBackend(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/slow":
			time.Sleep(400 * time.Millisecond)
			io.WriteString(w, "SLOWBODY")
		case r.URL.Path == "/file":
			http.ServeContent(w, r, "f.txt", time.Unix(1700000000, 0), strings.NewReader("0123456789"))
		case r.URL.Path == "/html":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, strings.Repeat("<p>hello world</p>", 100))
		case r.URL.Path == "/small":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<p>short</p>")
		case r.URL.Path == "/big":
			w.Write(bytes.Repeat([]byte("A"), 100*1024))
		case r.URL.Path == "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: one\n\n")
		default:
			io.WriteString(w, "PATH="+r.URL.Path)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func secCacheSite(t *testing.T, l *ListenerConfig, backend *httptest.Server) (*HTTPServer, string) {
	t.Helper()
	if !l.Cache.Enabled {
		l.Cache = config.CacheConfig{Enabled: true, MaxSize: "1MB"}
	}
	return secSite(t, l, []string{secHost(backend)}, secOpts{})
}

// TestCache_AbortedResponseNotCached: a GET whose client hung up before the
// backend answered must not leave an empty 200 in the cache.
func TestCache_AbortedResponseNotCached(t *testing.T) {
	s, addr := secCacheSite(t, &ListenerConfig{}, secCacheBackend(t))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET /slow HTTP/1.1\r\nHost: edge.test\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	c.Close()
	time.Sleep(600 * time.Millisecond)
	if n := s.ResponseCache.Len(); n != 0 {
		t.Fatalf("aborted GET left %d cache entries", n)
	}
	resp, _ := secRaw(t, addr, secGet("/slow", ""), 2*time.Second)
	if secBody(resp) != "SLOWBODY" {
		t.Fatalf("GET after an aborted GET -> %q %q, want SLOWBODY", secStatus(resp), secBody(resp))
	}
}

// TestCache_RangeAndConditionalBypass: a Range or conditional request's
// answer (206 / 304) is never stored under the plain key, nor served from it.
func TestCache_RangeAndConditionalBypass(t *testing.T) {
	s, addr := secCacheSite(t, &ListenerConfig{}, secCacheBackend(t))
	for _, extra := range []string{
		"Range: bytes=0-0\r\n",
		"If-Modified-Since: Mon, 01 Jan 2035 00:00:00 GMT\r\n",
		"If-None-Match: \"x\"\r\n",
	} {
		secRaw(t, addr, secGet("/file", extra), 2*time.Second)
		if n := s.ResponseCache.Len(); n != 0 {
			t.Fatalf("%q: %d cache entries after a partial/conditional request", strings.TrimSpace(extra), n)
		}
		resp, _ := secRaw(t, addr, secGet("/file", ""), 2*time.Second)
		if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") || secBody(resp) != "0123456789" {
			t.Fatalf("%q then plain GET -> %q %q, want 200 0123456789", strings.TrimSpace(extra), secStatus(resp), secBody(resp))
		}
		s.ResponseCache = NewCache(1<<20, time.Minute, nil) // next case starts empty
	}
}

// TestCache_OversizeNotStored: a response larger than the cache (or than the
// per-entry cap) is relayed but not stored.
func TestCache_OversizeNotStored(t *testing.T) {
	s, addr := secCacheSite(t, &ListenerConfig{Cache: config.CacheConfig{Enabled: true, MaxSize: "1KB"}}, secCacheBackend(t))
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	if _, body := secFetch(t, tr, "http://"+addr+"/big", ""); len(body) != 100*1024 {
		t.Fatalf("client got %d bytes of /big, want %d", len(body), 100*1024)
	}
	if n := s.ResponseCache.Len(); n != 0 {
		t.Fatalf("100 KB response stored in a 1 KB cache (%d entries)", n)
	}
}

// TestCache_UnsetMaxSizeIsBounded: max_size 0 (unset) no longer means
// unlimited; an entry over the per-entry cap is refused.
func TestCache_UnsetMaxSizeIsBounded(t *testing.T) {
	c := NewCache(0, time.Minute, nil)
	defer c.Stop()
	c.Put("huge", &CacheEntry{StatusCode: 200, Body: make([]byte, 9<<20), CreatedAt: time.Now()})
	if c.Len() != 0 {
		t.Fatal("9 MB entry stored in a cache with max_size unset")
	}
	c.Put("ok", &CacheEntry{StatusCode: 200, Body: make([]byte, 1<<20), CreatedAt: time.Now()})
	if c.Get("ok") == nil {
		t.Fatal("1 MB entry refused")
	}
}

// TestCache_LongKeyNotCached: a request with a very long URL is not cached.
func TestCache_LongKeyNotCached(t *testing.T) {
	s, addr := secCacheSite(t, &ListenerConfig{}, secCacheBackend(t))
	resp, _ := secRaw(t, addr, secGet("/"+strings.Repeat("k", 5000), ""), 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") {
		t.Fatalf("long URL -> %q", secStatus(resp))
	}
	if n := s.ResponseCache.Len(); n != 0 {
		t.Fatalf("5 KB cache key stored (%d entries)", n)
	}
}

// TestCache_RewriteDoesNotPoisonOtherPath: a route that rewrites /promo to
// /landing on another backend must not file its answer under /landing — a
// direct request for /landing gets the default backend's page.
func TestCache_RewriteDoesNotPoisonOtherPath(t *testing.T) {
	promo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "promo:"+r.URL.Path) }))
	defer promo.Close()
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "main:"+r.URL.Path) }))
	defer main.Close()
	l := &ListenerConfig{
		Cache: config.CacheConfig{Enabled: true, MaxSize: "1MB"},
		Routes: []config.RouteConfig{{
			Match:   config.RouteMatch{PathPrefix: "/promo"},
			Backend: "promo",
			Rewrite: config.RewriteConfig{Path: "/landing"},
		}},
	}
	s := secNewSite(t, l, []string{secHost(main)}, secOpts{})
	s.Balancers["promo"] = newRR(secHost(promo))
	s.Backends["promo"] = &config.Backend{Name: "promo", Servers: []string{secHost(promo)}}
	ts := httptest.NewServer(s)
	defer ts.Close()

	if resp, _ := secRaw(t, secHost(ts), secGet("/promo", ""), 2*time.Second); secBody(resp) != "promo:/landing" {
		t.Fatalf("/promo -> %q", secBody(resp))
	}
	if resp, _ := secRaw(t, secHost(ts), secGet("/landing", ""), 2*time.Second); secBody(resp) != "main:/landing" {
		t.Fatalf("/landing -> %q, want the main backend's page (cache poisoned by the /promo rewrite)", secBody(resp))
	}
	if resp, _ := secRaw(t, secHost(ts), secGet("/promo", ""), 2*time.Second); secBody(resp) != "promo:/landing" {
		t.Fatalf("/promo (hit) -> %q", secBody(resp))
	}
}

// TestCache_StreamNotCached: an event stream is not a cacheable document.
func TestCache_StreamNotCached(t *testing.T) {
	s, addr := secCacheSite(t, &ListenerConfig{}, secCacheBackend(t))
	secRaw(t, addr, secGet("/events", ""), 2*time.Second)
	if n := s.ResponseCache.Len(); n != 0 {
		t.Fatalf("event stream cached (%d entries)", n)
	}
}

// secFetch does a GET through tr and returns the response and its raw body.
func secFetch(t *testing.T, tr *http.Transport, url, acceptEncoding string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func secGunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not gzip: %v (%q...)", err, b[:min(len(b), 16)])
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("bad gzip: %v", err)
	}
	return string(out)
}

// TestCache_CompressedHitIsValidGzip (M2): with cache and compression on, a
// hit is compressed like a fresh response; a client without gzip gets the
// plain body.
func TestCache_CompressedHitIsValidGzip(t *testing.T) {
	l := &ListenerConfig{Compression: config.CompressionConfig{Enabled: true}}
	s, addr := secCacheSite(t, l, secCacheBackend(t))
	tr := &http.Transport{DisableCompression: true}
	defer tr.CloseIdleConnections()
	want := strings.Repeat("<p>hello world</p>", 100)

	for i := 0; i < 2; i++ {
		resp, body := secFetch(t, tr, "http://"+addr+"/html", "gzip")
		if resp.Header.Get("Content-Encoding") != "gzip" {
			t.Fatalf("gzip GET %d: Content-Encoding = %q", i, resp.Header.Get("Content-Encoding"))
		}
		if got := secGunzip(t, body); got != want {
			t.Fatalf("gzip GET %d: decompressed body differs (%d bytes)", i, len(got))
		}
	}
	if n := s.ResponseCache.Len(); n != 1 {
		t.Fatalf("cache entries = %d, want 1", n)
	}
	for i := 0; i < 2; i++ {
		resp, body := secFetch(t, tr, "http://"+addr+"/html", "")
		if resp.Header.Get("Content-Encoding") != "" || string(body) != want {
			t.Fatalf("identity GET %d: Content-Encoding=%q body %d bytes", i, resp.Header.Get("Content-Encoding"), len(body))
		}
	}
}

// TestCache_HitHasItsOwnRequestID: a hit carries the X-Request-ID of the
// request it answers, not also the one of the request that filled the cache.
func TestCache_HitHasItsOwnRequestID(t *testing.T) {
	l := &ListenerConfig{RequestID: config.RequestIDConfig{Enabled: true}}
	_, addr := secCacheSite(t, l, secCacheBackend(t))
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	secFetch(t, tr, "http://"+addr+"/doc", "")
	resp, _ := secFetch(t, tr, "http://"+addr+"/doc", "")
	if ids := resp.Header.Values("X-Request-ID"); len(ids) != 1 {
		t.Fatalf("cache hit carries X-Request-ID %q, want exactly its own", ids)
	}
}

// TestCompression_MinLength: compression.min_length (parsed, never read
// before) keeps short responses uncompressed; compressed ones say Vary.
func TestCompression_MinLength(t *testing.T) {
	l := &ListenerConfig{Compression: config.CompressionConfig{Enabled: true, MinLength: 1024}}
	_, addr := secSite(t, l, []string{secHost(secCacheBackend(t))}, secOpts{})
	tr := &http.Transport{DisableCompression: true}
	defer tr.CloseIdleConnections()

	resp, body := secFetch(t, tr, "http://"+addr+"/small", "gzip")
	if resp.Header.Get("Content-Encoding") != "" || string(body) != "<p>short</p>" {
		t.Fatalf("short response: Content-Encoding=%q body=%q, want it uncompressed", resp.Header.Get("Content-Encoding"), body)
	}
	resp, body = secFetch(t, tr, "http://"+addr+"/html", "gzip")
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("long response not compressed")
	}
	secGunzip(t, body)
	if !strings.Contains(strings.ToLower(strings.Join(resp.Header.Values("Vary"), ",")), "accept-encoding") {
		t.Fatalf("compressed response without Vary: Accept-Encoding (Vary=%q)", resp.Header.Values("Vary"))
	}
}
