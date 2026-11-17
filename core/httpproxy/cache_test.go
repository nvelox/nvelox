package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCache_PutGet(t *testing.T) {
	c := NewCache(1024*1024, 5*time.Minute, nil)
	defer c.Stop()

	entry := &CacheEntry{
		StatusCode: 200,
		Headers:    http.Header{"Content-Type": {"text/html"}},
		Body:       []byte("hello"),
		CreatedAt:  time.Now(),
	}
	c.Put("key1", entry)

	got := c.Get("key1")
	if got == nil {
		t.Fatal("expected entry")
	}
	if string(got.Body) != "hello" {
		t.Errorf("expected hello, got %s", string(got.Body))
	}
}

func TestCache_Expiry(t *testing.T) {
	c := NewCache(1024*1024, 100*time.Millisecond, nil)
	defer c.Stop()

	c.Put("key", &CacheEntry{Body: []byte("x"), CreatedAt: time.Now()})

	if c.Get("key") == nil {
		t.Error("expected entry before expiry")
	}

	time.Sleep(200 * time.Millisecond)

	if c.Get("key") != nil {
		t.Error("expected nil after expiry")
	}
}

func TestCache_MaxSize_Eviction(t *testing.T) {
	c := NewCache(100, 5*time.Minute, nil) // 100 bytes max
	defer c.Stop()

	c.Put("k1", &CacheEntry{Body: make([]byte, 60), CreatedAt: time.Now()})
	c.Put("k2", &CacheEntry{Body: make([]byte, 60), CreatedAt: time.Now().Add(1 * time.Second)})

	// k1 should be evicted (oldest)
	if c.Get("k1") != nil {
		t.Error("k1 should be evicted")
	}
	if c.Get("k2") == nil {
		t.Error("k2 should exist")
	}
}

func TestCache_ShouldCache(t *testing.T) {
	c := NewCache(1024, 1*time.Minute, []string{"GET", "HEAD"})
	defer c.Stop()

	if !c.ShouldCache("GET") {
		t.Error("GET should be cacheable")
	}
	if !c.ShouldCache("HEAD") {
		t.Error("HEAD should be cacheable")
	}
	if c.ShouldCache("POST") {
		t.Error("POST should not be cacheable")
	}
}

func TestCache_DefaultMethods(t *testing.T) {
	c := NewCache(1024, 1*time.Minute, nil)
	defer c.Stop()

	if !c.ShouldCache("GET") {
		t.Error("default should cache GET")
	}
	if c.ShouldCache("POST") {
		t.Error("default should not cache POST")
	}
}

func TestCacheKey(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path?q=1", nil)
	// No Accept-Encoding → identity class.
	key := CacheKey(r)
	if key != "GET|example.com|/path|q=1|identity" {
		t.Errorf("unexpected key: %s", key)
	}
}

func TestShouldSkipCache(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if ShouldSkipCache(r) {
		t.Error("should not skip without cache-control")
	}

	r.Header.Set("Cache-Control", "no-cache")
	if !ShouldSkipCache(r) {
		t.Error("should skip with no-cache")
	}
}

func TestServeCached(t *testing.T) {
	entry := &CacheEntry{
		StatusCode: 200,
		Headers:    http.Header{"X-Custom": {"val"}},
		Body:       []byte("cached-body"),
	}

	w := httptest.NewRecorder()
	prev := ExposeXCacheHeader
	ExposeXCacheHeader = true
	defer func() { ExposeXCacheHeader = prev }()
	ServeCached(w, entry)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Cache") != "HIT" {
		t.Error("expected X-Cache: HIT")
	}
	if w.Body.String() != "cached-body" {
		t.Errorf("expected cached-body, got %s", w.Body.String())
	}
}

func TestServeCached_XCacheHidden(t *testing.T) {
	// Default (ExposeXCacheHeader=false) must NOT leak cache state.
	entry := &CacheEntry{
		StatusCode: 200,
		Headers:    http.Header{"Content-Type": []string{"text/plain"}},
		Body:       []byte("hi"),
	}
	w := httptest.NewRecorder()
	ServeCached(w, entry)
	if got := w.Header().Get("X-Cache"); got != "" {
		t.Errorf("X-Cache leaked with default setting: %q", got)
	}
}

func TestBufferPool(t *testing.T) {
	bp := NewBufferPool(4096)

	buf := bp.Get()
	if len(buf) != 4096 {
		t.Errorf("expected 4096 bytes, got %d", len(buf))
	}
	bp.Put(buf)

	buf2 := bp.Get()
	if len(buf2) != 4096 {
		t.Errorf("expected 4096 bytes from pool, got %d", len(buf2))
	}
}

func TestCacheKey_VariesByAcceptEncoding(t *testing.T) {
	// Same request, different Accept-Encoding → different keys.
	rGzip := httptest.NewRequest("GET", "http://ex.com/x", nil)
	rGzip.Host = "ex.com"
	rGzip.Header.Set("Accept-Encoding", "gzip, deflate")

	rIdent := httptest.NewRequest("GET", "http://ex.com/x", nil)
	rIdent.Host = "ex.com"
	// no Accept-Encoding → identity

	kg := CacheKey(rGzip)
	ki := CacheKey(rIdent)
	if kg == ki {
		t.Errorf("gzip and identity requests must have distinct cache keys, both = %q", kg)
	}
	// Identical gzip-capable clients share a key (presence-based).
	rGzip2 := httptest.NewRequest("GET", "http://ex.com/x", nil)
	rGzip2.Host = "ex.com"
	rGzip2.Header.Set("Accept-Encoding", "gzip;q=0.9, br")
	if CacheKey(rGzip2) != kg {
		t.Error("two gzip-capable clients should hit the same cache entry")
	}
}

func TestShouldSkipCacheResponse_VaryBeyondAcceptEncoding(t *testing.T) {
	cases := []struct {
		vary string
		skip bool
	}{
		{"", false},
		{"Accept-Encoding", false},
		{"accept-encoding", false},
		{"Accept-Encoding, Accept-Encoding", false},
		{"User-Agent", true},
		{"Accept-Encoding, Cookie", true},
		{"*", true},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.vary != "" {
			h.Set("Vary", c.vary)
		}
		if got := ShouldSkipCacheResponse(h); got != c.skip {
			t.Errorf("Vary=%q: got skip=%v, want %v", c.vary, got, c.skip)
		}
	}
}
