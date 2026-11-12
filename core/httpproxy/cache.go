package httpproxy

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Cache provides an in-memory HTTP response cache with TTL and size limits.
type Cache struct {
	mu       sync.RWMutex
	entries  map[string]*CacheEntry
	maxSize  int64 // max total bytes
	maxEntry int64 // max bytes of one entry
	curSize  int64
	ttl      time.Duration
	methods  map[string]bool
	stopCh   chan struct{}
}

const (
	// defaultCacheMaxSize is the cache size when cache.max_size is unset or
	// 0. (0 used to mean "unlimited".)
	defaultCacheMaxSize = 64 << 20
	// maxCacheEntrySize caps one cached response; a smaller max_size caps it
	// further. A larger response is relayed but neither buffered past the
	// cap nor stored.
	maxCacheEntrySize = 8 << 20
	// maxCacheKeyLen: a request whose cache key (method, host, path, query)
	// is longer is neither looked up nor stored.
	maxCacheKeyLen = 4096
)

// CacheEntry stores a cached response.
type CacheEntry struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	CreatedAt  time.Time
	Size       int64
}

// NewCache creates a response cache.
func NewCache(maxSize int64, ttl time.Duration, methods []string) *Cache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if maxSize <= 0 {
		maxSize = defaultCacheMaxSize
	}
	maxEntry := int64(maxCacheEntrySize)
	if maxSize < maxEntry {
		maxEntry = maxSize
	}
	allowedMethods := make(map[string]bool)
	if len(methods) == 0 {
		allowedMethods["GET"] = true
	} else {
		for _, m := range methods {
			allowedMethods[strings.ToUpper(m)] = true
		}
	}
	c := &Cache{
		entries:  make(map[string]*CacheEntry),
		maxSize:  maxSize,
		maxEntry: maxEntry,
		ttl:      ttl,
		methods:  allowedMethods,
		stopCh:   make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// ShouldCache returns true if the request method is cacheable.
func (c *Cache) ShouldCache(method string) bool {
	return c.methods[method]
}

// MaxEntrySize is the largest entry Put accepts, in bytes (body, key and
// headers).
func (c *Cache) MaxEntrySize() int64 { return c.maxEntry }

// Get returns a cached entry for the key, or nil if not found/expired.
func (c *Cache) Get(key string) *CacheEntry {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(entry.CreatedAt) > c.ttl {
		c.mu.Lock()
		c.curSize -= entry.Size
		delete(c.entries, key)
		c.mu.Unlock()
		return nil
	}
	return entry
}

// Put stores a response in the cache. An entry larger than MaxEntrySize,
// or with a key longer than maxCacheKeyLen, is not stored. The size counts
// the key and headers along with the body, so max_size bounds the memory the
// cache holds.
func (c *Cache) Put(key string, entry *CacheEntry) {
	entry.Size = entrySize(key, entry)
	if entry.Size > c.maxEntry || len(key) > maxCacheKeyLen {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict old entry if exists
	if old, ok := c.entries[key]; ok {
		c.curSize -= old.Size
	}

	// Check size limit — evict oldest entries if needed
	for c.maxSize > 0 && c.curSize+entry.Size > c.maxSize && len(c.entries) > 0 {
		c.evictOldest()
	}

	c.entries[key] = entry
	c.curSize += entry.Size
}

// entrySize is the memory an entry takes: body, key and headers.
func entrySize(key string, e *CacheEntry) int64 {
	n := int64(len(key) + len(e.Body))
	for k, vv := range e.Headers {
		n += int64(len(k))
		for _, v := range vv {
			n += int64(len(v))
		}
	}
	return n
}

// CacheKey generates a cache key from the request.
//
// Accept-Encoding is part of the key: without it, a gzipped response cached
// from a gzip-capable client would be served to an identity-only client,
// who'd see garbage. Normalized to "gzip" / "identity" (presence-based) so
// trivially-different Accept-Encoding strings from the same class of client
// still hit the same cache entry.
func CacheKey(r *http.Request) string {
	enc := "identity"
	if ae := r.Header.Get("Accept-Encoding"); strings.Contains(ae, "gzip") {
		enc = "gzip"
	}
	return r.Method + "|" + r.Host + "|" + r.URL.Path + "|" + r.URL.RawQuery + "|" + enc
}

// conditionalRequestHeaders make a request partial or conditional. Its
// answer (206, 304, 412, or a full 200 the client may not expect) is not the
// plain response the cache key stands for, so such a request bypasses the
// cache in both directions.
var conditionalRequestHeaders = []string{
	"Range", "If-Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since",
}

// ShouldSkipCache checks if the request should bypass the cache.
// Skips caching for authenticated requests, cache-busting headers and
// range / conditional requests.
func ShouldSkipCache(r *http.Request) bool {
	// Never cache authenticated requests
	if r.Header.Get("Authorization") != "" {
		return true
	}
	if r.Header.Get("Cookie") != "" {
		return true
	}
	for _, h := range conditionalRequestHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	cc := r.Header.Get("Cache-Control")
	return strings.Contains(cc, "no-cache") || strings.Contains(cc, "no-store")
}

// ShouldSkipCacheResponse checks if the response should not be cached.
func ShouldSkipCacheResponse(h http.Header) bool {
	cc := h.Get("Cache-Control")
	if strings.Contains(cc, "no-cache") || strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return true
	}
	// Don't cache responses with Set-Cookie
	if h.Get("Set-Cookie") != "" {
		return true
	}
	// Vary only supports Accept-Encoding in our key. If the upstream
	// says the response varies on anything else (User-Agent, Cookie,
	// custom header, or "*"), we can't safely key it — skip caching.
	if v := h.Get("Vary"); v != "" {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(strings.ToLower(tok))
			if tok == "" || tok == "accept-encoding" {
				continue
			}
			return true
		}
	}
	return false
}

// sensitiveCacheHeaders are headers that should never be stored in cache.
var sensitiveCacheHeaders = []string{
	"Set-Cookie", "Authorization", "WWW-Authenticate",
	"Proxy-Authenticate", "Proxy-Authorization",
}

// ExposeXCacheHeader controls whether X-Cache: HIT/MISS is emitted to
// clients. Default false: the header leaks cache state and lets an
// attacker enumerate what other users fetched via timing-free observation.
// Operators who need it for debugging can set it true.
var ExposeXCacheHeader = false

// ServeCached writes a cached response to the ResponseWriter.
func ServeCached(w http.ResponseWriter, entry *CacheEntry) {
	for k, vv := range entry.Headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	if ExposeXCacheHeader {
		w.Header().Set("X-Cache", "HIT")
	}
	w.WriteHeader(entry.StatusCode)
	w.Write(entry.Body)
}

// Stop shuts down the cleanup goroutine.
func (c *Cache) Stop() {
	close(c.stopCh)
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, e := range c.entries {
		if first || e.CreatedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.CreatedAt
			first = false
		}
	}
	if oldestKey != "" {
		c.curSize -= c.entries[oldestKey].Size
		delete(c.entries, oldestKey)
	}
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

func (c *Cache) evictExpired() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if now.Sub(e.CreatedAt) > c.ttl {
			c.curSize -= e.Size
			delete(c.entries, k)
		}
	}
}

// cacheableResponse reports whether a backend response may be stored: a
// 200 (never a 206 / 304 / error), not marked uncacheable, not a stream, and
// not announced larger than limit.
func cacheableResponse(resp *http.Response, limit int64) bool {
	if resp.StatusCode != http.StatusOK || ShouldSkipCacheResponse(resp.Header) {
		return false
	}
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "text/event-stream") {
		return false
	}
	return resp.ContentLength <= limit
}

// cacheHeaders is the copy of a backend response's headers (hop-by-hop
// headers already removed, response header rules applied) that a cache
// entry keeps, minus credentials and cookies.
func cacheHeaders(h http.Header) http.Header {
	headers := h.Clone()
	for _, name := range sensitiveCacheHeaders {
		headers.Del(name)
	}
	return headers
}

// cacheWriter tees a response body into memory so it can be stored once it
// has been relayed in full. It buffers only after ModifyResponse marked the
// response cacheable (capture), and gives up — the response is then not
// stored — past limit bytes.
type cacheWriter struct {
	http.ResponseWriter
	limit    int64
	capture  bool
	status   int // final status written, 0 until then
	body     bytes.Buffer
	overflow bool
}

func newCacheWriter(w http.ResponseWriter, limit int64) *cacheWriter {
	return &cacheWriter{ResponseWriter: w, limit: limit}
}

func (w *cacheWriter) WriteHeader(code int) {
	if code >= 200 && w.status == 0 { // 1xx informational responses are not the response
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *cacheWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.capture && !w.overflow {
		if int64(w.body.Len())+int64(len(b)) > w.limit {
			w.overflow = true
			w.body = bytes.Buffer{}
		} else {
			w.body.Write(b)
		}
	}
	return w.ResponseWriter.Write(b)
}

// Flush keeps streaming responses streaming through the cache writer.
func (w *cacheWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the writers below.
func (w *cacheWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// complete reports whether the captured response may be stored: a 200 that
// was buffered whole. (The caller also checks the backend body hit EOF.)
func (w *cacheWriter) complete() bool {
	return w.capture && w.status == http.StatusOK && !w.overflow
}
