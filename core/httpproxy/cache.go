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
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int64 // max total bytes
	curSize int64
	ttl     time.Duration
	methods map[string]bool
	stopCh  chan struct{}
}

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
	allowedMethods := make(map[string]bool)
	if len(methods) == 0 {
		allowedMethods["GET"] = true
	} else {
		for _, m := range methods {
			allowedMethods[strings.ToUpper(m)] = true
		}
	}
	c := &Cache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
		methods: allowedMethods,
		stopCh:  make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// ShouldCache returns true if the request method is cacheable.
func (c *Cache) ShouldCache(method string) bool {
	return c.methods[method]
}

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

// Put stores a response in the cache.
func (c *Cache) Put(key string, entry *CacheEntry) {
	entry.Size = int64(len(entry.Body))

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

// CacheKey generates a cache key from the request.
func CacheKey(r *http.Request) string {
	return r.Method + "|" + r.Host + "|" + r.URL.Path + "|" + r.URL.RawQuery
}

// ShouldSkipCache checks if the request should bypass the cache.
// Skips caching for authenticated requests and cache-busting headers.
func ShouldSkipCache(r *http.Request) bool {
	// Never cache authenticated requests
	if r.Header.Get("Authorization") != "" {
		return true
	}
	if r.Header.Get("Cookie") != "" {
		return true
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
	return false
}

// sensitiveCacheHeaders are headers that should never be stored in cache.
var sensitiveCacheHeaders = []string{
	"Set-Cookie", "Authorization", "WWW-Authenticate",
	"Proxy-Authenticate", "Proxy-Authorization",
}

// ServeCached writes a cached response to the ResponseWriter.
func ServeCached(w http.ResponseWriter, entry *CacheEntry) {
	for k, vv := range entry.Headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Cache", "HIT")
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

// cacheWriter is a ResponseWriter that captures the response for caching.
type cacheWriter struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
	header     http.Header
}

func newCacheWriter(w http.ResponseWriter) *cacheWriter {
	return &cacheWriter{
		ResponseWriter: w,
		statusCode:     200,
		header:         make(http.Header),
	}
}

func (w *cacheWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *cacheWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *cacheWriter) ToCacheEntry() *CacheEntry {
	headers := make(http.Header)
	for k, vv := range w.ResponseWriter.Header() {
		headers[k] = vv
	}
	// Strip sensitive headers from cache
	for _, h := range sensitiveCacheHeaders {
		headers.Del(h)
	}
	return &CacheEntry{
		StatusCode: w.statusCode,
		Headers:    headers,
		Body:       w.body.Bytes(),
		CreatedAt:  time.Now(),
	}
}
