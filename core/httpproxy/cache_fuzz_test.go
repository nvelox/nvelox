package httpproxy

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/net/http/httpguts"
)

// cacheRequest is the request a handler gets from a request line built of
// the parts given, or nil when it gets none: what net/http reads, and its
// server lets through (a Host header with a character a host cannot have
// is answered 400 before any handler).
func cacheRequest(method, target, host, ae string) *http.Request {
	raw := method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\nAccept-Encoding: " + ae + "\r\n\r\n"
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil || !httpguts.ValidHostHeader(r.Host) {
		return nil
	}
	return r
}

// cacheTuple is what the upstream sees of a request that the cache key must
// tell apart: method, host, the escaped path, the query, and whether the
// client takes gzip (the encoding the cached body may be in).
func cacheTuple(r *http.Request) string {
	gz := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
	return strings.Join([]string{r.Method, r.Host, r.URL.EscapedPath(), r.URL.RawQuery}, "\x00") + map[bool]string{true: "\x00gzip", false: "\x00identity"}[gz]
}

// FuzzCacheKey: two requests share a cache entry only when the upstream
// sees the same of them: one client is never answered with what was cached
// for another request. The key's parts are joined with '|', which a method
// and a query may hold: the key still splits one way only, because the
// encoding is its last part, a host holds no '|' (the server refuses one
// that does) and a path begins with '/' or is "*".
func FuzzCacheKey(f *testing.F) {
	f.Add("GET", "/a?x=1", "example.test", "gzip", "GET", "/a?x=1", "example.test", "identity")
	f.Add("GET", "/a?x=1", "example.test", "", "GET", "/a?x=2", "example.test", "")
	f.Add("GET", "/a", "one.test", "", "GET", "/a", "two.test", "")
	f.Add("GET", "/a", "h", "", "HEAD", "/a", "h", "")
	f.Add("GET|x", "/", "h", "", "GET", "/", "x|h", "")
	f.Add("GET", "/?a|gzip", "h", "", "GET", "/?a", "h", "gzip")
	f.Add("GET", "/a%2Fb", "h", "", "GET", "/a/b", "h", "")
	f.Add("GET", "*", "h", "", "OPTIONS", "*", "h", "")
	f.Add("GET", "http://other.test/p", "h", "", "GET", "/p", "other.test", "")
	f.Fuzz(func(t *testing.T, m1, t1, h1, ae1, m2, t2, h2, ae2 string) {
		r1, r2 := cacheRequest(m1, t1, h1, ae1), cacheRequest(m2, t2, h2, ae2)
		if r1 == nil || r2 == nil {
			return
		}
		if CacheKey(r1) == CacheKey(r2) && cacheTuple(r1) != cacheTuple(r2) {
			t.Fatalf("two requests share the cache key %q:\n %q\n %q", CacheKey(r1), cacheTuple(r1), cacheTuple(r2))
		}
	})
}
