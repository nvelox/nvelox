package httpproxy

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/acl"
	"nvelox/core/sticky"
)

// secHeaderBackend records the headers of the last request it served.
func secHeaderBackend(t *testing.T) (*httptest.Server, func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	var last http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = r.Header.Clone()
		mu.Unlock()
		io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.Close)
	return ts, func() http.Header {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

// M8: realClientIP read only the first X-Forwarded-For line, skipped hops it
// could not parse (a port, brackets, "unknown") and kept walking left into
// client-controlled entries; the peer was also appended to X-Forwarded-For
// twice (once by nvelox, once more by ReverseProxy's Director handling).

func TestRealClientIP_EveryXFFLine(t *testing.T) {
	s := &HTTPServer{Listener: &ListenerConfig{}, TrustedProxies: acl.ParseCIDRList([]string{"10.0.0.0/8"})}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header["X-Forwarded-For"] = []string{"6.6.6.6", "203.0.113.5, 10.0.0.9"}
	if got := s.realClientIP(r); got != "203.0.113.5" {
		t.Fatalf("realClientIP = %q, want 203.0.113.5 (the last line holds the nearest hops)", got)
	}
}

func TestRealClientIP_PortsBracketsAndUnparseableHops(t *testing.T) {
	cases := []struct{ xff, want string }{
		{"6.6.6.6, 203.0.113.5:4444", "203.0.113.5"},
		{"6.6.6.6, [2001:db8::5]", "2001:db8::5"},
		{"6.6.6.6, [2001:db8::5]:443", "2001:db8::5"},
		{"6.6.6.6, 203.0.113.5, ", "203.0.113.5"},        // empty entry skipped
		{"6.6.6.6, unknown", "10.0.0.2"},                 // fail closed: the peer
		{"6.6.6.6, garbage, 10.0.0.9", "10.0.0.9"},       // fail closed: nearest trusted hop
		{"6.6.6.6, _hidden, 203.0.113.7", "203.0.113.7"}, // untrusted hop found before the garbage
		{"2001:DB8:0:0::7", "2001:db8::7"},               // normalized
		{"10.0.0.9, 10.0.0.8", "10.0.0.2"},               // all trusted: peer (no X-Real-IP)
	}
	s := &HTTPServer{Listener: &ListenerConfig{}, TrustedProxies: acl.ParseCIDRList([]string{"10.0.0.0/8"})}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.2:1234"
		r.Header.Set("X-Forwarded-For", c.xff)
		if got := s.realClientIP(r); got != c.want {
			t.Errorf("XFF %q: realClientIP = %q, want %q", c.xff, got, c.want)
		}
	}
}

// TestForwarded_XFFChainUpstream: the backend sees the peer once, after the
// trusted proxy's full chain (every line), or alone for an untrusted peer.
func TestForwarded_XFFChainUpstream(t *testing.T) {
	backend, last := secHeaderBackend(t)

	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{})
	secRaw(t, addr, secGet("/", "X-Forwarded-For: 6.6.6.6\r\n"), 2*time.Second)
	if got := last().Values("X-Forwarded-For"); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("untrusted peer: backend X-Forwarded-For = %q, want [127.0.0.1]", got)
	}

	_, addr = secSite(t, &ListenerConfig{TrustedProxies: []string{"127.0.0.1/32"}}, []string{secHost(backend)}, secOpts{})
	secRaw(t, addr, secGet("/", "X-Forwarded-For: 198.51.100.1\r\nX-Forwarded-For: 203.0.113.5\r\n"), 2*time.Second)
	if got := last().Values("X-Forwarded-For"); len(got) != 1 || got[0] != "198.51.100.1, 203.0.113.5, 127.0.0.1" {
		t.Errorf("trusted peer: backend X-Forwarded-For = %q, want [198.51.100.1, 203.0.113.5, 127.0.0.1]", got)
	}
}

// M9: from a peer that is not a trusted proxy, forwarding claims other than
// X-Forwarded-For / X-Real-IP / X-Forwarded-Proto went to the backend
// verbatim (Forwarded, X-Forwarded-Host, X-Original-URL, CF-Connecting-IP,
// ...). They are now removed; a trusted proxy's are kept.

var secForwardingClaims = map[string]string{
	"Forwarded":           "for=1.1.1.1;host=evil.test",
	"X-Forwarded-Host":    "evil.test",
	"X-Forwarded-Port":    "1",
	"X-Forwarded-Server":  "evil",
	"X-Forwarded-Prefix":  "/admin",
	"X-Forwarded-Scheme":  "https",
	"X-Forwarded-Ssl":     "on",
	"X-Original-URL":      "/admin",
	"X-Rewrite-URL":       "/admin",
	"X-Client-IP":         "1.1.1.1",
	"True-Client-IP":      "1.1.1.1",
	"CF-Connecting-IP":    "1.1.1.1",
	"Fastly-Client-IP":    "1.1.1.1",
	"X-Cluster-Client-IP": "1.1.1.1",
}

func secClaimHeaders() string {
	var b strings.Builder
	for k, v := range secForwardingClaims {
		b.WriteString(k + ": " + v + "\r\n")
	}
	return b.String()
}

func TestForwarded_UntrustedClaimsStripped(t *testing.T) {
	backend, last := secHeaderBackend(t)
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{})
	secRaw(t, addr, secGet("/", secClaimHeaders()), 2*time.Second)
	got := last()
	for k := range secForwardingClaims {
		if v := got.Values(k); len(v) != 0 {
			t.Errorf("untrusted peer's %s reached the backend: %q", k, v)
		}
	}
}

func TestForwarded_TrustedClaimsKept(t *testing.T) {
	backend, last := secHeaderBackend(t)
	_, addr := secSite(t, &ListenerConfig{TrustedProxies: []string{"127.0.0.1/32"}}, []string{secHost(backend)}, secOpts{})
	secRaw(t, addr, secGet("/", secClaimHeaders()), 2*time.Second)
	got := last()
	for k, v := range secForwardingClaims {
		if got.Get(k) != v {
			t.Errorf("trusted proxy's %s = %q, want %q", k, got.Get(k), v)
		}
	}
}

// TestSetForwardedHeaders_StripsUntrustedClaims: the in-place variant the
// FastCGI path uses applies the same rules.
func TestSetForwardedHeaders_StripsUntrustedClaims(t *testing.T) {
	s := &HTTPServer{Listener: &ListenerConfig{}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.10:5555"
	for k, v := range secForwardingClaims {
		r.Header.Set(k, v)
	}
	s.setForwardedHeaders(r)
	for k := range secForwardingClaims {
		if v := r.Header.Get(k); v != "" {
			t.Errorf("%s kept for an untrusted peer: %q", k, v)
		}
	}
	if r.Header.Get("X-Forwarded-For") != "192.0.2.10" || r.Header.Get("X-Real-IP") != "192.0.2.10" {
		t.Errorf("XFF=%q X-Real-IP=%q, want the peer", r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"))
	}
}

// TestConnectionTokensCannotStripInjectedHeaders (Low): a client listing
// header names in Connection: used to make ReverseProxy remove the headers
// nvelox had just set (X-Real-IP, X-Request-ID, request_set ones).
func TestConnectionTokensCannotStripInjectedHeaders(t *testing.T) {
	backend, last := secHeaderBackend(t)
	l := &ListenerConfig{
		RequestID: config.RequestIDConfig{Enabled: true},
		Headers:   config.HeadersConfig{RequestSet: map[string]string{"X-Proxy": "nvelox"}},
	}
	_, addr := secSite(t, l, []string{secHost(backend)}, secOpts{})
	resp, _ := secRaw(t, addr, "GET / HTTP/1.1\r\nHost: edge.test\r\nConnection: close, X-Real-IP, X-Request-ID, X-Proxy, X-Forwarded-For, X-Forwarded-Proto\r\n\r\n", 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") {
		t.Fatalf("status %q", secStatus(resp))
	}
	got := last()
	if got.Get("X-Real-IP") != "127.0.0.1" || got.Get("X-Forwarded-For") != "127.0.0.1" || got.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("client-IP headers stripped: X-Real-IP=%q XFF=%q XFP=%q", got.Get("X-Real-IP"), got.Get("X-Forwarded-For"), got.Get("X-Forwarded-Proto"))
	}
	if !hex32.MatchString(got.Get("X-Request-ID")) {
		t.Errorf("X-Request-ID stripped: %q", got.Get("X-Request-ID"))
	}
	if got.Get("X-Proxy") != "nvelox" {
		t.Errorf("request_set header stripped: X-Proxy=%q", got.Get("X-Proxy"))
	}
}

// M7: cookie stickiness used the raw cookie value as the store key (any
// size, any value, written to the store), never issued the cookie to a new
// client and set it without Secure / SameSite; header stickiness used the
// raw header value as the key.

func secStickySite(t *testing.T, mode string, servers ...*httptest.Server) (*HTTPServer, *sticky.Store) {
	t.Helper()
	store := sticky.NewStore(time.Hour)
	t.Cleanup(store.Stop)
	addrs := make([]string, len(servers))
	for i, ts := range servers {
		addrs[i] = secHost(ts)
	}
	be := &config.Backend{StickySession: config.StickyConfig{Type: mode, HeaderName: "X-Session"}}
	return secNewSite(t, &ListenerConfig{}, addrs, secOpts{backend: be, store: store}), store
}

func secNamedBackend(t *testing.T, name string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, name) }))
	t.Cleanup(ts.Close)
	return ts
}

func TestSticky_CookieIssuedWithAttributes(t *testing.T) {
	a := secNamedBackend(t, "A")
	s, _ := secStickySite(t, "cookie", a)

	for _, overTLS := range []bool{false, true} {
		req := httptest.NewRequest("GET", "http://edge.test/", nil)
		if overTLS {
			req.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("TLS=%v: %d cookies issued to a new client, want 1", overTLS, len(cookies))
		}
		c := cookies[0]
		if c.Name != "NVELOX_SRV" || c.Value != sticky.ServerToToken(secHost(a)) {
			t.Errorf("cookie %s=%s, want NVELOX_SRV=<token of the server>", c.Name, c.Value)
		}
		if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Secure != overTLS {
			t.Errorf("TLS=%v: HttpOnly=%v SameSite=%v Path=%q Secure=%v", overTLS, c.HttpOnly, c.SameSite, c.Path, c.Secure)
		}
	}
}

func TestSticky_CookieSelectsItsServer(t *testing.T) {
	a, b := secNamedBackend(t, "A"), secNamedBackend(t, "B")
	s, _ := secStickySite(t, "cookie", a, b)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("GET", "http://edge.test/", nil)
		req.AddCookie(&http.Cookie{Name: "NVELOX_SRV", Value: sticky.ServerToToken(secHost(b))})
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Body.String() != "B" {
			t.Fatalf("request %d with B's cookie went to %q", i, rec.Body.String())
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatalf("request %d: cookie re-issued although it already pins the server", i)
		}
	}
}

func TestSticky_ForgedCookieNeverStored(t *testing.T) {
	a := secNamedBackend(t, "A")
	s, store := secStickySite(t, "cookie", a)
	for _, v := range []string{strings.Repeat("a", 4000), "0123456789abcdef", "../../etc"} {
		req := httptest.NewRequest("GET", "http://edge.test/", nil)
		req.AddCookie(&http.Cookie{Name: "NVELOX_SRV", Value: v})
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("cookie %.20q: status %d", v, rec.Code)
		}
		if cookies := rec.Result().Cookies(); len(cookies) != 1 || cookies[0].Value != sticky.ServerToToken(secHost(a)) {
			t.Fatalf("cookie %.20q: a fresh cookie for the chosen server must be issued, got %v", v, cookies)
		}
	}
	if n := store.Len(); n != 0 {
		t.Fatalf("client cookie values written to the sticky store: %d entries", n)
	}
}

func TestSticky_HeaderKeyHashedAndBounded(t *testing.T) {
	a := secNamedBackend(t, "A")
	s, store := secStickySite(t, "header", a)
	send := func(v string) {
		req := httptest.NewRequest("GET", "http://edge.test/", nil)
		req.Header.Set("X-Session", v)
		s.ServeHTTP(httptest.NewRecorder(), req)
	}
	send("session-1")
	sum := sha256.Sum256([]byte("session-1"))
	if store.Get("session-1") != "" || store.Get(hex.EncodeToString(sum[:])) != secHost(a) {
		t.Fatalf("header value not stored as its SHA-256 (raw=%q hashed=%q)", store.Get("session-1"), store.Get(hex.EncodeToString(sum[:])))
	}
	send(strings.Repeat("x", 257)) // over the 256-byte cap
	if n := store.Len(); n != 1 {
		t.Fatalf("over-long header value stored: %d entries, want 1", n)
	}
}
