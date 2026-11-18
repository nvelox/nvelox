//go:build linux

package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/denylist"
	"nvelox/core/sticky"
	"nvelox/lb"
)

// The tests of this file compare the two paths of an HTTP listener, the
// event loops and net/http, on what a site's configuration asks of both:
// its routes, its gates, what it does about a backend that fails. Each
// also says what the answer is to be, so that two paths that both miss it
// do not pass.

// bothPaths runs f for net/http and for the event loops.
func bothPaths(t *testing.T, f func(t *testing.T, fast bool)) {
	t.Helper()
	for _, fast := range []bool{false, true} {
		t.Run(map[bool]string{false: "net/http", true: "event loops"}[fast], func(t *testing.T) { f(t, fast) })
	}
}

// plainSite is a site "site" for plain HTTP whose backend "be" is servers.
func plainSite(be *config.Backend, servers ...string) *HTTPServer {
	be.Servers = servers
	return fastTestSite(&ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}, be)
}

func statusOf(t *testing.T, addr, path string) int {
	t.Helper()
	return exchange(t, addr, "GET "+path+" HTTP/1.1\r\nHost: h\r\n\r\n", "GET")[0].StatusCode
}

// A listener's routes choose the backend of a request, rewrite its path,
// and keep with net/http what only net/http serves (files, FastCGI,
// redirects, expires). The event loops and net/http answer every request
// alike, and the same backend gets the same request from both.
func TestFastPath_RoutesMatchNetHTTP(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "files", "file.txt"), []byte("from the disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A script that exists, so that its request is sent to FastCGI.
	if err := os.MkdirAll(filepath.Join(root, "cgi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgi", "x.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	names := []string{"be", "api", "app"}
	backs := map[string]*rawBackend{}
	for _, n := range names {
		backs[n] = newRawBackend(t)
	}
	routes := []config.RouteConfig{
		{Match: config.RouteMatch{Host: "api.test"}, Backend: "api"},
		{Match: config.RouteMatch{PathRegex: `^/v(\d+)/users/(\d+)$`}, Backend: "api", Rewrite: config.RewriteConfig{Path: "/users/$2/version/$1"}},
		{Match: config.RouteMatch{PathRegex: `^/old/`}, Backend: "app", Rewrite: config.RewriteConfig{Path: "/new"}},
		{Match: config.RouteMatch{PathPrefix: "/legacy/"}, Backend: "app", Rewrite: config.RewriteConfig{Path: "/modern"}},
		{Match: config.RouteMatch{PathPrefix: "/app/"}, Backend: "app"},
		{Match: config.RouteMatch{PathPrefix: "/files/"}, Static: config.StaticConfig{Root: root}},
		{Match: config.RouteMatch{PathPrefix: "/moved/"}, Redirect: config.RedirectConfig{URL: "https://example.test/new", Code: 301}},
		{Match: config.RouteMatch{PathPrefix: "/cached/"}, Backend: "app", Expires: "1h"},
		{Match: config.RouteMatch{PathPrefix: "/cgi/"}, FastCGI: config.FastCGIConfig{Pass: "127.0.0.1:1", DocumentRoot: root}},
	}
	get := func(host, target string) string { return "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n" }
	cases := []struct {
		name, raw string
		backend   string // the backend that gets the request ("": none)
		body      string // what the answer's body is to hold ("": not looked at)
	}{
		{"no route: the default backend", get("any.test", "/plain"), "be", "hello GET /plain"},
		{"a host route, whatever the case and the port", get("API.test:8080", "/plain"), "api", "hello GET /plain"},
		{"a host that only begins like the route's", get("api.test.example", "/plain"), "be", ""},
		{"a prefix route", get("any.test", "/app/x?y=1"), "app", "hello GET /app/x?y=1"},
		{"a path that is short of the prefix", get("any.test", "/app"), "be", ""},
		{"a prefix route by the canonical path", get("any.test", "/x/../app/y"), "app", "hello GET /app/y"},
		{"a prefix route by the decoded path", get("any.test", "/%61pp/z"), "app", "hello GET /%61pp/z"},
		{"a regex route, rewritten with what it captured", get("any.test", "/v2/users/7?x=1"), "api", "hello GET /users/7/version/2?x=1"},
		{"a path the regex does not match", get("any.test", "/v2/users/abc"), "be", "hello GET /v2/users/abc"},
		{"a regex route with a fixed rewrite", get("any.test", "/old/thing"), "app", "hello GET /new"},
		{"a prefix route with a rewrite", get("any.test", "/legacy/a/b?q=2"), "app", "hello GET /modern?q=2"},
		{"a route of files", get("any.test", "/files/file.txt"), "", "from the disk"},
		{"a redirect", get("any.test", "/moved/x"), "", ""},
		{"a route with expires", get("any.test", "/cached/x"), "app", "hello GET /cached/x"},
		{"a FastCGI route whose server is away", get("any.test", "/cgi/x.php"), "", ""},
	}
	type answer struct {
		status                    int
		body, location, cache, to string
	}
	var got [2][]answer
	for i, fast := range []bool{false, true} {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Backend: "be", Routes: routes}
		backends, balancers := map[string]*config.Backend{}, map[string]lb.Balancer{}
		for _, n := range names {
			backends[n] = &config.Backend{Name: n, Servers: []string{backs[n].addr()}}
			balancers[n] = lb.NewRoundRobin(backends[n].Servers)
		}
		s := NewHTTPServer(l, balancers, backends, nil, nil, nil, nil, nil)
		addr := startTestGroup(t, s, fast)
		for _, c := range cases {
			before := map[string]int{}
			for _, n := range names {
				before[n] = backs[n].count()
			}
			resp := exchange(t, addr, c.raw, "GET")[0]
			a := answer{status: resp.StatusCode, body: readBody(resp), location: resp.Header.Get("Location"), cache: resp.Header.Get("Cache-Control")}
			for _, n := range names {
				if backs[n].count() != before[n] {
					a.to += n
				}
			}
			got[i] = append(got[i], a)
		}
	}
	for i, c := range cases {
		slow, fast := got[0][i], got[1][i]
		if slow != fast {
			t.Errorf("%s:\n net/http     %+v\n event loops  %+v", c.name, slow, fast)
		}
		if fast.to != c.backend || (c.body != "" && fast.body != c.body) {
			t.Errorf("%s: backend %q got it and the answer is %q; want backend %q and %q", c.name, fast.to, fast.body, c.backend, c.body)
		}
	}
	// What the routes of net/http's own add, so that the comparison above
	// is not one of two answers that both miss it.
	for i, c := range cases {
		a := got[1][i]
		switch c.name {
		case "a redirect":
			if a.status != 301 || a.location != "https://example.test/new" {
				t.Errorf("%s: %d to %q", c.name, a.status, a.location)
			}
		case "a route with expires":
			if !strings.Contains(a.cache, "max-age=3600") {
				t.Errorf("%s: Cache-Control %q", c.name, a.cache)
			}
		case "a FastCGI route whose server is away":
			if a.status < 500 {
				t.Errorf("%s: %d", c.name, a.status)
			}
		}
	}
}

// Which X-Request-Id a request goes on with is the listener's policy: an
// id the client sent is kept from a trusted proxy, and from anyone with
// request_id.trust_inbound; any other request gets a new one, and so does
// one whose id is not an id. The event loops and net/http decide alike.
func TestFastPath_InboundRequestIDMatchesNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	cases := []struct {
		name         string
		trustInbound bool
		proxies      []string
		sent         string
		kept         bool
	}{
		{"a client's id is replaced", false, nil, "abc-123", false},
		{"with trust_inbound it is kept", true, nil, "abc-123", true},
		{"a trusted proxy's is kept", false, []string{"127.0.0.0/8"}, "ABC-123-def", true},
		{"a peer that is not among the trusted proxies", false, []string{"10.0.0.0/8"}, "abc-123", false},
		{"what is not an id is replaced, trust_inbound or not", true, nil, "abc_123", false},
		{"one longer than an id may be", true, []string{"127.0.0.0/8"}, strings.Repeat("a", 129), false},
		{"the longest that may be", true, nil, strings.Repeat("a", 128), true},
		{"none sent", true, []string{"127.0.0.0/8"}, "", false},
	}
	for _, c := range cases {
		for _, fast := range []bool{false, true} {
			path := map[bool]string{false: "net/http", true: "the event loops"}[fast]
			l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", TrustedProxies: c.proxies}
			l.RequestID.Enabled, l.RequestID.TrustInbound = true, c.trustInbound
			addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}}), fast)
			raw := "GET /id HTTP/1.1\r\nHost: h\r\n"
			if c.sent != "" {
				raw += "X-Request-Id: " + c.sent + "\r\n"
			}
			resp := exchange(t, addr, raw+"\r\n", "GET")[0]
			up, back := be.last().Header.Get("X-Request-Id"), resp.Header.Get("X-Request-Id")
			if up == "" || up != back {
				t.Errorf("%s, %s: the backend got %q and the client %q", c.name, path, up, back)
			}
			if kept := up == c.sent; kept != c.kept {
				t.Errorf("%s, %s: sent %q, went on with %q", c.name, path, c.sent, up)
			}
			if !c.kept && (len(up) != 32 || !isValidRequestID(up)) {
				t.Errorf("%s, %s: the new id is %q", c.name, path, up)
			}
		}
	}
}

// A backend that has a balancer and no entry in the configuration is
// served, with the defaults.
func TestFastPath_BackendWithoutAnEntryMatchesNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Backend: "be"}
		s := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{be.addr()})}, nil, nil, nil, nil, nil, nil)
		before := be.count()
		if st := statusOf(t, startTestGroup(t, s, fast), "/ok"); st != 200 || be.count() != before+1 {
			t.Errorf("status %d, %d requests at the backend", st, be.count()-before)
		}
	})
}

// countingGate counts what it is asked, and says yes.
type countingGate struct{ asked atomic.Int32 }

func (g *countingGate) Allow() bool { g.asked.Add(1); return true }

// A client the deny list refuses does not take from the site's rate: the
// lists are asked first.
func TestFastPath_DeniedClientIsNotCountedByTheRateLimit(t *testing.T) {
	be := newRawBackend(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", IPDenylist: []string{"127.0.0.0/8"}}
		s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
		gate := &countingGate{}
		s.RateLimiter = gate
		if st := statusOf(t, startTestGroup(t, s, fast), "/ok"); st != 403 || gate.asked.Load() != 0 {
			t.Errorf("status %d, and the rate limit was asked %d times about a denied client", st, gate.asked.Load())
		}
	})
}

// The gates judge the client, not the peer: behind a trusted proxy the
// client is the one its forwarding header names. And they judge the path
// as it is decoded and made canonical, whatever way the client spelled it.
func TestFastPath_GatesSeeTheClientAndTheDecodedPath(t *testing.T) {
	be := newRawBackend(t)
	cases := []struct {
		name, target, xff string
		status            int
	}{
		{"a client the deny list names, behind the proxy", "/ok", "203.0.113.7", 403},
		{"another client behind the proxy", "/ok", "198.51.100.7", 200},
		{"the proxy's own request", "/ok", "", 200},
		{"a path the access rules deny", "/admin/x", "", 403},
		{"the same path with a letter encoded", "/%61dmin/x", "", 403},
		{"the same path behind encoded dot segments", "/public/%2e%2e/admin", "", 403},
		{"a path that only begins like it", "/adm", "", 200},
	}
	bothPaths(t, func(t *testing.T, fast bool) {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http",
			TrustedProxies: []string{"127.0.0.0/8"}, IPDenylist: []string{"203.0.113.0/24"},
			ACL: []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/admin"}, Action: "deny"}}}
		addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}}), fast)
		for _, c := range cases {
			raw := "GET " + c.target + " HTTP/1.1\r\nHost: h\r\n"
			if c.xff != "" {
				raw += "X-Forwarded-For: " + c.xff + "\r\n"
			}
			if st := exchange(t, addr, raw+"\r\n", "GET")[0].StatusCode; st != c.status {
				t.Errorf("%s: status %d, want %d", c.name, st, c.status)
			}
		}
	})
}

// The addresses blocked while nvelox runs (the runtime deny list) are
// refused like those of the configuration.
func TestFastPath_RuntimeDenyListMatchesNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		s := plainSite(&config.Backend{}, be.addr())
		s.DynDenylist = denylist.New()
		addr := startTestGroup(t, s, fast)
		if st := statusOf(t, addr, "/ok"); st != 200 {
			t.Fatalf("nothing blocked: status %d", st)
		}
		if _, err := s.DynDenylist.Add("127.0.0.1", time.Minute); err != nil {
			t.Fatal(err)
		}
		before := be.count()
		if st := statusOf(t, addr, "/ok"); st != 403 || be.count() != before {
			t.Errorf("a blocked client: status %d, %d requests at the backend", st, be.count()-before)
		}
	})
}

// placeLimiter is a backend's connection limit: max requests at a time.
type placeLimiter struct{ max, taken atomic.Int32 }

func (l *placeLimiter) Acquire() bool {
	if l.taken.Add(1) > l.max.Load() {
		l.taken.Add(-1)
		return false
	}
	return true
}

func (l *placeLimiter) Release() { l.taken.Add(-1) }

// A backend with max_connections serves that many requests at a time: the
// next one is answered 503, and a request that is over gives its place
// back.
func TestFastPath_ConnectionLimitMatchesNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		lim := &placeLimiter{}
		lim.max.Store(1)
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Backend: "be"}
		s := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{be.addr()})},
			map[string]*config.Backend{"be": {Name: "be", Servers: []string{be.addr()}}}, nil,
			map[string]ConnLimiterI{"be": lim}, nil, nil, nil)
		addr := startTestGroup(t, s, fast)
		first := make(chan int, 1)
		go func() { first <- statusOf(t, addr, "/sleep/600ms") }()
		for start := time.Now(); lim.taken.Load() != 1; time.Sleep(2 * time.Millisecond) {
			if time.Since(start) > 5*time.Second {
				t.Fatal("the first request took no place")
			}
		}
		if st := statusOf(t, addr, "/ok"); st != 503 {
			t.Errorf("a second request while the one place is taken: status %d, want 503", st)
		}
		if st := <-first; st != 200 {
			t.Errorf("the first request: status %d", st)
		}
		for start := time.Now(); lim.taken.Load() != 0; time.Sleep(2 * time.Millisecond) {
			if time.Since(start) > 5*time.Second {
				t.Fatalf("%d places are taken with no request left", lim.taken.Load())
			}
		}
		if st := statusOf(t, addr, "/ok"); st != 200 {
			t.Errorf("a request after the place was given back: status %d", st)
		}
	})
}

// toldBreaker is a circuit breaker that notes what it is told.
type toldBreaker struct {
	mu    sync.Mutex
	open  bool
	calls []string
}

func (b *toldBreaker) note(s string) { b.mu.Lock(); b.calls = append(b.calls, s); b.mu.Unlock() }
func (b *toldBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, "allow")
	return !b.open
}
func (b *toldBreaker) RecordSuccess() { b.note("success") }
func (b *toldBreaker) RecordFailure() { b.note("failure") }
func (b *toldBreaker) Release()       { b.note("release") }
func (b *toldBreaker) told() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.calls...)
}

// A backend's circuit breaker and its passive health record are asked and
// told the same on both paths: an answer is a success, a server that
// breaks off a failure, and an open breaker answers 503 without a request
// to the backend.
func TestFastPath_BreakerAndHealthMatchNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		br, ph := &toldBreaker{}, newSecPassive()
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Backend: "be"}
		s := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{be.addr()})},
			map[string]*config.Backend{"be": {Name: "be", Servers: []string{be.addr()}}}, nil, nil,
			map[string]PassiveHealthI{"be": ph}, nil, map[string]CircuitBreakerI{"be": br})
		addr := startTestGroup(t, s, fast)
		if st := statusOf(t, addr, "/ok"); st != 200 {
			t.Fatalf("an answer: status %d", st)
		}
		if st := statusOf(t, addr, "/reset"); st != 502 {
			t.Fatalf("a server that breaks off: status %d", st)
		}
		br.mu.Lock()
		br.open = true
		br.mu.Unlock()
		before := be.count()
		if st := statusOf(t, addr, "/ok"); st != 503 || be.count() != before {
			t.Errorf("with the breaker open: status %d, %d requests at the backend", st, be.count()-before)
		}
		if got, want := br.told(), []string{"allow", "success", "allow", "failure", "allow"}; !reflect.DeepEqual(got, want) {
			t.Errorf("the breaker was told %v, want %v", got, want)
		}
		if f, ok := ph.counts(be.addr()); f != 1 || ok != 1 {
			t.Errorf("the health record has %d failures and %d successes, want one of each", f, ok)
		}
	})
}

// ejectingPassive is passive health that takes a server out at its first
// failure, as max_fails 1 does.
type ejectingPassive struct{ b lb.Balancer }

func (p ejectingPassive) RecordFailure(s string) { p.b.Eject(s, time.Hour) }
func (p ejectingPassive) RecordSuccess(string)   {}

// A client that has passive health take every server of a backend out (a
// page they answer too slowly: 504) does not leave the site answering 503
// to everyone: the backend sends to its servers as if they were healthy,
// on both paths, until one is back.
func TestFastPath_EveryServerEjectedStillServes(t *testing.T) {
	first, second := newRawBackend(t), newRawBackend(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		servers := []string{first.addr(), second.addr()}
		bal := lb.NewRoundRobin(servers)
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Backend: "be"}
		be := &config.Backend{Name: "be", Servers: servers, Timeouts: config.TimeoutConfig{ResponseHeader: "200ms"}}
		s := NewHTTPServer(l, map[string]lb.Balancer{"be": bal}, map[string]*config.Backend{"be": be}, nil, nil,
			map[string]PassiveHealthI{"be": ejectingPassive{bal}}, nil, nil)
		addr := startTestGroup(t, s, fast)
		for i := 0; i < 2; i++ {
			if st := statusOf(t, addr, "/sleep/1s"); st != 504 {
				t.Fatalf("a page the servers answer too slowly: status %d, want 504", st)
			}
		}
		if !bal.AllOut() {
			t.Fatal("two slow pages did not take both servers out")
		}
		before := first.count() + second.count()
		if st := statusOf(t, addr, "/ok"); st != 200 || first.count()+second.count() != before+1 {
			t.Errorf("with every server taken out: status %d after %d requests at the servers; want 200 from one of them",
				st, first.count()+second.count()-before)
		}
	})
}

// A site whose access log is off (its listener's access_log, or
// logging.access) has no line for its requests on either path; a site with
// it on beside it has one per request.
func TestFastPath_AccessLogSwitch(t *testing.T) {
	be := newRawBackend(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		path := secAccessLog(t)
		on := fastTestSite(&ListenerConfig{Name: "on", Addr: "127.0.0.1:0", Protocol: "http"}, &config.Backend{Servers: []string{be.addr()}})
		off := fastTestSite(&ListenerConfig{Name: "off", Addr: "127.0.0.1:0", Protocol: "http", AccessLogOff: true}, &config.Backend{Servers: []string{be.addr()}})
		onAddr, offAddr := startTestGroup(t, on, fast), startTestGroup(t, off, fast)
		for _, c := range []struct{ addr, path string }{{offAddr, "/quiet"}, {onAddr, "/logged"}, {offAddr, "/quiet"}} {
			if st := statusOf(t, c.addr, c.path); st != 200 {
				t.Fatalf("GET %s: status %d", c.path, st)
			}
		}
		secLogLines(t, path, 1)
		time.Sleep(200 * time.Millisecond) // a line of the quiet site would be in by now
		data, _ := os.ReadFile(path)
		if n := strings.Count(string(data), "/logged"); n != 1 {
			t.Errorf("the site with its access log on has %d lines, want 1:\n%s", n, data)
		}
		if strings.Contains(string(data), "/quiet") {
			t.Errorf("the site with its access log off has lines:\n%s", data)
		}
	})
}

// A backend with retry.on "502" has a request tried on its next server when
// the first answers 502; one without does not.
func TestFastPath_RetryOn502MatchesNetHTTP(t *testing.T) {
	first, second := newRawBackend(t), newRawBackend(t)
	for on, attempts := range map[string]int{"502": 2, "503": 1} {
		bothPaths(t, func(t *testing.T, fast bool) {
			s := plainSite(&config.Backend{Retry: config.RetryConfig{Attempts: 2, On: on}}, first.addr(), second.addr())
			addr := startTestGroup(t, s, fast)
			before := first.count() + second.count()
			st := statusOf(t, addr, "/502")
			if got := first.count() + second.count() - before; st != 502 || got != attempts {
				t.Errorf("retry.on %q: status %d after %d requests at the servers, want 502 after %d", on, st, got, attempts)
			}
		})
	}
}

// A backend that has started to answer and then sends nothing for its
// timeouts.read is cut off, and the client's connection with it, long
// before the backend goes on.
func TestFastPath_SilentBackendMatchesNetHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\nabc")
				time.Sleep(4 * time.Second)
				io.WriteString(c, "defghij")
			}()
		}
	}()
	quietLog(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		s := plainSite(&config.Backend{Timeouts: config.TimeoutConfig{Read: "300ms"}}, ln.Addr().String())
		c, err := net.Dial("tcp", startTestGroup(t, s, fast))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		start := time.Now()
		io.WriteString(c, "GET /quiet HTTP/1.1\r\nHost: h\r\n\r\n")
		// (How much of the answer the client has when it is cut is each
		// path's own: net/http had not sent its head yet.)
		got, err := io.ReadAll(c)
		if took := time.Since(start); err != nil || strings.Contains(string(got), "defghij") || took > 2*time.Second {
			t.Errorf("the answer of a backend silent for 4 s, with timeouts.read 300ms: %q, error %v, after %v; want the connection closed within two seconds, without the rest", got, err, took)
		}
	})
}

// Sticky sessions are net/http's work: a site with them is served by
// net/http on a listener of the event loops too, and a new client gets
// its cookie.
func TestFastPath_StickySessionsMatchNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		store := sticky.NewStore(time.Hour)
		t.Cleanup(store.Stop)
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Backend: "be"}
		s := NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{be.addr()})},
			map[string]*config.Backend{"be": {Name: "be", Servers: []string{be.addr()}, StickySession: config.StickyConfig{Type: "cookie"}}},
			nil, nil, nil, map[string]*sticky.Store{"be": store}, nil)
		resp := exchange(t, startTestGroup(t, s, fast), "GET /ok HTTP/1.1\r\nHost: h\r\n\r\n", "GET")[0]
		if c := resp.Header.Get("Set-Cookie"); resp.StatusCode != 200 || !strings.HasPrefix(c, "NVELOX_SRV="+sticky.ServerToToken(be.addr())) {
			t.Errorf("status %d, Set-Cookie %q; want the cookie of the backend's server", resp.StatusCode, c)
		}
	})
}

// A backend_tls backend whose TLS settings cannot be used (here: a CA file
// that is not there) is never spoken to in plaintext: its requests are
// answered 502, and nothing reaches the server.
func TestFastPath_BackendTLSThatCannotBeSetUpGetsNoPlaintext(t *testing.T) {
	be := newRawBackend(t)
	quietLog(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		s := tlsBackendSite([]string{be.addr()}, config.BackendTLSConfig{CACert: filepath.Join(t.TempDir(), "no-such-ca.pem")}, config.Backend{})
		before := be.connCount()
		if st := statusOf(t, startTestGroup(t, s, fast), "/ok"); st != 502 || be.connCount() != before {
			t.Errorf("status %d, %d connections to the backend; want 502 and none", st, be.connCount()-before)
		}
	})
}

// An HTTP backend's timeouts.connect bounds the opening of a connection to
// its server, and the listener's where the backend names none.
func TestFastPath_ConnectTimeoutMatchesNetHTTP(t *testing.T) {
	quietLog(t)
	cases := []struct {
		name string
		l    ListenerConfig
		be   config.Backend
	}{
		{"the backend's", ListenerConfig{}, config.Backend{Timeouts: config.TimeoutConfig{Connect: "300ms"}}},
		{"the listener's", ListenerConfig{Timeouts: config.TimeoutConfig{Connect: "300ms"}}, config.Backend{}},
	}
	for _, c := range cases {
		bothPaths(t, func(t *testing.T, fast bool) {
			l, be := c.l, c.be
			l.Name, l.Addr, l.Protocol = "site", "127.0.0.1:0", "http"
			be.Servers = []string{hangingAddr(t)}
			addr := startTestGroup(t, fastTestSite(&l, &be), fast)
			start := time.Now()
			if st := statusOf(t, addr, "/"); st != 502 {
				t.Fatalf("%s timeouts.connect: a server that does not take the connection: status %d, want 502", c.name, st)
			}
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("%s timeouts.connect of 300ms: answered after %v", c.name, took)
			}
		})
	}
}

// An idle connection to a server is its site's and its backend's: another
// site, or another backend of the same site, opens its own, also to the
// same address, and each finds its own again.
func TestFastPath_IdleConnectionsStayWithTheirSiteAndBackend(t *testing.T) {
	be := newRawBackend(t)
	get := func(t *testing.T, br *bufio.Reader, c net.Conn, host, path string) {
		t.Helper()
		io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s%s: status %d", host, path, resp.StatusCode)
		}
	}
	bothPaths(t, func(t *testing.T, fast bool) {
		// Two sites, the second with two backends: all three on one server.
		one := &ListenerConfig{Name: "one", Addr: "127.0.0.1:0", Protocol: "http", ServerNames: []string{"one.test"}}
		two := &ListenerConfig{Name: "two", Addr: "127.0.0.1:0", Protocol: "http", ServerNames: []string{"two.test"}, Backend: "be",
			Routes: []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/other/"}, Backend: "other"}}}
		servers := []string{be.addr()}
		g := NewBindGroup("127.0.0.1:0", "http")
		g.AddSite(fastTestSite(one, &config.Backend{Servers: servers}))
		g.AddSite(NewHTTPServer(two, map[string]lb.Balancer{"be": lb.NewRoundRobin(servers), "other": lb.NewRoundRobin(servers)},
			map[string]*config.Backend{"be": {Name: "be", Servers: servers}, "other": {Name: "other", Servers: servers}}, nil, nil, nil, nil, nil))
		fastPathOff.Store(!fast)
		err := g.Start()
		fastPathOff.Store(false)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			g.Stop(ctx)
		})
		c, err := net.Dial("tcp", g.BoundAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(c)
		before := be.connCount()
		get(t, br, c, "one.test", "/a")
		get(t, br, c, "two.test", "/a")
		get(t, br, c, "two.test", "/other/a")
		if n := be.connCount() - before; n != 3 {
			t.Errorf("a request to each of two sites and to a second backend, all on one server: %d connections to it, want one each", n)
		}
		get(t, br, c, "one.test", "/b")
		get(t, br, c, "two.test", "/b")
		get(t, br, c, "two.test", "/other/b")
		if n := be.connCount() - before; n != 3 {
			t.Errorf("after a second request to each: %d connections, want the three there were", n)
		}
	})
}

// A site with HTTP/3 says so on its answers over TCP (Alt-Svc), over
// HTTP/1.1 and HTTP/2, on a proxied answer and on one of nvelox's own.
func TestFastTLS_AltSvcMatchesNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	quietLog(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		cert, key := genCertWithCN(t, t.TempDir(), "example.test")
		l := &ListenerConfig{Name: "tls-site", Addr: "127.0.0.1:0", Port: 8443, Protocol: "https", HTTP3: true,
			TLS: &config.TLSConfig{Cert: cert, Key: key}, IPDenylist: []string{"203.0.113.0/24"},
			ACL: []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/deny"}, Action: "deny"}}}
		addr := startTLSGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}}), fast)
		const want = `h3=":8443"; ma=86400`
		for _, r := range tlsExchange(t, addr, "GET /ok HTTP/1.1\r\nHost: example.test\r\n\r\nGET /deny HTTP/1.1\r\nHost: example.test\r\n\r\n", "GET", "GET") {
			if got := r.Header.Get("Alt-Svc"); got != want {
				t.Errorf("HTTP/1.1, status %d: Alt-Svc %q, want %q", r.StatusCode, got, want)
			}
		}
		client := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "example.test"}}}
		defer client.CloseIdleConnections()
		for _, path := range []string{"/ok", "/deny"} {
			resp, err := client.Get("https://" + addr + path)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if got := resp.Header.Get("Alt-Svc"); resp.ProtoMajor != 2 || got != want {
				t.Errorf("HTTP/%d, status %d: Alt-Svc %q, want %q over HTTP/2", resp.ProtoMajor, resp.StatusCode, got, want)
			}
		}
	})
}

// A header rule cannot start another header line, in a request to the
// backend or in an answer to the client: the line breaks of a rule's name
// and value are left out.
func TestFastPath_HeaderRulesCannotAddLines(t *testing.T) {
	be := newRawBackend(t)
	bothPaths(t, func(t *testing.T, fast bool) {
		l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http", Headers: config.HeadersConfig{
			RequestSet:  map[string]string{"X-Rule": "a\r\nX-Injected: request"},
			RequestAdd:  map[string]string{"X-Added\r\nX-Injected": "request"},
			ResponseSet: map[string]string{"X-Rule": "b\r\nX-Injected: response"},
			ResponseAdd: map[string]string{"X-Added\nX-Injected": "response"},
		}}
		addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}}), fast)
		resp := exchange(t, addr, "GET /ok HTTP/1.1\r\nHost: h\r\n\r\n", "GET")[0]
		up := be.last().Header
		if resp.StatusCode != 200 || up.Get("X-Injected") != "" || resp.Header.Get("X-Injected") != "" {
			t.Errorf("status %d; an injected header reached the backend (%q) or the client (%q)", resp.StatusCode, up.Get("X-Injected"), resp.Header.Get("X-Injected"))
		}
		if got := up.Get("X-Rule"); got != "aX-Injected: request" {
			t.Errorf("the backend got X-Rule %q", got)
		}
		if got := resp.Header.Get("X-Rule"); got != "bX-Injected: response" {
			t.Errorf("the client got X-Rule %q", got)
		}
	})
}

// A site with HTTP/3 needs its UDP port. When another socket has it, Start
// fails and leaves nothing behind: no server on the event loops, and the
// TCP port free again. On the loops' own HTTP/3, on the quic-go server
// beside the loops, and without the loops.
func TestBindGroup_HTTP3PortTakenFailsStart(t *testing.T) {
	be := newRawBackend(t)
	quietLog(t)
	for _, v := range []struct {
		name         string
		fast, h3Loop bool
	}{{"event loops", true, true}, {"event loops with quic-go", true, false}, {"net/http with quic-go", false, false}} {
		t.Run(v.name, func(t *testing.T) {
			addr := freeAddr(t)
			taken, err := net.ListenPacket("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer taken.Close()
			cert, key := genCertWithCN(t, t.TempDir(), "example.test")
			l := &ListenerConfig{Name: "tls-site", Addr: addr, Protocol: "https", HTTP3: true, TLS: &config.TLSConfig{Cert: cert, Key: key}}
			g := NewBindGroup(addr, "https")
			g.AddSite(fastTestSite(l, &config.Backend{Servers: []string{be.addr()}}))
			old := h3OnLoops
			fastPathOff.Store(!v.fast)
			h3OnLoops = v.h3Loop
			err = g.Start()
			fastPathOff.Store(false)
			h3OnLoops = old
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				g.Stop(ctx)
				t.Fatal("Start succeeded with the UDP port of HTTP/3 taken")
			}
			if g.fast != nil || g.h3loops != nil {
				t.Errorf("after the failed Start the group still has a server on the event loops (%v) or its HTTP/3 (%v)", g.fast != nil, g.h3loops != nil)
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatalf("the TCP port is not free after the failed Start: %v", err)
			}
			ln.Close()
		})
	}
}
