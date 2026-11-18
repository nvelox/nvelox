//go:build linux

package httpproxy

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"

	"github.com/nvelox/ngx/web"
)

// A site reaches the event loops as its configuration says: every field of
// web.Site, web.Route and web.Backend that nvelox fills in, with the
// defaults where the configuration names nothing.
func TestFastSite_FromTheConfiguration(t *testing.T) {
	l := &ListenerConfig{Name: "shop", Addr: "127.0.0.1:0", Protocol: "http", Backend: "app",
		Timeouts:       config.TimeoutConfig{Read: "2s", Write: "3s", Connect: "4s"},
		TrustedProxies: []string{"10.0.0.0/8", "192.0.2.0/24"},
		MaxBodySize:    "1MB",
		Headers: config.HeadersConfig{RequestAdd: map[string]string{"X-A": "a"}, RequestSet: map[string]string{"X-S": "s"},
			RequestRemove: []string{"X-R"}, ResponseSet: map[string]string{"X-Resp": "r"}},
		Routes: []config.RouteConfig{
			{Match: config.RouteMatch{Host: "API.Example"}, Backend: "api", Headers: config.HeadersConfig{RequestSet: map[string]string{"X-Route": "1"}}},
			{Match: config.RouteMatch{PathRegex: `^/v(\d+)/`}, Backend: "api", Rewrite: config.RewriteConfig{Path: "/$1"}},
			{Match: config.RouteMatch{PathPrefix: "/files/"}, Static: config.StaticConfig{Root: "/srv"}},
			{Match: config.RouteMatch{PathPrefix: "/php/"}, FastCGI: config.FastCGIConfig{Pass: "127.0.0.1:9000"}},
			{Match: config.RouteMatch{PathPrefix: "/old/"}, Redirect: config.RedirectConfig{URL: "/new"}},
			{Match: config.RouteMatch{PathPrefix: "/spa/"}, Backend: "app", TryFiles: config.TryFilesConfig{Files: []string{"$uri"}}},
			{Match: config.RouteMatch{PathPrefix: "/cached/"}, Backend: "app", Expires: "1h"},
		},
	}
	l.RequestID.Enabled, l.RequestID.TrustInbound = true, true
	key := []byte("0123456789abcdef0123456789abcdef")
	backends := map[string]*config.Backend{
		"app": {Name: "app", Servers: []string{"127.0.0.1:1"},
			Timeouts: config.TimeoutConfig{Connect: "5s", ResponseHeader: "6s", Read: "7s"},
			Retry:    config.RetryConfig{Attempts: 3, On: "502"}},
		"api":     {Name: "api", Servers: []string{"127.0.0.1:2"}, SendProxyV2: true, Retry: config.RetryConfig{Attempts: 2}},
		"signed":  {Name: "signed", Servers: []string{"127.0.0.1:3"}, SendProxyV2: true, SendProxyKey: key},
		"sticky":  {Name: "sticky", Servers: []string{"127.0.0.1:4"}, StickySession: config.StickyConfig{Type: "cookie"}},
		"tls":     {Name: "tls", Servers: []string{"127.0.0.1:5"}, BackendTLS: config.BackendTLSConfig{Enabled: true, ServerName: "backend.test"}},
		"badtls":  {Name: "badtls", Servers: []string{"127.0.0.1:6"}, BackendTLS: config.BackendTLSConfig{Enabled: true, CACert: filepath.Join(t.TempDir(), "none.pem")}},
		"orphan":  {Name: "orphan", Servers: []string{"127.0.0.1:7"}},
		"default": {Name: "default", Servers: []string{"127.0.0.1:8"}},
	}
	balancers := map[string]lb.Balancer{}
	for name, be := range backends {
		if name != "orphan" { // a configured backend without a balancer
			balancers[name] = lb.NewRoundRobin(be.Servers)
		}
	}
	balancers["bare"] = lb.NewRoundRobin([]string{"127.0.0.1:9"}) // a balancer without a configuration entry
	cl, br, ph := &placeLimiter{}, &toldBreaker{}, newSecPassive()
	s := NewHTTPServer(l, balancers, backends, nil, map[string]ConnLimiterI{"app": cl}, map[string]PassiveHealthI{"app": ph},
		nil, map[string]CircuitBreakerI{"app": br})
	t.Cleanup(s.Close)
	s.altSvcHeader = `h3=":443"; ma=86400`
	site := s.fastSite()
	if site != s.fastSite() {
		t.Error("the site is built again when asked again")
	}

	if site.Name != "shop" || site.ReadTimeout != 2*time.Second || site.WriteTimeout != 3*time.Second {
		t.Errorf("name %q, read %v, write %v; want shop, 2s, 3s", site.Name, site.ReadTimeout, site.WriteTimeout)
	}
	if !site.RequestID || !site.TrustRequestID || len(site.TrustedProxies) != 2 || site.AltSvc != `h3=":443"; ma=86400` || site.MaxBodySize != 1<<20 {
		t.Errorf("request id %v trust %v, %d trusted proxies, Alt-Svc %q, max body %d", site.RequestID, site.TrustRequestID, len(site.TrustedProxies), site.AltSvc, site.MaxBodySize)
	}
	if site.Admit == nil || site.DefaultBackend != "app" || len(site.RequestRules) != 3 || len(site.ResponseRules) != 1 {
		t.Errorf("admit set %v, default backend %q, %d request and %d response rules", site.Admit != nil, site.DefaultBackend, len(site.RequestRules), len(site.ResponseRules))
	}
	if len(site.Routes) != 7 {
		t.Fatalf("%d routes, want 7", len(site.Routes))
	}
	r := site.Routes
	if r[0].Host != "api.example" || r[0].Backend != "api" || len(r[0].RequestRules) != 1 || r[0].Slow {
		t.Errorf("the host route: %+v", r[0])
	}
	if r[1].PathRegex == nil || r[1].Rewrite != "/$1" || r[1].Backend != "api" || r[1].Slow {
		t.Errorf("the regex route: %+v", r[1])
	}
	for i, name := range []string{"files", "FastCGI", "redirect", "try_files", "expires"} {
		if !r[i+2].Slow {
			t.Errorf("a route with %s is the loops': %+v", name, r[i+2])
		}
	}
	if r[2].PathPrefix != "/files/" {
		t.Errorf("the prefix of the files route: %q", r[2].PathPrefix)
	}

	// The backends: every name that has a balancer, and none else.
	for _, name := range []string{"app", "api", "signed", "sticky", "tls", "badtls", "default", "bare"} {
		if b := site.Backends[name]; b == nil || b.Name != name || b.Balancer == nil {
			t.Errorf("backend %s: %+v", name, b)
		}
	}
	if b := site.Backends["orphan"]; b != nil || len(site.Backends) != 8 {
		t.Errorf("%d backends, the one without a balancer %+v", len(site.Backends), b)
	}
	app := site.Backends["app"]
	if app.ConnLimiter != cl || app.Breaker != br || app.Health != ph {
		t.Error("the app backend lost its limiter, breaker or health record")
	}
	if app.ConnectTimeout != 5*time.Second || app.ResponseHeaderTimeout != 6*time.Second || app.SilenceTimeout != 7*time.Second {
		t.Errorf("app's timeouts: connect %v, response header %v, silence %v", app.ConnectTimeout, app.ResponseHeaderTimeout, app.SilenceTimeout)
	}
	if app.Retry != (web.Retry{Attempts: 3, On502: true}) || app.Slow || app.TLS != nil || app.ProxyHeader != nil {
		t.Errorf("app: retry %+v, slow %v, TLS %v, PROXY header %v", app.Retry, app.Slow, app.TLS != nil, app.ProxyHeader != nil)
	}
	if def := site.Backends["default"]; def.ConnectTimeout != 4*time.Second || def.ResponseHeaderTimeout != 60*time.Second || def.SilenceTimeout != 0 || def.Retry != (web.Retry{Attempts: 1}) {
		t.Errorf("a backend with nothing set: connect %v (the listener's), response header %v, silence %v, retry %+v", def.ConnectTimeout, def.ResponseHeaderTimeout, def.SilenceTimeout, def.Retry)
	}
	if api := site.Backends["api"]; api.Retry != (web.Retry{Attempts: 2, OnConnectFailure: true}) || api.ProxyHeader == nil || api.ProxyHeaderVaries {
		t.Errorf("api: retry %+v, PROXY header %v, varies %v", api.Retry, api.ProxyHeader != nil, api.ProxyHeaderVaries)
	}
	client := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4321}
	local := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80}
	plain, err := site.Backends["api"].ProxyHeader(client, local)
	want, _ := backendProxyHeader(client, local, nil, time.Time{})
	if err != nil || string(plain) != string(want) {
		t.Errorf("api's PROXY header: %x, %v; want %x", plain, err, want)
	}
	signed := site.Backends["signed"]
	if !signed.ProxyHeaderVaries {
		t.Error("a signed header does not vary")
	}
	if h, err := signed.ProxyHeader(client, local); err != nil || len(h) <= len(want) {
		t.Errorf("the signed header: %d bytes, %v; want more than the %d of an unsigned one", len(h), err, len(want))
	}
	if !site.Backends["sticky"].Slow {
		t.Error("a sticky backend is the loops'")
	}
	if tb := site.Backends["tls"]; tb.TLS == nil || tb.Slow || tb.TLS.ServerName != "backend.test" {
		t.Errorf("a backend_tls backend: TLS %v, slow %v", tb.TLS != nil, tb.Slow)
	}
	if bt := site.Backends["badtls"]; bt.TLS != nil || !bt.Slow {
		t.Errorf("a backend_tls backend whose TLS cannot be set up: TLS %v, slow %v; want none, net/http's (502)", bt.TLS != nil, bt.Slow)
	}
}

// The defaults of a site whose listener names no limits.
func TestFastSite_Defaults(t *testing.T) {
	s := NewHTTPServer(&ListenerConfig{Name: "d", Addr: "127.0.0.1:0", Protocol: "http"}, nil, nil, nil, nil, nil, nil, nil)
	t.Cleanup(s.Close)
	site := s.fastSite()
	if site.ReadTimeout != defaultReadTimeout || site.WriteTimeout != defaultWriteTimeout || site.RequestID || site.MaxBodySize != 0 || len(site.Backends) != 0 || !site.AccessLog {
		t.Errorf("read %v, write %v, request id %v, max body %d, %d backends, access log %v", site.ReadTimeout, site.WriteTimeout, site.RequestID, site.MaxBodySize, len(site.Backends), site.AccessLog)
	}
	quiet := NewHTTPServer(&ListenerConfig{Name: "q", Addr: "127.0.0.1:0", Protocol: "http", AccessLogOff: true}, nil, nil, nil, nil, nil, nil, nil)
	t.Cleanup(quiet.Close)
	if quiet.fastSite().AccessLog {
		t.Errorf("a listener whose access log is off: the site's AccessLog is on")
	}
}

// The gates Admit runs, and in which order: the deny and allow lists, the
// listener's rate, the client's rate, the access rules.
func TestFastSite_Admit(t *testing.T) {
	l := &ListenerConfig{Name: "g", Addr: "127.0.0.1:0", Protocol: "http", IPDenylist: []string{"203.0.113.0/24"}, IPAllowlist: []string{"203.0.113.0/24", "198.51.100.0/24"},
		ACL: []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/admin"}, Action: "deny", Status: 451}}}
	s := NewHTTPServer(l, nil, nil, nil, nil, nil, nil, nil)
	t.Cleanup(s.Close)
	rate := &countingGate{}
	s.RateLimiter = rate
	ask := func(client, path string) int {
		return s.admit(&web.Request{Method: http.MethodGet, Path: path, Client: client})
	}
	if st := ask("203.0.113.9", "/"); st != 403 || rate.asked.Load() != 0 {
		t.Errorf("a denied client: %d, rate asked %d times", st, rate.asked.Load())
	}
	if st := ask("192.0.2.1", "/"); st != 403 {
		t.Errorf("a client the allow list does not name: %d", st)
	}
	if st := ask("198.51.100.9", "/admin/x"); st != 451 {
		t.Errorf("a path the access rules deny with 451: %d", st)
	}
	if st := ask("198.51.100.9", "/ok"); st != 0 || rate.asked.Load() != 2 {
		t.Errorf("an allowed request: %d, rate asked %d times (want 2: this one and the denied path's)", st, rate.asked.Load())
	}
}

// What the event loops log goes to nvelox's error log, at its level: a
// backend that does not start its answer in time is an error, a retry a
// warning.
func TestFastHost_LoopsLogToTheErrorLog(t *testing.T) {
	errPath := filepath.Join(t.TempDir(), "error.log")
	if err := logging.Init("info", "", errPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logging.Init("warning", "", "") })
	slow, first, second := newRawBackend(t), newRawBackend(t), newRawBackend(t)
	late := startTestGroup(t, plainSite(&config.Backend{Timeouts: config.TimeoutConfig{ResponseHeader: "200ms"}}, slow.addr()), true)
	if st := statusOf(t, late, "/sleep/1s"); st != 504 {
		t.Fatalf("a backend that answers too late: status %d", st)
	}
	retried := startTestGroup(t, plainSite(&config.Backend{Retry: config.RetryConfig{Attempts: 2, On: "502"}}, first.addr(), second.addr()), true)
	if st := statusOf(t, retried, "/502"); st != 502 {
		t.Fatalf("a request tried twice: status %d", st)
	}
	var text string
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		b, _ := os.ReadFile(errPath)
		if text = string(b); strings.Contains(text, "[ERR] [HTTP] Upstream") && strings.Contains(text, "[WARN] [HTTP] Retry 1/2") {
			return
		}
	}
	t.Errorf("the error log has no error for the late backend or no warning for the retry:\n%s", text)
}
