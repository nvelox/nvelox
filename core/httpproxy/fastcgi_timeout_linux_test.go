//go:build linux

package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nvelox/config"
)

// TestFastCGI_ConnectTimeout: the dial to a fastcgi route's upstream gives
// up after the route's timeouts.connect, else the listener's, as for an
// HTTP backend, and the client gets a 502 (before: no limit of nvelox's,
// about two minutes over TCP).
func TestFastCGI_ConnectTimeout(t *testing.T) {
	root := phpDocRoot(t)
	for _, c := range []struct {
		name            string
		route, listener config.TimeoutConfig
	}{
		{"route", config.TimeoutConfig{Connect: "300ms"}, config.TimeoutConfig{}},
		{"listener", config.TimeoutConfig{}, config.TimeoutConfig{Connect: "300ms"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			routes := []config.RouteConfig{{Match: config.RouteMatch{PathRegex: `\.php$`},
				FastCGI: config.FastCGIConfig{Pass: hangingAddr(t), DocumentRoot: root, Timeouts: c.route}}}
			l := &ListenerConfig{Name: "php-app", Addr: ":0", Protocol: "http", Routes: routes, Timeouts: c.listener}
			site := NewHTTPServer(l, nil, map[string]*config.Backend{}, nil, nil, nil, nil, nil)
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			start := time.Now()
			go func() {
				defer close(done)
				site.ServeHTTP(rec, httptest.NewRequest("GET", "/index.php", nil))
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("no answer 5 s after the request")
			}
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("unreachable FastCGI upstream -> %d, want 502", rec.Code)
			}
			if took := time.Since(start); took > 2*time.Second {
				t.Fatalf("502 after %v, want about the 300ms connect timeout", took)
			}
		})
	}
}
