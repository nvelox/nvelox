package admin

import (
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"nvelox/core/denylist"
	"nvelox/core/logging"
	"nvelox/lb"
)

// countingBalancer is a balancer that counts the changes the admin API
// asks of it.
type countingBalancer struct {
	lb.Balancer
	changes atomic.Int64
}

func (b *countingBalancer) UpdateStatus(server string, healthy bool) {
	b.changes.Add(1)
	b.Balancer.UpdateStatus(server, healthy)
}

func (b *countingBalancer) MarkDraining(server string) {
	b.changes.Add(1)
	b.Balancer.MarkDraining(server)
}

// FuzzAdminAPI: whatever request reaches the admin API from its own host,
// without the key it is refused (4xx), or sent by the router to the same
// path cleaned (a redirect on this host, before any handler), and changes
// nothing; with the key it is answered (never a panic, a status a client
// can read), and what the denylist holds afterwards is addresses and
// ranges only.
func FuzzAdminAPI(f *testing.F) {
	_ = logging.Init("error", "", "")
	f.Cleanup(func() { _ = logging.Init("debug", "", "") })
	for _, s := range []struct {
		method, target, ctype, body string
	}{
		{"GET", "/api/v1/stats", "", ""},
		{"GET", "/api/v1/backends", "", ""},
		{"POST", "/api/v1/backends/be/drain?server=s1:80", "application/json", "{}"},
		{"POST", "/api/v1/backends/be/enable?server=s1:80", "", ""},
		{"POST", "/api/v1/backends/../be/disable?server=s1:80", "application/json", ""},
		{"POST", "/api/v1/denylist", "application/json", `{"ip":"192.0.2.1","ttl_seconds":60}`},
		{"POST", "/api/v1/denylist", "application/json", `{"ip":"0.0.0.0/0"}`},
		{"POST", "/api/v1/denylist", "application/json", `{"ip":"not an address"}`},
		{"POST", "/api/v1/denylist", "text/plain", `{"ip":"192.0.2.2"}`},
		{"DELETE", "/api/v1/denylist?cidr=192.0.2.1", "", ""},
		{"DELETE", "/api/v1/denylist", "application/json", `{"ip":"192.0.2.1"}`},
		{"PUT", "/api/v1/denylist", "application/json", `[]`},
		{"POST", "/api/v1/denylist", "application/json", `{"ip":"2001:db8::/129","ttl_seconds":-1}`},
	} {
		f.Add(s.method, s.target, s.ctype, s.body, true)
		f.Add(s.method, s.target, s.ctype, s.body, false)
	}
	f.Fuzz(func(t *testing.T, method, target, ctype, body string, keyed bool) {
		bal := &countingBalancer{Balancer: lb.NewRoundRobin([]string{"s1:80", "s2:80"})}
		deny := denylist.New()
		s := NewServer("127.0.0.1:0", testAPIKey, map[string]lb.Balancer{"be": bal}, deny)
		req, err := http.NewRequest(method, "http://127.0.0.1"+target, strings.NewReader(body))
		if err != nil || req.URL.Host != "127.0.0.1" {
			return // not a request a client sends to this address
		}
		req.RemoteAddr = "127.0.0.1:12345"
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		if keyed {
			req.Header.Set("X-API-Key", testAPIKey)
		}
		w := serve(s, req)
		if w.Code < 200 || w.Code > 599 {
			t.Fatalf("%s %q: status %d", method, target, w.Code)
		}
		if !keyed {
			redirect := (w.Code == http.StatusMovedPermanently || w.Code == http.StatusTemporaryRedirect || w.Code == http.StatusPermanentRedirect) &&
				strings.HasPrefix(w.Header().Get("Location"), "/") && !strings.HasPrefix(w.Header().Get("Location"), "//")
			if (w.Code < 400 || w.Code > 499) && !redirect {
				t.Fatalf("%s %q without the key: status %d (Location %q)", method, target, w.Code, w.Header().Get("Location"))
			}
			if n := bal.changes.Load(); n != 0 || deny.Count() != 0 {
				t.Fatalf("%s %q without the key changed %d servers and %d denylist entries", method, target, n, deny.Count())
			}
			return
		}
		for _, e := range deny.List() {
			if _, _, err := net.ParseCIDR(e.CIDR); err != nil && net.ParseIP(e.CIDR) == nil {
				t.Fatalf("%s %q %q: the denylist holds %q", method, target, body, e.CIDR)
			}
		}
	})
}
