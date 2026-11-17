package httpproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/denylist"
	"nvelox/core/tlsutil"
	"nvelox/lb"
)

// A reload keeps an open WebSocket tunnel only while the new configuration
// would still admit its upgrade request to the same place; the dynamic
// denylist closes the tunnels of a client it blocks.

// recheckSite builds site "edge" with backends "be" (beServers) and "other"
// (otherServers), like secNewSite.
func recheckSite(t *testing.T, l *ListenerConfig, beServers, otherServers []string) *HTTPServer {
	t.Helper()
	return recheckSiteTLS(t, l, beServers, otherServers, config.BackendTLSConfig{})
}

// recheckSiteTLS is recheckSite with backend_tls beTLS on "be".
func recheckSiteTLS(t *testing.T, l *ListenerConfig, beServers, otherServers []string, beTLS config.BackendTLSConfig) *HTTPServer {
	t.Helper()
	if l.Name == "" {
		l.Name = "edge"
	}
	l.Protocol, l.Backend = "http", "be"
	s := NewHTTPServer(l,
		map[string]lb.Balancer{"be": lb.NewRoundRobin(beServers), "other": lb.NewRoundRobin(otherServers)},
		map[string]*config.Backend{"be": {Name: "be", Servers: beServers, BackendTLS: beTLS}, "other": {Name: "other", Servers: otherServers}},
		nil, nil, nil, nil, nil)
	t.Cleanup(s.Close)
	return s
}

// TestWebSocket_ReloadRechecksTunnels: a tunnel survives a reload that
// leaves its request admitted to the same backend server, and is closed by
// one that refuses it, routes it elsewhere or drops its server.
func TestWebSocket_ReloadRechecksTunnels(t *testing.T) {
	same := func(be, _ string) []string { return []string{be} }
	cases := []struct {
		name    string
		after   func() *ListenerConfig
		servers func(be, other string) []string // backend "be" after the reload
		keep    bool
	}{
		{"unchanged", func() *ListenerConfig { return &ListenerConfig{} }, same, true},
		{"unrelated route added", func() *ListenerConfig {
			return &ListenerConfig{Routes: []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/api"}, Backend: "other"}}}
		}, same, true},
		{"ACL denies another path", func() *ListenerConfig {
			return &ListenerConfig{ACL: []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/admin"}, Action: "deny"}}}
		}, same, true},
		{"client denylisted", func() *ListenerConfig { return &ListenerConfig{IPDenylist: []string{"127.0.0.1/32"}} }, same, false},
		{"client not allowlisted", func() *ListenerConfig { return &ListenerConfig{IPAllowlist: []string{"10.0.0.0/8"}} }, same, false},
		{"ACL denies its path", func() *ListenerConfig {
			return &ListenerConfig{ACL: []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/ws"}, Action: "deny"}}}
		}, same, false},
		{"route to another backend", func() *ListenerConfig {
			return &ListenerConfig{Routes: []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/ws"}, Backend: "other"}}}
		}, same, false},
		{"route rewrites its path", func() *ListenerConfig {
			return &ListenerConfig{Routes: []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/ws"}, Backend: "be",
				Rewrite: config.RewriteConfig{Path: "/socket"}}}}
		}, same, false},
		{"server left the backend", func() *ListenerConfig { return &ListenerConfig{} },
			func(_, other string) []string { return []string{other} }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, other := secStartWSBackend(t), secStartWSBackend(t)
			g := NewBindGroup(":0", "http")
			g.AddSite(recheckSite(t, &ListenerConfig{}, []string{b.addr}, []string{other.addr}))
			ts := httptest.NewServer(g)
			defer ts.Close()

			conn, br, resp := secUpgrade(t, secHost(ts), "")
			if resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("status = %d, want 101", resp.StatusCode)
			}
			assertEcho(t, conn, br)

			if err := g.ReplaceSites([]*HTTPServer{recheckSite(t, c.after(), c.servers(b.addr, other.addr), []string{other.addr})}); err != nil {
				t.Fatalf("ReplaceSites: %v", err)
			}
			if c.keep {
				time.Sleep(100 * time.Millisecond)
				conn.SetDeadline(time.Now().Add(wsTestTimeout))
				assertEcho(t, conn, br)
				return
			}
			secExpectEOF(t, conn, br, 2*time.Second, "tunnel the reloaded configuration refuses")
			select {
			case <-b.closed:
			case <-time.After(wsTestTimeout):
				t.Fatal("backend side of the refused tunnel not closed")
			}
		})
	}
}

// TestWebSocket_ReloadAppliesIdleTimeout: a tunnel the reload keeps takes the
// new site's idle timeout.
func TestWebSocket_ReloadAppliesIdleTimeout(t *testing.T) {
	b := secStartWSBackend(t)
	g := NewBindGroup(":0", "http")
	g.AddSite(recheckSite(t, &ListenerConfig{}, []string{b.addr}, nil)) // idle 120 s
	ts := httptest.NewServer(g)
	defer ts.Close()

	conn, br, resp := secUpgrade(t, secHost(ts), "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	assertEcho(t, conn, br)
	short := &ListenerConfig{Timeouts: config.TimeoutConfig{Idle: "300ms"}}
	if err := g.ReplaceSites([]*HTTPServer{recheckSite(t, short, []string{b.addr}, nil)}); err != nil {
		t.Fatalf("ReplaceSites: %v", err)
	}
	secExpectEOF(t, conn, br, 2*time.Second, "kept tunnel after the new 300ms idle timeout")
}

// TestWebSocket_UpgradeAcrossReloadRechecked: a tunnel that a replaced site
// instance starts after the reload (its upgrade was in flight) is checked
// against the new sites when it starts.
func TestWebSocket_UpgradeAcrossReloadRechecked(t *testing.T) {
	admission := func(target string) *tunnelAdmission {
		req := httptest.NewRequest(http.MethodGet, "https://edge.test/ws", nil)
		req.RemoteAddr = "127.0.0.1:5555"
		req.TLS = &tls.ConnectionState{ServerName: "edge.test"} // no client certificate
		return &tunnelAdmission{req: req, backend: "be", target: target, scheme: "http"}
	}
	cases := []struct {
		name  string
		after *ListenerConfig
		beTLS config.BackendTLSConfig // backend_tls of "be" after the reload
		adm   bool                    // the tunnel carries its admission
		keep  bool
	}{
		{"still admitted", &ListenerConfig{}, config.BackendTLSConfig{}, true, true},
		{"refused by the new rules", &ListenerConfig{IPDenylist: []string{"127.0.0.1/32"}}, config.BackendTLSConfig{}, true, false},
		{"client certificate now required", &ListenerConfig{ClientAuth: &tlsutil.ClientAuth{Mode: tls.RequireAndVerifyClientCert}},
			config.BackendTLSConfig{}, true, false},
		{"backend now over TLS", &ListenerConfig{}, config.BackendTLSConfig{Enabled: true, Insecure: true}, true, false},
		{"nothing to check", &ListenerConfig{}, config.BackendTLSConfig{}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const server = "127.0.0.1:9"
			old := recheckSite(t, &ListenerConfig{}, []string{server}, nil)
			g := NewBindGroup(":0", "http")
			g.AddSite(old)
			if err := g.ReplaceSites([]*HTTPServer{recheckSiteTLS(t, c.after, []string{server}, nil, c.beTLS)}); err != nil {
				t.Fatalf("ReplaceSites: %v", err)
			}
			proxySide, client := net.Pipe()
			defer client.Close()
			var adm *tunnelAdmission
			if c.adm {
				adm = admission(server)
			}
			_, cancel := context.WithCancel(context.Background())
			tun := old.trackTunnel(proxySide, cancel, adm, net.ParseIP("127.0.0.1"))
			isClosed := func() bool {
				tun.mu.Lock()
				defer tun.mu.Unlock()
				return tun.closed
			}
			if c.keep {
				time.Sleep(300 * time.Millisecond)
				if isClosed() {
					t.Fatal("tunnel the new sites admit was closed")
				}
			} else {
				deadline := time.Now().Add(2 * time.Second)
				for !isClosed() {
					if time.Now().After(deadline) {
						t.Fatal("tunnel the new sites refuse still open")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			_ = tun.Close()
		})
	}
}

// TestWebSocket_DenylistClosesClientTunnels: CloseTunnelsOf closes the
// tunnels of a client the dynamic denylist blocks — the client the access
// rules checked (here from X-Forwarded-For behind a trusted proxy) — and
// leaves the others open.
func TestWebSocket_DenylistClosesClientTunnels(t *testing.T) {
	b := secStartWSBackend(t)
	s := recheckSite(t, &ListenerConfig{TrustedProxies: []string{"127.0.0.1/32"}}, []string{b.addr}, nil)
	dyn := denylist.New()
	s.DynDenylist = dyn
	g := NewBindGroup(":0", "http")
	g.AddSite(s)
	ts := httptest.NewServer(g)
	defer ts.Close()

	blockedConn, blockedBr, resp := secUpgrade(t, secHost(ts), "X-Forwarded-For: 203.0.113.7\r\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	otherConn, otherBr, resp := secUpgrade(t, secHost(ts), "X-Forwarded-For: 203.0.113.8\r\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	assertEcho(t, blockedConn, blockedBr)
	assertEcho(t, otherConn, otherBr)

	if _, err := dyn.Add("203.0.113.7", 0); err != nil {
		t.Fatal(err)
	}
	if n := g.CloseTunnelsOf(dyn.Blocked); n != 1 {
		t.Fatalf("CloseTunnelsOf closed %d tunnels, want 1", n)
	}
	secExpectEOF(t, blockedConn, blockedBr, 2*time.Second, "tunnel of the blocked client")
	time.Sleep(100 * time.Millisecond)
	otherConn.SetDeadline(time.Now().Add(wsTestTimeout))
	assertEcho(t, otherConn, otherBr)
}

// TestWebSocket_ReloadReverifiesClientCert: a reload that replaces a site's
// client CAs closes the mTLS tunnels whose client certificate the new CAs do
// not verify (a new connection with it would fail the handshake); one the
// CAs still verify keeps running.
func TestWebSocket_ReloadReverifiesClientCert(t *testing.T) {
	pkiA, pkiB := newCAPKI(t, "ca-a"), newCAPKI(t, "ca-b")
	leaf, err := x509.ParseCertificate(pkiA.clientCert(t).Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	policy := func(pool *x509.CertPool) *ListenerConfig {
		return &ListenerConfig{ClientAuth: &tlsutil.ClientAuth{Mode: tls.RequireAndVerifyClientCert, CAs: pool}}
	}
	for _, c := range []struct {
		name string
		cas  *x509.CertPool // after the reload
		keep bool
	}{
		{"same CA", pkiA.pool, true},
		{"CA replaced", pkiB.pool, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			const server = "127.0.0.1:9"
			old := recheckSite(t, policy(pkiA.pool), []string{server}, nil)
			g := NewBindGroup(":0", "http")
			g.AddSite(old)
			if err := g.ReplaceSites([]*HTTPServer{recheckSite(t, policy(c.cas), []string{server}, nil)}); err != nil {
				t.Fatalf("ReplaceSites: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "https://edge.test/ws", nil)
			req.RemoteAddr = "127.0.0.1:5555"
			req.TLS = &tls.ConnectionState{ServerName: "edge.test", PeerCertificates: []*x509.Certificate{leaf},
				VerifiedChains: [][]*x509.Certificate{{leaf, pkiA.cert}}}
			adm := &tunnelAdmission{req: req, backend: "be", target: server, scheme: "http"}
			proxySide, client := net.Pipe()
			defer client.Close()
			_, cancel := context.WithCancel(context.Background())
			tun := old.trackTunnel(proxySide, cancel, adm, net.ParseIP("127.0.0.1"))
			defer tun.Close()
			isClosed := func() bool {
				tun.mu.Lock()
				defer tun.mu.Unlock()
				return tun.closed
			}
			deadline := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(deadline) && !isClosed() {
				time.Sleep(10 * time.Millisecond)
			}
			if isClosed() == c.keep {
				t.Fatalf("closed = %v, want %v", isClosed(), !c.keep)
			}
		})
	}
}

// TestWebSocket_TunnelOfClientBlockedDuringUpgradeClosed: a client blocked
// after its upgrade request passed the access rules but before the backend
// switched (so the denylist's close pass could not find its tunnel yet) has
// its tunnel closed when it starts.
func TestWebSocket_TunnelOfClientBlockedDuringUpgradeClosed(t *testing.T) {
	s := recheckSite(t, &ListenerConfig{}, []string{"127.0.0.1:9"}, nil)
	dyn := denylist.New()
	s.DynDenylist = dyn
	if _, err := dyn.Add("203.0.113.9", 0); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		client string
		closed bool
	}{{"203.0.113.9", true}, {"203.0.113.10", false}} {
		proxySide, peer := net.Pipe()
		_, cancel := context.WithCancel(context.Background())
		tun := s.trackTunnel(proxySide, cancel, nil, net.ParseIP(c.client))
		tun.mu.Lock()
		closed := tun.closed
		tun.mu.Unlock()
		if closed != c.closed {
			t.Errorf("client %s: tunnel closed = %v, want %v", c.client, closed, c.closed)
		}
		tun.Close()
		peer.Close()
	}
}
