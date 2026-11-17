package httpproxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/circuitbreaker"
)

// H2: a WebSocket upgrade used to be relayed by a custom path that ran
// before the forwarding headers were set, wrote the upgrade to the backend,
// hijacked the client without looking at the backend's answer and then
// copied raw bytes both ways — including what the client had pipelined
// behind the upgrade. A fake upgrade followed by "GET /admin/secret" reached
// the backend past an ACL deny, on that request and on every later one on
// the socket. Upgrades now go through httputil.ReverseProxy, which tunnels
// only after a 101 that switches to the requested protocol.

// TestWebSocket_SmuggledRequestNeverReachesBackend: a fake upgrade to a
// plain HTTP backend (it answers 200, not 101) followed by pipelined
// requests for a denied path: the backend sees only the upgrade request, the
// client gets that 200 and the connection is closed.
func TestWebSocket_SmuggledRequestNeverReachesBackend(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		io.WriteString(w, "public")
	}))
	defer backend.Close()

	l := &ListenerConfig{ACL: []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/admin"}, Action: "deny"}}}
	_, addr := secSite(t, l, []string{secHost(backend)}, secOpts{})

	resp, closed := secRaw(t, addr,
		"GET /public HTTP/1.1\r\nHost: edge.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"+
			"GET /admin/secret HTTP/1.1\r\nHost: edge.test\r\n\r\n"+
			"GET /admin/later HTTP/1.1\r\nHost: edge.test\r\n\r\n", 2*time.Second)

	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if strings.HasPrefix(p, "/admin") {
			t.Fatalf("smuggled request %q reached the backend (backend saw %q)", p, paths)
		}
	}
	if len(paths) != 1 || paths[0] != "/public" {
		t.Fatalf("backend saw %q, want only the upgrade request /public", paths)
	}
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") || !strings.Contains(resp, "public") {
		t.Fatalf("client did not get the backend's answer to the upgrade: %q", resp)
	}
	if strings.Count(resp, "HTTP/1.1 ") != 1 {
		t.Fatalf("pipelined requests after the failed upgrade were answered: %q", resp)
	}
	if !closed {
		t.Fatal("connection not closed after the failed upgrade")
	}
}

// TestWebSocket_PipelinedBytesBeforeSwitchDropped: bytes a client sends
// behind the upgrade request, before the 101, are not forwarded into the
// tunnel (RFC 6455: the client waits for the 101); only what follows the
// switch is.
func TestWebSocket_PipelinedBytesBeforeSwitchDropped(t *testing.T) {
	b := secStartWSBackend(t)
	_, addr := secSite(t, &ListenerConfig{}, []string{b.addr}, secOpts{})

	conn, br, resp := secUpgrade(t, addr, "Content-Length: 0\r\n\r\nGET /admin/secret HTTP/1.1\r\nHost: edge.test\r\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	assertEcho(t, conn, br)
	select {
	case first := <-b.first:
		if strings.Contains(first, "/admin/secret") {
			t.Fatalf("bytes pipelined before the 101 were forwarded into the tunnel: %q", first)
		}
	case <-time.After(wsTestTimeout):
		t.Fatal("backend received nothing after the handshake")
	}
}

// TestWebSocket_ForwardingHeadersRewritten: the upgrade request carries the
// same forwarding headers as any proxied request — the client's forged
// X-Forwarded-For / X-Real-IP / X-Forwarded-Host never reach the backend.
func TestWebSocket_ForwardingHeadersRewritten(t *testing.T) {
	b := secStartWSBackend(t)
	_, addr := secSite(t, &ListenerConfig{RequestID: config.RequestIDConfig{Enabled: true}}, []string{b.addr}, secOpts{})

	_, _, resp := secUpgrade(t, addr, "X-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nX-Forwarded-Host: evil.test\r\nX-Request-ID: deadbeef\r\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	req := <-b.reqs
	if got := req.Header.Values("X-Forwarded-For"); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want [127.0.0.1]", got)
	}
	if got := req.Header.Get("X-Real-IP"); got != "127.0.0.1" {
		t.Errorf("X-Real-IP = %q, want 127.0.0.1", got)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "" {
		t.Errorf("X-Forwarded-Host from an untrusted client reached the backend: %q", got)
	}
	if got := req.Header.Get("X-Request-ID"); got == "deadbeef" || !hex32.MatchString(got) {
		t.Errorf("X-Request-ID = %q, want a fresh id", got)
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		t.Errorf("Upgrade = %q, want websocket", req.Header.Get("Upgrade"))
	}
}

// TestWebSocket_BackendSwitchesToOtherProtocol: a 101 that does not switch to
// WebSocket is a 502, and the client connection is closed.
func TestWebSocket_BackendSwitchesToOtherProtocol(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n")
		brw.Flush()
		time.Sleep(time.Second)
	}))
	defer backend.Close()
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{})

	conn, br, resp := secUpgrade(t, addr, "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	resp.Body.Close()
	secExpectEOF(t, conn, br, wsTestTimeout, "after a rejected protocol switch")
}

// TestWebSocket_NonWebSocketUpgradeStripped: only WebSocket may switch
// protocols. An h2c upgrade reaches the backend as a plain request, so an
// h2c-speaking backend cannot open a tunnel past the proxy's checks.
func TestWebSocket_NonWebSocketUpgradeStripped(t *testing.T) {
	var gotUpgrade, gotConn string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUpgrade, gotConn = r.Header.Get("Upgrade"), r.Header.Get("Connection")
		io.WriteString(w, "plain")
	}))
	defer backend.Close()
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{})

	resp, _ := secRaw(t, addr, "GET / HTTP/1.1\r\nHost: edge.test\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n", 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") {
		t.Fatalf("status = %q, want 200", secStatus(resp))
	}
	if gotUpgrade != "" || strings.Contains(strings.ToLower(gotConn), "upgrade") {
		t.Fatalf("h2c upgrade forwarded to the backend: Upgrade=%q Connection=%q", gotUpgrade, gotConn)
	}
}

// TestWebSocket_IdleTunnelClosed: a tunnel with no traffic either way is
// closed after the site's idle timeout (it used to live forever: hijacking
// clears the connection's deadlines), and the backend side with it.
func TestWebSocket_IdleTunnelClosed(t *testing.T) {
	b := secStartWSBackend(t)
	l := &ListenerConfig{Timeouts: config.TimeoutConfig{Idle: "300ms"}}
	_, addr := secSite(t, l, []string{b.addr}, secOpts{})

	conn, br, resp := secUpgrade(t, addr, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	assertEcho(t, conn, br)
	secExpectEOF(t, conn, br, 2*time.Second, "idle tunnel")
	select {
	case <-b.closed:
	case <-time.After(wsTestTimeout):
		t.Fatal("backend side of the idle tunnel not closed")
	}
}

// TestWebSocket_TrafficKeepsTunnelOpen: traffic in either direction resets
// the idle timer.
func TestWebSocket_TrafficKeepsTunnelOpen(t *testing.T) {
	b := secStartWSBackend(t)
	l := &ListenerConfig{Timeouts: config.TimeoutConfig{Idle: "400ms"}}
	_, addr := secSite(t, l, []string{b.addr}, secOpts{})

	conn, br, resp := secUpgrade(t, addr, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	for i := 0; i < 8; i++ { // 8 x 150 ms = 1.2 s, three idle periods
		conn.SetDeadline(time.Now().Add(wsTestTimeout))
		assertEcho(t, conn, br)
		time.Sleep(150 * time.Millisecond)
	}
	secExpectEOF(t, conn, br, 2*time.Second, "tunnel idle after the traffic stopped")
}

// TestWebSocket_StopClosesTunnels: stopping the bind group closes its
// tunnels and the backend side with them (http.Server.Shutdown does not touch
// hijacked connections).
func TestWebSocket_StopClosesTunnels(t *testing.T) {
	b := secStartWSBackend(t)
	s := secNewSite(t, &ListenerConfig{}, []string{b.addr}, secOpts{})
	g := NewBindGroup(":0", "http")
	g.AddSite(s)
	ts := httptest.NewServer(g)
	defer ts.Close()

	conn, br, resp := secUpgrade(t, secHost(ts), "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	assertEcho(t, conn, br)
	if err := g.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	secExpectEOF(t, conn, br, 2*time.Second, "tunnel of a stopped bind group")
	select {
	case <-b.closed:
	case <-time.After(wsTestTimeout):
		t.Fatal("backend side not closed with the bind group")
	}
}

// TestWebSocket_ReloadKeepsTunnels: a reload (ReplaceSites) replaces every
// site instance, also the one rebuilt under the same name; a tunnel the new
// configuration still admits keeps running (tunnel_recheck_test.go covers
// the ones it closes). Stop still closes them all.
func TestWebSocket_ReloadKeepsTunnels(t *testing.T) {
	b := secStartWSBackend(t)
	old := secNewSite(t, &ListenerConfig{}, []string{b.addr}, secOpts{})
	g := NewBindGroup(":0", "http")
	g.AddSite(old)
	ts := httptest.NewServer(g)
	defer ts.Close()

	conn, br, resp := secUpgrade(t, secHost(ts), "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	assertEcho(t, conn, br)
	if err := g.ReplaceSites([]*HTTPServer{secNewSite(t, &ListenerConfig{}, []string{b.addr}, secOpts{})}); err != nil {
		t.Fatalf("ReplaceSites: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	assertEcho(t, conn, br) // still open after the reload

	// The new site serves upgrades.
	conn2, br2, resp2 := secUpgrade(t, secHost(ts), "")
	if resp2.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("after reload: status = %d, want 101", resp2.StatusCode)
	}
	assertEcho(t, conn2, br2)

	if err := g.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	secExpectEOF(t, conn, br, 2*time.Second, "pre-reload tunnel after Stop")
	secExpectEOF(t, conn2, br2, 2*time.Second, "post-reload tunnel after Stop")
}

// TestWebSocket_BreakerOutcomeRecorded (H4): an upgrade is an attempt like
// any other — a half-open breaker's probe slot taken by it is answered (here
// by the 101's success). It used to stay taken and refuse every later
// request.
func TestWebSocket_BreakerOutcomeRecorded(t *testing.T) {
	b := secStartWSBackend(t)
	cb := circuitbreaker.New(1, 50*time.Millisecond, 1)
	_, addr := secSite(t, &ListenerConfig{}, []string{b.addr}, secOpts{cb: cb})

	cb.RecordFailure() // open
	time.Sleep(80 * time.Millisecond)
	conn, br, resp := secUpgrade(t, addr, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	assertEcho(t, conn, br)
	if got := cb.State(); got != "closed" {
		t.Fatalf("breaker = %s after a successful upgrade probe, want closed", got)
	}
	conn.Close()

	_, _, resp2 := secUpgrade(t, addr, "")
	if resp2.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("second upgrade: status = %d, want 101 (breaker wedged?)", resp2.StatusCode)
	}
}

// TestWebSocket_TLSBackendEchoThroughBindGroup: the backend_tls WebSocket
// support of v1.1.7 (PR #28) holds through the ReverseProxy path, served by
// a BindGroup like production.
func TestWebSocket_TLSBackendEchoThroughBindGroup(t *testing.T) {
	certPath, keyPath := genCertWithCN(t, t.TempDir(), "localhost")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load backend cert: %v", err)
	}
	b := startWSBackend(t, &tls.Config{Certificates: []tls.Certificate{cert}}, http.StatusSwitchingProtocols)
	_, port, _ := net.SplitHostPort(b.addr)
	be := &config.Backend{BackendTLS: config.BackendTLSConfig{Enabled: true, CACert: certPath}}
	_, addr := secSite(t, &ListenerConfig{}, []string{net.JoinHostPort("localhost", port)}, secOpts{backend: be})

	conn, br, resp := secUpgrade(t, addr, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	for i := 0; i < 3; i++ {
		assertEcho(t, conn, br)
	}
}
