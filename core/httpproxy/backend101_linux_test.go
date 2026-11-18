//go:build linux

package httpproxy

import (
	"testing"

	"nvelox/config"
	"nvelox/lb"
)

// HTTP/2 and HTTP/3 have no 101 Switching Protocols: a backend that answers
// a request of theirs with one has answered wrongly, and the client gets a
// 502, whichever of nvelox's servers has the request (the event loops, the
// handlers behind them, net/http's HTTP/2 or quic-go's HTTP/3).
func TestBackend101IsRefusedOnHTTP2AndHTTP3(t *testing.T) {
	quietLog(t)
	be := newRawBackend(t)
	pki := newCAPKI(t, "ca-101")
	// handlers: a site whose requests the loops give to the handlers
	// (compression is theirs).
	site := func(http3, handlers bool) *HTTPServer {
		l := &ListenerConfig{Name: "site", Addr: ":0", Protocol: "https", Backend: "be", HTTP3: http3,
			TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
		l.Compression.Enabled = handlers
		return NewHTTPServer(l, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{be.addr()})},
			map[string]*config.Backend{"be": {Name: "be", Servers: []string{be.addr()}}}, nil, nil, nil, nil, nil)
	}
	for _, tc := range []struct {
		name            string
		loops, handlers bool
	}{
		{"the loops", true, false},
		{"the handlers behind the loops", true, true},
		{"the server without the loops", false, false},
	} {
		t.Run("HTTP/2, "+tc.name, func(t *testing.T) {
			hc := dialH2(t, startTLSGroup(t, site(false, tc.handlers), tc.loops))
			if r := hc.do(h2Fields("GET", "/101"), nil); r.status != 502 {
				t.Errorf("a backend's 101: the client got the status %d (reset: %v), want 502", r.status, r.reset)
			}
			// The connection serves on.
			if r := hc.do(h2Fields("GET", "/ok"), nil); r.status != 200 {
				t.Errorf("the next request on the connection: %d", r.status)
			}
		})
		t.Run("HTTP/3, "+tc.name, func(t *testing.T) {
			h3ServedBy(t, tc.loops)
			addr := freeAddr(t)
			g := startGroup(t, addr, site(true, tc.handlers))
			if tc.loops != (g.h3loops != nil) {
				t.Fatalf("HTTP/3 on the loops: %v, want %v", g.h3loops != nil, tc.loops)
			}
			cc, _ := h3Client(t, addr, pki)
			r, err := h3Do(testCtx(t), cc, "GET", "https://localhost/101", nil)
			if err != nil {
				t.Fatalf("a backend's 101: %v, want an answer of 502", err)
			}
			if r.status != 502 {
				t.Errorf("a backend's 101: the client got the status %d, want 502", r.status)
			}
			if r, err := h3Do(testCtx(t), cc, "GET", "https://localhost/ok", nil); err != nil || r.status != 200 {
				t.Errorf("the next request on the connection: %+v, %v", r, err)
			}
		})
	}
}
