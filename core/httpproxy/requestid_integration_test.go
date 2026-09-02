package httpproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"nvelox/config"
	"nvelox/lb"
)

// TestServeHTTP_RequestIDInjectedAndEchoed drives a full proxy round-trip and
// asserts the edge stamps X-Request-ID onto the upstream request AND echoes the
// same id back to the client, and that a forged client id is overwritten at the
// public edge (untrusted peer, trust_inbound=false).
func TestServeHTTP_RequestIDInjectedAndEchoed(t *testing.T) {
	var gotID string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer backend.Close()
	host := mustHost(t, backend.URL)

	backends := map[string]*config.Backend{"be": {Name: "be", Servers: []string{host}}}
	balancers := map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{host})}
	l := &ListenerConfig{
		Name: "edge", Addr: ":0", Protocol: "http", Backend: "be",
		RequestID: config.RequestIDConfig{Enabled: true},
	}
	s := NewHTTPServer(l, balancers, backends, nil, nil, nil, nil, nil)

	// (1) No inbound id → generated, injected upstream, echoed to the client.
	req := httptest.NewRequest("GET", "http://edge.test/", nil)
	req.RemoteAddr = "203.0.113.9:5000"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if !hex32.MatchString(gotID) {
		t.Fatalf("backend did not receive a generated X-Request-ID, got %q", gotID)
	}
	if echoed := rec.Header().Get("X-Request-ID"); echoed != gotID {
		t.Fatalf("response echo %q != upstream id %q", echoed, gotID)
	}

	// (2) A forged client id from an untrusted peer must be overwritten.
	forged := "deadbeefdeadbeefdeadbeefdeadbeef"
	req2 := httptest.NewRequest("GET", "http://edge.test/", nil)
	req2.RemoteAddr = "203.0.113.9:5000"
	req2.Header.Set("X-Request-ID", forged)
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, req2)

	if gotID == forged {
		t.Fatal("forged client id must be overwritten at the public edge, but the backend received it verbatim")
	}
	if !hex32.MatchString(gotID) {
		t.Fatalf("expected a fresh generated id after overwrite, got %q", gotID)
	}
	if echoed := rec2.Header().Get("X-Request-ID"); echoed != gotID {
		t.Fatalf("response echo %q != upstream id %q on the overwrite path", echoed, gotID)
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	return u.Host
}
