package core

// M5: backend_tls fails closed — a backend whose TLS config cannot be built
// aborts startup and the reload (which keeps the running config) instead of
// falling back to plaintext, and L4 listeners never send plaintext to a
// backend configured for TLS.

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

func TestBackendTLS_BrokenConfigFailsStart(t *testing.T) {
	missingCA := filepath.Join(t.TempDir(), "missing-ca.pem")
	for _, proto := range []string{"http", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			addr := stFreeTCPAddr(t)
			cfg := &config.Config{Version: "2", Backends: []config.Backend{{Name: "secure", Servers: []string{"127.0.0.1:1"},
				BackendTLS: config.BackendTLSConfig{Enabled: true, CACert: missingCA}}}}
			e := NewEngine(cfg)
			e.Listeners = []*ListenerConfig{{Name: "l", Addr: addr, Protocol: proto, Backend: "secure"}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := e.Start(ctx)
			if err == nil || !strings.Contains(err.Error(), "backend_tls") {
				t.Fatalf("Start: err=%v, want a backend_tls error", err)
			}
			if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
				c.Close()
				t.Fatal("a listener came up despite the backend_tls error")
			}
		})
	}
}

// An L4 listener on a working backend_tls backend is refused too: backend_tls
// is implemented on the HTTP path only.
func TestBackendTLS_L4ListenerOnTLSBackendFailsStart(t *testing.T) {
	cfg := &config.Config{Version: "2", Backends: []config.Backend{{Name: "secure", Servers: []string{"127.0.0.1:1"},
		BackendTLS: config.BackendTLSConfig{Enabled: true, Insecure: true}}}}
	for _, proto := range []string{"tcp", "udp"} {
		e := NewEngine(cfg)
		e.Listeners = []*ListenerConfig{{Name: "l4", Addr: "127.0.0.1:0", Protocol: proto, Backend: "secure"}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := e.Start(ctx)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "backend_tls") {
			t.Fatalf("%s: Start: err=%v, want a backend_tls error", proto, err)
		}
	}
}

func TestBackendTLS_BrokenConfigFailsReloadAndKeepsRunningConfig(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plain-v1")
	}))
	defer plain.Close()
	addr := stFreeTCPAddr(t)
	listeners := []config.Listener{{Name: "web", Bind: addr, Protocol: "http", Backend: "be"}}
	e := stStart(t, &config.Config{Listeners: listeners,
		Backends: []config.Backend{{Name: "be", Servers: []string{strings.TrimPrefix(plain.URL, "http://")}}}}, nil)

	get := func() string {
		t.Helper()
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + addr + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := get(); got != "plain-v1" {
		t.Fatalf("before reload: %q", got)
	}
	failBefore := e.Metrics.GetCounter("nvelox_reload_total", map[string]string{"result": "fail"}).Get()

	bad := &config.Config{Version: "2", Listeners: listeners,
		Backends: []config.Backend{{Name: "be", Servers: []string{strings.TrimPrefix(plain.URL, "http://")},
			BackendTLS: config.BackendTLSConfig{Enabled: true, CACert: filepath.Join(t.TempDir(), "missing-ca.pem")}}}}
	err := e.Reload(bad)
	if err == nil || !strings.Contains(err.Error(), "backend_tls") {
		t.Fatalf("Reload: err=%v, want a backend_tls error", err)
	}
	if got := e.Metrics.GetCounter("nvelox_reload_total", map[string]string{"result": "fail"}).Get(); got != failBefore+1 {
		t.Fatalf("reload fail counter %d → %d, want +1", failBefore, got)
	}
	e.reloadMu.Lock()
	be := e.Backends["be"]
	e.reloadMu.Unlock()
	if be.BackendTLS.Enabled {
		t.Fatal("the failed reload changed the running backend config")
	}
	if got := get(); got != "plain-v1" {
		t.Fatalf("after the failed reload the running config must still serve: %q", got)
	}
}

// A backend switched to backend_tls under a running L4 listener (L4
// listeners are not reloaded) gets no plaintext connection.
func TestBackendTLS_L4PathRefusesTLSBackend(t *testing.T) {
	echo, accepted := stTCPEchoBackend(t)
	cfg := &config.Config{Version: "2", Backends: []config.Backend{{Name: "be", Servers: []string{echo}}}}
	e := NewEngine(cfg)
	e.initBackends()
	e.Backends["be"].BackendTLS = config.BackendTLSConfig{Enabled: true, Insecure: true}
	h := NewProxyEventHandler(e)
	l := &ListenerConfig{Name: "l4", Protocol: "tcp", Backend: "be"}
	if err := l.prepare(); err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.serveTCP(server, l); close(done) }()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	client.Write([]byte("hello"))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("the session was relayed to a backend_tls backend in plaintext")
	}
	client.Close()
	<-done
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the backend got %d plaintext connection(s)", n)
	}
}
