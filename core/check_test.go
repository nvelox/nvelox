package core

import (
	"path/filepath"
	"strings"
	"testing"

	"nvelox/config"
)

// Check refuses, on a config that did not come through config.Load, what
// Start refuses before it touches a socket.
func TestCheck(t *testing.T) {
	good := func() *config.Config {
		return &config.Config{
			Version:   "2",
			Listeners: []config.Listener{{Name: "l", Bind: "127.0.0.1:39100-39102", Protocol: "tcp", Backend: "be"}},
			Backends:  []config.Backend{{Name: "be", Servers: []string{"127.0.0.1:1"}}},
		}
	}
	if err := Check(good()); err != nil {
		t.Fatalf("a config a start accepts: %v", err)
	}

	// A port range that does not expand.
	c := good()
	c.Listeners[0].Bind = "127.0.0.1:39102-39100x"
	if err := Check(c); err == nil || !strings.Contains(err.Error(), "listener l") {
		t.Fatalf("a bind that is no port range: got %v, want an error naming the listener", err)
	}

	// An access list that does not parse (a listener's derived state).
	c = good()
	c.Listeners[0].IPDenylist = []string{"not-a-network"}
	if err := Check(c); err == nil || !strings.Contains(err.Error(), "listener l") {
		t.Fatalf("an access list that does not parse: got %v, want an error naming the listener", err)
	}

	// A backend_tls config that cannot be built: never a start in plaintext.
	c = good()
	c.Listeners[0] = config.Listener{Name: "web", Bind: "127.0.0.1:39103", Protocol: "http", Backend: "be"}
	c.Backends[0].BackendTLS = config.BackendTLSConfig{Enabled: true, CACert: filepath.Join(t.TempDir(), "no-such-ca.pem")}
	if err := Check(c); err == nil || !strings.Contains(err.Error(), "backend be: backend_tls") {
		t.Fatalf("a backend_tls CA file that is not there: got %v", err)
	}

	// TLS to a backend from a tcp listener is not implemented.
	c = good()
	c.Backends[0].BackendTLS = config.BackendTLSConfig{Enabled: true, Insecure: true}
	if err := Check(c); err == nil || !strings.Contains(err.Error(), "not implemented for tcp listeners") {
		t.Fatalf("backend_tls behind a tcp listener: got %v", err)
	}
}
