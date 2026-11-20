package core

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"nvelox/config"
)

// A tcp listener that sets no timeouts.idle closes a connection with no
// traffic either way after the default, with tls and without: with tls it
// had no limit before 2.0.0.
func TestTCPIdleDefault_WithAndWithoutTLS(t *testing.T) {
	pki := newSTPKI(t, "idletls")
	echo, _ := stTCPEchoBackend(t)
	plainAddr, tlsAddr := stFreeTCPAddr(t), stFreeTCPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{
			{Name: "plain", Bind: plainAddr, Protocol: "tcp", Backend: "be"},
			{Name: "tls", Bind: tlsAddr, Protocol: "tcp", Backend: "be", TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}},
		},
		Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
	}, func(e *Engine) { e.tcpIdleDefault = 300 * time.Millisecond })

	closedWhenIdle := func(what string, c net.Conn) {
		t.Helper()
		if err := stEcho(c, "hello"); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		start := time.Now()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := c.Read(make([]byte, 1))
		var ne net.Error
		switch {
		case err == nil:
			t.Fatalf("%s: an idle connection brought data", what)
		case errors.As(err, &ne) && ne.Timeout():
			t.Fatalf("%s: still open after 5s without traffic; want it closed after the idle default", what)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s: closed after %v, want about the idle default", what, d)
		}
	}

	c, err := net.Dial("tcp", plainAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	closedWhenIdle("tcp", c)

	raw, err := net.Dial("tcp", tlsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"})
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tc.SetDeadline(time.Time{})
	closedWhenIdle("tcp with tls", tc)
}
