package core

// H5: the static ip_denylist / ip_allowlist / source_ip ACL, the dynamic
// denylist and backend max_connections are enforced on every L4 entry point
// — plain TCP, TLS-terminating TCP and UDP — on the RESOLVED client, i.e. the
// client a trusted relay's PROXY v2 header names.

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/denylist"
)

// stGateCases are the access policies every entry point is tested with. The
// test client is 127.0.0.1.
var stGateCases = []struct {
	name  string
	set   func(l *config.Listener)
	dyn   string // added to the dynamic denylist for the case
	admit bool
}{
	{"no policy", func(*config.Listener) {}, "", true},
	{"ip_denylist", func(l *config.Listener) { l.IPDenylist = []string{"127.0.0.0/8"} }, "", false},
	{"ip_allowlist without client", func(l *config.Listener) { l.IPAllowlist = []string{"203.0.113.0/24"} }, "", false},
	{"ip_allowlist with client", func(l *config.Listener) { l.IPAllowlist = []string{"203.0.113.0/24", "127.0.0.1"} }, "", true},
	{"acl deny", func(l *config.Listener) {
		l.ACL = []config.ACLRule{{Match: config.ACLMatch{SourceIP: []string{"127.0.0.0/8"}}, Action: "deny"}}
	}, "", false},
	{"acl allow then deny all", func(l *config.Listener) {
		l.ACL = []config.ACLRule{
			{Match: config.ACLMatch{SourceIP: []string{"127.0.0.1/32"}}, Action: "allow"},
			{Action: "deny"},
		}
	}, "", true},
	{"acl deny all", func(l *config.Listener) { l.ACL = []config.ACLRule{{Action: "deny"}} }, "", false},
	{"dynamic denylist", func(*config.Listener) {}, "127.0.0.1", false},
	{"deny list beats allow acl", func(l *config.Listener) {
		l.IPDenylist = []string{"127.0.0.1"}
		l.ACL = []config.ACLRule{{Match: config.ACLMatch{SourceIP: []string{"127.0.0.1"}}, Action: "allow"}}
	}, "", false},
}

func stBlock(t *testing.T, ip string) {
	t.Helper()
	if ip == "" {
		return
	}
	if _, err := denylist.Default.Add(ip, time.Minute); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { denylist.Default.Remove(ip) })
}

func TestL4Gates_PlainTCP(t *testing.T) {
	for _, c := range stGateCases {
		t.Run(c.name, func(t *testing.T) {
			echo, accepted := stTCPEchoBackend(t)
			addr := stFreeTCPAddr(t)
			l := config.Listener{Name: "tcp", Bind: addr, Protocol: "tcp", Backend: "be"}
			c.set(&l)
			stStart(t, &config.Config{Listeners: []config.Listener{l},
				Backends: []config.Backend{{Name: "be", Servers: []string{echo}}}}, nil)
			stBlock(t, c.dyn)

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if c.admit {
				if err := stEcho(conn, "hello"); err != nil {
					t.Fatalf("admitted client: %v", err)
				}
				return
			}
			stRefused(t, conn, "hello")
			if n := accepted.Load(); n != 0 {
				t.Fatalf("refused client reached the backend (%d connections)", n)
			}
		})
	}
}

func TestL4Gates_TLS(t *testing.T) {
	pki := newSTPKI(t, "gates")
	for _, c := range stGateCases {
		t.Run(c.name, func(t *testing.T) {
			echo, accepted := stTCPEchoBackend(t)
			addr := stFreeTCPAddr(t)
			l := config.Listener{Name: "tls", Bind: addr, Protocol: "tcp", Backend: "be",
				TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
			c.set(&l)
			stStart(t, &config.Config{Listeners: []config.Listener{l},
				Backends: []config.Backend{{Name: "be", Servers: []string{echo}}}}, nil)
			stBlock(t, c.dyn)

			d := &net.Dialer{Timeout: 2 * time.Second}
			conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"})
			if c.admit {
				if err != nil {
					t.Fatalf("admitted client: handshake: %v", err)
				}
				defer conn.Close()
				if err := stEcho(conn, "hello"); err != nil {
					t.Fatalf("admitted client: %v", err)
				}
				return
			}
			// Refused before the handshake: the dial fails, or (never) relays.
			if err == nil {
				defer conn.Close()
				stRefused(t, conn, "hello")
			}
			if n := accepted.Load(); n != 0 {
				t.Fatalf("refused client reached the backend (%d connections)", n)
			}
		})
	}
}

func TestL4Gates_UDP(t *testing.T) {
	for _, c := range stGateCases {
		t.Run(c.name, func(t *testing.T) {
			be, got := stUDPBackend(t, stEchoReply)
			addr := stFreeUDPAddr(t)
			l := config.Listener{Name: "udp", Bind: addr, Protocol: "udp", Backend: "be"}
			c.set(&l)
			stStart(t, &config.Config{Listeners: []config.Listener{l},
				Backends: []config.Backend{{Name: "be", Servers: []string{be}}}}, nil)
			stBlock(t, c.dyn)

			reply, err := stUDPExchange("127.0.0.1", addr, []byte("ping"), time.Second)
			if c.admit {
				if err != nil || string(reply) != "ping" {
					t.Fatalf("admitted client: reply=%q err=%v", reply, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("refused client got a reply %q", reply)
			}
			if d, ok := stWaitGot(got, 300*time.Millisecond); ok {
				t.Fatalf("refused client's datagram reached the backend: %q", d)
			}
		})
	}
}

// Behind a trusted relay (accept_proxy_from) the policy applies to the client
// the PROXY v2 header names — not to the relay, whose own address is
// infrastructure — and a relay that sends no header is itself the client.
func TestL4Gates_TrustedRelayTCP(t *testing.T) {
	echo, accepted := stTCPEchoBackend(t)
	addr := stFreeTCPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-in", Bind: addr, Protocol: "tcp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, IPDenylist: []string{"198.51.100.66/32"}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
	}, nil)
	stBlock(t, "198.51.100.9")

	relayed := func(client string) net.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		stTCPProxyHeader(t, conn, client)
		return conn
	}

	t.Run("dynamically denylisted client", func(t *testing.T) {
		stRefused(t, relayed("198.51.100.9:4444"), "hello")
	})
	t.Run("statically denied client", func(t *testing.T) {
		stRefused(t, relayed("198.51.100.66:4444"), "hello")
	})
	if n := accepted.Load(); n != 0 {
		t.Fatalf("refused relayed clients reached the backend (%d connections)", n)
	}
	t.Run("clean client", func(t *testing.T) {
		if err := stEcho(relayed("198.51.100.10:4444"), "hello"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("relay itself denylisted, client clean", func(t *testing.T) {
		stBlock(t, "127.0.0.1")
		if err := stEcho(relayed("198.51.100.11:4444"), "hello"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("relay without header is the client", func(t *testing.T) {
		stBlock(t, "127.0.0.1")
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		stRefused(t, conn, "hello")
	})
}

// The TLS-terminating listener reads the PROXY v2 header off the raw stream
// before the handshake (as the plain TCP path does) and admits the client it
// names.
func TestL4Gates_TrustedRelayTLS(t *testing.T) {
	pki := newSTPKI(t, "relaytls")
	echo, accepted := stTCPEchoBackend(t)
	addr := stFreeTCPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-tls", Bind: addr, Protocol: "tcp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"},
			TLS:             config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
	}, nil)
	stBlock(t, "198.51.100.9")

	relayedTLS := func(client string) (*tls.Conn, error) {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { raw.Close() })
		stTCPProxyHeader(t, raw, client)
		tc := tls.Client(raw, &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"})
		tc.SetDeadline(time.Now().Add(3 * time.Second))
		err = tc.Handshake()
		tc.SetDeadline(time.Time{})
		return tc, err
	}

	if tc, err := relayedTLS("198.51.100.9:5555"); err == nil {
		stRefused(t, tc, "hello")
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("denylisted relayed client reached the backend (%d connections)", n)
	}
	tc, err := relayedTLS("198.51.100.10:5555")
	if err != nil {
		t.Fatalf("clean relayed client: handshake after PROXY header: %v", err)
	}
	if err := stEcho(tc, "hello"); err != nil {
		t.Fatalf("clean relayed client: %v", err)
	}
}

func TestL4Gates_TrustedRelayUDP(t *testing.T) {
	be, got := stUDPBackend(t, stEchoReply)
	addr := stFreeUDPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, IPDenylist: []string{"198.51.100.66/32"}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	stBlock(t, "198.51.100.9")

	for _, client := range []string{"198.51.100.9:7000", "198.51.100.66:7000"} {
		reply, err := stUDPExchange("127.0.0.1", addr, stUDPDatagramWithProxy(t, client, addr, []byte("ping")), 700*time.Millisecond)
		if err == nil {
			t.Fatalf("refused relayed client %s got a reply %q", client, reply)
		}
	}
	if d, ok := stWaitGot(got, 300*time.Millisecond); ok {
		t.Fatalf("refused relayed client reached the backend: %q", d)
	}
	reply, err := stUDPExchange("127.0.0.1", addr, stUDPDatagramWithProxy(t, "198.51.100.10:7000", addr, []byte("ping")), 2*time.Second)
	if err != nil || string(reply) != "ping" {
		t.Fatalf("clean relayed client: reply=%q err=%v", reply, err)
	}
	// The relay's own address on the denylist does not cut relayed clients.
	stBlock(t, "127.0.0.1")
	reply, err = stUDPExchange("127.0.0.1", addr, stUDPDatagramWithProxy(t, "198.51.100.11:7000", addr, []byte("pong")), 2*time.Second)
	if err != nil || string(reply) != "pong" {
		t.Fatalf("clean client behind a denylisted relay: reply=%q err=%v", reply, err)
	}
}

// backend max_connections caps concurrent L4 sessions too (it used to bind
// HTTP requests only): a session beyond the cap is refused, and the slot is
// freed when a session ends.
func TestL4MaxConnections_TCP(t *testing.T) {
	pki := newSTPKI(t, "maxconn")
	for _, withTLS := range []bool{false, true} {
		name := "plain"
		if withTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			echo, _ := stTCPEchoBackend(t)
			addr := stFreeTCPAddr(t)
			l := config.Listener{Name: "mc", Bind: addr, Protocol: "tcp", Backend: "be"}
			if withTLS {
				l.TLS = config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}
			}
			stStart(t, &config.Config{Listeners: []config.Listener{l},
				Backends: []config.Backend{{Name: "be", Servers: []string{echo}, MaxConnections: 1}}}, nil)

			dial := func() net.Conn {
				t.Helper()
				if withTLS {
					c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
						&tls.Config{RootCAs: pki.caPool, ServerName: "localhost"})
					if err != nil {
						t.Fatalf("dial: %v", err)
					}
					return c
				}
				c, err := net.Dial("tcp", addr)
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				return c
			}

			first := dial()
			if err := stEcho(first, "one"); err != nil {
				t.Fatalf("first session: %v", err)
			}
			second := dial()
			stRefused(t, second, "two")
			second.Close()

			first.Close()
			deadline := time.Now().Add(3 * time.Second)
			for {
				third := dial()
				err := stEcho(third, "three")
				third.Close()
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("slot never freed after the first session ended: %v", err)
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

func TestL4MaxConnections_UDP(t *testing.T) {
	sink, got := stUDPBackend(t, nil) // never answers: sessions end after the no-reply TTL
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "mc-udp", Bind: addr, Protocol: "udp", Backend: "be"}},
		Backends:  []config.Backend{{Name: "be", Servers: []string{sink}, MaxConnections: 1}},
	}, func(e *Engine) { e.udpNoReplyTimeout = time.Second })

	stUDPExchange("127.0.0.1", addr, []byte("first"), 100*time.Millisecond)
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "first" {
		t.Fatalf("first session: backend got %q (ok=%v)", d, ok)
	}
	stUDPExchange("127.0.0.1", addr, []byte("second"), 100*time.Millisecond)
	if d, ok := stWaitGot(got, 200*time.Millisecond); ok {
		t.Fatalf("second session beyond max_connections reached the backend: %q", d)
	}
	// The first session ends (no backend reply within the TTL) and frees its slot.
	limiter := e.ConnLimiters["be"]
	deadline := time.Now().Add(3 * time.Second)
	for limiter.Active() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("backend slot not released: active=%d", limiter.Active())
		}
		time.Sleep(20 * time.Millisecond)
	}
	stUDPExchange("127.0.0.1", addr, []byte("third"), 100*time.Millisecond)
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "third" {
		t.Fatalf("session after the slot freed: backend got %q (ok=%v)", d, ok)
	}
	if n := limiter.OverReleaseCount(); n != 0 {
		t.Fatalf("conn limiter over-released %d times", n)
	}
}
