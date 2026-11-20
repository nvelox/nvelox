package core

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/config"
	"nvelox/proxy"
)

// A trusted relay (accept_proxy_from) starts every TCP connection with a
// PROXY v2 header, on plain and on TLS-terminating listeners alike: the
// client it names, or LOCAL for the relay's own traffic. A relay is never
// taken for the client of what it relays.

func stLocalHeader(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := (&proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}).WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func stClientHeader(t *testing.T, client string) []byte {
	t.Helper()
	src, err := net.ResolveTCPAddr("tcp", client)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := proxyproto.HeaderProxyFromAddrs(2, src, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}).WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// stConnPair returns the two ends of a fresh loopback TCP connection.
func stConnPair(t *testing.T) (dialed, accepted net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialed, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	accepted, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dialed.Close(); accepted.Close() })
	return dialed, accepted
}

// stBrokenHeader is the v2 magic and a TCP-over-IPv4 header 4 bytes long:
// too short for its addresses.
func stBrokenHeader() []byte {
	return append(append([]byte{}, proxy.V2Signature...), 0x21, 0x11, 0x00, 0x04, 1, 2, 3, 4)
}

func TestRelayHeaderRequired_TCP(t *testing.T) {
	for _, mode := range []string{"plain", "tls"} {
		t.Run(mode, func(t *testing.T) {
			echo, accepted := stTCPEchoBackend(t)
			addr := stFreeTCPAddr(t)
			name := "strict-" + mode
			l := config.Listener{Name: name, Bind: addr, Protocol: "tcp", Backend: "be", AcceptProxyFrom: []string{"127.0.0.0/8"}}
			var clientTLS *tls.Config
			if mode == "tls" {
				pki := newSTPKI(t, "strict")
				l.TLS = config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}
				clientTLS = &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"}
			}
			e := stStart(t, &config.Config{
				Listeners: []config.Listener{l},
				Backends:  []config.Backend{{Name: "be", Servers: []string{echo}}},
			}, nil)
			refusals := func(reason string) uint64 {
				return e.Metrics.GetCounter("nvelox_proxy_header_rejected_total", map[string]string{"listener": name, "reason": reason}).Get()
			}
			// session opens a relay's connection that starts with first,
			// then (on the TLS listener) the handshake, and echoes.
			session := func(first []byte) error {
				raw, err := net.Dial("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				if len(first) > 0 {
					if _, err := raw.Write(first); err != nil {
						return err
					}
				}
				var c net.Conn = raw
				if clientTLS != nil {
					tc := tls.Client(raw, clientTLS)
					tc.SetDeadline(time.Now().Add(3 * time.Second))
					if err := tc.Handshake(); err != nil {
						return err
					}
					c = tc
				}
				return stEcho(c, "hello")
			}
			notHung := func(what string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s: the session worked; want it refused", what)
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Fatalf("%s: the connection hung instead of being closed: %v", what, err)
				}
			}

			notHung("no header", session(nil))
			notHung("a header that does not parse", session(stBrokenHeader()))
			if n := accepted.Load(); n != 0 {
				t.Fatalf("refused relay connections reached the backend (%d)", n)
			}
			if a, b := refusals(proxy.RefusedMissing), refusals(proxy.RefusedMalformed); a != 1 || b != 1 {
				t.Fatalf("refusals counted: missing %d, malformed %d; want 1 and 1", a, b)
			}

			// A relay's connection that brings nothing is closed without a count.
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			time.Sleep(200 * time.Millisecond)
			for _, r := range []string{proxy.RefusedMissing, proxy.RefusedMalformed, proxy.RefusedTimeout, proxy.RefusedSignature} {
				want := uint64(0)
				if r == proxy.RefusedMissing || r == proxy.RefusedMalformed {
					want = 1
				}
				if n := refusals(r); n != want {
					t.Fatalf("after an empty connection: %s refusals = %d, want %d", r, n, want)
				}
			}

			if err := session(stClientHeader(t, "198.51.100.10:4444")); err != nil {
				t.Fatalf("a header naming a client: %v", err)
			}
			if err := session(stLocalHeader(t)); err != nil {
				t.Fatalf("a LOCAL header (the relay is the client): %v", err)
			}
			if n := accepted.Load(); n != 2 {
				t.Fatalf("backend connections = %d, want 2", n)
			}
		})
	}
}

// A peer outside accept_proxy_from is not looked at: what it sends is its
// session's bytes (plain TCP) or goes to the TLS handshake as it is. A PROXY
// header from it names nobody.
func TestRelayHeader_OtherPeersNotLookedAt(t *testing.T) {
	hdr := stClientHeader(t, "198.51.100.10:4444")
	t.Run("plain", func(t *testing.T) {
		echo, _ := stTCPEchoBackend(t)
		addr := stFreeTCPAddr(t)
		stStart(t, &config.Config{
			Listeners: []config.Listener{{Name: "other-plain", Bind: addr, Protocol: "tcp", Backend: "be", AcceptProxyFrom: []string{"10.99.0.0/16"}}},
			Backends:  []config.Backend{{Name: "be", Servers: []string{echo}}},
		}, nil)
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// The header is payload like the rest: the backend echoes all of it.
		if err := stEcho(c, string(hdr)+"hello"); err != nil {
			t.Fatalf("a header from a peer that is no relay was not relayed as payload: %v", err)
		}
	})
	t.Run("tls", func(t *testing.T) {
		pki := newSTPKI(t, "other")
		echo, accepted := stTCPEchoBackend(t)
		addr := stFreeTCPAddr(t)
		stStart(t, &config.Config{
			Listeners: []config.Listener{{Name: "other-tls", Bind: addr, Protocol: "tcp", Backend: "be", AcceptProxyFrom: []string{"10.99.0.0/16"},
				TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}},
			Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
		}, nil)
		handshake := func(first []byte) error {
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.Write(first)
			tc := tls.Client(raw, &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"})
			tc.SetDeadline(time.Now().Add(3 * time.Second))
			if err := tc.Handshake(); err != nil {
				return err
			}
			return stEcho(tc, "hello")
		}
		if err := handshake(hdr); err == nil {
			t.Fatal("a header from a peer that is no relay was taken off the stream: the TLS session worked")
		}
		if n := accepted.Load(); n != 0 {
			t.Fatalf("that connection reached the backend (%d)", n)
		}
		if err := handshake(nil); err != nil {
			t.Fatalf("a plain TLS client: %v", err)
		}
	})
}

// relayClient reads a relay's header and not one byte past it, and says why
// a connection without a usable one is closed.
func TestRelayClient(t *testing.T) {
	realClient := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4242}
	hdr := stClientHeader(t, realClient.String())
	trust := newProxyTrust([]string{"127.0.0.0/8"}, nil, false)

	t.Run("header split across writes, payload left on the connection", func(t *testing.T) {
		a, b := stConnPair(t)
		go func() {
			a.Write(hdr[:5])
			time.Sleep(20 * time.Millisecond)
			a.Write(append(append([]byte{}, hdr[5:]...), "payload"...))
		}()
		client, reason, _ := trust.relayClient(b, time.Second)
		if reason != "" || client.String() != realClient.String() {
			t.Fatalf("client=%v reason=%q", client, reason)
		}
		got := make([]byte, len("payload"))
		b.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(b, got); err != nil || string(got) != "payload" {
			t.Fatalf("after the header: %q, %v; want the payload", got, err)
		}
	})
	t.Run("LOCAL: the relay is the client", func(t *testing.T) {
		a, b := stConnPair(t)
		a.Write(stLocalHeader(t))
		client, reason, _ := trust.relayClient(b, time.Second)
		if reason != "" || client.String() != b.RemoteAddr().String() {
			t.Fatalf("client=%v reason=%q, want the relay %v", client, reason, b.RemoteAddr())
		}
	})
	for name, tc := range map[string]struct {
		send  []byte
		close bool
		want  string
	}{
		"a raw stream":                 {[]byte("\x16\x03\x01hello"), false, proxy.RefusedMissing},
		"a header that does not parse": {stBrokenHeader(), false, proxy.RefusedMalformed},
		"a header cut short":           {hdr[:20], true, proxy.RefusedMalformed},
		"a header that stalls":         {hdr[:10], false, proxy.RefusedTimeout},
		"nothing, then gone":           {nil, true, proxy.NothingSent},
		"nothing to the limit":         {nil, false, proxy.NothingSent},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := stConnPair(t)
			a.Write(tc.send)
			if tc.close {
				a.Close()
			}
			client, reason, cause := trust.relayClient(b, 150*time.Millisecond)
			if client != nil || reason != tc.want || cause == nil {
				t.Fatalf("client=%v reason=%q cause=%v, want %q and its cause", client, reason, cause, tc.want)
			}
		})
	}
	t.Run("the read deadline is cleared", func(t *testing.T) {
		a, b := stConnPair(t)
		a.Write(hdr)
		if _, reason, _ := trust.relayClient(b, 100*time.Millisecond); reason != "" {
			t.Fatal(reason)
		}
		time.Sleep(150 * time.Millisecond)
		go a.Write([]byte("z"))
		if _, err := b.Read(make([]byte, 1)); err != nil {
			t.Fatalf("connection unusable after the header: %v", err)
		}
	})
	t.Run("a signature is required with keys", func(t *testing.T) {
		keyed := newProxyTrust([]string{"127.0.0.0/8"}, [][]byte{sigKeyA}, false)
		a, b := stConnPair(t)
		a.Write(hdr)
		if client, reason, cause := keyed.relayClient(b, time.Second); client != nil || reason != proxy.RefusedSignature || !errors.Is(cause, proxy.ErrSignatureMissing) {
			t.Fatalf("unsigned: client=%v reason=%q", client, reason)
		}
		a, b = stConnPair(t)
		signedTCPHeader(t, a, sigKeyA, realClient.String())
		if client, reason, _ := keyed.relayClient(b, time.Second); reason != "" || client.String() != realClient.String() {
			t.Fatalf("signed: client=%v reason=%q", client, reason)
		}
	})
}
