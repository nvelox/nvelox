package core

import (
	"bufio"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"nvelox/config"

	"github.com/pires/go-proxyproto"
)

// The PROXY v2 header a send_proxy_v2 backend gets from a TCP listener names
// the client and, as its destination, the address the client connected to:
// on a plain listener and on one that terminates TLS alike. (The TLS one
// used to send the address nvelox itself dialed the backend from, which
// tells the backend nothing about the client's connection.)
func TestSendProxyDestination_TCP(t *testing.T) {
	for _, mode := range []string{"plain", "tls"} {
		t.Run(mode, func(t *testing.T) {
			// A backend that reads the header of each connection.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			type named struct{ src, dst string }
			got := make(chan named, 4)
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						c.SetDeadline(time.Now().Add(5 * time.Second))
						hdr, err := proxyproto.Read(bufio.NewReader(c))
						if err != nil || hdr.Command != proxyproto.PROXY {
							got <- named{}
							return
						}
						got <- named{hdr.SourceAddr.String(), hdr.DestinationAddr.String()}
					}()
				}
			}()

			addr := stFreeTCPAddr(t)
			l := config.Listener{Name: "dest-" + mode, Bind: addr, Protocol: "tcp", Backend: "be"}
			var clientTLS *tls.Config
			if mode == "tls" {
				pki := newSTPKI(t, "dest")
				l.TLS = config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}
				clientTLS = &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"}
			}
			stStart(t, &config.Config{
				Listeners: []config.Listener{l},
				Backends:  []config.Backend{{Name: "be", Servers: []string{ln.Addr().String()}, SendProxyV2: true}},
			}, nil)

			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			var c net.Conn = raw
			if clientTLS != nil {
				tc := tls.Client(raw, clientTLS)
				tc.SetDeadline(time.Now().Add(5 * time.Second))
				if err := tc.Handshake(); err != nil {
					t.Fatal(err)
				}
				c = tc
			}
			if _, err := c.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			select {
			case n := <-got:
				if n.src != raw.LocalAddr().String() || n.dst != addr {
					t.Errorf("the backend was told %q -> %q, want %s -> %s", n.src, n.dst, raw.LocalAddr(), addr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the backend got no connection")
			}
		})
	}
}
