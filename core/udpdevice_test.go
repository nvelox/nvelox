//go:build linux

package core

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

// firstNonLoopbackIPv4 returns an interface other than loopback that carries
// an IPv4 address, for the negative case.
func firstNonLoopbackIPv4(t *testing.T) (string, net.IP) {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return ifi.Name, ipn.IP.To4()
			}
		}
	}
	t.Skip("no non-loopback interface with an IPv4 address")
	return "", nil
}

// TestUDPInterfaces_TrustOnlyWhereListed: with accept_proxy_interfaces
// a relay's PROXY header is used only on datagrams that arrived on a listed
// interface. Traffic to 127.0.0.1 arrives on lo: listing lo trusts it,
// listing another interface does not. (Packets from another host arriving on
// an unlisted interface are covered by a two-host check, not here: the
// kernel files a host's own traffic to a local address under the interface
// that carries the address.)
func TestUDPInterfaces_TrustOnlyWhereListed(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	port := strings.TrimPrefix(stFreeUDPAddr(t), "127.0.0.1")
	ifName, _ := firstNonLoopbackIPv4(t)
	port2 := strings.TrimPrefix(stFreeUDPAddr(t), "127.0.0.1")
	stStart(t, &config.Config{
		Listeners: []config.Listener{
			{Name: "via-lo", Bind: port, Protocol: "udp", Backend: "be",
				AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyInterfaces: []string{"lo"}},
			{Name: "via-other", Bind: port2, Protocol: "udp", Backend: "be",
				AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyInterfaces: []string{ifName}},
		},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)

	loAddr := "127.0.0.1" + port
	stUDPExchange("127.0.0.1", loAddr, stUDPDatagramWithProxy(t, "198.51.100.80:4000", loAddr, []byte("trusted")), 30*time.Millisecond)
	if d, ok := stWaitGot(got, time.Second); !ok || string(d) != "trusted" {
		t.Fatalf("header on lo with lo listed: backend got %q (ok=%v), want the stripped payload", d, ok)
	}
	for _, dst := range []string{"127.0.0.1" + port2} {
		dgram := stUDPDatagramWithProxy(t, "198.51.100.81:4000", dst, []byte("untrusted"))
		stUDPExchange("127.0.0.1", dst, dgram, 30*time.Millisecond)
		d, ok := stWaitGot(got, time.Second)
		if !ok || !bytes.Equal(d, dgram) {
			t.Fatalf("to %s with only %s listed: backend got %q (ok=%v), want the datagram untouched (header not trusted)", dst, ifName, d, ok)
		}
	}
}

func TestUDPInterfaces_StartErrors(t *testing.T) {
	ifName, _ := firstNonLoopbackIPv4(t)
	for name, l := range map[string]config.Listener{
		"unknown interface": {Name: "u", Bind: stFreeUDPAddr(t), Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyInterfaces: []string{"nvelox-no-such-if0"}},
		"bind address not on the interface": {Name: "u", Bind: stFreeUDPAddr(t), Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyInterfaces: []string{ifName}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{Listeners: []config.Listener{l},
				Backends: []config.Backend{{Name: "be", Servers: []string{"127.0.0.1:1"}}}}
			exp, err := ExpandListeners(cfg.Listeners)
			if err != nil {
				t.Fatal(err)
			}
			e := NewEngine(cfg)
			e.Listeners = exp
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- e.Start(ctx) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "accept_proxy_interfaces") {
					t.Fatalf("Start: %v, want an accept_proxy_interfaces error", err)
				}
			case <-e.Ready():
				t.Fatal("started")
			case <-time.After(5 * time.Second):
				t.Fatal("neither failed nor started")
			}
		})
	}
}
