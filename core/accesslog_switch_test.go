package core

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

// The access-log switch of a TCP or UDP listener (its access_log): off, a
// connection or session has no line, served or refused; a reload turns the
// lines on and off again under the running listener, for what begins after
// it. TCP on the event loops and on goroutines, TCP with TLS, and UDP on
// both of its engines.
func TestL4_AccessLogSwitch(t *testing.T) {
	for _, v := range l4Variants(t) {
		t.Run(v.name, func(t *testing.T) { v.run(t, l4AccessLogSwitch) })
	}
}

// A connection the listener's rate refuses has its line, or none when the
// access log is off.
func TestL4_AccessLogSwitchRateLimited(t *testing.T) {
	for _, v := range l4Variants(t) {
		if v.proto == "udp" {
			continue // a UDP source over the rate is a refusal like any other (above)
		}
		t.Run(v.name, func(t *testing.T) {
			v.run(t, func(t *testing.T, v l4Variant) {
				for _, on := range []bool{true, false} {
					lines := stAccessLog(t)
					be, _ := stTCPEchoBackend(t)
					addr := stFreeTCPAddr(t)
					l := config.Listener{Name: "rl", Bind: addr, Protocol: "tcp", Backend: "be", AccessLog: &on,
						RateLimit: config.RateLimitConfig{ConnectionsPerSecond: 0.001, Burst: 1}}
					if v.tls {
						l.TLS = config.TLSConfig{Cert: v.pki.srvCert, Key: v.pki.srvKey}
					}
					stStart(t, &config.Config{Listeners: []config.Listener{l}, Backends: []config.Backend{{Name: "be", Servers: []string{be}}}}, nil)
					v.served(t, addr)
					v.refused(t, addr, "127.0.0.1")
					want := 0
					if on {
						want = 1
					}
					if on {
						waitFor(t, "the line of the connection over the rate", func() bool { return stLinesOf(lines(), "127.0.0.1", l4StatusRateLimited) == 1 })
					} else {
						time.Sleep(300 * time.Millisecond)
					}
					if n := stLinesOf(lines(), "127.0.0.1", l4StatusRateLimited); n != want {
						t.Errorf("access log %v: %d lines of a connection over the rate, want %d", on, n, want)
					}
				}
			})
		})
	}
}

// l4Variant is one way a TCP or UDP listener runs.
type l4Variant struct {
	name, proto string
	tls         bool
	pki         *stPKI
	run         func(t *testing.T, f func(t *testing.T, v l4Variant))
	served      func(t *testing.T, addr string)
	refused     func(t *testing.T, addr, ip string)
}

func l4Variants(t *testing.T) []l4Variant {
	pki := newSTPKI(t, "l4-access")
	tcpServed := func(t *testing.T, addr string) {
		t.Helper()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if err := stEcho(c, "ping"); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	tcpRefused := func(t *testing.T, addr, ip string) {
		t.Helper()
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		stRefused(t, c, "ping")
	}
	tlsConf := &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"}
	tlsServed := func(t *testing.T, addr string) {
		t.Helper()
		c, err := stTLSDial(addr, tlsConf)
		if err != nil {
			t.Fatal(err)
		}
		if err := stEcho(c, "ping"); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	tlsRefused := func(t *testing.T, addr, ip string) {
		t.Helper()
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}, Timeout: 2 * time.Second}
		raw, err := d.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		c := tls.Client(raw, tlsConf)
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if err := c.Handshake(); err == nil {
			if _, err := io.WriteString(c, "ping"); err == nil {
				buf := make([]byte, 4)
				if _, err := io.ReadFull(c, buf); err == nil {
					t.Fatalf("a refused client from %s was relayed", ip)
				}
			}
		} else if strings.Contains(err.Error(), "timeout") {
			t.Fatalf("a refused client from %s was not closed: %v", ip, err)
		}
	}
	// The UDP backend answers nothing: a session it answered stays for the
	// idle time (a minute), one it did not ends after the no-reply time,
	// which the test makes short. Its line says ok either way: it reached
	// its backend.
	udpServed := func(t *testing.T, addr string) {
		t.Helper()
		stUDPExchange("127.0.0.1", addr, []byte("ping"), 50*time.Millisecond)
	}
	udpRefused := func(t *testing.T, addr, ip string) {
		t.Helper()
		if reply, err := stUDPExchange(ip, addr, []byte("ping"), 300*time.Millisecond); err == nil {
			t.Fatalf("a refused UDP source got %q", reply)
		}
	}
	vs := []l4Variant{
		{name: "tcp-goroutines", proto: "tcp", served: tcpServed, refused: tcpRefused},
		{name: "tls", proto: "tcp", tls: true, pki: pki, served: tlsServed, refused: tlsRefused},
		{name: "udp", proto: "udp", served: udpServed, refused: udpRefused},
	}
	if l4FastEnabled() {
		vs = append([]l4Variant{{name: "tcp-loops", proto: "tcp", served: tcpServed, refused: tcpRefused}}, vs...)
	}
	for i := range vs {
		v := &vs[i]
		switch v.name {
		case "tcp-goroutines":
			v.run = func(t *testing.T, f func(t *testing.T, v l4Variant)) {
				l4FastOff.Store(true)
				defer l4FastOff.Store(false)
				f(t, *v)
			}
		case "udp":
			v.run = func(t *testing.T, f func(t *testing.T, v l4Variant)) {
				stUDPEngines(t, func(t *testing.T) { f(t, *v) })
			}
		default:
			v.run = func(t *testing.T, f func(t *testing.T, v l4Variant)) { f(t, *v) }
		}
	}
	return vs
}

func l4AccessLogSwitch(t *testing.T, v l4Variant) {
	lines := stAccessLog(t)
	var be, addr string
	if v.proto == "tcp" {
		be, _ = stTCPEchoBackend(t)
		addr = stFreeTCPAddr(t)
	} else {
		be, _ = stUDPBackend(t, nil)
		addr = stFreeUDPAddr(t)
	}
	// Clients from 127.0.0.9 to .11 are refused: one address per phase, as
	// a refused UDP source has one line in ten seconds.
	refusedIPs := []string{"127.0.0.9", "127.0.0.10", "127.0.0.11"}
	mk := func(on bool) *config.Config {
		l := config.Listener{Name: "l4-" + v.name, Bind: addr, Protocol: v.proto, Backend: "be",
			IPDenylist: []string{"127.0.0.9/32", "127.0.0.10/31"}, AccessLog: &on}
		if v.tls {
			l.TLS = config.TLSConfig{Cert: v.pki.srvCert, Key: v.pki.srvKey}
		}
		return &config.Config{Version: "2", Listeners: []config.Listener{l}, Backends: []config.Backend{{Name: "be", Servers: []string{be}}}}
	}
	// A UDP session has its line when it ends: here when its backend has
	// not answered for 300 ms.
	e := stStart(t, mk(false), func(e *Engine) {
		e.udpClientReadTimeout = 300 * time.Millisecond
		e.udpNoReplyTimeout = 300 * time.Millisecond
	})
	count := func() (ok, ref int) {
		l := lines()
		ok = stLinesOf(l, "127.0.0.1", "ok")
		for _, ip := range refusedIPs {
			for _, line := range l {
				if strings.HasPrefix(line, ip+" - l4 ") {
					ref++
				}
			}
		}
		return ok, ref
	}
	// none: no line comes, also once the sessions are over.
	none := func(phase string, okBefore, refBefore int) {
		t.Helper()
		time.Sleep(1200 * time.Millisecond)
		if ok, ref := count(); ok != okBefore || ref != refBefore {
			t.Errorf("%s: %d lines of served sessions and %d of refused ones, want %d and %d", phase, ok, ref, okBefore, refBefore)
		}
	}

	v.served(t, addr)
	v.refused(t, addr, refusedIPs[0])
	none("access_log off at start", 0, 0)

	if err := e.Reload(mk(true)); err != nil {
		t.Fatal(err)
	}
	v.served(t, addr)
	v.refused(t, addr, refusedIPs[1])
	waitFor(t, "the lines once a reload turned access_log on", func() bool { ok, ref := count(); return ok == 1 && ref == 1 })

	if err := e.Reload(mk(false)); err != nil {
		t.Fatal(err)
	}
	v.served(t, addr)
	v.refused(t, addr, refusedIPs[2])
	none("access_log off again by a reload", 1, 1)
}

// An HTTP listener's access_log reaches the site the engine builds for it
// (at start, and again at each reload), which both HTTP paths read.
func TestL7_AccessLogSwitchReachesTheSite(t *testing.T) {
	on, off := true, false
	cfg := &config.Config{
		Backends: []config.Backend{{Name: "be", Balance: "roundrobin", Servers: []string{"10.0.0.1:80"}}},
		Listeners: []config.Listener{
			{Name: "logged", Bind: "127.0.0.1:0", Protocol: "http", Backend: "be", AccessLog: &on},
			{Name: "quiet", Bind: "127.0.0.1:0", Protocol: "http", Backend: "be", AccessLog: &off},
			{Name: "default", Bind: "127.0.0.1:0", Protocol: "http", Backend: "be"},
		},
	}
	expanded, err := ExpandListeners(cfg.Listeners)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(cfg)
	e.Listeners = expanded
	e.initBackends()
	for i, want := range []bool{false, true, false} {
		s := e.buildL7Site(expanded[i])
		if s.Listener.AccessLogOff != want {
			t.Errorf("listener %s: the site's access log off %v, want %v", expanded[i].Name, s.Listener.AccessLogOff, want)
		}
	}
}
