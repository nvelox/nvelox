package core

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
)

// A source that is refused sends on, and without a session every datagram
// of it is a new session to refuse. What such a source costs is a look at
// the policy: it takes nothing from the listener's rate (which is for the
// clients the listener serves), its refusals are counted, and it has one
// line in the access log for many datagrams, not one for each.

// stAccessLog sends the access log to a file for the test and returns a
// function that reads its lines.
func stAccessLog(t *testing.T) func() []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("warning", path, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logging.Init("warning", "", "") })
	return func() []string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
}

// stLinesOf counts the access-log lines of client ip with status.
func stLinesOf(lines []string, ip, status string) int {
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, ip+" - l4 ") && strings.Contains(l, " "+status+" ") {
			n++
		}
	}
	return n
}

// stSendUDP sends n datagrams from srcIP to addr, each from a port of its
// own, and waits for no answer.
func stSendUDP(t *testing.T, srcIP, addr string, n int, payload []byte) {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(srcIP)}, raddr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
}

func TestUDP_RefusedSourceTakesNothingFromTheRate(t *testing.T) {
	stUDPEngines(t, func(t *testing.T) {
		be, _ := stUDPBackend(t, stEchoReply)
		addr := stFreeUDPAddr(t)
		e := stStart(t, &config.Config{
			Listeners: []config.Listener{{Name: "udp-in", Bind: addr, Protocol: "udp", Backend: "be",
				IPDenylist: []string{"127.0.0.2/32"},
				// Two new sessions, and the next in a minute.
				RateLimit: config.RateLimitConfig{ConnectionsPerSecond: 1.0 / 60, Burst: 2}}},
			Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
		}, nil)
		refused, limited := stDropped(e, udpDropRefused), stDropped(e, udpDropRateLimit)

		stSendUDP(t, "127.0.0.2", addr, 50, []byte("from a refused source"))
		waitFor(t, "the refused source's datagrams to be counted", func() bool { return refused() == 50 })
		for i := 0; i < 2; i++ {
			if got, err := stUDPExchange("127.0.0.1", addr, []byte("hello"), 2*time.Second); err != nil || string(got) != "hello" {
				t.Fatalf("client %d after the refused source's datagrams: %q, %v; the listener's rate is for the clients it serves", i+1, got, err)
			}
		}
		if n := limited(); n != 0 {
			t.Errorf("%d sessions refused by the rate limit, want none", n)
		}
		// The rate holds for the clients the listener serves.
		if got, err := stUDPExchange("127.0.0.1", addr, []byte("a third"), 300*time.Millisecond); err == nil {
			t.Errorf("a third new session within the rate's burst of 2 was served: %q", got)
		}
		if n := limited(); n != 1 {
			t.Errorf("%d sessions refused by the rate limit, want the third", n)
		}
	})
}

func TestUDP_RefusedSourceHasOneLineForManyDatagrams(t *testing.T) {
	const datagrams = 200
	for _, tc := range []struct {
		what     string
		listener func(l *config.Listener, b *config.Backend)
		perIP    int // the sessions a source may have (0: the default)
		// holder: a client that is served first and stays (it takes what
		// the refused source then finds used up).
		holder         string
		reason, status string
		// served: how many of another source's datagrams are served before
		// that source is refused too.
		served int
	}{
		{"refused by the listener's lists", func(l *config.Listener, _ *config.Backend) { l.IPDenylist = []string{"127.0.0.2/32", "127.0.0.3/32"} },
			0, "", udpDropRefused, l4StatusRefused, 0},
		{"refused by the rate limit", func(l *config.Listener, _ *config.Backend) {
			l.RateLimit = config.RateLimitConfig{ConnectionsPerSecond: 1.0 / 60, Burst: 1}
		}, 0, "127.0.0.1", udpDropRateLimit, l4StatusRateLimited, 0},
		{"refused for the backend's max_connections", func(_ *config.Listener, b *config.Backend) { b.MaxConnections = 1 },
			0, "127.0.0.1", udpDropBackendLimit, l4StatusRateLimited, 0},
		{"refused for the sessions a source may have", func(*config.Listener, *config.Backend) {},
			1, "127.0.0.2", udpDropSourceLimit, l4StatusRateLimited, 1},
	} {
		t.Run(tc.what, func(t *testing.T) {
			stUDPEngines(t, func(t *testing.T) {
				lines := stAccessLog(t)
				be, _ := stUDPBackend(t, stEchoReply)
				addr := stFreeUDPAddr(t)
				l := config.Listener{Name: "udp-in", Bind: addr, Protocol: "udp", Backend: "be"}
				b := config.Backend{Name: "be", Servers: []string{be}}
				tc.listener(&l, &b)
				e := stStart(t, &config.Config{Listeners: []config.Listener{l}, Backends: []config.Backend{b}}, func(e *Engine) {
					if tc.perIP > 0 {
						e.udpMaxSessionsPerIP = tc.perIP
					}
				})
				counted := stDropped(e, tc.reason)
				if tc.holder != "" {
					raddr, _ := net.ResolveUDPAddr("udp", addr)
					c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(tc.holder)}, raddr)
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					c.Write([]byte("first"))
					c.SetReadDeadline(time.Now().Add(2 * time.Second))
					if n, err := c.Read(make([]byte, 64)); err != nil || n != len("first") {
						t.Fatalf("the client that is served first: %d bytes, %v", n, err)
					}
				}

				stSendUDP(t, "127.0.0.2", addr, datagrams, []byte("again and again"))
				waitFor(t, "the refusals to be counted", func() bool { return counted() == datagrams })
				time.Sleep(100 * time.Millisecond) // a line that is one too many would be written by now
				if n := stLinesOf(lines(), "127.0.0.2", tc.status); n != 1 {
					t.Errorf("%d lines in the access log for %d datagrams of the refused source, want 1", n, datagrams)
				}

				// Another refused source has a line of its own.
				stSendUDP(t, "127.0.0.3", addr, 5, []byte("me too"))
				waitFor(t, "the second source's refusals to be counted", func() bool { return counted() == int64(datagrams+5-tc.served) })
				time.Sleep(100 * time.Millisecond)
				if n := stLinesOf(lines(), "127.0.0.3", tc.status); n != 1 {
					t.Errorf("%d lines in the access log for the second refused source, want 1", n)
				}
			})
		})
	}
}

// A trusted relay sends on for a client the policy refuses as that client
// would: its refusals are counted, and the client has one line.
func TestUDP_RefusedClientOfARelayHasOneLineForManyDatagrams(t *testing.T) {
	stUDPEngines(t, func(t *testing.T) {
		lines := stAccessLog(t)
		be, got := stUDPBackend(t, nil)
		addr := stFreeUDPAddr(t)
		e := stStart(t, &config.Config{
			Listeners: []config.Listener{{Name: "relay-udp", Bind: addr, Protocol: "udp", Backend: "be",
				AcceptProxyFrom: []string{"127.0.0.0/8"}, IPDenylist: []string{"198.51.100.66/32"}}},
			Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
		}, nil)
		refused := stDropped(e, udpDropRefused)
		const datagrams = 100
		raddr, _ := net.ResolveUDPAddr("udp", addr)
		c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, raddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		d := stUDPDatagramWithProxy(t, "198.51.100.66:7000", addr, []byte("not for the backend"))
		for i := 0; i < datagrams; i++ {
			c.Write(d)
			// Each is a session of its own: the one before is refused and
			// gone before the next arrives.
			n := int64(i + 1)
			waitFor(t, fmt.Sprintf("refusal %d to be counted", n), func() bool { return refused() >= n })
		}
		if n := refused(); n != datagrams {
			t.Errorf("%d refusals counted for %d datagrams", n, datagrams)
		}
		time.Sleep(100 * time.Millisecond)
		if n := stLinesOf(lines(), "198.51.100.66", l4StatusRefused); n != 1 {
			t.Errorf("%d lines in the access log for %d datagrams of the refused client, want 1", n, datagrams)
		}
		if d, ok := stWaitGot(got, 100*time.Millisecond); ok {
			t.Errorf("a datagram of the refused client reached the backend: %q", d)
		}
		// A client the policy admits is served through the same relay, and
		// its session has its line when it ends.
		c.Write(stUDPDatagramWithProxy(t, "198.51.100.10:7000", addr, []byte("for the backend")))
		if d, ok := stWaitGot(got, 2*time.Second); !ok || !bytes.Equal(d, []byte("for the backend")) {
			t.Errorf("the admitted client's datagram at the backend: %q (%v)", d, ok)
		}
	})
}

// What a socket remembers of the sources it refused: one line for a source
// within udpRefusalMemory, room for udpRefusalsKept sources, and room again
// when their time is over.
func TestUDPRefusals_Memory(t *testing.T) {
	var r udpRefusals
	ip := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) }
	t0 := int64(1_000_000_000_000)
	mem := int64(udpRefusalMemory)
	if !r.first(ip(1), t0) {
		t.Fatal("a source's first refusal has no line")
	}
	if r.first(ip(1), t0+mem-1) {
		t.Error("a second line for a source within the time it is remembered")
	}
	if !r.first(ip(2), t0+1) {
		t.Error("another source's first refusal has no line")
	}
	if !r.first(ip(1), t0+mem) {
		t.Error("no line for a source when its time is over")
	}
	// As many sources as are remembered, then one more.
	r = udpRefusals{}
	for i := 0; i < udpRefusalsKept; i++ {
		if !r.first(ip(i), t0) {
			t.Fatalf("source %d of %d has no line", i+1, udpRefusalsKept)
		}
	}
	half := int64(500 * time.Millisecond)
	if r.first(ip(udpRefusalsKept), t0+mem-half) {
		t.Errorf("a line for a source past the %d that are remembered", udpRefusalsKept)
	}
	if len(r.until) != udpRefusalsKept {
		t.Errorf("%d sources remembered, want %d", len(r.until), udpRefusalsKept)
	}
	// Room is looked for once a second at most (in a flood every datagram
	// would look): their time is over, but the look was half a second ago.
	if r.first(ip(udpRefusalsKept), t0+mem) {
		t.Error("room was looked for twice within a second")
	}
	// Their time is over: there is room again, and the old ones are gone.
	if !r.first(ip(udpRefusalsKept), t0+mem+half) {
		t.Error("no line for a new source after the remembered ones' time was over")
	}
	if len(r.until) != 1 {
		t.Errorf("%d sources remembered after the old ones' time was over, want the new one", len(r.until))
	}
}

// The same order for TCP: a client the policy refuses takes nothing from
// the listener's rate.
func TestL4_RefusedClientTakesNothingFromTheRate(t *testing.T) {
	paths := []string{"goroutines", "tls"}
	if l4FastEnabled() {
		paths = []string{"loops", "goroutines", "tls"}
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			if path == "goroutines" {
				stL4Goroutines(t)
			}
			var pki *stPKI
			var serverTLS config.TLSConfig
			if path == "tls" {
				pki = newSTPKI(t, "l4rate")
				serverTLS = config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}
			}
			beLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { beLn.Close() })
			go func() {
				for {
					c, err := beLn.Accept()
					if err != nil {
						return
					}
					go func() { io.Copy(c, c); c.Close() }()
				}
			}()
			addr := stFreeTCPAddr(t)
			stStart(t, &config.Config{
				Listeners: []config.Listener{{Name: "l4", Bind: addr, Protocol: "tcp", Backend: "be", TLS: serverTLS,
					IPDenylist: []string{"127.0.0.2/32"},
					RateLimit:  config.RateLimitConfig{ConnectionsPerSecond: 1.0 / 60, Burst: 2}}},
				Backends: []config.Backend{{Name: "be", Servers: []string{beLn.Addr().String()}}},
			}, nil)
			// dial connects from src; to the listener that ends TLS the
			// session is one of TLS (its handshake is made with the first
			// byte written).
			dial := func(src string) (net.Conn, error) {
				d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
				c, err := d.Dial("tcp", addr)
				if err != nil || pki == nil || src == "127.0.0.2" {
					return c, err
				}
				return tls.Client(c, &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"}), nil
			}
			for i := 0; i < 20; i++ {
				c, err := dial("127.0.0.2")
				if err != nil {
					t.Fatal(err)
				}
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
					t.Fatalf("the refused client's connection %d was not closed: %v", i+1, err)
				}
				c.Close()
			}
			for i := 0; i < 2; i++ {
				c, err := dial("127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if err := stEcho(c, "hello"); err != nil {
					t.Fatalf("client %d after the refused client's connections: %v; the listener's rate is for the clients it serves", i+1, err)
				}
			}
			// The rate holds for the clients the listener serves.
			c, err := dial("127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := stEcho(c, "a third"); err == nil {
				t.Error("a third connection within the rate's burst of 2 was served")
			}
		})
	}
}
