//go:build linux

package httpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/metrics"
	"nvelox/proxy"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// HTTP/3 through a UDP relay. The tests' QUIC clients send through a
// socket that, like a relay's socket for one client, puts a PROXY v2
// header naming that client in front of every datagram.

// relaySocket is such a socket. It offers no ReadMsgUDP / WriteMsgUDP, so
// quic-go sends every packet through WriteTo.
type relaySocket struct {
	uc     *net.UDPConn
	client atomic.Pointer[string] // the client named ("ip:port"); "": no header at all
	key    []byte                 // signs the header when set
}

func newRelaySocket(t *testing.T, client string, key []byte) *relaySocket {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	r := &relaySocket{uc: uc, key: key}
	r.client.Store(&client)
	return r
}

func (r *relaySocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	client := *r.client.Load()
	out := p
	if client != "" {
		src, err := net.ResolveUDPAddr("udp", client)
		if err != nil {
			return 0, err
		}
		var b bytes.Buffer
		if err := proxy.WriteProxyHeaderV2(&b, src, addr); err != nil {
			return 0, err
		}
		hdr := b.Bytes()
		if r.key != nil {
			if hdr, err = proxy.SignedHeaderBytes(hdr, r.key, p, time.Now()); err != nil {
				return 0, err
			}
		}
		out = append(hdr, p...)
	}
	if _, err := r.uc.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (r *relaySocket) ReadFrom(p []byte) (int, net.Addr, error) { return r.uc.ReadFrom(p) }
func (r *relaySocket) Close() error                             { return r.uc.Close() }
func (r *relaySocket) LocalAddr() net.Addr                      { return r.uc.LocalAddr() }
func (r *relaySocket) SetDeadline(t time.Time) error            { return r.uc.SetDeadline(t) }
func (r *relaySocket) SetReadDeadline(t time.Time) error        { return r.uc.SetReadDeadline(t) }
func (r *relaySocket) SetWriteDeadline(t time.Time) error       { return r.uc.SetWriteDeadline(t) }

var h3RelayKey = []byte("0123456789abcdef0123456789abcdef-h3-relay")

// h3RelaySite is an HTTP/3 site that trusts relays in cidr, with backend
// be; its backend's answer is the X-Real-IP nvelox sent it.
func h3RelaySite(t *testing.T, pki *caPKI, cidr string, backend *config.Backend) *HTTPServer {
	t.Helper()
	if backend == nil {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "client="+r.Header.Get("X-Real-IP"))
		}))
		t.Cleanup(srv.Close)
		backend = &config.Backend{Servers: []string{strings.TrimPrefix(srv.URL, "http://")}}
	}
	l := &ListenerConfig{Name: "h3-relay-" + t.Name(), Addr: ":0", Protocol: "https", HTTP3: true,
		TLS:        &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey},
		ProxyTrust: proxy.NewTrust([]string{cidr}, [][]byte{h3RelayKey})}
	return fastTestSite(l, backend)
}

// h3Get makes one request over a QUIC connection opened through sock and
// returns the body, or the error that ended the attempt within d.
func h3Get(t *testing.T, sock net.PacketConn, addr string, tlsConf *tls.Config, d time.Duration) (string, *quic.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: sock}
	conn, err := tr.Dial(ctx, ua, tlsConf, nil)
	if err != nil {
		return "", nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	resp, err := (&http3.Transport{}).NewClientConn(conn).RoundTrip(req)
	if err != nil {
		conn.CloseWithError(0, "")
		return "", nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "status " + resp.Status + ": " + string(body), conn, nil
	}
	return string(body), conn, nil
}

func h3Refusals(name, reason string) uint64 {
	return metrics.Default.GetCounter("nvelox_proxy_header_rejected_total", map[string]string{"listener": name, "reason": reason}).Get()
}

// A request that comes through a trusted relay is its client's: the client
// the relay's signed header names is what the site and the backend see. A
// relay's datagram that is unsigned, carries no header, or names another
// client than its socket's is dropped and counted; QUIC never sees it.
func TestHTTP3_ThroughRelay(t *testing.T) { quicGoPath(t); throughRelay(t, quicGoServes) }

// quicGoServes and loopsServe check which of the two HTTP/3 servers a
// group started.
func quicGoServes(t *testing.T, g *BindGroup) {
	t.Helper()
	if g.http3Server == nil || g.h3Relay == nil {
		t.Fatal("the group's HTTP/3 is not the quic-go server with its relay layer")
	}
}

func loopsServe(t *testing.T, g *BindGroup) {
	t.Helper()
	if g.h3loops == nil {
		t.Fatal("the group's HTTP/3 is not on the event loops")
	}
}

// onLoops has the groups a test starts serve HTTP/3 from the event loops.
func onLoops(t *testing.T) {
	h3ServedBy(t, true)
}

func throughRelay(t *testing.T, served func(*testing.T, *BindGroup)) {
	quietLog(t)
	pki := newCAPKI(t, "h3-relay-ca")
	site := h3RelaySite(t, pki, "127.0.0.0/8", nil)
	name := site.Listener.Name
	addr := freeAddr(t)
	served(t, startGroup(t, addr, site))
	tlsConf := h3ClientTLS(pki)

	// Signed, naming a client.
	sock := newRelaySocket(t, "203.0.113.9:4321", h3RelayKey)
	body, conn, err := h3Get(t, sock, addr, tlsConf, 10*time.Second)
	if err != nil || body != "client=203.0.113.9" {
		t.Fatalf("through the relay: %q, %v; want client=203.0.113.9", body, err)
	}
	// The same socket naming another client: dropped from then on.
	before := h3Refusals(name, h3RelayClientChanged)
	other := "198.51.100.77:9"
	sock.client.Store(&other)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	if resp, err := (&http3.Transport{}).NewClientConn(conn).RoundTrip(req); err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Errorf("a relay socket that names another client was served: %q", b)
	}
	cancel()
	conn.CloseWithError(0, "")
	if h3Refusals(name, h3RelayClientChanged) == before {
		t.Errorf("no datagram was counted as naming another client")
	}
	// Nor does a new connection through that socket get anywhere under
	// the other name.
	before = h3Refusals(name, h3RelayClientChanged)
	if body, c, err := h3Get(t, sock, addr, tlsConf, 1500*time.Millisecond); err == nil {
		c.CloseWithError(0, "")
		t.Errorf("a new connection through a relay socket that names another client was served: %q", body)
	}
	if h3Refusals(name, h3RelayClientChanged) == before {
		t.Errorf("no datagram of the new connection was counted as naming another client")
	}

	for _, tc := range []struct {
		what   string
		client string
		key    []byte
		reason string
	}{
		{"an unsigned header", "203.0.113.9:4321", nil, proxy.RefusedSignature},
		{"a header signed with another key", "203.0.113.9:4321", []byte("another key, also long enough: 0123456789"), proxy.RefusedSignature},
		{"no header", "", nil, proxy.RefusedMissing},
	} {
		before := h3Refusals(name, tc.reason)
		if body, c, err := h3Get(t, newRelaySocket(t, tc.client, tc.key), addr, tlsConf, 1500*time.Millisecond); err == nil {
			c.CloseWithError(0, "")
			t.Errorf("%s: served: %q", tc.what, body)
		}
		if h3Refusals(name, tc.reason) == before {
			t.Errorf("%s: no datagram counted as %q", tc.what, tc.reason)
		}
	}
}

// A client that is no relay reaches QUIC as it is, on a socket that has
// the relay layer.
func TestHTTP3_DirectClientBesideRelays(t *testing.T) {
	quicGoPath(t)
	directClientBesideRelays(t, quicGoServes)
}

func directClientBesideRelays(t *testing.T, served func(*testing.T, *BindGroup)) {
	pki := newCAPKI(t, "h3-direct-ca")
	site := h3RelaySite(t, pki, "192.0.2.0/24", nil) // the tests' own address is no relay
	addr := freeAddr(t)
	served(t, startGroup(t, addr, site))
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	body, conn, err := h3Get(t, uc, addr, h3ClientTLS(pki), 10*time.Second)
	if err != nil || body != "client=127.0.0.1" {
		t.Fatalf("direct client: %q, %v; want client=127.0.0.1", body, err)
	}
	conn.CloseWithError(0, "")
}

// The relayed client is also the one a send_proxy_v2 backend is told.
func TestHTTP3_ThroughRelayToProxyBackend(t *testing.T) {
	quicGoPath(t)
	throughRelayToProxyBackend(t, quicGoServes)
}

func throughRelayToProxyBackend(t *testing.T, served func(*testing.T, *BindGroup)) {
	quietLog(t)
	pki := newCAPKI(t, "h3-relay-be-ca")
	be := newProxyBackend(t, nil, nil)
	site := h3RelaySite(t, pki, "127.0.0.0/8", &config.Backend{Servers: []string{be.addr()}, SendProxyV2: true})
	addr := freeAddr(t)
	served(t, startGroup(t, addr, site))
	body, conn, err := h3Get(t, newRelaySocket(t, "203.0.113.9:4321", h3RelayKey), addr, h3ClientTLS(pki), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if got := parseProxyAnswer(t, body); got.src != "203.0.113.9:4321" {
		t.Errorf("the backend was told %s, want 203.0.113.9:4321", got.src)
	}
	be.noneRefused()
}

// The pins: one client per relay socket until its pin expires, a bounded
// table, and a lookup that forgets with it.
func TestH3RelayPins(t *testing.T) {
	tr := proxy.NewTrust([]string{"192.0.2.0/24"}, [][]byte{h3RelayKey})
	c := newH3RelayConn(nil, nil)
	dst := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	datagram := func(client string) []byte {
		src, err := net.ResolveUDPAddr("udp", client)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := proxy.WriteProxyHeaderV2(&b, src, dst); err != nil {
			t.Fatal(err)
		}
		payload := []byte("a QUIC packet")
		hdr, err := proxy.SignedHeaderBytes(b.Bytes(), h3RelayKey, payload, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return append(hdr, payload...)
	}
	relay := netip.MustParseAddrPort("192.0.2.10:7000")
	age := func(k netip.AddrPort) {
		c.mu.Lock()
		p := c.pins[k]
		p.seen -= int64(h3RelayPinTTL) + 1
		c.pins[k] = p
		c.mu.Unlock()
	}

	payload, reason, _ := c.relayed(tr, relay, datagram("203.0.113.9:4321"))
	if reason != "" || string(payload) != "a QUIC packet" {
		t.Fatalf("first datagram: %q, reason %q", payload, reason)
	}
	if got, ok := c.client(relay); !ok || got.String() != "203.0.113.9:4321" {
		t.Fatalf("pinned client %v, %v", got, ok)
	}
	if _, reason, _ := c.relayed(tr, relay, datagram("198.51.100.1:5")); reason != h3RelayClientChanged {
		t.Errorf("another client on the same relay socket: reason %q, want %q", reason, h3RelayClientChanged)
	}
	if _, reason, _ := c.relayed(tr, relay, datagram("203.0.113.9:4321")); reason != "" {
		t.Errorf("the pinned client again: reason %q", reason)
	}
	// Once the pin has expired the socket may serve another client, and
	// until a datagram comes the relay's connections name nobody.
	age(relay)
	if _, ok := c.client(relay); ok {
		t.Errorf("an expired pin still names a client")
	}
	if _, reason, _ := c.relayed(tr, relay, datagram("198.51.100.1:5")); reason != "" {
		t.Errorf("another client after the pin expired: reason %q", reason)
	}

	// A full table drops the datagrams of sockets it does not know, and
	// keeps serving the ones it knows; expired entries make room.
	c.mu.Lock()
	now := time.Now().UnixNano()
	for i := 0; len(c.pins) < h3RelayPinsMax; i++ {
		k := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(20 + i>>16)}), uint16(i))
		c.pins[k] = h3Pin{client: netip.MustParseAddrPort("203.0.113.1:1"), seen: now}
	}
	c.swept = now
	c.mu.Unlock()
	fresh := netip.MustParseAddrPort("192.0.2.11:7001")
	if _, reason, _ := c.relayed(tr, fresh, datagram("203.0.113.9:4321")); reason != h3RelayTableFull {
		t.Errorf("a new relay socket with the table full: reason %q, want %q", reason, h3RelayTableFull)
	}
	if _, reason, _ := c.relayed(tr, relay, datagram("198.51.100.1:5")); reason != "" {
		t.Errorf("a known relay socket with the table full: reason %q", reason)
	}
	c.mu.Lock()
	for k, p := range c.pins {
		if k != relay {
			p.seen -= int64(h3RelayPinTTL) + 1
			c.pins[k] = p
		}
	}
	c.mu.Unlock()
	if _, reason, _ := c.relayed(tr, fresh, datagram("203.0.113.9:4321")); reason != "" {
		t.Errorf("a new relay socket once the old pins expired: reason %q", reason)
	}
	c.mu.Lock()
	n := len(c.pins)
	c.mu.Unlock()
	if n != 2 {
		t.Errorf("%d pins left after the sweep, want 2", n)
	}

	// Without keys nothing a relay sends is taken.
	if _, reason, _ := c.relayed(proxy.NewTrust([]string{"192.0.2.0/24"}, nil), fresh, datagram("203.0.113.9:4321")); reason != proxy.RefusedSignature {
		t.Errorf("trust without keys: reason %q, want %q", reason, proxy.RefusedSignature)
	}
}

// The same through the event loops: a relayed client's requests are its
// own, what a relay's socket sends without a good header is dropped and
// counted, a direct client is served beside the relays, and a
// send_proxy_v2 backend is told the relayed client.
func TestH3Loops_ThroughRelay(t *testing.T) {
	onLoops(t)
	throughRelay(t, loopsServe)
}

func TestH3Loops_DirectClientBesideRelays(t *testing.T) {
	onLoops(t)
	directClientBesideRelays(t, loopsServe)
}

func TestH3Loops_ThroughRelayToProxyBackend(t *testing.T) {
	onLoops(t)
	throughRelayToProxyBackend(t, loopsServe)
}

// The relays a listener trusts are asked for at each datagram, so a reload
// that names them, or names them no more, holds for HTTP/3 from the next
// datagram on, as it does for HTTP/1.1 and HTTP/2. (The quic-go server
// puts its relay layer in when it starts: there a reload's relays wait for
// the restart, and a warning says so.)
func TestH3Loops_RelaysFollowAReload(t *testing.T) {
	onLoops(t)
	quietLog(t)
	pki := newCAPKI(t, "h3-relay-ca")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "client="+r.Header.Get("X-Real-IP"))
	}))
	t.Cleanup(srv.Close)
	name := "h3-relay-" + t.Name()
	site := func(trust *proxy.Trust) *HTTPServer {
		l := &ListenerConfig{Name: name, Addr: ":0", Protocol: "https", HTTP3: true,
			TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}, ProxyTrust: trust}
		return fastTestSite(l, &config.Backend{Servers: []string{strings.TrimPrefix(srv.URL, "http://")}})
	}
	relays := func() *proxy.Trust { return proxy.NewTrust([]string{"127.0.0.0/8"}, [][]byte{h3RelayKey}) }
	addr := freeAddr(t)
	g := startGroup(t, addr, site(nil))
	loopsServe(t, g)
	tlsConf := h3ClientTLS(pki)
	// get asks through a socket that puts a header naming client in front
	// of its datagrams (none for ""), and wants the answer want, or none.
	get := func(what, client, want string) {
		t.Helper()
		d := 10 * time.Second
		if want == "" {
			d = 1500 * time.Millisecond
		}
		body, conn, err := h3Get(t, newRelaySocket(t, client, h3RelayKey), addr, tlsConf, d)
		if conn != nil {
			conn.CloseWithError(0, "")
		}
		switch {
		case want == "" && err == nil:
			t.Errorf("%s: served: %q", what, body)
		case want != "" && (err != nil || body != want):
			t.Errorf("%s: %q, %v; want %s", what, body, err, want)
		}
	}
	// No relays: the address is a client's, and a header in front of a
	// datagram makes it no packet at all.
	get("no relays, a client", "", "client=127.0.0.1")
	get("no relays, a datagram with a relay's header", "203.0.113.9:4321", "")

	// A reload names the relays.
	if err := g.ReplaceSites([]*HTTPServer{site(relays())}); err != nil {
		t.Fatal(err)
	}
	get("relays named by a reload, through one", "203.0.113.9:4321", "client=203.0.113.9")
	before := h3Refusals(name, proxy.RefusedMissing)
	get("relays named by a reload, a relay's address without a header", "", "")
	if h3Refusals(name, proxy.RefusedMissing) == before {
		t.Errorf("relays named by a reload: no datagram without a header was counted as %q", proxy.RefusedMissing)
	}

	// A reload takes them away again.
	if err := g.ReplaceSites([]*HTTPServer{site(nil)}); err != nil {
		t.Fatal(err)
	}
	get("relays taken away by a reload, a client", "", "client=127.0.0.1")
	get("relays taken away by a reload, a datagram with a relay's header", "203.0.113.9:4321", "")
}

// A request that net/http's handlers serve is its client's too, on the
// loops, and also when the client's own address is one the listener would
// trust as a relay's: the client was named by a relay, it is not asked for
// again.
func TestH3Loops_RelayedClientForTheHandlers(t *testing.T) {
	onLoops(t)
	quietLog(t)
	pki := newCAPKI(t, "h3-relay-ca")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "client="+r.Header.Get("X-Real-IP"))
	}))
	t.Cleanup(srv.Close)
	l := &ListenerConfig{Name: "h3-relay-" + t.Name(), Addr: ":0", Protocol: "https", HTTP3: true,
		TLS:        &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey},
		ProxyTrust: proxy.NewTrust([]string{"127.0.0.0/8"}, [][]byte{h3RelayKey})}
	l.Compression.Enabled = true // its requests go to the handlers
	site := fastTestSite(l, &config.Backend{Servers: []string{strings.TrimPrefix(srv.URL, "http://")}})
	addr := freeAddr(t)
	loopsServe(t, startGroup(t, addr, site))
	for _, client := range []string{"203.0.113.9:4321", "127.0.0.77:5"} {
		body, conn, err := h3Get(t, newRelaySocket(t, client, h3RelayKey), addr, h3ClientTLS(pki), 10*time.Second)
		want, _, _ := net.SplitHostPort(client)
		if err != nil || body != "client="+want {
			t.Errorf("a client at %s through the relay, served by the handlers: %q, %v; want client=%s", client, body, err, want)
		}
		if conn != nil {
			conn.CloseWithError(0, "")
		}
	}
}

// A relay's socket stands for one client. When its pin has run out it may
// stand for another, but a connection that began as the first client's
// stays that client's: the datagrams that name the other one are dropped
// and counted, not taken for the connection.
func TestH3Loops_RelaySocketChangesItsClient(t *testing.T) {
	onLoops(t)
	quietLog(t)
	pki := newCAPKI(t, "h3-relay-ca")
	site := h3RelaySite(t, pki, "127.0.0.0/8", nil)
	name := site.Listener.Name
	addr := freeAddr(t)
	g := startGroup(t, addr, site)
	loopsServe(t, g)
	sock := newRelaySocket(t, "203.0.113.9:4321", h3RelayKey)
	body, conn, err := h3Get(t, sock, addr, h3ClientTLS(pki), 10*time.Second)
	if err != nil || body != "client=203.0.113.9" {
		t.Fatalf("through the relay: %q, %v", body, err)
	}
	defer conn.CloseWithError(0, "")
	// The socket names another client from here on; then its pin runs out
	// (as after a minute without a datagram that was taken), so that the
	// table lets the new name through.
	other := "198.51.100.77:9"
	sock.client.Store(&other)
	done := make(chan struct{}, len(g.h3loops.socks))
	for _, s := range g.h3loops.socks {
		s.l.Post(func() {
			for k, p := range s.relays.pins {
				p.seen -= int64(h3RelayPinTTL) + 1
				s.relays.pins[k] = p
			}
			done <- struct{}{}
		})
	}
	for range g.h3loops.socks {
		<-done
	}
	before := h3Refusals(name, h3RelayClientChanged)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	if resp, err := (&http3.Transport{}).NewClientConn(conn).RoundTrip(req); err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Errorf("the first client's connection served a request the relay sent for another client: %q", b)
	}
	if h3Refusals(name, h3RelayClientChanged) == before {
		t.Errorf("no datagram was counted as naming another client")
	}
}

// twoRelaySockets is a client's socket behind a relay that takes the
// client's datagrams to the server through one relay socket, and from a
// given moment through another: the client's address changed, and the
// relay opened a socket for the new one. What the server sends to either
// reaches the client.
type twoRelaySockets struct {
	*relaySocket
	next  *relaySocket
	moved atomic.Bool
	in    chan rovingDatagram
	by    atomic.Pointer[time.Time]
	kick  chan struct{}
}

func newTwoRelaySockets(t *testing.T, first, second string) *twoRelaySockets {
	r := &twoRelaySockets{relaySocket: newRelaySocket(t, first, h3RelayKey), next: newRelaySocket(t, second, h3RelayKey),
		in: make(chan rovingDatagram, 1024), kick: make(chan struct{}, 1)}
	for _, s := range []*relaySocket{r.relaySocket, r.next} {
		go func() {
			buf := make([]byte, 4096)
			for {
				n, from, err := s.uc.ReadFrom(buf)
				if err != nil {
					return
				}
				select {
				case r.in <- rovingDatagram{append([]byte(nil), buf[:n]...), from}:
				default:
				}
			}
		}()
	}
	return r
}

func (r *twoRelaySockets) WriteTo(p []byte, a net.Addr) (int, error) {
	if r.moved.Load() {
		return r.next.WriteTo(p, a)
	}
	return r.relaySocket.WriteTo(p, a)
}

func (r *twoRelaySockets) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		var timeout <-chan time.Time
		if by := r.by.Load(); by != nil && !by.IsZero() {
			t := time.NewTimer(time.Until(*by))
			defer t.Stop()
			timeout = t.C
		}
		select {
		case d := <-r.in:
			return copy(p, d.b), d.from, nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-r.kick:
		}
	}
}

func (r *twoRelaySockets) SetReadDeadline(t time.Time) error {
	r.by.Store(&t)
	select {
	case r.kick <- struct{}{}:
	default:
	}
	return nil
}

func (r *twoRelaySockets) SetDeadline(t time.Time) error { return r.SetReadDeadline(t) }

// A relayed client moves: its address changes, and the relay sends its
// datagrams from another socket, under the new address. The connection
// follows to that socket once the client has answered a challenge sent
// through it, and the requests that begin then are the new address's.
func TestH3Loops_RelayedClientMoves(t *testing.T) {
	onLoops(t)
	quietLog(t)
	pki := newCAPKI(t, "h3-relay-ca")
	site := h3RelaySite(t, pki, "127.0.0.0/8", nil)
	addr := freeAddr(t)
	g := startGroup(t, addr, site)
	loopsServe(t, g)
	sock := newTwoRelaySockets(t, "203.0.113.9:4321", "198.51.100.77:9")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ua, _ := net.ResolveUDPAddr("udp", addr)
	conn, err := quic.Dial(ctx, sock, ua, h3ClientTLS(pki), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	cc := (&http3.Transport{}).NewClientConn(conn)
	get := func(what string) string {
		t.Helper()
		r, err := h3Do(ctx, cc, "GET", "https://"+addr+"/", nil)
		if err != nil || r.status != 200 {
			t.Fatalf("%s: %v, %+v", what, err, r)
		}
		return string(r.body)
	}
	if body := get("before the move"); body != "client=203.0.113.9" {
		t.Fatalf("before the move: %q", body)
	}
	sock.moved.Store(true)
	get("the request that brings the news")
	waitCount(t, "moves of the connection", g.h3loops.moves.Load, 1)
	if body := get("after the move"); body != "client=198.51.100.77" {
		t.Errorf("after the move: %q, want client=198.51.100.77", body)
	}
}
