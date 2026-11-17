package httpproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"nvelox/config"
	"nvelox/proxy"

	"github.com/pires/go-proxyproto"
)

// PROXY protocol v2 to HTTP backends (send_proxy_v2).
//
// A backend with send_proxy_v2 is told who the client is by a PROXY
// protocol v2 header at the start of every connection nvelox opens to it.
// The header names one client, and the protocol does not let a connection
// that carried one client's header carry another client's request: such a
// backend's connections belong to one client connection each. They are
// opened for it, kept idle for it and closed with it. How many idle ones a
// client connection keeps: on the event loops as many as it had in use at
// the same time in the last seconds, and never fewer than ownConnsMin
// (proxysend_linux.go); on net/http ownConnsMin, a fixed number, for each
// backend it uses.
//
// The header's source is the client of the connection: the socket's peer,
// or the client a trusted relay named; an HTTP/3 client's UDP address,
// written as a TCP one, since the backend's connection is a stream. Its
// destination is the address the client connected to. With
// send_proxy_key_file the header is signed when the connection is opened.
// It goes out before anything else: before the TLS handshake of a
// backend_tls backend.

// ownConnsMin is how many idle backend connections a client connection
// keeps whatever its load: enough for the few servers its requests took
// turns on, or for a few requests at once.
const ownConnsMin = 4

// errProxyAddr: the client's connection has no address a header can name.
var errProxyAddr = errors.New("proxy protocol: the client's connection has no TCP or UDP address to name")

// sendsProxy reports whether connections to be get a PROXY header.
func sendsProxy(be *config.Backend) bool { return be != nil && be.SendProxyV2 }

// backendProxyHeader returns the header of a connection opened for the
// client at src, which connected to dst, signed with key when there is one.
func backendProxyHeader(src, dst net.Addr, key []byte, now time.Time) ([]byte, error) {
	s, d := streamAddr(src), streamAddr(dst)
	if s == nil || d == nil {
		return nil, errProxyAddr
	}
	// A QUIC socket bound to all interfaces reports the unspecified
	// address as its own: written as the zero address of the client's
	// family, as the UDP listeners write it.
	if d.IP.IsUnspecified() && !s.IP.IsUnspecified() {
		zero := net.IPv6unspecified
		if s.IP.To4() != nil {
			zero = net.IPv4zero
		}
		d = &net.TCPAddr{IP: zero, Port: d.Port}
	}
	h := &proxyproto.Header{Version: 2, Command: proxyproto.PROXY, SourceAddr: s, DestinationAddr: d}
	// Two IPv4 addresses are written as such; anything else as IPv6, an
	// IPv4 one among them in its mapped form (a relay may name an IPv4
	// client over an IPv6 connection).
	if s.IP.To4() != nil && d.IP.To4() != nil {
		h.TransportProtocol = proxyproto.TCPv4
	} else {
		h.TransportProtocol = proxyproto.TCPv6
	}
	if len(key) > 0 {
		if err := proxy.SignHeader(h, key, now); err != nil {
			return nil, err
		}
	}
	return h.Format()
}

// streamAddr returns a as a TCP address (a QUIC client's is a UDP one), nil
// when it is neither.
func streamAddr(a net.Addr) *net.TCPAddr {
	switch a := a.(type) {
	case *net.TCPAddr:
		if a == nil || a.IP == nil {
			return nil
		}
		return a
	case *net.UDPAddr:
		if a == nil || a.IP == nil {
			return nil
		}
		return &net.TCPAddr{IP: a.IP, Port: a.Port, Zone: a.Zone}
	}
	return nil
}

// ---- the net/http path ----

// clientBackends holds, for one client connection served by net/http (or by
// the HTTP/3 server, or a request an HTTP/2 connection on the event loops
// hands to net/http's handlers), the transports of its requests to
// send_proxy_v2 backends: one per site and backend, made on first use,
// whose connections start with this client's header. They are closed with
// the connection.
type clientBackends struct {
	// conn is the client's connection when net/http accepted it: its
	// addresses are asked on first use, in the goroutine that serves it (a
	// trusted relay's connection reads its PROXY header to answer, which
	// must not happen where connections are accepted). src and dst are set
	// directly otherwise.
	conn     net.Conn
	src, dst net.Addr
	// live, when set, gives the addresses as they are now (a QUIC client
	// may move to another address: connections opened after that name the
	// new one).
	live func() (src, dst net.Addr)
	// g is set for a connection net/http accepted: when its first
	// transport is made it is listed in the group, whose connState closes
	// it with the connection.
	g *BindGroup

	mu     sync.Mutex
	ts     map[clientBackendKey]*clientTransport
	uses   uint64 // counts the requests that asked for a transport
	closed bool
}

type clientBackendKey struct {
	site    *HTTPServer
	backend string
}

type clientTransport struct {
	t    *http.Transport
	used uint64 // cb.uses when a request last took it
}

// clientTransportsMax bounds the transports one client connection holds. A
// connection that outlives reloads would otherwise keep one per site
// instance it ever used; past the bound the one unused the longest is let
// go of (its idle connections are closed, a request still on it finishes).
const clientTransportsMax = 8

type clientBackendsKey struct{}

// withClientBackends returns ctx carrying cb, the backends of the client
// connection the requests under ctx come in on.
func withClientBackends(ctx context.Context, cb *clientBackends) context.Context {
	return context.WithValue(ctx, clientBackendsKey{}, cb)
}

// clientBackendsOf returns the backends of the connection a request came in
// on, nil when the server that accepted it attached none.
func clientBackendsOf(ctx context.Context) *clientBackends {
	cb, _ := ctx.Value(clientBackendsKey{}).(*clientBackends)
	return cb
}

// errNoProxyClient: a request to a send_proxy_v2 backend came in on a
// connection nvelox has no record of (or one already closed).
var errNoProxyClient = errors.New("proxy protocol: no client connection to name to the backend")

// transport returns the connection's transport to backend name of site s:
// base's settings, with a dial that sends the header first. Nil when there
// is no connection (a nil cb) or it is closed. ctx is the request's.
func (cb *clientBackends) transport(ctx context.Context, s *HTTPServer, name string, base *http.Transport, key []byte) *http.Transport {
	if cb == nil {
		return nil
	}
	cb.mu.Lock()
	if cb.closed {
		cb.mu.Unlock()
		return nil
	}
	cb.uses++
	k := clientBackendKey{site: s, backend: name}
	if ct := cb.ts[k]; ct != nil {
		ct.used = cb.uses
		cb.mu.Unlock()
		return ct.t
	}
	first := cb.ts == nil
	if first {
		cb.ts = make(map[clientBackendKey]*clientTransport)
		if cb.conn != nil {
			cb.src, cb.dst = cb.conn.RemoteAddr(), cb.conn.LocalAddr()
		}
	}
	var dropped *http.Transport
	if len(cb.ts) >= clientTransportsMax {
		var oldest clientBackendKey
		var at uint64
		for ok, ct := range cb.ts {
			if dropped == nil || ct.used < at {
				oldest, at, dropped = ok, ct.used, ct.t
			}
		}
		delete(cb.ts, oldest)
	}
	// base's settings, but for the idle connections: this client's few,
	// the ones unused the longest closed first.
	t := base.Clone()
	t.MaxIdleConns = ownConnsMin
	t.MaxIdleConnsPerHost = ownConnsMin
	dial := base.DialContext
	src, dst, live := cb.src, cb.dst, cb.live
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		src, dst := src, dst
		if live != nil {
			src, dst = live()
		}
		if err := writeBackendProxyHeader(ctx, c, src, dst, key); err != nil {
			c.Close()
			return nil, &net.OpError{Op: "dial", Net: network, Addr: c.RemoteAddr(), Err: err}
		}
		return c, nil
	}
	cb.ts[k] = &clientTransport{t: t, used: cb.uses}
	cb.mu.Unlock()
	if dropped != nil {
		dropped.CloseIdleConnections()
	}
	if first && cb.g != nil {
		cb.g.clientBackends.Store(cb.conn, cb)
		// The connection may have ended before it was listed (a handler
		// can outlive its HTTP/2 connection). net/http cancels the context
		// of a connection's requests before it reports the close, so a
		// context that is still live here means the close is still to come
		// and will find the entry; a cancelled one may mean it has passed.
		if ctx.Err() != nil {
			cb.g.clientBackends.Delete(cb.conn)
			cb.close()
			return nil
		}
	}
	return t
}

// close closes the connection's idle backend connections; the ones still
// answering a request end with that request.
func (cb *clientBackends) close() {
	cb.mu.Lock()
	ts := cb.ts
	cb.ts, cb.closed = nil, true
	cb.mu.Unlock()
	for _, ct := range ts {
		ct.t.CloseIdleConnections()
	}
}

// closeFromLoop is close for a caller that must not wait (an event loop):
// the idle connections are closed on a goroutine, when there are any.
func (cb *clientBackends) closeFromLoop() {
	cb.mu.Lock()
	ts := cb.ts
	cb.ts, cb.closed = nil, true
	cb.mu.Unlock()
	if len(ts) > 0 {
		go func() {
			for _, ct := range ts {
				ct.t.CloseIdleConnections()
			}
		}()
	}
}

// connContext is net/http's ConnContext for the group's server: every
// connection gets its (still empty) backends.
func (g *BindGroup) connContext(ctx context.Context, c net.Conn) context.Context {
	return withClientBackends(ctx, &clientBackends{conn: c, g: g})
}

// connState is net/http's ConnState for the group's server: a connection
// that ends (or is taken over for a WebSocket: no request follows on it)
// closes its idle backend connections.
func (g *BindGroup) connState(c net.Conn, st http.ConnState) {
	if st != http.StateClosed && st != http.StateHijacked {
		return
	}
	if v, ok := g.clientBackends.LoadAndDelete(c); ok {
		v.(*clientBackends).close()
	}
}

// proxyHeaderWriteTimeout bounds the write of a header on a connection that
// was just opened (the dial's own context may carry no deadline).
const proxyHeaderWriteTimeout = 10 * time.Second

// writeBackendProxyHeader writes the header for the client at src (which
// connected to dst) on c, a connection just opened to a backend.
func writeBackendProxyHeader(ctx context.Context, c net.Conn, src, dst net.Addr, key []byte) error {
	hdr, err := backendProxyHeader(src, dst, key, time.Now())
	if err != nil {
		return err
	}
	deadline := time.Now().Add(proxyHeaderWriteTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetWriteDeadline(deadline)
	_, err = c.Write(hdr)
	c.SetWriteDeadline(time.Time{})
	return err
}
