package httpproxy

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/core/logging"
	"nvelox/core/metrics"
	"nvelox/proxy"
)

// PROXY protocol v2 on the HTTP listeners (accept_proxy_from). A connection
// from a trusted relay starts with a header that names the real client; it
// is read once, before any byte of TLS or HTTP, and the client it names
// becomes the connection's peer for everything that looks at the peer:
// the IP lists, the dynamic denylist, the rate limits, the ACL, the access
// log, X-Forwarded-For and trusted_proxies. A relay must send the header on
// every connection (a LOCAL header for its own traffic, such as health
// checks): a connection without one, or with one that does not parse or
// verify, is closed. Connections from anyone else are not looked at: a
// header from them is plain garbage, as before.
//
// The header is read where the client's bytes enter: on the event loop for
// plain HTTP and in the handshake goroutine for HTTPS (the server of the
// event loops asks fastHost, its Relays), and by proxyListener when
// net/http accepts.

// proxyTrust returns the group's accept_proxy_from trust (nil: none). The
// sites of one bind address share one relay list and key file (checked when
// the configuration is loaded): the header arrives before the site is known.
func (g *BindGroup) proxyTrust() *proxy.Trust {
	ss := g.sites.Load()
	if ss == nil || len(ss.all) == 0 || ss.all[0].Listener == nil {
		return nil
	}
	return ss.all[0].Listener.ProxyTrust
}

// Why a relay's connection is closed (proxy.Trust.StreamClient); all but
// "nothing sent" are refusals, counted in
// nvelox_proxy_header_rejected_total{listener,reason}.
const (
	proxyRejectMissing   = proxy.RefusedMissing
	proxyRejectMalformed = proxy.RefusedMalformed
	proxyRejectSignature = proxy.RefusedSignature
	proxyRejectTimeout   = proxy.RefusedTimeout
	proxyNothingSent     = proxy.NothingSent
)

// proxyClient turns what a trusted relay sent (the result of reading its
// header) into the client's address: nil with no reason for a LOCAL header
// (the relay itself is the client), nil with a reason when the connection
// is to be closed (proxyRejected counts it, but for proxyNothingSent);
// cause is the error behind the reason, for the log.
func proxyClient(tr *proxy.Trust, hdr *proxyproto.Header, err error, relayPort uint16) (client *net.TCPAddr, reason string, cause error) {
	return tr.StreamClient(hdr, err, relayPort)
}

// tcpPort is the port of a TCP address; 0 for any other.
func tcpPort(a net.Addr) uint16 {
	if ta, ok := a.(*net.TCPAddr); ok {
		return uint16(ta.Port)
	}
	return 0
}

// proxyRejected counts a relay's connection that is refused, and logs it
// with the error behind the reason when there is one (at most one line a
// second per bind address). A relay that sent nothing is not counted.
func (g *BindGroup) proxyRejected(relay net.Addr, reason string, cause error) {
	if reason == proxyNothingSent {
		return
	}
	name := g.addr
	if ss := g.sites.Load(); ss != nil && len(ss.all) > 0 && ss.all[0].Listener != nil {
		name = ss.all[0].Listener.Name
	}
	metrics.Default.GetCounter("nvelox_proxy_header_rejected_total", map[string]string{"listener": name, "reason": reason}).Inc()
	now := time.Now().UnixNano()
	if last := g.proxyWarned.Load(); now-last >= int64(time.Second) && g.proxyWarned.CompareAndSwap(last, now) {
		if cause != nil {
			logging.Warn("[HTTP] %s: connection from relay %v refused (%s): %v", name, relay, reason, cause)
		} else {
			logging.Warn("[HTTP] %s: connection from relay %v refused: PROXY header %s", name, relay, reason)
		}
	}
}

// proxyListener is the group's listener for net/http: a trusted relay's
// connection reads its PROXY header on first use, in the goroutine net/http
// serves it in (never in Accept, where one slow relay would hold up the
// rest).
type proxyListener struct {
	net.Listener
	g       *BindGroup
	timeout time.Duration // for the header (the read-header limit)
}

func (l *proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tr := l.g.proxyTrust(); tr.Trusts(c.RemoteAddr()) {
		return &proxyHdrConn{Conn: c, g: l.g, trust: tr, timeout: l.timeout}, nil
	}
	return c, nil
}

// proxyHdrConn is a trusted relay's connection whose PROXY header is read
// by the first Read or RemoteAddr (net/http asks for the address before it
// reads).
type proxyHdrConn struct {
	net.Conn
	g       *BindGroup
	trust   *proxy.Trust
	timeout time.Duration
	once    sync.Once
	client  net.Addr // the client the header names; nil: the relay itself
	err     error
}

func (c *proxyHdrConn) header() {
	c.once.Do(func() {
		if c.timeout > 0 {
			c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
		}
		hdr, err := proxy.ReadStreamHeader(c.Conn)
		client, reason, cause := proxyClient(c.trust, hdr, err, tcpPort(c.Conn.RemoteAddr()))
		if reason != "" {
			c.g.proxyRejected(c.Conn.RemoteAddr(), reason, cause)
			c.err = errors.New("proxy protocol: connection refused (" + reason + ")")
			c.Conn.Close()
			return
		}
		c.Conn.SetReadDeadline(time.Time{})
		if client != nil {
			c.client = client
		}
	})
}

func (c *proxyHdrConn) Read(p []byte) (int, error) {
	c.header()
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

func (c *proxyHdrConn) RemoteAddr() net.Addr {
	c.header()
	if c.client != nil {
		return c.client
	}
	return c.Conn.RemoteAddr()
}

// CloseWrite lets net/http half-close the connection before closing it.
func (c *proxyHdrConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
