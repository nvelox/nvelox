//go:build linux

package httpproxy

import (
	"net"
	"time"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"
)

// ownConns are the idle connections of one client connection on the event
// loops to send_proxy_v2 backends (proxysend.go), the most recently used
// first. Such a connection began with this client's PROXY header: it waits
// here, never in the loop's pools, and is closed with the client's
// connection.
//
// How many are kept follows the client connection's own load, by the rule
// of the loops' pools (fast_linux.go): as many as it had in use at the
// same time in the last seconds, and never fewer than ownConnsMin. A
// client with one request at a time keeps a connection to each of the few
// servers it last used; one with many requests at once (HTTP/2) keeps what
// they used, so that a steady load, or the next burst, opens none.
//
// Unlike a pool, which every client's requests return connections to, a
// client connection may go quiet after a burst. Its list is therefore
// looked at when a period ends (trim): what the last seconds no longer
// account for is closed then, not when it has been idle for upIdleTimeout.
// Each client connection holding the backend connections of its largest
// burst for that long would cost a backend far more connections than the
// requests it serves.
type ownConns struct {
	idle   []*uconn
	few    [ownConnsMin]*uconn // idle's first backing array: most clients need no other
	closed bool
	usePeak
	// trim fires at the end of a period while more connections are idle
	// than ownConnsMin. l is its loop, set with the first idle connection.
	trim ngx.Timer
	l    *ngx.Loop

	// What the header names, asked from the client's connection on first
	// use, and the unsigned header (the same for each of its connections).
	asked    bool
	src, dst net.Addr
	hdr      []byte
}

// header returns the PROXY header of a new connection for the client of d,
// signed with key when there is one.
func (o *ownConns) header(d downstream, key []byte) ([]byte, error) {
	if !o.asked {
		o.asked = true
		o.src, o.dst = d.addrs()
	}
	if len(key) > 0 {
		return backendProxyHeader(o.src, o.dst, key, time.Now())
	}
	if o.hdr == nil {
		hdr, err := backendProxyHeader(o.src, o.dst, nil, time.Time{})
		if err != nil {
			return nil, err
		}
		o.hdr = hdr
	}
	return o.hdr, nil
}

// clientMoved: the client is at another address now. The header of the
// connections opened from here on names it; those already open stay as
// they are.
func (o *ownConns) clientMoved() {
	o.asked, o.src, o.dst, o.hdr = false, nil, nil, nil
}

// take returns an idle connection of the client's to the server of k, the
// one used most recently; nil when it has none.
func (o *ownConns) take(k poolKey) *uconn {
	for i, u := range o.idle {
		if u.pool == k {
			o.removeAt(i)
			u.reused = true
			u.fl.l.Stop(&u.timer)
			return u
		}
	}
	return nil
}

func (o *ownConns) removeAt(i int) {
	n := len(o.idle) - 1
	copy(o.idle[i:], o.idle[i+1:])
	o.idle[n] = nil
	o.idle = o.idle[:n]
}

// put keeps u, whose response is complete, for the client's next requests
// to its server. When that makes more idle connections than are kept, the
// ones unused the longest go.
func (o *ownConns) put(u *uconn, now int64) {
	if o.closed {
		u.close()
		return
	}
	o.shrink(o.keep(now, ownConnsMin) - 1)
	if o.idle == nil {
		o.idle = o.few[:0]
	}
	o.idle = append(o.idle, nil)
	copy(o.idle[1:], o.idle)
	o.idle[0] = u
	u.state = usIdle
	u.x = nil
	u.paused = false
	u.fl.l.Arm(&u.timer, upIdleTimeout)
	if len(o.idle) > ownConnsMin && !o.trim.Armed() {
		o.l, o.trim.F = u.fl.l, o
		o.armTrim(now)
	}
	if u.readable {
		u.OnEvent(ngx.EvIn) // something arrived meanwhile: check it
	}
}

// shrink closes the idle connections unused the longest until n are left.
func (o *ownConns) shrink(n int) {
	for len(o.idle) > max(n, 0) {
		old := o.idle[len(o.idle)-1]
		o.removeAt(len(o.idle) - 1)
		old.close()
	}
}

// armTrim sets the trim timer to the end of the current period.
func (o *ownConns) armTrim(now int64) {
	o.l.ArmAt(&o.trim, (now/poolPeakPeriod+1)*poolPeakPeriod)
}

// OnTimer: a period has ended. The idle connections above what is kept now
// are closed; while more than ownConnsMin stay, the next period's end is
// looked at too.
func (o *ownConns) OnTimer() {
	defer func() {
		if r := recover(); r != nil {
			logLoopPanic("a client's backend connections", r)
		}
	}()
	if o.closed {
		return
	}
	now := o.l.Now()
	o.shrink(o.keep(now, ownConnsMin))
	if len(o.idle) > ownConnsMin {
		o.armTrim(now)
	}
}

// remove takes u out of the idle ones (it is being closed).
func (o *ownConns) remove(u *uconn) {
	for i := range o.idle {
		if o.idle[i] == u {
			o.removeAt(i)
			return
		}
	}
}

// closeAll closes the idle connections: the client's connection is gone.
func (o *ownConns) closeAll() {
	o.closed = true
	if o.l != nil {
		o.l.Stop(&o.trim)
	}
	o.shrink(0)
}

// addrs: the client's address and the one it connected to, for an HTTP/1.1
// connection.
func (c *fconn) addrs() (client, local net.Addr) {
	if t := c.tls; t != nil {
		// Kept from the handshake: the client is the one a trusted relay
		// named, when one did.
		return t.tt.remote, t.tt.local
	}
	if c.proxyClient != nil {
		client = c.proxyClient
	} else if sa, err := unix.Getpeername(c.fd); err == nil {
		client = sockaddrTCPAddr(sa)
	}
	if sa, err := unix.Getsockname(c.fd); err == nil {
		local = sockaddrTCPAddr(sa)
	}
	return client, local
}

// addrs: the same for a stream's HTTP/2 connection.
func (s *h2stream) addrs() (client, local net.Addr) {
	if c := s.c; c != nil && c.tls != nil {
		return c.tls.tt.remote, c.tls.tt.local
	}
	return nil, nil
}

// sockaddrTCPAddr returns a socket address as a *net.TCPAddr, an IPv4 one
// in its 4-byte form; a nil net.Addr for any other family.
func sockaddrTCPAddr(sa unix.Sockaddr) net.Addr {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return &net.TCPAddr{IP: net.IP(append([]byte(nil), a.Addr[:]...)), Port: a.Port}
	case *unix.SockaddrInet6:
		ip := net.IP(append([]byte(nil), a.Addr[:]...))
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return &net.TCPAddr{IP: ip, Port: a.Port}
	}
	return nil
}
