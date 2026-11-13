package core

import (
	"net"
	"sync/atomic"

	"nvelox/core/denylist"
	"nvelox/core/httpproxy"
	"nvelox/core/logging"

	"github.com/lesismal/nbio"
)

// The dynamic denylist is consulted when a request, a connection or a UDP
// session starts. Adding a client to it also ends what that client has open
// at that moment: WebSocket tunnels (each bind group), L4 TCP and TLS
// connections (l4Conns) and UDP sessions (the handler's sessions).

// l4Client is the client of a live L4 TCP/TLS connection, as its access
// check saw it: the peer, or behind a trusted relay the client the relay's
// PROXY header names (nil until the header is read; a relay that sends no
// header is the client itself).
type l4Client struct{ ip atomic.Pointer[net.IP] }

// setL4Client records ip as the client of the accepted connection c.
func (e *Engine) setL4Client(c net.Conn, ip net.IP) {
	if ip == nil {
		return
	}
	if v, ok := e.l4Conns.Load(c); ok {
		v.(*l4Client).ip.Store(&ip)
	}
}

// closeDenylisted closes the open connections of every client the dynamic
// denylist blocks now. Engine.Start runs it after each add. The closes run
// in the background (a TLS close can wait for a stalled client).
func (e *Engine) closeDenylisted() {
	blocked := denylist.Default.Blocked
	e.reloadMu.Lock()
	groups := append([]*httpproxy.BindGroup(nil), e.BindGroups...)
	h := e.l4Handler
	e.reloadMu.Unlock()

	n := 0
	for _, g := range groups {
		n += g.CloseTunnelsOf(blocked)
	}
	e.l4Conns.Range(func(k, v any) bool {
		if ip := v.(*l4Client).ip.Load(); ip != nil && blocked(*ip) {
			go k.(net.Conn).Close()
			n++
		}
		return true
	})
	if h != nil {
		n += h.closeSessionsOf(blocked)
	}
	if n > 0 {
		logging.Info("[DENYLIST] closed %d open connection(s) of blocked clients", n)
	}
}

// closeSessionsOf closes the UDP sessions whose client blocked reports (a
// trusted relay's session once a header has named its client) and returns
// how many.
func (h *ProxyEventHandler) closeSessionsOf(blocked func(net.IP) bool) int {
	n := 0
	h.sessions.Range(func(k, v any) bool {
		ctx := v.(*ConnContext)
		ctx.Mu.Lock()
		skip := ctx.IsBackend || ctx.closed || (ctx.PeerTrusted && !ctx.ClientResolved)
		ip := net.ParseIP(ctx.RealClientIP)
		ctx.Mu.Unlock()
		if !skip && ip != nil && blocked(ip) {
			go k.(*nbio.Conn).Close()
			n++
		}
		return true
	})
	return n
}
