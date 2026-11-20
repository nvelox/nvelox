package core

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"nvelox/proxy"
)

// The UDP listener sockets where the event loops are not supported
// (udpfast.go), and in the tests that run both UDP paths. One goroutine per
// socket reads the datagrams; every client address and port is one session
// (udpConn), which the handler opens with its first datagram, feeds with
// each one and closes.

const (
	// udpClientReadTimeout ends a session whose client has sent nothing for
	// this long (Engine.udpClientReadTimeout; tests lower it).
	udpClientReadTimeout = 60 * time.Second
	// udpSweepInterval is how often a socket looks for such sessions, at
	// most; a quarter of the timeout when that is shorter.
	udpSweepInterval = time.Second
)

var (
	errUDPClientSilent = errors.New("no datagram from the client within the read timeout")
	errUDPSocketClosed = errors.New("the listener socket was closed")
)

// udpConn is one client of a UDP listener socket: a peer address and port.
type udpConn struct {
	sock   *udpListenSock
	remote netip.AddrPort
	raddr  *net.UDPAddr
	last   atomic.Int64 // when the client's last datagram came (UnixNano)
	// dest is where the datagram being handed on (OnData) was sent: what a
	// relay's signed header is bound to. The socket's reader alone writes
	// and reads it.
	dest netip.AddrPort
}

// LocalAddr is the address of the listener socket the client sent to.
func (c *udpConn) LocalAddr() net.Addr { return c.sock.laddr }

// RemoteAddr is the client's address and port.
func (c *udpConn) RemoteAddr() net.Addr { return c.raddr }

// Write sends one datagram to the client. An empty one is not sent: an empty
// reply of the backend is not relayed.
func (c *udpConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	return c.sock.pc.WriteToUDPAddrPort(b, c.remote)
}

// Close ends the session. Of several callers one ends it (OnClose hands the
// session to one of them only).
func (c *udpConn) Close() error {
	c.close(nil)
	return nil
}

func (c *udpConn) close(err error) {
	c.sock.forget(c)
	c.sock.handler.OnClose(c, err)
}

// udpListenSock is one UDP listener socket and the sessions of its clients.
type udpListenSock struct {
	pc      *net.UDPConn
	rd      *proxy.DestReader
	laddr   net.Addr
	handler *ProxyEventHandler
	// viaInterface: the socket is bound to one of its listener's
	// accept_proxy_interfaces (udpdevice.go).
	viaInterface bool
	readTimeout  time.Duration // udpClientReadTimeout of the engine

	mu      sync.Mutex
	conns   map[netip.AddrPort]*udpConn
	windows relayWindows // the relay sockets' replay windows
	closed  bool
	done    chan struct{}
	wg      sync.WaitGroup
}

// newUDPListenSock serves pc for h. dests: the listener trusts relays, whose
// signed headers are bound to where each datagram was sent (on a socket
// bound to every address, the system tells it).
func newUDPListenSock(pc *net.UDPConn, h *ProxyEventHandler, viaInterface, dests bool) *udpListenSock {
	s := &udpListenSock{pc: pc, rd: proxy.NewDestReader(pc, dests), laddr: pc.LocalAddr(), handler: h, viaInterface: viaInterface,
		readTimeout: udpClientReadTimeout,
		conns:       make(map[netip.AddrPort]*udpConn), done: make(chan struct{})}
	if h != nil && h.engine != nil && h.engine.udpClientReadTimeout > 0 {
		s.readTimeout = h.engine.udpClientReadTimeout
	}
	return s
}

// start begins reading the socket.
func (s *udpListenSock) start() {
	s.wg.Add(2)
	go s.read()
	go s.sweep()
}

// forget takes c out of the socket's table, if it is still the session of
// its client there.
func (s *udpListenSock) forget(c *udpConn) {
	s.mu.Lock()
	if s.conns[c.remote] == c {
		delete(s.conns, c.remote)
	}
	s.mu.Unlock()
}

// takeCounter takes counter, from a counted header of the relay socket at
// remote, in that socket's replay window, which the session ctx uses from
// its first such header on: false when the socket sent it before or it is
// older than the window.
func (s *udpListenSock) takeCounter(ctx *ConnContext, remote netip.AddrPort, counter uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.win == nil {
		now := time.Now().UnixNano()
		ctx.win = s.windows.attach(remote, now)
		if ctx.winReleased { // a datagram that came as the session ended
			s.windows.detach(ctx.win, now)
		}
	}
	return ctx.win.Take(counter)
}

// releaseWindow: the session ctx is over. The window it used stays for the
// next sessions of its relay socket (relayWindows.detach).
func (s *udpListenSock) releaseWindow(ctx *ConnContext) {
	s.mu.Lock()
	if ctx.win != nil && !ctx.winReleased {
		s.windows.detach(ctx.win, time.Now().UnixNano())
	}
	ctx.winReleased = true
	s.mu.Unlock()
}

// read hands every datagram to the handler: OnOpen for the first one of a
// client, then OnData. An empty datagram keeps its client's session, begins
// none and is not handed on. A datagram is valid only during the call.
func (s *udpListenSock) read() {
	defer s.wg.Done()
	buf := make([]byte, udpMaxDatagram)
	for {
		n, from, to, err := s.rd.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// What an ICMP error for an earlier reply leaves on the socket
			// on some systems: the socket itself goes on.
			select {
			case <-s.done:
				return
			case <-time.After(time.Millisecond):
			}
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		c := s.conns[from]
		fresh := c == nil
		if fresh {
			if n == 0 {
				// An empty datagram is not relayed, so it begins nothing
				// (on a session it counts as its client's activity).
				s.mu.Unlock()
				continue
			}
			c = &udpConn{sock: s, remote: from, raddr: net.UDPAddrFromAddrPort(from)}
			s.conns[from] = c
		}
		// Under the lock, so that sweep cannot end a session whose client
		// has just sent.
		c.last.Store(time.Now().UnixNano())
		s.mu.Unlock()

		if fresh {
			s.handler.onOpen(c, s.viaInterface)
		}
		if n > 0 {
			c.dest = to
			s.handler.OnData(c, buf[:n])
		}
	}
}

// sweep ends the sessions whose client has been silent for the read
// timeout.
func (s *udpListenSock) sweep() {
	defer s.wg.Done()
	every := udpSweepInterval
	if q := s.readTimeout / 4; q < every {
		every = q
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			limit := now.Add(-s.readTimeout).UnixNano()
			var silent []*udpConn
			s.mu.Lock()
			for from, c := range s.conns {
				if c.last.Load() < limit {
					silent = append(silent, c)
					delete(s.conns, from)
				}
			}
			s.mu.Unlock()
			for _, c := range silent {
				c.close(errUDPClientSilent)
			}
		}
	}
}

// stop closes the socket and ends every session of it.
func (s *udpListenSock) stop() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := make([]*udpConn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	close(s.done)
	_ = s.pc.Close()
	s.wg.Wait() // no reader is left: no session is opened or fed from here on
	for _, c := range conns {
		c.close(errUDPSocketClosed)
	}
}
