package core

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
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
	laddr   net.Addr
	handler *ProxyEventHandler
	// viaInterface: the socket is bound to one of its listener's
	// accept_proxy_interfaces (udpdevice.go).
	viaInterface bool
	readTimeout  time.Duration // udpClientReadTimeout of the engine

	mu     sync.Mutex
	conns  map[netip.AddrPort]*udpConn
	closed bool
	done   chan struct{}
	wg     sync.WaitGroup
}

func newUDPListenSock(pc *net.UDPConn, h *ProxyEventHandler, viaInterface bool) *udpListenSock {
	s := &udpListenSock{pc: pc, laddr: pc.LocalAddr(), handler: h, viaInterface: viaInterface,
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

// read hands every datagram to the handler: OnOpen for the first one of a
// client, then OnData. An empty datagram keeps its client's session, begins
// none and is not handed on. A datagram is valid only during the call.
func (s *udpListenSock) read() {
	defer s.wg.Done()
	buf := make([]byte, udpMaxDatagram)
	for {
		n, from, err := s.pc.ReadFromUDPAddrPort(buf)
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
