//go:build linux

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"
	"nvelox/proxy"

	"github.com/pires/go-proxyproto"
)

// Plain L4 TCP listeners on the event loops (the ngx module): the relay of
// relay.go — the same half-close semantics, back-pressure, idle timeout and
// L4 access record — without a goroutine pair per connection. A connection
// from a trusted relay (accept_proxy_from), whose PROXY header has to be
// read first, is served by serveTCP as before.

// l4FastOff turns the event-loop relay off for listeners started from now
// on (tests compare it with relayL4).
var l4FastOff atomic.Bool

func l4FastEnabled() bool { return ngx.Supported() && !l4FastOff.Load() }

// l4FastServer serves one plain L4 TCP listener from the loops.
type l4FastServer struct {
	e      *Engine
	h      *ProxyEventHandler
	l      *ListenerConfig
	lnfd   int
	group  *ngx.Group
	acc    []*l4Acceptor // by loop id
	lists  []l4List      // live sessions by loop id (loop goroutine only)
	closed atomic.Bool
	lnOnce sync.Once
}

type l4List struct{ head *l4Sess }

func (l *l4List) add(s *l4Sess) {
	s.lnext, s.lprev = l.head, nil
	if l.head != nil {
		l.head.lprev = s
	}
	l.head = s
}

func (l *l4List) remove(s *l4Sess) {
	if s.lprev != nil {
		s.lprev.lnext = s.lnext
	} else if l.head == s {
		l.head = s.lnext
	}
	if s.lnext != nil {
		s.lnext.lprev = s.lprev
	}
	s.lprev, s.lnext = nil, nil
}

// startL4Fast serves listener l, bound as ln, from the event loops once the
// serve gate opens.
func (e *Engine) startL4Fast(ln net.Listener, l *ListenerConfig, h *ProxyEventHandler) error {
	fd, err := ngx.DetachListener(ln)
	if err != nil {
		return fmt.Errorf("TCP listener %s: %v", l.Name, err)
	}
	grp := ngx.Default()
	f := &l4FastServer{e: e, h: h, l: l, lnfd: fd, group: grp}
	f.acc = make([]*l4Acceptor, len(grp.Loops()))
	f.lists = make([]l4List, len(grp.Loops()))
	e.l4Fast = append(e.l4Fast, f)
	e.acceptWG.Add(1)
	go func() {
		defer e.acceptWG.Done()
		if !e.serveGate.Wait(e.runDone()) {
			f.stop()
			return
		}
		var wg sync.WaitGroup
		for _, lp := range grp.Loops() {
			lp := lp
			wg.Add(1)
			lp.Post(func() {
				defer wg.Done()
				if f.closed.Load() {
					return
				}
				a := &l4Acceptor{f: f, l: lp}
				a.timer.F = a
				reg, err := lp.RegisterListener(f.lnfd, a)
				if err != nil {
					logging.Error("[ACCEPT] listener %s: %v", l.Name, err)
					return
				}
				a.reg = reg
				f.acc[lp.ID()] = a
			})
		}
		wg.Wait()
	}()
	return nil
}

// stop stops accepting and closes the listening socket (no new session
// starts once it returns).
func (f *l4FastServer) stop() {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	var wg sync.WaitGroup
	for _, lp := range f.group.Loops() {
		lp := lp
		wg.Add(1)
		lp.Post(func() {
			defer wg.Done()
			if a := f.acc[lp.ID()]; a != nil {
				a.stop()
				f.acc[lp.ID()] = nil
			}
		})
	}
	wg.Wait()
	f.lnOnce.Do(func() { unix.Close(f.lnfd) })
}

// closeAll aborts every live session.
func (f *l4FastServer) closeAll() {
	var wg sync.WaitGroup
	for _, lp := range f.group.Loops() {
		lp := lp
		wg.Add(1)
		lp.Post(func() {
			defer wg.Done()
			for s := f.lists[lp.ID()].head; s != nil; {
				next := s.lnext
				s.fail(errors.New("listener closed"))
				s = next
			}
		})
	}
	wg.Wait()
}

type l4Acceptor struct {
	f       *l4FastServer
	l       *ngx.Loop
	reg     ngx.Reg
	timer   ngx.Timer
	backoff time.Duration
	stopped bool
}

func (a *l4Acceptor) OnEvent(uint32) {
	for i := 0; i < 64; i++ {
		nfd, sa, err := unix.Accept4(a.f.lnfd, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		if err != nil {
			switch err {
			case unix.EAGAIN:
				a.backoff = 0
				return
			case unix.EINTR, unix.ECONNABORTED:
				continue
			}
			a.backoff = max(5*time.Millisecond, 2*a.backoff)
			if a.backoff > time.Second {
				a.backoff = time.Second
			}
			logging.Error("[ACCEPT] listener %s: %v (retrying in %v)", a.f.l.Name, err, a.backoff)
			a.l.Unregister(a.f.lnfd, a.reg)
			a.reg = ngx.Reg{}
			a.l.Arm(&a.timer, a.backoff)
			return
		}
		a.backoff = 0
		f := a.f
		target := f.group.Next()
		if target == a.l {
			f.newSession(target, nfd, sa)
		} else {
			target.Post(func() { f.newSession(target, nfd, sa) })
		}
	}
}

func (a *l4Acceptor) OnTimer() {
	if a.stopped || a.f.closed.Load() {
		return
	}
	reg, err := a.l.RegisterListener(a.f.lnfd, a)
	if err != nil {
		a.l.Arm(&a.timer, time.Second)
		return
	}
	a.reg = reg
}

func (a *l4Acceptor) stop() {
	a.stopped = true
	a.l.Stop(&a.timer)
	if a.reg.Registered() {
		a.l.Unregister(a.f.lnfd, a.reg)
		a.reg = ngx.Reg{}
	}
}

// l4Sess is one relayed connection.
type l4Sess struct {
	f     *l4FastServer
	lp    *ngx.Loop
	cfd   int
	bfd   int
	creg  ngx.Reg
	breg  ngx.Reg
	timer ngx.Timer
	state int

	c2b, b2c l4Dir // client -> backend, backend -> client
	cR, cW   bool  // the client socket is readable / writable
	bR, bW   bool  // the backend socket is readable / writable
	// cHup / bHup: the peer's FIN (or an error) was reported. A short read
	// then does not mean drained: the end of stream is still to be read,
	// and no new edge will announce it.
	cHup, bHup bool

	idle       time.Duration
	lastActive int64
	start      int64

	queued       bool // gave way in the middle of a relay (l4RelayRound)
	laterFn      func()
	peer         netip.Addr
	peerPort     int
	dialAddr     net.Addr // the backend address being dialed (dial errors name it)
	clientIP     string
	dstPort      int
	target       string
	balancer     lb.Balancer
	limiter      *ConnLimiter
	linked       bool
	refused      string
	err          error
	connectTO    time.Duration
	clientRecord *l4Client

	lprev, lnext *l4Sess
	cend         l4End
	bend         l4End
}

const (
	l4Connecting = iota
	l4Relaying
	l4Closed
)

// l4Dir is one direction of the relay.
type l4Dir struct {
	pending []byte // read from the source, not yet written to the destination
	eof     bool   // the source ended cleanly
	done    bool   // finished: half-closed, or drained after its destination failed
	discard bool   // the destination stopped accepting: drop what the source sends
}

// l4End is the handler of one socket of a session.
type l4End struct {
	s       *l4Sess
	backend bool
}

func (e *l4End) OnEvent(ev uint32) { e.s.onEvent(e.backend, ev) }

func (f *l4FastServer) newSession(lp *ngx.Loop, fd int, sa unix.Sockaddr) {
	e, l := f.e, f.l
	var peer netip.Addr
	var peerPort int
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		peer, peerPort = netip.AddrFrom4(a.Addr), a.Port
	case *unix.SockaddrInet6:
		peer, peerPort = netip.AddrFrom16(a.Addr).Unmap(), a.Port
	default:
		unix.Close(fd)
		return
	}
	if f.closed.Load() {
		unix.Close(fd)
		return
	}
	remote := &net.TCPAddr{IP: peer.AsSlice(), Port: peerPort}
	if l.proxyTrust.trusts(remote) {
		// A trusted relay: its PROXY header is read first (serveTCP).
		f.handOff(fd)
		return
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, 15)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 15)
	dstPort := 0
	if la, err := unix.Getsockname(fd); err == nil {
		dstPort = sockPort(la)
	}
	clientIP := peer.String()

	if rl, ok := e.RateLimiters[l.Name]; ok && !rl.Allow() {
		logging.Warn("[RATE] Connection from %s rejected (rate limit on %s)", remote, l.Name)
		logging.AccessL4(clientIP, l.Protocol, dstPort, l4StatusRateLimited, 0, 0, 0)
		unix.Close(fd)
		return
	}

	s := &l4Sess{f: f, lp: lp, cfd: fd, bfd: -1, peer: peer, peerPort: peerPort, clientIP: clientIP, dstPort: dstPort, idle: l4IdleTimeout(l)}
	s.timer.F = s
	s.cend = l4End{s: s}
	s.bend = l4End{s: s, backend: true}
	s.start = lp.Now()
	s.lastActive = s.start
	s.clientRecord = &l4Client{}
	ip := remote.IP
	s.clientRecord.ip.Store(&ip)
	// Listed before the admission check, as serveTCP does (setL4Client): a
	// denylist entry added meanwhile finds the session (closeDenylisted).
	e.l4Conns.Store(s, s.clientRecord)
	if ok, status := f.h.l4Admit(l, remote.IP); !ok {
		s.state = l4Closed // a Close posted meanwhile does nothing
		e.l4Conns.Delete(s)
		logging.AccessL4(clientIP, l.Protocol, dstPort, status, 0, 0, 0)
		unix.Close(fd)
		return
	}
	if logging.Enabled(logging.InfoLevel) {
		logging.Info("[CONN] New %s client %s -> :%d", l.Protocol, remote, dstPort)
	}
	e.ActiveConns.Add(1)
	f.lists[lp.ID()].add(s)
	reg, err := lp.Register(fd, &s.cend)
	if err != nil {
		s.err = err
		s.finish()
		return
	}
	s.creg = reg
	s.connectBackend()
}

func sockPort(sa unix.Sockaddr) int {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return a.Port
	case *unix.SockaddrInet6:
		return a.Port
	}
	return 0
}

// handOff serves fd with serveTCP on its own goroutine.
func (f *l4FastServer) handOff(fd int) {
	file := os.NewFile(uintptr(fd), "")
	c, err := net.FileConn(file)
	file.Close()
	if err != nil {
		logging.Error("[ACCEPT] listener %s: %v", f.l.Name, err)
		return
	}
	e := f.e
	e.ActiveConns.Add(1)
	e.l4Conns.Store(c, &l4Client{})
	go func() {
		defer e.ActiveConns.Done()
		defer e.l4Conns.Delete(c)
		f.h.serveTCP(c, f.l)
	}()
}

// connectBackend picks the server and starts the connect.
func (s *l4Sess) connectBackend() {
	e, l := s.f.e, s.f.l
	bv := e.backends()
	balancer, ok := bv.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for listener '%s'", l.Backend, l.Name)
		s.finish()
		return
	}
	backend := bv.Backends[l.Backend]
	if backend != nil && backend.BackendTLS.Enabled {
		logging.Error("[CONN] listener %s: backend %s has backend_tls enabled, which L4 listeners do not implement — refusing %s", l.Name, l.Backend, s.clientIP)
		s.finish()
		return
	}
	if cl, ok := bv.ConnLimiters[l.Backend]; ok {
		if !cl.Acquire() {
			logging.Warn("[CONN] listener %s: backend %s at max_connections — refusing %s", l.Name, l.Backend, s.clientIP)
			s.refused = l4StatusRateLimited
			s.finish()
			return
		}
		s.limiter = cl
	}
	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.Backend, err)
		s.finish()
		return
	}
	s.target, s.balancer = target, balancer
	dialTarget := target
	if _, _, err := net.SplitHostPort(dialTarget); err != nil {
		dialTarget = fmt.Sprintf("%s:%d", dialTarget, l.Port)
	}
	s.connectTO = l.Timeouts.ParseConnect()
	if backend != nil && backend.Timeouts.Connect != "" {
		s.connectTO = backend.Timeouts.ParseConnect()
	}
	s.state = l4Connecting
	if s.connectTO > 0 {
		s.lp.Arm(&s.timer, s.connectTO)
	}
	host, port, _ := net.SplitHostPort(dialTarget)
	ip, ipErr := netip.ParseAddr(host)
	pn, pErr := net.LookupPort("tcp", port)
	if ipErr == nil && pErr == nil && ip.Zone() == "" {
		s.dial(sockaddrOfAddr(ip, pn), backend)
		return
	}
	// A host name: resolve off the loop, as the dialer would.
	lp := s.lp
	runCtx := e.runCtx
	go func() {
		ctx := runCtx
		if ctx == nil {
			ctx = context.Background()
		}
		if s.connectTO > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, s.connectTO)
			defer cancel()
		}
		var sa unix.Sockaddr
		var err error
		if pErr != nil {
			err = pErr
		} else {
			var ips []netip.Addr
			ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err == nil && len(ips) == 0 {
				err = errors.New("no addresses")
			}
			if err == nil {
				sa = sockaddrOfAddr(ips[0], pn)
			}
		}
		lp.Post(func() {
			if s.state != l4Connecting || s.bfd >= 0 {
				return
			}
			if err != nil {
				s.dialFailed(&net.OpError{Op: "dial", Net: "tcp", Err: err})
				return
			}
			s.dial(sa, backend)
		})
	}()
}

func sockaddrOfAddr(a netip.Addr, port int) unix.Sockaddr {
	if a.Is4() || a.Is4In6() {
		return &unix.SockaddrInet4{Port: port, Addr: a.Unmap().As4()}
	}
	return &unix.SockaddrInet6{Port: port, Addr: a.As16()}
}

func (s *l4Sess) dial(sa unix.Sockaddr, backend *config.Backend) {
	s.dialAddr = tcpAddrOf(sa) // named in dial errors, as net.Dialer's are
	family := unix.AF_INET
	if _, ok := sa.(*unix.SockaddrInet6); ok {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		s.dialFailed(os.NewSyscallError("socket", err))
		return
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, 15)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 15)
	err = unix.Connect(fd, sa)
	if err != nil && err != unix.EINPROGRESS {
		unix.Close(fd)
		s.dialFailed(&net.OpError{Op: "dial", Net: "tcp", Addr: s.dialAddr, Err: os.NewSyscallError("connect", err)})
		return
	}
	s.bfd = fd
	reg, rerr := s.lp.Register(fd, &s.bend)
	if rerr != nil {
		s.dialFailed(rerr)
		return
	}
	s.breg = reg
	// PROXY v2 to the backend: the source is the client, the destination
	// the address the client connected to.
	if backend != nil && backend.SendProxyV2 {
		local, _ := unix.Getsockname(s.cfd)
		dst := tcpAddrOf(local)
		src := &net.TCPAddr{IP: s.peer.AsSlice(), Port: 0}
		if ra, err := unix.Getpeername(s.cfd); err == nil {
			src = tcpAddrOf(ra)
		}
		header := proxyproto.HeaderProxyFromAddrs(2, src, dst)
		if len(backend.SendProxyKey) > 0 {
			if err := proxy.SignHeader(header, backend.SendProxyKey, time.Now()); err != nil {
				logging.Error("Failed to sign PROXY v2 header: %v", err)
				s.err = err
				s.finish()
				return
			}
		}
		b, err := header.Format()
		if err != nil {
			logging.Error("Failed to write PROXY v2 header: %v", err)
			s.err = err
			s.finish()
			return
		}
		s.c2b.pending = append(s.c2b.pending, b...)
	}
	if err == nil {
		s.connected()
	}
	// else: EPOLLOUT reports the connect
}

func tcpAddrOf(sa unix.Sockaddr) *net.TCPAddr {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return &net.TCPAddr{IP: net.IP(append([]byte(nil), a.Addr[:]...)), Port: a.Port}
	case *unix.SockaddrInet6:
		return &net.TCPAddr{IP: net.IP(append([]byte(nil), a.Addr[:]...)), Port: a.Port}
	}
	return &net.TCPAddr{}
}

func (s *l4Sess) dialFailed(err error) {
	logging.Error("Backend TCP dial failed: %v", err)
	s.err = err
	s.finish()
}

func (s *l4Sess) connected() {
	s.state = l4Relaying
	s.linked = true
	s.balancer.OnConnect(s.target)
	s.lp.Stop(&s.timer)
	s.touch()
	if s.idle > 0 {
		s.lp.Arm(&s.timer, s.idle)
	}
	s.pump(&s.c2b, false)
	if s.state == l4Relaying {
		s.pump(&s.b2c, true)
	}
}

func (s *l4Sess) onEvent(backend bool, ev uint32) {
	if s.state == l4Closed {
		return
	}
	errOrHup := ev&(ngx.EvErr|ngx.EvHup) != 0
	hup := ev&ngx.EvRDHUP != 0 || errOrHup
	in := ev&ngx.EvIn != 0 || hup
	out := ev&ngx.EvOut != 0 || errOrHup
	if backend {
		if hup {
			s.bHup = true
		}
		if in {
			s.bR = true
		}
		if out {
			s.bW = true
		}
		if s.state == l4Connecting {
			if !out {
				return
			}
			errno, err := unix.GetsockoptInt(s.bfd, unix.SOL_SOCKET, unix.SO_ERROR)
			if err == nil && errno != 0 {
				err = syscall.Errno(errno)
			}
			if err != nil {
				s.dialFailed(&net.OpError{Op: "dial", Net: "tcp", Addr: s.dialAddr, Err: os.NewSyscallError("connect", err)})
				return
			}
			s.connected()
			return
		}
	} else {
		if hup {
			s.cHup = true
		}
		if in {
			s.cR = true
		}
		if out {
			s.cW = true
		}
		if s.state == l4Connecting {
			return // read once the backend is connected
		}
	}
	// Writable destinations first (they release back-pressure), then
	// readable sources.
	s.pump(&s.c2b, false)
	if s.state == l4Relaying {
		s.pump(&s.b2c, true)
	}
}

// pump moves what it can in one direction. toClient selects the
// backend -> client direction.
func (s *l4Sess) pump(d *l4Dir, toClient bool) {
	src, dst := s.cfd, s.bfd
	srcR, dstW, srcHup := &s.cR, &s.bW, s.cHup
	if toClient {
		src, dst = s.bfd, s.cfd
		srcR, dstW, srcHup = &s.bR, &s.cW, s.bHup
	}
	got := 0
	for s.state == l4Relaying && !d.done {
		// What is pending goes first.
		if len(d.pending) > 0 {
			if !*dstW {
				return
			}
			n, errno := ngx.Write(dst, d.pending)
			if errno == unix.EAGAIN {
				*dstW = false
				return
			}
			if errno == unix.EINTR {
				continue
			}
			if errno != 0 {
				s.writeFailed(d, toClient, errno)
				continue
			}
			s.touch()
			rest := copy(d.pending, d.pending[n:])
			d.pending = d.pending[:rest]
			if rest > 0 {
				*dstW = false
				return
			}
			continue
		}
		if d.eof {
			// Everything read has been written: half-close the
			// destination, never a full close.
			if !d.discard {
				if err := unix.Shutdown(dst, unix.SHUT_WR); err != nil {
					s.fail(s.opErr("close", !toClient, os.NewSyscallError("shutdown", err)))
					return
				}
			}
			d.done = true
			s.maybeDone()
			return
		}
		if !*srcR {
			return
		}
		if got >= l4RelayRound {
			// A sender that always has more: give way to the loop's
			// other sessions, then go on.
			s.later()
			return
		}
		buf := s.lp.Scratch[:relayBufSize]
		n, errno := ngx.Read(src, buf)
		got += n
		switch {
		case errno == unix.EAGAIN:
			*srcR = false
			return
		case errno == unix.EINTR:
			continue
		case errno != 0:
			s.fail(s.opErr("read", toClient, os.NewSyscallError("read", errno)))
			return
		case n == 0:
			d.eof = true
			continue
		}
		if n < len(buf) && !srcHup {
			*srcR = false
		}
		s.touch()
		if d.discard {
			continue
		}
		// Write straight through; keep what the destination does not take.
		w := 0
		if *dstW {
			var werr syscall.Errno
			w, werr = ngx.Write(dst, buf[:n])
			switch {
			case werr == unix.EAGAIN || werr == unix.EINTR:
				w = 0
				*dstW = false
			case werr != 0:
				s.writeFailed(d, toClient, werr)
				continue
			}
		}
		if w < n {
			d.pending = append(d.pending, buf[w:n]...)
			*dstW = false
		}
	}
}

// l4RelayRound is how much one direction of a session relays in one go
// before it gives way to the loop's other sessions.
const l4RelayRound = 1 << 20

// later goes on relaying from the loop's task queue, after the events that
// are waiting.
func (s *l4Sess) later() {
	if s.queued {
		return
	}
	s.queued = true
	if s.laterFn == nil {
		s.laterFn = func() {
			s.queued = false
			if s.state != l4Relaying {
				return
			}
			s.pump(&s.c2b, false)
			if s.state == l4Relaying {
				s.pump(&s.b2c, true)
			}
		}
	}
	s.lp.Post(s.laterFn)
}

// writeFailed: writing to a direction's destination failed. A backend that
// stopped accepting while the client still sends must not cut the response
// it may still be sending: the client's input is read and dropped (relay.go
// explains why). Any other failure ends the session.
func (s *l4Sess) writeFailed(d *l4Dir, toClient bool, errno syscall.Errno) {
	if !toClient && (errno == unix.EPIPE || errno == unix.ECONNRESET) {
		d.discard = true
		d.pending = d.pending[:0]
		return
	}
	s.fail(s.opErr("write", !toClient, os.NewSyscallError("write", errno)))
}

func (s *l4Sess) touch() { s.lastActive = s.lp.Now() }

func (s *l4Sess) maybeDone() {
	if s.c2b.done && s.b2c.done {
		s.finish()
	}
}

// OnTimer: the connect timeout, or the idle check.
func (s *l4Sess) OnTimer() {
	switch s.state {
	case l4Connecting:
		s.dialFailed(&net.OpError{Op: "dial", Net: "tcp", Addr: s.dialAddr, Err: errors.New("i/o timeout")})
	case l4Relaying:
		if s.idle <= 0 {
			return
		}
		if idleFor := time.Duration(s.lp.Now() - s.lastActive); idleFor < s.idle {
			s.lp.Arm(&s.timer, s.idle-idleFor)
			return
		}
		s.fail(s.opErr("read", true, os.ErrDeadlineExceeded))
	}
}

// opErr is a session error as the goroutine relay's net.Conn calls report
// it, "read tcp local->remote: ...": on the backend's connection or the
// client's. The session must be open (its sockets are queried).
func (s *l4Sess) opErr(op string, backend bool, err error) error {
	fd := s.cfd
	var remote net.Addr = &net.TCPAddr{IP: s.peer.AsSlice(), Port: s.peerPort}
	if backend {
		fd, remote = s.bfd, s.dialAddr
	}
	e := &net.OpError{Op: op, Net: "tcp", Addr: remote, Err: err}
	if sa, gerr := unix.Getsockname(fd); gerr == nil {
		e.Source = tcpAddrOf(sa)
	}
	return e
}

// fail aborts the session on its first real error: both sockets are closed
// at once.
func (s *l4Sess) fail(err error) {
	if s.state == l4Closed {
		return
	}
	if s.err == nil {
		s.err = err
	}
	s.finish()
}

// Close aborts the session from any goroutine (shutdown, the dynamic
// denylist).
func (s *l4Sess) Close() error {
	s.lp.Post(func() {
		if s.state != l4Closed {
			s.fail(s.opErr("read", false, net.ErrClosed))
		}
	})
	return nil
}

// finish releases the session and writes its L4 access record.
func (s *l4Sess) finish() {
	if s.state == l4Closed {
		return
	}
	s.state = l4Closed
	s.lp.Stop(&s.timer)
	if s.bfd >= 0 {
		s.lp.Unregister(s.bfd, s.breg)
		unix.Close(s.bfd)
		s.bfd = -1
	}
	s.lp.Unregister(s.cfd, s.creg)
	unix.Close(s.cfd)
	if s.linked {
		s.balancer.OnDisconnect(s.target)
	}
	if s.limiter != nil {
		s.limiter.Release()
	}
	s.c2b.pending, s.b2c.pending = nil, nil
	e, l := s.f.e, s.f.l
	dur := time.Duration(s.lp.Now() - s.start)
	if logging.Enabled(logging.InfoLevel) {
		logging.Info("[CONN] Closed %s (Dur: %v, Err: %v)", &net.TCPAddr{IP: s.peer.AsSlice(), Port: s.peerPort}, dur, s.err)
	}
	status := "no_route"
	switch {
	case s.refused != "":
		status = s.refused
	case s.linked:
		status = "ok"
	}
	logging.AccessL4(s.clientIP, l.Protocol, s.dstPort, status, 0, 0, float64(dur.Nanoseconds())/1e6)
	s.f.lists[s.lp.ID()].remove(s)
	e.l4Conns.Delete(s)
	e.ActiveConns.Done()
}
