//go:build linux

package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"

	"nvelox/core/logging"
	"nvelox/lb"
	"nvelox/proxy"
)

// UDP listeners on the event loops (the ngx module): the sessions, limits,
// relay rules and access records of handler.go without the nbio poller, the
// goroutine per session and the locks per datagram.
//
// Sockets. A single port (and a port range with fewer ports than loops) has
// one socket per loop, all bound to the port with SO_REUSEPORT: the kernel
// gives every datagram of one client (address and port) to the same socket,
// so a session lives on one loop and needs no lock. A range with at least
// as many ports as loops has one socket per port, the ports dealt to the
// loops in turn. The sockets of accept_proxy_interfaces are bound to their
// interface the same way. Every socket is bound at start (before the process
// gives up root) and read once the serve gate opens.
//
// A loop reads a socket with recvmmsg, and sends the replies it collected
// during a pass with one sendmmsg per listener socket at the end of the
// pass. A session's backend socket is a connected socket on the same loop.

const (
	// udpBatch is how many datagrams one recvmmsg or sendmmsg carries.
	udpBatch = 16
	// udpRounds bounds the batches taken from one socket per event; the
	// rest waits for the next pass (the socket stays readable).
	udpRounds = 4
	// udpWaitMax bounds the datagrams a session keeps while its backend's
	// host name is looked up; past it the session is closed.
	udpWaitMax = 1 << 20
)

// Drops of the ngx engine (nvelox_udp_dropped_total{reason}).
const (
	udpDropBackendBusy = "backend_busy" // the backend socket's send buffer was full
	udpDropClientBusy  = "client_busy"  // the listener socket's send buffer was full
)

func init() {
	udpDropText[udpDropBackendBusy] = "datagrams a backend socket could not take (its send buffer was full)"
	udpDropText[udpDropClientBusy] = "replies a listener socket could not take (its send buffer was full)"
}

const sizeofSockaddrInet6 = uint32(unsafe.Sizeof(unix.RawSockaddrInet6{}))

// udpFast serves every udp listener of an engine.
type udpFast struct {
	e      *Engine
	h      *ProxyEventHandler
	group  *ngx.Group
	per    []*udpPer // by loop id
	socks  []*udpSock
	closed atomic.Bool
	// started: the sockets are registered on their loops (the serve gate
	// opened). Read and written under mu.
	mu      sync.Mutex
	started bool
}

// udpPer is an engine's part of one loop: its sockets there and their live
// sessions (loop goroutine only, once the engine is started).
type udpPer struct {
	lp    *ngx.Loop
	ul    *udpLoop
	socks []*udpSock
	list  udpList
}

// udpLoop is a loop's UDP scratch, shared by every engine of the process
// (tests start many): the receive batch and the replies of the current
// pass. Loop goroutine only.
type udpLoop struct {
	lp *ngx.Loop

	// The receive batch.
	rmsgs  [udpBatch]ngx.Mmsghdr
	riov   [udpBatch]unix.Iovec
	rnames [udpBatch]unix.RawSockaddrInet6
	rbuf   []byte // udpBatch datagrams of up to udpMaxDatagram bytes

	// The replies of this pass, for one listener socket (sfd).
	smsgs  [udpBatch]ngx.Mmsghdr
	siov   [udpBatch]unix.Iovec
	snames [udpBatch]unix.RawSockaddrInet6
	ssess  [udpBatch]*udpSess
	sbuf   []byte
	sn     int
	sfd    int
	endIdx int
}

var udpLoops sync.Map // *ngx.Loop -> *udpLoop

// udpLoopOf returns lp's UDP scratch, made on first use (loop goroutine).
func udpLoopOf(lp *ngx.Loop) *udpLoop {
	if v, ok := udpLoops.Load(lp); ok {
		return v.(*udpLoop)
	}
	ul := &udpLoop{lp: lp, sfd: -1}
	ul.rbuf = make([]byte, udpBatch*udpMaxDatagram)
	ul.sbuf = make([]byte, udpBatch*udpMaxDatagram)
	for i := range ul.rmsgs {
		ul.riov[i].Base = &ul.rbuf[i*udpMaxDatagram]
		ul.riov[i].SetLen(udpMaxDatagram)
		m := &ul.rmsgs[i]
		m.Hdr.Iov = &ul.riov[i]
		m.Hdr.SetIovlen(1)
		m.Hdr.Name = (*byte)(unsafe.Pointer(&ul.rnames[i]))
		m.Hdr.Namelen = sizeofSockaddrInet6
		s := &ul.smsgs[i]
		s.Hdr.Iov = &ul.siov[i]
		s.Hdr.SetIovlen(1)
		s.Hdr.Name = (*byte)(unsafe.Pointer(&ul.snames[i]))
	}
	ul.endIdx = lp.OnIterationEnd(ul.flush)
	udpLoops.Store(lp, ul)
	return ul
}

// udpSock is one listener socket, on one loop.
type udpSock struct {
	u            *udpFast
	per          *udpPer
	ul           *udpLoop // per.ul, set when the engine starts
	l            *ListenerConfig
	fd           int
	reg          ngx.Reg
	local        *net.UDPAddr // the address it is bound to
	dstPort      int
	viaInterface bool // bound to one of the listener's accept_proxy_interfaces
	sessions     map[netip.AddrPort]*udpSess
}

type udpList struct{ head *udpSess }

func (l *udpList) add(s *udpSess) {
	s.lnext, s.lprev = l.head, nil
	if l.head != nil {
		l.head.lprev = s
	}
	l.head = s
}

func (l *udpList) remove(s *udpSess) {
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

// udpSess is one UDP session: one peer (address and port) on one listener
// socket. Everything in it belongs to its loop.
type udpSess struct {
	sock *udpSock
	ul   *udpLoop
	l    *ListenerConfig

	peer    netip.AddrPort        // the client, or the relay that names it
	name    unix.RawSockaddrInet6 // the peer's socket address, for replies
	namelen uint32

	bfd    int // the backend socket; -1 until it is open
	breg   ngx.Reg
	bend   udpBackendEnd
	timer  ngx.Timer
	closed bool

	// Loop-clock times: session start, the last datagram from the peer,
	// the backend socket's opening and its last reply.
	start, lastPeer, opened, lastReply int64
	replied                            bool

	// Admission, as ConnContext keeps it for the nbio engine.
	realClientIP   string
	peerTrusted    bool // the peer is a trusted relay
	clientResolved bool // a header of the relay named the client
	relayPending   bool // no valid header yet: the session holds nothing
	pendingHeld    bool
	slotHeld       bool
	sessionIP      netip.Addr
	limiter        *ConnLimiter
	named          net.Addr // the client the relay's first header named
	// inHdr is that header as it arrived, kept while headers need no
	// signature: a later datagram that starts with the same bytes names the
	// same client and needs no parsing.
	inHdr   []byte
	refused string

	balancer  lb.Balancer
	target    string
	onConnect bool // balancer.OnConnect was called
	linked    bool // the backend socket was opened ("ok" in the access record)

	proxyHdr []byte       // prepended to every datagram to the backend (send_proxy_v2)
	keyView  *backendView // the backend view key was read from
	key      []byte       // the backend's send_proxy_key_file key

	// wait holds the datagrams that arrived before the backend socket was
	// open, each behind its length (2 bytes).
	wait []byte

	lprev, lnext *udpSess
}

// udpBackendEnd is the handler of a session's backend socket.
type udpBackendEnd struct{ s *udpSess }

func (b *udpBackendEnd) OnEvent(uint32) { b.s.onReply() }

// startUDPFast binds the sockets of every udp listener and serves them from
// the event loops once the serve gate opens.
func (e *Engine) startUDPFast(plan *udpInterfacePlan, h *ProxyEventHandler) error {
	grp := ngx.Default()
	n := len(grp.Loops())
	u := &udpFast{e: e, h: h, group: grp, per: make([]*udpPer, n)}
	for i, lp := range grp.Loops() {
		u.per[i] = &udpPer{lp: lp}
	}
	type bind struct {
		l         *ListenerConfig
		addr, dev string
		perLoop   bool
		reuse     bool
		loop      int // for a socket that is not per loop
	}
	var binds []bind
	var probes []string
	listeners := 0
	for _, l := range e.Listeners {
		if l.Protocol != "udp" || l.TLS != nil {
			continue
		}
		logging.Info("Registering listener %s on %s", l.Name, l.Addr)
		listeners++
		if plan.onDevice[l.Addr] {
			probes = append(probes, l.Addr)
			continue // its own socket is bound to an interface (below)
		}
		_, portStr, err := net.SplitHostPort(l.Addr)
		if err != nil {
			return fmt.Errorf("listener %s: %v", l.Name, err)
		}
		port, _ := strconv.Atoi(portStr)
		perLoop := l.rangeSize < n
		reuse := perLoop || plan.sharedPorts[port]
		if reuse {
			probes = append(probes, l.Addr)
		}
		binds = append(binds, bind{l: l, addr: l.Addr, perLoop: perLoop, reuse: reuse, loop: l.rangeIndex % n})
	}
	for _, a := range plan.deviceAddrs {
		_, portStr, err := net.SplitHostPort(a)
		if err != nil {
			return err
		}
		l := h.listenerMap["udp:"+portStr]
		if l == nil {
			return fmt.Errorf("no udp listener for interface address %s", a)
		}
		binds = append(binds, bind{l: l, addr: a, dev: plan.deviceOf[a], perLoop: true, reuse: true})
	}
	// A port shared through SO_REUSEPORT would also be shared with another
	// nvelox started by the same user, which would then take a part of the
	// datagrams: a plain bind first refuses a port that is in use, as
	// before.
	for _, a := range probes {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			return err
		}
		pc.Close()
	}
	fail := func(err error) error {
		for _, s := range u.socks {
			unix.Close(s.fd)
		}
		return err
	}
	for _, b := range binds {
		count := 1
		if b.perLoop {
			count = n
		}
		for i := 0; i < count; i++ {
			fd, local, err := udpListenFD(b.addr, b.dev, b.reuse)
			if err != nil {
				return fail(err)
			}
			per := u.per[b.loop]
			if b.perLoop {
				per = u.per[i]
			}
			s := &udpSock{u: u, per: per, l: b.l, fd: fd, local: local, dstPort: local.Port,
				viaInterface: b.dev != "", sessions: make(map[netip.AddrPort]*udpSess)}
			u.socks = append(u.socks, s)
			per.socks = append(per.socks, s)
		}
	}
	e.udpFast = u
	if listeners == 0 {
		return nil
	}
	logging.Info("UDP Engine Started on %d listeners (%d sockets on %d event loops)", listeners, len(u.socks), n)
	if len(plan.deviceAddrs) > 0 {
		logging.Info("UDP accept_proxy_interfaces sockets started on %v", plan.deviceAddrs)
	}
	e.acceptWG.Add(1)
	go func() {
		defer e.acceptWG.Done()
		if !e.serveGate.Wait(e.runDone()) {
			u.stop()
			return
		}
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.closed.Load() {
			return
		}
		u.started = true
		var wg sync.WaitGroup
		for _, per := range u.per {
			per := per
			if len(per.socks) == 0 {
				continue
			}
			wg.Add(1)
			per.lp.Post(func() {
				defer wg.Done()
				per.start()
			})
		}
		wg.Wait()
	}()
	return nil
}

// udpListenFD binds a UDP socket to addr the way net.ListenUDP does (the
// same address family: a wildcard address gives one dual-stack socket),
// sharing its port (SO_REUSEPORT) and bound to the interface dev when they
// are set, and returns it detached from the Go runtime, non-blocking.
func udpListenFD(addr, dev string, reuseport bool) (int, *net.UDPAddr, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if reuseport {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
			if serr == nil && dev != "" {
				if serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev); serr != nil {
					serr = fmt.Errorf("bind to interface %s: %w", dev, serr)
				}
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return -1, nil, err
	}
	local, _ := pc.LocalAddr().(*net.UDPAddr)
	if local == nil {
		pc.Close()
		return -1, nil, fmt.Errorf("listen udp %s: no local address", addr)
	}
	fd, err := ngx.DetachPacketConn(pc)
	if err != nil {
		return -1, nil, err
	}
	return fd, local, nil
}

// start registers the engine's sockets of this loop (loop goroutine).
func (per *udpPer) start() {
	per.ul = udpLoopOf(per.lp)
	for _, s := range per.socks {
		s.ul = per.ul
		reg, err := per.lp.RegisterRead(s.fd, s)
		if err != nil {
			logging.Error("[UDP] listener %s: %v", s.l.Name, err)
			continue
		}
		s.reg = reg
	}
}

// stop closes every socket and ends every session (with its access
// record). No session starts once it returns.
func (u *udpFast) stop() {
	if !u.closed.CompareAndSwap(false, true) {
		return
	}
	u.mu.Lock()
	started := u.started
	u.mu.Unlock()
	if !started {
		for _, s := range u.socks {
			unix.Close(s.fd)
		}
		return
	}
	var wg sync.WaitGroup
	for _, per := range u.per {
		per := per
		wg.Add(1)
		per.lp.Post(func() {
			defer wg.Done()
			for _, s := range per.socks {
				if s.reg.Registered() {
					per.lp.Unregister(s.fd, s.reg)
					s.reg = ngx.Reg{}
				}
			}
			for s := per.list.head; s != nil; {
				next := s.lnext
				s.close(errors.New("listener closed"))
				s = next
			}
			if per.ul != nil {
				per.ul.flush() // replies still queued go out on sockets that are still open
			}
			for _, s := range per.socks {
				unix.Close(s.fd)
			}
		})
	}
	wg.Wait()
}

// closeSessionsOf ends the sessions whose client blocked reports (a
// trusted relay's session once a header named its client) and returns how
// many. Not for a loop goroutine: it waits for the loops.
func (u *udpFast) closeSessionsOf(blocked func(net.IP) bool) int {
	u.mu.Lock()
	started := u.started
	u.mu.Unlock()
	if !started || u.closed.Load() {
		return 0
	}
	var n atomic.Int64
	var wg sync.WaitGroup
	for _, per := range u.per {
		per := per
		wg.Add(1)
		per.lp.Post(func() {
			defer wg.Done()
			for s := per.list.head; s != nil; {
				next := s.lnext
				if !(s.peerTrusted && !s.clientResolved) {
					if ip := net.ParseIP(s.realClientIP); ip != nil && blocked(ip) {
						s.close(nil)
						n.Add(1)
					}
				}
				s = next
			}
		})
	}
	wg.Wait()
	return int(n.Load())
}

// OnEvent reads the socket: batches of datagrams while it has a full one,
// at most udpRounds per pass.
func (s *udpSock) OnEvent(uint32) {
	ul := s.ul
	for round := 0; round < udpRounds; round++ {
		n, errno := ngx.Recvmmsg(s.fd, ul.rmsgs[:])
		if errno != 0 || n == 0 {
			return
		}
		for i := 0; i < n; i++ {
			m := &ul.rmsgs[i]
			namelen := m.Hdr.Namelen
			m.Hdr.Namelen = sizeofSockaddrInet6
			from, ok := udpPeerOf(&ul.rnames[i])
			if !ok {
				continue
			}
			s.datagram(from, &ul.rnames[i], namelen, ul.rbuf[i*udpMaxDatagram:i*udpMaxDatagram+int(m.Len)])
		}
		if n < udpBatch {
			return
		}
	}
}

// udpPeerOf returns the address and port in a socket address the kernel
// filled in; IPv4-mapped addresses (an IPv4 peer of a dual-stack socket)
// as IPv4.
func udpPeerOf(sa *unix.RawSockaddrInet6) (netip.AddrPort, bool) {
	switch sa.Family {
	case unix.AF_INET:
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		p := (*[2]byte)(unsafe.Pointer(&sa4.Port))
		return netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), uint16(p[0])<<8|uint16(p[1])), true
	case unix.AF_INET6:
		p := (*[2]byte)(unsafe.Pointer(&sa.Port))
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), uint16(p[0])<<8|uint16(p[1])), true
	}
	return netip.AddrPort{}, false
}

// datagram handles one datagram from peer: it starts the peer's session
// when there is none, and relays the payload.
func (s *udpSock) datagram(from netip.AddrPort, name *unix.RawSockaddrInet6, namelen uint32, data []byte) {
	sess := s.sessions[from]
	if sess == nil {
		if sess = s.open(from, name, namelen); sess == nil {
			return
		}
	} else {
		sess.lastPeer = s.per.lp.Now()
	}
	if len(data) == 0 {
		// An empty datagram starts a session and counts as its peer's
		// activity, and is not relayed (as before).
		return
	}
	if sess.peerTrusted {
		if data = sess.relayed(data); data == nil {
			return
		}
	}
	sess.forward(data)
}

// open admits a new session for peer, in the order of the nbio engine's
// OnOpen: listener rate limit, access policy on the client (a relay's
// client is admitted when its header names it), session limits, the
// backend's max_connections, the backend socket. It returns nil when the
// peer is refused.
func (s *udpSock) open(from netip.AddrPort, name *unix.RawSockaddrInet6, namelen uint32) *udpSess {
	u, l := s.u, s.l
	e, h := u.e, u.h
	a16 := from.Addr().As16()
	ip := net.IP(a16[:])
	// A trusted relay (accept_proxy_from), and with accept_proxy_interfaces
	// only on a socket bound to one of them: a forged relay source that
	// arrives anywhere else is an ordinary client.
	peerTrusted := l.proxyTrust.shared().TrustsIP(ip) && (len(l.proxyInterfaces) == 0 || s.viaInterface)

	if rl, ok := e.RateLimiters[l.Name]; ok && !rl.Allow() {
		logging.Warn("[RATE] Connection from %s rejected (rate limit on %s)", from, l.Name)
		if !peerTrusted {
			logging.AccessL4(from.Addr().String(), l.Protocol, s.dstPort, l4StatusRateLimited, 0, 0, 0)
		}
		return nil
	}
	now := s.per.lp.Now()
	if peerTrusted {
		// Until a valid header names a client the policy admits, the
		// session holds no session slot, no backend slot and no backend
		// socket: a source forged to look like a relay cannot hold
		// capacity. Such sessions have a cap of their own and end after
		// udpRelayPendingTimeout.
		if reason := h.udpSessions.acquirePending(); reason != "" {
			h.udpDrops.noteIP(reason, l.Name, from.Addr())
			return nil
		}
		e.ActiveConns.Add(1)
		sess := s.newSess(from, name, namelen, now)
		sess.realClientIP = from.Addr().String() // the relay until a header names the client
		sess.peerTrusted, sess.relayPending, sess.pendingHeld = true, true, true
		sess.arm()
		return sess
	}

	clientIP := from.Addr().String()
	if ok, status := h.l4Admit(l, ip); !ok {
		logging.AccessL4(clientIP, l.Protocol, s.dstPort, status, 0, 0, 0)
		return nil
	}
	sessionIP := from.Addr()
	if reason := h.udpSessions.acquire(sessionIP); reason != "" {
		h.udpDrops.noteIP(reason, l.Name, from.Addr())
		if reason == udpDropSourceLimit {
			logging.AccessL4(clientIP, l.Protocol, s.dstPort, l4StatusRateLimited, 0, 0, 0)
		}
		return nil
	}
	var limiter *ConnLimiter
	if cl, ok := e.backends().ConnLimiters[l.Backend]; ok {
		if !cl.Acquire() {
			h.udpSessions.release(sessionIP)
			logging.Warn("[CONN] listener %s: backend %s at max_connections — refusing %s", l.Name, l.Backend, from)
			logging.AccessL4(clientIP, l.Protocol, s.dstPort, l4StatusRateLimited, 0, 0, 0)
			return nil
		}
		limiter = cl
	}
	if logging.Enabled(logging.InfoLevel) {
		logging.Info("[CONN] New %s client %s -> :%d", l.Protocol, from, s.dstPort)
	}
	e.ActiveConns.Add(1)
	sess := s.newSess(from, name, namelen, now)
	sess.realClientIP = clientIP
	sess.slotHeld, sess.sessionIP, sess.limiter = true, sessionIP, limiter
	// A block added after the access check above, before the session was
	// visible to the denylist's close pass, is caught here.
	if h.denylisted(ip) {
		sess.refused = l4StatusDenylisted
		sess.close(nil)
		return nil
	}
	sess.connectBackend()
	if sess.closed {
		return nil
	}
	sess.arm()
	return sess
}

func (s *udpSock) newSess(from netip.AddrPort, name *unix.RawSockaddrInet6, namelen uint32, now int64) *udpSess {
	sess := &udpSess{sock: s, ul: s.ul, l: s.l, peer: from, name: *name, namelen: namelen, bfd: -1, start: now, lastPeer: now}
	sess.timer.F = sess
	sess.bend.s = sess
	s.sessions[from] = sess
	s.per.list.add(sess)
	return sess
}

// relayed handles a datagram of a trusted relay's session: every datagram
// carries a PROXY v2 header that names the real client. It returns the
// payload, or nil when the datagram is dropped (or the session ended).
func (sess *udpSess) relayed(data []byte) []byte {
	l := sess.l
	h := sess.sock.u.h
	keys := l.proxyTrust.shared().Keys()
	if sess.inHdr != nil && keys == nil && len(data) >= len(sess.inHdr) && bytes.Equal(data[:len(sess.inHdr)], sess.inHdr) {
		return data[len(sess.inHdr):] // the header that admitted the session, byte for byte
	}
	hdr, consumed, isProxy := parseInboundProxyV2DatagramHeader(data)
	var src net.Addr
	if hdr != nil {
		src = hdr.SourceAddr
		// With accept_proxy_key_file the header must be signed over this
		// datagram: a forged relay datagram cannot name a client.
		if err := l.proxyTrust.verify(hdr, data[consumed:], true); err != nil {
			h.udpDrops.noteIP(udpDropBadSignature, l.Name, sess.peer.Addr())
			if sess.relayPending {
				sess.close(nil)
			}
			return nil
		}
	}
	if !isProxy || src == nil {
		// A trusted relay must name the client in EVERY datagram. A
		// session no header has admitted yet ends here: it holds nothing,
		// and nothing proves its source is the relay.
		h.udpDrops.noteIP(udpDropNoProxyHeader, l.Name, sess.peer.Addr())
		if sess.relayPending {
			sess.close(nil)
		}
		return nil
	}
	if !sess.clientResolved {
		// First header: the real client is known. Admit it like a direct
		// client: access policy, the session caps charged to it and the
		// backend's max_connections. Only then does the session get its
		// backend socket.
		e := sess.sock.u.e
		sess.realClientIP = ipStrOf(src)
		sess.clientResolved = true
		sess.named = src
		ip := ipOf(src)
		ok, status := h.l4Admit(l, ip)
		if ok {
			key := addrKey(ip)
			if reason := h.udpSessions.acquire(key); reason != "" {
				ok, status = false, l4StatusRateLimited
				h.udpDrops.note(reason, l.Name, src)
			} else {
				sess.slotHeld, sess.sessionIP = true, key
			}
		}
		bv := e.backends()
		if ok {
			if cl, found := bv.ConnLimiters[l.Backend]; found {
				if cl.Acquire() {
					sess.limiter = cl
				} else {
					ok, status = false, l4StatusRateLimited
					logging.Warn("[CONN] listener %s: backend %s at max_connections — refusing %s", l.Name, l.Backend, src)
				}
			}
		}
		if !ok {
			sess.refused = status
			sess.close(nil)
			return nil
		}
		sess.relayPending = false
		if sess.pendingHeld {
			sess.pendingHeld = false
			h.udpSessions.releasePending()
		}
		// The outbound header names the client the relay named.
		if be := bv.Backends[l.Backend]; be != nil && be.SendProxyV2 {
			var buf bytes.Buffer
			if err := proxy.WriteProxyHeaderV2(&buf, src, sess.sock.local); err == nil {
				sess.proxyHdr = buf.Bytes()
			} else {
				logging.Warn("[UDP] inbound PROXY v2 rebuild failed: %v", err)
			}
		}
		if keys == nil {
			sess.inHdr = append([]byte(nil), data[:consumed]...)
		}
		sess.connectBackend()
		if sess.closed {
			return nil
		}
		sess.arm()
	} else if !sameUDPClient(sess.named, src) {
		// The session was admitted (and is attributed) for the client its
		// first header named; a datagram naming another client must not
		// ride on that admission.
		h.udpDrops.noteIP(udpDropClientChanged, l.Name, sess.peer.Addr())
		return nil
	}
	return data[consumed:]
}

// connectBackend picks the server and opens the session's backend socket
// (after a lookup off the loop when the server is a host name).
func (sess *udpSess) connectBackend() {
	l := sess.l
	e := sess.sock.u.e
	bv := e.backends() // one consistent view for this session
	balancer, ok := bv.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for listener '%s'", l.Backend, l.Name)
		sess.close(nil)
		return
	}
	backend := bv.Backends[l.Backend]
	if backend != nil && backend.BackendTLS.Enabled {
		logging.Error("[CONN] listener %s: backend %s has backend_tls enabled, which L4 listeners do not implement — refusing %s", l.Name, l.Backend, sess.peer)
		sess.close(nil)
		return
	}
	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.Backend, err)
		sess.close(nil)
		return
	}
	sess.target, sess.balancer = target, balancer
	dialTarget := target
	if _, _, err := net.SplitHostPort(dialTarget); err != nil {
		// No port on the server entry: the listener's port (1:1 mapping).
		dialTarget = fmt.Sprintf("%s:%d", dialTarget, l.Port)
	}
	// PROXY v2 with every datagram: the source is the client, the
	// destination the listener address the client sent to (not the
	// backend), so one backend socket can serve a whole port range. A
	// relay's session got its header when the relay named the client.
	if backend != nil && backend.SendProxyV2 && !sess.peerTrusted {
		var buf bytes.Buffer
		src := &net.UDPAddr{IP: sess.peer.Addr().AsSlice(), Port: int(sess.peer.Port())}
		if err := proxy.WriteProxyHeaderV2(&buf, src, sess.sock.local); err == nil {
			sess.proxyHdr = buf.Bytes()
		} else {
			logging.Warn("[UDP] PROXY v2 header build failed: %v", err)
		}
	}
	if ap, err := netip.ParseAddrPort(dialTarget); err == nil && ap.Addr().Zone() == "" {
		sess.openBackend(ap, 0)
		return
	}
	// A host name: looked up off the loop; datagrams wait meanwhile.
	lp := sess.ul.lp
	go func() {
		raddr, err := net.ResolveUDPAddr("udp", dialTarget)
		var zone uint32
		if err == nil && raddr.Zone != "" {
			if ifi, ierr := net.InterfaceByName(raddr.Zone); ierr == nil {
				zone = uint32(ifi.Index)
			} else if n, perr := strconv.Atoi(raddr.Zone); perr == nil {
				zone = uint32(n)
			}
		}
		lp.Post(func() {
			if sess.closed {
				return
			}
			if err != nil {
				logging.Error("UDP Resolve failed: %v", err)
				sess.close(err)
				return
			}
			ap := raddr.AddrPort()
			sess.openBackend(netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()), zone)
		})
	}()
}

// openBackend opens the session's connected backend socket on its loop.
func (sess *udpSess) openBackend(to netip.AddrPort, zone uint32) {
	lp := sess.ul.lp
	family := unix.AF_INET6
	var sa unix.Sockaddr = &unix.SockaddrInet6{Port: int(to.Port()), Addr: to.Addr().As16(), ZoneId: zone}
	if to.Addr().Is4() {
		family = unix.AF_INET
		sa = &unix.SockaddrInet4{Port: int(to.Port()), Addr: to.Addr().As4()}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		err = os.NewSyscallError("socket", err)
		logging.Error("UDP Dial failed: %v", err)
		sess.close(err)
		return
	}
	// DF off: the PROXY v2 header can push a full-size datagram over a
	// later hop's MTU; fragment it, don't drop it (udp_df_linux.go).
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DONT)
	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		err = &net.OpError{Op: "dial", Net: "udp", Addr: net.UDPAddrFromAddrPort(to), Err: os.NewSyscallError("connect", err)}
		logging.Error("UDP Dial failed: %v", err)
		sess.close(err)
		return
	}
	reg, err := lp.RegisterRead(fd, &sess.bend)
	if err != nil {
		unix.Close(fd)
		logging.Error("UDP backend socket: %v", err)
		sess.close(err)
		return
	}
	sess.bfd, sess.breg = fd, reg
	sess.linked = true
	sess.balancer.OnConnect(sess.target)
	sess.onConnect = true
	sess.opened = lp.Now()
	// What arrived meanwhile, one datagram at a time.
	for w := sess.wait; len(w) >= 2 && !sess.closed; {
		n := int(w[0])<<8 | int(w[1])
		sess.send(w[2 : 2+n])
		w = w[2+n:]
	}
	sess.wait = nil
	if !sess.closed {
		sess.arm()
	}
}

// forward relays one datagram of the peer to the backend.
func (sess *udpSess) forward(data []byte) {
	if sess.bfd >= 0 {
		sess.send(data)
		return
	}
	// The backend socket is not open yet (its host name is being looked
	// up): keep the datagram, up to udpWaitMax in all.
	if len(sess.wait)+2+len(data) > udpWaitMax {
		logging.Warn("[DATA] Buffer overflow from %s, closing connection", sess.peer)
		sess.close(nil)
		return
	}
	sess.wait = append(sess.wait, byte(len(data)>>8), byte(len(data)))
	sess.wait = append(sess.wait, data...)
}

// send writes one datagram to the backend socket, behind the session's
// PROXY v2 header when it has one (signed over the datagram when the
// backend has a key now).
func (sess *udpSess) send(data []byte) {
	var errno syscall.Errno
	if hdr := sess.proxyHdr; len(hdr) == 0 && len(data) > 0 {
		_, errno = ngx.Write(sess.bfd, data)
	} else if len(hdr) == 0 {
		// A relay's datagram that was all header: an empty datagram to the
		// backend, as before.
		iov := sess.ul.lp.Iov[:1]
		ngx.SetIov(&iov[0], nil)
		_, errno = ngx.Writev(sess.bfd, iov)
	} else {
		if key := sess.sendKey(); len(key) > 0 {
			signed, err := proxy.SignedHeaderBytes(hdr, key, data, time.Now())
			if err != nil {
				logging.Error("[DATA] Write failed: %v", err)
				return
			}
			hdr = signed
		}
		iov := sess.ul.lp.Iov[:2]
		ngx.SetIov(&iov[0], hdr)
		ngx.SetIov(&iov[1], data)
		_, errno = ngx.Writev(sess.bfd, iov)
	}
	switch errno {
	case 0:
	case unix.EAGAIN:
		sess.sock.u.h.udpDrops.noteIP(udpDropBackendBusy, sess.l.Name, sess.peer.Addr())
	default:
		logging.Error("[DATA] Write failed: %v", os.NewSyscallError("write", errno))
	}
}

// sendKey is the key datagrams to the backend are signed with now: the
// backend's current send_proxy_key_file (a reload may have rotated it),
// nil for none. It is read again only when the backends changed.
func (sess *udpSess) sendKey() []byte {
	v := sess.sock.u.e.view.Load()
	if v != sess.keyView {
		sess.keyView, sess.key = v, nil
		if v != nil {
			if be := v.Backends[sess.l.Backend]; be != nil {
				sess.key = be.SendProxyKey
			}
		}
	}
	return sess.key
}

// onReply takes one reply from the backend socket and queues it for the
// peer; the pass's replies go out together (flush).
func (sess *udpSess) onReply() {
	if sess.closed {
		return
	}
	ul := sess.ul
	if ul.sn == udpBatch || (ul.sn > 0 && ul.sfd != sess.sock.fd) {
		ul.flush()
	}
	i := ul.sn
	slot := ul.sbuf[i*udpMaxDatagram : (i+1)*udpMaxDatagram]
	r, errno := ngx.Read(sess.bfd, slot)
	if errno != 0 {
		if errno == unix.EAGAIN || errno == unix.EINTR {
			return
		}
		// A read error ends the session, as before (ECONNREFUSED: nothing
		// listens on the backend's port).
		sess.close(os.NewSyscallError("read", errno))
		return
	}
	sess.lastReply, sess.replied = ul.lp.Now(), true
	if r == 0 {
		// An empty reply counts as the backend's activity and is not
		// relayed, like an empty datagram of the peer (as before).
		return
	}
	ul.snames[i] = sess.name
	ul.smsgs[i].Hdr.Namelen = sess.namelen
	ul.siov[i].Base = &slot[0]
	ul.siov[i].SetLen(r)
	ul.ssess[i] = sess
	ul.sfd = sess.sock.fd
	ul.sn++
	ul.lp.RequestIterationEnd(ul.endIdx)
}

// flush sends the replies collected in this pass.
func (ul *udpLoop) flush() {
	for off := 0; off < ul.sn; {
		n, errno := ngx.Sendmmsg(ul.sfd, ul.smsgs[off:ul.sn])
		off += n
		if errno == 0 {
			if n == 0 {
				break
			}
			continue // the next call reports why the rest was not sent
		}
		// The reply at off was not sent.
		switch errno {
		case unix.EINTR:
		case unix.EAGAIN:
			// The socket's send buffer is full: this pass's remaining
			// replies are dropped, as the network would drop them.
			for ; off < ul.sn; off++ {
				if s := ul.ssess[off]; s != nil {
					s.sock.u.h.udpDrops.noteIP(udpDropClientBusy, s.l.Name, s.peer.Addr())
				}
			}
		default:
			// The peer cannot be written to: its session ends, as before.
			if s := ul.ssess[off]; s != nil {
				s.close(os.NewSyscallError("sendmsg", errno))
			}
			off++
		}
	}
	for i := 0; i < ul.sn; i++ {
		ul.ssess[i] = nil
	}
	ul.sn = 0
}

// deadline is when the session ends unless something arrives: 60 s after
// the peer's last datagram and, apart from that, 10 s after the backend
// socket opened while the backend has not answered, then 60 s after its
// last reply. A relay's session no header has admitted yet has
// udpRelayPendingTimeout from its start.
func (sess *udpSess) deadline() int64 {
	e := sess.sock.u.e
	if sess.relayPending {
		return sess.start + int64(e.udpRelayPendingTimeout)
	}
	d := sess.lastPeer + int64(udpIdleTimeout)
	if sess.bfd >= 0 {
		b := sess.opened + int64(e.udpNoReplyTimeout)
		if sess.replied {
			b = sess.lastReply + int64(udpIdleTimeout)
		}
		if b < d {
			d = b
		}
	}
	return d
}

// arm sets the session's timer to its deadline. Datagrams only move the
// deadline later, so they do not touch the timer: OnTimer looks again.
func (sess *udpSess) arm() { sess.ul.lp.ArmAt(&sess.timer, sess.deadline()) }

func (sess *udpSess) OnTimer() {
	if sess.closed {
		return
	}
	if d := sess.deadline(); sess.ul.lp.Now() < d {
		sess.ul.lp.ArmAt(&sess.timer, d)
		return
	}
	sess.close(os.ErrDeadlineExceeded)
}

// close ends the session: its backend socket, its slots and its access
// record, as the nbio engine's OnClose.
func (sess *udpSess) close(err error) {
	if sess.closed {
		return
	}
	sess.closed = true
	ul := sess.ul
	lp := ul.lp
	lp.Stop(&sess.timer)
	if sess.bfd >= 0 {
		lp.Unregister(sess.bfd, sess.breg)
		unix.Close(sess.bfd)
		sess.bfd = -1
	}
	delete(sess.sock.sessions, sess.peer)
	sess.sock.per.list.remove(sess)
	sess.wait = nil

	u := sess.sock.u
	if sess.onConnect {
		sess.balancer.OnDisconnect(sess.target)
	}
	if sess.slotHeld {
		u.h.udpSessions.release(sess.sessionIP)
	}
	if sess.pendingHeld {
		u.h.udpSessions.releasePending()
	}
	if sess.limiter != nil {
		sess.limiter.Release()
	}
	dur := time.Duration(lp.Now() - sess.start)
	if logging.Enabled(logging.InfoLevel) {
		logging.Info("[CONN] Closed %s (Dur: %v, Err: %v)", sess.peer, dur, err)
	}
	// One L4 access record: "ok" when a backend socket was opened, else
	// "no_route" or the refusal. Not for a trusted relay whose client was
	// never named: the record would blame the relay.
	if !sess.peerTrusted || sess.clientResolved {
		status := "no_route"
		switch {
		case sess.refused != "":
			status = sess.refused
		case sess.linked:
			status = "ok"
		}
		logging.AccessL4(sess.realClientIP, sess.l.Protocol, sess.sock.dstPort, status, 0, 0, float64(dur.Nanoseconds())/1e6)
	}
	u.e.ActiveConns.Done()
}
