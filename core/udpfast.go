package core

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/nvelox/ngx"
	"github.com/nvelox/ngx/relay"

	"nvelox/core/logging"
	"nvelox/lb"
	"nvelox/proxy"
)

// UDP listeners on the event loops. The relay itself is the ngx module's
// (relay.UDP): sockets, batches of datagrams, a session per peer with its
// socket to the backend, and the sessions' deadlines, without the reading
// goroutine per socket, the goroutine per session and the locks per
// datagram of udpsock.go. This file is what nvelox decides for it, as
// handler.go does for the sessions of udpsock.go: which sockets there are,
// who gets a session, what a trusted relay's header says, which server a
// session goes to, the PROXY header its backend asks for, the drops and
// the L4 access record.
//
// Sockets. A single port (and a port range with fewer ports than loops) has
// one socket per loop; a range with at least as many ports as loops has
// one socket per port, the ports dealt to the loops in turn. The sockets of
// accept_proxy_interfaces are bound to their interface the same way. Every
// socket is bound at start (before the process gives up root) and read once
// the serve gate opens.

// udpFastOff turns the event-loop UDP engine off for engines started from
// now on: the listener sockets are read by goroutines then (udpsock.go), as
// they are where event loops are not supported (tests run both).
var udpFastOff atomic.Bool

func udpFastEnabled() bool { return ngx.Supported() && !udpFastOff.Load() }

// Drops of the event-loop engine (nvelox_udp_dropped_total{reason}).
const (
	udpDropBackendBusy = "backend_busy" // the backend socket's send buffer was full
	udpDropClientBusy  = "client_busy"  // the listener socket's send buffer was full
)

func init() {
	udpDropText[udpDropBackendBusy] = "datagrams a backend socket could not take (its send buffer was full)"
	udpDropText[udpDropClientBusy] = "replies a listener socket could not take (its send buffer was full)"
}

// udpFast serves every udp listener of an engine from the event loops, and
// is the host of their relay.
type udpFast struct {
	e     *Engine
	h     *ProxyEventHandler
	relay *relay.UDP
}

// udpFastSess is what nvelox keeps of one of the relay's sessions: its
// admission, as ConnContext keeps it for the sessions of udpsock.go.
type udpFastSess struct {
	l *ListenerConfig

	realClientIP   string
	peerTrusted    bool // the peer is a trusted relay
	clientResolved bool // a header of the relay named the client
	relayPending   bool // no valid header yet: the session holds nothing
	slotHeld       bool
	sessionIP      netip.Addr
	limiter        *ConnLimiter
	named          net.Addr // the client the relay's first header named
	// inHdr is that header as it arrived, kept while headers need no
	// signature: a later datagram that starts with the same bytes names the
	// same client and needs no parsing.
	inHdr   []byte
	refused string
	// refusedQuiet: the session was refused, and its source has had its
	// line in the access log lately: this refusal gets none.
	refusedQuiet bool

	balancer  lb.Balancer
	target    string
	onConnect bool // balancer.OnConnect was called

	proxyHdr []byte       // prepended to every datagram to the backend (send_proxy_v2)
	keyView  *backendView // the backend view key and hdrWanted were read from
	key      []byte       // the backend's send_proxy_key_file key
	// hdrWanted: the backend wants the PROXY v2 header (send_proxy_v2).
	hdrWanted bool
}

// startUDPFast binds the sockets of every udp listener and serves them from
// the event loops once the serve gate opens.
func (e *Engine) startUDPFast(plan *udpInterfacePlan, h *ProxyEventHandler) error {
	n := relay.Loops()
	if n == 0 {
		return errors.New("UDP on the event loops is supported on Linux only")
	}
	u := &udpFast{e: e, h: h}
	var binds []relay.UDPBind
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
		binds = append(binds, relay.UDPBind{Addr: l.Addr, PerLoop: perLoop, ReusePort: reuse, Loop: l.rangeIndex % n, Data: l})
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
		binds = append(binds, relay.UDPBind{Addr: a, Device: plan.deviceOf[a], PerLoop: true, ReusePort: true, Data: l})
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
	r, err := relay.NewUDP(relay.UDPConfig{Sockets: binds, IdleTimeout: udpIdleTimeout, NoReplyTimeout: e.udpNoReplyTimeout, Host: u})
	if err != nil {
		return err
	}
	u.relay = r
	e.udpFast = u
	if listeners == 0 {
		return nil
	}
	logging.Info("UDP Engine Started on %d listeners (%d sockets on %d event loops)", listeners, r.Sockets(), n)
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
		r.Start()
	}()
	return nil
}

// stop closes every socket and ends every session (with its access
// record). No session starts once it returns.
func (u *udpFast) stop() {
	if u.relay != nil {
		u.relay.Stop()
	}
}

// closeSessionsOf ends the sessions whose client blocked reports (a
// trusted relay's session once a header named its client) and returns how
// many. Not for a loop goroutine: it waits for the loops.
func (u *udpFast) closeSessionsOf(blocked func(net.IP) bool) int {
	if u.relay == nil {
		return 0
	}
	var n atomic.Int64
	u.relay.Each(func(s *relay.UDPSession) {
		d := s.Data.(*udpFastSess)
		if d.peerTrusted && !d.clientResolved {
			return
		}
		if ip := net.ParseIP(d.realClientIP); ip != nil && blocked(ip) {
			s.End(nil)
			n.Add(1)
		}
	})
	return int(n.Load())
}

// Opened admits a new session for a peer, in the order of the handler's
// OnOpen: access policy on the client (a relay's client is admitted when
// its header names it), listener rate limit, session limits, the backend's
// max_connections.
func (u *udpFast) Opened(s *relay.UDPSession) bool {
	e, h := u.e, u.h
	l := s.BindData().(*ListenerConfig)
	from := s.Peer()
	a16 := from.Addr().As16()
	ip := net.IP(a16[:])
	// A trusted relay (accept_proxy_from), and with accept_proxy_interfaces
	// only on a socket bound to one of them: a forged relay source that
	// arrives anywhere else is an ordinary client.
	peerTrusted := l.proxyTrust.shared().TrustsIP(ip) && (len(l.proxyInterfaces) == 0 || s.OnDevice())

	// The access policy first, when the peer is the client: a source it
	// refuses takes nothing from the listener's rate, which is for the
	// clients the listener serves. (A relay's client is checked when its
	// header names it.)
	if !peerTrusted {
		if ok, status := h.l4Admit(l, ip); !ok {
			u.refuse(s, l, udpDropOfStatus(status), status)
			return false
		}
	}
	if rl, ok := e.RateLimiters[l.Name]; ok && !rl.Allow() {
		if peerTrusted {
			h.udpDrops.noteIP(udpDropRateLimit, l.Name, from.Addr())
		} else {
			u.refuse(s, l, udpDropRateLimit, l4StatusRateLimited)
		}
		return false
	}
	if peerTrusted {
		// Until a valid header names a client the policy admits, the
		// session holds no session slot, no backend slot and no backend
		// socket: a source forged to look like a relay cannot hold
		// capacity. Nor does such a session wait: the datagram that
		// begins it (never an empty one) has the header that admits it,
		// or ends it (Arrived).
		e.ActiveConns.Add(1)
		s.Data = &udpFastSess{l: l, realClientIP: from.Addr().String(), peerTrusted: true, relayPending: true}
		s.Inspect = true
		return true
	}

	sessionIP := from.Addr()
	if reason := h.udpSessions.acquire(sessionIP); reason != "" {
		if reason == udpDropSourceLimit {
			u.refuse(s, l, reason, l4StatusRateLimited)
		} else {
			h.udpDrops.noteIP(reason, l.Name, from.Addr())
		}
		return false
	}
	var limiter *ConnLimiter
	if cl, ok := e.backends().ConnLimiters[l.Backend]; ok {
		if !cl.Acquire() {
			h.udpSessions.release(sessionIP)
			u.refuse(s, l, udpDropBackendLimit, l4StatusRateLimited)
			return false
		}
		limiter = cl
	}
	if logging.Enabled(logging.InfoLevel) {
		logging.Info("[CONN] New %s client %s -> :%d", l.Protocol, from, s.Local().Port)
	}
	e.ActiveConns.Add(1)
	d := &udpFastSess{l: l, realClientIP: from.Addr().String(), slotHeld: true, sessionIP: sessionIP, limiter: limiter}
	s.Data = d
	// A block added after the access check above is caught here.
	if h.denylisted(ip) {
		d.refused = l4StatusDenylisted
		u.ended(s, d, nil)
		return false
	}
	return true
}

// refuse counts a new session that was refused to s's peer for reason, and
// writes the refusal to the access log (status) unless the source has had
// its line lately.
func (u *udpFast) refuse(s *relay.UDPSession, l *ListenerConfig, reason, status string) {
	ip := s.Peer().Addr()
	if u.h.udpRefused(l.udpRefusals, reason, l.Name, ip) && l.logsAccess() {
		logging.AccessL4(ip.String(), l.Protocol, s.Local().Port, status, 0, 0, 0)
	}
}

// Arrived takes a trusted relay's datagram: its PROXY v2 header names the
// client, and what follows the header is relayed; false when the datagram
// is dropped. The first valid header admits the session for the client it
// names: only then does the session get its place and its backend.
func (u *udpFast) Arrived(s *relay.UDPSession, data []byte) ([]byte, bool) {
	d := s.Data.(*udpFastSess)
	l := d.l
	h := u.h
	keys := l.proxyTrust.shared().Keys()
	if d.inHdr != nil && keys == nil && len(data) >= len(d.inHdr) && bytes.Equal(data[:len(d.inHdr)], d.inHdr) {
		return data[len(d.inHdr):], true // the header that admitted the session, byte for byte
	}
	hdr, consumed, isProxy := parseInboundProxyV2DatagramHeader(data)
	var src net.Addr
	if hdr != nil {
		src = hdr.SourceAddr
		// With accept_proxy_key_file the header must be signed over this
		// datagram: a forged relay datagram cannot name a client.
		if err := l.proxyTrust.verify(hdr, data[consumed:], true); err != nil {
			h.udpDrops.noteIP(udpDropBadSignature, l.Name, s.Peer().Addr())
			if d.relayPending {
				s.End(nil)
			}
			return nil, false
		}
	}
	if !isProxy || src == nil {
		// A trusted relay must name the client in EVERY datagram. A
		// session no header has admitted yet ends here: it holds nothing,
		// and nothing proves its source is the relay.
		h.udpDrops.noteIP(udpDropNoProxyHeader, l.Name, s.Peer().Addr())
		if d.relayPending {
			s.End(nil)
		}
		return nil, false
	}
	if !d.clientResolved {
		// First header: the real client is known. Admit it like a direct
		// client: access policy, the session caps charged to it and the
		// backend's max_connections. Only then does the session get its
		// backend socket (the relay asks for its target next).
		e := u.e
		d.realClientIP = ipStrOf(src)
		d.clientResolved = true
		d.named = src
		ip := ipOf(src)
		key := addrKey(ip)
		ok, status := h.l4Admit(l, ip)
		reason := udpDropOfStatus(status)
		if ok {
			if reason = h.udpSessions.acquire(key); reason != "" {
				ok, status = false, l4StatusRateLimited
			} else {
				d.slotHeld, d.sessionIP = true, key
			}
		}
		bv := e.backends()
		if ok {
			if cl, found := bv.ConnLimiters[l.Backend]; found {
				if cl.Acquire() {
					d.limiter = cl
				} else {
					ok, status, reason = false, l4StatusRateLimited, udpDropBackendLimit
				}
			}
		}
		if !ok {
			// A refused client's relay sends on as the client does: the
			// refusal is counted, and has its line in the access log
			// (written when the session closes) once in a while.
			d.refused = status
			d.refusedQuiet = !h.udpRefused(l.udpRefusals, reason, l.Name, key)
			s.End(nil)
			return nil, false
		}
		d.relayPending = false
		// The outbound header names the client the relay named. A session
		// whose header cannot be built gets no backend: its datagrams
		// never go out without the header the backend expects.
		if be := bv.Backends[l.Backend]; be != nil && be.SendProxyV2 {
			var buf bytes.Buffer
			if err := proxy.WriteProxyHeaderV2(&buf, src, s.Local()); err != nil {
				h.udpDrops.noteIP(udpDropNoBackendHeader, l.Name, s.Peer().Addr())
				s.End(nil)
				return nil, false
			}
			d.proxyHdr = buf.Bytes()
		}
		if keys == nil {
			d.inHdr = append([]byte(nil), data[:consumed]...)
		}
	} else if !sameUDPClient(d.named, src) {
		// The session was admitted (and is attributed) for the client its
		// first header named; a datagram naming another client must not
		// ride on that admission.
		h.udpDrops.noteIP(udpDropClientChanged, l.Name, s.Peer().Addr())
		return nil, false
	}
	return data[consumed:], true
}

// Target picks the session's server.
func (u *udpFast) Target(s *relay.UDPSession) (relay.UDPTarget, bool) {
	d := s.Data.(*udpFastSess)
	l := d.l
	bv := u.e.backends() // one consistent view for this session
	balancer, ok := bv.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for listener '%s'", l.Backend, l.Name)
		return relay.UDPTarget{}, false
	}
	backend := bv.Backends[l.Backend]
	if backend != nil && backend.BackendTLS.Enabled {
		logging.Error("[CONN] listener %s: backend %s has backend_tls enabled, which L4 listeners do not implement — refusing %s", l.Name, l.Backend, s.Peer())
		return relay.UDPTarget{}, false
	}
	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.Backend, err)
		return relay.UDPTarget{}, false
	}
	d.target, d.balancer = target, balancer
	dialTarget := target
	if _, _, err := net.SplitHostPort(dialTarget); err != nil {
		// No port on the server entry: the listener's port (1:1 mapping).
		dialTarget = fmt.Sprintf("%s:%d", dialTarget, l.Port)
	}
	// PROXY v2 with every datagram: the source is the client, the
	// destination the listener address the client sent to (not the
	// backend), so one backend socket can serve a whole port range. A
	// relay's session got its header when the relay named the client.
	if backend != nil && backend.SendProxyV2 && !d.peerTrusted {
		var buf bytes.Buffer
		peer := s.Peer()
		src := &net.UDPAddr{IP: peer.Addr().AsSlice(), Port: int(peer.Port())}
		if err := proxy.WriteProxyHeaderV2(&buf, src, s.Local()); err != nil {
			// No header, no backend: see the relay's session (Arrived).
			u.h.udpDrops.noteIP(udpDropNoBackendHeader, l.Name, peer.Addr())
			return relay.UDPTarget{}, false
		}
		d.proxyHdr = buf.Bytes()
	}
	return relay.UDPTarget{Addr: dialTarget}, true
}

// Connected: the session's backend socket is open.
func (u *udpFast) Connected(s *relay.UDPSession) {
	d := s.Data.(*udpFastSess)
	d.balancer.OnConnect(d.target)
	d.onConnect = true
}

// Outgoing gives a datagram to the backend its PROXY v2 header when the
// session has one (signed over the datagram when the backend has a key
// now).
//
// The session has the header exactly when its backend wants it now. A
// reload that changed send_proxy_v2 ends the session instead: the client's
// next datagram opens one as the backend wants it, and nothing goes out in
// the other form (bare, to a backend that now expects the header, a
// datagram could bring a header of the client's own).
func (u *udpFast) Outgoing(s *relay.UDPSession, data []byte) ([]byte, bool) {
	d := s.Data.(*udpFastSess)
	hdr := d.proxyHdr
	key, wanted := u.sendOpts(d)
	if wanted != (len(hdr) > 0) {
		u.h.udpDrops.noteIP(udpDropHeaderChanged, d.l.Name, s.Peer().Addr())
		s.End(nil)
		return nil, false
	}
	if len(hdr) > 0 && len(key) > 0 {
		signed, err := proxy.SignedHeaderBytes(hdr, key, data, time.Now())
		if err != nil {
			logging.Error("[DATA] Write failed: %v", err)
			return nil, false
		}
		hdr = signed
	}
	return hdr, true
}

// sendOpts is what the session's backend asks of its datagrams now:
// whether it wants the PROXY v2 header (send_proxy_v2), and the key the
// header is signed with (send_proxy_key_file, nil for none). A reload may
// have changed either; they are read again only when the backends changed.
func (u *udpFast) sendOpts(d *udpFastSess) (key []byte, header bool) {
	v := u.e.view.Load()
	if v != d.keyView {
		d.keyView, d.key, d.hdrWanted = v, nil, false
		if v != nil {
			if be := v.Backends[d.l.Backend]; be != nil {
				d.key, d.hdrWanted = be.SendProxyKey, be.SendProxyV2
			}
		}
	}
	return d.key, d.hdrWanted
}

// Dropped counts a datagram a full socket did not take.
func (u *udpFast) Dropped(s *relay.UDPSession, toPeer bool) {
	reason := udpDropBackendBusy
	if toPeer {
		reason = udpDropClientBusy
	}
	u.h.udpDrops.noteIP(reason, s.Data.(*udpFastSess).l.Name, s.Peer().Addr())
}

// Failed logs an error of a session.
func (u *udpFast) Failed(s *relay.UDPSession, what relay.UDPFailure, err error) {
	switch what {
	case relay.UDPResolveFailed:
		logging.Error("UDP Resolve failed: %v", err)
	case relay.UDPDialFailed:
		logging.Error("UDP Dial failed: %v", err)
	case relay.UDPServerSocketFailed:
		logging.Error("UDP backend socket: %v", err)
	case relay.UDPWriteFailed:
		logging.Error("[DATA] Write failed: %v", err)
	case relay.UDPWaitFull:
		logging.Warn("[DATA] Buffer overflow from %s, closing connection", s.Peer())
	}
}

// Ended releases what the session held and writes its access record, as
// the handler's OnClose.
func (u *udpFast) Ended(s *relay.UDPSession, err error) {
	u.ended(s, s.Data.(*udpFastSess), err)
}

func (u *udpFast) ended(s *relay.UDPSession, d *udpFastSess, err error) {
	if d.onConnect {
		d.balancer.OnDisconnect(d.target)
	}
	if d.slotHeld {
		u.h.udpSessions.release(d.sessionIP)
	}
	if d.limiter != nil {
		d.limiter.Release()
	}
	dur := s.Took()
	if logging.Enabled(logging.InfoLevel) {
		logging.Info("[CONN] Closed %s (Dur: %v, Err: %v)", s.Peer(), dur, err)
	}
	// One L4 access record: "ok" when a backend socket was opened, else
	// "no_route" or the refusal. Not for a trusted relay whose client was
	// never named: the record would blame the relay.
	if (!d.peerTrusted || d.clientResolved) && !d.refusedQuiet {
		status := "no_route"
		switch {
		case d.refused != "":
			status = d.refused
		case s.Linked():
			status = "ok"
		}
		if d.l.logsAccess() {
			logging.AccessL4(d.realClientIP, d.l.Protocol, s.Local().Port, status, 0, 0, float64(dur.Nanoseconds())/1e6)
		}
	}
	u.e.ActiveConns.Done()
}

// SocketFailed logs a listener socket that could not be served.
func (u *udpFast) SocketFailed(data any, err error) {
	logging.Error("[UDP] listener %s: %v", data.(*ListenerConfig).Name, err)
}
