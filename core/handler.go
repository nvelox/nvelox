package core

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"
	"nvelox/proxy"

	"github.com/lesismal/nbio"
)

// ProxyEventHandler holds the L4 accept-time gating shared by every L4 path
// and is the nbio event handler for UDP. Plain TCP connections are served by
// serveTCP (l4tcp.go) on their own goroutines, not through nbio.
type ProxyEventHandler struct {
	engine      *Engine
	listenerMap map[string]*ListenerConfig
	sessions    sync.Map // *nbio.Conn -> *ConnContext (thread-safe session storage)
	udpSessions *udpSessionLimiter
	udpDrops    *udpDrops
}

func NewProxyEventHandler(e *Engine) *ProxyEventHandler {
	lm := make(map[string]*ListenerConfig)
	for _, l := range e.Listeners {
		_, port, _ := net.SplitHostPort(l.Addr)
		// Store with protocol prefix to distinguish TCP/UDP on same port
		key := fmt.Sprintf("%s:%s", l.Protocol, port)
		lm[key] = l
		// Also store by addr for exact matches if needed, prefixed with proto
		lm[fmt.Sprintf("%s:%s", l.Protocol, l.Addr)] = l
	}

	return &ProxyEventHandler{
		engine:      e,
		listenerMap: lm,
		udpSessions: newUDPSessionLimiter(e.udpMaxSessions, e.udpMaxSessionsPerIP),
		udpDrops:    newUDPDrops(e.Metrics),
	}
}

type ConnContext struct {
	IsBackend     bool
	PeerConn      net.Conn
	StartTime     time.Time
	Buffer        []byte      // Buffer for data received before backend is connected
	BackendServer string      // Original value from balancer.Next() (matches conns map key)
	BalancerRef   lb.Balancer // Reference for OnDisconnect in OnClose
	// L4 access logging (one record per connection at close, via logging.AccessL4):
	// the protocol, the dialed (listener) port, and the REAL client — the
	// PROXY-v2-decoded source behind a trusted relay, NOT the relay. Proto
	// and DstPort are set once at OnOpen; RealClientIP defaults to the peer and is
	// upgraded to the parsed client when a trusted inbound PROXY-v2 header resolves.
	// PeerTrusted: the immediate peer is a trusted relay (its inbound PROXY-v2 header
	// names the real client). ClientResolved: that header was actually parsed, so
	// RealClientIP is the real client. When PeerTrusted && !ClientResolved we must NOT
	// emit an L4 record — attributing it to the relay could get the relay itself
	// blocked by whatever acts on the access log (cutting off all its clients).
	Proto          string
	DstPort        int
	RealClientIP   string
	PeerTrusted    bool
	ClientResolved bool
	// ProxyHeader, when non-nil, is prepended to each datagram written to
	// PeerConn. Built once per session in connectBackendUDP when the
	// backend has send_proxy_v2: true (or, for StripInbound conns, in OnData
	// once the real client is recovered from the inbound header).
	ProxyHeader []byte
	// SendProxyKey (send_proxy_key_file): sign ProxyHeader over each
	// datagram it is sent with.
	SendProxyKey []byte
	// StripInbound (UDP): this listener trusts an inbound PROXY-v2 header from
	// the immediate peer (a relay). OnData then
	// strips a per-datagram DGRAM header and builds the OUTBOUND header from the
	// parsed REAL client instead of the relay's address. SendProxyV2/LocalAddr are
	// snapshotted so OnData can build that header (src = real client, dst =
	// LocalAddr = the dedicated port the relay dialed).
	StripInbound bool
	SendProxyV2  bool
	LocalAddr    net.Addr
	Mu           sync.Mutex

	// UDP session bookkeeping, released by OnClose. listener is the session's
	// listener (OnData admits a relayed client against it). slotHeld: the
	// session holds a session slot, charged to sessionIP in the per-IP limit.
	// relayPending: a trusted relay's session whose client no valid header
	// has named yet — it holds no slot, no backend slot and no backend
	// connection (H5). limiter is the backend max_connections slot the
	// session holds, if any. resolvedSrc is the client a trusted relay's
	// first header named. refused is the access-log status when the session
	// was refused after OnOpen. closed is set by OnClose so a late OnData
	// cannot charge a released session.
	listener     *ListenerConfig
	slotHeld     bool
	relayPending bool
	sessionIP    netip.Addr
	limiter      *ConnLimiter
	resolvedSrc  net.Addr
	refused      string
	closed       bool
	// pendingHeld: the session holds a place among the relay sessions
	// waiting for a header (udpSessionLimiter.acquirePending), and
	// pendingTimer ends it if no header comes. viaInterface: the session
	// arrived on a socket bound to one of the listener's
	// accept_proxy_interfaces (part of its backend-socket key).
	pendingHeld  bool
	pendingTimer *time.Timer
	viaInterface bool
}

func (h *ProxyEventHandler) setCtx(c *nbio.Conn, ctx *ConnContext) {
	h.sessions.Store(c, ctx)
	c.SetSession(ctx) // also set on nbio for the session != nil guard in OnOpen
}

func (h *ProxyEventHandler) getCtx(c *nbio.Conn) *ConnContext {
	v, ok := h.sessions.Load(c)
	if !ok {
		return nil
	}
	return v.(*ConnContext)
}

func (h *ProxyEventHandler) deleteCtx(c *nbio.Conn) {
	h.sessions.Delete(c)
}

// OnOpen admits a new UDP session (one client source ip:port on a listener).
// Order: listener rate limit -> access policy on the client (direct peers;
// a trusted relay's client is admitted in OnData once its PROXY header names
// it) -> session limits -> backend max_connections -> backend socket.
// Every refusal closes through closeOnOpen, never synchronously.
func (h *ProxyEventHandler) OnOpen(c *nbio.Conn) { h.onOpen(c, false) }

// onOpen is OnOpen for a session that arrived on a socket bound to one of the
// listener's accept_proxy_interfaces (viaListedInterface) or not.
func (h *ProxyEventHandler) onOpen(c *nbio.Conn, viaListedInterface bool) {
	// Backend connections from DialAsync already have session set in callback
	if h.getCtx(c) != nil {
		return
	}
	// Nothing is served before the process gave up root (Engine.HoldServing).
	if h.engine != nil && !h.engine.serveGate.Wait(h.engine.runDone()) {
		closeOnOpen(c)
		return
	}

	localAddr := c.LocalAddr()
	if localAddr == nil {
		return
	}

	// Avoid calling net.UDPAddr.String() (or .IP's appendTo) here — nbio
	// v1.6.8 can concurrently dupStdConn the same IP slice backing the
	// address, tripping the race detector. Reading Port (an int field) on
	// the concrete type sidesteps that slice walk entirely.
	l := h.findListenerForAddr(localAddr)
	if l == nil {
		return
	}

	dstPort := portOf(localAddr)
	// Is the immediate peer a TRUSTED relay (accept_proxy_from)? Its inbound PROXY-v2
	// header names the REAL client — but that isn't parsed until after the backend
	// dial, so until then an L4 record can only carry the relay IP. Track it so the
	// emit paths can suppress a record that would blame the relay for its clients.
	// With accept_proxy_interfaces the datagram must also have arrived on one
	// of them, that is on a socket bound to one (the interface engine,
	// udpdevice.go): a forged relay source arriving anywhere else is an
	// ordinary client.
	peerTrusted := l.proxyTrust.trusts(c.RemoteAddr()) &&
		(len(l.proxyInterfaces) == 0 || viaListedInterface)

	// Check rate limit
	if rl, ok := h.engine.RateLimiters[l.Name]; ok {
		if !rl.Allow() {
			logging.Warn("[RATE] Connection from %s rejected (rate limit on %s)", c.RemoteAddr(), l.Name)
			// Attribute the rejection only when the peer IS the client (untrusted/direct).
			// For a trusted relay the real client is unknowable here (no header parsed
			// yet), so emitting would misattribute the relay — suppress it.
			if !peerTrusted {
				logging.AccessL4(ipStrOf(c.RemoteAddr()), l.Protocol, dstPort, l4StatusRateLimited, 0, 0, 0)
			}
			closeOnOpen(c)
			return
		}
	}

	// A trusted relay names the real client in the PROXY-v2 header of every
	// datagram, which OnData checks. Until a valid header names a client the
	// policy admits, the session holds no session slot, no backend slot and
	// no backend connection (H5): a datagram without one ends it at once, so
	// a source forged to look like a relay cannot hold capacity. The timer
	// ends a session whose first datagram never reaches OnData.
	if peerTrusted {
		// Such sessions hold no session slot, so they have a cap of their
		// own; a session no header reaches (an empty datagram) ends after
		// udpRelayPendingTimeout.
		if reason := h.udpSessions.acquirePending(); reason != "" {
			h.udpDrops.note(reason, l.Name, c.RemoteAddr())
			closeOnOpen(c)
			return
		}
		h.engine.ActiveConns.Add(1)
		relayCtx := &ConnContext{
			IsBackend:    false,
			StartTime:    time.Now(),
			Proto:        l.Protocol,
			DstPort:      dstPort,
			RealClientIP: ipStrOf(c.RemoteAddr()), // the relay until a header names the client
			PeerTrusted:  true,
			StripInbound: true,
			LocalAddr:    c.LocalAddr(),
			listener:     l,
			relayPending: true,
			pendingHeld:  true,
			viaInterface: viaListedInterface,
		}
		h.setCtx(c, relayCtx)
		relayCtx.Mu.Lock()
		relayCtx.pendingTimer = time.AfterFunc(h.engine.udpRelayPendingTimeout, func() {
			relayCtx.Mu.Lock()
			pending := relayCtx.relayPending && !relayCtx.closed
			relayCtx.Mu.Unlock()
			if pending {
				_ = c.Close()
			}
		})
		relayCtx.Mu.Unlock()
		return
	}

	// Access policy (ip_denylist, the dynamic admin-API denylist,
	// ip_allowlist, acl) on the immediate peer, which IS the client.
	ip := ipOf(c.RemoteAddr())
	if ok, status := h.l4Admit(l, ip); !ok {
		logging.AccessL4(ipStrOf(c.RemoteAddr()), l.Protocol, dstPort, status, 0, 0, 0)
		closeOnOpen(c)
		return
	}
	sessionIP := addrKey(ip)

	// Session limits: a global cap and a per-client-IP cap.
	if reason := h.udpSessions.acquire(sessionIP); reason != "" {
		h.udpDrops.note(reason, l.Name, c.RemoteAddr())
		if reason == udpDropSourceLimit {
			logging.AccessL4(ipStrOf(c.RemoteAddr()), l.Protocol, dstPort, l4StatusRateLimited, 0, 0, 0)
		}
		closeOnOpen(c)
		return
	}
	// Backend max_connections: one slot per UDP session, released in OnClose.
	var limiter *ConnLimiter
	if cl, ok := h.engine.backends().ConnLimiters[l.Backend]; ok {
		if !cl.Acquire() {
			h.udpSessions.release(sessionIP)
			logging.Warn("[CONN] listener %s: backend %s at max_connections — refusing %s", l.Name, l.Backend, c.RemoteAddr())
			logging.AccessL4(ipStrOf(c.RemoteAddr()), l.Protocol, dstPort, l4StatusRateLimited, 0, 0, 0)
			closeOnOpen(c)
			return
		}
		limiter = cl
	}

	logging.Info("[CONN] New %s client %s -> :%d", l.Protocol, c.RemoteAddr(), dstPort)

	h.engine.ActiveConns.Add(1)

	clientCtx := &ConnContext{
		IsBackend:    false,
		StartTime:    time.Now(),
		Proto:        l.Protocol,
		DstPort:      dstPort,
		RealClientIP: ipStrOf(c.RemoteAddr()),
		listener:     l,
		slotHeld:     true,
		sessionIP:    sessionIP,
		limiter:      limiter,
		viaInterface: viaListedInterface,
	}
	h.setCtx(c, clientCtx)
	// A block added after the access check above, before the session was
	// visible to the denylist's close pass (closeSessionsOf), is caught here.
	if h.denylisted(ip) {
		clientCtx.Mu.Lock()
		clientCtx.refused = l4StatusDenylisted
		clientCtx.Mu.Unlock()
		closeOnOpen(c)
		return
	}

	h.connectBackend(c, l)
}

// closeOnOpen closes a UDP session being REJECTED from OnOpen (or failing
// inside it). It must NOT close synchronously: nbio calls OnOpen from the
// poller while it holds the UDP listener's (parent) conn mutex
// (ReadAndGetConn -> readUDP -> getConn -> onOpen), and closing a child conn
// takes that same mutex to remove itself from the parent's table
// (udpConn.Close). A synchronous Close therefore deadlocks the poller
// goroutine, and every UDP listener on that poller stops until a restart.
// Conn.Execute is NOT a fix here: nvelox runs nbio with the default (inline)
// Engine.Execute, which runs the job synchronously in place. A real goroutine
// blocks on the mutex until OnOpen returns and the poller releases it, then
// closes through nbio's normal path (OnClose included). (OnData runs after
// the poller released the mutex, so closing there is synchronous-safe.)
func closeOnOpen(c *nbio.Conn) {
	go func() { _ = c.Close() }()
}

func (h *ProxyEventHandler) OnClose(c *nbio.Conn, err error) {
	ctx := h.getCtx(c)
	if ctx == nil {
		return
	}
	h.deleteCtx(c)

	ctx.Mu.Lock()
	peer := ctx.PeerConn
	backendServer := ctx.BackendServer
	balancerRef := ctx.BalancerRef
	isBackend := ctx.IsBackend
	proto := ctx.Proto
	dstPort := ctx.DstPort
	realClientIP := ctx.RealClientIP
	peerTrusted := ctx.PeerTrusted
	clientResolved := ctx.ClientResolved
	refused := ctx.refused
	slotHeld, sessionIP, limiter := ctx.slotHeld, ctx.sessionIP, ctx.limiter
	pendingHeld := ctx.pendingHeld
	ctx.pendingHeld = false
	if ctx.pendingTimer != nil {
		ctx.pendingTimer.Stop()
	}
	ctx.PeerConn = nil // prevent double-close
	ctx.closed = true  // a late OnData must not charge the released session
	ctx.limiter = nil
	ctx.Mu.Unlock()

	if peer != nil {
		peer.Close()
	}

	// Notify balancer of disconnection (for LeastConn tracking)
	if !isBackend && backendServer != "" && balancerRef != nil {
		balancerRef.OnDisconnect(backendServer)
	}

	if !isBackend {
		if slotHeld {
			h.udpSessions.release(sessionIP)
		}
		if pendingHeld {
			h.udpSessions.releasePending()
		}
		if limiter != nil {
			limiter.Release()
		}
		logging.Info("[CONN] Closed %s (Dur: %v, Err: %v)", c.RemoteAddr(), time.Since(ctx.StartTime), err)
		// L4 access record (mirrors AccessHTTP for HTTP). A backend was linked iff
		// peer!=nil at close → "ok"; otherwise the connection never reached a backend
		// → "no_route" (the L4 analogue of a 404). A session refused after OnOpen
		// (a relayed client denied in OnData) records that refusal instead. Bytes
		// are not accumulated in v1.
		// SUPPRESS when the peer is a trusted relay whose real client we never resolved
		// (connection died before its inbound PROXY-v2 header was read): attributing the
		// record to the relay could get the relay itself blocked. A direct
		// (untrusted) peer IS the client, so it always emits.
		if !peerTrusted || clientResolved {
			status := "no_route"
			switch {
			case refused != "":
				status = refused
			case peer != nil:
				status = "ok"
			}
			durMs := float64(time.Since(ctx.StartTime).Nanoseconds()) / 1e6
			logging.AccessL4(realClientIP, proto, dstPort, status, 0, 0, durMs)
		}
		h.engine.ActiveConns.Done()
	}
}

func (h *ProxyEventHandler) OnData(c *nbio.Conn, data []byte) {
	ctx := h.getCtx(c)
	if ctx == nil {
		return
	}

	// UDP behind a relay: when this listener trusts the immediate peer
	// (accept_proxy_from), each datagram carries a leading PROXY-v2 DGRAM
	// header naming the REAL client. Strip it and build the OUTBOUND send_proxy_v2
	// header from that real client (once — it's stable per conn), so the backend
	// sees the client, not the relay. The header's dst is our
	// LocalAddr (the dedicated port the relay dialed) — already correct.
	ctx.Mu.Lock()
	stripInbound := ctx.StripInbound
	localAddr := ctx.LocalAddr
	l := ctx.listener
	ctx.Mu.Unlock()
	if stripInbound {
		hdr, consumed, isProxy := parseInboundProxyV2DatagramHeader(data)
		var src net.Addr
		if hdr != nil {
			src = hdr.SourceAddr
			// With accept_proxy_key_file the header must be signed over this
			// datagram: a forged relay datagram cannot name a client.
			if err := l.proxyTrust.verify(hdr, data[consumed:]); err != nil {
				h.udpDrops.note(udpDropBadSignature, listenerName(l), c.RemoteAddr())
				ctx.Mu.Lock()
				pending := ctx.relayPending
				ctx.Mu.Unlock()
				if pending {
					c.Close()
				}
				return
			}
		}
		if !isProxy || src == nil {
			// A trusted relay must name the client in EVERY datagram. One
			// without a (valid, non-LOCAL) header would be forwarded with no
			// client to check against the access policy or to attribute in
			// the access log: drop it. A session no header has admitted yet
			// ends here (H5): it holds nothing, and nothing proves its
			// source is the relay.
			h.udpDrops.note(udpDropNoProxyHeader, listenerName(l), c.RemoteAddr())
			ctx.Mu.Lock()
			pending := ctx.relayPending
			ctx.Mu.Unlock()
			if pending {
				c.Close()
			}
			return
		}
		data = data[consumed:]
		admitted := false
		ctx.Mu.Lock()
		if ctx.closed {
			ctx.Mu.Unlock()
			return
		}
		if !ctx.ClientResolved {
			// First datagram: the real UDP client (not the relay) is known.
			// Admit it like a direct client — access policy (static lists,
			// ACL, dynamic denylist), the session caps charged to it and the
			// backend's max_connections — and record it for the access log.
			// Only then does the session get its backend (H5).
			ctx.RealClientIP = ipStrOf(src)
			ctx.ClientResolved = true
			ctx.resolvedSrc = src
			ip := ipOf(src)
			ok, status := h.l4Admit(l, ip)
			if ok {
				key := addrKey(ip)
				if reason := h.udpSessions.acquire(key); reason != "" {
					ok, status = false, l4StatusRateLimited
					h.udpDrops.note(reason, listenerName(l), src)
				} else {
					ctx.slotHeld, ctx.sessionIP = true, key
				}
			}
			bv := h.engine.backends()
			if ok {
				if cl, found := bv.ConnLimiters[l.Backend]; found {
					if cl.Acquire() {
						ctx.limiter = cl
					} else {
						ok, status = false, l4StatusRateLimited
						logging.Warn("[CONN] listener %s: backend %s at max_connections — refusing %s", l.Name, l.Backend, src)
					}
				}
			}
			if !ok {
				ctx.refused = status
				ctx.Mu.Unlock()
				c.Close()
				return
			}
			ctx.relayPending = false
			if ctx.pendingHeld {
				ctx.pendingHeld = false
				h.udpSessions.releasePending()
			}
			if ctx.pendingTimer != nil {
				ctx.pendingTimer.Stop()
			}
			admitted = true
			// The outbound header names the client the relay named; the
			// backend connection (dialed below) sends it with every datagram.
			if be := bv.Backends[l.Backend]; be != nil && be.SendProxyV2 {
				var buf bytes.Buffer
				if err := proxy.WriteProxyHeaderV2(&buf, src, localAddr); err == nil {
					ctx.ProxyHeader = buf.Bytes()
				} else {
					logging.Warn("[UDP] inbound PROXY v2 rebuild failed: %v", err)
				}
			}
		} else if !sameUDPClient(ctx.resolvedSrc, src) {
			// The session was admitted (and is attributed) for the client
			// its first header named; a datagram naming another client must
			// not ride on that admission.
			ctx.Mu.Unlock()
			h.udpDrops.note(udpDropClientChanged, listenerName(l), c.RemoteAddr())
			return
		}
		ctx.Mu.Unlock()
		if admitted {
			// This datagram is buffered below until the backend connects
			// (or written at once to a pooled backend connection).
			h.connectBackend(c, l)
		}
	}

	ctx.Mu.Lock()
	if ctx.PeerConn != nil {
		peer := ctx.PeerConn
		hdr, key := ctx.ProxyHeader, ctx.SendProxyKey
		ctx.Mu.Unlock()
		_, err := writeWithProxy(peer, hdr, key, data)
		if err != nil {
			logging.Error("[DATA] Write failed: %v", err)
		}
	} else {
		// Buffer data until backend connects (max 1MB to prevent DoS)
		const maxBufferSize = 1 << 20 // 1MB
		if len(ctx.Buffer)+len(data) > maxBufferSize {
			ctx.Mu.Unlock()
			logging.Warn("[DATA] Buffer overflow from %s, closing connection", c.RemoteAddr())
			c.Close()
			return
		}
		ctx.Buffer = append(ctx.Buffer, data...)
		ctx.Mu.Unlock()
	}
}

// sameUDPClient reports whether two PROXY-v2 sources name the same client
// (IP and port).
func sameUDPClient(a, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	if ok1 && ok2 {
		return ua.Port == ub.Port && ua.IP.Equal(ub.IP)
	}
	return a != nil && b != nil && a.String() == b.String()
}

func listenerName(l *ListenerConfig) string {
	if l == nil {
		return ""
	}
	return l.Name
}

func (h *ProxyEventHandler) connectBackend(clientConn *nbio.Conn, l *ListenerConfig) {
	// Runs inside OnOpen (a direct client) or inside a relayed session's
	// first OnData: every failure closes through closeOnOpen (a synchronous
	// Close inside OnOpen deadlocks the nbio poller — see closeOnOpen).
	bv := h.engine.backends() // one consistent view for this session (H6)
	balancer, ok := bv.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for listener '%s'", l.Backend, l.Name)
		closeOnOpen(clientConn)
		return
	}

	// Get backend config to check SendProxyV2
	backend := bv.Backends[l.Backend]
	if backend != nil && backend.BackendTLS.Enabled {
		// backend_tls is implemented on the HTTP path only; never send
		// plaintext to a backend configured for TLS (config load refuses
		// this pairing; a reload can still change a backend under a running
		// L4 listener).
		logging.Error("[CONN] listener %s: backend %s has backend_tls enabled, which L4 listeners do not implement — refusing %s", l.Name, l.Backend, clientConn.RemoteAddr())
		closeOnOpen(clientConn)
		return
	}

	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.Backend, err)
		closeOnOpen(clientConn)
		return
	}

	// Store original balancer key before target normalization (must match conns map key)
	clientCtx := h.getCtx(clientConn)
	clientCtx.Mu.Lock()
	clientCtx.BackendServer = target
	clientCtx.BalancerRef = balancer
	clientCtx.Mu.Unlock()

	// Normalize target for dialing
	dialTarget := target
	if _, _, err := net.SplitHostPort(dialTarget); err != nil {
		// Valid assumption: missing port, use listener port (1:1 mapping)
		dialTarget = fmt.Sprintf("%s:%d", dialTarget, l.Port)
	}

	// nbio serves UDP only; plain TCP runs serveTCP (l4tcp.go).
	h.connectBackendUDP(clientConn, dialTarget, backend, l)
}

func (h *ProxyEventHandler) connectBackendUDP(clientConn *nbio.Conn, target string, backend *config.Backend, l *ListenerConfig) {
	clientCtx := h.getCtx(clientConn)

	sendProxyV2 := backend != nil && backend.SendProxyV2
	// acceptInbound: this listener trusts an inbound PROXY-v2 header from the
	// immediate peer (a relay in accept_proxy_from). When set, the
	// REAL client isn't known until the first inbound datagram is parsed, so we do
	// NOT build the outbound header here — OnData strips the inbound header and
	// builds the outbound one from the parsed real client. Untrusted peers skip
	// this entirely: their headers are never parsed.
	// Decided once, in OnOpen (address and, with accept_proxy_interfaces,
	// arrival interface): a session OnOpen did not trust never strips a header.
	clientCtx.Mu.Lock()
	acceptInbound := clientCtx.PeerTrusted
	clientCtx.Mu.Unlock()

	// Snapshot what OnData needs to do the strip + outbound-header build. Set
	// before any datagram of this session is forwarded (this runs inside
	// OnOpen, or inside the relayed session's first OnData).
	clientCtx.Mu.Lock()
	clientCtx.StripInbound = acceptInbound
	clientCtx.SendProxyV2 = sendProxyV2
	clientCtx.SendProxyKey = nil
	if backend != nil {
		clientCtx.SendProxyKey = backend.SendProxyKey
	}
	clientCtx.LocalAddr = clientConn.LocalAddr()
	clientCtx.Mu.Unlock()

	// Build PROXY v2 datagram prefix once per session if the backend has
	// send_proxy_v2: true AND we are NOT accepting an inbound header. src = real
	// external client; dst = the address the CLIENT sent to (clientConn.LocalAddr
	// = our listener, i.e. the original dedicated UDP port) — NOT the backend
	// target. This lets the backend MUX a whole UDP port range on one socket and
	// recover the dialed port from the header.
	var proxyHdr []byte
	if sendProxyV2 && !acceptInbound {
		var buf bytes.Buffer
		if err := proxy.WriteProxyHeaderV2(&buf, clientConn.RemoteAddr(), clientConn.LocalAddr()); err == nil {
			proxyHdr = buf.Bytes()
		} else {
			logging.Warn("[UDP] PROXY v2 header build failed: %v", err)
		}
	}

	// Check UDP pool for existing session (session affinity).
	// The key includes the LOCAL (dedicated) port the client hit — portOf() reads
	// the int Port field race-safely (vs .String() which walks the IP slice that
	// nbio races on). Under a range-funnel ALL dedicated ports share one backend
	// name, so without the local port two clients with the same source IP:port
	// (CGNAT) hitting DIFFERENT dedicated ports would collide on one backend conn
	// and their replies would cross.
	//
	// With accept_proxy_interfaces one relay address can have two sessions
	// on one port at once: a trusted one that arrived on a listed interface
	// and an ordinary one (perhaps a forged source) that arrived elsewhere.
	// The arrival path is part of the key, so they never share a backend
	// socket (one could write into, or close, the other's flow).
	poolKey := fmt.Sprintf("%s|%d|%t|%s", clientConn.RemoteAddr().String(), portOf(clientConn.LocalAddr()), clientCtx.viaInterface, clientCtx.BackendServer)
	if session := h.engine.UDPPool.Get(poolKey); session != nil {
		// Reuse existing backend connection
		clientCtx.Mu.Lock()
		clientCtx.PeerConn = session.BackendConn
		if !acceptInbound {
			clientCtx.ProxyHeader = proxyHdr // else OnData builds it from the real client
		}
		if clientCtx.BalancerRef != nil {
			clientCtx.BalancerRef.OnConnect(clientCtx.BackendServer)
		}
		if len(clientCtx.Buffer) > 0 {
			writeWithProxy(session.BackendConn, clientCtx.ProxyHeader, clientCtx.SendProxyKey, clientCtx.Buffer)
			clientCtx.Buffer = nil
		}
		clientCtx.Mu.Unlock()
		return
	}

	noReply := h.engine.udpNoReplyTimeout
	go func() {
		// Resolve and dial UDP
		raddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			logging.Error("UDP Resolve failed: %v", err)
			clientConn.Close()
			return
		}

		backendConn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			logging.Error("UDP Dial failed: %v", err)
			clientConn.Close()
			return
		}
		// DF off: the PROXY v2 header can push a full-size datagram over a later
		// hop's MTU (a 1,450 B VXLAN pod network); fragment it, don't drop it.
		setUDPNoDF(backendConn)
		reader, err := newUDPBackendReader(backendConn)
		if err != nil {
			logging.Error("UDP backend socket: %v", err)
			backendConn.Close()
			clientConn.Close()
			return
		}

		// Link client to backend — unless the session already ended while we
		// dialed (OnClose ran: e.g. a relayed client refused on its first
		// datagram). Then the socket is dropped now, not after the TTL, and
		// never reaches the pool. Checked and linked under the session lock,
		// so OnClose either sees PeerConn and closes it or we see closed.
		clientCtx.Mu.Lock()
		if clientCtx.closed {
			clientCtx.Mu.Unlock()
			backendConn.Close()
			return
		}
		// Store in pool for session affinity
		session := &UDPSession{
			BackendConn: backendConn,
			Target:      target,
			LastActive:  time.Now(),
		}
		h.engine.UDPPool.Put(poolKey, session)
		clientCtx.PeerConn = backendConn
		if !acceptInbound {
			clientCtx.ProxyHeader = proxyHdr // else OnData builds it from the real client
		}

		// Notify balancer of new connection (for LeastConn tracking)
		if clientCtx.BalancerRef != nil {
			clientCtx.BalancerRef.OnConnect(clientCtx.BackendServer)
		}

		// Flush any buffered data
		if len(clientCtx.Buffer) > 0 {
			_, writeErr := writeWithProxy(backendConn, clientCtx.ProxyHeader, clientCtx.SendProxyKey, clientCtx.Buffer)
			if writeErr != nil {
				logging.Error("Failed to flush UDP buffer: %v", writeErr)
				clientCtx.Mu.Unlock()
				clientConn.Close()
				backendConn.Close()
				return
			}
			clientCtx.Buffer = nil
		}
		clientCtx.Mu.Unlock()

		// Read from backend and write to client. Until the backend's first
		// reply the session lives udpNoReplyTimeout (a one-datagram or spoofed
		// source frees its slot quickly), then udpIdleTimeout after each reply.
		// Replies up to 65535 B (the max UDP payload) are relayed whole: a 4096
		// buffer silently truncated any backend datagram >4 KB (the kernel
		// discards the remainder of that datagram) — large DNS/QUIC/jumbo
		// responses lost data.
		timeout := noReply
		var writeErr error
		deliver := func(b []byte) { _, writeErr = clientConn.Write(b) }
		for {
			backendConn.SetReadDeadline(time.Now().Add(timeout))
			if err := reader.read(deliver); err != nil || writeErr != nil {
				h.engine.UDPPool.Remove(poolKey)
				clientConn.Close()
				return
			}
			timeout = udpIdleTimeout

			// Update session activity
			session.mu.Lock()
			session.LastActive = time.Now()
			session.mu.Unlock()
		}
	}()
}

func (h *ProxyEventHandler) findListener(network, localAddr string) *ListenerConfig {
	_, port, _ := net.SplitHostPort(localAddr)
	// Lookup with protocol prefix
	key := fmt.Sprintf("%s:%s", network, port)
	if l, ok := h.listenerMap[key]; ok {
		return l
	}
	return nil
}

// findListenerForAddr is the race-safe variant of findListener: it reads the
// port directly from the concrete *net.UDPAddr / *net.TCPAddr Port field
// (an int, a scalar word) instead of calling .String() which walks the IP
// byte slice that nbio@v1.6.8 races on during UDP conn setup.
func (h *ProxyEventHandler) findListenerForAddr(addr net.Addr) *ListenerConfig {
	var network string
	var port int
	switch a := addr.(type) {
	case *net.UDPAddr:
		network = "udp"
		port = a.Port
	case *net.TCPAddr:
		network = "tcp"
		port = a.Port
	default:
		// Fallback to the string-based lookup for unknown addr types.
		return h.findListener(addr.Network(), addr.String())
	}
	key := fmt.Sprintf("%s:%d", network, port)
	if l, ok := h.listenerMap[key]; ok {
		return l
	}
	return nil
}

// portOf returns the Port field of a *net.UDPAddr / *net.TCPAddr, or 0 if
// the address is of an unknown type. Used for logging so we don't call
// Addr.String() (which walks the IP slice and races with nbio's conn setup).
func portOf(addr net.Addr) int {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.Port
	case *net.TCPAddr:
		return a.Port
	}
	return 0
}

// ipStrOf is the string form of the existing ipOf(addr) net.IP helper, "" when the
// IP can't be resolved — used for the L4 access record's client field.
func ipStrOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if ip := ipOf(addr); ip != nil {
		return ip.String()
	}
	return ""
}

// writeWithProxy writes data to peer, optionally prepending a PROXY v2
// header, signed over data when key is set (send_proxy_key_file). When hdr
// is empty this is a plain peer.Write(data) — the hot path for backends
// without send_proxy_v2.
func writeWithProxy(peer net.Conn, hdr, key, data []byte) (int, error) {
	if len(hdr) == 0 {
		return peer.Write(data)
	}
	if len(key) > 0 {
		signed, err := proxy.SignedHeaderBytes(hdr, key, data, time.Now())
		if err != nil {
			return 0, err
		}
		hdr = signed
	}
	out := make([]byte, len(hdr)+len(data))
	copy(out, hdr)
	copy(out[len(hdr):], data)
	return peer.Write(out)
}
