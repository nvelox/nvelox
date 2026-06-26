package core

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"
	"nvelox/proxy"

	"github.com/lesismal/nbio"
	"github.com/pires/go-proxyproto"
)

type ProxyEventHandler struct {
	engine      *Engine
	listenerMap map[string]*ListenerConfig
	sessions    sync.Map // *nbio.Conn -> *ConnContext (thread-safe session storage)
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
	// PROXY-v2-decoded source for a cross-region/trusted peer, NOT the relay. Proto
	// and DstPort are set once at OnOpen; RealClientIP defaults to the peer and is
	// upgraded to the parsed client when a trusted inbound PROXY-v2 header resolves.
	Proto        string
	DstPort      int
	RealClientIP string
	// ProxyHeader, when non-nil, is prepended to each datagram written to
	// PeerConn. Built once per session in connectBackendUDP when the
	// backend has send_proxy_v2: true (or, for StripInbound conns, in OnData
	// once the real client is recovered from the inbound header).
	ProxyHeader []byte
	// StripInbound (UDP, cross-region #77 / N1): this listener trusts an inbound
	// PROXY-v2 header from the immediate peer (a peer-region relay). OnData then
	// strips a per-datagram DGRAM header and builds the OUTBOUND header from the
	// parsed REAL client instead of the relay's address. SendProxyV2/LocalAddr are
	// snapshotted so OnData can build that header (src = real client, dst =
	// LocalAddr = the dedicated port the relay dialed).
	StripInbound bool
	SendProxyV2  bool
	LocalAddr    net.Addr
	Mu           sync.Mutex
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

func (h *ProxyEventHandler) OnOpen(c *nbio.Conn) {
	// Backend connections from DialAsync already have session set in callback
	if h.getCtx(c) != nil {
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

	// Check rate limit
	if rl, ok := h.engine.RateLimiters[l.Name]; ok {
		if !rl.Allow() {
			logging.Warn("[RATE] Connection from %s rejected (rate limit on %s)", c.RemoteAddr(), l.Name)
			// L4 access record so ngris-sentinel sees the rejected flood (ratelimited→429).
			logging.AccessL4(ipStrOf(c.RemoteAddr()), l.Protocol, dstPort, "ratelimited", 0, 0, 0)
			c.Close()
			return
		}
	}

	logging.Info("[CONN] New %s client %s -> :%d", l.Protocol, c.RemoteAddr(), dstPort)

	h.engine.ActiveConns.Add(1)

	clientCtx := &ConnContext{
		IsBackend:    false,
		StartTime:    time.Now(),
		Proto:        l.Protocol,
		DstPort:      dstPort,
		RealClientIP: ipStrOf(c.RemoteAddr()), // upgraded to the PROXY-v2 client if a trusted header resolves
	}
	h.setCtx(c, clientCtx)

	h.connectBackend(c, l)
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
	ctx.PeerConn = nil // prevent double-close
	ctx.Mu.Unlock()

	if peer != nil {
		peer.Close()
	}

	// Notify balancer of disconnection (for LeastConn tracking)
	if !isBackend && backendServer != "" && balancerRef != nil {
		balancerRef.OnDisconnect(backendServer)
	}

	if !isBackend {
		logging.Info("[CONN] Closed %s (Dur: %v, Err: %v)", c.RemoteAddr(), time.Since(ctx.StartTime), err)
		// L4 access record (mirrors AccessHTTP for HTTP). A backend was linked iff
		// peer!=nil at close → "ok"; otherwise the connection never reached a backend
		// (no active tunnel on the dialed port) → "no_route", the L4 analogue of a 404
		// that drives ngris-sentinel's port-scan fan-out heuristic. Bytes are not
		// accumulated in v1 (the heuristics key off port fan-out + status, not volume).
		status := "no_route"
		if peer != nil {
			status = "ok"
		}
		durMs := float64(time.Since(ctx.StartTime).Nanoseconds()) / 1e6
		logging.AccessL4(realClientIP, proto, dstPort, status, 0, 0, durMs)
		h.engine.ActiveConns.Done()
	}
}

func (h *ProxyEventHandler) OnData(c *nbio.Conn, data []byte) {
	ctx := h.getCtx(c)
	if ctx == nil {
		return
	}

	// Cross-region UDP inbound (#77 / N1): when this listener trusts the immediate
	// peer (a peer-region relay), each datagram carries a leading PROXY-v2 DGRAM
	// header naming the REAL client. Strip it and build the OUTBOUND send_proxy_v2
	// header from that real client (once — it's stable per conn), so the backend
	// (tunnel-server) sees the client, not the relay. The header's dst is our
	// LocalAddr (the dedicated port the relay dialed) — already correct.
	ctx.Mu.Lock()
	stripInbound := ctx.StripInbound
	sendProxyV2 := ctx.SendProxyV2
	localAddr := ctx.LocalAddr
	ctx.Mu.Unlock()
	if stripInbound {
		if src, consumed, isProxy := parseInboundProxyV2Datagram(data); isProxy {
			data = data[consumed:]
			if src != nil {
				ctx.Mu.Lock()
				ctx.RealClientIP = ipStrOf(src) // the real UDP client (not the relay) for the L4 access record
				if sendProxyV2 && ctx.ProxyHeader == nil {
					var buf bytes.Buffer
					if err := proxy.WriteProxyHeaderV2(&buf, src, localAddr); err == nil {
						ctx.ProxyHeader = buf.Bytes()
					} else {
						logging.Warn("[UDP] inbound PROXY v2 rebuild failed: %v", err)
					}
				}
				ctx.Mu.Unlock()
			}
		}
	}

	ctx.Mu.Lock()
	if ctx.PeerConn != nil {
		peer := ctx.PeerConn
		hdr := ctx.ProxyHeader
		ctx.Mu.Unlock()
		_, err := writeWithProxy(peer, hdr, data)
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

func (h *ProxyEventHandler) connectBackend(clientConn *nbio.Conn, l *ListenerConfig) {
	balancer, ok := h.engine.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for listener '%s'", l.Backend, l.Name)
		clientConn.Close()
		return
	}

	// Get backend config to check SendProxyV2
	backend := h.engine.Backends[l.Backend]

	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.Backend, err)
		clientConn.Close()
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

	if l.Protocol == "udp" {
		h.connectBackendUDP(clientConn, dialTarget, backend, l)
	} else {
		h.connectBackendTCP(clientConn, dialTarget, backend, balancer, target, l)
	}
}

func (h *ProxyEventHandler) connectBackendTCP(clientConn *nbio.Conn, target string, backend *config.Backend, balancer lb.Balancer, balancerKey string, l *ListenerConfig) {
	// Use configurable timeout: prefer backend timeout, fall back to listener timeout, default 10s
	connectTimeout := l.Timeouts.ParseConnect()
	if backend != nil && backend.Timeouts.Connect != "" {
		connectTimeout = backend.Timeouts.ParseConnect()
	}

	go func() {
		// Blocking dial — guarantees sequential byte ordering for PROXY v2 + TLS
		backendConn, err := net.DialTimeout("tcp", target, connectTimeout)
		if err != nil {
			logging.Error("Backend TCP dial failed: %v", err)
			clientConn.Close()
			return
		}

		clientCtx := h.getCtx(clientConn)
		if clientCtx == nil {
			// Client already closed during backend dial
			backendConn.Close()
			return
		}

		// Determine the real client. When this listener trusts an inbound
		// PROXY-v2 header from this peer (a peer-region relay), wait briefly for
		// the header to land in the pre-backend buffer, parse it, and strip the
		// consumed bytes so they aren't forwarded as payload. Untrusted peers
		// skip this entirely (no spoofing). PeerConn is still nil here, so OnData
		// keeps buffering — we set it only after the header is resolved.
		src := clientConn.RemoteAddr()
		if l.proxyTrust.trusts(clientConn.RemoteAddr()) {
			deadline := time.Now().Add(5 * time.Second)
			for {
				clientCtx.Mu.Lock()
				done, parsedSrc, consumed := tryParseInboundProxyV2(clientCtx.Buffer)
				if done {
					if parsedSrc != nil {
						src = parsedSrc
					}
					if consumed > 0 {
						clientCtx.Buffer = clientCtx.Buffer[consumed:]
					}
					clientCtx.Mu.Unlock()
					break
				}
				clientCtx.Mu.Unlock()
				if time.Now().After(deadline) {
					break // header never completed; fall back to peer addr, buffer intact
				}
				time.Sleep(5 * time.Millisecond)
			}
		}

		// Send PROXY protocol v2 header to the backend if enabled. The header's
		// DESTINATION is the address the CLIENT connected to (clientConn.LocalAddr
		// = our listener's local addr, i.e. the original dedicated port for a
		// range listener) — NOT backendConn.LocalAddr (our ephemeral source toward
		// the backend, which is useless to the backend). This is the correct PROXY
		// semantic and is what lets a backend MUX a whole port range on one socket:
		// it recovers the original dialed port from the header instead of needing a
		// listener per port. (For a chained relay, clientConn.LocalAddr is still the
		// dedicated port because the relay dials that same port.)
		if backend != nil && backend.SendProxyV2 {
			header := proxyproto.HeaderProxyFromAddrs(2, src, clientConn.LocalAddr())
			if _, err := header.WriteTo(backendConn); err != nil {
				logging.Error("Failed to write PROXY v2 header: %v", err)
				backendConn.Close()
				clientConn.Close()
				return
			}
		}

		// Link client to backend
		clientCtx.Mu.Lock()
		clientCtx.PeerConn = backendConn
		clientCtx.RealClientIP = ipStrOf(src) // the resolved client (PROXY-v2 source if trusted, else peer) for the L4 access record

		// Notify balancer
		balancer.OnConnect(balancerKey)

		// Flush any buffered data
		if len(clientCtx.Buffer) > 0 {
			_, writeErr := backendConn.Write(clientCtx.Buffer)
			if writeErr != nil {
				logging.Error("Failed to flush buffer: %v", writeErr)
				clientCtx.Mu.Unlock()
				clientConn.Close()
				backendConn.Close()
				return
			}
			clientCtx.Buffer = nil
		}
		clientCtx.Mu.Unlock()

		// Blocking read loop: backend → client (with idle timeout)
		idleTimeout := 5 * time.Minute
		if l.Timeouts.Idle != "" {
			idleTimeout = l.Timeouts.ParseIdle()
		}
		buf := make([]byte, 32*1024)
		for {
			if idleTimeout > 0 {
				backendConn.SetReadDeadline(time.Now().Add(idleTimeout))
			}
			n, err := backendConn.Read(buf)
			if err != nil {
				backendConn.Close()
				clientConn.Close()
				return
			}
			_, err = clientConn.Write(buf[:n])
			if err != nil {
				backendConn.Close()
				clientConn.Close()
				return
			}
		}
	}()
}

func (h *ProxyEventHandler) connectBackendUDP(clientConn *nbio.Conn, target string, backend *config.Backend, l *ListenerConfig) {
	clientCtx := h.getCtx(clientConn)

	sendProxyV2 := backend != nil && backend.SendProxyV2
	// acceptInbound: this listener trusts an inbound PROXY-v2 header from the
	// immediate peer (a peer-region relay, cross-region #77 / N1). When set, the
	// REAL client isn't known until the first inbound datagram is parsed, so we do
	// NOT build the outbound header here — OnData strips the inbound header and
	// builds the outbound one from the parsed real client. Untrusted peers skip
	// this entirely (a forged header can never spoof a source).
	acceptInbound := l.proxyTrust.trusts(clientConn.RemoteAddr())

	// Snapshot what OnData needs to do the strip + outbound-header build. Set
	// synchronously (this runs inside OnOpen, before any OnData for this conn).
	clientCtx.Mu.Lock()
	clientCtx.StripInbound = acceptInbound
	clientCtx.SendProxyV2 = sendProxyV2
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
	// and their replies would cross. (UDP cross-region MUX, task #77 / N2.)
	poolKey := fmt.Sprintf("%s|%d|%s", clientConn.RemoteAddr().String(), portOf(clientConn.LocalAddr()), clientCtx.BackendServer)
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
			writeWithProxy(session.BackendConn, clientCtx.ProxyHeader, clientCtx.Buffer)
			clientCtx.Buffer = nil
		}
		clientCtx.Mu.Unlock()
		return
	}

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

		// Store in pool for session affinity
		session := &UDPSession{
			BackendConn: backendConn,
			Target:      target,
			LastActive:  time.Now(),
		}
		h.engine.UDPPool.Put(poolKey, session)

		// Link client to backend
		clientCtx.Mu.Lock()
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
			_, writeErr := writeWithProxy(backendConn, clientCtx.ProxyHeader, clientCtx.Buffer)
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

		// Read from backend and write to client. 65535 = max UDP payload; a
		// 4096 buffer silently truncated any backend datagram >4 KB (the kernel
		// discards the remainder of that datagram) — large DNS/QUIC/jumbo
		// responses lost data. (UDP cross-region MUX, task #77 / N3.)
		buf := make([]byte, 65535)
		for {
			backendConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := backendConn.Read(buf)
			if err != nil {
				h.engine.UDPPool.Remove(poolKey)
				clientConn.Close()
				return
			}

			_, err = clientConn.Write(buf[:n])
			if err != nil {
				h.engine.UDPPool.Remove(poolKey)
				clientConn.Close()
				return
			}

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
// header. When hdr is empty this is a plain peer.Write(data) — the hot
// path for backends without send_proxy_v2.
func writeWithProxy(peer net.Conn, hdr, data []byte) (int, error) {
	if len(hdr) == 0 {
		return peer.Write(data)
	}
	out := make([]byte, len(hdr)+len(data))
	copy(out, hdr)
	copy(out[len(hdr):], data)
	return peer.Write(out)
}
