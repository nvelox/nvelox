package core

import (
	"fmt"
	"net"
	"sync"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"

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
	Mu            sync.Mutex
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

	if c.LocalAddr() == nil {
		return
	}

	l := h.findListener(c.LocalAddr().Network(), c.LocalAddr().String())
	if l == nil {
		return
	}

	// Check rate limit
	if rl, ok := h.engine.RateLimiters[l.Name]; ok {
		if !rl.Allow() {
			logging.Warn("[RATE] Connection from %s rejected (rate limit on %s)", c.RemoteAddr(), l.Name)
			c.Close()
			return
		}
	}

	logging.Info("[CONN] New %s client %s -> %s", l.Protocol, c.RemoteAddr(), c.LocalAddr())

	h.engine.ActiveConns.Add(1)

	clientCtx := &ConnContext{
		IsBackend: false,
		StartTime: time.Now(),
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
		h.engine.ActiveConns.Done()
	}
}

func (h *ProxyEventHandler) OnData(c *nbio.Conn, data []byte) {
	ctx := h.getCtx(c)
	if ctx == nil {
		return
	}

	ctx.Mu.Lock()
	if ctx.PeerConn != nil {
		peer := ctx.PeerConn
		ctx.Mu.Unlock()
		_, err := peer.Write(data)
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
	balancer, ok := h.engine.Balancers[l.DefaultBackend]
	if !ok {
		logging.Error("Balancer '%s' not found for listener '%s'", l.DefaultBackend, l.Name)
		clientConn.Close()
		return
	}

	// Get backend config to check SendProxyV2
	backend := h.engine.Backends[l.DefaultBackend]

	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.DefaultBackend, err)
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
		h.connectBackendUDP(clientConn, dialTarget)
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

		// Send PROXY protocol v2 header if enabled on backend
		if backend != nil && backend.SendProxyV2 {
			header := proxyproto.HeaderProxyFromAddrs(2, clientConn.RemoteAddr(), backendConn.LocalAddr())
			if _, err := header.WriteTo(backendConn); err != nil {
				logging.Error("Failed to write PROXY v2 header: %v", err)
				backendConn.Close()
				clientConn.Close()
				return
			}
		}

		// Link client to backend
		clientCtx := h.getCtx(clientConn)
		if clientCtx == nil {
			// Client already closed during backend dial
			backendConn.Close()
			return
		}
		clientCtx.Mu.Lock()
		clientCtx.PeerConn = backendConn

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

func (h *ProxyEventHandler) connectBackendUDP(clientConn *nbio.Conn, target string) {
	clientCtx := h.getCtx(clientConn)

	// Check UDP pool for existing session (session affinity)
	poolKey := fmt.Sprintf("%s|%s", clientConn.RemoteAddr().String(), clientCtx.BackendServer)
	if session := h.engine.UDPPool.Get(poolKey); session != nil {
		// Reuse existing backend connection
		clientCtx.Mu.Lock()
		clientCtx.PeerConn = session.BackendConn
		if clientCtx.BalancerRef != nil {
			clientCtx.BalancerRef.OnConnect(clientCtx.BackendServer)
		}
		if len(clientCtx.Buffer) > 0 {
			session.BackendConn.Write(clientCtx.Buffer)
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

		// Notify balancer of new connection (for LeastConn tracking)
		if clientCtx.BalancerRef != nil {
			clientCtx.BalancerRef.OnConnect(clientCtx.BackendServer)
		}

		// Flush any buffered data
		if len(clientCtx.Buffer) > 0 {
			_, writeErr := backendConn.Write(clientCtx.Buffer)
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

		// Read from backend and write to client
		buf := make([]byte, 4096)
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
