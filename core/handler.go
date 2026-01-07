package core

import (
	"fmt"
	"net"
	"sync"
	"time"

	"nvelox/core/logging"

	"github.com/lesismal/nbio"
)

type ProxyEventHandler struct {
	engine      *Engine
	listenerMap map[string]*ListenerConfig
}

func NewProxyEventHandler(e *Engine) *ProxyEventHandler {
	lm := make(map[string]*ListenerConfig)
	for _, l := range e.Listeners {
		_, port, _ := net.SplitHostPort(l.Addr)
		lm[":"+port] = l
		lm[l.Addr] = l
	}

	return &ProxyEventHandler{
		engine:      e,
		listenerMap: lm,
	}
}

type ConnContext struct {
	IsBackend bool
	PeerConn  net.Conn
	StartTime time.Time
	Buffer    []byte // Buffer for data received before backend is connected
	Mu        sync.Mutex
}

func (h *ProxyEventHandler) OnOpen(c *nbio.Conn) {
	if c.Session() != nil {
		return
	}

	// LocalAddr might be nil for some UDP edge cases?
	if c.LocalAddr() == nil {
		return
	}

	l := h.findListener(c.LocalAddr().String())
	if l == nil {
		c.Close()
		return
	}

	logging.Info("[CONN] New %s client %s -> %s", l.Protocol, c.RemoteAddr(), c.LocalAddr())

	clientCtx := &ConnContext{
		IsBackend: false,
		StartTime: time.Now(),
	}
	c.SetSession(clientCtx)
	logging.Info("[TRACE] OnOpen: Linked session, connecting backend...")

	h.connectBackend(c, l)
}

func (h *ProxyEventHandler) OnClose(c *nbio.Conn, err error) {
	ctx, ok := c.Session().(*ConnContext)
	if !ok || ctx == nil {
		return
	}

	if ctx.PeerConn != nil {
		ctx.PeerConn.Close()
	}

	if !ctx.IsBackend {
		logging.Info("[CONN] Closed %s (Dur: %v, Err: %v)", c.RemoteAddr(), time.Since(ctx.StartTime), err)
	}
}

func (h *ProxyEventHandler) OnData(c *nbio.Conn, data []byte) {
	logging.Debug("[DATA] Len %d from %s", len(data), c.RemoteAddr())
	ctx, ok := c.Session().(*ConnContext)
	if !ok || ctx == nil {
		logging.Debug("[DATA] No session for %s", c.RemoteAddr())
		return
	}

	ctx.Mu.Lock()
	if ctx.PeerConn != nil {
		ctx.Mu.Unlock()
		_, err := ctx.PeerConn.Write(data)
		if err != nil {
			logging.Error("[DATA] Write failed: %v", err)
		}
	} else {
		// Buffer data until backend connects
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

	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.DefaultBackend, err)
		clientConn.Close()
		return
	}

	logging.Info("[TRACE] Selected target: %s", target)

	if _, _, err := net.SplitHostPort(target); err != nil {
		// Valid assumption: missing port, use listener port (1:1 mapping)
		target = fmt.Sprintf("%s:%d", target, l.Port)
	}

	if l.Protocol == "udp" {
		h.connectBackendUDP(clientConn, target)
	} else {
		h.connectBackendTCP(clientConn, target)
	}
}

func (h *ProxyEventHandler) connectBackendTCP(clientConn *nbio.Conn, target string) {
	if h.engine.TCPEngine == nil {
		return
	}
	h.engine.TCPEngine.DialAsync("tcp", target, func(c *nbio.Conn, err error) {
		logging.Info("[TRACE] DialAsync callback: err=%v", err)
		if err != nil {
			logging.Error("Backend TCP dial failed: %v", err)
			if clientConn != nil {
				clientConn.Close()
			}
			return
		}

		h.setupSession(clientConn, c)
	})
}

func (h *ProxyEventHandler) connectBackendUDP(clientConn *nbio.Conn, target string) {
	if h.engine.UDPEngine == nil {
		return
	}

	// NBIO UDP Client Polling is proving unstable in tests, so we use a Hybrid approach for UDP Backend:
	// 1. Resolve & Dial UDP
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		logging.Error("UDP Resolve failed: %v", err)
		clientConn.Close()
		return
	}

	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		logging.Error("UDP Dial failed: %v", err)
		clientConn.Close()
		return
	}

	// 2. Link Session
	h.setupSession(clientConn, uc)

	// 3. Start Goroutine to pump data from Backend -> Client
	go func() {
		defer uc.Close()
		buf := make([]byte, 4096)
		for {
			// Keep client alive check? NBIO handles client timeout on its own if configured.
			uc.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := uc.Read(buf)
			if err != nil {
				// Backend closed or error
				logging.Debug("UDP Backend read error: %v", err)
				clientConn.Close()
				return
			}

			// Forward to client (nbio conn is thread safe for Write)
			_, err = clientConn.Write(buf[:n])
			if err != nil {
				logging.Debug("UDP Client write error: %v", err)
				clientConn.Close()
				return
			}
		}
	}()
}

func (h *ProxyEventHandler) setupSession(client *nbio.Conn, backend net.Conn) {
	backendCtx := &ConnContext{
		IsBackend: true,
		PeerConn:  client,
	}
	// If backend is *nbio.Conn, set session. If UDPConn, we can't set session on it (it's raw).
	// But we need to set session on CLIENT to point to backend.
	if nbioBackend, ok := backend.(*nbio.Conn); ok {
		nbioBackend.SetSession(backendCtx)
	}

	clientCtx := client.Session().(*ConnContext)

	clientCtx.Mu.Lock()
	defer clientCtx.Mu.Unlock()
	clientCtx.PeerConn = backend

	// Flush Buffer
	if len(clientCtx.Buffer) > 0 {
		_, err := backend.Write(clientCtx.Buffer)
		if err != nil {
			logging.Error("Failed to flush buffer to backend: %v", err)
			client.Close()
			return
		}
		clientCtx.Buffer = nil // Clear buffer
	}
}

func (h *ProxyEventHandler) findListener(localAddr string) *ListenerConfig {
	_, port, _ := net.SplitHostPort(localAddr)
	if l, ok := h.listenerMap[":"+port]; ok {
		return l
	}
	return nil
}
