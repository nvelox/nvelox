package core

import (
	"fmt"
	"net"
	"sync"
	"time"

	"nvelox/config"
	"nvelox/core/logging"

	"github.com/lesismal/nbio"
	"github.com/pires/go-proxyproto"
)

type ProxyEventHandler struct {
	engine      *Engine
	listenerMap map[string]*ListenerConfig
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

	l := h.findListener(c.LocalAddr().Network(), c.LocalAddr().String())
	if l == nil {
		// Backend connections from DialAsync already have session set in callback.
		// If we get here with no session and no listener, just ignore.
		return
	}

	logging.Info("[CONN] New %s client %s -> %s", l.Protocol, c.RemoteAddr(), c.LocalAddr())

	// Enforce TCP_NODELAY on client connection (Agent -> Proxy)
	_ = c.SetNoDelay(true)

	clientCtx := &ConnContext{
		IsBackend: false,
		StartTime: time.Now(),
	}
	c.SetSession(clientCtx)

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
	ctx, ok := c.Session().(*ConnContext)
	if !ok || ctx == nil {
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

	// Get backend config to check SendProxyV2
	backend := h.engine.Backends[l.DefaultBackend]

	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.DefaultBackend, err)
		clientConn.Close()
		return
	}

	if _, _, err := net.SplitHostPort(target); err != nil {
		// Valid assumption: missing port, use listener port (1:1 mapping)
		target = fmt.Sprintf("%s:%d", target, l.Port)
	}

	if l.Protocol == "udp" {
		h.connectBackendUDP(clientConn, target)
	} else {
		h.connectBackendTCP(clientConn, target, backend)
	}
}

func (h *ProxyEventHandler) connectBackendTCP(clientConn *nbio.Conn, target string, backend *config.Backend) {
	go func() {
		// Dial backend synchronously
		backendConn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			logging.Error("Backend TCP dial failed: %v", err)
			clientConn.Close()
			return
		}
		// Enforce TCP_NODELAY on backend connection to prevent Nagle's algorithm delay
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
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
			logging.Info("Sent PROXY v2 header for client %s -> %s", clientConn.RemoteAddr(), target)
		}

		// Link client to backend
		clientCtx := clientConn.Session().(*ConnContext)
		clientCtx.Mu.Lock()
		clientCtx.PeerConn = backendConn

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

		// Read from backend and write to client
		buf := make([]byte, 32*1024)
		for {
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

		// Link client to backend
		clientCtx := clientConn.Session().(*ConnContext)
		clientCtx.Mu.Lock()
		clientCtx.PeerConn = backendConn

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

func (h *ProxyEventHandler) findListener(network, localAddr string) *ListenerConfig {
	_, port, _ := net.SplitHostPort(localAddr)
	// Lookup with protocol prefix
	key := fmt.Sprintf("%s:%s", network, port)
	if l, ok := h.listenerMap[key]; ok {
		return l
	}
	return nil
}
