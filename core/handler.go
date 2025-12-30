package core

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"nvelox/core/logging"
	"nvelox/proxy"

	"github.com/panjf2000/gnet/v2"
)

const (
	tcpDialTimeout = 5 * time.Second
	udpReadTimeout = 60 * time.Second
	copyBufferSize = 32 * 1024 // 32KB
	udpBufferSize  = 4096      // 4KB
)

type ProxyEventHandler struct {
	gnet.BuiltinEventEngine
	engine      *Engine
	listenerMap map[string]*ListenerConfig // Addr -> Config

	// UDP Session Table: remoteAddr(string) -> *net.UDPConn (for backend)
	udpSessions sync.Map
}

// OnTraffic fires when data is available.
func (h *ProxyEventHandler) OnTraffic(c gnet.Conn) (action gnet.Action) {
	// Find listener for this connection
	l := h.getListenerConfig(c)
	if l == nil {
		logging.Error("Unknown listener for connection on %s", c.LocalAddr())
		return gnet.Close
	}

	if l.Protocol == "udp" {
		return h.handleUDP(c, l)
	}
	return h.handleTCP(c, l)
}

// OnBoot fires when the engine starts.
func (h *ProxyEventHandler) OnBoot(eng gnet.Engine) (action gnet.Action) {
	logging.Info("Shared Server Engine Started")
	return gnet.None
}

// OnOpen fires when a new connection is opened.
func (h *ProxyEventHandler) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	l := h.getListenerConfig(c)
	if l == nil {
		logging.Error("Unknown listener for connection on %s", c.LocalAddr())
		return nil, gnet.Close
	}

	logging.Info("[CONN] New connection from %s on %s (Listener: %s)", c.RemoteAddr(), c.LocalAddr(), l.Name)

	ctx := &ConnContext{
		StartTime: time.Now(),
		buffer:    make([]byte, 0),
	}
	c.SetContext(ctx)

	// Initiate connection to backend asynchronously
	go h.connectBackend(c, ctx, l)

	return nil, gnet.None
}

func (h *ProxyEventHandler) getListenerConfig(c gnet.Conn) *ListenerConfig {
	// Address matching logic
	// LocalAddr() returns specific IP "127.0.0.1:9090"
	// Config might be ":9090"

	// Fast path: Try exact match first (if map was populated with full address?)
	_, port, _ := net.SplitHostPort(c.LocalAddr().String())

	// Safe fallback: Match by Port
	for _, l := range h.listenerMap {
		_, lPort, _ := net.SplitHostPort(l.Addr)
		if lPort == port {
			return l
		}
	}
	return nil
}

// OnClose fires when a connection is closed.
func (h *ProxyEventHandler) OnClose(c gnet.Conn, err error) (action gnet.Action) {
	duration := time.Duration(0)
	if val := c.Context(); val != nil {
		if ctx, ok := val.(*ConnContext); ok {
			duration = time.Since(ctx.StartTime)
			ctx.mu.Lock()
			if ctx.BackendConn != nil {
				ctx.BackendConn.Close()
			}
			ctx.closed = true // Mark as closed to stop dialer updates
			ctx.mu.Unlock()
		}
	} else if conn, ok := c.Context().(net.Conn); ok {
		conn.Close()
	}

	logging.Info("[CONN] Closed connection from %s (Duration: %v, Err: %v)", c.RemoteAddr(), duration, err)
	return gnet.None
}

type ConnContext struct {
	BackendConn net.Conn
	StartTime   time.Time

	mu        sync.Mutex
	buffer    []byte
	connected bool
	closed    bool
}

func (h *ProxyEventHandler) connectBackend(c gnet.Conn, ctx *ConnContext, l *ListenerConfig) {
	backendName := l.DefaultBackend
	balancer, ok := h.engine.Balancers[backendName]
	if !ok {
		logging.Error("[ERR] backend not found: %s", backendName)
		c.Close()
		return
	}

	target, err := balancer.Next()
	if err != nil {
		logging.Error("[ERR] failed to pick backend: %v", err)
		h.safeClose(c, ctx)
		return
	}

	// If target has no port (e.g. "10.0.0.103"), assume 1:1 mapping and append listener port
	if _, _, err := net.SplitHostPort(target); err != nil {
		// Verify if it's missing port error or something else
		// "missing port in address" is the typical error
		target = fmt.Sprintf("%s:%d", target, l.Port)
	}

	// Blocking dial
	rc, err := net.DialTimeout("tcp", target, tcpDialTimeout)
	if err != nil {
		logging.Error("[ERR] backend connect failed: %v", err)
		h.safeClose(c, ctx)
		return
	}

	ctx.mu.Lock()
	if ctx.closed {
		rc.Close()
		ctx.mu.Unlock()
		return
	}
	ctx.BackendConn = rc
	ctx.connected = true

	// Flush buffer
	if len(ctx.buffer) > 0 {
		_, err := rc.Write(ctx.buffer)
		if err != nil {
			logging.Error("[ERR] failed to flush buffer: %v", err)
			rc.Close()
			ctx.mu.Unlock()
			h.safeClose(c, ctx)
			return
		}
		ctx.buffer = nil // Clear buffer to free memory
	}
	ctx.mu.Unlock()

	// Start Copy Backend -> Frontend
	buf := make([]byte, copyBufferSize)
	for {
		n, err := rc.Read(buf)

		if n > 0 {
			// Copy data for safe async usage
			data := make([]byte, n)
			copy(data, buf[:n])

			// Safe Write: Execute Write only if Context matches
			errAsync := c.AsyncWrite(nil, func(c gnet.Conn, err error) error {
				if c.Context() != ctx {
					return nil // Stale connection, ignore
				}
				// If previous error?
				if err != nil {
					return err
				}
				_, writeErr := c.Write(data)
				return writeErr
			})

			if errAsync != nil {
				// gnet error (closed?)
				break
			}
		}
		if err != nil {
			if err != io.EOF {
				logging.Error("[CONN] Backend read error: %v", err)
			}
			break
		}
	}

	// Backend finished
	h.safeClose(c, ctx)

	ctx.mu.Lock()
	ctx.closed = true
	ctx.mu.Unlock()
}

// safeClose closes the connection strictly via AsyncWrite to ensure thread safety and context identity.
func (h *ProxyEventHandler) safeClose(c gnet.Conn, ctx *ConnContext) {
	_ = c.AsyncWrite(nil, func(c gnet.Conn, err error) error {
		if c.Context() != ctx {
			return nil // Stale
		}
		return c.Close()
	})
}

// handleTCP handles TCP traffic.
func (h *ProxyEventHandler) handleTCP(c gnet.Conn, l *ListenerConfig) gnet.Action {
	val := c.Context()
	if val == nil {
		// Should not happen if OnOpen works
		return gnet.Close
	}
	ctx, ok := val.(*ConnContext)
	if !ok {
		return gnet.Close
	}

	data, _ := c.Next(-1)
	if len(data) == 0 {
		return gnet.None
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if ctx.connected {
		// Fast path
		_, err := ctx.BackendConn.Write(data)
		if err != nil {
			return gnet.Close
		}
	} else {
		// Buffer data
		ctx.buffer = append(ctx.buffer, data...)
	}

	return gnet.None
}

// handleUDP handles UDP traffic.
func (h *ProxyEventHandler) handleUDP(c gnet.Conn, l *ListenerConfig) gnet.Action {
	buf, _ := c.Next(-1)
	if len(buf) == 0 {
		return gnet.None
	}

	remoteAddr := c.RemoteAddr().String()

	// Lookup session
	var conn *net.UDPConn
	v, ok := h.udpSessions.Load(remoteAddr)

	isNewSession := false
	if !ok {
		isNewSession = true
		// Resolve Backend
		balancer, ok := h.engine.Balancers[l.DefaultBackend]
		if !ok {
			return gnet.None
		}
		backendName := l.DefaultBackend
		bkConf, hasBE := h.engine.Backends[backendName]

		target, err := balancer.Next()
		if err != nil {
			return gnet.None
		}

		raddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			return gnet.None
		}

		// Dial dial UDP to backend (creates connected socket)
		loc, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			return gnet.None
		}

		conn = loc
		h.udpSessions.Store(remoteAddr, conn)

		// Start goroutine to copy back from Backend -> Frontend
		// Note: UDP is stateless, so "Frontend" is `c`.
		// gnet `c.Write` sends packet to `c.RemoteAddr`.
		go func() {
			defer conn.Close()
			defer h.udpSessions.Delete(remoteAddr)

			b := make([]byte, udpBufferSize)
			// Read timeout for auto-cleanup
			conn.SetReadDeadline(time.Now().Add(udpReadTimeout))

			for {
				n, _, err := conn.ReadFromUDP(b)
				if err != nil {
					break
				}
				// Write back to client
				c.Write(b[:n])
				conn.SetReadDeadline(time.Now().Add(udpReadTimeout))
			}
		}()

		// Send PROXY header if configured
		if hasBE && bkConf != nil && bkConf.SendProxyV2 && isNewSession {
			_ = proxy.WriteProxyHeaderV2(conn, c.RemoteAddr(), c.LocalAddr())
		}
	} else {
		conn = v.(*net.UDPConn)
	}

	// Forward the payload
	conn.Write(buf)

	return gnet.None
}
