package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"nvelox/core/logging"

	"github.com/pires/go-proxyproto"
)

// Plain (non-TLS-terminating) L4 TCP listeners: one accept loop per listener
// and one goroutine pair per connection (relayL4). TCP used to run on the
// nbio event loop, but nbio cannot express half-close: it full-closes a conn
// on the peer's FIN (EPOLLRDHUP) and its Close discards the unflushed write
// queue — see relay.go. UDP stays on nbio (no half-close there).

// inboundProxyHeaderWait bounds how long a TRUSTED peer (accept_proxy_from)
// gets to deliver its inbound PROXY-v2 header before nvelox falls back to the
// peer address (unchanged from the previous data path).
const inboundProxyHeaderWait = 5 * time.Second

// maxInboundProxyHeaderBuf caps what is read while waiting for that header
// (a v2 header is at most 16+65535 bytes).
const maxInboundProxyHeaderBuf = 1 << 20

type tcpListener struct {
	ln net.Listener
	l  *ListenerConfig
}

// startAcceptLoop accepts on ln until it is closed and runs serve on its own
// goroutine per connection. Every accepted conn is counted in ActiveConns and
// registered in l4Conns BEFORE its goroutine starts, so shutdown (close
// listeners -> acceptWG.Wait -> closeL4Conns -> ActiveConns.Wait) never races
// a late Add. Transient accept errors (EMFILE, ENFILE, ECONNABORTED...) back
// off and retry instead of silently killing the listener.
func (e *Engine) startAcceptLoop(ln net.Listener, name string, serve func(net.Conn)) {
	e.acceptWG.Add(1)
	go func() {
		defer e.acceptWG.Done()
		var backoff time.Duration
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				backoff = max(5*time.Millisecond, 2*backoff)
				if backoff > time.Second {
					backoff = time.Second
				}
				logging.Error("[ACCEPT] listener %s: %v (retrying in %v)", name, err, backoff)
				time.Sleep(backoff)
				continue
			}
			backoff = 0
			e.ActiveConns.Add(1)
			e.l4Conns.Store(c, struct{}{})
			go func() {
				defer e.ActiveConns.Done()
				defer e.l4Conns.Delete(c)
				serve(c)
			}()
		}
	}()
}

// dialL4Backend dials an L4 backend, bounded by timeout and aborted when the
// engine shuts down (so the drain never waits out a hanging dial).
func (e *Engine) dialL4Backend(target string, timeout time.Duration) (net.Conn, error) {
	ctx := e.runCtx
	if ctx == nil {
		ctx = context.Background()
	}
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", target)
}

// closeL4Conns closes every live L4 TCP client connection (plain and TLS).
// Used at shutdown after the accept loops have exited; each session unwinds
// through its relay's error path. This keeps the old restart behaviour (the
// nbio TCP engine's Stop closed every TCP conn) and the drain fast.
func (e *Engine) closeL4Conns() {
	e.l4Conns.Range(func(k, _ any) bool {
		k.(net.Conn).Close()
		return true
	})
}

// serveTCP proxies one accepted plain L4 TCP connection end to end. It is the
// goroutine-per-connection replacement of the nbio OnOpen -> connectBackend ->
// OnData/OnClose chain for TCP, with identical accept-time gating, PROXY-v2
// handling and L4 access record.
func (h *ProxyEventHandler) serveTCP(clientConn net.Conn, l *ListenerConfig) {
	e := h.engine
	dstPort := portOf(clientConn.LocalAddr())
	// Is the immediate peer a TRUSTED relay (cross-region)? Its inbound PROXY-v2
	// header names the REAL client, which isn't known until it is parsed below —
	// until then an L4 record could only carry the relay IP, so the emit paths
	// suppress a relay-misattributed record (cross-region-outage risk).
	peerTrusted := l.proxyTrust.trusts(clientConn.RemoteAddr())

	if rl, ok := e.RateLimiters[l.Name]; ok && !rl.Allow() {
		logging.Warn("[RATE] Connection from %s rejected (rate limit on %s)", clientConn.RemoteAddr(), l.Name)
		if !peerTrusted {
			logging.AccessL4(ipStrOf(clientConn.RemoteAddr()), l.Protocol, dstPort, "ratelimited", 0, 0, 0)
		}
		clientConn.Close()
		return
	}
	// Dynamic denylist on the immediate peer when it IS the client (see l4Denied).
	if h.l4Denied(clientConn.RemoteAddr(), peerTrusted) {
		logging.AccessL4(ipStrOf(clientConn.RemoteAddr()), l.Protocol, dstPort, "denylisted", 0, 0, 0)
		clientConn.Close()
		return
	}

	logging.Info("[CONN] New %s client %s -> :%d", l.Protocol, clientConn.RemoteAddr(), dstPort)
	start := time.Now()
	realClientIP := ipStrOf(clientConn.RemoteAddr()) // upgraded to the PROXY-v2 client if a trusted header resolves
	clientResolved := false
	linked := false
	var sessErr error
	defer func() {
		clientConn.Close()
		logging.Info("[CONN] Closed %s (Dur: %v, Err: %v)", clientConn.RemoteAddr(), time.Since(start), sessErr)
		// L4 access record: "ok" when a backend was linked, else "no_route" (the
		// L4 analogue of a 404). Bytes are not accumulated in v1. SUPPRESSED when
		// the peer is a trusted relay whose real client was never resolved.
		if !peerTrusted || clientResolved {
			status := "no_route"
			if linked {
				status = "ok"
			}
			durMs := float64(time.Since(start).Nanoseconds()) / 1e6
			logging.AccessL4(realClientIP, l.Protocol, dstPort, status, 0, 0, durMs)
		}
	}()

	balancer, ok := e.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for listener '%s'", l.Backend, l.Name)
		return
	}
	backend := e.Backends[l.Backend]
	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.Backend, err)
		return
	}
	dialTarget := target
	if _, _, err := net.SplitHostPort(dialTarget); err != nil {
		// No port on the server entry: use the listener port (1:1 mapping).
		dialTarget = fmt.Sprintf("%s:%d", dialTarget, l.Port)
	}
	connectTimeout := l.Timeouts.ParseConnect()
	if backend != nil && backend.Timeouts.Connect != "" {
		connectTimeout = backend.Timeouts.ParseConnect()
	}
	backendConn, err := e.dialL4Backend(dialTarget, connectTimeout)
	if err != nil {
		logging.Error("Backend TCP dial failed: %v", err)
		sessErr = err
		return
	}
	defer backendConn.Close()

	// Determine the real client. For a trusted peer, read its inbound PROXY-v2
	// header off the stream; payload bytes read past it are forwarded first.
	// Untrusted peers skip this entirely (a forged header can never spoof).
	src := clientConn.RemoteAddr()
	var pending []byte
	if peerTrusted {
		src, pending, err = readInboundProxyV2(clientConn, src, inboundProxyHeaderWait)
		if err != nil {
			sessErr = err
			return
		}
	}

	// PROXY v2 to the backend. Its DESTINATION is the address the CLIENT
	// connected to (clientConn.LocalAddr = the dedicated port the client or
	// relay dialed), NOT our ephemeral source toward the backend — that is
	// what lets one backend socket MUX a whole port range.
	if backend != nil && backend.SendProxyV2 {
		header := proxyproto.HeaderProxyFromAddrs(2, src, clientConn.LocalAddr())
		if _, err := header.WriteTo(backendConn); err != nil {
			logging.Error("Failed to write PROXY v2 header: %v", err)
			sessErr = err
			return
		}
	}
	if len(pending) > 0 {
		if _, err := backendConn.Write(pending); err != nil {
			logging.Error("Failed to flush buffer: %v", err)
			sessErr = err
			return
		}
	}

	realClientIP = ipStrOf(src)
	clientResolved = true
	linked = true
	balancer.OnConnect(target)
	defer balancer.OnDisconnect(target)

	res := relayL4(clientConn, backendConn, l4IdleTimeout(l))
	sessErr = res.Err
}

// readInboundProxyV2 reads a TRUSTED peer's inbound PROXY-v2 header off the
// raw stream, waiting at most wait. It returns the real client (fallback when
// the stream is not PROXY-v2, carries a LOCAL/malformed header, or the header
// never completes) plus any bytes read past the header, which the caller must
// forward to the backend before relaying.
func readInboundProxyV2(c net.Conn, fallback net.Addr, wait time.Duration) (net.Addr, []byte, error) {
	c.SetReadDeadline(time.Now().Add(wait))
	defer c.SetReadDeadline(time.Time{})
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if done, src, consumed := tryParseInboundProxyV2(buf); done {
			if src == nil {
				src = fallback
			}
			return src, buf[consumed:], nil
		}
		if err != nil {
			if isTimeout(err) || errors.Is(err, io.EOF) {
				// Header never completed (or the peer half-closed first): fall
				// back to the peer address and forward the bytes intact.
				return fallback, buf, nil
			}
			return nil, nil, err
		}
		if len(buf) >= maxInboundProxyHeaderBuf {
			return fallback, buf, nil
		}
	}
}
