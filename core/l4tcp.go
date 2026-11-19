package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"nvelox/core/logging"
	"nvelox/proxy"

	"github.com/pires/go-proxyproto"
)

// Plain (non-TLS-terminating) L4 TCP listeners: one accept loop per listener
// and one goroutine pair per connection (relayL4), which half-closes and
// flushes before it closes — see relay.go.

// inboundProxyHeaderWait bounds how long a TRUSTED peer (accept_proxy_from)
// gets to deliver its inbound PROXY-v2 header; its connection is closed
// when the header is not complete by then.
const inboundProxyHeaderWait = 5 * time.Second

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
		if !e.serveGate.Wait(e.runDone()) {
			return // shutting down before serving began (Stop closes ln)
		}
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
			e.l4Conns.Store(c, &l4Client{})
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
// through its relay's error path. A restart closes every TCP connection,
// and the drain stays fast.
func (e *Engine) closeL4Conns() {
	e.l4Conns.Range(func(k, _ any) bool {
		k.(io.Closer).Close()
		return true
	})
}

// serveTCP proxies one accepted plain L4 TCP connection end to end, on its
// own goroutine, with the accept-time gating, PROXY-v2 handling and L4
// access record that the UDP sessions have (handler.go).
//
// Order: access policy on a direct client (the peer) -> listener rate limit
// -> for a trusted accept_proxy_from relay, access policy on the client its
// PROXY-v2 header names, read before anything is dialed -> backend
// max_connections -> dial -> relay. A client the policy refuses takes
// nothing from the listener's rate, which is for the clients it serves.
func (h *ProxyEventHandler) serveTCP(clientConn net.Conn, l *ListenerConfig) {
	e := h.engine
	dstPort := portOf(clientConn.LocalAddr())
	// Is the immediate peer a TRUSTED relay (accept_proxy_from)? Its inbound PROXY-v2
	// header names the REAL client, which isn't known until it is parsed below —
	// until then an L4 record could only carry the relay IP, so the emit paths
	// suppress a record that would blame the relay for its clients.
	peerTrusted := l.proxyTrust.trusts(clientConn.RemoteAddr())

	// Access policy (ip_denylist, dynamic denylist, ip_allowlist, acl) on the
	// immediate peer when it IS the client. A trusted relay's real client is
	// checked below, once its header is read.
	// The client is recorded before the check, so a block added after the
	// check still finds the connection (closeDenylisted).
	if !peerTrusted {
		e.setL4Client(clientConn, ipOf(clientConn.RemoteAddr()))
		if ok, status := h.l4Admit(l, ipOf(clientConn.RemoteAddr())); !ok {
			if l.logsAccess() {
				logging.AccessL4(ipStrOf(clientConn.RemoteAddr()), l.Protocol, dstPort, status, 0, 0, 0)
			}
			clientConn.Close()
			return
		}
	}
	if rl, ok := e.RateLimiters[l.Name]; ok && !rl.Allow() {
		logging.Warn("[RATE] Connection from %s rejected (rate limit on %s)", clientConn.RemoteAddr(), l.Name)
		if !peerTrusted && l.logsAccess() {
			logging.AccessL4(ipStrOf(clientConn.RemoteAddr()), l.Protocol, dstPort, l4StatusRateLimited, 0, 0, 0)
		}
		clientConn.Close()
		return
	}

	logging.Info("[CONN] New %s client %s -> :%d", l.Protocol, clientConn.RemoteAddr(), dstPort)
	start := time.Now()
	realClientIP := ipStrOf(clientConn.RemoteAddr()) // upgraded to the PROXY-v2 client if a trusted header resolves
	clientResolved := false
	linked := false
	refused := "" // access-log status when the resolved client or a limit refuses the session
	var sessErr error
	defer func() {
		clientConn.Close()
		logging.Info("[CONN] Closed %s (Dur: %v, Err: %v)", clientConn.RemoteAddr(), time.Since(start), sessErr)
		// L4 access record: "ok" when a backend was linked, else "no_route" (the
		// L4 analogue of a 404) or the refusal status. Bytes are not accumulated
		// in v1. SUPPRESSED when the peer is a trusted relay whose real client
		// was never resolved.
		if !peerTrusted || clientResolved {
			status := "no_route"
			switch {
			case refused != "":
				status = refused
			case linked:
				status = "ok"
			}
			if l.logsAccess() {
				durMs := float64(time.Since(start).Nanoseconds()) / 1e6
				logging.AccessL4(realClientIP, l.Protocol, dstPort, status, 0, 0, durMs)
			}
		}
	}()

	// Determine the real client. A trusted peer's connection must start
	// with its PROXY-v2 header, read off the stream BEFORE dialing (and not
	// one byte past it), so the access policy runs on the client it names:
	// the relay itself for a LOCAL header. A relay's connection without a
	// valid header (and, with accept_proxy_key_file, a valid signature) is
	// closed: the relay is never taken for the client of what it relays.
	// Untrusted peers skip this entirely (a forged header can never spoof).
	src := clientConn.RemoteAddr()
	if peerTrusted {
		named, reason, cause := l.proxyTrust.relayClient(clientConn, inboundProxyHeaderWait)
		if reason != "" {
			e.proxyRefused(l, clientConn.RemoteAddr(), reason, cause)
			sessErr = cause
			return
		}
		src = named
		realClientIP = ipStrOf(src)
		clientResolved = true
		e.setL4Client(clientConn, ipOf(src))
		if ok, status := h.l4Admit(l, ipOf(src)); !ok {
			refused = status
			return
		}
	}

	bv := e.backends() // one consistent view for this connection (H6)
	balancer, ok := bv.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for listener '%s'", l.Backend, l.Name)
		return
	}
	backend := bv.Backends[l.Backend]
	if backend != nil && backend.BackendTLS.Enabled {
		// backend_tls is implemented on the HTTP path only; never send
		// plaintext to a backend configured for TLS (config load refuses
		// this pairing; a reload can still change a backend under a running
		// L4 listener).
		logging.Error("[CONN] listener %s: backend %s has backend_tls enabled, which L4 listeners do not implement — refusing %s", l.Name, l.Backend, realClientIP)
		return
	}
	// Backend max_connections: one slot per session, held until it ends.
	if cl, ok := bv.ConnLimiters[l.Backend]; ok {
		if !cl.Acquire() {
			logging.Warn("[CONN] listener %s: backend %s at max_connections — refusing %s", l.Name, l.Backend, realClientIP)
			refused = l4StatusRateLimited
			return
		}
		defer cl.Release()
	}
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

	// PROXY v2 to the backend. Its DESTINATION is the address the CLIENT
	// connected to (clientConn.LocalAddr = the dedicated port the client or
	// relay dialed), NOT our ephemeral source toward the backend — that is
	// what lets one backend socket MUX a whole port range.
	if backend != nil && backend.SendProxyV2 {
		header := proxyproto.HeaderProxyFromAddrs(2, src, clientConn.LocalAddr())
		if len(backend.SendProxyKey) > 0 {
			if err := proxy.SignHeaderFrom(header, backend.SendProxyKey, time.Now(), uint16(portOf(backendConn.LocalAddr()))); err != nil {
				logging.Error("Failed to sign PROXY v2 header: %v", err)
				sessErr = err
				return
			}
		}
		if _, err := header.WriteTo(backendConn); err != nil {
			logging.Error("Failed to write PROXY v2 header: %v", err)
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
