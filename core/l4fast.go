package core

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/nvelox/ngx"
	"github.com/nvelox/ngx/relay"
	"github.com/pires/go-proxyproto"

	"nvelox/core/logging"
	"nvelox/lb"
	"nvelox/proxy"
)

// Plain L4 TCP listeners on the event loops. The relay itself is the ngx
// module's (relay.TCP): the same half-close semantics, back-pressure and
// idle timeout as relay.go, without a goroutine pair per connection. This
// file is what nvelox decides for it: which clients are admitted, which
// server a connection goes to, the PROXY header a backend asks for, and
// the L4 access record. A connection from a trusted relay
// (accept_proxy_from), whose PROXY header has to be read first, is served
// by serveTCP as before.

// l4FastOff turns the event-loop relay off for listeners started from now
// on (tests compare it with relayL4).
var l4FastOff atomic.Bool

func l4FastEnabled() bool { return ngx.Supported() && !l4FastOff.Load() }

// l4FastServer is one plain L4 TCP listener that the loops serve, and the
// host of its relay.
type l4FastServer struct {
	e   *Engine
	h   *ProxyEventHandler
	l   *ListenerConfig
	tcp *relay.TCP
}

// l4FastSess is what nvelox keeps of one of the relay's sessions.
type l4FastSess struct {
	clientIP string
	target   string
	balancer lb.Balancer
	limiter  *ConnLimiter
	refused  string
}

// startL4Fast serves listener l, bound as ln, from the event loops once the
// serve gate opens.
func (e *Engine) startL4Fast(ln net.Listener, l *ListenerConfig, h *ProxyEventHandler) error {
	f := &l4FastServer{e: e, h: h, l: l}
	t, err := relay.NewTCP(relay.TCPConfig{Listener: ln, IdleTimeout: e.tcpIdleTimeout(l), Context: e.runCtx, Host: f})
	if err != nil {
		return fmt.Errorf("TCP listener %s: %v", l.Name, err)
	}
	f.tcp = t
	e.l4Fast = append(e.l4Fast, f)
	e.acceptWG.Add(1)
	go func() {
		defer e.acceptWG.Done()
		if !e.serveGate.Wait(e.runDone()) {
			f.stop()
			return
		}
		t.Start()
	}()
	return nil
}

// stop stops accepting and closes the listening socket (no new session
// starts once it returns).
func (f *l4FastServer) stop() { f.tcp.Stop() }

// Accepted admits a connection the relay accepted: the access policy, then
// the listener's rate (a client the policy refuses takes nothing from it).
func (f *l4FastServer) Accepted(s *relay.TCPSession) relay.Verdict {
	e, l := f.e, f.l
	peer := s.Peer()
	remote := &net.TCPAddr{IP: peer.Addr().AsSlice(), Port: int(peer.Port())}
	if l.proxyTrust.trusts(remote) {
		// A trusted relay: its PROXY header is read first (serveTCP).
		return relay.Take
	}
	clientIP := peer.Addr().String()
	dstPort := s.LocalPort()
	record := &l4Client{}
	ip := remote.IP
	record.ip.Store(&ip)
	// Listed before the admission check, as serveTCP does (setL4Client): a
	// denylist entry added meanwhile finds the session (closeDenylisted).
	e.l4Conns.Store(s, record)
	if ok, status := f.h.l4Admit(l, remote.IP); !ok {
		e.l4Conns.Delete(s)
		if l.logsAccess() {
			logging.AccessL4(clientIP, l.Protocol, dstPort, status, 0, 0, 0)
		}
		return relay.Refuse
	}
	if rl, ok := e.RateLimiters[l.Name]; ok && !rl.Allow() {
		e.l4Conns.Delete(s)
		logging.Warn("[RATE] Connection from %s rejected (rate limit on %s)", remote, l.Name)
		if l.logsAccess() {
			logging.AccessL4(clientIP, l.Protocol, dstPort, l4StatusRateLimited, 0, 0, 0)
		}
		return relay.Refuse
	}
	if logging.Enabled(logging.InfoLevel) {
		logging.Info("[CONN] New %s client %s -> :%d", l.Protocol, remote, dstPort)
	}
	e.ActiveConns.Add(1)
	s.Data = &l4FastSess{clientIP: clientIP}
	return relay.Serve
}

// Taken serves a trusted relay's connection with serveTCP on its own
// goroutine.
func (f *l4FastServer) Taken(c net.Conn) {
	e := f.e
	e.ActiveConns.Add(1)
	e.l4Conns.Store(c, &l4Client{})
	go func() {
		defer e.ActiveConns.Done()
		defer e.l4Conns.Delete(c)
		f.h.serveTCP(c, f.l)
	}()
}

// Target picks the session's server.
func (f *l4FastServer) Target(s *relay.TCPSession) (relay.TCPTarget, bool) {
	e, l := f.e, f.l
	d := s.Data.(*l4FastSess)
	bv := e.backends()
	balancer, ok := bv.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for listener '%s'", l.Backend, l.Name)
		return relay.TCPTarget{}, false
	}
	backend := bv.Backends[l.Backend]
	if backend != nil && backend.BackendTLS.Enabled {
		logging.Error("[CONN] listener %s: backend %s has backend_tls enabled, which L4 listeners do not implement — refusing %s", l.Name, l.Backend, d.clientIP)
		return relay.TCPTarget{}, false
	}
	if cl, ok := bv.ConnLimiters[l.Backend]; ok {
		if !cl.Acquire() {
			logging.Warn("[CONN] listener %s: backend %s at max_connections — refusing %s", l.Name, l.Backend, d.clientIP)
			d.refused = l4StatusRateLimited
			return relay.TCPTarget{}, false
		}
		d.limiter = cl
	}
	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.Backend, err)
		return relay.TCPTarget{}, false
	}
	d.target, d.balancer = target, balancer
	t := relay.TCPTarget{Addr: target, ConnectTimeout: l.Timeouts.ParseConnect()}
	if _, _, err := net.SplitHostPort(t.Addr); err != nil {
		t.Addr = fmt.Sprintf("%s:%d", t.Addr, l.Port)
	}
	if backend != nil && backend.Timeouts.Connect != "" {
		t.ConnectTimeout = backend.Timeouts.ParseConnect()
	}
	if backend != nil && backend.SendProxyV2 {
		// PROXY v2 to the backend: the source is the client, the
		// destination the address the client connected to.
		// A signed header is bound to the connection to the backend: the
		// address it leaves from (from) and the backend's (to).
		key := backend.SendProxyKey
		t.PrefaceFrom = len(key) > 0
		t.Preface = func(src, dst *net.TCPAddr, from, to netip.AddrPort) ([]byte, error) {
			header := proxyproto.HeaderProxyFromAddrs(2, src, dst)
			if len(key) > 0 {
				if !from.IsValid() || !to.IsValid() {
					logging.Error("Failed to sign PROXY v2 header: the addresses of the connection to the backend are not known")
					return nil, errNoSendAddr
				}
				if err := proxy.SignHeaderFrom(header, key, time.Now(), proxy.Ends{Relay: from, Receiver: to}); err != nil {
					logging.Error("Failed to sign PROXY v2 header: %v", err)
					return nil, err
				}
			}
			b, err := header.Format()
			if err != nil {
				logging.Error("Failed to write PROXY v2 header: %v", err)
				return nil, err
			}
			return b, nil
		}
	}
	return t, true
}

// errNoSendAddr: a header cannot be signed for a connection whose own
// address is not known.
var errNoSendAddr = errors.New("the address of the connection to the backend is not known")

// Connected: the session's backend connection is there.
func (f *l4FastServer) Connected(s *relay.TCPSession) {
	d := s.Data.(*l4FastSess)
	d.balancer.OnConnect(d.target)
}

// Ended releases what the session held and writes its L4 access record.
func (f *l4FastServer) Ended(s *relay.TCPSession, err error) {
	e, l := f.e, f.l
	d := s.Data.(*l4FastSess)
	if s.DialFailed() {
		logging.Error("Backend TCP dial failed: %v", err)
	}
	if s.Linked() {
		d.balancer.OnDisconnect(d.target)
	}
	if d.limiter != nil {
		d.limiter.Release()
	}
	dur := s.Took()
	if logging.Enabled(logging.InfoLevel) {
		peer := s.Peer()
		logging.Info("[CONN] Closed %s (Dur: %v, Err: %v)", &net.TCPAddr{IP: peer.Addr().AsSlice(), Port: int(peer.Port())}, dur, err)
	}
	status := "no_route"
	switch {
	case d.refused != "":
		status = d.refused
	case s.Linked():
		status = "ok"
	}
	if l.logsAccess() {
		logging.AccessL4(d.clientIP, l.Protocol, s.LocalPort(), status, 0, 0, float64(dur.Nanoseconds())/1e6)
	}
	e.l4Conns.Delete(s)
	e.ActiveConns.Done()
}

// AcceptFailed logs an error of the listening socket.
func (f *l4FastServer) AcceptFailed(err error, retry time.Duration) {
	if retry > 0 {
		logging.Error("[ACCEPT] listener %s: %v (retrying in %v)", f.l.Name, err, retry)
		return
	}
	logging.Error("[ACCEPT] listener %s: %v", f.l.Name, err)
}
