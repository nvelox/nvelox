package httpproxy

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"nvelox/core/logging"
)

// tunnelConn is the client side of an upgraded (WebSocket) connection. Both
// directions of the relay go through it (the client's bytes are read from
// it, the backend's are written to it), so it sees all of the tunnel's
// traffic: it closes the tunnel after an idle period with no byte either way
// and when its bind group stops. A reload keeps it only while the new
// configuration still admits it (BindGroup.recheckTunnel), and the dynamic
// denylist closes it when it blocks its client (BindGroup.CloseTunnelsOf).
// Closing it also cancels the request context, which makes ReverseProxy
// close the backend connection.
//
// It deliberately has no CloseWrite: when one side ends, ReverseProxy then
// closes both instead of half-closing the client and waiting.
type tunnelConn struct {
	net.Conn
	set     *tunnelSet
	cancel  context.CancelFunc
	idle    atomic.Int64 // the idle period (a reload can change it)
	last    atomic.Int64 // UnixNano of the last byte in either direction
	written atomic.Int64 // bytes written to the client

	// adm is what the tunnel was admitted with (nil: nothing a reload can
	// re-check, so a reload closes it); gen is the reload generation of the
	// site instance that admitted it.
	adm *tunnelAdmission
	gen uint64
	// client is the client the access rules checked, for the dynamic
	// denylist (nil: unknown).
	client atomic.Pointer[net.IP]

	mu        sync.Mutex
	timer     *time.Timer
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

// tunnelAdmission is what a tunnel's upgrade request was admitted with. A
// reload asks the new configuration whether it would admit the same request
// to the same place (HTTPServer.tunnelRefusal).
type tunnelAdmission struct {
	req     *http.Request // the upgrade request as the access rules saw it
	route   *RouteResult  // the route it matched (nil: no route, the default backend)
	backend string        // the backend the tunnel goes to
	target  string        // the backend server it is connected to
	scheme  string        // "http" or "https" to that server
	// rerouted: try_files moved the request to another path or route on the
	// way to the backend. The re-check does not replay that, so a reload
	// closes such a tunnel.
	rerouted bool
}

// tunnelIdleTimeout is how long a tunnel may carry no byte in either
// direction before it is closed: the site's timeouts.idle when set, else
// defaultIdleTimeout (120 s). An explicit idle "0" (no keep-alive limit)
// still gets the default here: a hijacked connection has no other bound.
func (s *HTTPServer) tunnelIdleTimeout() time.Duration {
	if s.Listener != nil {
		if d := s.Listener.Timeouts.ParseIdle(); d > 0 {
			return d
		}
	}
	return defaultIdleTimeout
}

// tunnelSet tracks open tunnels. All sites of a bind group share the group's
// set (AddSite / ReplaceSites), so BindGroup.Stop finds every tunnel, also
// those still open on site instances a reload replaced, and a reload can
// re-check them all. A site outside any bind group uses its own set.
type tunnelSet struct {
	mu     sync.Mutex
	m      map[*tunnelConn]struct{}
	closed bool
	// gen counts the bind group's reloads. recheck (set by the group)
	// closes a tunnel the group's current sites would no longer admit.
	gen     uint64
	recheck func(*tunnelConn)
}

// add tracks t; ok is false once the set is closed. stale: t was admitted by
// a site instance a reload has replaced since (its upgrade was in flight
// across the reload), so the caller must re-check it.
func (ts *tunnelSet) add(t *tunnelConn) (ok, stale bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.closed {
		return false, false
	}
	if ts.m == nil {
		ts.m = make(map[*tunnelConn]struct{})
	}
	ts.m[t] = struct{}{}
	return true, ts.recheck != nil && t.gen < ts.gen
}

// nextGen is the generation the sites of the next reload get.
func (ts *tunnelSet) nextGen() uint64 {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.gen + 1
}

// startGen makes gen current (the sites of gen are published) and returns
// the open tunnels, which the caller re-checks. A tunnel added from here on
// by an older site instance is reported stale by add.
func (ts *tunnelSet) startGen(gen uint64) []*tunnelConn {
	ts.mu.Lock()
	ts.gen = gen
	ts.mu.Unlock()
	return ts.open()
}

// open returns the tunnels open now.
func (ts *tunnelSet) open() []*tunnelConn {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	open := make([]*tunnelConn, 0, len(ts.m))
	for t := range ts.m {
		open = append(open, t)
	}
	return open
}

func (ts *tunnelSet) remove(t *tunnelConn) {
	ts.mu.Lock()
	delete(ts.m, t)
	ts.mu.Unlock()
}

// closeAll closes every tunnel of the set and any added after this.
func (ts *tunnelSet) closeAll() {
	ts.mu.Lock()
	ts.closed = true
	ts.mu.Unlock()
	for _, t := range ts.open() {
		_ = t.Close()
	}
}

// tunnelSet returns the set s tracks its tunnels in (its bind group's, else
// its own) and the reload generation s belongs to.
func (s *HTTPServer) tunnelSet() (*tunnelSet, uint64) {
	s.tunnelsMu.Lock()
	defer s.tunnelsMu.Unlock()
	if s.tunnels == nil {
		s.tunnels = &tunnelSet{}
	}
	return s.tunnels, s.tunnelGen
}

// setTunnelSet points s at its bind group's set, as a site of reload
// generation gen, before s serves traffic.
func (s *HTTPServer) setTunnelSet(ts *tunnelSet, gen uint64) {
	s.tunnelsMu.Lock()
	s.tunnels, s.tunnelGen = ts, gen
	s.tunnelsMu.Unlock()
}

// trackTunnel wraps a hijacked client connection as a tunnel of s. cancel
// cancels the upgrade request's context; adm and client are what the
// request was admitted with (nil when unknown). If the set is already
// closed (the bind group stopped), the tunnel is closed at once; if s was
// replaced by a reload while the upgrade was in flight, the tunnel is
// re-checked against the current sites.
func (s *HTTPServer) trackTunnel(c net.Conn, cancel context.CancelFunc, adm *tunnelAdmission, client net.IP) *tunnelConn {
	set, gen := s.tunnelSet()
	t := &tunnelConn{Conn: c, set: set, cancel: cancel, adm: adm, gen: gen}
	t.idle.Store(int64(s.tunnelIdleTimeout()))
	if client != nil {
		t.client.Store(&client)
	}
	t.last.Store(time.Now().UnixNano())
	ok, stale := t.set.add(t)
	if !ok {
		_ = t.Close()
		return t
	}
	if client != nil && s.DynDenylist != nil && s.DynDenylist.Blocked(client) {
		// Blocked after the request's access check, before the tunnel was
		// tracked: the denylist's close pass (CloseTunnelsOf) missed it.
		_ = t.Close()
		return t
	}
	t.mu.Lock()
	if !t.closed {
		t.timer = time.AfterFunc(time.Duration(t.idle.Load()), t.checkIdle)
	}
	t.mu.Unlock()
	if stale {
		t.set.recheck(t)
	}
	return t
}

func (t *tunnelConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (t *tunnelConn) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	if n > 0 {
		t.last.Store(time.Now().UnixNano())
		t.written.Add(int64(n))
	}
	return n, err
}

// Close closes the client connection, cancels the upgrade request (closing
// the backend side) and forgets the tunnel. Idempotent.
func (t *tunnelConn) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		if t.timer != nil {
			t.timer.Stop()
		}
		t.mu.Unlock()
		t.cancel()
		t.closeErr = t.Conn.Close()
		t.set.remove(t)
	})
	return t.closeErr
}

// checkIdle runs when the idle period may have elapsed: it closes the tunnel
// if no byte moved for the idle period, else waits for the rest of it.
func (t *tunnelConn) checkIdle() {
	idle := time.Duration(t.idle.Load())
	idleFor := time.Since(time.Unix(0, t.last.Load()))
	if idleFor >= idle {
		logging.Info("[WS] closing tunnel %s idle for %v", t.Conn.RemoteAddr(), idleFor.Round(time.Millisecond))
		_ = t.Close()
		return
	}
	t.mu.Lock()
	if !t.closed {
		t.timer.Reset(idle - idleFor)
	}
	t.mu.Unlock()
}

// setIdle gives the tunnel another idle period (a reload kept it under a
// site with another timeouts.idle) and re-arms the timer for it.
func (t *tunnelConn) setIdle(d time.Duration) {
	if time.Duration(t.idle.Swap(int64(d))) == d {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.timer == nil {
		return
	}
	t.timer.Reset(max(0, d-time.Since(time.Unix(0, t.last.Load()))))
}
