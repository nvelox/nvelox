package httpproxy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"nvelox/core/logging"
)

// tunnelConn is the client side of an upgraded (WebSocket) connection. Both
// directions of the relay go through it (the client's bytes are read from
// it, the backend's are written to it), so it sees all of the tunnel's
// traffic: it closes the tunnel after an idle period with no byte either way
// and when its bind group stops. A reload leaves it running. Closing it also
// cancels the request context, which makes ReverseProxy close the backend
// connection.
//
// It deliberately has no CloseWrite: when one side ends, ReverseProxy then
// closes both instead of half-closing the client and waiting.
type tunnelConn struct {
	net.Conn
	set     *tunnelSet
	cancel  context.CancelFunc
	idle    time.Duration
	last    atomic.Int64 // UnixNano of the last byte in either direction
	written atomic.Int64 // bytes written to the client

	mu        sync.Mutex
	timer     *time.Timer
	closed    bool
	closeOnce sync.Once
	closeErr  error
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
// those still open on site instances a reload replaced: a reload does not cut
// a tunnel, it runs until it ends or goes idle. A site outside any bind group
// uses its own set.
type tunnelSet struct {
	mu     sync.Mutex
	m      map[*tunnelConn]struct{}
	closed bool
}

// add tracks t; false once the set is closed.
func (ts *tunnelSet) add(t *tunnelConn) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.closed {
		return false
	}
	if ts.m == nil {
		ts.m = make(map[*tunnelConn]struct{})
	}
	ts.m[t] = struct{}{}
	return true
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
	open := make([]*tunnelConn, 0, len(ts.m))
	for t := range ts.m {
		open = append(open, t)
	}
	ts.mu.Unlock()
	for _, t := range open {
		_ = t.Close()
	}
}

// tunnelSet returns the set s tracks its tunnels in: its bind group's, else
// its own.
func (s *HTTPServer) tunnelSet() *tunnelSet {
	s.tunnelsMu.Lock()
	defer s.tunnelsMu.Unlock()
	if s.tunnels == nil {
		s.tunnels = &tunnelSet{}
	}
	return s.tunnels
}

// setTunnelSet points s at its bind group's set, before s serves traffic.
func (s *HTTPServer) setTunnelSet(ts *tunnelSet) {
	s.tunnelsMu.Lock()
	s.tunnels = ts
	s.tunnelsMu.Unlock()
}

// trackTunnel wraps a hijacked client connection as a tunnel of s. cancel
// cancels the upgrade request's context. If the set is already closed (the
// bind group stopped), the tunnel is closed at once.
func (s *HTTPServer) trackTunnel(c net.Conn, cancel context.CancelFunc) *tunnelConn {
	t := &tunnelConn{Conn: c, set: s.tunnelSet(), cancel: cancel, idle: s.tunnelIdleTimeout()}
	t.last.Store(time.Now().UnixNano())
	if !t.set.add(t) {
		_ = t.Close()
		return t
	}
	t.mu.Lock()
	if !t.closed {
		t.timer = time.AfterFunc(t.idle, t.checkIdle)
	}
	t.mu.Unlock()
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
// if no byte moved for t.idle, else waits for the rest of the period.
func (t *tunnelConn) checkIdle() {
	idleFor := time.Since(time.Unix(0, t.last.Load()))
	if idleFor >= t.idle {
		logging.Info("[WS] closing tunnel %s idle for %v", t.Conn.RemoteAddr(), idleFor.Round(time.Millisecond))
		_ = t.Close()
		return
	}
	t.mu.Lock()
	if !t.closed {
		t.timer.Reset(t.idle - idleFor)
	}
	t.mu.Unlock()
}
