package core

import (
	"net"
	"sync"
	"syscall"
	"testing"

	"github.com/nvelox/ngx/relay"
)

// The UDP listeners are served by the event loops where they are supported
// and by a reading goroutine per socket elsewhere (udpsock.go). The tests of
// UDP behaviour run on both, and look at live sessions through
// stUDPSessions, whatever path holds them.

// stUDPEngines runs body once per UDP engine this platform has.
func stUDPEngines(t *testing.T, body func(t *testing.T)) {
	t.Helper()
	engines := []string{"sockets"}
	if udpFastEnabled() {
		engines = []string{"loops", "sockets"}
	}
	for _, eng := range engines {
		t.Run(eng, func(t *testing.T) {
			udpFastOff.Store(eng == "sockets")
			defer udpFastOff.Store(false)
			body(t)
		})
	}
}

// stUDPSession is a live UDP session as the tests see it.
type stUDPSession struct {
	RealClientIP   string // the client: the peer, or the client a relay named
	PeerTrusted    bool   // the peer is a trusted relay
	ClientResolved bool   // a header of the relay named the client
	RelayPending   bool   // a relay's session no header has admitted yet
	HasBackend     bool   // the session has its backend socket
	// BackendSockopt reads an integer option of the backend socket.
	BackendSockopt func(level, opt int) (int, error)
	// Close ends the session.
	Close func()
}

// stUDPSessions lists the live UDP sessions of e.
func stUDPSessions(e *Engine) []stUDPSession {
	var out []stUDPSession
	h := stHandler(e)
	h.sessions.Range(func(k, v any) bool {
		ctx := v.(*ConnContext)
		ctx.Mu.Lock()
		defer ctx.Mu.Unlock()
		if ctx.IsBackend || ctx.closed {
			return true
		}
		s := stUDPSession{RealClientIP: ctx.RealClientIP, PeerTrusted: ctx.PeerTrusted, ClientResolved: ctx.ClientResolved,
			RelayPending: ctx.relayPending, HasBackend: ctx.PeerConn != nil}
		if uc, ok := ctx.PeerConn.(*net.UDPConn); ok {
			s.BackendSockopt = func(level, opt int) (int, error) {
				raw, err := uc.SyscallConn()
				if err != nil {
					return 0, err
				}
				var v int
				var serr error
				if err := raw.Control(func(fd uintptr) { v, serr = syscall.GetsockoptInt(int(fd), level, opt) }); err != nil {
					return 0, err
				}
				return v, serr
			}
		}
		closer := k.(interface{ Close() error })
		s.Close = func() { closer.Close() }
		out = append(out, s)
		return true
	})
	return append(out, stFastUDPSessions(e)...)
}

// stFastUDPSessions lists the sessions of the event loops' relay.
func stFastUDPSessions(e *Engine) []stUDPSession {
	e.reloadMu.Lock()
	u := e.udpFast
	e.reloadMu.Unlock()
	if u == nil || u.relay == nil {
		return nil
	}
	var mu sync.Mutex
	var out []stUDPSession
	u.relay.Each(func(s *relay.UDPSession) {
		d := s.Data.(*udpFastSess)
		info := stUDPSession{RealClientIP: d.realClientIP, PeerTrusted: d.peerTrusted, ClientResolved: d.clientResolved,
			RelayPending: d.relayPending, HasBackend: s.Linked()}
		info.BackendSockopt = func(level, opt int) (v int, err error) {
			s.Do(func() { v, err = s.ServerSockopt(level, opt) })
			return v, err
		}
		info.Close = func() { s.Do(func() { s.End(nil) }) }
		mu.Lock()
		out = append(out, info)
		mu.Unlock()
	})
	return out
}

// stL4Goroutines has the TCP listeners that start during the test served
// by goroutines and not by the event loops.
func stL4Goroutines(t *testing.T) {
	l4FastOff.Store(true)
	t.Cleanup(func() { l4FastOff.Store(false) })
}
