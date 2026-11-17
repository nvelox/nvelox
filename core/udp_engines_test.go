package core

import (
	"net"
	"syscall"
	"testing"
)

// The UDP listeners are served by the event loops where they are supported
// and by nbio elsewhere. The tests of UDP behaviour run on both, and look at
// live sessions through stUDPSessions, whatever engine holds them.

// stUDPEngines runs body once per UDP engine this platform has.
func stUDPEngines(t *testing.T, body func(t *testing.T)) {
	t.Helper()
	engines := []string{"nbio"}
	if udpFastEnabled() {
		engines = []string{"loops", "nbio"}
	}
	for _, eng := range engines {
		t.Run(eng, func(t *testing.T) {
			udpFastOff.Store(eng == "nbio")
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
