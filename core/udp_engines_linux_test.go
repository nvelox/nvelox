//go:build linux

package core

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

// stFastUDPSessions lists the sessions of the ngx engine.
func stFastUDPSessions(e *Engine) []stUDPSession {
	e.reloadMu.Lock()
	u := e.udpFast
	e.reloadMu.Unlock()
	if u == nil {
		return nil
	}
	u.mu.Lock()
	started := u.started
	u.mu.Unlock()
	if !started {
		return nil
	}
	var mu sync.Mutex
	var out []stUDPSession
	var wg sync.WaitGroup
	for _, per := range u.per {
		per := per
		wg.Add(1)
		per.lp.Post(func() {
			defer wg.Done()
			for s := per.list.head; s != nil; s = s.lnext {
				s := s
				info := stUDPSession{RealClientIP: s.realClientIP, PeerTrusted: s.peerTrusted, ClientResolved: s.clientResolved,
					RelayPending: s.relayPending, HasBackend: s.bfd >= 0}
				info.BackendSockopt = func(level, opt int) (int, error) {
					var v int
					err := errors.New("the session has no backend socket")
					done := make(chan struct{})
					per.lp.Post(func() {
						defer close(done)
						if !s.closed && s.bfd >= 0 {
							v, err = unix.GetsockoptInt(s.bfd, level, opt)
						}
					})
					<-done
					return v, err
				}
				info.Close = func() {
					done := make(chan struct{})
					per.lp.Post(func() { s.close(nil); close(done) })
					<-done
				}
				mu.Lock()
				out = append(out, info)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return out
}
