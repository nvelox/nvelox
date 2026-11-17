package core

import (
	"sync"
	"time"

	"nvelox/core/logging"
	"nvelox/lb"
)

// PassiveEjectDuration is how long passive health keeps a server out of
// rotation after max_fails consecutive failures. The ejection then expires
// on its own: the server takes traffic again, and its next failure (the
// count is not reset until a success) ejects it for another period. It used
// to be marked down for good — an active health check only reports its own
// up/down flips, so it never brought the server back, and nothing else did.
const PassiveEjectDuration = 30 * time.Second

// PassiveHealthTracker tracks consecutive failures per server and ejects a
// server for PassiveEjectDuration when the threshold is reached.
type PassiveHealthTracker struct {
	mu       sync.Mutex
	failures map[string]int // server -> consecutive failure count
	maxFails int
	balancer lb.Balancer
	backend  string
	ejectFor time.Duration
}

// NewPassiveHealthTracker creates a tracker for the given backend.
func NewPassiveHealthTracker(backendName string, maxFails int, balancer lb.Balancer) *PassiveHealthTracker {
	return &PassiveHealthTracker{
		failures: make(map[string]int),
		maxFails: maxFails,
		balancer: balancer,
		backend:  backendName,
		ejectFor: PassiveEjectDuration,
	}
}

// RecordFailure increments the failure count for a server. If it reaches
// maxFails, the server is ejected for ejectFor. The ejection never overrides
// an active health check or the admin API (see lb.Balancer.Eject).
func (p *PassiveHealthTracker) RecordFailure(server string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures[server]++
	if p.failures[server] >= p.maxFails {
		logging.Warn("[PASSIVE-HEALTH] Server %s in backend %s ejected for %v after %d failures",
			server, p.backend, p.ejectFor, p.failures[server])
		p.balancer.Eject(server, p.ejectFor)
	}
}

// RecordSuccess resets the failure count for a server.
func (p *PassiveHealthTracker) RecordSuccess(server string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failures[server] > 0 {
		p.failures[server] = 0
	}
}

// GetFailures returns the current failure count for a server.
func (p *PassiveHealthTracker) GetFailures(server string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failures[server]
}
