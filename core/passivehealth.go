package core

import (
	"sync"

	"nvelox/core/logging"
	"nvelox/lb"
)

// PassiveHealthTracker tracks consecutive failures per server and marks
// backends as unhealthy when the threshold is reached.
type PassiveHealthTracker struct {
	mu       sync.Mutex
	failures map[string]int // server -> consecutive failure count
	maxFails int
	balancer lb.Balancer
	backend  string
}

// NewPassiveHealthTracker creates a tracker for the given backend.
func NewPassiveHealthTracker(backendName string, maxFails int, balancer lb.Balancer) *PassiveHealthTracker {
	return &PassiveHealthTracker{
		failures: make(map[string]int),
		maxFails: maxFails,
		balancer: balancer,
		backend:  backendName,
	}
}

// RecordFailure increments the failure count for a server.
// If it reaches maxFails, the server is marked unhealthy.
func (p *PassiveHealthTracker) RecordFailure(server string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures[server]++
	if p.failures[server] >= p.maxFails {
		logging.Warn("[PASSIVE-HEALTH] Server %s in backend %s marked unhealthy after %d failures",
			server, p.backend, p.failures[server])
		p.balancer.UpdateStatus(server, false)
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
