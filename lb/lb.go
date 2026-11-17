package lb

import (
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrNoServers = errors.New("no healthy servers available")
)

// Balancer selects a backend server for a new connection.
type Balancer interface {
	Next() (string, error)
	// NextExcluding selects a server excluding the given list (for retries).
	NextExcluding(exclude []string) (string, error)
	// OnConnect notifies the balancer that a connection has been established (for leastconn).
	OnConnect(server string)
	// OnDisconnect notifies the balancer that a connection has closed (for leastconn).
	OnDisconnect(server string)
	// UpdateStatus updates the health status of a server.
	UpdateStatus(server string, healthy bool)
	// MarkDraining marks a server as draining (no new connections, existing continue).
	MarkDraining(server string)
	// IsHealthy returns whether a server is currently in the healthy pool.
	IsHealthy(server string) bool
	// UpdateServers replaces the server list (for DNS-based discovery).
	UpdateServers(servers []string)
	// Eject takes a server out of rotation for d (passive health). The
	// ejection expires on its own and is independent of UpdateStatus: an
	// expired ejection never re-enables a server that an active health
	// check or the admin API marked down, and UpdateStatus(server, true)
	// ends an ejection early.
	Eject(server string, d time.Duration)
	// Servers returns a copy of the configured server list, healthy or not.
	Servers() []string
}

// activeServers returns, in configuration order, the servers that are up
// (status) and not passively ejected at now.
func activeServers(all []string, status map[string]bool, ejected map[string]time.Time, now time.Time) []string {
	active := make([]string, 0, len(all))
	for _, s := range all {
		if !status[s] {
			continue
		}
		if until, ok := ejected[s]; ok && now.Before(until) {
			continue
		}
		active = append(active, s)
	}
	return active
}

// ejectedNow reports whether server has an ejection that has not expired.
func ejectedNow(ejected map[string]time.Time, server string) bool {
	until, ok := ejected[server]
	return ok && time.Now().Before(until)
}

// keepEjections drops the ejections of servers that are no longer in all.
func keepEjections(ejected map[string]time.Time, all []string) map[string]time.Time {
	kept := make(map[string]time.Time, len(ejected))
	for _, s := range all {
		if until, ok := ejected[s]; ok {
			kept[s] = until
		}
	}
	return kept
}

// scheduleEjectionEnd rebuilds the healthy list once the ejection of server
// that ends at until expires. A newer ejection of the same server (another
// until) is left alone; its own timer ends it.
func scheduleEjectionEnd(mu *sync.RWMutex, ejected *map[string]time.Time, server string, until time.Time, rebuild func()) {
	time.AfterFunc(time.Until(until), func() {
		mu.Lock()
		defer mu.Unlock()
		if cur, ok := (*ejected)[server]; ok && cur.Equal(until) {
			delete(*ejected, server)
			rebuild()
		}
	})
}

// NewBalancer creates a new load balancer based on the algorithm name.
func NewBalancer(algorithm string, servers []string) Balancer {
	switch algorithm {
	case "roundrobin":
		return NewRoundRobin(servers)
	case "leastconn":
		return NewLeastConn(servers)
	case "random":
		return NewRandom(servers)
	default:
		return NewRoundRobin(servers)
	}
}

// RoundRobin implementation.
type RoundRobin struct {
	allServers []string             // Immutable configuration
	status     map[string]bool      // Current status (active checks / admin)
	ejected    map[string]time.Time // Passive ejections (until)

	mu      sync.RWMutex
	healthy []string // Derived active list
	current uint64
}

func NewRoundRobin(servers []string) *RoundRobin {
	// Deep copy servers
	all := make([]string, len(servers))
	copy(all, servers)

	// Initially all UP
	status := make(map[string]bool)
	for _, s := range all {
		status[s] = true
	}

	return &RoundRobin{
		allServers: all,
		status:     status,
		ejected:    make(map[string]time.Time),
		healthy:    all, // Initial healthy list is full list
	}
}

func (b *RoundRobin) Next() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.healthy) == 0 {
		return "", errors.New("no healthy backends available")
	}

	next := atomic.AddUint64(&b.current, 1)
	idx := (next - 1) % uint64(len(b.healthy))
	return b.healthy[idx], nil
}

func (b *RoundRobin) UpdateStatus(server string, healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.status[server] = healthy
	if healthy {
		delete(b.ejected, server) // an explicit "up" ends a passive ejection
	}
	b.rebuildLocked()
}

// rebuildLocked recomputes the healthy list, preserving order. b.mu held.
func (b *RoundRobin) rebuildLocked() {
	b.healthy = activeServers(b.allServers, b.status, b.ejected, time.Now())
}

func (b *RoundRobin) Eject(server string, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	until := time.Now().Add(d)
	b.ejected[server] = until
	b.rebuildLocked()
	scheduleEjectionEnd(&b.mu, &b.ejected, server, until, b.rebuildLocked)
}

func (b *RoundRobin) Servers() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]string(nil), b.allServers...)
}

func (b *RoundRobin) OnConnect(server string)    {}
func (b *RoundRobin) OnDisconnect(server string) {}

func (b *RoundRobin) MarkDraining(server string) {
	b.UpdateStatus(server, false)
}

func (b *RoundRobin) IsHealthy(server string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.status[server] && !ejectedNow(b.ejected, server)
}

func (b *RoundRobin) UpdateServers(servers []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allServers = make([]string, len(servers))
	copy(b.allServers, servers)
	b.status = make(map[string]bool)
	for _, s := range b.allServers {
		b.status[s] = true
	}
	b.ejected = keepEjections(b.ejected, b.allServers)
	b.rebuildLocked()
}

func (b *RoundRobin) NextExcluding(exclude []string) (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	excl := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		excl[e] = true
	}
	for i := 0; i < len(b.healthy); i++ {
		next := atomic.AddUint64(&b.current, 1)
		idx := (next - 1) % uint64(len(b.healthy))
		s := b.healthy[idx]
		if !excl[s] {
			return s, nil
		}
	}
	return "", ErrNoServers
}

// Random implementation. Selection uses math/rand/v2's top-level
// functions, which are safe for concurrent use: Next and NextExcluding run
// under the read lock, so a shared *rand.Rand (not goroutine-safe) raced.
type Random struct {
	allServers []string
	status     map[string]bool
	ejected    map[string]time.Time

	mu      sync.RWMutex
	healthy []string
}

func NewRandom(servers []string) *Random {
	all := make([]string, len(servers))
	copy(all, servers)

	status := make(map[string]bool)
	for _, s := range all {
		status[s] = true
	}

	return &Random{
		allServers: all,
		status:     status,
		ejected:    make(map[string]time.Time),
		healthy:    all,
	}
}

func (b *Random) Next() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.healthy) == 0 {
		return "", errors.New("no healthy backends available")
	}
	return b.healthy[rand.IntN(len(b.healthy))], nil
}

func (b *Random) UpdateStatus(server string, healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.status[server] = healthy
	if healthy {
		delete(b.ejected, server)
	}
	b.rebuildLocked()
}

// rebuildLocked recomputes the healthy list. b.mu held.
func (b *Random) rebuildLocked() {
	b.healthy = activeServers(b.allServers, b.status, b.ejected, time.Now())
}

func (b *Random) Eject(server string, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	until := time.Now().Add(d)
	b.ejected[server] = until
	b.rebuildLocked()
	scheduleEjectionEnd(&b.mu, &b.ejected, server, until, b.rebuildLocked)
}

func (b *Random) Servers() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]string(nil), b.allServers...)
}

func (r *Random) OnConnect(server string)    {}
func (r *Random) OnDisconnect(server string) {}

func (r *Random) MarkDraining(server string) {
	r.UpdateStatus(server, false)
}

func (r *Random) IsHealthy(server string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status[server] && !ejectedNow(r.ejected, server)
}

func (r *Random) UpdateServers(servers []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allServers = make([]string, len(servers))
	copy(r.allServers, servers)
	r.status = make(map[string]bool)
	for _, s := range r.allServers {
		r.status[s] = true
	}
	r.ejected = keepEjections(r.ejected, r.allServers)
	r.rebuildLocked()
}

func (r *Random) NextExcluding(exclude []string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	excl := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		excl[e] = true
	}
	candidates := make([]string, 0, len(r.healthy))
	for _, s := range r.healthy {
		if !excl[s] {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		return "", ErrNoServers
	}
	return candidates[rand.IntN(len(candidates))], nil
}

// LeastConn implementation
type LeastConn struct {
	allServers []string
	status     map[string]bool
	ejected    map[string]time.Time

	mu      sync.RWMutex
	healthy []string

	conns map[string]int64 // map[server_addr]count
}

func NewLeastConn(servers []string) *LeastConn {
	all := make([]string, len(servers))
	copy(all, servers)

	status := make(map[string]bool)
	conns := make(map[string]int64)
	for _, s := range all {
		status[s] = true
		conns[s] = 0
	}

	return &LeastConn{
		allServers: all,
		status:     status,
		ejected:    make(map[string]time.Time),
		healthy:    all,
		conns:      conns,
	}
}

func (b *LeastConn) Next() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.healthy) == 0 {
		return "", errors.New("no healthy backends available")
	}

	best := b.healthy[0]
	min := b.conns[best] // Start with first healthy

	for _, s := range b.healthy[1:] {
		c := b.conns[s]
		if c < min {
			best = s
			min = c
		}
	}

	// We optimistically increment here to avoid thundering herd if multiple calls happen before Connect?
	// No, strict implementation waits for OnConnect.
	// But to avoid race where all pick same "0" server, we could pre-increment?
	// For now, adhere to interface.

	return best, nil
}

func (b *LeastConn) UpdateStatus(server string, healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.status[server] = healthy
	if healthy {
		delete(b.ejected, server)
	}
	b.rebuildLocked()
}

// rebuildLocked recomputes the healthy list. b.mu held.
func (b *LeastConn) rebuildLocked() {
	b.healthy = activeServers(b.allServers, b.status, b.ejected, time.Now())
}

func (b *LeastConn) Eject(server string, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	until := time.Now().Add(d)
	b.ejected[server] = until
	b.rebuildLocked()
	scheduleEjectionEnd(&b.mu, &b.ejected, server, until, b.rebuildLocked)
}

func (b *LeastConn) Servers() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]string(nil), b.allServers...)
}

func (b *LeastConn) OnConnect(server string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conns[server]++
}

// OnDisconnect decrements the active connection count for server, clamped
// at 0. An unpaired disconnect (or double-disconnect on an error path)
// used to drive the counter negative — making that server look like
// "most idle" forever and concentrating all new traffic on it.
func (b *LeastConn) OnDisconnect(server string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conns[server] > 0 {
		b.conns[server]--
	}
}

func (b *LeastConn) MarkDraining(server string) {
	b.UpdateStatus(server, false)
}

func (b *LeastConn) IsHealthy(server string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.status[server] && !ejectedNow(b.ejected, server)
}

func (b *LeastConn) UpdateServers(servers []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allServers = make([]string, len(servers))
	copy(b.allServers, servers)
	b.status = make(map[string]bool)
	newConns := make(map[string]int64)
	for _, s := range b.allServers {
		b.status[s] = true
		newConns[s] = b.conns[s] // preserve existing counts
	}
	b.conns = newConns
	b.ejected = keepEjections(b.ejected, b.allServers)
	b.rebuildLocked()
}

func (b *LeastConn) NextExcluding(exclude []string) (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	excl := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		excl[e] = true
	}
	best := ""
	min := int64(1<<63 - 1)
	for _, s := range b.healthy {
		if excl[s] {
			continue
		}
		c := b.conns[s]
		if c < min {
			best = s
			min = c
		}
	}
	if best == "" {
		return "", ErrNoServers
	}
	return best, nil
}
