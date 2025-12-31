package lb

import (
	"errors"
	"math/rand"
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
	// OnConnect notifies the balancer that a connection has been established (for leastconn).
	OnConnect(server string)
	// OnDisconnect notifies the balancer that a connection has closed (for leastconn).
	OnDisconnect(server string)
	// UpdateStatus updates the health status of a server.
	UpdateStatus(server string, healthy bool)
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
	allServers []string        // Immutable configuration
	status     map[string]bool // Current status

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

	// Rebuild healthy list preserving order
	active := make([]string, 0, len(b.allServers))
	for _, s := range b.allServers {
		if b.status[s] {
			active = append(active, s)
		}
	}
	b.healthy = active
}

func (b *RoundRobin) OnConnect(server string)    {}
func (b *RoundRobin) OnDisconnect(server string) {}

// Random implementation.
type Random struct {
	allServers []string
	status     map[string]bool

	mu      sync.RWMutex
	healthy []string

	rnd *rand.Rand
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
		healthy:    all,
		rnd:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (b *Random) Next() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.healthy) == 0 {
		return "", errors.New("no healthy backends available")
	}
	return b.healthy[b.rnd.Intn(len(b.healthy))], nil
}

func (b *Random) UpdateStatus(server string, healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.status[server] = healthy

	active := make([]string, 0, len(b.allServers))
	for _, s := range b.allServers {
		if b.status[s] {
			active = append(active, s)
		}
	}
	b.healthy = active
}

func (r *Random) OnConnect(server string)    {}
func (r *Random) OnDisconnect(server string) {}

// LeastConn implementation
type LeastConn struct {
	allServers []string
	status     map[string]bool

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

	active := make([]string, 0, len(b.allServers))
	for _, s := range b.allServers {
		if b.status[s] {
			active = append(active, s)
		}
	}
	b.healthy = active
}

func (b *LeastConn) OnConnect(server string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conns[server]++
}

func (b *LeastConn) OnDisconnect(server string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conns[server]--
}
