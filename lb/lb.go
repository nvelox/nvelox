package lb

import (
	"errors"
	"math/rand"
	"sync/atomic"
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

// RoundRobin implementation
type RoundRobin struct {
	servers []string
	next    uint64
}

func NewRoundRobin(servers []string) *RoundRobin {
	return &RoundRobin{
		servers: servers,
	}
}

func (r *RoundRobin) Next() (string, error) {
	if len(r.servers) == 0 {
		return "", ErrNoServers
	}
	n := atomic.AddUint64(&r.next, 1)
	return r.servers[(n-1)%uint64(len(r.servers))], nil
}

func (r *RoundRobin) OnConnect(server string)    {}
func (r *RoundRobin) OnDisconnect(server string) {}

// Random implementation
type Random struct {
	servers []string
}

func NewRandom(servers []string) *Random {
	return &Random{
		servers: servers,
	}
}

func (r *Random) Next() (string, error) {
	if len(r.servers) == 0 {
		return "", ErrNoServers
	}
	return r.servers[rand.Intn(len(r.servers))], nil
}

func (r *Random) OnConnect(server string)    {}
func (r *Random) OnDisconnect(server string) {}

// LeastConn implementation
type LeastConn struct {
	servers []*serverState
}

type serverState struct {
	addr  string
	conns int64
}

func NewLeastConn(servers []string) *LeastConn {
	ss := make([]*serverState, len(servers))
	for i, s := range servers {
		ss[i] = &serverState{addr: s}
	}
	return &LeastConn{servers: ss}
}

func (l *LeastConn) Next() (string, error) {
	if len(l.servers) == 0 {
		return "", ErrNoServers
	}

	var best *serverState
	var min int64 = -1

	// O(N) scan. For small N this is fine. For large N, a heap would be better.
	for _, s := range l.servers {
		c := atomic.LoadInt64(&s.conns)
		if min == -1 || c < min {
			min = c
			best = s
		}
	}
	// Fallback if no servers
	if best == nil {
		return "", ErrNoServers
	}
	return best.addr, nil
}

func (l *LeastConn) OnConnect(server string) {
	for _, s := range l.servers {
		if s.addr == server {
			atomic.AddInt64(&s.conns, 1)
			break
		}
	}
}

func (l *LeastConn) OnDisconnect(server string) {
	for _, s := range l.servers {
		if s.addr == server {
			atomic.AddInt64(&s.conns, -1)
			break
		}
	}
}
