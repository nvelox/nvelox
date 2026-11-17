package core

import (
	"net"
	"sync"
	"time"

	"nvelox/core/logging"
)

// UDPPool manages UDP session affinity — packets from the same client
// go to the same backend connection for the duration of the session.
type UDPPool struct {
	mu       sync.RWMutex
	sessions map[string]*UDPSession // key: "clientAddr|backendName"
	ttl      time.Duration
	stopCh   chan struct{}
}

// UDPSession represents an active UDP client-to-backend mapping.
type UDPSession struct {
	BackendConn net.Conn
	Target      string
	LastActive  time.Time
	mu          sync.Mutex
}

// NewUDPPool creates a pool with the given session TTL and starts cleanup.
func NewUDPPool(ttl time.Duration) *UDPPool {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	p := &UDPPool{
		sessions: make(map[string]*UDPSession),
		ttl:      ttl,
		stopCh:   make(chan struct{}),
	}
	go p.cleanupLoop()
	return p
}

// Get returns an existing session for the key, or nil if not found/expired.
func (p *UDPPool) Get(key string) *UDPSession {
	p.mu.RLock()
	s, ok := p.sessions[key]
	p.mu.RUnlock()

	if !ok {
		return nil
	}

	s.mu.Lock()
	if time.Since(s.LastActive) > p.ttl {
		s.mu.Unlock()
		// Expired — remove and close
		p.Remove(key)
		return nil
	}
	s.LastActive = time.Now()
	s.mu.Unlock()
	return s
}

// Put stores a new session.
func (p *UDPPool) Put(key string, session *UDPSession) {
	p.mu.Lock()
	p.sessions[key] = session
	p.mu.Unlock()
}

// Remove removes and closes a session.
func (p *UDPPool) Remove(key string) {
	p.mu.Lock()
	s, ok := p.sessions[key]
	if ok {
		delete(p.sessions, key)
	}
	p.mu.Unlock()

	if ok && s.BackendConn != nil {
		s.BackendConn.Close()
	}
}

// Stop shuts down the cleanup goroutine and closes all sessions.
func (p *UDPPool) Stop() {
	close(p.stopCh)

	p.mu.Lock()
	for k, s := range p.sessions {
		if s.BackendConn != nil {
			s.BackendConn.Close()
		}
		delete(p.sessions, k)
	}
	p.mu.Unlock()
}

// Len returns the number of active sessions.
func (p *UDPPool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

func (p *UDPPool) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.evictExpired()
		}
	}
}

func (p *UDPPool) evictExpired() {
	now := time.Now()
	var toRemove []string

	p.mu.RLock()
	for k, s := range p.sessions {
		s.mu.Lock()
		if now.Sub(s.LastActive) > p.ttl {
			toRemove = append(toRemove, k)
		}
		s.mu.Unlock()
	}
	p.mu.RUnlock()

	for _, k := range toRemove {
		logging.Info("[UDP-POOL] Evicting expired session: %s", k)
		p.Remove(k)
	}
}
