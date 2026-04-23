package sticky

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"
)

// Store maps session keys to backend servers with TTL-based expiry.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*session
	ttl      time.Duration
	stopCh   chan struct{}
}

type session struct {
	server   string
	lastSeen time.Time
}

// NewStore creates a sticky session store with the given TTL.
func NewStore(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	s := &Store{
		sessions: make(map[string]*session),
		ttl:      ttl,
		stopCh:   make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Get returns the sticky server for the given key, or empty string if not found/expired.
func (s *Store) Get(key string) string {
	s.mu.RLock()
	sess, ok := s.sessions[key]
	s.mu.RUnlock()
	if !ok {
		return ""
	}
	if time.Since(sess.lastSeen) > s.ttl {
		s.mu.Lock()
		delete(s.sessions, key)
		s.mu.Unlock()
		return ""
	}
	s.mu.Lock()
	sess.lastSeen = time.Now()
	s.mu.Unlock()
	return sess.server
}

// Set stores a sticky mapping.
func (s *Store) Set(key, server string) {
	s.mu.Lock()
	s.sessions[key] = &session{server: server, lastSeen: time.Now()}
	s.mu.Unlock()
}

// Stop shuts down the cleanup goroutine.
func (s *Store) Stop() {
	close(s.stopCh)
}

// Len returns the number of active sessions.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.evict()
		}
	}
}

func (s *Store) evict() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sess := range s.sessions {
		if now.Sub(sess.lastSeen) > s.ttl {
			delete(s.sessions, k)
		}
	}
}

// KeyFromCookie extracts the sticky key from a request cookie.
func KeyFromCookie(r *http.Request, cookieName string) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// KeyFromHeader extracts the sticky key from a request header.
func KeyFromHeader(r *http.Request, headerName string) string {
	return r.Header.Get(headerName)
}

// KeyFromIPHash returns a hash of the client IP for IP-hash stickiness.
func KeyFromIPHash(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	h := sha256.Sum256([]byte(host))
	return hex.EncodeToString(h[:8])
}

// ServerToToken encodes a server address as a short cookie-safe token.
func ServerToToken(server string) string {
	h := sha256.Sum256([]byte(server))
	return hex.EncodeToString(h[:8])
}
