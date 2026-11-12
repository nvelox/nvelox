package sticky

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"sort"
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

// MaxSessions is the cap on concurrent sticky sessions. When reached, the
// oldest 10% (by lastSeen) are evicted. Map-iteration-order eviction would
// let an attacker with many spoofed cookies DoS legitimate users' sessions
// by random removal — we sort by lastSeen instead.
const MaxSessions = 100000

// Set stores a sticky mapping. Evicts oldest (by lastSeen) entries if over MaxSessions.
func (s *Store) Set(key, server string) {
	s.mu.Lock()
	if len(s.sessions) >= MaxSessions {
		s.evictOldestLocked(MaxSessions / 10)
	}
	s.sessions[key] = &session{server: server, lastSeen: time.Now()}
	s.mu.Unlock()
}

// evictOldestLocked removes the n entries with the smallest lastSeen.
// Must be called with s.mu held for write.
// O(n) scan + O(k log k) sort where k is the victim count; cheap enough at
// 10k victims on a 100k map that it runs once per ~90k inserts.
func (s *Store) evictOldestLocked(n int) {
	if n <= 0 || len(s.sessions) == 0 {
		return
	}
	type entry struct {
		key string
		ts  time.Time
	}
	entries := make([]entry, 0, len(s.sessions))
	for k, sess := range s.sessions {
		entries = append(entries, entry{k, sess.lastSeen})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ts.Before(entries[j].ts)
	})
	if n > len(entries) {
		n = len(entries)
	}
	for i := 0; i < n; i++ {
		delete(s.sessions, entries[i].key)
	}
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

// tokenLen is the length of a ServerToToken value: 8 bytes, hex-encoded.
const tokenLen = 16

// isToken reports whether v has the exact shape ServerToToken produces.
func isToken(v string) bool {
	if len(v) != tokenLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// KeyFromCookie returns the server token carried by the sticky cookie, or ""
// when the cookie is absent or is not a token ServerToToken could have
// produced. The value is client input: it is only ever compared against the
// tokens of the pool's own servers (ServerForToken), never stored.
func KeyFromCookie(r *http.Request, cookieName string) string {
	c, err := r.Cookie(cookieName)
	if err != nil || !isToken(c.Value) {
		return ""
	}
	return c.Value
}

// ServerForToken returns the server of servers whose ServerToToken is token,
// or "" if none is.
func ServerForToken(token string, servers []string) string {
	if !isToken(token) {
		return ""
	}
	for _, s := range servers {
		if ServerToToken(s) == token {
			return s
		}
	}
	return ""
}

// NewCookie builds the sticky cookie that pins a client to server: the
// server's token, HttpOnly, SameSite=Lax, Path=/, and Secure when the
// request came in over TLS.
func NewCookie(name, server string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    ServerToToken(server),
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// MaxHeaderKeyLen bounds the header value used as a sticky key; a longer
// value is ignored (no stickiness for that request).
const MaxHeaderKeyLen = 256

// KeyFromHeader returns the sticky key for header-based stickiness: the
// SHA-256 of the header value (hex), so a store key has a fixed size
// whatever the client sends, or "" when the header is absent or longer than
// MaxHeaderKeyLen.
func KeyFromHeader(r *http.Request, headerName string) string {
	v := r.Header.Get(headerName)
	if v == "" || len(v) > MaxHeaderKeyLen {
		return ""
	}
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
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
