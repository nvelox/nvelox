package middleware

import (
	"net"
	"sync"
	"time"
)

// IPRateLimiter provides per-IP rate limiting using token buckets.
type IPRateLimiter struct {
	rate   float64
	burst  int
	mu     sync.Mutex
	ips    map[string]*ipEntry
	stopCh chan struct{}
}

type ipEntry struct {
	tokens   float64
	lastTime time.Time
}

// NewIPRateLimiter creates a per-IP rate limiter.
func NewIPRateLimiter(rate float64, burst int) *IPRateLimiter {
	if burst < 1 {
		burst = 1
	}
	rl := &IPRateLimiter{
		rate:   rate,
		burst:  burst,
		ips:    make(map[string]*ipEntry),
		stopCh: make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Allow checks if a request from the given remote address is allowed.
func (rl *IPRateLimiter) Allow(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.ips[host]
	if !ok {
		// Prevent unbounded growth — evict oldest if over 100k entries
		const maxEntries = 100000
		if len(rl.ips) >= maxEntries {
			rl.evictUnsafe()
		}
		entry = &ipEntry{
			tokens:   float64(rl.burst) - 1,
			lastTime: time.Now(),
		}
		rl.ips[host] = entry
		return true
	}

	now := time.Now()
	elapsed := now.Sub(entry.lastTime).Seconds()
	entry.lastTime = now

	entry.tokens += elapsed * rl.rate
	if entry.tokens > float64(rl.burst) {
		entry.tokens = float64(rl.burst)
	}

	if entry.tokens >= 1.0 {
		entry.tokens -= 1.0
		return true
	}
	return false
}

// Stop shuts down the cleanup goroutine.
func (rl *IPRateLimiter) Stop() {
	close(rl.stopCh)
}

func (rl *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.evict()
		}
	}
}

// evictUnsafe removes the oldest 10% of entries. Must be called with lock held.
func (rl *IPRateLimiter) evictUnsafe() {
	count := len(rl.ips) / 10
	if count < 1 {
		count = 1
	}
	for ip := range rl.ips {
		delete(rl.ips, ip)
		count--
		if count <= 0 {
			break
		}
	}
}

func (rl *IPRateLimiter) evict() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, entry := range rl.ips {
		if entry.lastTime.Before(cutoff) {
			delete(rl.ips, ip)
		}
	}
}
