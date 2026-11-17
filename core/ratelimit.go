package core

import (
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	rate     float64 // tokens per second
	burst    float64 // max tokens (bucket capacity)
	tokens   float64
	lastTime time.Time
	mu       sync.Mutex
}

// NewRateLimiter creates a rate limiter with the given rate (tokens/sec) and burst size.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	b := float64(burst)
	if b < 1 {
		b = 1
	}
	return &RateLimiter{
		rate:     rate,
		burst:    b,
		tokens:   b, // start full
		lastTime: time.Now(),
	}
}

// Allow returns true if a token is available, consuming one token.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.lastTime = now

	// Replenish tokens
	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.burst {
		rl.tokens = rl.burst
	}

	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0
		return true
	}
	return false
}
