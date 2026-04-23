package middleware

import (
	"testing"
	"time"
)

func TestIPRateLimiter_Basic(t *testing.T) {
	rl := NewIPRateLimiter(10, 3)
	defer rl.Stop()

	// First 3 from same IP allowed (burst)
	for i := 0; i < 3; i++ {
		if !rl.Allow("10.0.0.1:1234") {
			t.Errorf("request %d should be allowed (burst)", i)
		}
	}

	// 4th should be denied
	if rl.Allow("10.0.0.1:1234") {
		t.Error("4th request should be denied")
	}
}

func TestIPRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewIPRateLimiter(10, 2)
	defer rl.Stop()

	// Each IP gets its own bucket
	if !rl.Allow("10.0.0.1:1234") {
		t.Error("IP1 request 1 should be allowed")
	}
	if !rl.Allow("10.0.0.2:1234") {
		t.Error("IP2 request 1 should be allowed")
	}
	if !rl.Allow("10.0.0.1:1234") {
		t.Error("IP1 request 2 should be allowed (burst=2)")
	}
	if rl.Allow("10.0.0.1:1234") {
		t.Error("IP1 request 3 should be denied")
	}
	// IP2 still has 1 token
	if !rl.Allow("10.0.0.2:5678") {
		t.Error("IP2 request 2 should be allowed (same IP different port)")
	}
}

func TestIPRateLimiter_Replenish(t *testing.T) {
	rl := NewIPRateLimiter(20, 1)
	defer rl.Stop()

	if !rl.Allow("10.0.0.1:80") {
		t.Error("first request should be allowed")
	}
	if rl.Allow("10.0.0.1:80") {
		t.Error("second request should be denied")
	}

	time.Sleep(100 * time.Millisecond) // 20/s * 0.1s = 2 tokens replenished, capped to burst=1

	if !rl.Allow("10.0.0.1:80") {
		t.Error("request after replenish should be allowed")
	}
}
