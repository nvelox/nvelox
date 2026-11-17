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

// TestEvictUnsafe_PrefersOldest verifies the cap-hit eviction removes the
// oldest entries (by lastTime), not random ones. A bot-farm attacker with
// many IPs must not be able to evict legitimate users' token buckets,
// which would reset their rate limits on demand.
func TestEvictUnsafe_PrefersOldest(t *testing.T) {
	rl := NewIPRateLimiter(1, 1)
	defer rl.Stop()

	base := time.Now()
	rl.mu.Lock()
	for i, ip := range []string{"old1", "old2", "new1", "new2", "new3"} {
		rl.ips[ip] = &ipEntry{
			tokens:   1.0,
			lastTime: base.Add(time.Duration(i) * time.Second),
		}
	}
	// Evict 40% (2 out of 5) to exercise the oldest-first logic deterministically.
	// evictUnsafe always picks len/10 but min 1; force the path with a manual call
	// using the private helper to prove ordering.
	entries := make(map[string]bool)
	for k := range rl.ips {
		entries[k] = true
	}
	rl.mu.Unlock()

	// Shrink len/10 calculation by seeding more entries so 10% == 2.
	rl.mu.Lock()
	for i := 0; i < 15; i++ {
		ip := "pad" + time.Duration(i).String()
		rl.ips[ip] = &ipEntry{
			tokens:   1.0,
			lastTime: base.Add(1 * time.Hour), // padding is newer than our old1/old2
		}
	}
	rl.evictUnsafe()
	// After evictUnsafe, 10% of 20 = 2 entries removed — must be old1,old2.
	_, hasOld1 := rl.ips["old1"]
	_, hasOld2 := rl.ips["old2"]
	_, hasNew1 := rl.ips["new1"]
	rl.mu.Unlock()

	if hasOld1 || hasOld2 {
		t.Error("oldest entries (old1, old2) must be evicted first")
	}
	if !hasNew1 {
		t.Error("newer entry (new1) must survive the eviction")
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
