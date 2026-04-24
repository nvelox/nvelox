package core

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_Burst(t *testing.T) {
	rl := NewRateLimiter(10, 5) // 10/s, burst 5

	// First 5 should be allowed (burst)
	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Errorf("call %d should be allowed (within burst)", i)
		}
	}

	// 6th should be denied (burst exhausted, no time elapsed)
	if rl.Allow() {
		t.Error("call 6 should be denied (burst exhausted)")
	}
}

func TestRateLimiter_Replenish(t *testing.T) {
	rl := NewRateLimiter(10, 1) // 10/s, burst 1

	// Use the initial token
	if !rl.Allow() {
		t.Error("first call should be allowed")
	}

	// Should be denied immediately
	if rl.Allow() {
		t.Error("second call should be denied")
	}

	// Wait 150ms — should replenish ~1.5 tokens, capped to burst=1
	time.Sleep(150 * time.Millisecond)

	if !rl.Allow() {
		t.Error("call after 150ms should be allowed (replenished)")
	}
}

func TestRateLimiter_BurstDefaultsToOne(t *testing.T) {
	rl := NewRateLimiter(100, 0) // burst 0 → defaults to 1

	if rl.burst != 1 {
		t.Errorf("expected burst=1, got %f", rl.burst)
	}

	if !rl.Allow() {
		t.Error("first call should be allowed")
	}
	if rl.Allow() {
		t.Error("second call should be denied (burst=1)")
	}
}

func TestRateLimiter_HighRate(t *testing.T) {
	rl := NewRateLimiter(1000, 100)

	allowed := 0
	for i := 0; i < 200; i++ {
		if rl.Allow() {
			allowed++
		}
	}

	// Should allow ~100 (the burst). Exact count drifts under -race because
	// each Allow takes long enough to accrue a sub-token of replenishment
	// at rate=1000/s. Allow a small tolerance instead of requiring exact 100.
	if allowed < 100 || allowed > 105 {
		t.Errorf("expected 100-105 allowed (burst + minor replenish drift), got %d", allowed)
	}
}

func TestRateLimiter_Concurrent(t *testing.T) {
	rl := NewRateLimiter(1000, 50)

	var wg sync.WaitGroup
	n := 200
	wg.Add(n)

	allowed := int64(0)
	var mu sync.Mutex

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if rl.Allow() {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Should allow approximately burst (50) ± a few from timing
	if allowed > 55 {
		t.Errorf("expected ~50 allowed, got %d", allowed)
	}
}
