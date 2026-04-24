package core

import (
	"sync"
	"testing"
)

func TestConnLimiter_Basic(t *testing.T) {
	cl := NewConnLimiter(3)

	if !cl.Acquire() {
		t.Error("first acquire should succeed")
	}
	if !cl.Acquire() {
		t.Error("second acquire should succeed")
	}
	if !cl.Acquire() {
		t.Error("third acquire should succeed")
	}
	if cl.Acquire() {
		t.Error("fourth acquire should fail (at capacity)")
	}

	if cl.Active() != 3 {
		t.Errorf("expected 3 active, got %d", cl.Active())
	}

	cl.Release()
	if cl.Active() != 2 {
		t.Errorf("expected 2 active after release, got %d", cl.Active())
	}

	if !cl.Acquire() {
		t.Error("acquire after release should succeed")
	}
}

func TestConnLimiter_Concurrent(t *testing.T) {
	cl := NewConnLimiter(5)

	// Fill the limiter
	for i := 0; i < 5; i++ {
		if !cl.Acquire() {
			t.Fatalf("acquire %d should succeed", i)
		}
	}

	// Next acquire should fail
	var wg sync.WaitGroup
	rejected := int64(0)
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !cl.Acquire() {
				mu.Lock()
				rejected++
				mu.Unlock()
			} else {
				cl.Release()
			}
		}()
	}
	wg.Wait()

	if rejected != 10 {
		t.Errorf("expected 10 rejected, got %d", rejected)
	}

	// Release all and verify
	for i := 0; i < 5; i++ {
		cl.Release()
	}
	if cl.Active() != 0 {
		t.Errorf("expected 0 active after release all, got %d", cl.Active())
	}
}

// TestConnLimiter_OverReleaseDetected verifies that Release without a
// matching Acquire no longer silently succeeds — it's tracked in
// OverReleaseCount so error-path bugs that inflate capacity get caught.
func TestConnLimiter_OverReleaseDetected(t *testing.T) {
	cl := NewConnLimiter(3)

	// No Acquires; over-release straight away.
	cl.Release()
	cl.Release()

	if n := cl.OverReleaseCount(); n != 2 {
		t.Errorf("expected 2 over-releases, got %d", n)
	}

	// Matched pair should NOT count as over-release.
	if !cl.Acquire() {
		t.Fatal("Acquire failed")
	}
	cl.Release()
	if n := cl.OverReleaseCount(); n != 2 {
		t.Errorf("matched Acquire/Release must not count; got %d", n)
	}

	// Extra Release again → incremented.
	cl.Release()
	if n := cl.OverReleaseCount(); n != 3 {
		t.Errorf("expected 3 over-releases, got %d", n)
	}
}
