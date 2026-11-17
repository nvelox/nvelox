package circuitbreaker

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBreaker_ClosedAllows(t *testing.T) {
	b := New(3, 1*time.Second, 1)

	for i := 0; i < 10; i++ {
		if !b.Allow() {
			t.Errorf("closed breaker should allow request %d", i)
		}
	}
	if b.State() != "closed" {
		t.Errorf("expected closed, got %s", b.State())
	}
}

func TestBreaker_OpensOnThreshold(t *testing.T) {
	b := New(3, 1*time.Second, 1)

	b.RecordFailure()
	b.RecordFailure()

	if b.State() != "closed" {
		t.Error("should still be closed after 2 failures")
	}

	b.RecordFailure() // 3rd failure = threshold

	if b.State() != "open" {
		t.Errorf("expected open after 3 failures, got %s", b.State())
	}
	if b.Allow() {
		t.Error("open breaker should not allow requests")
	}
}

func TestBreaker_HalfOpenAfterTimeout(t *testing.T) {
	b := New(2, 100*time.Millisecond, 2)

	b.RecordFailure()
	b.RecordFailure()

	if b.State() != "open" {
		t.Fatal("expected open")
	}

	time.Sleep(150 * time.Millisecond)

	if !b.Allow() {
		t.Error("should allow after timeout (half-open)")
	}
	if b.State() != "half-open" {
		t.Errorf("expected half-open, got %s", b.State())
	}
}

func TestBreaker_HalfOpenSuccess_Closes(t *testing.T) {
	b := New(2, 100*time.Millisecond, 1)

	b.RecordFailure()
	b.RecordFailure()

	time.Sleep(150 * time.Millisecond)
	b.Allow() // transition to half-open
	b.RecordSuccess()

	if b.State() != "closed" {
		t.Errorf("expected closed after half-open success, got %s", b.State())
	}
}

func TestBreaker_HalfOpenFailure_Opens(t *testing.T) {
	b := New(2, 100*time.Millisecond, 1)

	b.RecordFailure()
	b.RecordFailure()

	time.Sleep(150 * time.Millisecond)
	b.Allow() // transition to half-open
	b.RecordFailure()

	if b.State() != "open" {
		t.Errorf("expected open after half-open failure, got %s", b.State())
	}
}

func TestBreaker_HalfOpenMaxRequests(t *testing.T) {
	b := New(1, 100*time.Millisecond, 2)

	b.RecordFailure()
	time.Sleep(150 * time.Millisecond)

	// Half-open allows up to 2 requests
	if !b.Allow() {
		t.Error("half-open should allow 1st request")
	}
	if !b.Allow() {
		t.Error("half-open should allow 2nd request")
	}
	if b.Allow() {
		t.Error("half-open should deny 3rd request (max=2)")
	}
}

func TestBreaker_SuccessResetsFailures(t *testing.T) {
	b := New(3, 1*time.Second, 1)

	b.RecordFailure()
	b.RecordFailure()
	b.RecordSuccess() // resets

	b.RecordFailure()
	b.RecordFailure()

	if b.State() != "closed" {
		t.Error("should still be closed (reset after success)")
	}
}

// TestBreaker_HalfOpen_ConcurrentCapRespected exercises the previously-racy
// Open→HalfOpen transition with many concurrent Allow() callers. Exactly
// halfOpenMax probes must be admitted, never more.
func TestBreaker_HalfOpen_ConcurrentCapRespected(t *testing.T) {
	const halfMax = 5
	b := New(1, 10*time.Millisecond, halfMax)

	// Trip the breaker open.
	b.RecordFailure()
	if b.State() != "open" {
		t.Fatalf("precondition: expected open, got %s", b.State())
	}
	time.Sleep(15 * time.Millisecond) // past timeout

	// Fire many concurrent Allow() calls; count how many succeed.
	var wg sync.WaitGroup
	var admitted atomic.Int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.Allow() {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()

	// Exactly halfMax probes should have been admitted (the transition probe
	// + halfMax-1 concurrent HalfOpen admissions).
	got := admitted.Load()
	if got != halfMax {
		t.Errorf("concurrent Allow() in HalfOpen: admitted %d, want %d", got, halfMax)
	}
}

// TestBreaker_RecordFailure_ConcurrentThreshold verifies that concurrent
// RecordFailure calls cleanly cross the threshold without torn state.
// Run with -race to catch lastFail write-without-lock races.
func TestBreaker_RecordFailure_ConcurrentThreshold(t *testing.T) {
	b := New(5, 1*time.Minute, 1)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.RecordFailure()
		}()
	}
	wg.Wait()

	if b.State() != "open" {
		t.Errorf("after 100 concurrent failures (threshold=5): expected open, got %s", b.State())
	}
}
