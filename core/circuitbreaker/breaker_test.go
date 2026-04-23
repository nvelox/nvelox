package circuitbreaker

import (
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
