package circuitbreaker

import (
	"testing"
	"time"
)

// TestBreaker_Release: Release gives a half-open probe slot back without
// deciding the breaker's state; in the other states it changes nothing.
func TestBreaker_Release(t *testing.T) {
	b := New(1, 50*time.Millisecond, 1)
	b.Release() // closed: no-op
	if b.State() != "closed" {
		t.Fatalf("state %s", b.State())
	}
	b.RecordFailure()
	b.Release() // open: no-op
	if b.State() != "open" || b.Allow() {
		t.Fatal("Release changed an open breaker")
	}
	time.Sleep(70 * time.Millisecond)
	if !b.Allow() {
		t.Fatal("probe refused")
	}
	b.Release()
	if b.State() != "half-open" {
		t.Fatalf("Release decided the state: %s", b.State())
	}
	if !b.Allow() {
		t.Fatal("released slot not reusable")
	}
	b.RecordSuccess()
	if b.State() != "closed" {
		t.Fatalf("state %s after a successful probe", b.State())
	}
}
