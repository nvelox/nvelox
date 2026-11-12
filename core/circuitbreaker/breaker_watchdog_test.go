package circuitbreaker

import (
	"testing"
	"time"
)

// TestBreaker_HalfOpenWatchdog (H4): a probe that never reports back used
// to hold its half-open slot forever, refusing every request after it. Once
// no probe was handed out for a whole timeout, the slots are reclaimed.
func TestBreaker_HalfOpenWatchdog(t *testing.T) {
	b := New(1, 50*time.Millisecond, 1)
	b.RecordFailure()
	time.Sleep(70 * time.Millisecond)
	if !b.Allow() {
		t.Fatal("first probe refused")
	}
	if b.Allow() {
		t.Fatal("second concurrent probe allowed (half_open_max 1)")
	}
	time.Sleep(70 * time.Millisecond) // the probe never reported back
	if !b.Allow() {
		t.Fatal("breaker wedged in half-open by a probe that never reported back")
	}
}
