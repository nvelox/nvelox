package core

import (
	"testing"
	"time"

	"nvelox/core/logging"
	"nvelox/lb"
)

// TestPassiveHealth_EjectionExpires (H4): max_fails consecutive failures
// eject the server for the cool-down only; it used to stay down forever
// (an active check never re-enables it: it reports only its own flips).
func TestPassiveHealth_EjectionExpires(t *testing.T) {
	logging.Init("debug", "", "")
	balancer := lb.NewBalancer("roundrobin", []string{"s1:80", "s2:80"})
	tracker := NewPassiveHealthTracker("test-be", 2, balancer)
	tracker.ejectFor = 60 * time.Millisecond

	tracker.RecordFailure("s1:80")
	tracker.RecordFailure("s1:80")
	if balancer.IsHealthy("s1:80") {
		t.Fatal("s1 should be ejected after max_fails")
	}
	time.Sleep(100 * time.Millisecond)
	if !balancer.IsHealthy("s1:80") {
		t.Fatal("s1 still out of rotation after the cool-down")
	}
	// Not reset by the expiry: one more failure ejects it again.
	tracker.RecordFailure("s1:80")
	if balancer.IsHealthy("s1:80") {
		t.Fatal("a failure right after the cool-down should eject again")
	}
}

func TestPassiveHealth_DefaultCooldown(t *testing.T) {
	tracker := NewPassiveHealthTracker("be", 1, lb.NewBalancer("roundrobin", []string{"s1:80"}))
	if tracker.ejectFor != PassiveEjectDuration || PassiveEjectDuration <= 0 {
		t.Fatalf("ejectFor = %v, PassiveEjectDuration = %v", tracker.ejectFor, PassiveEjectDuration)
	}
}
