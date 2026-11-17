package core

import (
	"testing"

	"nvelox/core/logging"
	"nvelox/lb"
)

func TestPassiveHealth_MarkUnhealthy(t *testing.T) {
	logging.Init("debug", "", "")
	balancer := lb.NewBalancer("roundrobin", []string{"s1:80", "s2:80"})
	tracker := NewPassiveHealthTracker("test-be", 3, balancer)

	// Two failures — still healthy
	tracker.RecordFailure("s1:80")
	tracker.RecordFailure("s1:80")

	if !balancer.IsHealthy("s1:80") {
		t.Error("s1 should still be healthy after 2 failures")
	}

	// Third failure — marked unhealthy
	tracker.RecordFailure("s1:80")

	if balancer.IsHealthy("s1:80") {
		t.Error("s1 should be unhealthy after 3 failures")
	}
}

func TestPassiveHealth_ResetOnSuccess(t *testing.T) {
	logging.Init("debug", "", "")
	balancer := lb.NewBalancer("roundrobin", []string{"s1:80", "s2:80"})
	tracker := NewPassiveHealthTracker("test-be", 3, balancer)

	tracker.RecordFailure("s1:80")
	tracker.RecordFailure("s1:80")
	tracker.RecordSuccess("s1:80")

	if tracker.GetFailures("s1:80") != 0 {
		t.Errorf("expected 0 failures after success, got %d", tracker.GetFailures("s1:80"))
	}

	// Two more failures — should not trigger (reset happened)
	tracker.RecordFailure("s1:80")
	tracker.RecordFailure("s1:80")

	if !balancer.IsHealthy("s1:80") {
		t.Error("s1 should still be healthy after reset + 2 failures")
	}
}
