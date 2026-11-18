package core

import (
	"os"
	"path/filepath"
	"strings"
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

// When max_fails has ejected every server of a backend, the backend goes on
// sending to them (lb: AllOut), and the error log says so once, not at each
// failure after.
func TestPassiveHealth_EveryServerEjected(t *testing.T) {
	errPath := filepath.Join(t.TempDir(), "error.log")
	if err := logging.Init("info", "", errPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logging.Init("debug", "", "") })
	balancer := lb.NewBalancer("roundrobin", []string{"s1:80", "s2:80"})
	tracker := NewPassiveHealthTracker("test-be", 1, balancer)
	tracker.RecordFailure("s1:80")
	if balancer.AllOut() {
		t.Fatal("one of two servers ejected: all out")
	}
	tracker.RecordFailure("s2:80")
	tracker.RecordFailure("s2:80")
	tracker.RecordFailure("s1:80")
	if !balancer.AllOut() {
		t.Fatal("both servers ejected: not all out")
	}
	if s, err := balancer.Next(); err != nil || s == "" {
		t.Fatalf("Next() with every server ejected: %q, %v", s, err)
	}
	b, err := os.ReadFile(errPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "Every server of backend test-be is ejected"); n != 1 {
		t.Errorf("the error log says %d times that every server is ejected, want once:\n%s", n, b)
	}
}
