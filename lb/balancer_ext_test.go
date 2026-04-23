package lb

import (
	"testing"
)

func TestNextExcluding_RoundRobin(t *testing.T) {
	b := NewRoundRobin([]string{"s1", "s2", "s3"})

	got, err := b.NextExcluding([]string{"s1", "s2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s3" {
		t.Errorf("expected s3, got %s", got)
	}
}

func TestNextExcluding_AllExcluded(t *testing.T) {
	b := NewRoundRobin([]string{"s1", "s2"})

	_, err := b.NextExcluding([]string{"s1", "s2"})
	if err == nil {
		t.Error("expected error when all servers excluded")
	}
}

func TestMarkDraining(t *testing.T) {
	b := NewRoundRobin([]string{"s1", "s2", "s3"})

	b.MarkDraining("s2")

	if b.IsHealthy("s2") {
		t.Error("s2 should not be healthy after draining")
	}
	if !b.IsHealthy("s1") {
		t.Error("s1 should still be healthy")
	}

	// s2 should never be selected
	for i := 0; i < 10; i++ {
		got, _ := b.Next()
		if got == "s2" {
			t.Error("draining server s2 should not be selected")
		}
	}
}

func TestIsHealthy(t *testing.T) {
	b := NewLeastConn([]string{"s1:80", "s2:80"})

	if !b.IsHealthy("s1:80") {
		t.Error("s1 should be healthy initially")
	}

	b.UpdateStatus("s1:80", false)

	if b.IsHealthy("s1:80") {
		t.Error("s1 should be unhealthy after UpdateStatus")
	}
}

func TestNextExcluding_LeastConn(t *testing.T) {
	b := NewLeastConn([]string{"s1:80", "s2:80", "s3:80"})
	b.OnConnect("s3:80") // s3 has 1 conn

	got, err := b.NextExcluding([]string{"s1:80"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// s2 has 0 conns and is not excluded, should be picked
	if got != "s2:80" {
		t.Errorf("expected s2:80, got %s", got)
	}
}

func TestNextExcluding_Random(t *testing.T) {
	b := NewRandom([]string{"s1", "s2", "s3"})

	// Exclude s1 and s2, only s3 should be returned
	for i := 0; i < 10; i++ {
		got, err := b.NextExcluding([]string{"s1", "s2"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "s3" {
			t.Errorf("expected s3, got %s", got)
		}
	}
}
