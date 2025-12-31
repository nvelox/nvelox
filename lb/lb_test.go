package lb

import (
	"sync"
	"testing"
)

func TestRoundRobin(t *testing.T) {
	servers := []string{"s1", "s2", "s3"}
	lb := NewBalancer("roundrobin", servers)

	// Test sequence
	expected := []string{"s1", "s2", "s3", "s1", "s2"}
	for i, exp := range expected {
		got, err := lb.Next()
		if err != nil {
			t.Fatalf("Iteration %d: unexpected error: %v", i, err)
		}
		if got != exp {
			t.Errorf("Iteration %d: expected %s, got %s", i, exp, got)
		}
	}
}

func TestRoundRobin_MarkUnhealthy(t *testing.T) {
	servers := []string{"s1", "s2", "s3"}
	lb := NewBalancer("roundrobin", servers)

	// Mark s2 unhealthy
	lb.UpdateStatus("s2", false)

	// Should skip s2: s1 -> s3 -> s1
	expected := []string{"s1", "s3", "s1", "s3"}
	for i, exp := range expected {
		got, err := lb.Next()
		if err != nil {
			t.Fatalf("Iteration %d: unexpected error: %v", i, err)
		}
		if got != exp {
			t.Errorf("Iteration %d: expected %s, got %s", i, exp, got)
		}
	}
}

func TestRoundRobin_AllUnhealthy(t *testing.T) {
	servers := []string{"s1", "s2"}
	lb := NewBalancer("roundrobin", servers)

	lb.UpdateStatus("s1", false)
	lb.UpdateStatus("s2", false)

	_, err := lb.Next()
	if err == nil {
		t.Error("Expected error when all servers are unhealthy, got nil")
	}
}

func TestRoundRobin_Concurrent(t *testing.T) {
	servers := []string{"s1", "s2", "s3"}
	lb := NewBalancer("roundrobin", servers)

	var wg sync.WaitGroup
	count := 100
	wg.Add(count)

	// Just ensure no race conditions panic
	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()
			lb.Next()
		}()
	}
	wg.Wait()
}
