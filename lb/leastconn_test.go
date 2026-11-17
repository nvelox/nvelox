package lb

import (
	"sync"
	"testing"
)

func TestLeastConn_Next_SelectsLowest(t *testing.T) {
	servers := []string{"s1:80", "s2:80", "s3:80"}
	b := NewLeastConn(servers)

	// All at 0, should pick first
	got, err := b.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s1:80" {
		t.Errorf("expected s1:80, got %s", got)
	}
}

func TestLeastConn_OnConnect_OnDisconnect(t *testing.T) {
	servers := []string{"s1:80", "s2:80"}
	b := NewLeastConn(servers)

	// Simulate 3 connections to s1
	b.OnConnect("s1:80")
	b.OnConnect("s1:80")
	b.OnConnect("s1:80")

	// s2 has 0 conns, should be picked
	got, err := b.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s2:80" {
		t.Errorf("expected s2:80 (0 conns), got %s", got)
	}

	// Add 1 to s2, now s2=1, s1=3, still pick s2
	b.OnConnect("s2:80")
	got, _ = b.Next()
	if got != "s2:80" {
		t.Errorf("expected s2:80 (1 conn), got %s", got)
	}

	// Disconnect 2 from s1, now s1=1, s2=1, should pick s1 (first in list)
	b.OnDisconnect("s1:80")
	b.OnDisconnect("s1:80")
	got, _ = b.Next()
	if got != "s1:80" {
		t.Errorf("expected s1:80 (1 conn, first in list), got %s", got)
	}
}

func TestLeastConn_OnDisconnect_NoNegative(t *testing.T) {
	servers := []string{"s1:80"}
	b := NewLeastConn(servers)

	// Disconnect without a matching connect must be clamped at 0.
	// Previously it went to -1 and made this server look "most idle" →
	// all new traffic concentrated on it.
	b.OnDisconnect("s1:80")
	if b.conns["s1:80"] != 0 {
		t.Errorf("unpaired disconnect must stay at 0, got %d", b.conns["s1:80"])
	}

	// Normal connect/disconnect still works.
	b.OnConnect("s1:80")
	if b.conns["s1:80"] != 1 {
		t.Errorf("after connect: want 1, got %d", b.conns["s1:80"])
	}
	b.OnDisconnect("s1:80")
	if b.conns["s1:80"] != 0 {
		t.Errorf("after connect+disconnect: want 0, got %d", b.conns["s1:80"])
	}

	// Double-disconnect must not go negative.
	b.OnDisconnect("s1:80")
	if b.conns["s1:80"] != 0 {
		t.Errorf("double-disconnect must stay at 0, got %d", b.conns["s1:80"])
	}
}

func TestLeastConn_UpdateStatus(t *testing.T) {
	servers := []string{"s1:80", "s2:80", "s3:80"}
	b := NewLeastConn(servers)

	// Put conns on s1 and s3
	b.OnConnect("s1:80")
	b.OnConnect("s1:80")
	// s2 has 0 conns, s3 has 0 conns

	// Mark s2 unhealthy
	b.UpdateStatus("s2:80", false)

	// Should pick s3 (0 conns, healthy)
	got, _ := b.Next()
	if got != "s3:80" {
		t.Errorf("expected s3:80 (0 conns, healthy), got %s", got)
	}
}

func TestLeastConn_AllUnhealthy(t *testing.T) {
	servers := []string{"s1:80", "s2:80"}
	b := NewLeastConn(servers)

	b.UpdateStatus("s1:80", false)
	b.UpdateStatus("s2:80", false)

	_, err := b.Next()
	if err == nil {
		t.Error("expected error when all servers unhealthy")
	}
}

func TestLeastConn_Concurrent(t *testing.T) {
	servers := []string{"s1:80", "s2:80", "s3:80"}
	b := NewLeastConn(servers)

	var wg sync.WaitGroup
	n := 100
	wg.Add(n * 3)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			b.Next()
		}()
		go func() {
			defer wg.Done()
			b.OnConnect("s1:80")
		}()
		go func() {
			defer wg.Done()
			b.OnDisconnect("s1:80")
		}()
	}
	wg.Wait()
}

func TestLeastConn_EvenDistribution(t *testing.T) {
	servers := []string{"s1:80", "s2:80"}
	b := NewLeastConn(servers)

	counts := map[string]int{}
	for i := 0; i < 10; i++ {
		got, err := b.Next()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		b.OnConnect(got)
		counts[got]++
	}

	// With proper OnConnect tracking, distribution should be even: 5/5
	if counts["s1:80"] != 5 || counts["s2:80"] != 5 {
		t.Errorf("expected 5/5 distribution, got s1=%d s2=%d", counts["s1:80"], counts["s2:80"])
	}

	// Disconnect all
	for i := 0; i < 5; i++ {
		b.OnDisconnect("s1:80")
		b.OnDisconnect("s2:80")
	}

	// Verify counts are back to 0
	if b.conns["s1:80"] != 0 || b.conns["s2:80"] != 0 {
		t.Errorf("expected 0/0 after disconnect, got s1=%d s2=%d", b.conns["s1:80"], b.conns["s2:80"])
	}
}
