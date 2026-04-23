package core

import (
	"net"
	"sync"
	"testing"
	"time"

	"nvelox/core/logging"
)

func init() {
	logging.Init("debug", "", "")
}

func TestUDPPool_GetOrCreate(t *testing.T) {
	pool := NewUDPPool(5 * time.Second)
	defer pool.Stop()

	// First Get returns nil (miss)
	s := pool.Get("client1|backend1")
	if s != nil {
		t.Error("expected nil for missing session")
	}

	// Put and Get returns same session
	session := &UDPSession{
		Target:     "10.0.0.1:9000",
		LastActive: time.Now(),
	}
	pool.Put("client1|backend1", session)

	s = pool.Get("client1|backend1")
	if s == nil {
		t.Fatal("expected session after Put")
	}
	if s.Target != "10.0.0.1:9000" {
		t.Errorf("expected target 10.0.0.1:9000, got %s", s.Target)
	}
}

func TestUDPPool_DifferentKeys(t *testing.T) {
	pool := NewUDPPool(5 * time.Second)
	defer pool.Stop()

	s1 := &UDPSession{Target: "backend1", LastActive: time.Now()}
	s2 := &UDPSession{Target: "backend2", LastActive: time.Now()}

	pool.Put("client1|pool", s1)
	pool.Put("client2|pool", s2)

	got1 := pool.Get("client1|pool")
	got2 := pool.Get("client2|pool")

	if got1.Target != "backend1" {
		t.Errorf("expected backend1, got %s", got1.Target)
	}
	if got2.Target != "backend2" {
		t.Errorf("expected backend2, got %s", got2.Target)
	}
}

func TestUDPPool_Expiry(t *testing.T) {
	pool := NewUDPPool(100 * time.Millisecond)
	defer pool.Stop()

	session := &UDPSession{Target: "test", LastActive: time.Now()}
	pool.Put("key", session)

	// Should be available immediately
	if pool.Get("key") == nil {
		t.Error("expected session before expiry")
	}

	// Wait for expiry
	time.Sleep(200 * time.Millisecond)

	// Should be expired
	if pool.Get("key") != nil {
		t.Error("expected nil after expiry")
	}
}

func TestUDPPool_LastActiveUpdated(t *testing.T) {
	pool := NewUDPPool(200 * time.Millisecond)
	defer pool.Stop()

	session := &UDPSession{Target: "test", LastActive: time.Now()}
	pool.Put("key", session)

	// Access before expiry to refresh LastActive
	time.Sleep(100 * time.Millisecond)
	s := pool.Get("key")
	if s == nil {
		t.Fatal("expected session before expiry")
	}

	// Wait another 100ms — should still be alive because we refreshed
	time.Sleep(100 * time.Millisecond)
	if pool.Get("key") == nil {
		t.Error("expected session to be alive after refresh")
	}
}

func TestUDPPool_Remove(t *testing.T) {
	pool := NewUDPPool(5 * time.Second)
	defer pool.Stop()

	session := &UDPSession{Target: "test", LastActive: time.Now()}
	pool.Put("key", session)

	pool.Remove("key")

	if pool.Get("key") != nil {
		t.Error("expected nil after Remove")
	}
	if pool.Len() != 0 {
		t.Errorf("expected 0 sessions, got %d", pool.Len())
	}
}

func TestUDPPool_Concurrent(t *testing.T) {
	pool := NewUDPPool(5 * time.Second)
	defer pool.Stop()

	var wg sync.WaitGroup
	n := 100
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			key := "key"
			session := &UDPSession{Target: "test", LastActive: time.Now()}
			pool.Put(key, session)
			pool.Get(key)
		}(i)
	}
	wg.Wait()
}

func TestUDPPool_EvictExpired(t *testing.T) {
	pool := NewUDPPool(100 * time.Millisecond)
	defer pool.Stop()

	// Create a mock UDP connection for the session
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	ln.Close()

	session := &UDPSession{
		BackendConn: conn,
		Target:      "test",
		LastActive:  time.Now(),
	}
	pool.Put("key", session)

	// Wait for expiry
	time.Sleep(200 * time.Millisecond)

	// Manually trigger eviction
	pool.evictExpired()

	if pool.Len() != 0 {
		t.Errorf("expected 0 sessions after eviction, got %d", pool.Len())
	}
}
