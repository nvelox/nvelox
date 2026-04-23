package discovery

import (
	"sync"
	"testing"
	"time"

	"nvelox/core/logging"
)

func init() {
	logging.Init("debug", "", "")
}

func TestDNSResolver_IPAddresses(t *testing.T) {
	// IP addresses should pass through unchanged
	var result []string
	var mu sync.Mutex

	resolver := NewDNSResolver("test", []string{"10.0.0.1:80", "10.0.0.2:80"}, 100*time.Millisecond, func(servers []string) {
		mu.Lock()
		result = servers
		mu.Unlock()
	})
	resolver.Start()
	defer resolver.Stop()

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(result) != 2 {
		t.Errorf("expected 2 servers, got %d", len(result))
	}
}

func TestDNSResolver_Localhost(t *testing.T) {
	// "localhost" should resolve to 127.0.0.1 or ::1
	var result []string
	var mu sync.Mutex

	resolver := NewDNSResolver("test", []string{"localhost:80"}, 100*time.Millisecond, func(servers []string) {
		mu.Lock()
		result = servers
		mu.Unlock()
	})
	resolver.Start()
	defer resolver.Stop()

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(result) == 0 {
		t.Error("expected at least one resolved address for localhost")
	}
}

func TestDNSResolver_NoChange_NoCallback(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	resolver := NewDNSResolver("test", []string{"10.0.0.1:80"}, 50*time.Millisecond, func(servers []string) {
		mu.Lock()
		callCount++
		mu.Unlock()
	})
	resolver.Start()
	defer resolver.Stop()

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	// Should only be called once (initial resolve), not on every tick since IPs don't change
	if callCount != 1 {
		t.Errorf("expected 1 callback (no change), got %d", callCount)
	}
}
