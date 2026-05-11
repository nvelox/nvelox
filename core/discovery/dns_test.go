package discovery

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

func TestDNSResolver_IPAddresses(t *testing.T) {
	// IP addresses should pass through unchanged
	var result []string
	var mu sync.Mutex

	resolver := NewDNSResolver("test", []string{"10.0.0.1:80", "10.0.0.2:80"}, 100*time.Millisecond, true, func(servers []string) {
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

	resolver := NewDNSResolver("test", []string{"localhost:80"}, 100*time.Millisecond, true, func(servers []string) {
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

	resolver := NewDNSResolver("test", []string{"10.0.0.1:80"}, 50*time.Millisecond, true, func(servers []string) {
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

func TestIsPrivateOrLoopback(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		// Loopback
		{"127.0.0.1", true},
		{"127.255.255.254", true},
		{"::1", true},
		// RFC1918
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		// CGNAT (net.IP.IsPrivate misses this one)
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"100.128.0.1", false}, // outside 100.64/10
		// Link-local
		{"169.254.1.1", true},
		{"fe80::1", true},
		// Unspecified
		{"0.0.0.0", true},
		{"::", true},
		// Public
		{"8.8.8.8", false},
		{"172.32.0.1", false}, // outside 172.16/12
		{"100.63.255.255", false}, // outside CGNAT
		{"2001:4860:4860::8888", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if got := isPrivateOrLoopback(ip); got != c.want {
			t.Errorf("isPrivateOrLoopback(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// TestDNSResolver_RejectPrivateIPs verifies that with allowPrivateIPs=false
// a configured private IP is dropped from the resolved set.
// DNS-rebinding scenarios (attacker-controlled hostname → 127.0.0.1)
// take the same code path.
func TestDNSResolver_RejectPrivateIPs(t *testing.T) {
	var result []string
	var mu sync.Mutex

	r := NewDNSResolver("public-backend",
		[]string{"8.8.8.8:53", "10.0.0.1:80", "127.0.0.1:80"},
		100*time.Millisecond, false,
		func(servers []string) {
			mu.Lock()
			result = servers
			mu.Unlock()
		})
	r.Start()
	defer r.Stop()

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(result) != 1 {
		t.Fatalf("expected 1 resolved (only 8.8.8.8), got %d: %v", len(result), result)
	}
	if result[0] != "8.8.8.8:53" {
		t.Errorf("expected 8.8.8.8:53 survived, got %q", result[0])
	}
}

func TestDNSResolver_AllowPrivateIPs(t *testing.T) {
	var result []string
	var mu sync.Mutex

	r := NewDNSResolver("internal",
		[]string{"10.0.0.1:80", "192.168.1.5:443"},
		100*time.Millisecond, true,
		func(servers []string) {
			mu.Lock()
			result = servers
			mu.Unlock()
		})
	r.Start()
	defer r.Stop()

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(result) != 2 {
		t.Errorf("allow_private_ips=true: expected 2 resolved, got %d: %v", len(result), result)
	}
}
