package lb

import (
	"testing"
	"time"
)

func eachBalancer(t *testing.T, f func(t *testing.T, b Balancer)) {
	for _, algo := range []string{"roundrobin", "leastconn", "random"} {
		t.Run(algo, func(t *testing.T) { f(t, NewBalancer(algo, []string{"s1", "s2"})) })
	}
}

// TestEject_Expires (H4): a passive ejection takes the server out of
// rotation for its duration only (it used to be marked down for good).
func TestEject_Expires(t *testing.T) {
	eachBalancer(t, func(t *testing.T, b Balancer) {
		b.Eject("s1", 60*time.Millisecond)
		if b.IsHealthy("s1") {
			t.Fatal("ejected server still healthy")
		}
		for i := 0; i < 10; i++ {
			if s, _ := b.Next(); s != "s2" {
				t.Fatalf("Next() = %q during the ejection", s)
			}
		}
		time.Sleep(100 * time.Millisecond)
		if !b.IsHealthy("s1") {
			t.Fatal("server not back after its ejection expired")
		}
		seen := map[string]bool{}
		for i := 0; i < 50; i++ {
			s, _ := b.NextExcluding([]string{"s2"})
			seen[s] = true
		}
		if !seen["s1"] {
			t.Fatal("expired ejection: s1 never selected")
		}
	})
}

// TestEject_DoesNotOverrideStatus: an expired ejection does not bring back a
// server an active health check (or the admin API) marked down, and an
// explicit "up" ends an ejection early.
func TestEject_DoesNotOverrideStatus(t *testing.T) {
	eachBalancer(t, func(t *testing.T, b Balancer) {
		b.UpdateStatus("s1", false)
		b.Eject("s1", 30*time.Millisecond)
		time.Sleep(60 * time.Millisecond)
		if b.IsHealthy("s1") {
			t.Fatal("ejection expiry re-enabled a server marked down")
		}
		b.UpdateStatus("s1", true)
		if !b.IsHealthy("s1") {
			t.Fatal("UpdateStatus(true) did not bring the server back")
		}
		b.Eject("s2", time.Hour)
		b.UpdateStatus("s2", true)
		if !b.IsHealthy("s2") {
			t.Fatal("UpdateStatus(true) did not end the ejection")
		}
	})
}

func TestServers_ReturnsCopy(t *testing.T) {
	eachBalancer(t, func(t *testing.T, b Balancer) {
		s := b.Servers()
		if len(s) != 2 || s[0] != "s1" || s[1] != "s2" {
			t.Fatalf("Servers() = %q", s)
		}
		s[0] = "changed"
		if b.Servers()[0] != "s1" {
			t.Fatal("Servers() exposed the internal slice")
		}
	})
}
