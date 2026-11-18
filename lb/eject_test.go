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

// TestEject_AllOutUsesThemAnyway: when passive health has ejected every
// server that is up, the balancer uses them as if they were healthy instead
// of none; once one is back, that one alone. A server an active check or the
// admin API marked down stays out even then, and with every server marked
// down there is none, as before.
func TestEject_AllOutUsesThemAnyway(t *testing.T) {
	eachBalancer(t, func(t *testing.T, b Balancer) {
		b.Eject("s1", time.Hour)
		if b.AllOut() {
			t.Fatal("one of two servers ejected: all out")
		}
		b.Eject("s2", 80*time.Millisecond)
		if !b.AllOut() {
			t.Fatal("both servers ejected: not all out")
		}
		if _, err := b.Next(); err != nil {
			t.Fatalf("Next() with every server ejected: %v", err)
		}
		// Both are in use (leastconn takes the first of equals, so each is
		// asked for by leaving out the other).
		for _, s := range []string{"s1", "s2"} {
			other := map[string]string{"s1": "s2", "s2": "s1"}[s]
			if got, err := b.NextExcluding([]string{other}); err != nil || got != s {
				t.Fatalf("NextExcluding(%s) with every server ejected: %q, %v; want %s", other, got, err, s)
			}
		}
		if !b.IsHealthy("s1") || !b.IsHealthy("s2") {
			t.Fatal("with every server ejected, IsHealthy does not take them as healthy")
		}
		time.Sleep(150 * time.Millisecond) // s2's ejection ends
		if b.AllOut() {
			t.Fatal("s2 is back: still all out")
		}
		for i := 0; i < 16; i++ {
			if s, err := b.Next(); err != nil || s != "s2" {
				t.Fatalf("s2 back, s1 ejected: Next() = %q, %v", s, err)
			}
		}
		if b.IsHealthy("s1") {
			t.Fatal("s2 back, s1 ejected: s1 healthy")
		}
		// s1 marked down, s2 ejected: s2 alone, as if healthy.
		b.UpdateStatus("s1", false)
		b.Eject("s2", time.Hour)
		for i := 0; i < 16; i++ {
			if s, err := b.Next(); err != nil || s != "s2" {
				t.Fatalf("s1 marked down, s2 ejected: Next() = %q, %v", s, err)
			}
		}
		if b.IsHealthy("s1") {
			t.Fatal("a server marked down is healthy while the other is ejected")
		}
		b.UpdateStatus("s2", false)
		if s, err := b.Next(); err == nil {
			t.Fatalf("every server marked down: Next() = %q", s)
		}
		if b.AllOut() {
			t.Fatal("every server marked down: all out")
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
