package denylist

import (
	"net"
	"testing"
	"time"
)

func TestDynamic_AddBlockedRemove(t *testing.T) {
	d := New()

	if _, err := d.Add("1.2.3.4", 0); err != nil {
		t.Fatalf("add bare IP: %v", err)
	}
	if !d.Blocked(net.ParseIP("1.2.3.4")) {
		t.Error("1.2.3.4 should be blocked")
	}
	if d.Blocked(net.ParseIP("1.2.3.5")) {
		t.Error("1.2.3.5 should NOT be blocked")
	}

	// CIDR range.
	if _, err := d.Add("10.0.0.0/24", 0); err != nil {
		t.Fatalf("add cidr: %v", err)
	}
	if !d.Blocked(net.ParseIP("10.0.0.77")) {
		t.Error("10.0.0.77 should be blocked by 10.0.0.0/24")
	}
	if d.Blocked(net.ParseIP("10.0.1.1")) {
		t.Error("10.0.1.1 should NOT be blocked by 10.0.0.0/24")
	}

	// /32 normalizes to an exact single-host block.
	if _, err := d.Add("9.9.9.9/32", 0); err != nil {
		t.Fatalf("add /32: %v", err)
	}
	if !d.Blocked(net.ParseIP("9.9.9.9")) {
		t.Error("9.9.9.9/32 should block 9.9.9.9")
	}

	// IPv6.
	if _, err := d.Add("2001:db8::1", 0); err != nil {
		t.Fatalf("add ipv6: %v", err)
	}
	if !d.Blocked(net.ParseIP("2001:db8::1")) {
		t.Error("2001:db8::1 should be blocked")
	}

	// Remove.
	if !d.Remove("1.2.3.4") {
		t.Error("remove 1.2.3.4 should report existed=true")
	}
	if d.Blocked(net.ParseIP("1.2.3.4")) {
		t.Error("1.2.3.4 should be unblocked after remove")
	}
	if d.Remove("1.2.3.4") {
		t.Error("removing absent IP should report existed=false")
	}
	if !d.Remove("10.0.0.0/24") {
		t.Error("remove cidr should report existed=true")
	}
	if d.Blocked(net.ParseIP("10.0.0.77")) {
		t.Error("10.0.0.77 should be unblocked after cidr remove")
	}
}

func TestDynamic_TTLExpiry(t *testing.T) {
	d := New()
	if _, err := d.Add("5.5.5.5", 30*time.Millisecond); err != nil {
		t.Fatalf("add: %v", err)
	}
	if !d.Blocked(net.ParseIP("5.5.5.5")) {
		t.Fatal("5.5.5.5 should be blocked immediately after add")
	}
	time.Sleep(50 * time.Millisecond)
	if d.Blocked(net.ParseIP("5.5.5.5")) {
		t.Error("5.5.5.5 should be expired (lazy) after TTL")
	}
	// Still physically present until swept.
	if c := d.Count(); c != 1 {
		t.Errorf("expected 1 unswept entry, got %d", c)
	}
	if removed := d.Sweep(); removed != 1 {
		t.Errorf("sweep should remove 1 expired entry, removed %d", removed)
	}
	if c := d.Count(); c != 0 {
		t.Errorf("expected 0 entries after sweep, got %d", c)
	}
}

func TestDynamic_ExpiredEntryHiddenFromList(t *testing.T) {
	d := New()
	d.Add("1.1.1.1", 0)                   // permanent
	d.Add("2.2.2.2", 10*time.Millisecond) // will expire
	time.Sleep(25 * time.Millisecond)
	list := d.List()
	if len(list) != 1 || list[0].CIDR != "1.1.1.1" {
		t.Errorf("List should only show the permanent entry, got %+v", list)
	}
	if list[0].ExpiresAt != nil {
		t.Error("permanent entry must have nil ExpiresAt")
	}
}

func TestDynamic_InvalidInput(t *testing.T) {
	d := New()
	for _, bad := range []string{"", "   ", "not-an-ip", "999.999.999.999", "1.2.3.0/99"} {
		if _, err := d.Add(bad, 0); err == nil {
			t.Errorf("Add(%q) should error", bad)
		}
	}
	if d.Blocked(nil) {
		t.Error("Blocked(nil) must be false")
	}
}

func TestDynamic_AddReplacesTTL(t *testing.T) {
	d := New()
	d.Add("8.8.8.8", 10*time.Millisecond)
	// Re-add with a long TTL before the first expires → refreshes.
	d.Add("8.8.8.8", time.Hour)
	time.Sleep(25 * time.Millisecond)
	if !d.Blocked(net.ParseIP("8.8.8.8")) {
		t.Error("re-adding with a longer TTL should keep 8.8.8.8 blocked")
	}
	if c := d.Count(); c != 1 {
		t.Errorf("re-add should not duplicate; got %d entries", c)
	}
}
