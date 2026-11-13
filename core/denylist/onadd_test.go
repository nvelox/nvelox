package denylist

import (
	"net"
	"testing"
)

// TestOnAdd: a callback runs after each successful Add, when Blocked already
// reports the entry; not after a refused Add, and no more once removed.
func TestOnAdd(t *testing.T) {
	d := New()
	calls, sawBlocked := 0, false
	remove := d.OnAdd(func() {
		calls++
		sawBlocked = d.Blocked(net.ParseIP("192.0.2.7"))
	})
	if _, err := d.Add("192.0.2.7", 0); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !sawBlocked {
		t.Fatalf("after Add: calls=%d, entry visible to the callback=%v; want 1, true", calls, sawBlocked)
	}
	if _, err := d.Add("0.0.0.0/0", 0); err == nil {
		t.Fatal("Add of a too-wide range succeeded")
	}
	if _, err := d.Add("not-an-ip", 0); err == nil {
		t.Fatal("Add of garbage succeeded")
	}
	if calls != 1 {
		t.Fatalf("refused Adds ran the callback: calls=%d", calls)
	}
	remove()
	if _, err := d.Add("192.0.2.8", 0); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("removed callback still runs: calls=%d", calls)
	}
}
