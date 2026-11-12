package core

import (
	"net"
	"testing"
	"time"

	"nvelox/core/denylist"
)

// TestL4Denied verifies the L4 (TCP/UDP) admission gate's dynamic-denylist
// part: a client whose IP is on the dynamic denylist is refused with the
// "denylisted" status, a clean IP passes. (Which address is checked — the
// peer, or the client a trusted relay's PROXY header names — is decided by
// the callers; see l4gates_test.go.) This mirrors the HTTP plane's
// Blocked() gate onto TCP/UDP.
func TestL4Denied(t *testing.T) {
	h := &ProxyEventHandler{}
	l := &ListenerConfig{Name: "l4", Protocol: "tcp"}
	if err := l.prepare(); err != nil {
		t.Fatal(err)
	}

	const blockedIP = "203.0.113.7"
	blocked := net.ParseIP(blockedIP)
	clean := net.ParseIP("203.0.113.9")

	// Clean denylist: nothing is denied.
	if ok, _ := h.l4Admit(l, blocked); !ok {
		t.Fatalf("with empty denylist, %s must not be denied", blockedIP)
	}

	if _, err := denylist.Default.Add(blockedIP, time.Hour); err != nil {
		t.Fatalf("seed denylist: %v", err)
	}
	defer denylist.Default.Remove(blockedIP)

	if ok, status := h.l4Admit(l, blocked); ok || status != l4StatusDenylisted {
		t.Errorf("blocked client %s: admitted=%v status=%q, want refused as %q", blockedIP, ok, status, l4StatusDenylisted)
	}
	// The 4-byte form of the same address (net.ParseIP returns 16 bytes).
	if ok, _ := h.l4Admit(l, blocked.To4()); ok {
		t.Errorf("blocked client in 4-byte form must be denied")
	}
	if ok, _ := h.l4Admit(l, clean); !ok {
		t.Errorf("unblocked client must pass")
	}
	// An unparseable address with no static control configured passes (the
	// dynamic denylist cannot match it either).
	if ok, _ := h.l4Admit(l, nil); !ok {
		t.Errorf("nil ip without static controls must not be denied")
	}
}

// TestL4DeniedExpiry confirms an expired block no longer denies (TTL-aware).
func TestL4DeniedExpiry(t *testing.T) {
	h := &ProxyEventHandler{}
	l := &ListenerConfig{Name: "l4", Protocol: "udp"}
	if err := l.prepare(); err != nil {
		t.Fatal(err)
	}
	const ip = "203.0.113.11"

	if _, err := denylist.Default.Add(ip, 20*time.Millisecond); err != nil {
		t.Fatalf("seed: %v", err)
	}
	defer denylist.Default.Remove(ip)

	if ok, _ := h.l4Admit(l, net.ParseIP(ip)); ok {
		t.Fatalf("freshly-blocked %s must be denied", ip)
	}
	time.Sleep(40 * time.Millisecond)
	if ok, _ := h.l4Admit(l, net.ParseIP(ip)); !ok {
		t.Errorf("expired block for %s must no longer deny", ip)
	}
}
