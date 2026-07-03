package core

import (
	"net"
	"testing"
	"time"

	"nvelox/core/denylist"
)

// TestL4Denied verifies the L4 (TCP/UDP) accept-path denylist gate: a direct
// client whose IP is on the dynamic denylist is dropped, a clean IP passes, and
// a trusted relay's peer IP is never dropped (its real client is enforced in
// OnData). This mirrors the HTTP plane's Blocked() gate onto TCP/UDP.
func TestL4Denied(t *testing.T) {
	h := &ProxyEventHandler{}

	const blockedIP = "203.0.113.7"
	tcpBlocked := &net.TCPAddr{IP: net.ParseIP(blockedIP), Port: 40000}
	udpBlocked := &net.UDPAddr{IP: net.ParseIP(blockedIP), Port: 53}
	tcpClean := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}

	// Clean denylist: nothing is denied.
	if h.l4Denied(tcpBlocked, false) {
		t.Fatalf("with empty denylist, %s must not be denied", blockedIP)
	}

	if _, err := denylist.Default.Add(blockedIP, time.Hour); err != nil {
		t.Fatalf("seed denylist: %v", err)
	}
	defer denylist.Default.Remove(blockedIP)

	if !h.l4Denied(tcpBlocked, false) {
		t.Errorf("blocked TCP client %s must be denied", blockedIP)
	}
	if !h.l4Denied(udpBlocked, false) {
		t.Errorf("blocked UDP client %s must be denied", blockedIP)
	}
	if h.l4Denied(tcpClean, false) {
		t.Errorf("unblocked client must pass")
	}
	// A trusted relay's peer is infra, not the client — never deny on the peer IP
	// even if (pathologically) it appears on the list; the real client is gated
	// in OnData after PROXY-v2 resolution.
	if h.l4Denied(tcpBlocked, true) {
		t.Errorf("trusted-relay peer must not be denied on the peer IP")
	}
	// A nil/unresolved address must not panic and must not deny.
	if h.l4Denied(nil, false) {
		t.Errorf("nil addr must not be denied")
	}
}

// TestL4DeniedExpiry confirms an expired block no longer denies (TTL-aware).
func TestL4DeniedExpiry(t *testing.T) {
	h := &ProxyEventHandler{}
	const ip = "203.0.113.11"
	addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: 1}

	if _, err := denylist.Default.Add(ip, 20*time.Millisecond); err != nil {
		t.Fatalf("seed: %v", err)
	}
	defer denylist.Default.Remove(ip)

	if !h.l4Denied(addr, false) {
		t.Fatalf("freshly-blocked %s must be denied", ip)
	}
	time.Sleep(40 * time.Millisecond)
	if h.l4Denied(addr, false) {
		t.Errorf("expired block for %s must no longer deny", ip)
	}
}
