// Package denylist provides a process-wide, TTL-aware dynamic IP/CIDR
// denylist that is mutated at runtime (via the admin API) and consulted by
// the L7 request path on every request.
//
// It is deliberately separate from the static per-listener ip_denylist
// (config-driven, compiled at boot). This one is for DYNAMIC, EXPIRING blocks
// pushed by an external controller — e.g. ngris-sentinel's AI/heuristic abuse
// detection — without a config reload or process restart. Because the Default
// instance is process-global, blocks apply to every listener/site and survive
// SIGHUP config reloads (which rebuild HTTPServers but not this set).
//
// Single-host blocks (the common case) are stored in an exact-match map for
// O(1) lookup; CIDR ranges fall back to a linear scan (expected small).
package denylist

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Default is the process-wide dynamic denylist. The admin API mutates it and
// every HTTPServer consults it; a single instance means a block applies to all
// sites and survives config reloads.
var Default = New()

type entry struct {
	cidr      string     // canonical key (normalized bare IP or CIDR network)
	ipnet     *net.IPNet // set for range entries; nil for exact single-IP entries
	expiresAt time.Time  // zero = never expires
}

// Dynamic is a thread-safe, TTL-aware IP/CIDR denylist.
type Dynamic struct {
	mu     sync.RWMutex
	exact  map[string]entry // key: net.IP.String() for single-host blocks
	ranges map[string]entry // key: canonical CIDR (net.IPNet.String()) for multi-host blocks
}

// Entry is the public view of a denylist row (List / admin API).
type Entry struct {
	CIDR      string     `json:"cidr"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// New returns an empty Dynamic denylist.
func New() *Dynamic {
	return &Dynamic{
		exact:  make(map[string]entry),
		ranges: make(map[string]entry),
	}
}

func expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{} // never expires
	}
	return time.Now().Add(ttl)
}

func expPtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	tt := t
	return &tt
}

// Add inserts a single IP ("1.2.3.4", "2001:db8::1") or CIDR ("1.2.3.0/24")
// into the denylist with an optional TTL (ttl<=0 means never expire). Adding
// an existing key replaces it (refreshes the TTL). Returns the normalized
// entry, or an error if the input is not a valid IP/CIDR.
func (d *Dynamic) Add(ipOrCIDR string, ttl time.Duration) (Entry, error) {
	ipOrCIDR = strings.TrimSpace(ipOrCIDR)
	if ipOrCIDR == "" {
		return Entry{}, fmt.Errorf("empty ip/cidr")
	}
	exp := expiry(ttl)

	if ip, ipnet, err := net.ParseCIDR(ipOrCIDR); err == nil {
		ones, bits := ipnet.Mask.Size()
		d.mu.Lock()
		defer d.mu.Unlock()
		if ones == bits { // /32 or /128 → single host
			key := ip.String()
			d.exact[key] = entry{cidr: key, expiresAt: exp}
			return Entry{CIDR: key, ExpiresAt: expPtr(exp)}, nil
		}
		key := ipnet.String()
		d.ranges[key] = entry{cidr: key, ipnet: ipnet, expiresAt: exp}
		return Entry{CIDR: key, ExpiresAt: expPtr(exp)}, nil
	}

	if ip := net.ParseIP(ipOrCIDR); ip != nil {
		key := ip.String()
		d.mu.Lock()
		defer d.mu.Unlock()
		d.exact[key] = entry{cidr: key, expiresAt: exp}
		return Entry{CIDR: key, ExpiresAt: expPtr(exp)}, nil
	}

	return Entry{}, fmt.Errorf("invalid ip/cidr: %q", ipOrCIDR)
}

// Blocked reports whether ip is currently denied (present and not expired).
// Hot path: exact-match map lookup first, then a scan of CIDR ranges.
func (d *Dynamic) Blocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	now := time.Now()
	d.mu.RLock()
	defer d.mu.RUnlock()
	if e, ok := d.exact[ip.String()]; ok {
		if e.expiresAt.IsZero() || now.Before(e.expiresAt) {
			return true
		}
	}
	for _, e := range d.ranges {
		if e.ipnet != nil && e.ipnet.Contains(ip) {
			if e.expiresAt.IsZero() || now.Before(e.expiresAt) {
				return true
			}
		}
	}
	return false
}

// Remove deletes an IP/CIDR from the denylist. Returns true if it was present.
func (d *Dynamic) Remove(ipOrCIDR string) bool {
	ipOrCIDR = strings.TrimSpace(ipOrCIDR)
	d.mu.Lock()
	defer d.mu.Unlock()
	if ip, ipnet, err := net.ParseCIDR(ipOrCIDR); err == nil {
		ones, bits := ipnet.Mask.Size()
		if ones == bits {
			key := ip.String()
			if _, ok := d.exact[key]; ok {
				delete(d.exact, key)
				return true
			}
			return false
		}
		key := ipnet.String()
		if _, ok := d.ranges[key]; ok {
			delete(d.ranges, key)
			return true
		}
		return false
	}
	if ip := net.ParseIP(ipOrCIDR); ip != nil {
		key := ip.String()
		if _, ok := d.exact[key]; ok {
			delete(d.exact, key)
			return true
		}
	}
	return false
}

// List returns the currently-active (non-expired) entries, sorted by CIDR.
func (d *Dynamic) List() []Entry {
	now := time.Now()
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Entry, 0, len(d.exact)+len(d.ranges))
	add := func(e entry) {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			return // expired
		}
		out = append(out, Entry{CIDR: e.cidr, ExpiresAt: expPtr(e.expiresAt)})
	}
	for _, e := range d.exact {
		add(e)
	}
	for _, e := range d.ranges {
		add(e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDR < out[j].CIDR })
	return out
}

// Count returns the number of stored entries (including not-yet-swept expired).
func (d *Dynamic) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.exact) + len(d.ranges)
}

// Sweep removes expired entries and returns how many were removed.
func (d *Dynamic) Sweep() int {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	removed := 0
	for k, e := range d.exact {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(d.exact, k)
			removed++
		}
	}
	for k, e := range d.ranges {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(d.ranges, k)
			removed++
		}
	}
	return removed
}

// StartSweeper launches a background goroutine that evicts expired entries on
// the given interval (default 1m). Intended to be called once per process for
// the Default instance; runs for the process lifetime.
func (d *Dynamic) StartSweeper(interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			d.Sweep()
		}
	}()
}
