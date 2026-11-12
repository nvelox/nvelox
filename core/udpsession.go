package core

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"nvelox/core/logging"
	"nvelox/core/metrics"
)

// UDP session limits. A UDP session is one client source ip:port on one
// listener: an nbio conn, a connected backend socket (one fd and one
// ephemeral port) and the goroutine relaying the backend's replies. Without a
// bound every datagram from a new source — trivially spoofed — created one
// that lived 60 s (2000 sources: +1928 goroutines, +125 MiB).
//
// Cost per idle session, measured (2000 one-datagram sources, Go heap +
// goroutine stacks): ~7 KiB — the 64 KiB reply buffer is borrowed only while
// a reply is relayed (udpBackendReader); it used to be held for the
// session's whole life (~68 KiB per session).
const (
	// maxUDPSessions caps concurrent UDP sessions per process. Worst case
	// (table full of junk) ≈ 16384 × 7 KiB ≈ 110 MiB plus the kernel's socket
	// memory, which a 2-4 GB gateway VM absorbs (it would have been ~1.1 GiB
	// with the per-session buffer), and 16384 backend sockets stay well
	// inside the 28,232-port ephemeral range every backend socket draws from.
	maxUDPSessions = 16384
	// maxUDPSessionsPerIP caps sessions per client IP — behind a trusted
	// accept_proxy_from relay the client its PROXY header names, never the
	// relay — so one source cannot fill the table. Generous for CGNAT.
	maxUDPSessionsPerIP = 512
	// udpNoReplyTimeout ends a session its backend has not answered yet: a
	// one-datagram (or spoofed) source frees its slot after 10 s instead of
	// 60 s. A session the backend answered keeps udpIdleTimeout.
	udpNoReplyTimeout = 10 * time.Second
	// udpIdleTimeout ends a session after this long without a backend reply
	// (the nbio client-side read timeout is the same).
	udpIdleTimeout = 60 * time.Second
	// udpMaxDatagram is the reply buffer size (largest UDP payload).
	udpMaxDatagram = 65535
)

// UDP drop reasons (nvelox_udp_dropped_total{reason=...}).
const (
	udpDropSessionLimit  = "session_limit"   // maxUDPSessions reached: new session refused
	udpDropSourceLimit   = "source_limit"    // maxUDPSessionsPerIP reached: new session refused
	udpDropNoProxyHeader = "no_proxy_header" // trusted relay datagram without a valid PROXY v2 header
	udpDropClientChanged = "client_changed"  // trusted relay datagram naming another client than the session's
)

// udpSessionLimiter counts live UDP sessions, globally and per client IP.
type udpSessionLimiter struct {
	mu       sync.Mutex
	total    int
	perIP    map[netip.Addr]int
	maxTotal int
	maxPerIP int
}

func newUDPSessionLimiter(maxTotal, maxPerIP int) *udpSessionLimiter {
	return &udpSessionLimiter{perIP: make(map[netip.Addr]int), maxTotal: maxTotal, maxPerIP: maxPerIP}
}

// acquire reserves a session slot, charged to ip when ip is valid (a zero ip
// = client not known yet: a trusted relay's, charged later by chargeIP). It
// returns "" on success, else the drop reason.
func (s *udpSessionLimiter) acquire(ip netip.Addr) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= s.maxTotal {
		return udpDropSessionLimit
	}
	if ip.IsValid() {
		if s.perIP[ip] >= s.maxPerIP {
			return udpDropSourceLimit
		}
		s.perIP[ip]++
	}
	s.total++
	return ""
}

// chargeIP charges a session that already holds a slot to its client ip, once
// known. False when ip is at its limit (the caller ends the session).
func (s *udpSessionLimiter) chargeIP(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perIP[ip] >= s.maxPerIP {
		return false
	}
	s.perIP[ip]++
	return true
}

// release frees a slot taken by acquire (and chargeIP for ip, when valid).
func (s *udpSessionLimiter) release(ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	if ip.IsValid() {
		if n := s.perIP[ip] - 1; n > 0 {
			s.perIP[ip] = n
		} else {
			delete(s.perIP, ip)
		}
	}
}

// count returns the live sessions, in total and for ip.
func (s *udpSessionLimiter) count(ip netip.Addr) (total, forIP int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total, s.perIP[ip]
}

// addrKey is ip as a map key (IPv4-mapped IPv6 folded to IPv4); zero for nil.
func addrKey(ip net.IP) netip.Addr {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}

// udpDropLogEvery spaces the WARN lines for one drop reason; the metric
// counts every drop.
const udpDropLogEvery = 10 * time.Second

// udpDrops counts dropped UDP sessions / datagrams per reason in the metrics
// registry and logs at most one WARN per reason per udpDropLogEvery, with the
// number of drops since the previous line — a flood of spoofed sources must
// not become a flood of log lines.
type udpDrops struct {
	reasons map[string]*udpDropReason
}

type udpDropReason struct {
	counter *metrics.Counter
	pending atomic.Int64
	lastLog atomic.Int64 // unix nanos of the last WARN line
}

func newUDPDrops(reg *metrics.Registry) *udpDrops {
	if reg == nil {
		reg = metrics.Default
	}
	d := &udpDrops{reasons: make(map[string]*udpDropReason)}
	for _, r := range []string{udpDropSessionLimit, udpDropSourceLimit, udpDropNoProxyHeader, udpDropClientChanged} {
		d.reasons[r] = &udpDropReason{counter: reg.GetCounter("nvelox_udp_dropped_total", map[string]string{"reason": r})}
	}
	return d
}

// note records one drop on listener from who (the client, or the relay for a
// datagram drop); the log line names the latest one.
func (d *udpDrops) note(reason, listener string, who net.Addr) {
	r := d.reasons[reason]
	if r == nil {
		return
	}
	r.counter.Inc()
	r.pending.Add(1)
	now := time.Now().UnixNano()
	last := r.lastLog.Load()
	if last != 0 && now-last < int64(udpDropLogEvery) {
		return
	}
	if !r.lastLog.CompareAndSwap(last, now) {
		return
	}
	logging.Warn("[UDP] %s: dropped %d since the last report (%s) — latest on listener %s from %s",
		udpDropText[reason], r.pending.Swap(0), reason, listener, ipStrOf(who))
}

var udpDropText = map[string]string{
	udpDropSessionLimit:  fmt.Sprintf("UDP session limit (%d) reached, new sessions refused", maxUDPSessions),
	udpDropSourceLimit:   fmt.Sprintf("UDP per-client session limit (%d) reached, new sessions refused", maxUDPSessionsPerIP),
	udpDropNoProxyHeader: "datagrams from a trusted relay without a valid PROXY v2 header",
	udpDropClientChanged: "datagrams from a trusted relay naming another client than the session's",
}
