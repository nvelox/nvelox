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
// listener: its entry in the listener socket's table, a connected backend socket (one fd and one
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
	// (udpClientReadTimeout, for a silent client, is the same).
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
	udpDropBadSignature  = "bad_signature"   // trusted relay datagram whose header signature is missing or wrong (accept_proxy_key_file)
	udpDropReplayed      = "replayed"        // trusted relay datagram whose counter its relay socket sent before, or older than its window (accept_proxy_replay_window)
	// The backend wants the PROXY v2 header with every datagram
	// (send_proxy_v2), and a datagram never goes to it without one: where
	// the backend expects the header, a client could put one of its own
	// first and so name any source.
	udpDropNoBackendHeader = "no_backend_header"  // the header could not be built for the session's client: session refused
	udpDropHeaderChanged   = "send_proxy_changed" // a reload changed send_proxy_v2 of the session's backend: session ended

	// New sessions refused before they hold anything. A refused source
	// sends on, and every datagram of it is a new session to refuse: each
	// is counted here, and the source's line in the access log is written
	// once in udpRefusalMemory (udpRefusals).
	udpDropRefused      = "refused"       // the listener's ip_denylist, ip_allowlist or acl
	udpDropDenylisted   = "denylisted"    // the denylist (admin API)
	udpDropRateLimit    = "rate_limit"    // the listener's rate_limit
	udpDropBackendLimit = "backend_limit" // the backend's max_connections
)

// udpSessionLimiter counts live UDP sessions, globally and per client IP,
// and apart from them the trusted relays' sessions still waiting for a
// PROXY header: those hold no session slot (H5), so they get a cap of
// their own, as large as the session cap.
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

// acquire reserves a session slot, charged to ip when ip is valid. A trusted
// relay's session acquires once a valid PROXY header names its client. It
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

// release frees a slot taken by acquire.
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
	// Every reason that has a log text: one that is missing here would be
	// dropped by note without a count or a line.
	for r := range udpDropText {
		d.reasons[r] = &udpDropReason{counter: reg.GetCounter("nvelox_udp_dropped_total", map[string]string{"reason": r})}
	}
	return d
}

// note records one drop on listener from who (the client, or the relay for a
// datagram drop); the log line names the latest one.
func (d *udpDrops) note(reason, listener string, who net.Addr) {
	if n, due := d.count(reason); due {
		logging.Warn("[UDP] %s: dropped %d since the last report (%s) — latest on listener %s from %s",
			udpDropText[reason], n, reason, listener, ipStrOf(who))
	}
}

// noteIP is note for an address already taken apart (nothing is formatted
// unless a line is due).
func (d *udpDrops) noteIP(reason, listener string, who netip.Addr) {
	if n, due := d.count(reason); due {
		logging.Warn("[UDP] %s: dropped %d since the last report (%s) — latest on listener %s from %s",
			udpDropText[reason], n, reason, listener, who.Unmap())
	}
}

// count counts one drop for reason. due reports that a log line is to be
// written now, for the n drops since the previous one.
func (d *udpDrops) count(reason string) (n int64, due bool) {
	r := d.reasons[reason]
	if r == nil {
		return 0, false
	}
	r.counter.Inc()
	r.pending.Add(1)
	now := time.Now().UnixNano()
	last := r.lastLog.Load()
	if last != 0 && now-last < int64(udpDropLogEvery) {
		return 0, false
	}
	if !r.lastLog.CompareAndSwap(last, now) {
		return 0, false
	}
	return r.pending.Swap(0), true
}

var udpDropText = map[string]string{
	udpDropSessionLimit:  fmt.Sprintf("UDP session limit (%d) reached, new sessions refused", maxUDPSessions),
	udpDropSourceLimit:   fmt.Sprintf("UDP per-client session limit (%d) reached, new sessions refused", maxUDPSessionsPerIP),
	udpDropNoProxyHeader: "datagrams from a trusted relay without a valid PROXY v2 header",
	udpDropClientChanged: "datagrams from a trusted relay naming another client than the session's",
	udpDropBadSignature:  "datagrams from a trusted relay without a valid header signature",
	udpDropReplayed:      "datagrams from a trusted relay whose header's counter its socket sent before, or is older than its window (a copy)",

	udpDropNoBackendHeader: "sessions refused: their backend wants the PROXY v2 header (send_proxy_v2), which cannot be built for the client",
	udpDropHeaderChanged:   "sessions ended: a reload changed send_proxy_v2 of their backend",

	udpDropRefused:      "new sessions refused by the listener's access policy (ip_denylist, ip_allowlist, acl)",
	udpDropDenylisted:   "new sessions refused: the source is on the denylist",
	udpDropRateLimit:    "new sessions refused: the listener's rate limit",
	udpDropBackendLimit: "new sessions refused: the backend is at max_connections",
}

// udpDropOfStatus is the drop reason of a refusal by the access policy,
// from its access-log status.
func udpDropOfStatus(status string) string {
	if status == l4StatusDenylisted {
		return udpDropDenylisted
	}
	return udpDropRefused
}

const (
	// udpRefusalMemory is how long a listener remembers a source it
	// refused: within it the source's refusals are counted and have no
	// line of their own in the access log.
	udpRefusalMemory = 10 * time.Second
	// udpRefusalsKept is how many refused sources a listener remembers.
	// Past it (a flood from made-up sources) a refusal is counted only.
	udpRefusalsKept = 1024
)

// udpRefusals is what a UDP listener remembers of the sources it refused:
// a datagram of a source without a session is a new session, so a refused
// source has its session refused again with every datagram it sends. The
// policy is asked each time (a change of it holds at once); what is not
// repeated is the line in the access log.
type udpRefusals struct {
	mu    sync.Mutex
	until map[netip.Addr]int64 // the source's next line is due then (unix nanos)
	swept int64
}

// first reports whether a refusal of ip at now gets a line in the access
// log: the source has had none within udpRefusalMemory, and there is room
// to remember it.
func (r *udpRefusals) first(ip netip.Addr, now int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if until, ok := r.until[ip]; ok && now < until {
		return false
	}
	if len(r.until) >= udpRefusalsKept {
		// Full: the sources whose time is over make room, looked for at
		// most once a second.
		if now-r.swept < int64(time.Second) {
			return false
		}
		r.swept = now
		for k, until := range r.until {
			if now >= until {
				delete(r.until, k)
			}
		}
		if len(r.until) >= udpRefusalsKept {
			return false
		}
	}
	if r.until == nil {
		r.until = make(map[netip.Addr]int64)
	}
	r.until[ip] = now + int64(udpRefusalMemory)
	return true
}

// udpRefused counts a new UDP session that listener refused to ip, for
// reason. True: the refusal's line is to be written to the access log.
func (h *ProxyEventHandler) udpRefused(r *udpRefusals, reason, listener string, ip netip.Addr) bool {
	h.udpDrops.noteIP(reason, listener, ip)
	return r == nil || r.first(ip, time.Now().UnixNano())
}
