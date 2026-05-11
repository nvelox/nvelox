package discovery

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"nvelox/core/logging"
)

// DNSResolver periodically resolves hostnames in backend server lists
// and calls onUpdate when the resolved IP list changes.
type DNSResolver struct {
	backendName     string
	servers         []string // original server list (may contain hostnames)
	interval        time.Duration
	allowPrivateIPs bool // if false, reject resolved IPs in private/loopback/link-local ranges
	onUpdate        func(servers []string)
	lastResult      string // sorted joined list for change detection
	stopCh          chan struct{}
}

// NewDNSResolver creates a resolver for the given backend servers.
// allowPrivateIPs: if false (default / recommended for public backends),
// resolved IPs in RFC1918, loopback (127/8, ::1), link-local (169.254/16,
// fe80::/10) and CGNAT (100.64/10) ranges are dropped to prevent SSRF
// when backend hostnames are attacker-controlled.
func NewDNSResolver(backendName string, servers []string, interval time.Duration, allowPrivateIPs bool, onUpdate func(servers []string)) *DNSResolver {
	return &DNSResolver{
		backendName:     backendName,
		servers:         servers,
		interval:        interval,
		allowPrivateIPs: allowPrivateIPs,
		onUpdate:        onUpdate,
		stopCh:          make(chan struct{}),
	}
}

// isPrivateOrLoopback reports whether an IP is in a range that should not
// be reached over the public internet. The list is deliberately broad:
// loopback, RFC1918, link-local, CGNAT, unique-local IPv6.
func isPrivateOrLoopback(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	// CGNAT 100.64.0.0/10 is not flagged by net.IP.IsPrivate.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && (ip4[1]&0xc0) == 64 {
			return true
		}
	}
	return false
}

// Start begins periodic DNS resolution.
func (r *DNSResolver) Start() {
	// Do an initial resolve
	r.resolve()

	go func() {
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopCh:
				return
			case <-ticker.C:
				r.resolve()
			}
		}
	}()

	logging.Info("[DNS] Resolver started for %s (interval: %v)", r.backendName, r.interval)
}

// Stop halts the resolver.
func (r *DNSResolver) Stop() {
	close(r.stopCh)
}

func (r *DNSResolver) resolve() {
	var resolved []string

	for _, server := range r.servers {
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			// No port — try as hostname
			host = server
			port = ""
		}

		// Check if host is already an IP. We still enforce the private-IP
		// policy so operators can't accidentally bypass it by pre-resolving.
		if ip := net.ParseIP(host); ip != nil {
			if !r.allowPrivateIPs && isPrivateOrLoopback(ip) {
				logging.Warn("[DNS] Backend %s: rejecting configured private/loopback IP %s (set allow_private_ips to override)",
					r.backendName, ip)
				continue
			}
			resolved = append(resolved, server)
			continue
		}

		// Resolve hostname
		ips, err := net.LookupHost(host)
		if err != nil {
			logging.Warn("[DNS] Failed to resolve %s: %v", host, err)
			resolved = append(resolved, server) // keep original on failure
			continue
		}

		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if !r.allowPrivateIPs && isPrivateOrLoopback(ip) {
				// Possible DNS rebinding / SSRF vector — a public hostname
				// resolving to a private IP. Drop silently but log once.
				logging.Warn("[DNS] Backend %s: rejecting resolved private/loopback IP %s (host %s)",
					r.backendName, ipStr, host)
				continue
			}
			if port != "" {
				resolved = append(resolved, fmt.Sprintf("%s:%s", ipStr, port))
			} else {
				resolved = append(resolved, ipStr)
			}
		}
	}

	// Sort for stable comparison
	sort.Strings(resolved)
	result := strings.Join(resolved, ",")

	if result != r.lastResult {
		r.lastResult = result
		logging.Info("[DNS] Backend %s resolved to: %v", r.backendName, resolved)
		if r.onUpdate != nil {
			r.onUpdate(resolved)
		}
	}
}
