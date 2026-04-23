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
	backendName string
	servers     []string // original server list (may contain hostnames)
	interval    time.Duration
	onUpdate    func(servers []string)
	lastResult  string // sorted joined list for change detection
	stopCh      chan struct{}
}

// NewDNSResolver creates a resolver for the given backend servers.
func NewDNSResolver(backendName string, servers []string, interval time.Duration, onUpdate func(servers []string)) *DNSResolver {
	return &DNSResolver{
		backendName: backendName,
		servers:     servers,
		interval:    interval,
		onUpdate:    onUpdate,
		stopCh:      make(chan struct{}),
	}
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

		// Check if host is already an IP
		if ip := net.ParseIP(host); ip != nil {
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

		for _, ip := range ips {
			if port != "" {
				resolved = append(resolved, fmt.Sprintf("%s:%s", ip, port))
			} else {
				resolved = append(resolved, ip)
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
