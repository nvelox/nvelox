package config

import (
	"fmt"
	"net"
	"strings"
)

// validateAddrLists rejects an ip_allowlist, ip_denylist or trusted_proxies
// entry, or an ACL rule's source_ip entry, that is neither an IP address nor
// a CIDR. These used to be dropped silently when the listener was built: a
// typo removed an allowlist entry, left the real upstream proxy untrusted,
// or — when every source_ip entry of an ACL rule was bad — turned the rule
// into one that matched every client.
func validateAddrLists(listeners []Listener) error {
	for _, l := range listeners {
		lists := []struct {
			field   string
			entries []string
		}{
			{"ip_allowlist", l.IPAllowlist},
			{"ip_denylist", l.IPDenylist},
			{"trusted_proxies", l.TrustedProxies},
		}
		for i, a := range l.ACL {
			lists = append(lists, struct {
				field   string
				entries []string
			}{fmt.Sprintf("acl %d source_ip", i), a.Match.SourceIP})
		}
		for _, list := range lists {
			for _, e := range list.entries {
				if !isAddrOrCIDR(e) {
					return fmt.Errorf("listener %s: %s: %q is not an IP address or CIDR", l.Name, list.field, e)
				}
			}
		}
	}
	return nil
}

// addrNet parses one entry as acl.ParseCIDR does: a CIDR, or an address as
// a /32 or /128; nil if it is neither.
func addrNet(s string) *net.IPNet {
	s = strings.TrimSpace(s)
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

// firstOverlap returns the first entry of a and entry of b whose ranges
// share an address (two CIDR ranges do when one holds the other's first
// address).
func firstOverlap(a, b []string) (string, string, bool) {
	for _, x := range a {
		xn := addrNet(x)
		if xn == nil {
			continue
		}
		for _, y := range b {
			yn := addrNet(y)
			if yn == nil {
				continue
			}
			if xn.Contains(yn.IP) || yn.Contains(xn.IP) {
				return strings.TrimSpace(x), strings.TrimSpace(y), true
			}
		}
	}
	return "", "", false
}

// isAddrOrCIDR reports whether s (surrounding spaces ignored) is an IP
// address or a CIDR — the forms acl.ParseCIDR accepts.
func isAddrOrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}
