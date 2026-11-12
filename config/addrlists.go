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

// isAddrOrCIDR reports whether s (surrounding spaces ignored) is an IP
// address or a CIDR — the forms acl.ParseCIDR accepts.
func isAddrOrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}
