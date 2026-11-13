package core

import (
	"fmt"
	"net"

	"nvelox/config"
	"nvelox/core/acl"
	"nvelox/core/denylist"
	"nvelox/core/tlsutil"
)

// L4 access control: the static ip_denylist / ip_allowlist / source_ip ACL
// and the dynamic (admin API) denylist, enforced on every L4 entry point —
// plain TCP, TLS-terminating TCP and UDP — on the RESOLVED client: the
// PROXY-v2 source when a trusted accept_proxy_from relay names one, else the
// connection peer. The HTTP path enforces the same lists per request in
// httpproxy.HTTPServer.ServeHTTP.

// L4 access-log status tokens for a refused connection / UDP session.
const (
	l4StatusRefused     = "refused"     // static ip_denylist, ip_allowlist or acl deny
	l4StatusDenylisted  = "denylisted"  // dynamic denylist (admin API)
	l4StatusRateLimited = "ratelimited" // a limit: listener rate, backend max_connections, UDP session caps
)

// l4Access is a listener's static access policy, parsed once (prepare).
type l4Access struct {
	deny  []*net.IPNet
	allow []*net.IPNet
	acl   []l4ACLRule
}

// l4ACLRule is a source_ip-only ACL rule (tcp/udp listeners reject the HTTP
// matchers at load). No networks = matches every client, as on HTTP.
type l4ACLRule struct {
	nets  []*net.IPNet
	allow bool
}

// parseIPNets parses a client list (ip_denylist, ip_allowlist, an ACL rule's
// source_ip) the way the HTTP path does — acl.ParseIPMatchList: surrounding
// spaces ignored, "0.0.0.0/0" also matches IPv6 clients — but fails on a bad
// entry instead of dropping it (a dropped entry can empty an allowlist, or
// turn an ACL rule into a match-all).
func parseIPNets(list []string) ([]*net.IPNet, error) {
	for _, s := range list {
		if acl.ParseCIDR(s) == nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR", s)
		}
	}
	return acl.ParseIPMatchList(list), nil
}

func newL4Access(denyList, allowList []string, rules []config.ACLRule) (*l4Access, error) {
	var a l4Access
	var err error
	if a.deny, err = parseIPNets(denyList); err != nil {
		return nil, fmt.Errorf("ip_denylist: %v", err)
	}
	if a.allow, err = parseIPNets(allowList); err != nil {
		return nil, fmt.Errorf("ip_allowlist: %v", err)
	}
	for i, r := range rules {
		if r.Action != "allow" && r.Action != "deny" {
			return nil, fmt.Errorf("acl %d: action must be 'allow' or 'deny', got %q", i, r.Action)
		}
		if r.Match.PathPrefix != "" || r.Match.PathRegex != "" || len(r.Match.Method) > 0 || len(r.Match.Headers) > 0 {
			return nil, fmt.Errorf("acl %d: only source_ip can be matched on a tcp/udp listener", i)
		}
		nets, err := parseIPNets(r.Match.SourceIP)
		if err != nil {
			return nil, fmt.Errorf("acl %d: source_ip: %v", i, err)
		}
		a.acl = append(a.acl, l4ACLRule{nets: nets, allow: r.Action == "allow"})
	}
	return &a, nil
}

func inNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// check applies the static policy in the HTTP path's order: ip_denylist, the
// dynamic denylist dyn, ip_allowlist (when set, only listed clients), then
// the first matching ACL rule (no match = allowed). A client whose address
// cannot be parsed (nil ip) is refused whenever any static control is set.
func (a *l4Access) check(ip net.IP, dyn *denylist.Dynamic) (bool, string) {
	if ip == nil {
		if a != nil && (len(a.deny) > 0 || len(a.allow) > 0 || len(a.acl) > 0) {
			return false, l4StatusRefused
		}
		return true, ""
	}
	if a != nil && inNets(ip, a.deny) {
		return false, l4StatusRefused
	}
	if dyn != nil && dyn.Blocked(ip) {
		return false, l4StatusDenylisted
	}
	if a == nil {
		return true, ""
	}
	if len(a.allow) > 0 && !inNets(ip, a.allow) {
		return false, l4StatusRefused
	}
	for _, r := range a.acl {
		if len(r.nets) == 0 || inNets(ip, r.nets) {
			if r.allow {
				return true, ""
			}
			return false, l4StatusRefused
		}
	}
	return true, ""
}

// prepare parses the listener's derived state once: the L4 access policy
// (tcp/udp) and the client-certificate policy (tls). ExpandListeners calls it
// so a bad entry fails the config load / reload pre-flight before anything
// changes; Engine.Start calls it again for listeners built by hand (tests),
// where it is a no-op once done.
func (l *ListenerConfig) prepare() error {
	if l.prepared {
		return nil
	}
	if l.Protocol == "tcp" || l.Protocol == "udp" {
		a, err := newL4Access(l.IPDenylist, l.IPAllowlist, l.ACL)
		if err != nil {
			return fmt.Errorf("listener %s: %v", l.Name, err)
		}
		l.access = a
	}
	if l.TLS != nil {
		ca, err := tlsutil.LoadClientAuth(*l.TLS)
		if err != nil {
			return fmt.Errorf("listener %s: tls: %v", l.Name, err)
		}
		l.clientAuth = ca
	}
	l.prepared = true
	return nil
}

// l4Admit decides whether the resolved client ip may use listener l: static
// lists and ACL plus the dynamic denylist. It returns the access-log status
// for a refusal ("refused" or "denylisted").
func (h *ProxyEventHandler) l4Admit(l *ListenerConfig, ip net.IP) (bool, string) {
	return l.access.check(ip, denylist.Default)
}
