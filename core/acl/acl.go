package acl

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"nvelox/config"
	"nvelox/core/httppath"
)

// CompiledRule is a pre-compiled ACL rule for fast matching.
type CompiledRule struct {
	Networks []*net.IPNet
	// SourceIPSet is true when the rule names source_ip at all. Such a rule
	// matches only clients inside Networks: if none of its entries parsed,
	// it matches nobody (it used to match everybody, because an empty
	// Networks list read as "no source condition").
	SourceIPSet bool
	Methods     map[string]bool
	Headers     map[string]string // header name -> required value
	PathPrefix  string            // request path must start with this (if set)
	PathRegex   *regexp.Regexp    // request path must match this (if set)
	Action      string            // "allow" or "deny"
	Status      int               // HTTP status for a matched "deny" (0 = default 403)
}

// Engine evaluates ACL rules against HTTP requests.
type Engine struct {
	rules []CompiledRule
}

// NewEngine compiles ACL rules from config.
func NewEngine(rules []config.ACLRule) *Engine {
	compiled := make([]CompiledRule, 0, len(rules))
	for _, r := range rules {
		cr := CompiledRule{
			Action: r.Action,
			Status: r.Status,
		}

		// Compile path conditions. A path_regex that fails to compile is
		// dropped to nil here; config validation (validate() in config)
		// rejects bad regexes at startup, so this is only defense-in-depth.
		cr.PathPrefix = r.Match.PathPrefix
		if r.Match.PathRegex != "" {
			cr.PathRegex, _ = regexp.Compile(r.Match.PathRegex)
		}

		// Compile source IP CIDRs. Config validation rejects an entry that
		// is not an IP or CIDR; one that still fails here is dropped, and a
		// rule left with no network never matches (SourceIPSet).
		cr.SourceIPSet = len(r.Match.SourceIP) > 0
		cr.Networks = ParseIPMatchList(r.Match.SourceIP)

		// Compile methods
		if len(r.Match.Method) > 0 {
			cr.Methods = make(map[string]bool)
			for _, m := range r.Match.Method {
				cr.Methods[strings.ToUpper(m)] = true
			}
		}

		// Headers
		cr.Headers = r.Match.Headers

		compiled = append(compiled, cr)
	}
	return &Engine{rules: compiled}
}

// Check evaluates the request against all rules, matching source-IP rules
// against the raw connection peer (r.RemoteAddr). Returns "allow", "deny",
// or "" (no match). Prefer CheckClientIP when a trusted-proxy-resolved
// client IP is available so rules match the real client, not the upstream
// proxy.
func (e *Engine) Check(r *http.Request) string {
	return e.CheckClientIP(r, extractIP(r.RemoteAddr))
}

// CheckClientIP is like Check but matches source-IP rules against an
// explicitly-resolved client IP (e.g. the real client recovered from a
// trusted proxy's X-Forwarded-For) instead of the raw connection peer. A
// nil clientIP simply never matches a source-IP rule.
func (e *Engine) CheckClientIP(r *http.Request, clientIP net.IP) string {
	action, _ := e.DecideClientIP(r, clientIP)
	return action
}

// DecideClientIP is like CheckClientIP but also returns the HTTP status the
// caller should use when the winning rule is a "deny". The status is 0 for an
// "allow" or no match, and for a "deny" it is the rule's configured Status or 0
// if unset (the caller applies its own default, conventionally 403). The first
// matching rule wins.
//
// Path conditions see the request path in canonical form (dot segments
// resolved, duplicate slashes merged; see httppath.Canonical), so "//admin",
// "/x/../admin" and "/%2e/admin" are "/admin". When the path carries
// ";params" (which servlet containers and some frameworks strip before
// routing) a rule also looks at the form without them: a deny rule matches
// if either form matches ("/admin;x" is denied by a rule for "/admin"), an
// allow rule only if both do ("/public/..;/admin" is not allowed by a rule
// for "/public"). A path that does not start with '/' (OPTIONS *) is
// matched as "/". Matching is case-sensitive; use path_regex with (?i) in
// front of a case-insensitive backend.
func (e *Engine) DecideClientIP(r *http.Request, clientIP net.IP) (string, int) {
	path := httppath.Canonical(r.URL.Path)
	if !strings.HasPrefix(path, "/") {
		path = "/"
	}
	bare := path
	if strings.Contains(path, ";") {
		bare = httppath.WithoutParams(path)
	}
	for _, rule := range e.rules {
		m := e.matches(r, path, clientIP, &rule)
		if bare != path {
			mb := e.matches(r, bare, clientIP, &rule)
			if rule.Action == "deny" {
				m = m || mb
			} else {
				m = m && mb
			}
		}
		if m {
			return rule.Action, rule.Status
		}
	}
	return "", 0 // no rule matched
}

func (e *Engine) matches(r *http.Request, path string, clientIP net.IP, rule *CompiledRule) bool {
	// Check path prefix
	if rule.PathPrefix != "" && !strings.HasPrefix(path, rule.PathPrefix) {
		return false
	}

	// Check path regex
	if rule.PathRegex != nil && !rule.PathRegex.MatchString(path) {
		return false
	}

	// Check source IP
	if rule.SourceIPSet {
		matched := false
		for _, net := range rule.Networks {
			if net.Contains(clientIP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check method (normalize to uppercase — rule methods compiled uppercase)
	if len(rule.Methods) > 0 {
		if !rule.Methods[strings.ToUpper(r.Method)] {
			return false
		}
	}

	// Check headers
	for name, value := range rule.Headers {
		if r.Header.Get(name) != value {
			return false
		}
	}

	return true
}

func extractIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

// CheckIPList checks if the client IP is in a CIDR list.
// Returns true if the IP matches any entry.
func CheckIPList(remoteAddr string, cidrs []*net.IPNet) bool {
	ip := extractIP(remoteAddr)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRList parses a list of CIDR strings (or bare IPs, as a /32 or
// /128) into net.IPNet. Surrounding spaces are ignored; an entry that is
// neither is dropped (config validation rejects it at load, see
// config.validateIPLists). Used for trusted_proxies and accept_proxy_from:
// "0.0.0.0/0" stays IPv4-only there, so it never widens trust to IPv6.
func ParseCIDRList(strs []string) []*net.IPNet {
	var result []*net.IPNet
	for _, s := range strs {
		if ipnet := ParseCIDR(s); ipnet != nil {
			result = append(result, ipnet)
		}
	}
	return result
}

// ParseCIDR parses one CIDR or bare IP (surrounding spaces ignored); nil if
// it is neither.
func ParseCIDR(s string) *net.IPNet {
	s = strings.TrimSpace(s)
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return ipnet
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

// anyIPv6 is ::/0, added next to every "0.0.0.0/0" of a match list.
var anyIPv6 = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}

// ParseIPMatchList is ParseCIDRList for the lists that select clients:
// ip_allowlist, ip_denylist and an ACL rule's source_ip. There "0.0.0.0/0"
// is written to mean "any client", so it also matches IPv6 (::/0 is added);
// it used to match IPv4 clients only, letting every IPv6 client past a
// "deny from 0.0.0.0/0" rule.
func ParseIPMatchList(strs []string) []*net.IPNet {
	nets := ParseCIDRList(strs)
	for _, n := range nets {
		if ones, bits := n.Mask.Size(); ones == 0 && bits == 32 {
			return append(nets, anyIPv6)
		}
	}
	return nets
}
