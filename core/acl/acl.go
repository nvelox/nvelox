package acl

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"nvelox/config"
)

// CompiledRule is a pre-compiled ACL rule for fast matching.
type CompiledRule struct {
	Networks   []*net.IPNet
	Methods    map[string]bool
	Headers    map[string]string // header name -> required value
	PathPrefix string            // request path must start with this (if set)
	PathRegex  *regexp.Regexp    // request path must match this (if set)
	Action     string            // "allow" or "deny"
	Status     int               // HTTP status for a matched "deny" (0 = default 403)
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

		// Compile source IP CIDRs
		for _, cidr := range r.Match.SourceIP {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				// Try as single IP
				ip := net.ParseIP(cidr)
				if ip != nil {
					mask := net.CIDRMask(32, 32)
					if ip.To4() == nil {
						mask = net.CIDRMask(128, 128)
					}
					ipnet = &net.IPNet{IP: ip, Mask: mask}
				} else {
					continue
				}
			}
			cr.Networks = append(cr.Networks, ipnet)
		}

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
func (e *Engine) DecideClientIP(r *http.Request, clientIP net.IP) (string, int) {
	for _, rule := range e.rules {
		if e.matches(r, clientIP, &rule) {
			return rule.Action, rule.Status
		}
	}
	return "", 0 // no rule matched
}

func (e *Engine) matches(r *http.Request, clientIP net.IP, rule *CompiledRule) bool {
	// Check path prefix
	if rule.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, rule.PathPrefix) {
		return false
	}

	// Check path regex
	if rule.PathRegex != nil && !rule.PathRegex.MatchString(r.URL.Path) {
		return false
	}

	// Check source IP
	if len(rule.Networks) > 0 {
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

// ParseCIDRList parses a list of CIDR strings into net.IPNet.
func ParseCIDRList(strs []string) []*net.IPNet {
	var result []*net.IPNet
	for _, s := range strs {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			ip := net.ParseIP(s)
			if ip != nil {
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				ipnet = &net.IPNet{IP: ip, Mask: mask}
			} else {
				continue
			}
		}
		result = append(result, ipnet)
	}
	return result
}
