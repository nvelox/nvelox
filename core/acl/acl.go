package acl

import (
	"net"
	"net/http"
	"strings"

	"nvelox/config"
)

// CompiledRule is a pre-compiled ACL rule for fast matching.
type CompiledRule struct {
	Networks []*net.IPNet
	Methods  map[string]bool
	Headers  map[string]string // header name -> required value
	Action   string            // "allow" or "deny"
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

// Check evaluates the request against all rules. Returns "allow", "deny", or "" (no match).
func (e *Engine) Check(r *http.Request) string {
	clientIP := extractIP(r.RemoteAddr)

	for _, rule := range e.rules {
		if e.matches(r, clientIP, &rule) {
			return rule.Action
		}
	}
	return "" // no rule matched
}

func (e *Engine) matches(r *http.Request, clientIP net.IP, rule *CompiledRule) bool {
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

	// Check method
	if len(rule.Methods) > 0 {
		if !rule.Methods[r.Method] {
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
