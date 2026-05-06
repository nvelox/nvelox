package tlsutil

import "strings"

// MatchHost reports whether `name` (a hostname from SNI or the Host header)
// matches one of the patterns. Exact matches are case-insensitive. Wildcard
// patterns of the form "*.foo.com" match exactly one leftmost label
// ("api.foo.com" matches; "foo.com" and "x.y.foo.com" do not). This is
// nginx semantics and what every common TLS CA issues.
//
// Returns the matched pattern (so callers can rank exact > wildcard) and
// true on hit, or "", false on miss.
func MatchHost(name string, patterns []string) (string, bool) {
	if name == "" || len(patterns) == 0 {
		return "", false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// Exact match takes priority over wildcards.
	for _, p := range patterns {
		p = strings.ToLower(p)
		if !strings.HasPrefix(p, "*.") && p == name {
			return p, true
		}
	}

	// Leftmost wildcard: "*.foo.com" matches a name with exactly one extra
	// label ("api.foo.com" matches, "foo.com" does not, "x.y.foo.com" does not).
	for _, p := range patterns {
		p = strings.ToLower(p)
		if !strings.HasPrefix(p, "*.") {
			continue
		}
		suffix := p[1:] // ".foo.com"
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		// Check that the part before the suffix has no further dots.
		head := name[:len(name)-len(suffix)]
		if head == "" || strings.Contains(head, ".") {
			continue
		}
		return p, true
	}

	return "", false
}

// MatchSite walks a list of {patterns, payload} entries and returns the
// first payload whose patterns match name. Exact matches across the whole
// list win over wildcard matches — so an entry with "api.foo.com" beats
// another entry's "*.foo.com" regardless of order.
func MatchSite[T any](name string, sites []SiteEntry[T]) (T, bool) {
	var zero T
	if name == "" || len(sites) == 0 {
		return zero, false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// Exact pass first.
	for _, s := range sites {
		for _, p := range s.Patterns {
			if !strings.HasPrefix(p, "*.") && strings.EqualFold(p, name) {
				return s.Payload, true
			}
		}
	}
	// Wildcard pass.
	for _, s := range sites {
		for _, p := range s.Patterns {
			if !strings.HasPrefix(p, "*.") {
				continue
			}
			suffix := strings.ToLower(p[1:])
			if !strings.HasSuffix(name, suffix) {
				continue
			}
			head := name[:len(name)-len(suffix)]
			if head == "" || strings.Contains(head, ".") {
				continue
			}
			return s.Payload, true
		}
	}
	return zero, false
}

// SiteEntry pairs a list of hostname patterns with a payload (typically a
// *tls.Certificate or a site handler). Used by MatchSite for one-pass
// dispatch over many sites.
type SiteEntry[T any] struct {
	Patterns []string
	Payload  T
}
