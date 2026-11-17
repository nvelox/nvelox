package tlsutil

import "testing"

func TestMatchHost(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		patterns []string
		want     string
		hit      bool
	}{
		// Exact matches.
		{"exact lower", "api.foo.com", []string{"api.foo.com"}, "api.foo.com", true},
		{"exact mixed case host", "API.Foo.com", []string{"api.foo.com"}, "api.foo.com", true},
		{"exact mixed case pattern", "api.foo.com", []string{"API.Foo.COM"}, "api.foo.com", true},
		{"trailing dot stripped", "api.foo.com.", []string{"api.foo.com"}, "api.foo.com", true},

		// Wildcard matches.
		{"wildcard match", "api.foo.com", []string{"*.foo.com"}, "*.foo.com", true},
		{"wildcard nope at apex", "foo.com", []string{"*.foo.com"}, "", false},
		{"wildcard only one label", "x.y.foo.com", []string{"*.foo.com"}, "", false},

		// Exact wins over wildcard regardless of pattern order.
		{"exact wins over wildcard same name", "api.foo.com",
			[]string{"*.foo.com", "api.foo.com"}, "api.foo.com", true},
		{"wildcard order before exact still picks exact", "api.foo.com",
			[]string{"api.foo.com", "*.foo.com"}, "api.foo.com", true},

		// Misses.
		{"empty host", "", []string{"foo.com"}, "", false},
		{"empty patterns", "foo.com", nil, "", false},
		{"unrelated", "bar.com", []string{"foo.com", "*.foo.com"}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, hit := MatchHost(c.host, c.patterns)
			if hit != c.hit || got != c.want {
				t.Errorf("MatchHost(%q, %v) = (%q, %v); want (%q, %v)",
					c.host, c.patterns, got, hit, c.want, c.hit)
			}
		})
	}
}

func TestMatchSite_ExactBeatsWildcard(t *testing.T) {
	// Two sites: one wildcard, one exact. Even with wildcard listed first,
	// the exact match for api.foo.com wins.
	sites := []SiteEntry[string]{
		{Patterns: []string{"*.foo.com"}, Payload: "wild"},
		{Patterns: []string{"api.foo.com"}, Payload: "exact"},
	}
	got, ok := MatchSite("api.foo.com", sites)
	if !ok || got != "exact" {
		t.Errorf("got (%q,%v), want (exact, true)", got, ok)
	}

	// A name only the wildcard matches goes to wild.
	got, ok = MatchSite("other.foo.com", sites)
	if !ok || got != "wild" {
		t.Errorf("got (%q,%v), want (wild, true)", got, ok)
	}

	// No match at all.
	if _, ok := MatchSite("unknown.com", sites); ok {
		t.Error("unrelated host must miss")
	}
}
