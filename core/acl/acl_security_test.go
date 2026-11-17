package acl

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"nvelox/config"
)

// TestACL_ZeroCIDRMatchesIPv6: "0.0.0.0/0" in a source_ip, an ip_allowlist
// or an ip_denylist means every client, IPv6 included (it matched IPv4
// only, so "deny DELETE from 0.0.0.0/0" let every IPv6 client through).
func TestACL_ZeroCIDRMatchesIPv6(t *testing.T) {
	e := NewEngine([]config.ACLRule{{Match: config.ACLMatch{SourceIP: []string{"0.0.0.0/0"}, Method: []string{"DELETE"}}, Action: "deny"}})
	r := httptest.NewRequest("DELETE", "/", nil)
	for _, ip := range []string{"1.2.3.4", "2001:db8::1", "::1"} {
		if a, _ := e.DecideClientIP(r, net.ParseIP(ip)); a != "deny" {
			t.Errorf("DELETE from %s: %q, want deny", ip, a)
		}
	}
}

// TestACL_UnparsableSourceIPNeverMatches: a rule whose source_ip entries
// all fail to parse used to have no source condition and matched everyone —
// an allow rule then let any client past the deny below it.
func TestACL_UnparsableSourceIPNeverMatches(t *testing.T) {
	e := NewEngine([]config.ACLRule{
		{Match: config.ACLMatch{SourceIP: []string{"10.0.0.0/33", "bogus"}, PathPrefix: "/admin"}, Action: "allow"},
		{Match: config.ACLMatch{PathPrefix: "/admin"}, Action: "deny"},
	})
	if a, _ := e.DecideClientIP(httptest.NewRequest("GET", "/admin", nil), net.ParseIP("8.8.8.8")); a != "deny" {
		t.Fatalf("8.8.8.8 -> %q, want deny", a)
	}
}

// TestACL_CanonicalPathAndParams: rules see the canonical path; a deny
// rule also matches the form without ";params", an allow rule needs both.
func TestACL_CanonicalPathAndParams(t *testing.T) {
	deny := NewEngine([]config.ACLRule{{Match: config.ACLMatch{PathRegex: `^/admin(/|$)`}, Action: "deny", Status: http.StatusNotFound}})
	for _, p := range []string{"//admin", "/x/../admin", "/./admin/", "/admin;jsessionid=1", "/admin;x/y", "/a/..;/admin"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p // as decoded from the request line
		if a, s := deny.DecideClientIP(r, net.ParseIP("203.0.113.1")); a != "deny" || s != http.StatusNotFound {
			t.Errorf("%s -> %q/%d, want deny/404", p, a, s)
		}
	}
	allow := NewEngine([]config.ACLRule{
		{Match: config.ACLMatch{PathPrefix: "/public"}, Action: "allow"},
		{Match: config.ACLMatch{PathPrefix: "/"}, Action: "deny"},
	})
	for p, want := range map[string]string{
		"/public/a":        "allow",
		"/public;v=1/a":    "allow", // both forms are under /public
		"/public/..;/priv": "deny",  // without params it is /priv
		"/priv":            "deny",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		if a, _ := allow.DecideClientIP(r, net.ParseIP("203.0.113.1")); a != want {
			t.Errorf("allowlist: %s -> %q, want %q", p, a, want)
		}
	}
}
