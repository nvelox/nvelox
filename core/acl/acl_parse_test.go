package acl

import "testing"

// TestParseIPMatchList_ZeroCIDRIsAny: in ip_allowlist / ip_denylist /
// source_ip, "0.0.0.0/0" also matches IPv6 clients; in trusted_proxies
// (ParseCIDRList) it keeps its literal IPv4-only meaning, so trust is never
// widened.
func TestParseIPMatchList_ZeroCIDRIsAny(t *testing.T) {
	list := ParseIPMatchList([]string{"0.0.0.0/0"})
	if !CheckIPList("2001:db8::1", list) || !CheckIPList("1.2.3.4", list) {
		t.Error("ip list 0.0.0.0/0 must match IPv4 and IPv6 clients")
	}
	if CheckIPList("2001:db8::1", ParseCIDRList([]string{"0.0.0.0/0"})) {
		t.Error("ParseCIDRList(0.0.0.0/0) must stay IPv4-only")
	}
}

func TestParseCIDR_TrimsAndRejects(t *testing.T) {
	if n := ParseCIDR(" 10.0.0.0/8 "); n == nil || n.String() != "10.0.0.0/8" {
		t.Errorf("ParseCIDR(\" 10.0.0.0/8 \") = %v", n)
	}
	if n := ParseCIDR("192.0.2.7"); n == nil || n.String() != "192.0.2.7/32" {
		t.Errorf("bare IPv4 = %v, want /32", n)
	}
	if n := ParseCIDR("2001:db8::7"); n == nil || n.String() != "2001:db8::7/128" {
		t.Errorf("bare IPv6 = %v, want /128", n)
	}
	for _, bad := range []string{"", "10.0.0.0/33", "bogus", "1.2.3.4/"} {
		if n := ParseCIDR(bad); n != nil {
			t.Errorf("ParseCIDR(%q) = %v, want nil", bad, n)
		}
	}
}
