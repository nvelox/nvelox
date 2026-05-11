package acl

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"nvelox/config"
)

func TestACL_SourceIP_Deny(t *testing.T) {
	engine := NewEngine([]config.ACLRule{
		{Match: config.ACLMatch{SourceIP: []string{"192.168.1.0/24"}}, Action: "deny"},
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.50:1234"

	if action := engine.Check(r); action != "deny" {
		t.Errorf("expected deny, got %q", action)
	}

	r.RemoteAddr = "10.0.0.1:1234"
	if action := engine.Check(r); action != "" {
		t.Errorf("expected no match, got %q", action)
	}
}

func TestACL_Method_Deny(t *testing.T) {
	engine := NewEngine([]config.ACLRule{
		{Match: config.ACLMatch{Method: []string{"DELETE", "PUT"}}, Action: "deny"},
	})

	r := httptest.NewRequest("DELETE", "/resource", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	if action := engine.Check(r); action != "deny" {
		t.Errorf("expected deny for DELETE, got %q", action)
	}

	r = httptest.NewRequest("GET", "/resource", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	if action := engine.Check(r); action != "" {
		t.Errorf("expected no match for GET, got %q", action)
	}
}

func TestACL_Method_CaseInsensitive(t *testing.T) {
	// Rule methods are compiled uppercase; request methods must be normalized
	// before lookup or attackers can bypass rules by sending lowercase verbs.
	engine := NewEngine([]config.ACLRule{
		{Match: config.ACLMatch{Method: []string{"DELETE"}}, Action: "deny"},
	})

	for _, m := range []string{"DELETE", "delete", "Delete", "dElEtE"} {
		r := httptest.NewRequest(m, "/resource", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		if action := engine.Check(r); action != "deny" {
			t.Errorf("expected deny for method %q, got %q", m, action)
		}
	}
}

func TestACL_Combined(t *testing.T) {
	engine := NewEngine([]config.ACLRule{
		{
			Match:  config.ACLMatch{SourceIP: []string{"10.0.0.0/8"}, Method: []string{"DELETE"}},
			Action: "deny",
		},
	})

	// DELETE from 10.x → deny
	r := httptest.NewRequest("DELETE", "/", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	if engine.Check(r) != "deny" {
		t.Error("expected deny for DELETE from 10.x")
	}

	// GET from 10.x → no match (method doesn't match)
	r = httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	if engine.Check(r) != "" {
		t.Error("expected no match for GET from 10.x")
	}

	// DELETE from 192.x → no match (IP doesn't match)
	r = httptest.NewRequest("DELETE", "/", nil)
	r.RemoteAddr = "192.168.1.1:1234"
	if engine.Check(r) != "" {
		t.Error("expected no match for DELETE from 192.x")
	}
}

func TestACL_Headers(t *testing.T) {
	engine := NewEngine([]config.ACLRule{
		{Match: config.ACLMatch{Headers: map[string]string{"X-Bad": "true"}}, Action: "deny"},
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Bad", "true")
	if engine.Check(r) != "deny" {
		t.Error("expected deny with matching header")
	}

	r.Header.Del("X-Bad")
	if engine.Check(r) != "" {
		t.Error("expected no match without header")
	}
}

func TestACL_Allow(t *testing.T) {
	engine := NewEngine([]config.ACLRule{
		{Match: config.ACLMatch{SourceIP: []string{"10.0.0.0/8"}}, Action: "allow"},
		{Match: config.ACLMatch{}, Action: "deny"}, // deny everything else
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	if engine.Check(r) != "allow" {
		t.Error("expected allow for 10.x")
	}

	r.RemoteAddr = "192.168.1.1:1234"
	if engine.Check(r) != "deny" {
		t.Error("expected deny for non-10.x")
	}
}

func TestCheckIPList(t *testing.T) {
	cidrs := ParseCIDRList([]string{"10.0.0.0/8", "192.168.1.100"})

	if !CheckIPList("10.0.0.5:1234", cidrs) {
		t.Error("10.0.0.5 should match 10.0.0.0/8")
	}
	if !CheckIPList("192.168.1.100:5678", cidrs) {
		t.Error("192.168.1.100 should match")
	}
	if CheckIPList("172.16.0.1:1234", cidrs) {
		t.Error("172.16.0.1 should not match")
	}
}

func TestParseCIDRList_SingleIP(t *testing.T) {
	cidrs := ParseCIDRList([]string{"1.2.3.4"})
	if len(cidrs) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(cidrs))
	}
	if !CheckIPList("1.2.3.4:80", cidrs) {
		t.Error("1.2.3.4 should match")
	}
}

func TestACL_NoRules(t *testing.T) {
	engine := NewEngine(nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	if action := engine.Check(r); action != "" {
		t.Errorf("expected no match with no rules, got %q", action)
	}
}

// Ensure http import is used
var _ = http.StatusOK
