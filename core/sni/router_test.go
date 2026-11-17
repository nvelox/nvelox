package sni

import (
	"testing"

	"nvelox/config"
)

func TestSNIRouter_ExactMatch(t *testing.T) {
	r := NewRouter([]config.SNIRoute{
		{ServerName: "api.example.com", Backend: "api"},
		{ServerName: "web.example.com", Backend: "web"},
	})

	if got := r.Match("api.example.com"); got != "api" {
		t.Errorf("expected api, got %s", got)
	}
	if got := r.Match("web.example.com"); got != "web" {
		t.Errorf("expected web, got %s", got)
	}
	if got := r.Match("other.example.com"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestSNIRouter_Wildcard(t *testing.T) {
	r := NewRouter([]config.SNIRoute{
		{ServerName: "*.example.com", Backend: "wildcard"},
	})

	if got := r.Match("sub.example.com"); got != "wildcard" {
		t.Errorf("expected wildcard, got %s", got)
	}
	if got := r.Match("other.example.com"); got != "wildcard" {
		t.Errorf("expected wildcard, got %s", got)
	}
	// sub.sub.example.com should NOT match *.example.com (single level)
	if got := r.Match("sub.sub.example.com"); got != "" {
		t.Errorf("expected empty for multi-level, got %s", got)
	}
}

func TestSNIRouter_CaseInsensitive(t *testing.T) {
	r := NewRouter([]config.SNIRoute{
		{ServerName: "API.Example.COM", Backend: "api"},
	})

	if got := r.Match("api.example.com"); got != "api" {
		t.Errorf("expected api, got %s", got)
	}
}

func TestSNIRouter_NoRoutes(t *testing.T) {
	r := NewRouter(nil)
	if got := r.Match("anything"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestExtractSNI(t *testing.T) {
	// This is a minimal TLS 1.2 ClientHello with SNI "example.com"
	// In real usage, extractSNI is tested via integration tests
	// Here we test the empty/invalid cases
	if got := extractSNI(nil); got != "" {
		t.Errorf("expected empty for nil, got %s", got)
	}
	if got := extractSNI([]byte{0x00}); got != "" {
		t.Errorf("expected empty for non-handshake, got %s", got)
	}
	if got := extractSNI([]byte{0x16, 0x03, 0x01, 0x00, 0x00}); got != "" {
		t.Errorf("expected empty for empty handshake, got %s", got)
	}
}
