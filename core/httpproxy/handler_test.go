package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"nvelox/config"
	"nvelox/core/acl"
)

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name       string
		upgrade    string
		connection string
		want       bool
	}{
		{"valid websocket", "websocket", "Upgrade", true},
		{"case insensitive upgrade", "WebSocket", "upgrade", true},
		{"connection with keep-alive", "websocket", "keep-alive, Upgrade", true},
		{"no upgrade header", "", "Upgrade", false},
		{"no connection header", "websocket", "", false},
		{"wrong upgrade value", "h2c", "Upgrade", false},
		{"both empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/ws", nil)
			if tt.upgrade != "" {
				r.Header.Set("Upgrade", tt.upgrade)
			}
			if tt.connection != "" {
				r.Header.Set("Connection", tt.connection)
			}
			got := isWebSocketUpgrade(r)
			if got != tt.want {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyRequestHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Existing", "value")
	r.Header.Set("ToRemove", "gone")

	h := &config.HeadersConfig{
		RequestAdd:    map[string]string{"X-Added": "added-val"},
		RequestSet:    map[string]string{"Existing": "overwritten"},
		RequestRemove: []string{"ToRemove"},
	}

	applyRequestHeaders(r, h)

	if r.Header.Get("X-Added") != "added-val" {
		t.Errorf("expected X-Added=added-val, got %q", r.Header.Get("X-Added"))
	}
	if r.Header.Get("Existing") != "overwritten" {
		t.Errorf("expected Existing=overwritten, got %q", r.Header.Get("Existing"))
	}
	if r.Header.Get("ToRemove") != "" {
		t.Errorf("expected ToRemove to be removed, got %q", r.Header.Get("ToRemove"))
	}
}

func TestApplyResponseHeaders(t *testing.T) {
	h := make(http.Header)
	h.Set("Existing", "value")
	h.Set("ToRemove", "gone")

	cfg := &config.HeadersConfig{
		ResponseAdd:    map[string]string{"X-Added": "resp-val"},
		ResponseSet:    map[string]string{"Existing": "new-value"},
		ResponseRemove: []string{"ToRemove"},
	}

	applyResponseHeaders(h, cfg)

	if h.Get("X-Added") != "resp-val" {
		t.Errorf("expected X-Added=resp-val, got %q", h.Get("X-Added"))
	}
	if h.Get("Existing") != "new-value" {
		t.Errorf("expected Existing=new-value, got %q", h.Get("Existing"))
	}
	if h.Get("ToRemove") != "" {
		t.Errorf("expected ToRemove to be removed, got %q", h.Get("ToRemove"))
	}
}

func TestSetForwardedHeaders_NoTrustList(t *testing.T) {
	// No trusted_proxies configured → always overwrite with peer IP,
	// even if the client presents a forged XFF chain.
	s := &HTTPServer{Listener: &ListenerConfig{}}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.100:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8") // attacker-supplied

	s.setForwardedHeaders(r)

	if got := r.Header.Get("X-Forwarded-For"); got != "192.168.1.100" {
		t.Errorf("untrusted peer: XFF must be replaced, got %q", got)
	}
	if r.Header.Get("X-Real-IP") != "192.168.1.100" {
		t.Errorf("expected X-Real-IP=192.168.1.100, got %q", r.Header.Get("X-Real-IP"))
	}
	if r.Header.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("expected X-Forwarded-Proto=http, got %q", r.Header.Get("X-Forwarded-Proto"))
	}
}

func TestSetForwardedHeaders_UntrustedPeerSpoof(t *testing.T) {
	// Peer 192.168.1.100 is NOT in the trusted list. Their attempt to
	// present a forged XFF chain must be overwritten.
	s := &HTTPServer{Listener: &ListenerConfig{}}
	s.TrustedProxies = acl.ParseCIDRList([]string{"10.0.0.0/8"})

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.100:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "1.2.3.4")

	s.setForwardedHeaders(r)

	if r.Header.Get("X-Forwarded-For") != "192.168.1.100" {
		t.Errorf("untrusted peer must not extend XFF, got %q", r.Header.Get("X-Forwarded-For"))
	}
	if r.Header.Get("X-Real-IP") != "192.168.1.100" {
		t.Errorf("untrusted peer must not keep forged X-Real-IP, got %q", r.Header.Get("X-Real-IP"))
	}
}

func TestSetForwardedHeaders_TrustedPeerChain(t *testing.T) {
	// Peer 10.0.0.2 IS in the trusted list. Its XFF chain is extended.
	s := &HTTPServer{Listener: &ListenerConfig{}}
	s.TrustedProxies = acl.ParseCIDRList([]string{"10.0.0.0/8"})

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("X-Real-IP", "10.0.0.1")

	s.setForwardedHeaders(r)

	if got := r.Header.Get("X-Forwarded-For"); got != "10.0.0.1, 10.0.0.2" {
		t.Errorf("trusted peer: XFF must be extended, got %q", got)
	}
	if got := r.Header.Get("X-Real-IP"); got != "10.0.0.1" {
		t.Errorf("trusted peer: X-Real-IP from proxy must be preserved, got %q", got)
	}
}

func TestSetForwardedHeaders_TrustedPeerBackfill(t *testing.T) {
	// Trusted peer that did NOT send X-Real-IP / X-Forwarded-Proto → we
	// backfill them with authoritative values but still append XFF.
	s := &HTTPServer{Listener: &ListenerConfig{}}
	s.TrustedProxies = acl.ParseCIDRList([]string{"10.0.0.0/8"})

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.2:1234"

	s.setForwardedHeaders(r)

	if r.Header.Get("X-Forwarded-For") != "10.0.0.2" {
		t.Errorf("XFF, got %q", r.Header.Get("X-Forwarded-For"))
	}
	if r.Header.Get("X-Real-IP") != "10.0.0.2" {
		t.Errorf("backfill X-Real-IP, got %q", r.Header.Get("X-Real-IP"))
	}
	if r.Header.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("backfill X-Forwarded-Proto, got %q", r.Header.Get("X-Forwarded-Proto"))
	}
}

func TestExpandRedirectVars(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		reqURL   string
		host     string
		expected string
	}{
		{"host+path", "https://${host}${path}", "/page", "example.com", "https://example.com/page"},
		{"scheme", "${scheme}://${host}/", "/", "example.com", "http://example.com/"},
		{"host with port", "https://${host}${path}", "/x", "example.com:8080", "https://example.com/x"},
		{"port var", "https://${host}:${port}${path}", "/x", "example.com:8080", "https://example.com:8080/x"},
		{"query", "https://${host}${path}?${query}", "/search?q=test", "example.com", "https://example.com/search?q=test"},
		{"no vars", "https://static.example.com/", "/anything", "whatever.com", "https://static.example.com/"},
		{"uri", "https://new.com${uri}", "/path?q=1", "old.com", "https://new.com/path?q=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://"+tt.host+tt.reqURL, nil)
			r.Host = tt.host
			got := expandRedirectVars(tt.url, r)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestApplyRequestHeaders_EmptyConfig(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Keep", "me")

	applyRequestHeaders(r, &config.HeadersConfig{})

	if r.Header.Get("Keep") != "me" {
		t.Error("empty config should not modify existing headers")
	}
}
