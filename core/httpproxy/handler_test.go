package httpproxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"nvelox/config"
	"nvelox/core/acl"
	"nvelox/core/logging"
)

func init() {
	// buildBackendTLSConfig logs a warning when Insecure is set; the logger
	// must be initialized or Warn() panics.
	_ = logging.Init("debug", "", "")
}

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

func TestBuildBackendTLSConfig_Default(t *testing.T) {
	tlsCfg, err := buildBackendTLSConfig(config.BackendTLSConfig{Enabled: true})
	if err != nil {
		t.Fatalf("default config should succeed: %v", err)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("default must NOT set InsecureSkipVerify")
	}
	if tlsCfg.RootCAs != nil {
		t.Error("default must use system roots (RootCAs nil)")
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion must be TLS 1.2, got %x", tlsCfg.MinVersion)
	}
}

func TestBuildBackendTLSConfig_Insecure(t *testing.T) {
	// Must only be set when operator explicitly opts in. Used for testing
	// or when talking to backends with self-signed certs where CA pinning
	// is not practical.
	tlsCfg, err := buildBackendTLSConfig(config.BackendTLSConfig{Enabled: true, Insecure: true})
	if err != nil {
		t.Fatalf("insecure config should succeed: %v", err)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("insecure: true must set InsecureSkipVerify")
	}
}

func TestBuildBackendTLSConfig_MTLSBothOrNeither(t *testing.T) {
	// Client cert without client key (or vice versa) must be rejected —
	// silently dropping either half would produce a broken mTLS setup.
	_, err := buildBackendTLSConfig(config.BackendTLSConfig{
		Enabled: true, ClientCert: "/tmp/cert.pem",
	})
	if err == nil {
		t.Error("client_cert without client_key must be rejected")
	}
	_, err = buildBackendTLSConfig(config.BackendTLSConfig{
		Enabled: true, ClientKey: "/tmp/key.pem",
	})
	if err == nil {
		t.Error("client_key without client_cert must be rejected")
	}
}

func TestBuildBackendTLSConfig_BadCACert(t *testing.T) {
	_, err := buildBackendTLSConfig(config.BackendTLSConfig{
		Enabled: true, CACert: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Error("missing ca_cert file must return error")
	}
}

// TestNewHTTPServer_BackendTLSWiring proves that a backend with
// backend_tls.enabled=true gets its own Transport and https scheme,
// while a plaintext backend uses the default transport.
func TestNewHTTPServer_BackendTLSWiring(t *testing.T) {
	backends := map[string]*config.Backend{
		"plain": {Servers: []string{"10.0.0.1:80"}},
		"tls": {
			Servers:    []string{"10.0.0.2:443"},
			BackendTLS: config.BackendTLSConfig{Enabled: true, Insecure: true},
		},
	}
	l := &ListenerConfig{Name: "test", Addr: ":0", Protocol: "http"}
	s := NewHTTPServer(l, nil, backends, nil, nil, nil, nil, nil)

	if _, ok := s.backendTransports["plain"]; ok {
		t.Error("plain backend must NOT have a per-backend transport")
	}
	if _, ok := s.backendTransports["tls"]; !ok {
		t.Error("tls backend must have a per-backend transport")
	}
	if s.backendSchemes["tls"] != "https" {
		t.Errorf("tls backend scheme must be https, got %q", s.backendSchemes["tls"])
	}
}

func TestParseByteSize_Overflow(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"1024", 1024},
		{"10KB", 10 * 1024},
		{"1MB", 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"-5MB", 0},                       // negative → 0
		{"99999999999999999999GB", 0},     // Sscanf fails to parse, n=0
		// Exact overflow: math.MaxInt64 / (1024*1024*1024) ≈ 8_589_934_591
		// so (math.MaxInt64/1GB + 1) GB overflows — must clamp, not wrap negative.
		{"9999999999GB", 9223372036854775807}, // math.MaxInt64
	}
	for _, c := range cases {
		got := parseByteSize(c.in)
		if got != c.want {
			t.Errorf("parseByteSize(%q) = %d, want %d", c.in, got, c.want)
		}
		if got < 0 {
			t.Errorf("parseByteSize(%q) returned negative %d — would disable size limits", c.in, got)
		}
	}
}
