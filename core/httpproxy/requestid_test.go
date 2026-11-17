package httpproxy

import (
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"nvelox/config"
)

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestGenerateRequestID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := generateRequestID()
		if !hex32.MatchString(id) {
			t.Fatalf("id %q is not 32 lowercase hex chars (must match shared/auth format)", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id generated: %q", id)
		}
		seen[id] = true
	}
}

func TestIsValidRequestID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"0123456789abcdef0123456789abcdef", true}, // bare 32-hex
		{"ABCDEF", true}, // uppercase hex ok
		{"550e8400-e29b-41d4-a716-446655440000", true},         // dashed UUID from a trusted upstream
		{"has space", false},                                   // space
		{"line\nINJECT", false},                                // CRLF / log injection
		{"tab\there", false},                                   // control char
		{"not_hex_g", false},                                   // non-hex letter
		{strings.Repeat("a", maxInboundRequestIDLen), true},    // exactly at the cap, valid hex
		{strings.Repeat("a", maxInboundRequestIDLen+1), false}, // over the length cap
	}
	for _, c := range cases {
		if got := isValidRequestID(c.in); got != c.want {
			t.Errorf("isValidRequestID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func newReq(remoteAddr, inbound string) *http.Request {
	r, _ := http.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = remoteAddr
	if inbound != "" {
		r.Header.Set(requestIDHeader, inbound)
	}
	return r
}

func TestResolveRequestID(t *testing.T) {
	_, trustedNet, _ := net.ParseCIDR("10.9.0.0/16")
	valid := "0123456789abcdef0123456789abcdef"

	t.Run("disabled returns off", func(t *testing.T) {
		s := &HTTPServer{Listener: &ListenerConfig{}}
		if id, on := s.resolveRequestID(newReq("1.2.3.4:5000", valid)); on || id != "" {
			t.Fatalf("disabled listener should return (\"\", false), got (%q, %v)", id, on)
		}
	})

	t.Run("enabled, no inbound, generates", func(t *testing.T) {
		s := &HTTPServer{Listener: &ListenerConfig{RequestID: config.RequestIDConfig{Enabled: true}}}
		id, on := s.resolveRequestID(newReq("1.2.3.4:5000", ""))
		if !on || !hex32.MatchString(id) {
			t.Fatalf("want a freshly generated 32-hex id, got (%q, %v)", id, on)
		}
	})

	t.Run("public edge overwrites an untrusted inbound id", func(t *testing.T) {
		// trust_inbound=false, peer NOT trusted → mint fresh, do not honor client id.
		s := &HTTPServer{Listener: &ListenerConfig{RequestID: config.RequestIDConfig{Enabled: true}}}
		id, on := s.resolveRequestID(newReq("203.0.113.7:5000", valid))
		if !on || id == valid || !hex32.MatchString(id) {
			t.Fatalf("untrusted inbound id must be overwritten with a fresh one, got (%q, %v)", id, on)
		}
	})

	t.Run("public edge honors an inbound id from a trusted proxy peer", func(t *testing.T) {
		s := &HTTPServer{
			Listener:       &ListenerConfig{RequestID: config.RequestIDConfig{Enabled: true}},
			TrustedProxies: []*net.IPNet{trustedNet},
		}
		id, on := s.resolveRequestID(newReq("10.9.1.1:5000", valid))
		if !on || id != valid {
			t.Fatalf("inbound id from a trusted peer should be preserved, got (%q, %v)", id, on)
		}
	})

	t.Run("internal listener with trust_inbound preserves any valid inbound id", func(t *testing.T) {
		s := &HTTPServer{Listener: &ListenerConfig{RequestID: config.RequestIDConfig{Enabled: true, TrustInbound: true}}}
		id, on := s.resolveRequestID(newReq("10.42.0.9:5000", valid))
		if !on || id != valid {
			t.Fatalf("trust_inbound should preserve a valid inbound id from any peer, got (%q, %v)", id, on)
		}
	})

	t.Run("a malformed inbound id is never trusted", func(t *testing.T) {
		s := &HTTPServer{Listener: &ListenerConfig{RequestID: config.RequestIDConfig{Enabled: true, TrustInbound: true}}}
		id, on := s.resolveRequestID(newReq("10.42.0.9:5000", "bad\nid"))
		if !on || !hex32.MatchString(id) {
			t.Fatalf("a malformed inbound id must be replaced with a fresh one even under trust_inbound, got (%q, %v)", id, on)
		}
	})
}
