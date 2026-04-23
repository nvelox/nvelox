package httpproxy

import (
	"testing"

	"nvelox/config"
)

func TestRouter_HostMatch(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{Host: "api.example.com"}, Backend: "api"},
		{Match: config.RouteMatch{Host: "web.example.com"}, Backend: "web"},
	}, "default")

	backend, _ := r.Match("api.example.com", "/anything")
	if backend != "api" {
		t.Errorf("expected api, got %s", backend)
	}

	backend, _ = r.Match("web.example.com", "/")
	if backend != "web" {
		t.Errorf("expected web, got %s", backend)
	}
}

func TestRouter_HostCaseInsensitive(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{Host: "API.Example.COM"}, Backend: "api"},
	}, "default")

	backend, _ := r.Match("api.example.com", "/")
	if backend != "api" {
		t.Errorf("expected api, got %s", backend)
	}
}

func TestRouter_HostWithPort(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{Host: "example.com"}, Backend: "web"},
	}, "default")

	backend, _ := r.Match("example.com:443", "/")
	if backend != "web" {
		t.Errorf("expected web, got %s", backend)
	}
}

func TestRouter_PathPrefixMatch(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{PathPrefix: "/api"}, Backend: "api"},
		{Match: config.RouteMatch{PathPrefix: "/static"}, Backend: "cdn"},
	}, "default")

	backend, _ := r.Match("any.host", "/api/users")
	if backend != "api" {
		t.Errorf("expected api, got %s", backend)
	}

	backend, _ = r.Match("any.host", "/static/img.png")
	if backend != "cdn" {
		t.Errorf("expected cdn, got %s", backend)
	}
}

func TestRouter_CombinedMatch(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{Host: "api.example.com", PathPrefix: "/v2"}, Backend: "api-v2"},
		{Match: config.RouteMatch{Host: "api.example.com"}, Backend: "api-v1"},
	}, "default")

	backend, _ := r.Match("api.example.com", "/v2/users")
	if backend != "api-v2" {
		t.Errorf("expected api-v2, got %s", backend)
	}

	backend, _ = r.Match("api.example.com", "/v1/users")
	if backend != "api-v1" {
		t.Errorf("expected api-v1, got %s", backend)
	}
}

func TestRouter_FirstMatchWins(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{PathPrefix: "/api"}, Backend: "first"},
		{Match: config.RouteMatch{PathPrefix: "/api"}, Backend: "second"},
	}, "default")

	backend, _ := r.Match("any", "/api/test")
	if backend != "first" {
		t.Errorf("expected first (first-match-wins), got %s", backend)
	}
}

func TestRouter_FallbackToDefault(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{Host: "specific.com"}, Backend: "specific"},
	}, "fallback")

	backend, _ := r.Match("other.com", "/")
	if backend != "fallback" {
		t.Errorf("expected fallback, got %s", backend)
	}
}

func TestRouter_NoMatchNoDefault(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{Host: "specific.com"}, Backend: "specific"},
	}, "")

	backend, _ := r.Match("other.com", "/")
	if backend != "" {
		t.Errorf("expected empty string, got %s", backend)
	}
}

func TestRouter_RouteHeaders(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{
			Match:   config.RouteMatch{Host: "api.com"},
			Backend: "api",
			Headers: config.HeadersConfig{
				RequestAdd: map[string]string{"X-Route": "api"},
			},
		},
	}, "default")

	_, headers := r.Match("api.com", "/")
	if headers == nil {
		t.Fatal("expected route headers")
	}
	if headers.RequestAdd["X-Route"] != "api" {
		t.Errorf("expected X-Route=api, got %s", headers.RequestAdd["X-Route"])
	}

	// Default backend returns nil headers
	_, headers = r.Match("other.com", "/")
	if headers != nil {
		t.Error("expected nil headers for default backend")
	}
}
