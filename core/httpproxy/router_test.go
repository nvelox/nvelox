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

func TestRouter_RegexMatch(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{PathRegex: `^/api/v(\d+)/(.*)`}, Backend: "api"},
	}, "default")

	result := r.MatchFull("any.com", "/api/v2/users")
	if result == nil {
		t.Fatal("expected match")
	}
	if result.Backend != "api" {
		t.Errorf("expected api, got %s", result.Backend)
	}
	if len(result.RegexMatches) < 3 {
		t.Fatalf("expected 3 captures, got %d", len(result.RegexMatches))
	}
	if result.RegexMatches[1] != "2" {
		t.Errorf("expected capture $1=2, got %s", result.RegexMatches[1])
	}
	if result.RegexMatches[2] != "users" {
		t.Errorf("expected capture $2=users, got %s", result.RegexMatches[2])
	}
}

func TestRouter_RegexNoMatch(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{Match: config.RouteMatch{PathRegex: `^/special/\d+$`}, Backend: "special"},
	}, "default")

	result := r.MatchFull("any.com", "/other/path")
	if result != nil {
		t.Error("expected no match for non-matching regex")
	}
}

func TestRouter_Redirect(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{
			Match:    config.RouteMatch{PathPrefix: "/old"},
			Redirect: config.RedirectConfig{URL: "/new", Code: 301},
		},
	}, "default")

	result := r.MatchFull("any.com", "/old/page")
	if result == nil {
		t.Fatal("expected match")
	}
	if result.Redirect.URL != "/new" {
		t.Errorf("expected redirect to /new, got %s", result.Redirect.URL)
	}
	if result.Redirect.Code != 301 {
		t.Errorf("expected 301, got %d", result.Redirect.Code)
	}
}

func TestRouter_Rewrite(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{
			Match:   config.RouteMatch{PathRegex: `^/api/v(\d+)/(.*)`},
			Backend: "api",
			Rewrite: config.RewriteConfig{Path: "/v$1/$2"},
		},
	}, "default")

	result := r.MatchFull("any.com", "/api/v2/users")
	if result == nil {
		t.Fatal("expected match")
	}
	rewritten := ApplyRewrite(result.Rewrite.Path, result.RegexMatches)
	if rewritten != "/v2/users" {
		t.Errorf("expected /v2/users, got %s", rewritten)
	}
}

func TestApplyRewrite_NoCaptures(t *testing.T) {
	result := ApplyRewrite("/static/path", nil)
	if result != "/static/path" {
		t.Errorf("expected /static/path, got %s", result)
	}
}
