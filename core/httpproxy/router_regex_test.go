package httpproxy

import (
	"net/http"
	"strings"
	"testing"

	"nvelox/config"
)

// TestRouter_BadPathRegexNeverMatchesAll: a route whose path_regex does not
// compile, or is longer than the limit, must not turn into a route that
// matches every path — it is left out and the next route decides.
func TestRouter_BadPathRegexNeverMatchesAll(t *testing.T) {
	for name, re := range map[string]string{
		"invalid":   "^/internal/(.*",
		"over-long": "^/" + strings.Repeat("a", 1100),
	} {
		r := NewRouter([]config.RouteConfig{
			{Match: config.RouteMatch{PathRegex: re}, Backend: "internal"},
			{Match: config.RouteMatch{PathPrefix: "/"}, Backend: "web"},
		}, "")
		if res := r.MatchFull("www.example.com", "/home"); res == nil || res.Backend != "web" {
			t.Errorf("%s regex: /home matched %+v, want the catch-all route (backend web)", name, res)
		}
	}

	// Host-scoped over-long regex on a listener with a default backend:
	// requests for other hosts must still reach the default backend's
	// catch-all, not a 503 from an empty route.
	l := &ListenerConfig{Name: "x", Addr: ":0", Protocol: "http", Backend: "web", Routes: []config.RouteConfig{
		{Match: config.RouteMatch{Host: "admin.example.com", PathRegex: "^/" + strings.Repeat("a", 1100)}, Backend: "admin"},
	}}
	s := NewHTTPServer(l, nil, map[string]*config.Backend{}, nil, nil, nil, nil, nil)
	if res := s.router.MatchFull("www.example.com", "/home"); res != nil {
		t.Errorf("www.example.com/home matched route %+v, want no route (default backend)", res)
	}
	if rec := serveRaw(s, "http://www.example.com/home"); rec.Code == http.StatusServiceUnavailable {
		t.Errorf("www.example.com/home: 503 from an empty route")
	}
}
