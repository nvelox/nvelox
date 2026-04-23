package httpproxy

import (
	"strings"

	"nvelox/config"
)

type compiledRoute struct {
	host       string
	pathPrefix string
	backend    string
	headers    config.HeadersConfig
}

// Router matches HTTP requests to backends using ordered first-match-wins semantics.
type Router struct {
	routes         []compiledRoute
	defaultBackend string
}

// NewRouter creates a router from config routes and a default backend.
func NewRouter(routes []config.RouteConfig, defaultBackend string) *Router {
	compiled := make([]compiledRoute, len(routes))
	for i, r := range routes {
		compiled[i] = compiledRoute{
			host:       strings.ToLower(r.Match.Host),
			pathPrefix: r.Match.PathPrefix,
			backend:    r.Backend,
			headers:    r.Headers,
		}
	}
	return &Router{
		routes:         compiled,
		defaultBackend: defaultBackend,
	}
}

// Match returns the backend name and optional route-level headers for the given host and path.
// Returns empty string if no route matches and no default backend is set.
func (r *Router) Match(host, path string) (string, *config.HeadersConfig) {
	host = strings.ToLower(host)
	// Strip port from host if present (e.g., "example.com:443" -> "example.com")
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	for i := range r.routes {
		route := &r.routes[i]
		hostMatch := route.host == "" || route.host == host
		pathMatch := route.pathPrefix == "" || strings.HasPrefix(path, route.pathPrefix)
		if hostMatch && pathMatch {
			return route.backend, &route.headers
		}
	}
	return r.defaultBackend, nil
}
