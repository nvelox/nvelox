package httpproxy

import (
	"regexp"
	"strconv"
	"strings"

	"nvelox/config"
)

type compiledRoute struct {
	host       string
	pathPrefix string
	pathRegex  *regexp.Regexp
	backend    string
	headers    config.HeadersConfig
	rewrite    config.RewriteConfig
	redirect   config.RedirectConfig
	static     config.StaticConfig
	tryFiles   config.TryFilesConfig
	expires    string
	fastcgi    config.FastCGIConfig
}

// RouteResult contains the result of a route match.
type RouteResult struct {
	Backend      string
	Headers      *config.HeadersConfig
	Rewrite      config.RewriteConfig
	Redirect     config.RedirectConfig
	Static       config.StaticConfig
	TryFiles     config.TryFilesConfig
	Expires      string
	FastCGI      config.FastCGIConfig
	RegexMatches []string // capture groups from regex match
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
		cr := compiledRoute{
			host:       strings.ToLower(r.Match.Host),
			pathPrefix: r.Match.PathPrefix,
			backend:    r.Backend,
			headers:    r.Headers,
			rewrite:    r.Rewrite,
			redirect:   r.Redirect,
			static:     r.Static,
			tryFiles:   r.TryFiles,
			expires:    r.Expires,
			fastcgi:    r.FastCGI,
		}
		if r.Match.PathRegex != "" {
			// Validate regex length to mitigate ReDoS
			if len(r.Match.PathRegex) > 1024 {
				continue // skip overly complex regex
			}
			cr.pathRegex, _ = regexp.Compile(r.Match.PathRegex)
		}
		compiled[i] = cr
	}
	return &Router{
		routes:         compiled,
		defaultBackend: defaultBackend,
	}
}

// Match returns the backend name and optional route-level headers for the given host and path.
// Returns empty string if no route matches and no default backend is set.
func (r *Router) Match(host, path string) (string, *config.HeadersConfig) {
	result := r.MatchFull(host, path)
	if result == nil {
		return r.defaultBackend, nil
	}
	return result.Backend, result.Headers
}

// MatchFull returns the full route result including rewrite/redirect info.
func (r *Router) MatchFull(host, path string) *RouteResult {
	host = strings.ToLower(host)
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	for i := range r.routes {
		route := &r.routes[i]
		hostMatch := route.host == "" || route.host == host

		if !hostMatch {
			continue
		}

		var regexMatches []string

		if route.pathRegex != nil {
			matches := route.pathRegex.FindStringSubmatch(path)
			if matches == nil {
				continue
			}
			regexMatches = matches
		} else if route.pathPrefix != "" {
			if !strings.HasPrefix(path, route.pathPrefix) {
				continue
			}
		}

		return &RouteResult{
			Backend:      route.backend,
			Headers:      &route.headers,
			Rewrite:      route.rewrite,
			Redirect:     route.redirect,
			Static:       route.static,
			TryFiles:     route.tryFiles,
			Expires:      route.expires,
			FastCGI:      route.fastcgi,
			RegexMatches: regexMatches,
		}
	}
	return nil
}

// ApplyRewrite applies regex capture substitution to a rewrite path.
//
// Uses strings.NewReplacer for a single left-to-right pass, so a capture
// value containing literal "$N" can't feed back into a subsequent iteration
// (which the old "for each i, ReplaceAll" approach did — with a URL like
// /foo$2bar/baz against regex ^/(.*)/(.*)$ + rewrite /api/$1/$2, the old
// code produced /api/foobazbar/baz instead of /api/foo$2bar/baz).
//
// Placeholders are registered longest-first ($10 before $1) so double-digit
// captures match before the single-digit prefix swallows them.
func ApplyRewrite(rewritePath string, matches []string) string {
	if len(matches) <= 1 {
		return rewritePath
	}
	// Build pairs: longest placeholder first so "$10" wins over "$1" at the
	// same position. NewReplacer picks the FIRST registered match, not the
	// longest, so registration order matters.
	pairs := make([]string, 0, (len(matches)-1)*2)
	for i := len(matches) - 1; i >= 1; i-- {
		pairs = append(pairs, "$"+strconv.Itoa(i), matches[i])
	}
	return strings.NewReplacer(pairs...).Replace(rewritePath)
}
