package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"nvelox/config"
	"nvelox/core/acl"
	"nvelox/core/denylist"
	"nvelox/core/httppath"
	"nvelox/core/httpproxy/errorhtml"
	"nvelox/core/logging"
	"nvelox/core/middleware"
	"nvelox/core/sticky"
	"nvelox/core/tlsutil"
	"nvelox/lb"
)

// ConnLimiterI is the interface for connection limiting.
type ConnLimiterI interface {
	Acquire() bool
	Release()
}

// PassiveHealthI is the interface for passive health tracking.
type PassiveHealthI interface {
	RecordFailure(server string)
	RecordSuccess(server string)
}

// CircuitBreakerI is the interface for circuit breakers. Every Allow() that
// returns true is answered by exactly one of RecordSuccess, RecordFailure or
// Release (the attempt ended without a backend outcome), so a half-open
// probe slot is never left taken.
type CircuitBreakerI interface {
	Allow() bool
	RecordSuccess()
	RecordFailure()
	Release()
}

// MetricsI is the interface for metrics recording.
type MetricsI interface {
	GetCounter(name string, labels map[string]string) interface{ Inc() }
	GetHistogram(name string) interface{ Observe(float64) }
	GetGauge(name string, labels map[string]string) interface {
		Inc()
		Dec()
	}
}

// EngineRef provides access to shared engine components without circular imports.
type EngineRef struct {
	Balancers    map[string]lb.Balancer
	Backends     map[string]*config.Backend
	RateLimiters interface{ Allow() bool } // nil if no rate limiter
}

// HTTPServer is the per-site bundle of L7 state: routes, ACL, headers,
// error pages, sticky stores, etc. It does NOT own a listening socket;
// the BindGroup it's attached to does. ServeHTTP is the entry point the
// BindGroup dispatches into.
type HTTPServer struct {
	Listener       *ListenerConfig
	bindGroup      *BindGroup // back-reference; set by Start() for back-compat
	router         *Router
	Balancers      map[string]lb.Balancer
	Backends       map[string]*config.Backend
	RateLimiter    interface{ Allow() bool }
	ConnLimiters   map[string]ConnLimiterI
	PassiveHealth  map[string]PassiveHealthI
	StickyStores   map[string]*sticky.Store
	ACLEngine      *acl.Engine
	IPAllowlist    []*net.IPNet
	IPDenylist     []*net.IPNet
	TrustedProxies []*net.IPNet
	// DynDenylist is the process-wide runtime denylist (TTL-bearing blocks
	// pushed via the admin API). Defaults to denylist.Default in NewHTTPServer;
	// tests may inject their own. nil disables the dynamic check.
	DynDenylist      *denylist.Dynamic
	IPRateLimiter    *middleware.IPRateLimiter
	CircuitBreakers  map[string]CircuitBreakerI
	MaxBodySize      int64 // 0 = unlimited
	Compression      config.CompressionConfig
	ErrorPages       map[int][]byte // status code -> pre-loaded HTML content
	ResponseCache    *Cache
	BufferPool       *BufferPool
	backendTransport *http.Transport // transport of a backend without a config entry
	// plainTransports holds the transports of plaintext backends,
	// backendTransports those of backend_tls backends: a backend_tls backend
	// missing from backendTransports is refused (backendTLSReady), never
	// sent in plaintext.
	plainTransports   map[string]*http.Transport
	backendTransports map[string]*http.Transport
	backendSchemes    map[string]string // "https" when backend_tls is enabled
	altSvcHeader      string
	closeOnce         sync.Once // guards Close() against double-invocation

	// Upgraded (WebSocket) connections relayed through this site, in the
	// bind group's shared set, and the group's reload generation this site
	// instance belongs to (see tunnel.go).
	tunnelsMu sync.Mutex
	tunnels   *tunnelSet
	tunnelGen uint64
}

// ListenerConfig mirrors core.ListenerConfig to avoid circular imports.
type ListenerConfig struct {
	Name           string
	Addr           string
	Protocol       string
	Backend        string
	Port           int
	TLS            *config.TLSConfig
	HTTP3          bool
	Routes         []config.RouteConfig
	Headers        config.HeadersConfig
	IPAllowlist    []string
	IPDenylist     []string
	MaxBodySize    string
	IPRateLimit    config.IPRateLimitConfig
	ACL            []config.ACLRule
	TrustedProxies []string
	Compression    config.CompressionConfig
	ErrorPages     map[int]string
	Buffering      config.BufferingConfig
	Cache          config.CacheConfig
	RequestID      config.RequestIDConfig
	// Multi-server-per-port (nginx-style): SNI / Host names this site
	// answers to, and whether it's the catch-all default for unknown SNI/Host.
	ServerNames   []string
	DefaultServer bool
	// Per-listener timeouts. ReadHeader / Idle are shared across sites on the
	// same bind port (the http.Server has one slot each); the engine derives
	// the per-port value as the max across sites. Read / Write are applied
	// per-request in BindGroup.ServeHTTP via http.ResponseController and so
	// can differ between sites sharing the same bind.
	Timeouts config.TimeoutConfig
	// ClientAuth is the site's parsed client-certificate policy (from
	// TLS.ClientAuth / ClientCA), nil when off. The engine parses it once;
	// a BindGroup loads it from TLS itself when a caller left it nil.
	ClientAuth *tlsutil.ClientAuth
}

// NewHTTPServer creates an HTTP server for the given listener.
func NewHTTPServer(l *ListenerConfig, balancers map[string]lb.Balancer, backends map[string]*config.Backend, rateLimiter interface{ Allow() bool }, connLimiters map[string]ConnLimiterI, passiveHealth map[string]PassiveHealthI, stickyStores map[string]*sticky.Store, circuitBreakers map[string]CircuitBreakerI) *HTTPServer {
	s := &HTTPServer{
		Listener:        l,
		router:          NewRouter(l.Routes, l.Backend),
		Balancers:       balancers,
		Backends:        backends,
		ConnLimiters:    connLimiters,
		PassiveHealth:   passiveHealth,
		StickyStores:    stickyStores,
		CircuitBreakers: circuitBreakers,
		IPAllowlist:     acl.ParseIPMatchList(l.IPAllowlist),
		IPDenylist:      acl.ParseIPMatchList(l.IPDenylist),
		TrustedProxies:  acl.ParseCIDRList(l.TrustedProxies),
		DynDenylist:     denylist.Default,
		MaxBodySize:     parseByteSize(l.MaxBodySize),
		RateLimiter:     rateLimiter,
	}

	s.Compression = l.Compression

	// Initialize buffer pool
	if l.Buffering.ResponseBuffer != "" {
		bufSize := parseByteSize(l.Buffering.ResponseBuffer)
		if bufSize > 0 {
			s.BufferPool = NewBufferPool(int(bufSize))
		}
	}

	// Initialize response cache
	if l.Cache.Enabled {
		maxSize := parseByteSize(l.Cache.MaxSize)
		ttl := 5 * time.Minute
		if l.Cache.DefaultTTL != "" {
			if d, err := time.ParseDuration(l.Cache.DefaultTTL); err == nil {
				ttl = d
			}
		}
		s.ResponseCache = NewCache(maxSize, ttl, l.Cache.Methods)
	}

	// Load error pages
	if len(l.ErrorPages) > 0 {
		s.ErrorPages = make(map[int][]byte)
		for code, path := range l.ErrorPages {
			data, err := os.ReadFile(path)
			if err != nil {
				logging.Error("[HTTP] Failed to load error page for %d from %s: %v", code, path, err)
				continue
			}
			s.ErrorPages[code] = data
		}
	}

	if len(l.ACL) > 0 {
		s.ACLEngine = acl.NewEngine(l.ACL)
	}
	if l.IPRateLimit.RequestsPerSecond > 0 {
		s.IPRateLimiter = middleware.NewIPRateLimiter(l.IPRateLimit.RequestsPerSecond, l.IPRateLimit.Burst)
	}

	// Backend transports, with connection pooling. Each backend gets its own,
	// carrying its dial and response-header timeouts (backendTimeouts);
	// backendTransport serves a backend without a config entry. WebSocket
	// upgrades go through the same transports.
	s.backendTransport = newBackendTransport(l, nil, nil)
	s.plainTransports = make(map[string]*http.Transport)

	// Per-backend TLS transports: a backend with backend_tls.enabled=true gets
	// its own Transport with a TLSClientConfig built from the backend config.
	// The engine refuses to start / reload when one cannot be built; should it
	// still fail here (a file changed in between) the backend gets NO
	// transport and every request to it is answered 502 — never plaintext.
	// WebSocket upgrades go through the same Transport (HTTP/1.1, no ALPN,
	// ServerName from the target), so they get the same verification.
	s.backendTransports = make(map[string]*http.Transport)
	s.backendSchemes = make(map[string]string)
	for name, be := range backends {
		if be == nil {
			continue
		}
		if !be.BackendTLS.Enabled {
			s.plainTransports[name] = newBackendTransport(l, be, nil)
			continue
		}
		tlsCfg, err := buildBackendTLSConfig(be.BackendTLS)
		if err != nil {
			logging.Error("[HTTP] backend %q: backend_tls invalid: %v — requests to it fail with 502 (never sent in plaintext)", name, err)
			continue
		}
		s.backendTransports[name] = newBackendTransport(l, be, tlsCfg)
		s.backendSchemes[name] = "https"
	}

	// http.Server / TLS / HTTP/3 setup now lives on BindGroup. Site is
	// just the handler from here on.
	return s
}

// Timeouts of an HTTP backend that sets none (nor its listener, for connect).
const (
	defaultBackendConnect        = 10 * time.Second
	defaultBackendResponseHeader = 60 * time.Second
)

// backendTimeouts returns backend be's dial and response-header timeouts on
// listener l: the backend's own timeouts.connect / timeouts.response_header,
// else the listener's timeouts.connect, else the defaults. 0 means no limit.
// be and l may be nil.
func backendTimeouts(l *ListenerConfig, be *config.Backend) (connect, responseHeader time.Duration) {
	connect, responseHeader = defaultBackendConnect, defaultBackendResponseHeader
	if l != nil && l.Timeouts.Connect != "" {
		connect = l.Timeouts.ParseConnect()
	}
	if be != nil {
		if be.Timeouts.Connect != "" {
			connect = be.Timeouts.ParseConnect()
		}
		responseHeader = be.Timeouts.ResolveResponseHeader(defaultBackendResponseHeader)
	}
	return max(connect, 0), max(responseHeader, 0)
}

// newBackendTransport builds the transport to backend be (nil: a backend
// without a config entry) of listener l; tlsCfg is its backend_tls config
// (nil: plaintext). A backend that does not start answering within the
// response-header timeout fails the attempt with a timeout (answered 504).
func newBackendTransport(l *ListenerConfig, be *config.Backend, tlsCfg *tls.Config) *http.Transport {
	connect, responseHeader := backendTimeouts(l, be)
	dialer := &net.Dialer{Timeout: connect, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		TLSClientConfig:       tlsCfg,
		ResponseHeaderTimeout: responseHeader,
		DisableCompression:    true, // we handle compression ourselves
		ForceAttemptHTTP2:     true,
	}
}

// parseByteSize parses human-readable byte sizes ("10MB", "512KB") into bytes.
// Returns 0 for invalid/empty input and clamps n*multiplier to math.MaxInt64
// on overflow — prevents an attacker-supplied config like "99999GB" from
// wrapping to a negative int64 which http.MaxBytesReader would treat as "no limit".
func parseByteSize(s string) int64 {
	if s == "" {
		return 0
	}
	s = strings.TrimSpace(strings.ToUpper(s))
	multiplier := int64(1)
	if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	} else if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	} else if strings.HasSuffix(s, "B") {
		s = strings.TrimSuffix(s, "B")
	}
	n := int64(0)
	fmt.Sscanf(s, "%d", &n)
	if n < 0 {
		return 0 // negative input is invalid, treat as 0
	}
	// Overflow guard: if n*multiplier would exceed int64, return MaxInt64.
	if multiplier > 0 && n > math.MaxInt64/multiplier {
		return math.MaxInt64
	}
	return n * multiplier
}

// tryFilesFallback points r at a try_files fallback target: the target is
// split at its first '?' into path and query (a target without '?' keeps the
// request's query) and the new path goes through the listener ACL again. The
// caller serves it from the same route or routes it again. A target path
// with a "." or ".." segment, a backslash or a NUL is refused with 400.
// Returns false when the request has been answered.
func (s *HTTPServer) tryFilesFallback(w http.ResponseWriter, r *http.Request, target, clientIP string) bool {
	p, query, hasQuery := strings.Cut(target, "?")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if unsafeTargetPath(p) {
		logging.Warn("[HTTP] Refusing try_files target %q", logging.SanitizeLogField(target))
		s.serveError(w, http.StatusBadRequest)
		return false
	}
	if hasQuery {
		r.URL.RawQuery = query
	}
	return s.rewriteRequestPath(w, r, p, clientIP)
}

// rewriteRequestPath points r at a new path chosen inside nvelox (a
// try_files target, a directory index script) and runs the listener ACL on
// it, as on the original path. Returns false when a deny rule answered.
func (s *HTTPServer) rewriteRequestPath(w http.ResponseWriter, r *http.Request, p, clientIP string) bool {
	r.URL.Path, r.URL.RawPath = p, ""
	if s.ACLEngine == nil {
		return true
	}
	action, status := s.ACLEngine.DecideClientIP(r, net.ParseIP(clientIP))
	if action != "deny" {
		return true
	}
	if status == 0 {
		status = http.StatusForbidden
	}
	s.serveError(w, status)
	return false
}

// warnIfKeyWorldReadable logs a WARN if a private-key file on disk has
// group or world permission bits set. Operators in containerized setups
// sometimes can't change perms, so we log rather than refuse the load.
func warnIfKeyWorldReadable(keyPath string) {
	if keyPath == "" {
		return
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		return
	}
	if fi.Mode().Perm()&0o077 != 0 {
		logging.Warn("[TLS] Private key %q has overly permissive mode %o — recommend 0600",
			keyPath, fi.Mode().Perm())
	}
}

// BuildBackendTLSConfig builds a backend_tls client config; the engine calls
// it at startup and reload pre-flight so a broken one aborts them.
func BuildBackendTLSConfig(cfg config.BackendTLSConfig) (*tls.Config, error) {
	return buildBackendTLSConfig(cfg)
}

// buildBackendTLSConfig turns a BackendTLSConfig into a *tls.Config suitable
// for use as Transport.TLSClientConfig.
//
// Security defaults: InsecureSkipVerify is OFF unless the operator explicitly
// sets backend_tls.insecure: true (the engine logs a warning per such backend
// at startup and reload). System CA pool is used when no ca_cert is
// provided. Client cert/key are both required if either is set (mTLS).
func buildBackendTLSConfig(cfg config.BackendTLSConfig) (*tls.Config, error) {
	t := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.Insecure {
		t.InsecureSkipVerify = true
	} else if cfg.CACert != "" {
		pem, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_cert %q: no certificates parsed", cfg.CACert)
		}
		t.RootCAs = pool
	}
	// If neither Insecure nor CACert are set, Go's default (system roots) is used.

	// mTLS client cert: both files must be present together.
	if (cfg.ClientCert != "") != (cfg.ClientKey != "") {
		return nil, fmt.Errorf("backend_tls: client_cert and client_key must both be set for mTLS")
	}
	if cfg.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		t.Certificates = []tls.Certificate{cert}
	}

	return t, nil
}

// Start is a back-compat shortcut: build a one-site BindGroup, attach this
// HTTPServer, and start the group. New code should construct a BindGroup
// directly so multiple sites can share the socket.
func (s *HTTPServer) Start() error {
	g := NewBindGroup(s.Listener.Addr, s.Listener.Protocol)
	g.AddSite(s)
	if err := g.Start(); err != nil {
		return err
	}
	s.bindGroup = g
	return nil
}

// Stop gracefully shuts down the BindGroup this site was attached to via
// Start(). If the site was attached to a multi-site group externally, the
// caller should Stop the group, not the site.
func (s *HTTPServer) Stop(ctx context.Context) error {
	if s.bindGroup != nil {
		return s.bindGroup.Stop(ctx)
	}
	return nil
}

// Close stops every per-site background goroutine (response cache cleanup
// loop, per-IP rate limiter cleanup loop). Called by BindGroup.ReplaceSites
// for every site instance a SIGHUP reload replaces, and by BindGroup.Stop.
//
// Idempotent (sync.Once) — the underlying Cache.Stop / IPRateLimiter.Stop
// close their stopCh channels, which would panic on second close.
//
// In-flight plain requests in the site's handlers complete normally;
// stopping these tickers only disables background pruning. Upgraded
// (WebSocket) connections keep running until they end or go idle
// (timeouts.idle); BindGroup.Stop closes them.
func (s *HTTPServer) Close() {
	s.closeOnce.Do(func() {
		if s.ResponseCache != nil {
			s.ResponseCache.Stop()
		}
		if s.IPRateLimiter != nil {
			s.IPRateLimiter.Stop()
		}
	})
}

// ServeHTTP handles incoming HTTP requests with routing, proxying, and header manipulation.
//
// Every request gets exactly one access-log line, written when ServeHTTP
// returns (for an upgraded WebSocket connection: when the tunnel closes),
// with the status the client was actually sent — denials, rate limits,
// redirects, cache hits and proxy errors included.
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	serverW := w // http.MaxBytesReader needs the server's own writer (it closes the connection after a 413)
	// The listener's read and write limits: how long the client may stall
	// sending its body or taking the response (stall.go). Deferred first, so
	// that finish runs last, after every write of the handler.
	if lim := newStallLimits(w, r, s.Listener); lim != nil {
		defer lim.finish()
		w = lim.writer(w)
		r.Body = lim.wrapBody(r.Body)
	}
	rec := &statusRecorder{ResponseWriter: w}
	w = rec

	// Every decision below (IP lists, ACL, routing) matches the decoded path
	// in canonical form (dot segments resolved, duplicate slashes merged;
	// see httppath.Canonical) — the conservative view: decoding "%2F" can
	// only add separators. When canonicalizing changed the path, the
	// upstream request gets the canonical path (re-encoded), so the backend
	// acts on exactly the path that was checked; otherwise it gets the path
	// as the client encoded it ("/repo/a%2Fb" keeps its "%2F").
	if p := httppath.Canonical(r.URL.Path); strings.HasPrefix(p, "/") && p != r.URL.Path {
		r.URL.Path, r.URL.RawPath = p, ""
	}
	// The access log shows the path the decisions saw, escaped: one spelling
	// per path whatever the client's encoding ("/%2Eenv" is "/.env").
	logPath := (&url.URL{Path: r.URL.Path}).EscapedPath()

	// Security headers on all responses
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Advertise HTTP/3 if enabled
	if s.altSvcHeader != "" {
		w.Header().Set("Alt-Svc", s.altSvcHeader)
	}

	// Correlation id (opt-in per listener via request_id). Resolved BEFORE any
	// gate or early return so the id is echoed on every response (including the
	// error / redirect / static and WebSocket paths) and is available for both
	// the upstream request and the access log. When enabled and the inbound id
	// isn't trusted, a fresh id is minted here — making this gateway the
	// recorded origin of the trace. See resolveRequestID for the trust policy.
	reqID, reqIDOn := s.resolveRequestID(r)
	if reqIDOn {
		r.Header.Set(requestIDHeader, reqID)   // for FastCGI; the proxy path sets it again on the upstream request
		w.Header().Set(requestIDHeader, reqID) // echo to the client
	}

	// Resolve the real client IP once: behind a trusted proxy this is the
	// origin client recovered from X-Forwarded-For; otherwise it's the
	// connection peer. Reused below for the allow/deny lists, the per-IP
	// rate limiter, the ACL engine and the access log so every decision
	// reflects the real client rather than the upstream proxy's address.
	clientIP := s.realClientIP(r)

	// Browser Fetch Metadata and User-Agent as the client sent them — read
	// before any configured request-header rewrite can drop them — for the
	// access log.
	fetchSite, fetchDest := r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Sec-Fetch-Dest")
	userAgent := r.UserAgent()

	// upstream is the backend server of the last proxy attempt ("" when the
	// request was answered without one).
	var upstream string
	defer func() {
		duration := float64(time.Since(start).Microseconds()) / 1000.0
		logging.AccessHTTP(clientIP, r.Host, r.Method, logPath, r.Proto, rec.statusForLog(), rec.bytesForLog(), duration, upstream, userAgent,
			fetchSite, fetchDest, r.TLS != nil, reqID, s.Listener.Name)
	}()

	// ip_denylist, the dynamic denylist, ip_allowlist.
	if status := s.clientStatus(clientIP); status != 0 {
		s.serveError(w, status)
		return
	}

	// Per-listener rate limiting
	if s.RateLimiter != nil {
		if !s.RateLimiter.Allow() {
			s.serveError(w, http.StatusTooManyRequests)
			return
		}
	}

	// Per-IP rate limiting
	if s.IPRateLimiter != nil {
		if !s.IPRateLimiter.Allow(clientIP) {
			s.serveError(w, http.StatusTooManyRequests)
			return
		}
	}

	if status := s.aclStatus(r, clientIP); status != 0 {
		s.serveError(w, status)
		return
	}

	// CONNECT asks for a tunnel to an arbitrary host: this is a reverse
	// proxy, not a forward proxy. (It used to reach ReverseProxy, fail there
	// and be counted against the backend's health.)
	if r.Method == http.MethodConnect {
		s.serveError(w, http.StatusMethodNotAllowed)
		return
	}

	// Request body size limit
	if s.MaxBodySize > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(serverW, r.Body, s.MaxBodySize)
	}

	// Cache lookup. The key is taken here, from the requested path, and the
	// same key stores the response, so a route rewrite cannot file one
	// path's response under another path. WebSocket upgrades bypass the
	// cache (and compression).
	upgrade := isWebSocketUpgrade(r)
	var admitted *http.Request
	if upgrade {
		// The upgrade request as the access rules above saw it: while the
		// tunnel lasts, a reload runs the rules again on it.
		admitted = r.Clone(context.Background())
	}
	cacheKey := ""
	if !upgrade && s.ResponseCache != nil && s.ResponseCache.ShouldCache(r.Method) && !ShouldSkipCache(r) {
		if k := CacheKey(r); len(k) <= maxCacheKeyLen {
			cacheKey = k
			if entry := s.ResponseCache.Get(k); entry != nil {
				s.serveCached(w, r, entry)
				return
			}
		}
	}

	// Route matching
	routeResult := s.router.MatchFull(r.Host, r.URL.Path)
	matched := routeResult // what a reload compares a tunnel's route with
	var backendName string
	var routeHeaders *config.HeadersConfig
	// A try_files fallback the route cannot serve itself is an internal
	// redirect (nginx semantics): the ACL and the router run again on the
	// new path and dispatch restarts here, once — the route it lands on
	// serves the target without try_files.
	tryFilesRedirected := false
	rerouted := false // try_files moved the request (see tunnelAdmission)
dispatch:
	if routeResult != nil {
		backendName = routeResult.Backend
		routeHeaders = routeResult.Headers

		// Handle redirect with variable substitution
		if routeResult.Redirect.URL != "" {
			code := routeResult.Redirect.Code
			if code == 0 {
				code = 302
			}
			redirectURL := expandRedirectVars(routeResult.Redirect.URL, r)
			if len(routeResult.RegexMatches) > 0 {
				redirectURL = ApplyRewrite(redirectURL, routeResult.RegexMatches)
			}
			http.Redirect(w, r, redirectURL, code)
			return
		}

		// Handle static file serving
		if routeResult.Static.Root != "" {
			// try_files: a candidate that exists is served by this route,
			// and so is the fallback when this route's root has it (a file,
			// or a directory with an index; a script only where this route
			// runs FastCGI), as before v1.2.0: an SPA's fallback "/" is its
			// own index even where "/" itself routes elsewhere. Any other
			// fallback is an internal redirect (e.g. /index.php reaches the
			// FastCGI route).
			if len(routeResult.TryFiles.Files) > 0 && !tryFilesRedirected {
				target, isFallback := TryFiles(routeResult.Static.Root, r, routeResult.TryFiles.Files, routeResult.TryFiles.Fallback)
				switch {
				case isFallback && strings.HasPrefix(target, "="):
					// Status fallback (e.g. "=404")
					code := 404
					fmt.Sscanf(target[1:], "%d", &code)
					s.serveError(w, code)
					return
				case isFallback:
					if !s.tryFilesFallback(w, r, target, clientIP) {
						return
					}
					rerouted = true
					if _, ok := NewStaticHandler(routeResult.Static).Resolve(r.URL.Path, routeResult.FastCGI.Pass != ""); !ok {
						routeResult = s.router.MatchFull(r.Host, r.URL.Path)
						tryFilesRedirected = true
						goto dispatch
					}
				case target != "" && target != r.URL.Path:
					if !s.rewriteRequestPath(w, r, target, clientIP) {
						return
					}
					rerouted = true
				}
			}

			// A script (.php, .phtml, .phar) is never served as a file. On a
			// route with FastCGI it runs there — a directory index script
			// under its own path; otherwise it counts as missing.
			handler := NewStaticHandler(routeResult.Static)
			f, found := handler.Resolve(r.URL.Path, routeResult.FastCGI.Pass != "")
			switch {
			case found && !f.script:
				handler.Serve(newExpiresWriter(w, routeResult.Expires), r, f)
				return
			case found:
				if f.urlPath != r.URL.Path && !s.rewriteRequestPath(w, r, f.urlPath, clientIP) {
					return
				}
				// Falls through to the FastCGI block below.
			case backendName == "" && routeResult.FastCGI.Pass == "":
				// File not found — no backend or FastCGI to fall through to.
				s.serveError(w, http.StatusNotFound)
				return
			}
		}

		// Handle FastCGI (PHP-FPM) forwarding.
		//
		// Set the standard forwarding headers before dispatch so PHP sees
		// the same X-Forwarded-For / X-Real-IP / X-Forwarded-Proto values
		// the reverse-proxy path would inject. Without this, scripts that
		// rely on $_SERVER['HTTP_X_FORWARDED_FOR'] (rate-limiting,
		// geolocation, audit logs) see "(none)" even though nvelox knows
		// the real client IP. The listener and route request-header rules
		// apply exactly as they do to proxied requests.
		if routeResult.FastCGI.Pass != "" {
			s.setForwardedHeaders(r)
			applyRequestHeaders(r, &s.Listener.Headers)
			if routeHeaders != nil {
				applyRequestHeaders(r, routeHeaders)
			}
			ServeFastCGI(newExpiresWriter(w, routeResult.Expires), r, routeResult.FastCGI, s.serveError)
			return
		}

		// Handle rewrite
		if routeResult.Rewrite.Path != "" {
			newPath := routeResult.Rewrite.Path
			if len(routeResult.RegexMatches) > 0 {
				newPath = ApplyRewrite(newPath, routeResult.RegexMatches)
			}
			r.URL.Path = newPath
		}

		// The route's expires lands on the backend's response once its
		// status is known: cacheable statuses only, never over the
		// backend's own Cache-Control / Expires (see applyExpires).
		w = newExpiresWriter(w, routeResult.Expires)
	} else {
		backendName = s.router.defaultBackend
	}

	if backendName == "" {
		s.serveError(w, http.StatusServiceUnavailable)
		return
	}

	balancer, ok := s.Balancers[backendName]
	if !ok {
		s.serveError(w, http.StatusBadGateway)
		return
	}

	backend := s.Backends[backendName]

	// Connection limit check
	if cl, ok := s.ConnLimiters[backendName]; ok {
		if !cl.Acquire() {
			s.serveError(w, http.StatusServiceUnavailable)
			return
		}
		defer cl.Release()
	}

	// backend_tls fails closed: a backend configured for TLS whose TLS
	// transport could not be built is answered 502, never proxied in
	// plaintext (HTTP and WebSocket alike).
	if !s.backendTLSReady(backendName, backend) {
		s.serveError(w, http.StatusBadGateway)
		return
	}

	u := &upstreamRequest{
		backendName:  backendName,
		backend:      backend,
		balancer:     balancer,
		route:        routeResult,
		routeHeaders: routeHeaders,
		reqID:        reqID,
		reqIDOn:      reqIDOn,
		cacheKey:     cacheKey,
		upgrade:      upgrade,
	}
	if upgrade {
		u.admission = &tunnelAdmission{req: admitted, route: matched, backend: backendName,
			scheme: s.backendScheme(backendName), rerouted: rerouted}
		u.clientIP = net.ParseIP(clientIP)
	}
	s.proxy(w, r, rec, u, &upstream)
}

// clientStatus applies the client checks, in order: ip_denylist, the dynamic
// denylist (TTL-bearing blocks pushed via the admin API, e.g. by an abuse
// detector; process-global, so it survives SIGHUP config reloads) and
// ip_allowlist (if set, only listed clients). It returns the refusal status,
// or 0 when clientIP may pass. ServeHTTP runs it on every request, a reload
// on every open tunnel.
func (s *HTTPServer) clientStatus(clientIP string) int {
	if len(s.IPDenylist) > 0 && acl.CheckIPList(clientIP, s.IPDenylist) {
		return http.StatusForbidden
	}
	if s.DynDenylist != nil {
		if ip := net.ParseIP(clientIP); ip != nil && s.DynDenylist.Blocked(ip) {
			return http.StatusForbidden
		}
	}
	if len(s.IPAllowlist) > 0 && !acl.CheckIPList(clientIP, s.IPAllowlist) {
		return http.StatusForbidden
	}
	return 0
}

// aclStatus is the ACL's refusal status for r from clientIP, 0 when the ACL
// lets it through. A deny may carry a custom status (e.g. 404 to hide an
// admin surface from unauthorized clients); default to 403 when unset.
func (s *HTTPServer) aclStatus(r *http.Request, clientIP string) int {
	if s.ACLEngine == nil {
		return 0
	}
	action, status := s.ACLEngine.DecideClientIP(r, net.ParseIP(clientIP))
	if action != "deny" {
		return 0
	}
	if status == 0 {
		status = http.StatusForbidden
	}
	return status
}

// tunnelRefusal says why s would not admit the upgrade request of a tunnel
// admitted with a ("" = it would), and returns the client s resolves for it.
// It applies what a new request meets — the client checks and the ACL, not
// the rate limits, which meter new requests — and requires the same route
// to the same backend, which still lists the tunnel's server and reaches it
// over the same transport.
func (s *HTTPServer) tunnelRefusal(a *tunnelAdmission) (string, net.IP) {
	clientIP := s.realClientIP(a.req)
	if s.clientStatus(clientIP) != 0 {
		return "its client is refused (ip_denylist, denylist or ip_allowlist)", nil
	}
	if s.aclStatus(a.req, clientIP) != 0 {
		return "the ACL refuses its request", nil
	}
	route := s.router.MatchFull(a.req.Host, a.req.URL.Path)
	if !reflect.DeepEqual(route, a.route) {
		return "its route changed", nil
	}
	backendName := s.router.defaultBackend
	if route != nil {
		backendName = route.Backend
	}
	if backendName != a.backend {
		return "its backend changed", nil
	}
	balancer, ok := s.Balancers[backendName]
	if !ok || !slices.Contains(balancer.Servers(), a.target) {
		return "its server left the backend", nil
	}
	if !s.backendTLSReady(backendName, s.Backends[backendName]) || s.backendScheme(backendName) != a.scheme {
		return "its backend's transport changed", nil
	}
	return "", net.ParseIP(clientIP)
}

// backendScheme is the scheme of requests to backendName: its backend_tls
// transport's ("https"), else "http".
func (s *HTTPServer) backendScheme(backendName string) string {
	if _, ok := s.backendTransports[backendName]; ok {
		return s.backendSchemes[backendName]
	}
	return "http"
}

// backendTLSReady reports whether a request may be proxied to backendName:
// true unless the backend has backend_tls enabled and this site holds no TLS
// transport for it (its config failed to build, or the backend was switched
// to TLS by a reload that has not reached this site yet).
func (s *HTTPServer) backendTLSReady(backendName string, backend *config.Backend) bool {
	if backend == nil || !backend.BackendTLS.Enabled {
		return true
	}
	if _, ok := s.backendTransports[backendName]; ok {
		return true
	}
	logging.Error("[HTTP] backend %q: backend_tls is enabled but no TLS transport is available — refusing to proxy in plaintext", backendName)
	return false
}

// statusClientClosedRequest is logged when the client went away before any
// response could be sent (nginx's 499); nothing is written to the client.
const statusClientClosedRequest = 499

// statusRecorder sits at the top of every response's writer chain. It
// records the status and body bytes the client was sent, for the access log,
// and owns the client side of a WebSocket upgrade: Hijack is only possible
// once the proxy armed it (onHijack), after which the connection is tracked
// as a tunnel of the site.
type statusRecorder struct {
	http.ResponseWriter
	status int   // final status written, 0 until then
	bytes  int64 // body bytes written
	// logStatus is logged when nothing was written (the client went away).
	logStatus int
	// closeUnlessSwitching adds "Connection: close" to a final response
	// other than 101: the client of a failed upgrade must not have what it
	// sent after the upgrade request read as its next request.
	closeUnlessSwitching bool
	onHijack             func(net.Conn) *tunnelConn
	tunnel               *tunnelConn
}

func (r *statusRecorder) WriteHeader(code int) {
	// 1xx informational responses (100 Continue, 103 Early Hints) precede
	// the response; they are passed on and not recorded.
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		r.ResponseWriter.WriteHeader(code)
		return
	}
	if r.status == 0 {
		r.status = code
		if r.closeUnlessSwitching && code != http.StatusSwitchingProtocols {
			r.Header().Set("Connection", "close")
		}
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// ReadFrom keeps the server's sendfile path for static files.
func (r *statusRecorder) ReadFrom(src io.Reader) (int64, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	var n int64
	var err error
	if rf, ok := r.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(src)
	} else {
		n, err = io.Copy(struct{ io.Writer }{r.ResponseWriter}, src)
	}
	r.bytes += n
	return n, err
}

// Hijack hands the client connection to the WebSocket relay. Only the
// upgrade path arms it (ReverseProxy hijacks only after the backend answered
// 101 with the requested protocol); anything else gets an error.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if r.onHijack == nil {
		return nil, nil, errors.New("httpproxy: hijack not supported")
	}
	conn, brw, err := http.NewResponseController(r.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	r.status = http.StatusSwitchingProtocols
	r.tunnel = r.onHijack(conn)
	return r.tunnel, brw, nil
}

// Flush supports streaming responses.
func (r *statusRecorder) Flush() {
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the server's writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// statusForLog is the status the client was sent; 200 when the handler wrote
// nothing (net/http then sends an empty 200), unless logStatus says why
// nothing was sent.
func (r *statusRecorder) statusForLog() int {
	switch {
	case r.status != 0:
		return r.status
	case r.logStatus != 0:
		return r.logStatus
	default:
		return http.StatusOK
	}
}

// bytesForLog is the body bytes sent, plus the tunnel's bytes towards the
// client for an upgraded connection.
func (r *statusRecorder) bytesForLog() int64 {
	if r.tunnel != nil {
		return r.bytes + r.tunnel.written.Load()
	}
	return r.bytes
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade: a GET
// (RFC 6455 section 4.1) with Upgrade: websocket and Connection: upgrade.
// Only such a request may switch protocols; any other Upgrade (h2c, ...) is
// stripped before the request goes upstream.
func isWebSocketUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// switchesToWebSocket reports whether a 101 response switches to WebSocket.
func switchesToWebSocket(h http.Header) bool {
	return strings.EqualFold(h.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(strings.Join(h.Values("Connection"), ",")), "upgrade")
}

// untrustedForwardingHeaders claim something about the client or the
// original request (its address, host, port, scheme or path) on behalf of a
// proxy in front of nvelox. From a peer that is not a trusted proxy they are
// forged by definition and removed; X-Forwarded-For, X-Real-IP and
// X-Forwarded-Proto are replaced with the values nvelox knows. A trusted
// proxy's are kept.
var untrustedForwardingHeaders = []string{
	"Forwarded",
	"X-Forwarded-Host",
	"X-Forwarded-Port",
	"X-Forwarded-Server",
	"X-Forwarded-Prefix",
	"X-Forwarded-Scheme",
	"X-Forwarded-Ssl",
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Client-IP",
	"True-Client-IP",
	"CF-Connecting-IP",
	"Fastly-Client-IP",
	"X-Cluster-Client-IP",
}

// setForwardedHeaders adds standard proxy headers to r in place (the
// FastCGI path; the reverse-proxy path applies the same rules to the
// upstream request, see applyForwardedHeaders).
//
// XFF spoofing defense: if TrustedProxies is configured and the direct peer
// is in it, the client-provided XFF/X-Real-IP/X-Forwarded-Proto are trusted
// and the peer IP is appended. If the peer is NOT in the trust list (or the
// list is empty), the headers are *replaced* with authoritative values —
// preventing a direct client from spoofing its source IP via a forged XFF —
// and the other forwarding headers (untrustedForwardingHeaders) are removed.
func (s *HTTPServer) setForwardedHeaders(r *http.Request) {
	s.applyForwardedHeaders(r.Header, r)
}

// applyForwardedHeaders sets the forwarding headers for the inbound request
// in on dst (in.Header itself, or the upstream request's headers). Every
// X-Forwarded-For line the trusted peer sent is kept, joined in order.
func (s *HTTPServer) applyForwardedHeaders(dst http.Header, in *http.Request) {
	peer := peerHost(in.RemoteAddr)
	proto := "http"
	if in.TLS != nil {
		proto = "https"
	}

	if s.ipTrusted(net.ParseIP(peer)) {
		// Read everything from in before writing dst: they may be the same.
		chain := strings.Join(in.Header.Values("X-Forwarded-For"), ", ")
		realIP := in.Header.Get("X-Real-IP")
		fwdProto := in.Header.Get("X-Forwarded-Proto")
		forwarded := in.Header.Values("Forwarded")
		fwdHost := in.Header.Values("X-Forwarded-Host")

		// Peer is a trusted proxy: extend its XFF chain and trust its claims.
		if chain != "" {
			dst.Set("X-Forwarded-For", chain+", "+peer)
		} else {
			dst.Set("X-Forwarded-For", peer)
		}
		// Keep X-Real-IP / X-Forwarded-Proto set by the trusted proxy; only
		// backfill when absent.
		if realIP == "" {
			realIP = peer
		}
		dst.Set("X-Real-IP", realIP)
		if fwdProto == "" {
			fwdProto = proto
		}
		dst.Set("X-Forwarded-Proto", fwdProto)
		// ReverseProxy drops these before Rewrite; a trusted proxy's stay.
		if len(forwarded) > 0 {
			dst["Forwarded"] = forwarded
		}
		if len(fwdHost) > 0 {
			dst["X-Forwarded-Host"] = fwdHost
		}
		return
	}

	// Untrusted peer (or no trust list configured): overwrite the client-IP
	// headers with authoritative values and drop every other forwarding claim.
	for _, h := range untrustedForwardingHeaders {
		dst.Del(h)
	}
	dst.Set("X-Forwarded-For", peer)
	dst.Set("X-Real-IP", peer)
	dst.Set("X-Forwarded-Proto", proto)
}

// peerHost is the host part of a RemoteAddr (the address itself when it
// has no port).
func peerHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// realClientIP returns the best-effort real client IP for the request as a
// bare IP string. When the immediate connection peer is a configured trusted
// proxy, it walks the X-Forwarded-For chain right-to-left — every
// X-Forwarded-For line, in order — skipping entries that are themselves
// trusted proxies, and returns the first untrusted address: the real client
// (matching nginx's real_ip_recursive). A hop may carry a port or brackets
// ("203.0.113.5:4711", "[2001:db8::5]:443"); empty entries are skipped. A
// hop that does not parse ends the walk and the answer is the nearest
// trusted hop (or the peer): everything left of it came through a hop nvelox
// cannot identify, so none of it can be believed. X-Real-IP is the fallback
// when every hop is a trusted proxy. When the peer is NOT trusted (or no
// trust list is configured) the peer address is returned verbatim, so a
// direct client can never spoof its source via a forged header. The result
// is always a validated IP (the peer, or a parsed header value), so callers
// — including the access logger — can treat it as trusted.
//
// This is what makes the real client survive the hop in the access log, the
// IP allow/deny lists, the per-IP rate limiter and the ACL engine when this
// nvelox runs behind another proxy. trusted_proxies previously only affected
// the X-Forwarded-For forwarded to the backend (see setForwardedHeaders);
// every internal decision still keyed off the upstream proxy's address.
func (s *HTTPServer) realClientIP(r *http.Request) string {
	peer := peerHost(r.RemoteAddr)
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !s.ipTrusted(peerIP) {
		// Direct/untrusted client — never believe forwarding headers.
		return peer
	}
	// Peer is a trusted proxy: believe its forwarding headers.
	nearest := peer
	for _, line := range reverse(r.Header.Values("X-Forwarded-For")) {
		hops := strings.Split(line, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop := strings.TrimSpace(hops[i])
			if hop == "" {
				continue
			}
			ip := parseHop(hop)
			if ip == nil {
				return nearest // fail closed: nothing left of this hop is trustworthy
			}
			if !s.ipTrusted(ip) {
				return ip.String() // first untrusted hop = the real client
			}
			nearest = ip.String() // another trusted hop — keep walking toward the origin
		}
	}
	if ip := parseHop(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
		return ip.String()
	}
	return peer
}

// reverse returns the lines of a header from the last one to the first.
func reverse(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[len(lines)-1-i] = l
	}
	return out
}

// parseHop parses one X-Forwarded-For entry: an IP, optionally with a port
// and/or IPv6 brackets. nil if it is none of these.
func parseHop(hop string) net.IP {
	if ip := net.ParseIP(hop); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(hop); err == nil {
		return net.ParseIP(host)
	}
	if len(hop) > 2 && hop[0] == '[' && hop[len(hop)-1] == ']' {
		return net.ParseIP(hop[1 : len(hop)-1])
	}
	return nil
}

// ipTrusted reports whether ip falls within the listener's configured
// trusted_proxies CIDRs.
func (s *HTTPServer) ipTrusted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range s.TrustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// applyRequestHeaders applies header add/set/remove to the request.
// expandRedirectVars substitutes variables in redirect URLs.
// Supported: ${host}, ${path}, ${query}, ${scheme}, ${uri}, ${port}
// serveError writes an HTML error page. Uses custom error page if configured,
// otherwise falls back to the built-in styled template.
func (s *HTTPServer) serveError(w http.ResponseWriter, statusCode int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Check for custom error page
	if s.ErrorPages != nil {
		if page, ok := s.ErrorPages[statusCode]; ok {
			w.WriteHeader(statusCode)
			w.Write(page)
			return
		}
	}

	// Default styled error page
	w.WriteHeader(statusCode)
	w.Write(errorhtml.DefaultErrorPage(statusCode))
}

func expandRedirectVars(url string, r *http.Request) string {
	if !strings.Contains(url, "${") {
		return url
	}

	host := r.Host
	// Strip port from host for ${host}
	hostOnly := host
	port := ""
	if h, p, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
		port = p
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	uri := r.URL.RequestURI()

	replacer := strings.NewReplacer(
		"${host}", hostOnly,
		"${path}", r.URL.Path,
		"${query}", r.URL.RawQuery,
		"${scheme}", scheme,
		"${uri}", uri,
		"${port}", port,
	)
	return replacer.Replace(url)
}

// sanitizeHeaderValue removes CR/LF/tab to prevent header injection.
func sanitizeHeaderValue(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}, v)
}

func applyRequestHeaders(r *http.Request, h *config.HeadersConfig) {
	for k, v := range h.RequestAdd {
		r.Header.Add(sanitizeHeaderValue(k), sanitizeHeaderValue(v))
	}
	for k, v := range h.RequestSet {
		r.Header.Set(sanitizeHeaderValue(k), sanitizeHeaderValue(v))
	}
	for _, k := range h.RequestRemove {
		r.Header.Del(k)
	}
}

// applyResponseHeaders applies header add/set/remove to the response.
func applyResponseHeaders(h http.Header, cfg *config.HeadersConfig) {
	for k, v := range cfg.ResponseAdd {
		h.Add(sanitizeHeaderValue(k), sanitizeHeaderValue(v))
	}
	for k, v := range cfg.ResponseSet {
		h.Set(sanitizeHeaderValue(k), sanitizeHeaderValue(v))
	}
	for _, k := range cfg.ResponseRemove {
		h.Del(k)
	}
}
