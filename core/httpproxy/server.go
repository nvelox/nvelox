package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"nvelox/config"
	"nvelox/core/acl"
	"nvelox/core/denylist"
	"nvelox/core/httpproxy/errorhtml"
	"nvelox/core/logging"
	"nvelox/core/middleware"
	"nvelox/core/sticky"
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

// CircuitBreakerI is the interface for circuit breakers.
type CircuitBreakerI interface {
	Allow() bool
	RecordSuccess()
	RecordFailure()
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
	backendTransport *http.Transport // default transport (plaintext HTTP backends)
	// backendTransports holds per-backend TLS-enabled transports. If a backend's
	// name is absent here, the default backendTransport is used.
	backendTransports map[string]*http.Transport
	backendSchemes    map[string]string // "https" when backend_tls is enabled
	altSvcHeader      string
	closeOnce         sync.Once // guards Close() against double-invocation
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
		IPAllowlist:     acl.ParseCIDRList(l.IPAllowlist),
		IPDenylist:      acl.ParseCIDRList(l.IPDenylist),
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

	// Shared transport with connection pooling to backends
	s.backendTransport = &http.Transport{
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 256,
		MaxConnsPerHost:     0, // unlimited
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  true, // we handle compression ourselves
		ForceAttemptHTTP2:   true,
	}

	// Per-backend TLS transports: a backend with backend_tls.enabled=true gets
	// its own Transport with a TLSClientConfig built from the backend config.
	s.backendTransports = make(map[string]*http.Transport)
	s.backendSchemes = make(map[string]string)
	for name, be := range backends {
		if be == nil || !be.BackendTLS.Enabled {
			continue
		}
		tlsCfg, err := buildBackendTLSConfig(be.BackendTLS)
		if err != nil {
			logging.Error("[HTTP] backend %q: backend_tls invalid: %v — falling back to plaintext transport", name, err)
			continue
		}
		s.backendTransports[name] = &http.Transport{
			MaxIdleConns:        1024,
			MaxIdleConnsPerHost: 256,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     tlsCfg,
			DisableCompression:  true,
			ForceAttemptHTTP2:   true,
		}
		s.backendSchemes[name] = "https"
	}

	// http.Server / TLS / HTTP/3 setup now lives on BindGroup. Site is
	// just the handler from here on.
	return s
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

// isPHPPath reports whether a request path should be handled by FastCGI
// rather than the static-file handler. Matches the typical PHP-FPM
// dispatch shape: a path ending in `.php` or containing `.php/` (the
// latter is the PATH_INFO form, e.g. /index.php/foo/bar). Operators who
// run a non-PHP FastCGI backend can configure their own regex on the
// matching route; this helper only kicks in when static+fastcgi coexist
// on the same route.
func isPHPPath(p string) bool {
	return strings.HasSuffix(p, ".php") || strings.Contains(p, ".php/")
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

// buildBackendTLSConfig turns a BackendTLSConfig into a *tls.Config suitable
// for use as Transport.TLSClientConfig.
//
// Security defaults: InsecureSkipVerify is OFF unless the operator explicitly
// sets backend_tls.insecure: true. System CA pool is used when no ca_cert is
// provided. Client cert/key are both required if either is set (mTLS).
func buildBackendTLSConfig(cfg config.BackendTLSConfig) (*tls.Config, error) {
	t := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.Insecure {
		// Operator opted out of verification explicitly. Document loudly.
		logging.Warn("[HTTP] backend_tls.insecure=true — certificate verification DISABLED for backend")
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

// Close stops every per-site background goroutine: response cache cleanup
// loop and per-IP rate limiter cleanup loop. Called by BindGroup.ReplaceSites
// when this site is being removed from a bind group on SIGHUP reload.
//
// Idempotent (sync.Once) — the underlying Cache.Stop / IPRateLimiter.Stop
// close their stopCh channels, which would panic on second close.
//
// In-flight requests in the site's handlers complete normally; stopping
// these tickers only disables background pruning, not the handlers.
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
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		r.Header.Set(requestIDHeader, reqID)   // propagate to the backend (before the WebSocket / FastCGI / ReverseProxy forks)
		w.Header().Set(requestIDHeader, reqID) // echo to the client
	}

	// Resolve the real client IP once: behind a trusted proxy this is the
	// origin client recovered from X-Forwarded-For; otherwise it's the
	// connection peer. Reused below for the allow/deny lists, the per-IP
	// rate limiter, the ACL engine and the access log so every decision
	// reflects the real client rather than the upstream proxy's address.
	clientIP := s.realClientIP(r)

	// IP denylist check (static, per-listener config)
	if len(s.IPDenylist) > 0 && acl.CheckIPList(clientIP, s.IPDenylist) {
		s.serveError(w, http.StatusForbidden)
		return
	}

	// Dynamic (runtime) denylist — TTL-bearing blocks pushed via the admin
	// API (e.g. by ngris-sentinel abuse detection). Consulted on every request
	// using the same trusted-proxy-resolved client IP; process-global so it
	// survives SIGHUP config reloads.
	if s.DynDenylist != nil {
		if ip := net.ParseIP(clientIP); ip != nil && s.DynDenylist.Blocked(ip) {
			s.serveError(w, http.StatusForbidden)
			return
		}
	}

	// IP allowlist check (if set, only listed IPs are allowed)
	if len(s.IPAllowlist) > 0 && !acl.CheckIPList(clientIP, s.IPAllowlist) {
		s.serveError(w, http.StatusForbidden)
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

	// ACL check. A deny may carry a custom status (e.g. 404 to hide an admin
	// surface from unauthorized clients); default to 403 when unset.
	if s.ACLEngine != nil {
		action, status := s.ACLEngine.DecideClientIP(r, net.ParseIP(clientIP))
		if action == "deny" {
			if status == 0 {
				status = http.StatusForbidden
			}
			s.serveError(w, status)
			return
		}
	}

	// Request body size limit
	if s.MaxBodySize > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, s.MaxBodySize)
	}

	// Cache lookup
	if s.ResponseCache != nil && s.ResponseCache.ShouldCache(r.Method) && !ShouldSkipCache(r) {
		key := CacheKey(r)
		if entry := s.ResponseCache.Get(key); entry != nil {
			ServeCached(w, entry)
			return
		}
	}

	// Route matching
	routeResult := s.router.MatchFull(r.Host, r.URL.Path)
	var backendName string
	var routeHeaders *config.HeadersConfig
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
			// Set expires header
			if routeResult.Expires != "" {
				SetExpires(w, routeResult.Expires)
			}

			root := routeResult.Static.Root

			// try_files logic
			if len(routeResult.TryFiles.Files) > 0 {
				resolved := TryFiles(root, r, routeResult.TryFiles.Files, routeResult.TryFiles.Fallback)
				if resolved != "" {
					// Check if fallback is a status code (e.g., "=404")
					if strings.HasPrefix(resolved, "=") {
						code := 404
						fmt.Sscanf(resolved[1:], "%d", &code)
						s.serveError(w, code)
						return
					}
					// Update request path and serve
					r.URL.Path = resolved
				}
			}

			// If the route ALSO has FastCGI configured AND try_files
			// resolved to a PHP path (front-controller pattern), skip
			// the static handler and let FastCGI run the script.
			// Without this, the static handler would happily serve
			// index.php as plain text.
			if routeResult.FastCGI.Pass != "" && isPHPPath(r.URL.Path) {
				// Fall through to the FastCGI block below.
			} else {
				handler := NewStaticHandler(routeResult.Static)
				if handler.ServeFile(w, r) {
					return
				}
				// File not found — fall through to backend or 404
				if backendName == "" && routeResult.FastCGI.Pass == "" {
					s.serveError(w, http.StatusNotFound)
					return
				}
			}
		}

		// Handle FastCGI (PHP-FPM) forwarding.
		//
		// Set the standard forwarding headers before dispatch so PHP sees
		// the same X-Forwarded-For / X-Real-IP / X-Forwarded-Proto values
		// the reverse-proxy path would inject. Without this, scripts that
		// rely on $_SERVER['HTTP_X_FORWARDED_FOR'] (rate-limiting,
		// geolocation, audit logs) see "(none)" even though nvelox knows
		// the real client IP.
		if routeResult.FastCGI.Pass != "" {
			s.setForwardedHeaders(r)
			if routeResult.Expires != "" {
				SetExpires(w, routeResult.Expires)
			}
			ServeFastCGI(w, r, routeResult.FastCGI)
			return
		}

		// Set expires header for non-static routes
		if routeResult.Static.Root == "" && routeResult.Expires != "" {
			SetExpires(w, routeResult.Expires)
		}

		// Handle rewrite
		if routeResult.Rewrite.Path != "" {
			newPath := routeResult.Rewrite.Path
			if len(routeResult.RegexMatches) > 0 {
				newPath = ApplyRewrite(newPath, routeResult.RegexMatches)
			}
			r.URL.Path = newPath
		}
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

	// Circuit breaker check
	if cb, ok := s.CircuitBreakers[backendName]; ok {
		if !cb.Allow() {
			s.serveError(w, http.StatusServiceUnavailable)
			return
		}
	}

	// Connection limit check
	if cl, ok := s.ConnLimiters[backendName]; ok {
		if !cl.Acquire() {
			s.serveError(w, http.StatusServiceUnavailable)
			return
		}
		defer cl.Release()
	}

	// WebSocket upgrade detection
	if isWebSocketUpgrade(r) {
		s.handleWebSocket(w, r, balancer, backendName, clientIP)
		return
	}

	// Sticky session lookup
	var stickyTarget string
	if store, ok := s.StickyStores[backendName]; ok && backend != nil {
		key := s.getStickyKey(r, backend.StickySession)
		if key != "" {
			stickyTarget = store.Get(key)
			if stickyTarget != "" && !balancer.IsHealthy(stickyTarget) {
				stickyTarget = "" // sticky server is down, pick new
			}
		}
	}

	// Determine retry config
	maxAttempts := 1
	retryOn502 := false
	retryOn503 := false
	if backend != nil && backend.Retry.Attempts > 1 {
		maxAttempts = backend.Retry.Attempts
		retryOn502 = strings.Contains(backend.Retry.On, "502")
		retryOn503 = strings.Contains(backend.Retry.On, "503")
	}

	// Apply request headers
	s.setForwardedHeaders(r)
	applyRequestHeaders(r, &s.Listener.Headers)
	if routeHeaders != nil {
		applyRequestHeaders(r, routeHeaders)
	}

	// Compression wrapping
	var cw *compressWriter
	responseWriter := w
	if shouldCompress(r, s.Compression) {
		cw = newCompressWriter(w, s.Compression)
		responseWriter = cw
		defer cw.Close()
	}

	// Retry loop
	var excluded []string
	var lastTarget string
	rec := &statusRecorder{ResponseWriter: responseWriter, status: 200}
	start := time.Now()

	for attempt := 0; attempt < maxAttempts; attempt++ {
		var target string
		var err error

		if attempt == 0 && stickyTarget != "" {
			target = stickyTarget
		} else if attempt == 0 {
			target, err = balancer.Next()
		} else {
			target, err = balancer.NextExcluding(excluded)
		}
		if err != nil {
			s.serveError(w, http.StatusServiceUnavailable)
			return
		}

		lastTarget = target
		balancer.OnConnect(target)

		proxyErr := make(chan error, 1)
		// Pick per-backend TLS transport if configured, else shared default.
		transport := s.backendTransport
		scheme := "http"
		if t, ok := s.backendTransports[backendName]; ok {
			transport = t
			scheme = s.backendSchemes[backendName]
		}
		proxy := &httputil.ReverseProxy{
			Transport: transport,
			Director: func(req *http.Request) {
				req.URL.Scheme = scheme
				req.URL.Host = target
				req.Host = r.Host
			},
			ModifyResponse: func(resp *http.Response) error {
				balancer.OnDisconnect(target)
				// Track passive health + circuit breaker on success
				if ph, ok := s.PassiveHealth[backendName]; ok {
					ph.RecordSuccess(target)
				}
				if cb, ok := s.CircuitBreakers[backendName]; ok {
					cb.RecordSuccess()
				}
				// Check if we should retry on this status
				if attempt < maxAttempts-1 {
					if (resp.StatusCode == 502 && retryOn502) || (resp.StatusCode == 503 && retryOn503) {
						if ph, ok := s.PassiveHealth[backendName]; ok {
							ph.RecordFailure(target)
						}
						return fmt.Errorf("retry: status %d", resp.StatusCode)
					}
				}
				applyResponseHeaders(resp.Header, &s.Listener.Headers)
				if routeHeaders != nil {
					applyResponseHeaders(resp.Header, routeHeaders)
				}
				// Set sticky session cookie
				if store, ok := s.StickyStores[backendName]; ok && backend != nil {
					key := s.getStickyKey(r, backend.StickySession)
					if key != "" {
						store.Set(key, target)
						if backend.StickySession.Type == "cookie" {
							cookieName := backend.StickySession.CookieName
							if cookieName == "" {
								cookieName = "NVELOX_SRV"
							}
							http.SetCookie(rec, &http.Cookie{
								Name:     cookieName,
								Value:    sticky.ServerToToken(target),
								Path:     "/",
								HttpOnly: true,
							})
						}
					}
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				balancer.OnDisconnect(target)
				if ph, ok := s.PassiveHealth[backendName]; ok {
					ph.RecordFailure(target)
				}
				if cb, ok := s.CircuitBreakers[backendName]; ok {
					cb.RecordFailure()
				}
				proxyErr <- err
			},
		}
		if s.BufferPool != nil {
			proxy.BufferPool = s.BufferPool
		}

		// Wrap with cache writer if caching is enabled for this request
		var cacheW *cacheWriter
		proxyTarget := http.ResponseWriter(rec)
		if s.ResponseCache != nil && s.ResponseCache.ShouldCache(r.Method) && !ShouldSkipCache(r) {
			cacheW = newCacheWriter(rec)
			proxyTarget = cacheW
		}

		proxy.ServeHTTP(proxyTarget, r)

		// Store in cache if applicable
		if cacheW != nil && cacheW.statusCode >= 200 && cacheW.statusCode < 400 {
			if !ShouldSkipCacheResponse(cacheW.ResponseWriter.Header()) {
				s.ResponseCache.Put(CacheKey(r), cacheW.ToCacheEntry())
			}
		}

		// Check if we need to retry
		select {
		case err := <-proxyErr:
			excluded = append(excluded, target)
			if attempt < maxAttempts-1 {
				logging.Warn("[HTTP] Retry %d/%d for %s: %v", attempt+1, maxAttempts, logging.SanitizeLogField(r.URL.Path), err)
				rec = &statusRecorder{ResponseWriter: w, status: 200} // reset recorder
				continue
			}
			logging.Error("[HTTP] All retries exhausted for %s: %v", logging.SanitizeLogField(r.URL.Path), err)
			s.serveError(w, http.StatusBadGateway)
		default:
			// Success or non-retryable response
		}
		break
	}

	duration := float64(time.Since(start).Microseconds()) / 1000.0
	logging.AccessHTTP(clientIP, r.Host, r.Method, r.URL.Path, r.Proto, rec.status, rec.bytes, duration, lastTarget, r.UserAgent(), reqID, s.Listener.Name)
}

// getStickyKey returns the session key based on the sticky session config.
func (s *HTTPServer) getStickyKey(r *http.Request, cfg config.StickyConfig) string {
	switch cfg.Type {
	case "cookie":
		cookieName := cfg.CookieName
		if cookieName == "" {
			cookieName = "NVELOX_SRV"
		}
		return sticky.KeyFromCookie(r, cookieName)
	case "header":
		return sticky.KeyFromHeader(r, cfg.HeaderName)
	case "ip_hash":
		return sticky.KeyFromIPHash(r)
	default:
		return ""
	}
}

// statusRecorder wraps http.ResponseWriter to capture status code and bytes written.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Implement http.Hijacker for WebSocket support
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// Implement http.Flusher for streaming
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// setForwardedHeaders adds standard proxy headers.
//
// XFF spoofing defense: if TrustedProxies is configured and the direct peer
// is in it, the client-provided XFF/X-Real-IP/X-Forwarded-Proto are trusted
// and the peer IP is appended. If the peer is NOT in the trust list (or the
// list is empty), the headers are *replaced* with authoritative values —
// preventing a direct client from spoofing its source IP via a forged XFF.
func (s *HTTPServer) setForwardedHeaders(r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	trusted := false
	if len(s.TrustedProxies) > 0 {
		if peerIP := net.ParseIP(clientIP); peerIP != nil {
			for _, cidr := range s.TrustedProxies {
				if cidr.Contains(peerIP) {
					trusted = true
					break
				}
			}
		}
	}

	if trusted {
		// Peer is a trusted proxy: extend its XFF chain and trust its claim.
		if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
			r.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			r.Header.Set("X-Forwarded-For", clientIP)
		}
		// Keep existing X-Real-IP / X-Forwarded-Proto if already set by the
		// trusted proxy; only backfill when absent.
		if r.Header.Get("X-Real-IP") == "" {
			r.Header.Set("X-Real-IP", clientIP)
		}
		if r.Header.Get("X-Forwarded-Proto") == "" {
			if r.TLS != nil {
				r.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Header.Set("X-Forwarded-Proto", "http")
			}
		}
		return
	}

	// Untrusted peer (or no trust list configured): overwrite any client-
	// supplied forwarding headers with authoritative values.
	r.Header.Set("X-Forwarded-For", clientIP)
	r.Header.Set("X-Real-IP", clientIP)
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Proto", "https")
	} else {
		r.Header.Set("X-Forwarded-Proto", "http")
	}
}

// realClientIP returns the best-effort real client IP for the request as a
// bare IP string. When the immediate connection peer is a configured trusted
// proxy, it walks the X-Forwarded-For chain right-to-left, skipping entries
// that are themselves trusted proxies, and returns the first untrusted,
// parseable address — the real client (matching nginx's real_ip_recursive).
// X-Real-IP is the fallback when XFF yields nothing usable. When the peer is
// NOT trusted (or no trust list is configured) the peer address is returned
// verbatim, so a direct client can never spoof its source via a forged
// header. The result is always a validated IP (the peer, or a parsed header
// value), so callers — including the access logger — can treat it as trusted.
//
// This is what makes the real client survive the hop in the access log, the
// IP allow/deny lists, the per-IP rate limiter and the ACL engine when this
// nvelox runs behind another proxy. trusted_proxies previously only affected
// the X-Forwarded-For forwarded to the backend (see setForwardedHeaders);
// every internal decision still keyed off the upstream proxy's address.
func (s *HTTPServer) realClientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !s.ipTrusted(peerIP) {
		// Direct/untrusted client — never believe forwarding headers.
		return peer
	}
	// Peer is a trusted proxy: believe its forwarding headers.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue // skip malformed entries
			}
			if s.ipTrusted(parsed) {
				continue // another trusted hop — keep walking toward the origin
			}
			return ip // first untrusted, valid entry = the real client
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(xr) != nil {
		return xr
	}
	return peer
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

// handleWebSocket handles WebSocket upgrade requests by hijacking and relaying.
func (s *HTTPServer) handleWebSocket(w http.ResponseWriter, r *http.Request, balancer lb.Balancer, backendName string, clientIP string) {
	target, err := balancer.Next()
	if err != nil {
		s.serveError(w, http.StatusServiceUnavailable)
		return
	}
	balancer.OnConnect(target)
	defer balancer.OnDisconnect(target)

	// Dial backend
	backendConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logging.Error("[WS] Backend dial failed: %v", err)
		s.serveError(w, http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Forward the original upgrade request to backend
	if err := r.Write(backendConn); err != nil {
		logging.Error("[WS] Failed to write upgrade request: %v", err)
		s.serveError(w, http.StatusBadGateway)
		return
	}

	// Hijack client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.serveError(w, http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		logging.Error("[WS] Hijack failed: %v", err)
		return
	}
	defer clientConn.Close()

	logging.Info("[WS] %s -> %s (%s)", clientIP, target, backendName)

	// Bidirectional relay
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := backendConn.Read(buf)
			if err != nil {
				break
			}
			if _, err := clientConn.Write(buf[:n]); err != nil {
				break
			}
		}
		close(done)
	}()

	// Flush any buffered data from hijack
	if clientBuf.Reader.Buffered() > 0 {
		buffered := make([]byte, clientBuf.Reader.Buffered())
		clientBuf.Read(buffered)
		backendConn.Write(buffered)
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := clientConn.Read(buf)
		if err != nil {
			break
		}
		if _, err := backendConn.Write(buf[:n]); err != nil {
			break
		}
	}
	<-done
}
