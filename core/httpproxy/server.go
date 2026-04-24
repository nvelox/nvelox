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
	"time"

	"nvelox/config"
	"nvelox/core/acl"
	"nvelox/core/httpproxy/errorhtml"
	"nvelox/core/logging"
	"nvelox/core/middleware"
	"nvelox/core/sticky"
	"nvelox/lb"

	"github.com/quic-go/quic-go/http3"
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
	GetGauge(name string, labels map[string]string) interface{ Inc(); Dec() }
}

// EngineRef provides access to shared engine components without circular imports.
type EngineRef struct {
	Balancers    map[string]lb.Balancer
	Backends     map[string]*config.Backend
	RateLimiters interface{ Allow() bool } // nil if no rate limiter
}

// HTTPServer manages an HTTP/HTTPS listener with L7 routing.
type HTTPServer struct {
	Listener      *ListenerConfig
	httpServer    *http.Server
	http3Server   *http3.Server
	router        *Router
	Balancers     map[string]lb.Balancer
	Backends      map[string]*config.Backend
	RateLimiter   interface{ Allow() bool }
	ConnLimiters  map[string]ConnLimiterI
	PassiveHealth map[string]PassiveHealthI
	StickyStores  map[string]*sticky.Store
	ACLEngine     *acl.Engine
	IPAllowlist   []*net.IPNet
	IPDenylist    []*net.IPNet
	TrustedProxies []*net.IPNet
	IPRateLimiter *middleware.IPRateLimiter
	CircuitBreakers map[string]CircuitBreakerI
	MaxBodySize     int64 // 0 = unlimited
	Compression     config.CompressionConfig
	ErrorPages      map[int][]byte // status code -> pre-loaded HTML content
	ResponseCache   *Cache
	BufferPool      *BufferPool
	backendTransport *http.Transport // default transport (plaintext HTTP backends)
	// backendTransports holds per-backend TLS-enabled transports. If a backend's
	// name is absent here, the default backendTransport is used.
	backendTransports map[string]*http.Transport
	backendSchemes    map[string]string // "https" when backend_tls is enabled
	altSvcHeader    string
}

// ListenerConfig mirrors core.ListenerConfig to avoid circular imports.
type ListenerConfig struct {
	Name           string
	Addr           string
	Protocol       string
	DefaultBackend string
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
}

// NewHTTPServer creates an HTTP server for the given listener.
func NewHTTPServer(l *ListenerConfig, balancers map[string]lb.Balancer, backends map[string]*config.Backend, rateLimiter interface{ Allow() bool }, connLimiters map[string]ConnLimiterI, passiveHealth map[string]PassiveHealthI, stickyStores map[string]*sticky.Store, circuitBreakers map[string]CircuitBreakerI) *HTTPServer {
	s := &HTTPServer{
		Listener:      l,
		router:        NewRouter(l.Routes, l.DefaultBackend),
		Balancers:     balancers,
		Backends:      backends,
		ConnLimiters:  connLimiters,
		PassiveHealth: passiveHealth,
		StickyStores:    stickyStores,
		CircuitBreakers: circuitBreakers,
		IPAllowlist:     acl.ParseCIDRList(l.IPAllowlist),
		IPDenylist:     acl.ParseCIDRList(l.IPDenylist),
		TrustedProxies: acl.ParseCIDRList(l.TrustedProxies),
		MaxBodySize:   parseByteSize(l.MaxBodySize),
		RateLimiter: rateLimiter,
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

	s.httpServer = &http.Server{
		Addr:         l.Addr,
		Handler:      s,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

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

// Start begins listening for HTTP/HTTPS connections.
func (s *HTTPServer) Start() error {
	if s.Listener.TLS != nil {
		warnIfKeyWorldReadable(s.Listener.TLS.Key)
		cert, err := tls.LoadX509KeyPair(s.Listener.TLS.Cert, s.Listener.TLS.Key)
		if err != nil {
			return fmt.Errorf("failed to load TLS cert/key: %v", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
		s.httpServer.TLSConfig = tlsCfg

		// Start HTTP/3 (QUIC) if enabled
		if s.Listener.HTTP3 {
			// HTTP/3 server uses the same ServeHTTP handler
			s.http3Server = &http3.Server{
				Addr:      s.Listener.Addr,
				Handler:   s, // HTTP/3 requests go through same routing
				TLSConfig: http3.ConfigureTLSConfig(tlsCfg.Clone()),
			}
			go func() {
				if err := s.http3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logging.Error("[HTTP3] Server error: %v", err)
				}
			}()
			logging.Info("[HTTP3] QUIC listener started on %s", s.Listener.Addr)

			// Enable Alt-Svc header injection in ServeHTTP
			s.altSvcHeader = fmt.Sprintf(`h3=":%d"; ma=86400`, s.Listener.Port)
		}

		go func() {
			ln, err := tls.Listen("tcp", s.Listener.Addr, s.httpServer.TLSConfig)
			if err != nil {
				logging.Error("[HTTP] TLS listen failed on %s: %v", s.Listener.Addr, err)
				return
			}
			if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
				logging.Error("[HTTP] Server error: %v", err)
			}
		}()
	} else {
		go func() {
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logging.Error("[HTTP] Server error: %v", err)
			}
		}()
	}
	return nil
}


// Stop gracefully shuts down the HTTP server.
func (s *HTTPServer) Stop(ctx context.Context) error {
	if s.http3Server != nil {
		s.http3Server.Close()
	}
	return s.httpServer.Shutdown(ctx)
}

// ServeHTTP handles incoming HTTP requests with routing, proxying, and header manipulation.
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Security headers on all responses
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Advertise HTTP/3 if enabled
	if s.altSvcHeader != "" {
		w.Header().Set("Alt-Svc", s.altSvcHeader)
	}

	// IP denylist check
	if len(s.IPDenylist) > 0 && acl.CheckIPList(r.RemoteAddr, s.IPDenylist) {
		s.serveError(w, http.StatusForbidden)
		return
	}

	// IP allowlist check (if set, only listed IPs are allowed)
	if len(s.IPAllowlist) > 0 && !acl.CheckIPList(r.RemoteAddr, s.IPAllowlist) {
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
		if !s.IPRateLimiter.Allow(r.RemoteAddr) {
			s.serveError(w, http.StatusTooManyRequests)
			return
		}
	}

	// ACL check
	if s.ACLEngine != nil {
		action := s.ACLEngine.Check(r)
		if action == "deny" {
			s.serveError(w, http.StatusForbidden)
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

			handler := NewStaticHandler(routeResult.Static)
			if handler.ServeFile(w, r) {
				return
			}
			// File not found — fall through to backend or 404
			if backendName == "" {
				s.serveError(w, http.StatusNotFound)
				return
			}
		}

		// Handle FastCGI (PHP-FPM) forwarding
		if routeResult.FastCGI.Pass != "" {
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
		s.handleWebSocket(w, r, balancer, backendName)
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
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	logging.AccessHTTP(clientIP, r.Method, r.URL.Path, r.Proto, rec.status, rec.bytes, duration, lastTarget)
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
func (s *HTTPServer) handleWebSocket(w http.ResponseWriter, r *http.Request, balancer lb.Balancer, backendName string) {
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

	logging.Info("[WS] %s -> %s (%s)", r.RemoteAddr, target, backendName)

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
