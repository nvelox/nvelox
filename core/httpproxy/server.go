package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"

	"github.com/quic-go/quic-go/http3"
)

// EngineRef provides access to shared engine components without circular imports.
type EngineRef struct {
	Balancers    map[string]lb.Balancer
	Backends     map[string]*config.Backend
	RateLimiters interface{ Allow() bool } // nil if no rate limiter
}

// HTTPServer manages an HTTP/HTTPS listener with L7 routing.
type HTTPServer struct {
	Listener     *ListenerConfig
	httpServer   *http.Server
	http3Server  *http3.Server
	router       *Router
	Balancers    map[string]lb.Balancer
	Backends     map[string]*config.Backend
	RateLimiter  interface{ Allow() bool }
	altSvcHeader string // set when HTTP/3 is enabled
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
}

// NewHTTPServer creates an HTTP server for the given listener.
func NewHTTPServer(l *ListenerConfig, balancers map[string]lb.Balancer, backends map[string]*config.Backend, rateLimiter interface{ Allow() bool }) *HTTPServer {
	s := &HTTPServer{
		Listener:    l,
		router:      NewRouter(l.Routes, l.DefaultBackend),
		Balancers:   balancers,
		Backends:    backends,
		RateLimiter: rateLimiter,
	}

	s.httpServer = &http.Server{
		Addr:    l.Addr,
		Handler: s,
	}

	return s
}

// Start begins listening for HTTP/HTTPS connections.
func (s *HTTPServer) Start() error {
	if s.Listener.TLS != nil {
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
	// Advertise HTTP/3 if enabled
	if s.altSvcHeader != "" {
		w.Header().Set("Alt-Svc", s.altSvcHeader)
	}

	// Rate limiting
	if s.RateLimiter != nil {
		if !s.RateLimiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}

	// Route matching
	backendName, routeHeaders := s.router.Match(r.Host, r.URL.Path)
	if backendName == "" {
		http.Error(w, "No backend available", http.StatusServiceUnavailable)
		return
	}

	balancer, ok := s.Balancers[backendName]
	if !ok {
		http.Error(w, "Backend not found", http.StatusBadGateway)
		return
	}

	// WebSocket upgrade detection
	if isWebSocketUpgrade(r) {
		s.handleWebSocket(w, r, balancer, backendName)
		return
	}

	// Select backend server
	target, err := balancer.Next()
	if err != nil {
		http.Error(w, "No healthy backends", http.StatusServiceUnavailable)
		return
	}

	// LeastConn tracking
	balancer.OnConnect(target)

	// Apply request headers
	setForwardedHeaders(r)
	applyRequestHeaders(r, &s.Listener.Headers)
	if routeHeaders != nil {
		applyRequestHeaders(r, routeHeaders)
	}

	// Create reverse proxy
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = target
			req.Host = r.Host // preserve original Host header
		},
		ModifyResponse: func(resp *http.Response) error {
			balancer.OnDisconnect(target)
			applyResponseHeaders(resp.Header, &s.Listener.Headers)
			if routeHeaders != nil {
				applyResponseHeaders(resp.Header, routeHeaders)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			balancer.OnDisconnect(target)
			logging.Error("[HTTP] proxy error for %s: %v", r.URL.Path, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// Wrap ResponseWriter to capture status and bytes for access logging
	rec := &statusRecorder{ResponseWriter: w, status: 200}
	start := time.Now()
	proxy.ServeHTTP(rec, r)
	duration := float64(time.Since(start).Microseconds()) / 1000.0 // ms

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	logging.AccessHTTP(clientIP, r.Method, r.URL.Path, r.Proto, rec.status, rec.bytes, duration, target)
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
func setForwardedHeaders(r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		r.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		r.Header.Set("X-Forwarded-For", clientIP)
	}
	r.Header.Set("X-Real-IP", clientIP)
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Proto", "https")
	} else {
		r.Header.Set("X-Forwarded-Proto", "http")
	}
}

// applyRequestHeaders applies header add/set/remove to the request.
func applyRequestHeaders(r *http.Request, h *config.HeadersConfig) {
	for k, v := range h.RequestAdd {
		r.Header.Add(k, v)
	}
	for k, v := range h.RequestSet {
		r.Header.Set(k, v)
	}
	for _, k := range h.RequestRemove {
		r.Header.Del(k)
	}
}

// applyResponseHeaders applies header add/set/remove to the response.
func applyResponseHeaders(h http.Header, cfg *config.HeadersConfig) {
	for k, v := range cfg.ResponseAdd {
		h.Add(k, v)
	}
	for k, v := range cfg.ResponseSet {
		h.Set(k, v)
	}
	for _, k := range cfg.ResponseRemove {
		h.Del(k)
	}
}

// handleWebSocket handles WebSocket upgrade requests by hijacking and relaying.
func (s *HTTPServer) handleWebSocket(w http.ResponseWriter, r *http.Request, balancer lb.Balancer, backendName string) {
	target, err := balancer.Next()
	if err != nil {
		http.Error(w, "No healthy backends", http.StatusServiceUnavailable)
		return
	}
	balancer.OnConnect(target)
	defer balancer.OnDisconnect(target)

	// Dial backend
	backendConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logging.Error("[WS] Backend dial failed: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Forward the original upgrade request to backend
	if err := r.Write(backendConn); err != nil {
		logging.Error("[WS] Failed to write upgrade request: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Hijack client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket hijack not supported", http.StatusInternalServerError)
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
