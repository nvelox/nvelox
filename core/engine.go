package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"nvelox/config"
	"nvelox/core/admin"
	"nvelox/core/circuitbreaker"
	"nvelox/core/discovery"
	"nvelox/core/health"
	"nvelox/core/httpproxy"
	"nvelox/core/logging"
	"nvelox/core/metrics"
	"nvelox/core/sticky"
	"nvelox/core/tlsutil"
	"nvelox/lb"

	"github.com/lesismal/nbio"
	"github.com/pires/go-proxyproto"
)

type Engine struct {
	TCPEngine    *nbio.Engine
	UDPEngine    *nbio.Engine
	Listeners    []*ListenerConfig
	Config       *config.Config
	Balancers    map[string]lb.Balancer
	Backends     map[string]*config.Backend
	Checkers     map[string]*health.Checker
	RateLimiters    map[string]*RateLimiter           // keyed by listener name
	ConnLimiters    map[string]*ConnLimiter           // keyed by backend name
	PassiveHealth   map[string]*PassiveHealthTracker  // keyed by backend name
	StickyStores    map[string]*sticky.Store          // keyed by backend name
	CircuitBreakers map[string]*circuitbreaker.Breaker // keyed by backend name
	Metrics         *metrics.Registry
	DNSResolvers    []*discovery.DNSResolver
	AdminServer     *admin.Server
	metricsServer   *http.Server
	UDPPool         *UDPPool                          // UDP session affinity pool
	HTTPServers     []*httpproxy.HTTPServer           // L7 HTTP sites (per listener config)
	BindGroups      []*httpproxy.BindGroup            // socket-owning groups (one per bind addr)
	ActiveConns  sync.WaitGroup            // tracks in-flight connections for graceful drain
	DrainTimeout time.Duration             // max wait on shutdown (default 30s)
	tlsListeners []net.Listener            // TLS listeners to close on shutdown
	configPath   string                    // path for reload
}

type ListenerConfig struct {
	Name           string
	Addr           string
	Protocol       string
	ZeroCopy       bool
	Backend        string
	SendProxyV2    bool // Send PROXY protocol v2 to backend
	Port           int
	RateLimit      config.RateLimitConfig
	Timeouts       config.TimeoutConfig
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
	ServerNames    []string
	DefaultServer  bool
	Compression    config.CompressionConfig
	ErrorPages     map[int]string
	Buffering      config.BufferingConfig
	Cache          config.CacheConfig
}

func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		Listeners:     make([]*ListenerConfig, 0),
		Config:        cfg,
		Balancers:     make(map[string]lb.Balancer),
		Backends:      make(map[string]*config.Backend),
		Checkers:      make(map[string]*health.Checker),
		RateLimiters:    make(map[string]*RateLimiter),
		ConnLimiters:    make(map[string]*ConnLimiter),
		PassiveHealth:   make(map[string]*PassiveHealthTracker),
		StickyStores:    make(map[string]*sticky.Store),
		CircuitBreakers: make(map[string]*circuitbreaker.Breaker),
		Metrics:         metrics.Default,
	}
	return e
}

func (e *Engine) Start(ctx context.Context) error {
	// 1. Initialize Backends & Health Checkers
	e.initBackends()

	// 1b. Initialize Rate Limiters
	for _, l := range e.Listeners {
		if l.RateLimit.ConnectionsPerSecond > 0 {
			e.RateLimiters[l.Name] = NewRateLimiter(l.RateLimit.ConnectionsPerSecond, l.RateLimit.Burst)
			logging.Info("Rate limiter for %s: %.0f conn/s, burst %d", l.Name, l.RateLimit.ConnectionsPerSecond, l.RateLimit.Burst)
		}
	}

	// 1c. Initialize UDP Pool
	e.UDPPool = NewUDPPool(60 * time.Second)

	// 1e. Start admin API
	if e.Config.Admin.Enabled {
		e.AdminServer = admin.NewServer(e.Config.Admin.Bind, e.Config.Admin.APIKey, e.Balancers)
		e.AdminServer.Start()
	}

	// 1f. Start metrics server
	if e.Config.Metrics.Enabled {
		metricsPath := e.Config.Metrics.Path
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		mux := http.NewServeMux()
		mux.Handle(metricsPath, e.Metrics.Handler())
		e.metricsServer = &http.Server{
			Addr:    e.Config.Metrics.Bind,
			Handler: mux,
		}
		go func() {
			if err := e.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logging.Error("[METRICS] Server error: %v", err)
			}
		}()
		logging.Info("Metrics endpoint started on %s%s", e.Config.Metrics.Bind, metricsPath)
	}

	// 1d. Start HTTP/HTTPS listeners (L7), grouped by bind address.
	//
	// Multiple listeners may share a bind: address (nginx-style multi-server-
	// per-port). For each unique addr we open exactly one socket and attach
	// every site (HTTPServer) that shares it. The BindGroup dispatches by
	// SNI (TLS) and Host header (HTTP) to pick the right site per request.
	type siteSpec struct {
		listener *ListenerConfig
		site     *httpproxy.HTTPServer
	}
	bindGroups := make(map[string][]siteSpec) // addr → sites in order
	bindOrder := make([]string, 0)            // preserve config order for stable startup logging
	for _, l := range e.Listeners {
		if l.Protocol != "http" && l.Protocol != "https" {
			continue
		}
		var rl interface{ Allow() bool }
		if limiter, ok := e.RateLimiters[l.Name]; ok {
			rl = limiter
		}
		httpL := &httpproxy.ListenerConfig{
			Name:           l.Name,
			Addr:           l.Addr,
			Protocol:       l.Protocol,
			Backend:        l.Backend,
			Port:           l.Port,
			TLS:            l.TLS,
			HTTP3:          l.HTTP3,
			Routes:         l.Routes,
			Headers:        l.Headers,
			IPAllowlist:    l.IPAllowlist,
			IPDenylist:     l.IPDenylist,
			MaxBodySize:    l.MaxBodySize,
			IPRateLimit:    l.IPRateLimit,
			ACL:            l.ACL,
			TrustedProxies: l.TrustedProxies,
			ServerNames:    l.ServerNames,
			DefaultServer:  l.DefaultServer,
			Compression:    l.Compression,
			ErrorPages:     l.ErrorPages,
			Buffering:      l.Buffering,
			Cache:          l.Cache,
		}
		connLimiters := make(map[string]httpproxy.ConnLimiterI)
		for k, v := range e.ConnLimiters {
			connLimiters[k] = v
		}
		passiveHealth := make(map[string]httpproxy.PassiveHealthI)
		for k, v := range e.PassiveHealth {
			passiveHealth[k] = v
		}
		cbs := make(map[string]httpproxy.CircuitBreakerI)
		for k, v := range e.CircuitBreakers {
			cbs[k] = v
		}
		site := httpproxy.NewHTTPServer(httpL, e.Balancers, e.Backends, rl, connLimiters, passiveHealth, e.StickyStores, cbs)
		e.HTTPServers = append(e.HTTPServers, site)

		if _, seen := bindGroups[l.Addr]; !seen {
			bindOrder = append(bindOrder, l.Addr)
		}
		bindGroups[l.Addr] = append(bindGroups[l.Addr], siteSpec{listener: l, site: site})
	}

	for _, addr := range bindOrder {
		group := bindGroups[addr]
		bg := httpproxy.NewBindGroup(addr, group[0].listener.Protocol)
		for _, s := range group {
			bg.AddSite(s.site)
		}
		if err := bg.Start(); err != nil {
			return fmt.Errorf("HTTP bind group %s start failed: %v", addr, err)
		}
		e.BindGroups = append(e.BindGroups, bg)
		if len(group) == 1 {
			l := group[0].listener
			logging.Info("HTTP listener %s started on %s (protocol: %s)", l.Name, l.Addr, l.Protocol)
		} else {
			names := make([]string, 0, len(group))
			for _, s := range group {
				names = append(names, s.listener.Name)
			}
			logging.Info("HTTP bind group %s started with %d sites (%s)", addr, len(group), strings.Join(names, ", "))
		}
	}

	// 2. Setup Handler
	handler := NewProxyEventHandler(e)

	// 3. Setup TCP Engine (non-TLS listeners only; TLS uses separate accept loop)
	tcpAddrs := e.getAddrs("tcp")
	tlsListeners := e.getTLSListeners()
	needsTCPEngine := len(tcpAddrs) > 0 || len(tlsListeners) > 0

	if needsTCPEngine {
		conf := nbio.Config{
			Network:            "tcp",
			Addrs:              tcpAddrs,
			MaxWriteBufferSize: 6 * 1024 * 1024,
		}
		e.TCPEngine = nbio.NewEngine(conf)
		e.TCPEngine.OnOpen(handler.OnOpen)
		e.TCPEngine.OnData(handler.OnData)
		e.TCPEngine.OnClose(handler.OnClose)

		if err := e.TCPEngine.Start(); err != nil {
			return fmt.Errorf("TCP Engine start failed: %v", err)
		}
		logging.Info("NBIO TCP Engine Started on %d listeners", len(tcpAddrs))

		// Start TLS accept loops
		for _, tlsL := range tlsListeners {
			if err := e.startTLSListener(tlsL, handler); err != nil {
				return fmt.Errorf("TLS listener %s start failed: %v", tlsL.Name, err)
			}
		}
	}

	// 4. Setup UDP Engine
	udpAddrs := e.getAddrs("udp")
	if len(udpAddrs) > 0 {
		conf := nbio.Config{
			Network:        "udp",
			Addrs:          udpAddrs,
			UDPReadTimeout: 60 * time.Second,
		}
		e.UDPEngine = nbio.NewEngine(conf)
		e.UDPEngine.OnOpen(handler.OnOpen)
		e.UDPEngine.OnData(handler.OnData)
		e.UDPEngine.OnClose(handler.OnClose)

		if err := e.UDPEngine.Start(); err != nil {
			return fmt.Errorf("UDP Engine start failed: %v", err)
		}
		logging.Info("NBIO UDP Engine Started on %d listeners", len(udpAddrs))
	}

	// 5. Wait for Context
	<-ctx.Done()

	logging.Info("Stopping Engines...")

	// Stop admin API
	if e.AdminServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		e.AdminServer.Stop(shutdownCtx)
		cancel()
	}
	// Stop metrics server
	if e.metricsServer != nil {
		e.metricsServer.Close()
	}

	// Stop HTTP bind groups (each owns the socket; HTTPServers are sites
	// within them and have nothing to shut down on their own).
	for _, bg := range e.BindGroups {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		bg.Stop(shutdownCtx)
		cancel()
	}

	// Close TLS listeners to stop accepting new connections
	for _, l := range e.tlsListeners {
		l.Close()
	}

	// Stop nbio engines (stops accepting new L4 connections)
	if e.TCPEngine != nil {
		e.TCPEngine.Stop()
	}
	if e.UDPEngine != nil {
		e.UDPEngine.Stop()
	}

	// Drain active L4 connections
	drainTimeout := e.DrainTimeout
	if drainTimeout == 0 {
		drainTimeout = 30 * time.Second
	}
	drainDone := make(chan struct{})
	go func() {
		e.ActiveConns.Wait()
		close(drainDone)
	}()
	select {
	case <-drainDone:
		logging.Info("All connections drained")
	case <-time.After(drainTimeout):
		logging.Warn("Drain timeout reached (%v), forcing shutdown", drainTimeout)
	}

	if e.UDPPool != nil {
		e.UDPPool.Stop()
	}
	for _, r := range e.DNSResolvers {
		r.Stop()
	}

	return nil
}

// Reload applies a new config to a running engine. Today it handles:
//   - Backends (balancer + health checker) rebuilt from scratch.
//   - TLS certs hot-swapped on every BindGroup via atomic.Pointer
//     (operators can rotate Let's Encrypt certs without restart).
//
// Listener add/remove/route-edit still requires restart (F2/F3 work).
func (e *Engine) Reload(cfg *config.Config) {
	logging.Info("Reloading backends...")

	// Stop existing health checkers
	for name, checker := range e.Checkers {
		checker.Stop()
		delete(e.Checkers, name)
	}

	// Update config and re-initialize backends
	e.Config = cfg
	e.initBackends()

	// Hot-reload TLS certs on every HTTPS bind group. Failures here are
	// isolated to the site that broke; the rest of the bind group keeps
	// running with the previous snapshot.
	totalRotated := 0
	for _, bg := range e.BindGroups {
		rotated, err := bg.ReloadCerts()
		if err != nil {
			// loadCertState validates presence of TLS-enabled sites; on
			// a plain-HTTP bind group ReloadCerts also errors with "no
			// TLS-enabled sites" — silently skip those.
			logging.Debug("[RELOAD] bind group cert reload skipped: %v", err)
			continue
		}
		totalRotated += rotated
	}
	if totalRotated > 0 {
		logging.Info("Reload complete: %d backends, %d TLS certs rotated", len(cfg.Backends), totalRotated)
	} else {
		logging.Info("Reload complete: %d backends, no cert rotation needed", len(cfg.Backends))
	}
}

func (e *Engine) initBackends() {
	for i := range e.Config.Backends {
		be := &e.Config.Backends[i]
		balancer := lb.NewBalancer(be.Balance, be.Servers)
		e.Balancers[be.Name] = balancer
		e.Backends[be.Name] = be
		logging.Info("Initialized backend %s with %s balancing", be.Name, be.Balance)

		// Connection limiter
		if be.MaxConnections > 0 {
			e.ConnLimiters[be.Name] = NewConnLimiter(be.MaxConnections)
			logging.Info("Connection limiter for %s: max %d", be.Name, be.MaxConnections)
		}

		// Passive health checks
		if be.HealthCheck.Passive.MaxFails > 0 {
			e.PassiveHealth[be.Name] = NewPassiveHealthTracker(be.Name, be.HealthCheck.Passive.MaxFails, balancer)
			logging.Info("Passive health for %s: max_fails=%d", be.Name, be.HealthCheck.Passive.MaxFails)
		}

		// Sticky sessions
		if be.StickySession.Type != "" {
			ttl := 1 * time.Hour
			if be.StickySession.TTL != "" {
				if d, err := time.ParseDuration(be.StickySession.TTL); err == nil {
					ttl = d
				}
			}
			e.StickyStores[be.Name] = sticky.NewStore(ttl)
			logging.Info("Sticky session for %s: type=%s, ttl=%v", be.Name, be.StickySession.Type, ttl)
		}

		// Circuit breaker
		if be.CircuitBreaker.Enabled {
			cbTimeout := 30 * time.Second
			if be.CircuitBreaker.Timeout != "" {
				if d, err := time.ParseDuration(be.CircuitBreaker.Timeout); err == nil {
					cbTimeout = d
				}
			}
			e.CircuitBreakers[be.Name] = circuitbreaker.New(
				be.CircuitBreaker.Threshold,
				cbTimeout,
				be.CircuitBreaker.HalfOpenMax,
			)
			logging.Info("Circuit breaker for %s: threshold=%d, timeout=%v", be.Name, be.CircuitBreaker.Threshold, cbTimeout)
		}

		// DNS-based service discovery
		if be.ResolveInterval != "" {
			interval, err := time.ParseDuration(be.ResolveInterval)
			if err == nil && interval > 0 {
				resolver := discovery.NewDNSResolver(be.Name, be.Servers, interval, be.AllowPrivateIPs, func(servers []string) {
					balancer.UpdateServers(servers)
				})
				resolver.Start()
				e.DNSResolvers = append(e.DNSResolvers, resolver)
			}
		}

		// Active health checks
		if be.HealthCheck.Active.Interval != "" {
			checker := health.NewChecker(be.HealthCheck, be)
			checker.OnStatusChange = func(server string, healthy bool) {
				log.Printf("Health status change for backend %s, server %s: healthy=%t", be.Name, server, healthy)
				balancer.UpdateStatus(server, healthy)
			}
			e.Checkers[be.Name] = checker
			checker.Start()
		}
	}
}

func (e *Engine) getAddrs(proto string) []string {
	addrs := make([]string, 0)
	for _, l := range e.Listeners {
		// Skip HTTP/HTTPS listeners (handled by HTTPServer) and TLS TCP listeners
		if l.Protocol == "http" || l.Protocol == "https" {
			continue
		}
		if l.Protocol == proto && l.TLS == nil {
			addrs = append(addrs, l.Addr)
			logging.Info("Registering listener %s on %s", l.Name, l.Addr)
		}
	}
	return addrs
}

func (e *Engine) getTLSListeners() []*ListenerConfig {
	var result []*ListenerConfig
	for _, l := range e.Listeners {
		if l.Protocol == "tcp" && l.TLS != nil {
			result = append(result, l)
		}
	}
	return result
}

// warnIfKeyWorldReadable logs a WARN if a private-key file on disk has
// group or world permission bits set. Doesn't refuse the load (operators
// sometimes can't change perms in containerized / mounted-secret setups),
// but surfaces the issue at startup so it isn't silent.
func warnIfKeyWorldReadable(keyPath string) {
	if keyPath == "" {
		return
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		return
	}
	// Refuse if any of group/other bits are set.
	if fi.Mode().Perm()&0o077 != 0 {
		logging.Warn("[TLS] Private key %q has overly permissive mode %o — recommend 0600",
			keyPath, fi.Mode().Perm())
	}
}

func (e *Engine) startTLSListener(l *ListenerConfig, handler *ProxyEventHandler) error {
	warnIfKeyWorldReadable(l.TLS.Key)
	cert, err := tls.LoadX509KeyPair(l.TLS.Cert, l.TLS.Key)
	if err != nil {
		return fmt.Errorf("failed to load TLS cert/key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if err := tlsutil.ApplyTLSVersionAndCiphers(tlsConfig, *l.TLS); err != nil {
		return fmt.Errorf("TLS listener %s: %v", l.Name, err)
	}

	ln, err := tls.Listen("tcp", l.Addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", l.Addr, err)
	}

	e.tlsListeners = append(e.tlsListeners, ln)
	logging.Info("TLS listener %s started on %s", l.Name, l.Addr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go e.handleTLSConn(conn, l, handler)
		}
	}()

	return nil
}

func (e *Engine) handleTLSConn(clientConn net.Conn, l *ListenerConfig, handler *ProxyEventHandler) {
	defer clientConn.Close()

	// Check rate limit
	if rl, ok := e.RateLimiters[l.Name]; ok {
		if !rl.Allow() {
			logging.Warn("[RATE] TLS connection from %s rejected (rate limit on %s)", clientConn.RemoteAddr(), l.Name)
			return
		}
	}

	logging.Info("[CONN] New tls client %s -> %s", clientConn.RemoteAddr(), clientConn.LocalAddr())
	startTime := time.Now()

	// Select backend
	balancer, ok := e.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for TLS listener '%s'", l.Backend, l.Name)
		return
	}

	backend := e.Backends[l.Backend]

	target, err := balancer.Next()
	if err != nil {
		logging.Error("Balancer '%s' error: %v", l.Backend, err)
		return
	}

	originalTarget := target
	dialTarget := target
	if _, _, err := net.SplitHostPort(dialTarget); err != nil {
		dialTarget = fmt.Sprintf("%s:%d", dialTarget, l.Port)
	}

	// Dial backend with configurable timeout
	connectTimeout := l.Timeouts.ParseConnect()
	if backend != nil && backend.Timeouts.Connect != "" {
		connectTimeout = backend.Timeouts.ParseConnect()
	}
	backendConn, err := net.DialTimeout("tcp", dialTarget, connectTimeout)
	if err != nil {
		logging.Error("TLS backend dial failed: %v", err)
		return
	}
	defer backendConn.Close()

	// Notify balancer
	balancer.OnConnect(originalTarget)
	defer balancer.OnDisconnect(originalTarget)

	// Send PROXY v2 if configured
	if backend != nil && backend.SendProxyV2 {
		header := proxyproto.HeaderProxyFromAddrs(2, clientConn.RemoteAddr(), backendConn.LocalAddr())
		if _, err := header.WriteTo(backendConn); err != nil {
			logging.Error("Failed to write PROXY v2 header on TLS conn: %v", err)
			return
		}
	}

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
	logging.Info("[CONN] Closed TLS %s (Dur: %v)", clientConn.RemoteAddr(), time.Since(startTime))
}
