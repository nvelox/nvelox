package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nvelox/config"
	"nvelox/core/admin"
	"nvelox/core/circuitbreaker"
	"nvelox/core/denylist"
	"nvelox/core/discovery"
	"nvelox/core/health"
	"nvelox/core/httpproxy"
	"nvelox/core/logging"
	"nvelox/core/metrics"
	"nvelox/core/sticky"
	"nvelox/core/tlsutil"
	"nvelox/lb"
	"nvelox/proxy"

	"github.com/lesismal/nbio"
	"github.com/pires/go-proxyproto"
)

type Engine struct {
	UDPEngine       *nbio.Engine
	Listeners       []*ListenerConfig
	Config          *config.Config
	Balancers       map[string]lb.Balancer
	Backends        map[string]*config.Backend
	Checkers        map[string]*health.Checker
	RateLimiters    map[string]*RateLimiter            // keyed by listener name
	ConnLimiters    map[string]*ConnLimiter            // keyed by backend name
	PassiveHealth   map[string]*PassiveHealthTracker   // keyed by backend name
	StickyStores    map[string]*sticky.Store           // keyed by backend name
	CircuitBreakers map[string]*circuitbreaker.Breaker // keyed by backend name
	Metrics         *metrics.Registry
	DNSResolvers    map[string]*discovery.DNSResolver // keyed by backend name
	AdminServer     *admin.Server
	metricsServer   *http.Server
	UDPPool         *UDPPool                    // UDP session affinity pool
	HTTPServers     []*httpproxy.HTTPServer     // L7 HTTP sites (per listener config)
	BindGroups      []*httpproxy.BindGroup      // socket-owning groups (one per bind addr)
	ActiveConns     sync.WaitGroup              // tracks in-flight connections for graceful drain
	DrainTimeout    time.Duration               // max wait on shutdown (default 30s)
	tlsListeners    []net.Listener              // TLS listeners to close on shutdown
	tcpListeners    []tcpListener               // plain L4 TCP listeners (std accept loop + relayL4)
	acceptWG        sync.WaitGroup              // L4 TCP/TLS accept loops; waited on before closing live conns
	l4Conns         sync.Map                    // live L4 TCP/TLS client conns (net.Conn -> struct{}), closed on shutdown
	runCtx          context.Context             // Start's ctx: cancels in-flight L4 backend dials on shutdown
	reloadMu        sync.Mutex                  // serializes concurrent SIGHUPs
	view            atomic.Pointer[backendView] // what request paths read (backendview.go)
	ready           chan struct{}               // closed once Start holds every listening socket
	// l4Running: the L4 (tcp, udp) listener configs Start began serving,
	// keyed by protocol, name and address. A reload does not rebuild them;
	// it only swaps their PROXY signing keys (rotation).
	l4Running  map[string]*ListenerConfig
	configPath string // path for reload

	// UDP session limits (see udpsession.go). Set from code constants in
	// NewEngine — deliberately not configurable; tests lower them.
	udpMaxSessions      int
	udpMaxSessionsPerIP int
	udpNoReplyTimeout   time.Duration
	l4Handler           *ProxyEventHandler // set by Start (under reloadMu)
}

type ListenerConfig struct {
	Name            string
	Addr            string
	Protocol        string
	ZeroCopy        bool
	Backend         string
	SendProxyV2     bool // Send PROXY protocol v2 to backend
	Port            int
	RateLimit       config.RateLimitConfig
	Timeouts        config.TimeoutConfig
	TLS             *config.TLSConfig
	HTTP3           bool
	Routes          []config.RouteConfig
	Headers         config.HeadersConfig
	IPAllowlist     []string
	IPDenylist      []string
	MaxBodySize     string
	IPRateLimit     config.IPRateLimitConfig
	ACL             []config.ACLRule
	TrustedProxies  []string
	AcceptProxyFrom []string
	proxyTrust      *proxyTrust // parsed once from AcceptProxyFrom (inbound PROXY-v2 trust)
	ServerNames     []string
	DefaultServer   bool
	Compression     config.CompressionConfig
	ErrorPages      map[int]string
	Buffering       config.BufferingConfig
	Cache           config.CacheConfig
	RequestID       config.RequestIDConfig

	// Derived by prepare(): the parsed L4 access policy (tcp/udp) and the
	// client-certificate policy (tls). prepared marks them built.
	access     *l4Access
	clientAuth *tlsutil.ClientAuth
	prepared   bool
}

// l4Key identifies an L4 listener across a reload.
func l4Key(l *ListenerConfig) string { return l.Protocol + "|" + l.Name + "|" + l.Addr }

// Ready is closed once Start has bound every listening socket (HTTP, HTTPS
// and HTTP/3, TCP, UDP, admin API, metrics). main switches to server.user /
// server.group only then.
func (e *Engine) Ready() <-chan struct{} { return e.ready }

func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		ready:           make(chan struct{}),
		Listeners:       make([]*ListenerConfig, 0),
		Config:          cfg,
		Balancers:       make(map[string]lb.Balancer),
		Backends:        make(map[string]*config.Backend),
		Checkers:        make(map[string]*health.Checker),
		RateLimiters:    make(map[string]*RateLimiter),
		ConnLimiters:    make(map[string]*ConnLimiter),
		PassiveHealth:   make(map[string]*PassiveHealthTracker),
		StickyStores:    make(map[string]*sticky.Store),
		CircuitBreakers: make(map[string]*circuitbreaker.Breaker),
		DNSResolvers:    make(map[string]*discovery.DNSResolver),
		Metrics:         metrics.Default,

		udpMaxSessions:      maxUDPSessions,
		udpMaxSessionsPerIP: maxUDPSessionsPerIP,
		udpNoReplyTimeout:   udpNoReplyTimeout,
	}
	return e
}

// preflight checks what Start and Reload must refuse before touching any
// state: every listener's derived state (access lists, client CA) builds,
// every backend_tls config builds (no plaintext fallback), and no tcp/udp
// listener forwards to a backend_tls backend (TLS to backends exists on the
// HTTP path only). config.Load checks the same at load; this catches files
// that changed since and hand-built configs.
func preflight(listeners []*ListenerConfig, backends []config.Backend) error {
	for _, l := range listeners {
		if err := l.prepare(); err != nil {
			return err
		}
	}
	tlsBackends := make(map[string]bool)
	for i := range backends {
		be := &backends[i]
		if !be.BackendTLS.Enabled {
			continue
		}
		tlsBackends[be.Name] = true
		if _, err := httpproxy.BuildBackendTLSConfig(be.BackendTLS); err != nil {
			return fmt.Errorf("backend %s: backend_tls: %v", be.Name, err)
		}
	}
	for _, l := range listeners {
		if (l.Protocol == "tcp" || l.Protocol == "udp") && tlsBackends[l.Backend] {
			return fmt.Errorf("listener %s: backend %s has backend_tls enabled, which is not implemented for %s listeners", l.Name, l.Backend, l.Protocol)
		}
	}
	return nil
}

// warnInsecureBackendTLS logs, once per start / reload, every backend that
// skips certificate verification (backend_tls.insecure).
func warnInsecureBackendTLS(backends []config.Backend) {
	for _, be := range backends {
		if be.BackendTLS.Enabled && be.BackendTLS.Insecure {
			logging.Warn("[HTTP] backend %s: backend_tls.insecure=true — certificate verification DISABLED", be.Name)
		}
	}
}

func (e *Engine) Start(ctx context.Context) error {
	// Engine.Reload (SIGHUP) rewrites Listeners, BindGroups, HTTPServers and
	// the backend maps under reloadMu. Hold it for the whole startup so a
	// reload that arrives early waits for a fully started engine instead of
	// racing it (the race detector caught Start's listener loop reading
	// e.Listeners while a SIGHUP reload replaced it). Released before blocking
	// on ctx; the shutdown path snapshots BindGroups under it again.
	e.reloadMu.Lock()
	startupLocked := true
	defer func() {
		if startupLocked {
			e.reloadMu.Unlock()
		}
	}()

	// 0. Refuse to start on anything that would fail open: an unparseable
	// access list or client CA, a backend_tls config that cannot be built,
	// a tcp/udp listener on a backend_tls backend.
	if err := preflight(e.Listeners, e.Config.Backends); err != nil {
		return err
	}
	warnInsecureBackendTLS(e.Config.Backends)
	e.l4Running = make(map[string]*ListenerConfig)
	for _, l := range e.Listeners {
		if l.Protocol == "tcp" || l.Protocol == "udp" {
			e.l4Running[l4Key(l)] = l
		}
	}

	// 1. Initialize Backends & Health Checkers
	e.initBackends()
	e.publishBackends()

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
		e.AdminServer = admin.NewServer(e.Config.Admin.Bind, e.Config.Admin.APIKey, nil, denylist.Default)
		e.AdminServer.SetBalancerSource(func() map[string]lb.Balancer { return e.backends().Balancers })
		if err := e.AdminServer.Start(); err != nil {
			return err
		}
		// Evict expired dynamic-denylist entries periodically (admin API is the
		// only mutator, so the sweeper only matters when admin is enabled).
		denylist.Default.StartSweeper(time.Minute)
	}

	// 1f. Start metrics server
	if e.Config.Metrics.Enabled {
		metricsPath := e.Config.Metrics.Path
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		mux := http.NewServeMux()
		mux.Handle(metricsPath, e.Metrics.Handler())
		e.metricsServer = newMetricsServer(e.Config.Metrics.Bind, mux)
		// Bound here, like every listener, before Start reports ready.
		mln, err := net.Listen("tcp", e.metricsServer.Addr)
		if err != nil {
			return fmt.Errorf("metrics endpoint: %w", err)
		}
		go func() {
			if err := e.metricsServer.Serve(mln); err != nil && err != http.ErrServerClosed {
				logging.Error("[METRICS] Server error: %v", err)
			}
		}()
		logging.Info("Metrics endpoint started on %s%s", e.metricsServer.Addr, metricsPath)
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
		site := e.buildL7Site(l)
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
	e.l4Handler = handler

	e.runCtx = ctx

	// 3. L4 TCP listeners. Plain (non-TLS) listeners run a std accept loop
	// with one relayL4 goroutine pair per connection; TLS-terminating
	// listeners use their own accept loop and the same relay. (TCP no longer
	// runs on nbio: nbio cannot half-close and drops unflushed bytes on close
	// — see relay.go.) Bind everything first so a bind failure leaves no
	// accept loop running.
	for _, l := range e.Listeners {
		if l.Protocol != "tcp" || l.TLS != nil {
			continue
		}
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			e.closeTCPListeners()
			return fmt.Errorf("TCP listener %s start failed: %v", l.Name, err)
		}
		logging.Info("Registering listener %s on %s", l.Name, l.Addr)
		e.tcpListeners = append(e.tcpListeners, tcpListener{ln: ln, l: l})
	}
	for _, tl := range e.tcpListeners {
		l := tl.l
		e.startAcceptLoop(tl.ln, l.Name, func(c net.Conn) { handler.serveTCP(c, l) })
	}
	if len(e.tcpListeners) > 0 {
		logging.Info("L4 TCP started on %d listeners", len(e.tcpListeners))
	}
	for _, tlsL := range e.getTLSListeners() {
		if err := e.startTLSListener(tlsL, handler); err != nil {
			e.closeTCPListeners()
			return fmt.Errorf("TLS listener %s start failed: %v", tlsL.Name, err)
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

	// 5. Every socket is bound: report ready, then wait for the context.
	// Reloads may run from here on.
	startupLocked = false
	e.reloadMu.Unlock()
	close(e.ready)
	<-ctx.Done()

	logging.Info("Stopping Engines...")

	// Snapshot the bind groups under reloadMu: a reload in flight may still be
	// adding or removing one.
	e.reloadMu.Lock()
	stopGroups := append([]*httpproxy.BindGroup(nil), e.BindGroups...)
	e.reloadMu.Unlock()

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
	for _, bg := range stopGroups {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		bg.Stop(shutdownCtx)
		cancel()
	}

	// Stop accepting new L4 TCP/TLS connections, wait for the accept loops to
	// exit (no further ActiveConns.Add), then close the live L4 TCP sessions —
	// the restart behaviour the nbio TCP engine's Stop() had.
	e.closeTCPListeners()
	e.acceptWG.Wait()
	e.closeL4Conns()

	// Stop the nbio UDP engine
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

// Reload applies a new config to a running engine. Handles:
//   - Backend reconciliation by name (kept / added / removed), preserving
//     balancer state, sticky stores, circuit breakers, and DNS resolvers
//     across renames-of-server-list-only. Goroutines for removed
//     backends are stopped.
//   - Per-site config swap on every existing HTTPS/HTTP bind group:
//     routes / ACL / headers / error pages / compression / cache all
//     hot-swapped via atomic.Pointer. In-flight requests keep their
//     old site reference; new requests see the new config.
//   - Bind-group composition changes: new bind addrs start a fresh
//     BindGroup, removed addrs gracefully drain.
//   - TLS certs hot-swapped on every BindGroup via atomic.Pointer
//     (operators can rotate Let's Encrypt certs without restart).
//
// All-or-nothing: every NEW bind addr is probed via net.Listen BEFORE
// any mutation. If any probe fails (port in use, missing perms), Reload
// returns the error and no state changes — operators keep their last
// good config running.
//
// Concurrency: serialized by reloadMu. Two SIGHUPs in quick succession
// queue; the second waits for the first to complete. Metrics are
// emitted via the engine's Metrics registry.
func (e *Engine) Reload(cfg *config.Config) error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()

	logging.Info("Reloading config...")
	start := time.Now()

	// Pre-flight 1: listener expansion must succeed (it also parses every
	// listener's access lists and client CA), and every backend_tls config
	// must build: a reload never downgrades a backend to plaintext.
	expanded, err := ExpandListeners(cfg.Listeners)
	if err != nil {
		e.recordReload("fail", start)
		return fmt.Errorf("reload: listener expansion: %w", err)
	}
	if err := preflight(expanded, cfg.Backends); err != nil {
		e.recordReload("fail", start)
		return fmt.Errorf("reload: %w", err)
	}

	// Pre-flight 2: any NEW L7 bind addr must be bindable RIGHT NOW.
	// We check before mutating engine state so a port conflict doesn't
	// leave the engine half-reconfigured.
	bgByAddr := make(map[string]struct{}, len(e.BindGroups))
	for _, bg := range e.BindGroups {
		bgByAddr[bg.Addr()] = struct{}{}
	}
	for _, l := range expanded {
		if l.Protocol != "http" && l.Protocol != "https" {
			continue
		}
		if _, kept := bgByAddr[l.Addr]; kept {
			continue
		}
		probe, perr := net.Listen("tcp", l.Addr)
		if perr != nil {
			e.recordReload("fail", start)
			return fmt.Errorf("reload: cannot bind new addr %s: %w", l.Addr, perr)
		}
		probe.Close()
	}

	// Pre-flight passed — apply mutations.
	// L4 listeners keep running as configured at start, except for their
	// PROXY signing keys, which take the re-read key files (rotation).
	for _, l := range expanded {
		if running := e.l4Running[l4Key(l)]; running != nil && running.proxyTrust != nil && l.proxyTrust != nil {
			var keys [][]byte
			if k := l.proxyTrust.keys.Load(); k != nil {
				keys = *k
			}
			running.proxyTrust.setKeys(keys)
		}
	}
	warnInsecureBackendTLS(cfg.Backends)
	e.Config = cfg
	beAdded, beRemoved, beUpdated := e.reconcileBackends(cfg)
	e.publishBackends()
	sitesSwapped, bgAdded, bgRemoved := e.reloadL7Sites(expanded)

	totalRotated := 0
	for _, bg := range e.BindGroups {
		rotated, err := bg.ReloadCerts()
		if err != nil {
			logging.Debug("[RELOAD] bind group cert reload skipped: %v", err)
			continue
		}
		totalRotated += rotated
	}
	logging.Info("Reload complete: backends +%d/-%d/~%d, bind groups +%d/-%d, %d sites swapped, %d TLS certs rotated",
		beAdded, beRemoved, beUpdated, bgAdded, bgRemoved, sitesSwapped, totalRotated)
	e.recordReload("ok", start)
	return nil
}

// recordReload emits the reload outcome to the metrics registry.
// nvelox_reload_total{result="ok|fail"} counts total reloads; the
// duration histogram tracks how long each Reload took (operators can
// alert on slow reloads which usually indicate slow drains).
func (e *Engine) recordReload(result string, start time.Time) {
	if e.Metrics == nil {
		return
	}
	e.Metrics.GetCounter("nvelox_reload_total", map[string]string{"result": result}).Inc()
	e.Metrics.GetHistogram("nvelox_reload_duration_seconds").Observe(time.Since(start).Seconds())
}

// reloadL7Sites reconciles the L7 (HTTP/HTTPS) listener set against the
// new config:
//   - bind addrs in BOTH old and new: ReplaceSites atomic swap.
//   - bind addrs only in NEW: start a fresh BindGroup, append to engine.
//   - bind addrs only in OLD: graceful Stop (10s drain) in background.
//
// All-or-nothing: pre-flight every NEW addr by attempting to bind a
// socket. If any port is unavailable we abort the entire L7 reload
// before mutating any engine state — operators get a clear "reload
// failed, keeping current state" outcome rather than a half-applied mess.
// Pre-existing bind groups are left running on failure.
//
// Returns the counts (sites swapped on existing groups, bind groups
// added, bind groups removed). expanded is the new config's listener set as
// Reload expanded (and pre-flighted) it.
func (e *Engine) reloadL7Sites(expanded []*ListenerConfig) (swapped, added, removed int) {
	bgByAddr := make(map[string]*httpproxy.BindGroup, len(e.BindGroups))
	for _, bg := range e.BindGroups {
		bgByAddr[bg.Addr()] = bg
	}

	type group struct {
		protocol string
		sites    []*httpproxy.HTTPServer
		l7l      []*ListenerConfig // matching listener configs for the group
	}
	newGroups := make(map[string]*group)
	for _, l := range expanded {
		if l.Protocol != "http" && l.Protocol != "https" {
			continue
		}
		g, ok := newGroups[l.Addr]
		if !ok {
			g = &group{protocol: l.Protocol}
			newGroups[l.Addr] = g
		}
		g.sites = append(g.sites, e.buildL7Site(l))
		g.l7l = append(g.l7l, l)
	}

	// Pre-flight: every NEW addr must be bindable RIGHT NOW. Without
	// this an "add a listener on :8080" reload that conflicts with
	// another process leaves engine state inconsistent. We probe by
	// opening + immediately closing a TCP listener.
	var newAddrs []string
	for addr := range newGroups {
		if _, kept := bgByAddr[addr]; kept {
			continue
		}
		newAddrs = append(newAddrs, addr)
	}
	for _, addr := range newAddrs {
		probe, err := net.Listen("tcp", addr)
		if err != nil {
			logging.Error("[RELOAD] cannot bind new addr %s (%v) — aborting L7 reload, keeping current state", addr, err)
			// Close every site we just built — they hold per-site
			// goroutines we don't want to leak.
			for _, g := range newGroups {
				for _, s := range g.sites {
					s.Close()
				}
			}
			return 0, 0, 0
		}
		probe.Close()
	}

	// Mutations from this point. Pre-flight passed, so add/swap shouldn't fail.

	// 1. ReplaceSites on bind groups present in BOTH old and new.
	for addr, g := range newGroups {
		bg, kept := bgByAddr[addr]
		if !kept {
			continue
		}
		if err := bg.ReplaceSites(g.sites); err != nil {
			logging.Error("[RELOAD] bind group %s ReplaceSites: %v", addr, err)
			continue
		}
		swapped++
	}

	// 2. Start fresh BindGroup for NEW addrs.
	for _, addr := range newAddrs {
		g := newGroups[addr]
		bg := httpproxy.NewBindGroup(addr, g.protocol)
		for _, s := range g.sites {
			bg.AddSite(s)
		}
		if err := bg.Start(); err != nil {
			logging.Error("[RELOAD] bind group %s Start: %v", addr, err)
			for _, s := range g.sites {
				s.Close()
			}
			continue
		}
		e.BindGroups = append(e.BindGroups, bg)
		added++
		logging.Info("[RELOAD] Added bind group %s with %d site(s)", addr, len(g.sites))
	}

	// 3. Graceful Stop of bind groups present in OLD but not NEW. Shutdown
	// drains in-flight requests; we run it in a background goroutine with
	// a 10s deadline so SIGHUP itself doesn't block on slow clients.
	survivors := e.BindGroups[:0]
	for _, bg := range e.BindGroups {
		if _, kept := newGroups[bg.Addr()]; kept {
			survivors = append(survivors, bg)
			continue
		}
		addr := bg.Addr()
		removed++
		go func(bg *httpproxy.BindGroup, addr string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := bg.Stop(ctx); err != nil {
				logging.Warn("[RELOAD] bind group %s graceful Stop: %v", addr, err)
			} else {
				logging.Info("[RELOAD] Removed bind group %s (drained)", addr)
			}
		}(bg, addr)
	}
	e.BindGroups = survivors

	// 4. Refresh engine.Listeners and engine.HTTPServers so operators
	// looking at engine state see the up-to-date list.
	e.Listeners = expanded
	e.HTTPServers = e.HTTPServers[:0]
	for _, bg := range e.BindGroups {
		if g, ok := newGroups[bg.Addr()]; ok {
			e.HTTPServers = append(e.HTTPServers, g.sites...)
		}
	}
	return swapped, added, removed
}

func (e *Engine) initBackends() {
	for i := range e.Config.Backends {
		e.initBackend(&e.Config.Backends[i])
	}
}

// ExpandListeners takes the raw []config.Listener (as loaded from YAML)
// and produces the engine-side []*ListenerConfig with port ranges
// expanded into individual single-port entries.
//
// Used at startup by main.go and at SIGHUP reload by Engine.Reload so
// the two paths can't drift. A bind like ":2000-2025" produces 26
// listeners with Port set, each carrying the same per-listener config.
// Each listener's derived state (access lists, client CA) is built here, once
// per config entry, so a bad value fails the expansion.
func ExpandListeners(listeners []config.Listener) ([]*ListenerConfig, error) {
	expanded := make([]*ListenerConfig, 0, len(listeners))
	for _, l := range listeners {
		host, portStr, err := net.SplitHostPort(l.Bind)
		if err != nil {
			return nil, fmt.Errorf("listener %s: invalid bind %q: %v", l.Name, l.Bind, err)
		}
		var tlsCfg *config.TLSConfig
		if l.TLS.Cert != "" {
			tlsCfgCopy := l.TLS
			tlsCfg = &tlsCfgCopy
		}

		base := ListenerConfig{
			Name:            l.Name,
			Protocol:        l.Protocol,
			ZeroCopy:        l.ZeroCopy,
			Backend:         l.Backend,
			RateLimit:       l.RateLimit,
			Timeouts:        l.Timeouts,
			TLS:             tlsCfg,
			HTTP3:           l.HTTP3,
			Routes:          l.Routes,
			Headers:         l.Headers,
			IPAllowlist:     l.IPAllowlist,
			IPDenylist:      l.IPDenylist,
			MaxBodySize:     l.MaxBodySize,
			IPRateLimit:     l.IPRateLimit,
			ACL:             l.ACL,
			TrustedProxies:  l.TrustedProxies,
			AcceptProxyFrom: l.AcceptProxyFrom,
			proxyTrust:      newProxyTrust(l.AcceptProxyFrom, l.AcceptProxyKeys),
			ServerNames:     l.ServerNames,
			DefaultServer:   l.DefaultServer,
			Compression:     l.Compression,
			ErrorPages:      l.ErrorPages,
			Buffering:       l.Buffering,
			Cache:           l.Cache,
			RequestID:       l.RequestID,
		}
		if err := base.prepare(); err != nil {
			return nil, err
		}

		mk := func(name, addr string, port int) *ListenerConfig {
			lc := base
			lc.Name, lc.Addr, lc.Port = name, addr, port
			return &lc
		}

		if strings.Contains(portStr, "-") {
			parts := strings.Split(portStr, "-")
			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("listener %s: invalid port range %q", l.Name, portStr)
			}
			for p := start; p <= end; p++ {
				expanded = append(expanded,
					mk(fmt.Sprintf("%s-%d", l.Name, p),
						fmt.Sprintf("%s:%d", host, p), p))
			}
		} else {
			p, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("listener %s: invalid port %q: %v", l.Name, portStr, err)
			}
			expanded = append(expanded, mk(l.Name, l.Bind, p))
		}
	}
	return expanded, nil
}

// buildL7Site constructs a fresh httpproxy.HTTPServer (Site) from a
// core.ListenerConfig. Used at startup by Engine.Start and at SIGHUP
// reload by Engine.reloadL7Sites to swap per-site config without
// disturbing in-flight connections.
//
// Always builds against the engine's CURRENT balancers/backends maps —
// so a reload that adds/changes backends sees the new state.
func (e *Engine) buildL7Site(l *ListenerConfig) *httpproxy.HTTPServer {
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
		RequestID:      l.RequestID,
		Timeouts:       l.Timeouts,
		ClientAuth:     l.clientAuth,
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
	v := e.backends()
	return httpproxy.NewHTTPServer(httpL, v.Balancers, v.Backends, rl, connLimiters, passiveHealth, v.StickyStores, cbs)
}

// initBackend wires one backend's balancer, conn limiter, passive health,
// sticky store, circuit breaker, DNS resolver, and active health checker.
// Used by initBackends at startup and by reconcileBackends for added
// backends on SIGHUP reload.
func (e *Engine) initBackend(be *config.Backend) {
	balancer := lb.NewBalancer(be.Balance, be.Servers)
	e.Balancers[be.Name] = balancer
	e.Backends[be.Name] = be
	logging.Info("Initialized backend %s with %s balancing", be.Name, be.Balance)

	if be.MaxConnections > 0 {
		e.ConnLimiters[be.Name] = NewConnLimiter(be.MaxConnections)
		logging.Info("Connection limiter for %s: max %d", be.Name, be.MaxConnections)
	}

	if be.HealthCheck.Passive.MaxFails > 0 {
		e.PassiveHealth[be.Name] = NewPassiveHealthTracker(be.Name, be.HealthCheck.Passive.MaxFails, balancer)
		logging.Info("Passive health for %s: max_fails=%d", be.Name, be.HealthCheck.Passive.MaxFails)
	}

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

	if be.ResolveInterval != "" {
		interval, err := time.ParseDuration(be.ResolveInterval)
		if err == nil && interval > 0 {
			resolver := discovery.NewDNSResolver(be.Name, be.Servers, interval, be.AllowPrivateIPs, func(servers []string) {
				balancer.UpdateServers(servers)
			})
			resolver.Start()
			e.DNSResolvers[be.Name] = resolver
		}
	}

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

// teardownBackend stops every goroutine and releases every resource
// associated with a backend name. Used by reconcileBackends when a
// backend is removed from the config on reload.
//
// In-flight requests that captured the old balancer via closure
// (httpproxy.ReverseProxy.Director) continue to run against it — Go's
// GC keeps it alive until those requests complete. Memory is reclaimed
// naturally; no leak.
func (e *Engine) teardownBackend(name string) {
	if c, ok := e.Checkers[name]; ok {
		c.Stop()
		delete(e.Checkers, name)
	}
	if r, ok := e.DNSResolvers[name]; ok {
		r.Stop()
		delete(e.DNSResolvers, name)
	}
	if s, ok := e.StickyStores[name]; ok {
		s.Stop()
		delete(e.StickyStores, name)
	}
	delete(e.Balancers, name)
	delete(e.Backends, name)
	delete(e.ConnLimiters, name)
	delete(e.PassiveHealth, name)
	delete(e.CircuitBreakers, name)
}

// reconcileBackends diffs the running config against newCfg and applies
// the minimum change set:
//
//   - Backends still present (KEPT): preserve balancer (so LeastConn
//     keeps its connection counts), sticky store (so client cookies
//     stay valid), circuit breaker state. UpdateServers() if the
//     server list changed.
//   - New backends (ADDED): init from scratch via initBackend.
//   - Backends gone from new config (REMOVED): teardownBackend stops
//     all goroutines (health checker, DNS resolver, sticky cleanup)
//     and drops the maps. No goroutine leaks.
//
// Returns counts (added, removed, updated) for logging.
func (e *Engine) reconcileBackends(newCfg *config.Config) (added, removed, updated int) {
	newByName := make(map[string]*config.Backend, len(newCfg.Backends))
	for i := range newCfg.Backends {
		newByName[newCfg.Backends[i].Name] = &newCfg.Backends[i]
	}

	// Phase 1: tear down REMOVED backends. Collect names first so we
	// don't mutate maps while iterating.
	toRemove := make([]string, 0)
	for name := range e.Balancers {
		if _, kept := newByName[name]; !kept {
			toRemove = append(toRemove, name)
		}
	}
	for _, name := range toRemove {
		e.teardownBackend(name)
		removed++
		logging.Info("[RELOAD] Removed backend: %s", name)
	}

	// Phase 2: update KEPT backends; add NEW ones.
	for name, be := range newByName {
		if bal, kept := e.Balancers[name]; kept {
			// Refresh the cached *config.Backend pointer so per-request reads
			// (Backend.Retry, Backend.Timeouts.*, etc.) see the new values.
			old := e.Backends[name]
			e.Backends[name] = be
			if !sliceEqual(old.Servers, be.Servers) {
				bal.UpdateServers(be.Servers)
				updated++
				logging.Info("[RELOAD] Updated backend %s server list (%d → %d servers)",
					name, len(old.Servers), len(be.Servers))
			}
		} else {
			e.initBackend(be)
			added++
			logging.Info("[RELOAD] Added backend: %s", name)
		}
	}
	return added, removed, updated
}

// sliceEqual reports whether two string slices have identical contents
// in the same order. Used to detect backend server-list changes during
// reconcile.
func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// getAddrs returns the bind addresses of the nbio-served listeners of proto
// (UDP; plain TCP now runs its own accept loops — see l4tcp.go).
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

// closeTCPListeners closes the plain L4 TCP and TLS listeners (idempotent:
// a second Close just returns an error) so their accept loops exit.
func (e *Engine) closeTCPListeners() {
	for _, tl := range e.tcpListeners {
		tl.ln.Close()
	}
	for _, l := range e.tlsListeners {
		l.Close()
	}
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
	// Client-certificate policy (tls.client_auth / client_ca), parsed by
	// prepare(). With "require" the handshake fails unless the client
	// presents a certificate that verifies against client_ca.
	if err := l.prepare(); err != nil {
		return err
	}
	l.clientAuth.Apply(tlsConfig)

	raw, err := net.Listen("tcp", l.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", l.Addr, err)
	}

	// Trusted inbound PROXY-v2 acceptance: when accept_proxy_from is set, the
	// RAW TCP listener is wrapped, so the PROXY header a trusted peer sends is
	// read off the stream BEFORE the TLS handshake (as on the plain TCP path)
	// and conn.RemoteAddr() becomes the real client. Untrusted peers have any
	// header IGNORED (no spoofing); non-PROXY clients start the handshake at
	// once (a ClientHello can never look like a PROXY signature).
	var inner net.Listener = raw
	if l.proxyTrust.enabled() {
		pol, perr := l.proxyTrust.policy()
		if perr != nil {
			raw.Close()
			return fmt.Errorf("TLS listener %s accept_proxy_from: %v", l.Name, perr)
		}
		inner = &proxyproto.Listener{
			Listener:          raw,
			Policy:            pol,
			ReadHeaderTimeout: tlsProxyHeaderTimeout,
			// With accept_proxy_key_file a trusted peer's header must be
			// signed; the library drops the connection otherwise.
			ValidateHeader: func(h *proxyproto.Header) error { return l.proxyTrust.verify(h, nil) },
		}
		logging.Info("TLS listener %s accepts inbound PROXY-v2 from %v", l.Name, l.AcceptProxyFrom)
	}
	listener := tls.NewListener(inner, tlsConfig)

	e.tlsListeners = append(e.tlsListeners, listener)
	logging.Info("TLS listener %s started on %s", l.Name, l.Addr)

	e.startAcceptLoop(listener, l.Name, func(c net.Conn) { e.handleTLSConn(c, l, handler) })

	return nil
}

// tlsProxyHeaderTimeout bounds how long a TLS-terminating listener waits for
// an inbound PROXY-v2 header (and, for any peer, for the first byte).
const tlsProxyHeaderTimeout = 10 * time.Second

// l4TLSHandshakeTimeout bounds the TLS handshake on a TLS-terminating L4
// listener. The handshake (and the client-certificate check) completes
// before the backend is dialed, so an unauthenticated client never reaches it.
const l4TLSHandshakeTimeout = 10 * time.Second

func (e *Engine) handleTLSConn(clientConn net.Conn, l *ListenerConfig, handler *ProxyEventHandler) {
	defer clientConn.Close()

	// The raw TCP peer (a trusted relay or the client itself) and the port it
	// dialed; reading them from the transport does not touch the PROXY header.
	rawConn := transportOf(clientConn)
	peer := rawConn.RemoteAddr()
	dstPort := portOf(rawConn.LocalAddr())
	peerTrusted := l.proxyTrust.trusts(peer)

	// Check rate limit
	if rl, ok := e.RateLimiters[l.Name]; ok {
		if !rl.Allow() {
			logging.Warn("[RATE] TLS connection from %s rejected (rate limit on %s)", peer, l.Name)
			if !peerTrusted {
				logging.AccessL4(ipStrOf(peer), l.Protocol, dstPort, l4StatusRateLimited, 0, 0, 0)
			}
			return
		}
	}

	// The resolved client: the PROXY-v2 source when a trusted relay sent a
	// header, else the peer itself (proxyproto reads the header here, bounded
	// by tlsProxyHeaderTimeout).
	client := clientConn.RemoteAddr()
	start := time.Now()
	status := "no_route"
	defer func() {
		// One L4 access record per connection, as on the plain TCP path. Not
		// for a trusted relay whose header never named a client: the record
		// would blame the relay (see serveTCP).
		if peerTrusted && client.String() == peer.String() {
			return
		}
		durMs := float64(time.Since(start).Nanoseconds()) / 1e6
		logging.AccessL4(ipStrOf(client), l.Protocol, dstPort, status, 0, 0, durMs)
	}()

	// Access policy (static lists, ACL, dynamic denylist) on the resolved
	// client, before the handshake: a refused client costs no crypto.
	if ok, st := handler.l4Admit(l, ipOf(client)); !ok {
		status = st
		return
	}

	logging.Info("[CONN] New tls client %s -> %s", client, clientConn.LocalAddr())

	// Complete the handshake (and the client-certificate check) before any
	// backend is dialed.
	if tc, ok := clientConn.(*tls.Conn); ok {
		ctx := e.runCtx
		if ctx == nil {
			ctx = context.Background()
		}
		hctx, cancel := context.WithTimeout(ctx, l4TLSHandshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			logging.Debug("[CONN] TLS handshake with %s failed: %v", client, err)
			status = "error"
			return
		}
	}

	// Select backend (one consistent view for this connection, H6)
	bv := e.backends()
	balancer, ok := bv.Balancers[l.Backend]
	if !ok {
		logging.Error("Balancer '%s' not found for TLS listener '%s'", l.Backend, l.Name)
		return
	}

	backend := bv.Backends[l.Backend]
	if backend != nil && backend.BackendTLS.Enabled {
		// backend_tls is implemented on the HTTP path only; never send
		// plaintext to a backend configured for TLS (config load refuses
		// this pairing; a reload can still change a backend under a running
		// L4 listener).
		logging.Error("[CONN] TLS listener %s: backend %s has backend_tls enabled, which L4 listeners do not implement — refusing %s", l.Name, l.Backend, client)
		return
	}

	// Backend max_connections: one slot per session, held until it ends.
	if cl, ok := bv.ConnLimiters[l.Backend]; ok {
		if !cl.Acquire() {
			logging.Warn("[CONN] TLS listener %s: backend %s at max_connections — refusing %s", l.Name, l.Backend, client)
			status = l4StatusRateLimited
			return
		}
		defer cl.Release()
	}

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
	backendConn, err := e.dialL4Backend(dialTarget, connectTimeout)
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
		header := proxyproto.HeaderProxyFromAddrs(2, client, backendConn.LocalAddr())
		if len(backend.SendProxyKey) > 0 {
			if err := proxy.SignHeader(header, backend.SendProxyKey, time.Now()); err != nil {
				logging.Error("Failed to sign PROXY v2 header on TLS conn: %v", err)
				return
			}
		}
		if _, err := header.WriteTo(backendConn); err != nil {
			logging.Error("Failed to write PROXY v2 header on TLS conn: %v", err)
			return
		}
	}
	status = "ok"

	// Bidirectional relay with half-close semantics (relay.go): a backend that
	// closes first gets its whole response delivered followed by close_notify
	// + FIN; a client that half-closes still gets the backend's answer. The
	// idle timeout applies only when timeouts.idle is set — this path never
	// had a default one.
	res := relayL4(clientConn, backendConn, l.Timeouts.ParseIdle())
	if res.Err != nil {
		logging.Debug("[CONN] TLS %s ended with error: %v", client, res.Err)
	}
	logging.Info("[CONN] Closed TLS %s (Dur: %v)", client, time.Since(start))
}
