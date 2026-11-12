package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nvelox/core/denylist"
	"nvelox/core/logging"
	"nvelox/lb"
)

// DefaultBind is where the admin API listens when admin.bind is empty:
// loopback only, so leaving bind out can never expose the API to a network.
// (Before, an empty bind fell through to net/http's ":http" — every
// interface on port 80.)
const DefaultBind = "127.0.0.1:9091"

// Brute-force defense parameters. The API key is compared in constant time,
// and failed attempts are counted per source IP. A valid key is ALWAYS
// served: the lockout only throttles failures (429 instead of 401, no log
// line per attempt), so an attacker who shares an address with a legitimate
// caller (NAT, SNAT'd pods) cannot lock that caller out. Online guessing is
// defeated by the key's length, not by the lockout — use a long random key.
const (
	authFailWindow      = 10 * time.Minute // window for counting failed attempts
	authFailThreshold   = 10               // fail this many in the window → lockout
	authLockoutDuration = 15 * time.Minute
	// authMaxTracked caps the failure table so a flood of failing source
	// addresses cannot grow it without bound. While it is full, a failure
	// from an untracked address is throttled without a record.
	authMaxTracked = 4096
	// authPruneInterval: expired failure records are swept at most this often.
	authPruneInterval = time.Minute
)

// maxBodyBytes bounds a JSON request body.
const maxBodyBytes = 4096

type authAttempt struct {
	failures    int
	firstFailAt time.Time
	lockedUntil time.Time
}

// bindInfo is the parsed admin bind address, used for the loopback-peer and
// Host header checks.
type bindInfo struct {
	host     string // lower-cased host part ("" when listening on every address)
	ip       net.IP // host as an IP literal; nil for a hostname or an empty host
	wildcard bool   // every address: "", 0.0.0.0 or ::
	loopback bool   // a loopback IP literal or "localhost"
	err      error  // the bind does not parse; Start refuses to run
}

func parseBind(bind string) bindInfo {
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return bindInfo{err: fmt.Errorf("invalid bind %q: %v", bind, err)}
	}
	if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
		return bindInfo{err: fmt.Errorf("invalid bind %q: port must be a number from 0 to 65535", bind)}
	}
	b := bindInfo{host: strings.ToLower(host)}
	switch ip := net.ParseIP(host); {
	case host == "":
		b.wildcard = true
	case ip != nil:
		b.ip = ip
		b.wildcard = ip.IsUnspecified()
		b.loopback = ip.IsLoopback()
	default:
		b.loopback = b.host == "localhost"
	}
	return b
}

// Server provides a REST API for runtime management.
type Server struct {
	httpServer *http.Server
	balancers  map[string]lb.Balancer
	// balancerSource, when set, returns the engine's current backend view: a
	// map a reload never writes again (the engine publishes a fresh one), so
	// reading it races nothing. It replaces balancers.
	balancerSource func() map[string]lb.Balancer
	startTime      time.Time
	apiKey         string
	apiKeySum      [sha256.Size]byte // sha256(apiKey): compared without leaking the key length
	dynDeny        *denylist.Dynamic // runtime IP/CIDR denylist (nil = endpoint disabled)
	bind           bindInfo

	// Per-source-IP failed auth tracking.
	authMu       sync.Mutex
	authFailures map[string]*authAttempt
	lastPrune    time.Time
	lastFullLog  time.Time
}

// BackendStatus represents a backend's status in the API response.
type BackendStatus struct {
	Name    string   `json:"name"`
	Servers []string `json:"servers"`
}

// StatsResponse is the response for GET /api/v1/stats.
type StatsResponse struct {
	Uptime   string `json:"uptime"`
	Backends int    `json:"backends"`
}

// NewServer creates an admin API server. An empty bind means DefaultBind.
// dynDeny is the process-wide runtime denylist exposed via /api/v1/denylist;
// pass denylist.Default (or nil to disable that endpoint). Start refuses to
// run without an API key.
func NewServer(bind string, apiKey string, balancers map[string]lb.Balancer, dynDeny *denylist.Dynamic) *Server {
	if bind == "" {
		bind = DefaultBind
	}
	s := &Server{
		balancers:    balancers,
		startTime:    time.Now(),
		apiKey:       apiKey,
		apiKeySum:    sha256.Sum256([]byte(apiKey)),
		dynDeny:      dynDeny,
		bind:         parseBind(bind),
		authFailures: make(map[string]*authAttempt),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/stats", s.authenticate(s.handleStats))
	mux.HandleFunc("/api/v1/backends", s.authenticate(s.handleBackends))
	mux.HandleFunc("/api/v1/backends/", s.authenticate(s.handleBackendAction))
	mux.HandleFunc("/api/v1/denylist", s.authenticate(s.handleDenylist))

	// Before routing: the peer and Host checks, then the browser cross-origin
	// (CSRF) check, which refuses a state-changing request that a browser
	// marks cross-site (Sec-Fetch-Site) or whose Origin is not this host.
	// Clients that send neither header (curl, ngris-sentinel) pass it.
	s.httpServer = &http.Server{
		Addr:              bind,
		Handler:           s.guard(http.NewCrossOriginProtection().Handler(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	return s
}

// guard enforces, for every request: a loopback peer when the API is bound
// to loopback, and a Host header naming the bind address (DNS-rebinding
// defense: a page on attacker.example that re-resolves to this address
// still sends Host: attacker.example).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.bind.loopback {
			ip := net.ParseIP(peerIP(r))
			if ip == nil || !ip.IsLoopback() {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		if !s.hostAllowed(r.Host) {
			logging.Debug("[ADMIN] Rejected request from %s: Host %q is not the admin bind address", r.RemoteAddr, clip(r.Host, 100))
			http.Error(w, "Forbidden: the Host header must be the admin bind address", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostAllowed reports whether a request's Host header names this server:
//   - bound to every address: any IP literal, or localhost;
//   - bound to loopback: localhost or a loopback IP literal;
//   - bound to an IP: that IP;
//   - bound to a hostname: that hostname.
//
// The port is not compared. A DNS-rebinding page always carries its own
// hostname, which none of these accept.
func (s *Server) hostAllowed(hostport string) bool {
	h := hostOnly(hostport)
	if h == "" {
		return false
	}
	ip := net.ParseIP(h)
	switch {
	case s.bind.wildcard:
		return ip != nil || h == "localhost"
	case s.bind.loopback:
		return h == "localhost" || (ip != nil && ip.IsLoopback())
	case s.bind.ip != nil:
		return ip != nil && ip.Equal(s.bind.ip)
	default:
		return h == s.bind.host
	}
}

// hostOnly returns the lower-cased host of a Host header value, without the
// port or IPv6 brackets.
func hostOnly(hostport string) string {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	} else {
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	return strings.ToLower(h)
}

// peerIP is the TCP peer's address without the port.
func peerIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// authenticate wraps a handler with API key authentication, then requires a
// JSON body on state-changing requests.
//
// The key is checked first and a valid key is always served. A failure is
// counted per source IP; once authFailThreshold failures land within
// authFailWindow, further failures from that IP get 429 for
// authLockoutDuration.
func (s *Server) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := peerIP(r)
		if !s.validKey(r.Header.Get("X-API-Key")) {
			if retry, throttled := s.recordAuthFailure(clientIP); throttled {
				secs := int((retry + time.Second - 1) / time.Second)
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			logging.Warn("[ADMIN] Unauthorized request from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Success → clear any accumulated failures for this IP.
		s.clearAuthFailures(clientIP)

		if !jsonBodyOK(r) {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		next(w, r)
	}
}

// validKey compares key with the configured API key in constant time. With
// no key configured nothing is authorized (Start refuses that config).
func (s *Server) validKey(key string) bool {
	if s.apiKey == "" {
		return false
	}
	sum := sha256.Sum256([]byte(key))
	return subtle.ConstantTimeCompare(sum[:], s.apiKeySum[:]) == 1
}

// jsonBodyOK requires Content-Type: application/json on every request that
// can change state (POST, PUT, PATCH, a DELETE with a body), including the
// body-less backend actions. An HTML form can only send form or text
// encodings, so a form-based cross-site POST is refused even if a browser
// skipped the cross-origin check. A body-less DELETE (target in ?cidr=)
// needs no Content-Type: browsers never send DELETE cross-site without a
// CORS preflight, which this API never grants.
func jsonBodyOK(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	case http.MethodDelete:
		if r.ContentLength == 0 {
			return true
		}
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// recordAuthFailure counts a failed attempt from ip and reports whether to
// throttle it (429) and for how long. The authFailThreshold-th failure in a
// window starts a lockout; failures during the lockout are throttled. While
// the table is full, a failure from an untracked IP is throttled without a
// record.
func (s *Server) recordAuthFailure(ip string) (retryAfter time.Duration, throttled bool) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	now := time.Now()
	if now.Sub(s.lastPrune) >= authPruneInterval {
		s.pruneAuthFailuresLocked(now)
	}

	a := s.authFailures[ip]
	if a != nil && now.Before(a.lockedUntil) {
		return a.lockedUntil.Sub(now), true
	}
	if a == nil || now.Sub(a.firstFailAt) > authFailWindow {
		// First failure, or window expired → start a fresh window.
		if a == nil && len(s.authFailures) >= authMaxTracked {
			if now.Sub(s.lastPrune) >= time.Second {
				s.pruneAuthFailuresLocked(now)
			}
			if len(s.authFailures) >= authMaxTracked {
				if now.Sub(s.lastFullLog) >= authPruneInterval {
					s.lastFullLog = now
					logging.Warn("[ADMIN] Failed-auth table full (%d source IPs): throttling failures from new IPs", len(s.authFailures))
				}
				return authPruneInterval, true
			}
		}
		s.authFailures[ip] = &authAttempt{failures: 1, firstFailAt: now}
		return 0, false
	}
	a.failures++
	if a.failures >= authFailThreshold {
		a.lockedUntil = now.Add(authLockoutDuration)
		logging.Warn("[ADMIN] IP %s locked out after %d failed auth attempts until %v (a valid key is still served)",
			ip, a.failures, a.lockedUntil.Format(time.RFC3339))
	}
	return 0, false
}

// pruneAuthFailuresLocked drops records whose window and lockout are both
// over. Caller holds authMu.
func (s *Server) pruneAuthFailuresLocked(now time.Time) {
	s.lastPrune = now
	for ip, a := range s.authFailures {
		if !now.Before(a.lockedUntil) && now.Sub(a.firstFailAt) > authFailWindow {
			delete(s.authFailures, ip)
		}
	}
}

// clearAuthFailures removes the failure record for an IP after a successful auth.
func (s *Server) clearAuthFailures(ip string) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	delete(s.authFailures, ip)
}

// Start validates the server's configuration and starts listening in the
// background. A missing API key or an unparsable bind is an error: the
// admin API never runs unauthenticated. A listen failure (port taken,
// address not yet up) is logged and does not stop the proxy.
func (s *Server) Start() error {
	if s.apiKey == "" {
		return errors.New("admin API: api_key is required (set admin.api_key)")
	}
	if s.bind.err != nil {
		return fmt.Errorf("admin API: %w", s.bind.err)
	}
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Error("[ADMIN] Server error: %v", err)
		}
	}()
	logging.Info("[ADMIN] API started on %s", s.httpServer.Addr)
	return nil
}

// Stop shuts down the admin server.
func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	resp := StatsResponse{
		Uptime:   time.Since(s.startTime).Round(time.Second).String(),
		Backends: len(s.currentBalancers()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleBackends(w http.ResponseWriter, r *http.Request) {
	var backends []BackendStatus
	for name := range s.currentBalancers() {
		backends = append(backends, BackendStatus{Name: name})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(backends)
}

func (s *Server) handleBackendAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := splitPath(r.URL.Path)
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	backendName := parts[3]
	action := parts[4]

	balancer, ok := s.currentBalancers()[backendName]
	if !ok {
		http.Error(w, "Backend not found", http.StatusNotFound)
		return
	}

	server := r.URL.Query().Get("server")
	if server == "" {
		http.Error(w, "server query param required", http.StatusBadRequest)
		return
	}

	switch action {
	case "drain":
		balancer.MarkDraining(server)
		logging.Info("[ADMIN] Server %s in %s marked as draining", server, backendName)
	case "enable":
		balancer.UpdateStatus(server, true)
		logging.Info("[ADMIN] Server %s in %s enabled", server, backendName)
	case "disable":
		balancer.UpdateStatus(server, false)
		logging.Info("[ADMIN] Server %s in %s disabled", server, backendName)
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": action, "server": server})
}

// denylistRequest is the POST/DELETE body for /api/v1/denylist.
type denylistRequest struct {
	IP         string `json:"ip"`          // IP or CIDR
	TTLSeconds int    `json:"ttl_seconds"` // <=0 = never expires
}

// handleDenylist manages the runtime IP/CIDR denylist:
//
//	GET    /api/v1/denylist            → list active entries
//	POST   /api/v1/denylist {ip,ttl_seconds} → add/refresh a block
//	DELETE /api/v1/denylist?cidr=<ip>  (or body {ip})  → remove a block
//
// DELETE takes the target via the ?cidr= query (or body) rather than a path
// segment so CIDRs (which contain '/') don't break path routing. A range
// wider than denylist.MinPrefixV4 / MinPrefixV6 is refused (400).
func (s *Server) handleDenylist(w http.ResponseWriter, r *http.Request) {
	if s.dynDeny == nil {
		http.Error(w, "denylist unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]any{"entries": s.dynDeny.List()})

	case http.MethodPost:
		var req denylistRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		var ttl time.Duration
		if req.TTLSeconds > 0 {
			ttl = time.Duration(req.TTLSeconds) * time.Second
		}
		ent, err := s.dynDeny.Add(req.IP, ttl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		logging.Info("[ADMIN] denylist add %s ttl=%ds (total=%d)", ent.CIDR, req.TTLSeconds, s.dynDeny.Count())
		json.NewEncoder(w).Encode(map[string]any{"status": "blocked", "entry": ent})

	case http.MethodDelete:
		cidr := r.URL.Query().Get("cidr")
		if cidr == "" {
			var req denylistRequest
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req)
			cidr = req.IP
		}
		if cidr == "" {
			http.Error(w, "cidr query param or {ip} body required", http.StatusBadRequest)
			return
		}
		existed := s.dynDeny.Remove(cidr)
		logging.Info("[ADMIN] denylist remove %s existed=%v (total=%d)", cidr, existed, s.dynDeny.Count())
		json.NewEncoder(w).Encode(map[string]any{"status": "removed", "cidr": cidr, "existed": existed})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func splitPath(path string) []string {
	var parts []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// SetBalancerSource makes the API read its backends through fn on every
// request instead of the map given to NewServer. The engine passes its
// published backend view, so a reload that adds or removes a backend never
// writes a map a request is reading.
func (s *Server) SetBalancerSource(fn func() map[string]lb.Balancer) {
	s.balancerSource = fn
}

// currentBalancers is the backend map to read for this request.
func (s *Server) currentBalancers() map[string]lb.Balancer {
	if s.balancerSource != nil {
		return s.balancerSource()
	}
	return s.balancers
}
