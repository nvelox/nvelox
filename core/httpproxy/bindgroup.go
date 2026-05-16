package httpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"nvelox/core/logging"
	"nvelox/core/tlsutil"

	"github.com/quic-go/quic-go/http3"
)

// BindGroup owns one listening socket and dispatches requests to one or more
// Sites. A "Site" today is an *HTTPServer — the per-listener bundle of
// routes, ACL, headers, error pages, etc.
//
// In Phase B (this commit) every BindGroup has exactly one Site, which means
// behaviour is identical to the pre-refactor single-listener world. Phase C
// adds multi-cert SNI dispatch for groups with multiple HTTPS sites. Phase D
// adds Host-header dispatch so the right Site handles each request.
type BindGroup struct {
	addr        string
	protocol    string // "http" or "https"
	httpServer  *http.Server
	http3Server *http3.Server
	primary     *HTTPServer // for shared TLS / HTTP3 config; first site

	// Site dispatch state. Lives behind an atomic.Pointer so ReplaceSites
	// (called by Engine.Reload on listener config changes) can swap the
	// site list without locking ServeHTTP. Reads via siteSet.Load().
	sites atomic.Pointer[siteSet]

	// Multi-cert SNI dispatch state. Same atomic-pointer pattern.
	// ReloadCerts swaps without disturbing in-flight handshakes.
	tlsState atomic.Pointer[tlsState]
}

// siteSet is the immutable snapshot of sites the bind group dispatches to.
// Pre-computed exact / wildcard / default lookup tables so pickSite is one
// map probe in the common case.
type siteSet struct {
	all         []*HTTPServer            // for iteration (cert reload etc.)
	exact       map[string]*HTTPServer   // lowercased exact server_name → site
	wildcard    []*HTTPServer            // sites with leftmost-wildcard names
	defaultSite *HTTPServer              // explicit default_server, else first site
}

// tlsState is the immutable snapshot of every site's loaded cert for
// SNI dispatch. ReloadCerts builds a fresh tlsState and atomic-stores it;
// the old one stays alive until the last in-flight handshake using it
// completes, then it's GC'd.
type tlsState struct {
	certs       []siteCert
	defaultCert *siteCert
}

// Addr returns the bind address the group is listening on. Used by
// Engine.Reload to index its BindGroups slice by bind for site swaps.
func (g *BindGroup) Addr() string { return g.addr }

// NewBindGroup creates a group bound to addr. Use AddSite to attach one or
// more *HTTPServer instances before calling Start.
func NewBindGroup(addr, protocol string) *BindGroup {
	return &BindGroup{
		addr:     addr,
		protocol: protocol,
	}
}

// AddSite attaches a Site to this group. Idempotent during initial
// construction (before Start); the first site becomes the primary and
// drives the shared TLS/HTTP3 config. After Start, prefer ReplaceSites
// for any modification — it does the atomic swap correctly.
func (g *BindGroup) AddSite(s *HTTPServer) {
	if g.primary == nil {
		g.primary = s
	}
	current := g.sites.Load()
	var all []*HTTPServer
	if current != nil {
		all = append([]*HTTPServer{}, current.all...)
	}
	all = append(all, s)
	g.sites.Store(buildSiteSet(all))
}

// siteList returns a snapshot of the currently-published sites. Returns
// an empty slice if Start hasn't been called (shouldn't happen in
// practice, but defensive against caller bugs in tests).
func (g *BindGroup) siteList() []*HTTPServer {
	ss := g.sites.Load()
	if ss == nil {
		return nil
	}
	return ss.all
}

// buildSiteSet pre-computes the exact-name lookup map, the wildcard
// candidate list, and the default site. Called every time the site list
// is modified; cheap (one pass).
func buildSiteSet(all []*HTTPServer) *siteSet {
	ss := &siteSet{
		all:   all,
		exact: make(map[string]*HTTPServer),
	}
	for _, s := range all {
		for _, name := range s.Listener.ServerNames {
			ln := strings.ToLower(name)
			if strings.HasPrefix(ln, "*.") {
				ss.wildcard = append(ss.wildcard, s)
				break // wildcard candidate; matched by tlsutil.MatchSite
			} else {
				ss.exact[ln] = s
			}
		}
		if s.Listener.DefaultServer {
			ss.defaultSite = s
		}
	}
	// Implicit default: first site if none marked default_server. Preserves
	// today's single-site behaviour.
	if ss.defaultSite == nil && len(all) > 0 {
		ss.defaultSite = all[0]
	}
	return ss
}

// Defaults preserved when a listener doesn't configure timeouts. Mirrors
// the original hard-coded http.Server values so unconfigured listeners
// keep their pre-per-listener-timeouts behavior.
const (
	defaultReadHeaderTimeout = 10 * time.Second
	defaultReadTimeout       = 60 * time.Second
	defaultWriteTimeout      = 60 * time.Second
	defaultIdleTimeout       = 120 * time.Second
)

// ServeHTTP picks the Site that owns r.Host and delegates. Single-site
// bind groups skip the lookup entirely (zero overhead for the common case).
// Per-listener Read/Write timeouts are applied here, after the site is
// known, via http.ResponseController so two sites sharing the same bind
// port can carry different request budgets.
func (g *BindGroup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ss := g.sites.Load()
	if ss == nil || len(ss.all) == 0 {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if len(ss.all) == 1 {
		applySiteDeadlines(w, ss.all[0])
		ss.all[0].ServeHTTP(w, r)
		return
	}

	host := r.Host
	// Strip port if present. IPv6 literals are bracketed; SplitHostPort
	// handles both.
	if i := strings.LastIndex(host, ":"); i != -1 {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else if !strings.Contains(host[:i], "]") {
			host = host[:i]
		}
	}

	site := g.pickSite(ss, host)
	applySiteDeadlines(w, site)
	site.ServeHTTP(w, r)
}

// applySiteDeadlines sets per-request read/write deadlines based on the
// matched site's listener.timeouts. A configured "0" yields no deadline
// (unlimited); an unconfigured field gets the bindgroup default (60s).
// Errors from SetReadDeadline / SetWriteDeadline are intentionally
// ignored — they indicate a wrapped ResponseWriter that doesn't surface
// the underlying connection (e.g., a test fake), and the request will
// still complete; we just won't enforce a per-request deadline in that
// case.
func applySiteDeadlines(w http.ResponseWriter, site *HTTPServer) {
	if site == nil {
		return
	}
	rc := http.NewResponseController(w)
	readTO := site.Listener.Timeouts.ResolveRead(defaultReadTimeout)
	writeTO := site.Listener.Timeouts.ResolveWrite(defaultWriteTimeout)
	now := time.Now()
	if readTO > 0 {
		_ = rc.SetReadDeadline(now.Add(readTO))
	} else {
		_ = rc.SetReadDeadline(time.Time{}) // explicit "unlimited"
	}
	if writeTO > 0 {
		_ = rc.SetWriteDeadline(now.Add(writeTO))
	} else {
		_ = rc.SetWriteDeadline(time.Time{})
	}
}

// resolveHeaderAndIdleTimeouts derives the http.Server-level timeouts that
// must be shared across all sites on this bind. Read-header is the slowloris
// guard for header parsing — one http.Server has a single ReadHeaderTimeout
// slot, so we take the max across sites (any site that needs more leeway
// pulls the bind up); listeners that don't configure it inherit the 10s
// default. Idle is the same shape. Both honour explicit "0" → unlimited.
func (g *BindGroup) resolveHeaderAndIdleTimeouts() (readHeader, idle time.Duration) {
	readHeader = defaultReadHeaderTimeout
	idle = defaultIdleTimeout
	anyHeader, anyIdle := false, false
	for _, s := range g.siteList() {
		if s.Listener.Timeouts.ReadHeader != "" {
			d := s.Listener.Timeouts.ParseReadHeader()
			if !anyHeader || d == 0 || (readHeader != 0 && d > readHeader) {
				readHeader = d
				anyHeader = true
			}
		}
		if s.Listener.Timeouts.Idle != "" {
			d := s.Listener.Timeouts.ParseIdle()
			if !anyIdle || d == 0 || (idle != 0 && d > idle) {
				idle = d
				anyIdle = true
			}
		}
	}
	return readHeader, idle
}

// pickSite resolves a hostname to the owning Site against the supplied
// snapshot. Precedence: exact > leftmost-wildcard > defaultSite.
// O(1) exact lookup, O(wildcards) fallback.
func (g *BindGroup) pickSite(ss *siteSet, host string) *HTTPServer {
	if host != "" {
		if site, ok := ss.exact[strings.ToLower(host)]; ok {
			return site
		}
		if len(ss.wildcard) > 0 {
			entries := make([]tlsutil.SiteEntry[*HTTPServer], 0, len(ss.wildcard))
			for _, s := range ss.wildcard {
				entries = append(entries, tlsutil.SiteEntry[*HTTPServer]{
					Patterns: s.Listener.ServerNames,
					Payload:  s,
				})
			}
			if site, ok := tlsutil.MatchSite(host, entries); ok {
				return site
			}
		}
	}
	return ss.defaultSite
}

// ReplaceSites atomically swaps the bind group's site list. Used by
// Engine.Reload to apply per-listener config changes (routes, ACL,
// headers, error pages, etc.) without dropping in-flight connections.
//
// In-flight requests that already entered an old site's ServeHTTP
// captured that pointer and run to completion. New requests see the
// new siteSet via atomic.Load.
//
// Sites that disappear from the new list have Close() called on them
// to stop their cleanup goroutines (ResponseCache, IPRateLimiter).
// Note: Close is called immediately — any request currently inside
// the dropped site still holds references to those collaborators, but
// neither cache eviction nor IP-rate-limit pruning is critical for an
// in-flight request to finish, so stopping their tickers is safe.
//
// ReplaceSites also rebuilds the TLS cert snapshot, in case site
// server_names or cert paths changed. Failures during cert load follow
// the same partial-success policy as ReloadCerts (keep prev cert).
func (g *BindGroup) ReplaceSites(newSites []*HTTPServer) error {
	if len(newSites) == 0 {
		return fmt.Errorf("bind group %s: ReplaceSites called with empty site list", g.addr)
	}
	oldSet := g.sites.Load()

	// Index old sites by listener name so we can identify which were
	// dropped and need Close().
	oldByName := make(map[string]*HTTPServer)
	if oldSet != nil {
		for _, s := range oldSet.all {
			oldByName[s.Listener.Name] = s
		}
	}

	// Publish the new site set BEFORE closing dropped sites — in-flight
	// requests should see the new set, and dropped sites' Close stops
	// background tickers but doesn't interrupt running handlers.
	g.sites.Store(buildSiteSet(newSites))

	// Primary tracks the first site; update so subsequent ReloadCerts
	// / Stop pick up the right reference for shared-TLS-profile lookups.
	g.primary = newSites[0]

	// Refresh TLS state. Per-site failures keep previous cert.
	if g.tlsState.Load() != nil {
		if _, err := g.ReloadCerts(); err != nil {
			logging.Warn("[RELOAD] bind group %s: cert refresh after ReplaceSites: %v", g.addr, err)
		}
	}

	// Close dropped sites (in old, not in new).
	newByName := make(map[string]struct{}, len(newSites))
	for _, s := range newSites {
		newByName[s.Listener.Name] = struct{}{}
	}
	for name, old := range oldByName {
		if _, kept := newByName[name]; kept {
			continue
		}
		old.Close()
	}
	return nil
}

// Start opens the listening socket and builds a TLS config that supports
// SNI-based cert selection across all sites in the group.
func (g *BindGroup) Start() error {
	if g.primary == nil {
		return fmt.Errorf("bind group %s has no sites", g.addr)
	}

	// http.Server has only one slot for ReadHeaderTimeout / IdleTimeout per
	// bind, so those are derived from the site set (max across sites, with
	// defaults). ReadTimeout / WriteTimeout are deliberately 0 here: Read
	// and Write are applied per-request from the matched site's listener
	// timeouts via http.ResponseController in ServeHTTP. ReadHeaderTimeout
	// remains the slowloris guard for the pre-routing header-parse phase.
	readHeaderTO, idleTO := g.resolveHeaderAndIdleTimeouts()
	g.httpServer = &http.Server{
		Addr:              g.addr,
		Handler:           g,
		ReadHeaderTimeout: readHeaderTO,
		IdleTimeout:       idleTO,
	}

	primary := g.primary

	if primary.Listener.TLS != nil {
		tlsCfg, err := g.buildTLSConfig()
		if err != nil {
			return err
		}
		g.httpServer.TLSConfig = tlsCfg

		// Start HTTP/3 (QUIC) if ANY site in the group enables it. The
		// shared QUIC listener uses the same multi-cert tls.Config — its
		// GetCertificate already routes by SNI. Each site that opted into
		// HTTP/3 gets its own altSvcHeader populated so its own responses
		// carry the right Alt-Svc value (sites without http3:true don't
		// advertise it).
		//
		// altSvcHeader values are written BEFORE the goroutine spawn so
		// the goroutine-create happens-before relationship covers the
		// field's first read in HTTPServer.ServeHTTP (race-detector clean).
		var anyH3 bool
		for _, s := range g.siteList() {
			if s.Listener.HTTP3 {
				s.altSvcHeader = fmt.Sprintf(`h3=":%d"; ma=86400`, s.Listener.Port)
				anyH3 = true
			}
		}
		if anyH3 {
			g.http3Server = &http3.Server{
				Addr:      g.addr,
				Handler:   g,
				TLSConfig: http3.ConfigureTLSConfig(tlsCfg.Clone()),
			}
			go func() {
				if err := g.http3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logging.Error("[HTTP3] Server error: %v", err)
				}
			}()
			logging.Info("[HTTP3] QUIC listener started on %s", g.addr)
		}

		go func() {
			ln, err := tls.Listen("tcp", g.addr, g.httpServer.TLSConfig)
			if err != nil {
				logging.Error("[HTTP] TLS listen failed on %s: %v", g.addr, err)
				return
			}
			if err := g.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
				logging.Error("[HTTP] Server error: %v", err)
			}
		}()
	} else {
		go func() {
			if err := g.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logging.Error("[HTTP] Server error: %v", err)
			}
		}()
	}

	return nil
}

// siteCert pairs one loaded TLS certificate with the server_names patterns
// the owning Site claims. Built once at Start time; consulted on every
// ClientHello via the GetCertificate callback.
type siteCert struct {
	patterns []string
	cert     *tls.Certificate
	site     *HTTPServer
}

// buildTLSConfig constructs the shared *tls.Config for the group and
// publishes the initial cert snapshot via tlsState.Store. Subsequent
// reloads can swap the snapshot atomically without rebuilding tls.Config.
//
// GetCertificate uses tlsState.Load — lock-free on the handshake hot path.
// MinVersion / MaxVersion / CipherSuites come from the PRIMARY site
// (same TLS profile across sites in a group). NextProtos forces h2 +
// http/1.1 ALPN on every site.
func (g *BindGroup) buildTLSConfig() (*tls.Config, error) {
	state, err := g.loadCertState()
	if err != nil {
		return nil, err
	}
	g.tlsState.Store(state)

	tlsCfg := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		// Set Certificates to a single-element slice so callers/tooling that
		// inspect c.Certificates see something sensible. The actual cert
		// served at handshake time comes from GetCertificate below.
		Certificates: []tls.Certificate{*state.defaultCert.cert},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return g.pickCert(chi.ServerName), nil
		},
	}
	if err := tlsutil.ApplyTLSVersionAndCiphers(tlsCfg, *g.primary.Listener.TLS); err != nil {
		return nil, fmt.Errorf("TLS bind group %s: %v", g.addr, err)
	}
	return tlsCfg, nil
}

// loadCertState walks the group's sites and reads each TLS cert/key from
// disk. Returns a fresh tlsState ready to publish, or an error if any
// site's cert fails to load. Used both at Start and by ReloadCerts.
//
// Note: all-or-nothing during initial Start — if any cert is broken at
// startup we refuse to listen. ReloadCerts handles partial failure
// differently (keeps the prior cert for that site).
func (g *BindGroup) loadCertState() (*tlsState, error) {
	sites := g.siteList()
	if len(sites) == 0 {
		return nil, fmt.Errorf("bind group %s: no sites", g.addr)
	}
	certs := make([]siteCert, 0, len(sites))
	var defaultCert *siteCert
	for _, s := range sites {
		if s.Listener.TLS == nil || s.Listener.TLS.Cert == "" {
			continue
		}
		warnIfKeyWorldReadable(s.Listener.TLS.Key)
		cert, err := tls.LoadX509KeyPair(s.Listener.TLS.Cert, s.Listener.TLS.Key)
		if err != nil {
			return nil, fmt.Errorf("site %s: failed to load TLS cert/key: %v", s.Listener.Name, err)
		}
		certs = append(certs, siteCert{
			patterns: s.Listener.ServerNames,
			cert:     &cert,
			site:     s,
		})
		if s.Listener.DefaultServer || defaultCert == nil {
			c := certs[len(certs)-1]
			defaultCert = &c
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("bind group %s: no TLS-enabled sites", g.addr)
	}
	return &tlsState{certs: certs, defaultCert: defaultCert}, nil
}

// ReloadCerts re-reads every site's TLS cert from disk and atomically
// publishes a new tlsState. The TLS handshake hot path is unaffected:
// in-flight handshakes complete against the old snapshot, new handshakes
// see the new one.
//
// Per-site failure is isolated. If a single cert fails to load (file
// missing, expired, corrupt), that site keeps its previous cert from
// the current snapshot and we log the failure. Operators get a partial
// reload rather than nothing.
//
// Returns the number of certs that were actually rotated (i.e. their
// raw bytes changed). Zero means no-op; logging.Info can show the count.
func (g *BindGroup) ReloadCerts() (int, error) {
	prev := g.tlsState.Load()
	if prev == nil {
		// No initial snapshot — bind group never started. Caller bug.
		return 0, fmt.Errorf("bind group %s: ReloadCerts before Start", g.addr)
	}

	// Index the previous state by site name for fallback on per-site failure.
	prevByName := make(map[string]siteCert, len(prev.certs))
	for _, c := range prev.certs {
		if c.site != nil {
			prevByName[c.site.Listener.Name] = c
		}
	}

	sites := g.siteList()
	certs := make([]siteCert, 0, len(sites))
	var defaultCert *siteCert
	rotated := 0
	for _, s := range sites {
		if s.Listener.TLS == nil || s.Listener.TLS.Cert == "" {
			continue
		}
		warnIfKeyWorldReadable(s.Listener.TLS.Key)
		cert, err := tls.LoadX509KeyPair(s.Listener.TLS.Cert, s.Listener.TLS.Key)
		if err != nil {
			old, ok := prevByName[s.Listener.Name]
			if !ok {
				return rotated, fmt.Errorf("site %s: cert reload failed and no previous cert to fall back to: %v",
					s.Listener.Name, err)
			}
			logging.Warn("[TLS] site %s: cert reload failed, keeping previous cert: %v",
				s.Listener.Name, err)
			certs = append(certs, old)
		} else {
			if old, ok := prevByName[s.Listener.Name]; ok && !certBytesEqual(old.cert, &cert) {
				rotated++
			} else if !ok {
				rotated++ // new site since last load
			}
			certs = append(certs, siteCert{
				patterns: s.Listener.ServerNames,
				cert:     &cert,
				site:     s,
			})
		}
		if s.Listener.DefaultServer || defaultCert == nil {
			c := certs[len(certs)-1]
			defaultCert = &c
		}
	}
	if len(certs) == 0 {
		return 0, fmt.Errorf("bind group %s: no TLS-enabled sites after reload", g.addr)
	}

	g.tlsState.Store(&tlsState{certs: certs, defaultCert: defaultCert})
	return rotated, nil
}

// certBytesEqual reports whether two loaded certs carry the same DER bytes.
// Used by ReloadCerts to count actual rotations vs. no-ops. Comparing the
// raw Certificate slice (the chain) is sufficient — if any byte changed,
// the cert changed.
func certBytesEqual(a, b *tls.Certificate) bool {
	if a == nil || b == nil || len(a.Certificate) != len(b.Certificate) {
		return false
	}
	for i := range a.Certificate {
		if len(a.Certificate[i]) != len(b.Certificate[i]) {
			return false
		}
		for j := range a.Certificate[i] {
			if a.Certificate[i][j] != b.Certificate[i][j] {
				return false
			}
		}
	}
	return true
}

// pickCert resolves an SNI hostname to the cert that should be served.
// Exact match > wildcard > default site's cert. If sni is empty (e.g.
// IP-only TLS connect with no SNI), we still return the default — same
// as nginx and any L7 proxy.
func (g *BindGroup) pickCert(sni string) *tls.Certificate {
	state := g.tlsState.Load()
	if state == nil {
		return nil
	}
	if sni == "" {
		if state.defaultCert != nil {
			return state.defaultCert.cert
		}
		return nil
	}
	entries := make([]tlsutil.SiteEntry[*tls.Certificate], 0, len(state.certs))
	for i := range state.certs {
		entries = append(entries, tlsutil.SiteEntry[*tls.Certificate]{
			Patterns: state.certs[i].patterns,
			Payload:  state.certs[i].cert,
		})
	}
	if cert, ok := tlsutil.MatchSite(sni, entries); ok {
		return cert
	}
	if state.defaultCert != nil {
		return state.defaultCert.cert
	}
	return nil
}

// Stop gracefully shuts the group's HTTP and HTTP/3 listeners.
func (g *BindGroup) Stop(ctx context.Context) error {
	if g.http3Server != nil {
		g.http3Server.Close()
	}
	if g.httpServer != nil {
		return g.httpServer.Shutdown(ctx)
	}
	return nil
}
