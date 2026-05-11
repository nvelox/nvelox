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
	sites       []*HTTPServer
	primary     *HTTPServer // for shared TLS / HTTP3 config; first site for now

	// Multi-cert SNI dispatch state. Lives behind an atomic.Pointer so
	// ReloadCerts can swap it without disturbing in-flight handshakes —
	// the GetCertificate callback does a Load() on every ClientHello,
	// which is lock-free.
	tlsState atomic.Pointer[tlsState]
}

// tlsState is the immutable snapshot of every site's loaded cert for
// SNI dispatch. ReloadCerts builds a fresh tlsState and atomic-stores it;
// the old one stays alive until the last in-flight handshake using it
// completes, then it's GC'd.
type tlsState struct {
	certs       []siteCert
	defaultCert *siteCert
}

// NewBindGroup creates a group bound to addr. Use AddSite to attach one or
// more *HTTPServer instances before calling Start.
func NewBindGroup(addr, protocol string) *BindGroup {
	return &BindGroup{
		addr:     addr,
		protocol: protocol,
	}
}

// AddSite attaches a Site (an *HTTPServer) to this group. The first site
// added becomes the "primary" — its TLS / HTTP3 config drives the shared
// listener until Phase C teaches the group to merge multiple certs.
func (g *BindGroup) AddSite(s *HTTPServer) {
	g.sites = append(g.sites, s)
	if g.primary == nil {
		g.primary = s
	}
}

// ServeHTTP picks the Site that owns r.Host and delegates. Strategy:
//   1. Strip port from Host.
//   2. Try exact match against any site's ServerNames, then leftmost-wildcard.
//   3. Fall back to the site marked DefaultServer; else the first site.
//
// Single-site bind groups skip the lookup entirely — keeps overhead at zero
// for the common case.
func (g *BindGroup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(g.sites) == 1 {
		g.sites[0].ServeHTTP(w, r)
		return
	}

	host := r.Host
	// Strip port if present (Host can be "api.foo.com:8443").
	if i := strings.LastIndex(host, ":"); i != -1 {
		// IPv6 literals come bracketed: "[::1]:8443" — only strip after the bracket.
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else if !strings.Contains(host[:i], "]") {
			host = host[:i]
		}
	}

	site := g.pickSite(host)
	site.ServeHTTP(w, r)
}

// pickSite resolves a hostname to the owning Site. Mirrors pickCert's
// precedence: exact > wildcard > default > first.
func (g *BindGroup) pickSite(host string) *HTTPServer {
	if host != "" && len(g.sites) > 1 {
		entries := make([]tlsutil.SiteEntry[*HTTPServer], 0, len(g.sites))
		for _, s := range g.sites {
			entries = append(entries, tlsutil.SiteEntry[*HTTPServer]{
				Patterns: s.Listener.ServerNames,
				Payload:  s,
			})
		}
		if site, ok := tlsutil.MatchSite(host, entries); ok {
			return site
		}
	}
	// Fallback: explicit default_server, else primary (first site).
	for _, s := range g.sites {
		if s.Listener.DefaultServer {
			return s
		}
	}
	return g.primary
}

// Start opens the listening socket and builds a TLS config that supports
// SNI-based cert selection across all sites in the group.
func (g *BindGroup) Start() error {
	if g.primary == nil {
		return fmt.Errorf("bind group %s has no sites", g.addr)
	}

	g.httpServer = &http.Server{
		Addr:         g.addr,
		Handler:      g,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
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
		for _, s := range g.sites {
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
	if len(g.sites) == 0 {
		return nil, fmt.Errorf("bind group %s: no sites", g.addr)
	}
	certs := make([]siteCert, 0, len(g.sites))
	var defaultCert *siteCert
	for _, s := range g.sites {
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

	certs := make([]siteCert, 0, len(g.sites))
	var defaultCert *siteCert
	rotated := 0
	for _, s := range g.sites {
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
