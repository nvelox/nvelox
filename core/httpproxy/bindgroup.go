package httpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
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

	// Multi-cert dispatch state, populated by buildTLSConfig at Start.
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

// ServeHTTP routes the request to a Site. Phase B: always primary. Phase D
// will replace this with Host-based dispatch using server_names.
func (g *BindGroup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.primary.ServeHTTP(w, r)
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

		// Start HTTP/3 (QUIC) if enabled. altSvcHeader is written BEFORE
		// the goroutine spawn so the goroutine-create happens-before
		// covers the field's first read in ServeHTTP.
		if primary.Listener.HTTP3 {
			primary.altSvcHeader = fmt.Sprintf(`h3=":%d"; ma=86400`, primary.Listener.Port)
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

// buildTLSConfig constructs the shared *tls.Config for the group:
//   - Loads every site's cert/key once at startup.
//   - GetCertificate picks by SNI: exact match wins, then wildcard, then
//     the default site's cert. No match + no default → handshake error
//     (Go's tls package treats nil cert + nil err as "no cert available").
//   - MinVersion / MaxVersion / CipherSuites come from the PRIMARY site
//     (Phase C constraint — same TLS profile across sites in a group).
//   - NextProtos forces h2 + http/1.1 ALPN on every site.
func (g *BindGroup) buildTLSConfig() (*tls.Config, error) {
	if len(g.sites) == 0 {
		return nil, fmt.Errorf("bind group %s: no sites", g.addr)
	}

	// Load each site's cert.
	certs := make([]siteCert, 0, len(g.sites))
	var defaultCert *siteCert
	for _, s := range g.sites {
		if s.Listener.TLS == nil || s.Listener.TLS.Cert == "" {
			// HTTP-only site in a group with TLS sites — handled at validation
			// time. Defensive: skip rather than panic.
			continue
		}
		warnIfKeyWorldReadable(s.Listener.TLS.Key)
		cert, err := tls.LoadX509KeyPair(s.Listener.TLS.Cert, s.Listener.TLS.Key)
		if err != nil {
			return nil, fmt.Errorf("site %s: failed to load TLS cert/key: %v", s.Listener.Name, err)
		}
		entry := siteCert{
			patterns: s.Listener.ServerNames,
			cert:     &cert,
			site:     s,
		}
		certs = append(certs, entry)
		if s.Listener.DefaultServer || defaultCert == nil {
			// First site is the implicit default if no DefaultServer is set,
			// preserving today's behaviour for single-site bind groups.
			c := certs[len(certs)-1]
			defaultCert = &c
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("bind group %s: no TLS-enabled sites", g.addr)
	}
	g.certs = certs
	g.defaultCert = defaultCert

	tlsCfg := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		// Set Certificates to a single-element slice so callers/tooling that
		// inspect c.Certificates see something sensible. The actual cert
		// served at handshake time comes from GetCertificate below.
		Certificates: []tls.Certificate{*defaultCert.cert},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return g.pickCert(chi.ServerName), nil
		},
	}
	if err := tlsutil.ApplyTLSVersionAndCiphers(tlsCfg, *g.primary.Listener.TLS); err != nil {
		return nil, fmt.Errorf("TLS bind group %s: %v", g.addr, err)
	}
	return tlsCfg, nil
}

// pickCert resolves an SNI hostname to the cert that should be served.
// Exact match > wildcard > default site's cert. If sni is empty (e.g.
// IP-only TLS connect with no SNI), we still return the default — same
// as nginx and any L7 proxy.
func (g *BindGroup) pickCert(sni string) *tls.Certificate {
	if sni == "" {
		if g.defaultCert != nil {
			return g.defaultCert.cert
		}
		return nil
	}
	entries := make([]tlsutil.SiteEntry[*tls.Certificate], 0, len(g.certs))
	for i := range g.certs {
		entries = append(entries, tlsutil.SiteEntry[*tls.Certificate]{
			Patterns: g.certs[i].patterns,
			Payload:  g.certs[i].cert,
		})
	}
	if cert, ok := tlsutil.MatchSite(sni, entries); ok {
		return cert
	}
	if g.defaultCert != nil {
		return g.defaultCert.cert
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
