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

// Start opens the listening socket and (if HTTPS) loads the primary site's
// TLS config. http.Server.Handler is set to the BindGroup so dispatch goes
// through ServeHTTP.
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
		warnIfKeyWorldReadable(primary.Listener.TLS.Key)
		cert, err := tls.LoadX509KeyPair(primary.Listener.TLS.Cert, primary.Listener.TLS.Key)
		if err != nil {
			return fmt.Errorf("failed to load TLS cert/key: %v", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}
		if err := tlsutil.ApplyTLSVersionAndCiphers(tlsCfg, *primary.Listener.TLS); err != nil {
			return fmt.Errorf("TLS listener %s: %v", primary.Listener.Name, err)
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
