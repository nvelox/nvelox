package httpproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/nvelox/ngx/web"

	"nvelox/core/httppath"
	"nvelox/core/httpproxy/errorhtml"
	"nvelox/core/logging"
	"nvelox/core/metrics"
	"nvelox/proxy"
)

// The event loops log where nvelox logs, write its access log, take the
// canonical form of a path from the function the access rules use, and
// answer with nvelox's error pages and within server.http3's limits.
func init() {
	web.SetHooks(web.Hooks{
		Errorf:             logging.Error,
		Warnf:              logging.Warn,
		Debugf:             logging.Debug,
		AccessHead:         logging.AppendAccessHTTPHead,
		AccessMid:          logging.AppendAccessHTTPMid,
		AccessTail:         logging.AppendAccessHTTPTail,
		WriteAccess:        logging.WriteAccess,
		CanonicalPath:      httppath.Canonical,
		ErrorPage:          errorhtml.DefaultErrorPage,
		H3Limits:           fastH3Limits,
		H3HandshakeRefused: h3HandshakeRefused,
	})
}

// h3RefusedPerSource counts the first packets of QUIC clients the event
// loops dropped because their address had server.http3.handshakes_per_source
// handshakes running.
var h3RefusedPerSource = metrics.Default.GetCounter("nvelox_h3_handshakes_refused_total", map[string]string{"reason": "per_source"})

// h3HandshakeRefused counts a QUIC client's first packet an event loop
// dropped, by the reason the loop gives (Hooks.H3HandshakeRefused).
func h3HandshakeRefused(reason string) {
	if reason == "per_source" {
		h3RefusedPerSource.Inc()
	}
}

// This file is a bind group's side of its server on the event loops (the
// server of package web of the ngx module): how the server is made, started and stopped,
// the answers to what it asks while it serves (fastHost), and each site in
// the form the loops take it (web.Site), built from its configuration.

// fastPathEnabled reports whether bind groups serve through the event loops.
func fastPathEnabled() bool { return web.Supported() && !fastPathOff.Load() }

// fastPathOff turns the event loops off for bind groups started from now
// on (tests compare them with the net/http path).
var fastPathOff atomic.Bool

// h3OnLoops serves a group's HTTP/3 from the event loops too, on the QUIC
// transport of the ngx module, in place of the quic-go server, which
// serves it where there are no event loops. A variable for the tests,
// which also run what the quic-go server does: nothing else sets it.
var h3OnLoops = true

// newFast makes the group's server on the event loops for its bound socket
// ln: an HTTPS one when the group has a TLS configuration. It serves once
// serveFast is called.
func (g *BindGroup) newFast(ln net.Listener, readHeader, idle time.Duration) error {
	cfg := web.Config{
		Name:              g.addr,
		ReadHeaderTimeout: readHeader,
		IdleTimeout:       idle,
		TLS:               g.tlsBase,
		Slow:              g.httpServer,
		Host:              fastHost{g},
		Relays:            fastHost{g},
	}
	fs, err := web.NewServer(ln, cfg)
	if err != nil {
		return fmt.Errorf("listen %s: %w", g.addr, err)
	}
	if cfg.TLS != nil {
		// A TLS connection the loops hand over brings its TLS state with
		// it, for its requests (ServeHTTP).
		g.httpServer.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			return web.HandoffContext(g.connContext(ctx, c), c)
		}
	}
	g.fast = fs
	return nil
}

// dropFast gives up the group's server on the event loops before it served
// (Start failed after making it).
func (g *BindGroup) dropFast() {
	if fs := g.fast; fs != nil {
		g.fast, g.h3loops = nil, nil
		fs.Abandon()
	}
}

// serveFast starts the group's server on the event loops once the group
// serves (the serve gate), and net/http's server for the connections the
// loops hand over.
func (g *BindGroup) serveFast() {
	fs := g.fast
	go func() {
		if !g.serveGate.Wait(g.gateDone) {
			fs.Abandon()
			return
		}
		fs.Serve()
		if err := g.httpServer.Serve(fs.Handoff()); err != nil && err != http.ErrServerClosed {
			logging.Error("[HTTP] Server error: %v", err)
		}
	}()
}

// fastHost is a bind group as its server on the event loops asks it: which
// site a request is for (Host), and what a trusted relay's PROXY header
// says (Relays).
type fastHost struct{ g *BindGroup }

// Site returns the site that serves a request for host (a Host header
// value) as the event loops serve it; nil when the request is net/http's:
// the group has no site, or the site has something only the net/http path
// implements.
func (h fastHost) Site(host string) *web.Site {
	ss := h.g.sites.Load()
	if ss == nil || len(ss.all) == 0 {
		return nil
	}
	site := h.g.siteForHost(ss, host)
	if site.fastIneligible() {
		return nil
	}
	return site.fastSite()
}

// HandsOverTLS: a group with a site that asks for client certificates
// keeps its TLS connections with net/http, which checks them per request.
func (h fastHost) HandsOverTLS() bool { return h.g.anyClientAuth() }

// anyClientAuth reports whether a site of the group asks for client
// certificates.
func (g *BindGroup) anyClientAuth() bool {
	ss := g.sites.Load()
	if ss == nil {
		return false
	}
	for _, s := range ss.all {
		if s.Listener.ClientAuth != nil || (s.Listener.TLS != nil && clientAuthConfigured(s.Listener.TLS.ClientAuth)) {
			return true
		}
	}
	return false
}

// ConnContext: the requests of an HTTP/2 or HTTP/3 connection that
// net/http's handlers serve go to send_proxy_v2 backends over backend
// connections of the client connection's own (proxysend.go), closed with
// it. They name the client's address as it is when they are opened.
func (h fastHost) ConnContext(ctx context.Context, addrs func() (client, local net.Addr)) (context.Context, func()) {
	cb := &clientBackends{live: addrs}
	return withClientBackends(ctx, cb), cb.closeFromLoop
}

// Trusted: a relay the group's listener trusts (accept_proxy_from) sends a
// PROXY header first.
func (h fastHost) Trusted(peer net.IP) bool { return h.g.proxyTrust().TrustsIP(peer) }

// Header parses the PROXY v2 header at the start of a trusted relay's
// plain-HTTP connection; one that does not pass (malformed, a bad
// signature) is counted and the connection closed.
func (h fastHost) Header(relay, local netip.AddrPort, data []byte) (int, *net.TCPAddr) {
	done, hdr, consumed, perr := proxy.ParseStreamStrict(data)
	if !done {
		return 0, nil
	}
	client, reason, cause := proxyClient(h.g.proxyTrust(), hdr, perr, proxy.Ends{Relay: relay, Receiver: local})
	if reason != "" {
		h.g.proxyRejected(net.TCPAddrFromAddrPort(relay), reason, cause)
		return -1, nil
	}
	return consumed, client
}

// Failed counts a relay's connection that ended before its header was in.
func (h fastHost) Failed(relay net.IP, how web.RelayFailure) {
	addr := &net.TCPAddr{IP: relay}
	switch how {
	case web.RelayHeaderTooLong:
		h.g.proxyRejected(addr, proxyRejectMalformed, proxy.ErrBadHeader)
	case web.RelayHeaderCut:
		h.g.proxyRejected(addr, proxyRejectMalformed, io.ErrUnexpectedEOF)
	case web.RelayHeaderLate:
		h.g.proxyRejected(addr, proxyRejectTimeout, nil)
	}
}

// Read reads the PROXY header of a trusted relay's TLS connection, which
// comes before the ClientHello.
func (h fastHost) Read(c net.Conn) (*net.TCPAddr, bool) {
	remote := c.RemoteAddr()
	tr := h.g.proxyTrust()
	if !tr.Trusts(remote) {
		return nil, true
	}
	hdr, err := proxy.ReadStreamHeader(c)
	client, reason, cause := proxyClient(tr, hdr, err, proxy.ReceiverEnds(c.LocalAddr(), remote))
	if reason != "" {
		h.g.proxyRejected(remote, reason, cause)
		return nil, false
	}
	return client, true
}

// Datagram: a datagram from a relay the listener trusts must begin with
// the relay's signed header (h3relay.go): it is checked and taken off, and
// the client it names goes with the datagram; what does not pass is dropped
// and counted. The relays are the ones the group trusts now: a reload that
// changes them applies at once. state holds the socket's pins: the client
// each relay socket that sends to it stands for.
func (h fastHost) Datagram(state *any, from netip.AddrPort, to web.Dest, d []byte, now int64) ([]byte, netip.AddrPort, bool) {
	tr := h.g.proxyTrust()
	if !tr.Enabled() || !trustsAddr(tr, from.Addr()) {
		return d, netip.AddrPort{}, true
	}
	payload, client, counter, counted, reason, cause := h3RelayHeader(tr, d, proxy.Ends{Relay: from, Receiver: to.AddrPort()})
	if reason == "" {
		pins, _ := (*state).(*h3Pins)
		if pins == nil {
			pins = &h3Pins{}
			*state = pins
		}
		reason, cause = pins.pin(from, client, now, counter, counted)
	}
	if reason != "" {
		h.g.proxyRejected(net.UDPAddrFromAddrPort(from), reason, cause)
		return nil, netip.AddrPort{}, false
	}
	return payload, client, true
}

// ClientChanged counts a datagram dropped because its relay socket stands
// for another client than the one its connection began with (or stopped,
// or began, being a relay's).
func (h fastHost) ClientChanged(relay netip.AddrPort) {
	h.g.proxyRejected(net.UDPAddrFromAddrPort(relay), h3RelayClientChanged, errH3RelayClientChanged)
}

// fastSite returns the site as the event loops serve it, built on first
// use. A reload builds new site instances, and each builds its own.
func (s *HTTPServer) fastSite() *web.Site {
	if fs := s.fastCfg.Load(); fs != nil {
		return fs
	}
	s.fastCfg.CompareAndSwap(nil, s.buildFastSite())
	return s.fastCfg.Load()
}

func (s *HTTPServer) buildFastSite() *web.Site {
	fs := &web.Site{
		AccessLog:      true,
		ReadTimeout:    defaultReadTimeout,
		WriteTimeout:   defaultWriteTimeout,
		TrustedProxies: s.TrustedProxies,
		AltSvc:         s.altSvcHeader,
		MaxBodySize:    s.MaxBodySize,
		Admit:          s.admit,
		ErrorPages:     s.ErrorPages,
		Backends:       make(map[string]*web.Backend),
	}
	if l := s.Listener; l != nil {
		fs.Name = l.Name
		fs.AccessLog = !l.AccessLogOff
		fs.ReadTimeout = l.Timeouts.ResolveRead(defaultReadTimeout)
		fs.WriteTimeout = l.Timeouts.ResolveWrite(defaultWriteTimeout)
		fs.RequestID, fs.TrustRequestID = l.RequestID.Enabled, l.RequestID.TrustInbound
		h := &l.Headers
		fs.RequestRules = web.HeaderRules(h.RequestAdd, h.RequestSet, h.RequestRemove, true)
		fs.ResponseRules = web.HeaderRules(h.ResponseAdd, h.ResponseSet, h.ResponseRemove, false)
	}
	if s.router != nil {
		fs.DefaultBackend = s.router.defaultBackend
		for i := range s.router.routes {
			r := &s.router.routes[i]
			fs.Routes = append(fs.Routes, web.Route{
				Host:       r.host,
				PathPrefix: r.pathPrefix,
				PathRegex:  r.pathRegex,
				Backend:    r.backend,
				Rewrite:    r.rewrite.Path,
				// Static files, FastCGI, redirects, try_files and expires
				// are net/http's.
				Slow: r.static.Root != "" || r.fastcgi.Pass != "" || r.redirect.URL != "" ||
					len(r.tryFiles.Files) > 0 || r.expires != "",
				RequestRules:  web.HeaderRules(r.headers.RequestAdd, r.headers.RequestSet, r.headers.RequestRemove, true),
				ResponseRules: web.HeaderRules(r.headers.ResponseAdd, r.headers.ResponseSet, r.headers.ResponseRemove, false),
			})
		}
	}
	// Every name a request can be sent to has a balancer. (A name without
	// one is answered 502 on either path, whatever else is known of it.)
	for name := range s.Balancers {
		fs.Backends[name] = s.fastBackend(name)
	}
	return fs
}

// fastBackend returns the site's backend name as the event loops use it.
func (s *HTTPServer) fastBackend(name string) *web.Backend {
	be := s.Backends[name] // nil: a backend without a configuration entry
	b := &web.Backend{
		Name:           name,
		Balancer:       s.Balancers[name],
		ConnLimiter:    s.ConnLimiters[name],
		Breaker:        s.CircuitBreakers[name],
		Health:         s.PassiveHealth[name],
		SilenceTimeout: backendSilenceLimit(be),
	}
	b.ConnectTimeout, b.ResponseHeaderTimeout = backendTimeouts(s.Listener, be)
	p := newRetryPolicy(be)
	b.Retry = web.Retry{Attempts: p.attempts, OnConnectFailure: p.onConnectFailure, On502: p.on502, On503: p.on503}
	// Sticky sessions are net/http's.
	if _, ok := s.StickyStores[name]; ok || (be != nil && be.StickySession.Type != "") {
		b.Slow = true
	}
	if be != nil && be.BackendTLS.Enabled {
		// TLS to the backend runs on the loops. net/http keeps a backend
		// whose TLS configuration could not be built: it answers 502,
		// never plaintext.
		if b.TLS = s.backendFastTLS[name]; b.TLS == nil {
			b.Slow = true
		}
	}
	if sendsProxy(be) {
		b.ProxyHeaderVaries = len(be.SendProxyKey) > 0 // a signed header carries its time
		b.ProxyHeader = func(client, local net.Addr, from, to netip.AddrPort) ([]byte, error) {
			if key := be.SendProxyKey; len(key) > 0 {
				// from and to: the connection to the server, which a
				// signed header is bound to (ProxyHeaderVaries).
				if !from.IsValid() || !to.IsValid() {
					return nil, errProxyAddr
				}
				return backendProxyHeader(client, local, key, time.Now(), proxy.Ends{Relay: from, Receiver: to})
			}
			return backendProxyHeader(client, local, nil, time.Time{}, proxy.Ends{})
		}
	}
	return b
}

// fastIneligible reports whether the site has something only the net/http
// path implements; its requests are then handed to net/http. Read per
// request from the live fields.
func (s *HTTPServer) fastIneligible() bool {
	l := s.Listener
	return s.ResponseCache != nil || l == nil || l.Compression.Enabled ||
		l.ClientAuth != nil || (l.TLS != nil && clientAuthConfigured(l.TLS.ClientAuth))
}

// admit is the gates of ServeHTTP that come before a request is proxied,
// for a request on the event loops: the deny and allow lists, the rate
// limits and the access rules, in that order. 0 lets the request through;
// any other status answers it.
func (s *HTTPServer) admit(r *web.Request) int {
	if st := s.clientStatusIP(r.ClientIP()); st != 0 {
		return st
	}
	if s.RateLimiter != nil && !s.RateLimiter.Allow() {
		return http.StatusTooManyRequests
	}
	if s.IPRateLimiter != nil && !s.IPRateLimiter.Allow(r.Client) {
		return http.StatusTooManyRequests
	}
	if s.ACLEngine != nil {
		if action, status := s.ACLEngine.Decide(r.Method, r.Path, r, r.ClientIP()); action == "deny" {
			if status == 0 {
				status = http.StatusForbidden
			}
			return status
		}
	}
	return 0
}

// clientStatusIP is clientStatus for a parsed client address.
func (s *HTTPServer) clientStatusIP(ip net.IP) int {
	if ip == nil {
		return 0
	}
	if len(s.IPDenylist) > 0 && ipInNets(ip, s.IPDenylist) {
		return http.StatusForbidden
	}
	if s.DynDenylist != nil && !s.DynDenylist.Empty() && s.DynDenylist.Blocked(ip) {
		return http.StatusForbidden
	}
	if len(s.IPAllowlist) > 0 && !ipInNets(ip, s.IPAllowlist) {
		return http.StatusForbidden
	}
	return 0
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
