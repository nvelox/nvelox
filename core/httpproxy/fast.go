package httpproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"nvelox/config"
	"nvelox/core/httppath"
	"nvelox/core/httpproxy/errorhtml"
)

// This file holds the platform-independent parts of the HTTP/1.1 fast path
// (fast_linux.go): what a site lets it do, the header rules in the form it
// applies them, and helpers that mirror net/http and net/url exactly.

// bstr views b as a string for a lookup that does not keep it.
func bstr(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

// fastSiteConfig is what the fast path needs of a site beyond its live
// fields: its header rules (sanitized and in a fixed order) and its routes.
// Built once per site instance (a reload builds new instances).
type fastSiteConfig struct {
	reqRules  []headerRule // listener request rules
	respRules []headerRule // listener response rules
	routes    []fastRoute

	// bigHeads is held while one of the site's backend response heads is
	// parsed off the event loops: one per site at a time, so a site whose
	// backend floods such heads waits behind itself and not ahead of
	// every other site.
	bigHeads sync.Mutex
}

type fastRoute struct {
	r         *compiledRoute
	slow      bool // static, fastcgi, redirect, try_files or expires: net/http serves it
	reqRules  []headerRule
	respRules []headerRule
	headers   *config.HeadersConfig
}

// headerRule is one add / set / remove of a header rule set, in the order
// the slow path applies them: every add, then every set, then every remove.
type headerRule struct {
	op    uint8 // ruleAdd, ruleSet, ruleRemove
	name  string
	value string
	// skip: a request rule net/http's request writer ignores (Host,
	// Content-Length, Transfer-Encoding, Trailer are written from the
	// request itself, never from its header map).
	skip bool
}

const (
	ruleAdd uint8 = iota
	ruleSet
	ruleRemove
)

func buildRules(add, set map[string]string, remove []string, request bool) []headerRule {
	var rules []headerRule
	for _, k := range sortedKeys(add) {
		rules = append(rules, headerRule{op: ruleAdd, name: sanitizeHeaderValue(k), value: sanitizeHeaderValue(add[k])})
	}
	for _, k := range sortedKeys(set) {
		rules = append(rules, headerRule{op: ruleSet, name: sanitizeHeaderValue(k), value: sanitizeHeaderValue(set[k])})
	}
	for _, k := range remove {
		rules = append(rules, headerRule{op: ruleRemove, name: k})
	}
	for i := range rules {
		rules[i].name = http.CanonicalHeaderKey(rules[i].name)
		if request {
			switch rules[i].name {
			case "Host", "Content-Length", "Transfer-Encoding", "Trailer":
				rules[i].skip = true
			}
		}
	}
	return rules
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// fastConfig returns the site's fast-path configuration.
func (s *HTTPServer) fastConfig() *fastSiteConfig {
	if c := s.fastCfg.Load(); c != nil {
		return c
	}
	c := &fastSiteConfig{}
	if s.Listener != nil {
		h := &s.Listener.Headers
		c.reqRules = buildRules(h.RequestAdd, h.RequestSet, h.RequestRemove, true)
		c.respRules = buildRules(h.ResponseAdd, h.ResponseSet, h.ResponseRemove, false)
	}
	if s.router != nil {
		for i := range s.router.routes {
			r := &s.router.routes[i]
			fr := fastRoute{
				r: r,
				slow: r.static.Root != "" || r.fastcgi.Pass != "" || r.redirect.URL != "" ||
					len(r.tryFiles.Files) > 0 || r.expires != "",
				reqRules:  buildRules(r.headers.RequestAdd, r.headers.RequestSet, r.headers.RequestRemove, true),
				respRules: buildRules(r.headers.ResponseAdd, r.headers.ResponseSet, r.headers.ResponseRemove, false),
				headers:   &r.headers,
			}
			c.routes = append(c.routes, fr)
		}
	}
	s.fastCfg.CompareAndSwap(nil, c)
	return s.fastCfg.Load()
}

// fastIneligible reports whether the site has something only the net/http
// path implements; its requests are then handed to net/http. Read per
// request from the live fields.
func (s *HTTPServer) fastIneligible() bool {
	l := s.Listener
	return s.ResponseCache != nil || l == nil || l.Compression.Enabled ||
		l.ClientAuth != nil || (l.TLS != nil && clientAuthConfigured(l.TLS.ClientAuth))
}

// matchFast is Router.MatchFull for the fast path: the first route whose
// host and path match, or nil. host is the request's Host (any case, maybe
// with a port), path the canonical decoded path.
func (c *fastSiteConfig) matchFast(host, path []byte) (*fastRoute, []string) {
	// Router.MatchFull: lower-case, then cut at the LAST ':'.
	if i := bytes.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	for i := range c.routes {
		fr := &c.routes[i]
		r := fr.r
		if r.host != "" && !equalFoldLower(host, r.host) {
			continue
		}
		var matches []string
		if r.pathRegex != nil {
			if !r.pathRegex.Match(path) {
				continue
			}
			if r.rewrite.Path != "" && strings.Contains(r.rewrite.Path, "$") {
				matches = r.pathRegex.FindStringSubmatch(string(path))
			} else {
				matches = []string{""} // non-nil: a regex route matched
			}
		} else if r.pathPrefix != "" && !(len(path) >= len(r.pathPrefix) && bstr(path[:len(r.pathPrefix)]) == r.pathPrefix) {
			continue
		}
		return fr, matches
	}
	return nil, nil
}

// appendEscapedPath appends p escaped the way net/url escapes a path
// (url.URL{Path: p}.EscapedPath() when RawPath is empty).
func appendEscapedPath(dst, p []byte) []byte {
	const hexUpper = "0123456789ABCDEF"
	for _, c := range p {
		if shouldEscapePath(c) {
			dst = append(dst, '%', hexUpper[c>>4], hexUpper[c&15])
		} else {
			dst = append(dst, c)
		}
	}
	return dst
}

// shouldEscapePath is net/url's shouldEscape(c, encodePath).
func shouldEscapePath(c byte) bool {
	if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' {
		return false
	}
	switch c {
	case '-', '_', '.', '~':
		return false
	case '$', '&', '+', ',', '/', ':', ';', '=', '@':
		return false
	}
	return true
}

// isCanonicalPath is httppath's isCanonical (p starts with '/').
func isCanonicalPath(p []byte) bool {
	start := 1
	for i := 1; i <= len(p); i++ {
		if i < len(p) && p[i] != '/' {
			continue
		}
		seg := p[start:i]
		if (len(seg) == 1 && seg[0] == '.') || (len(seg) == 2 && seg[0] == '.' && seg[1] == '.') || (len(seg) == 0 && i < len(p)) {
			return false
		}
		start = i + 1
	}
	return true
}

// canonicalPath returns httppath.Canonical(p) (allocates; rare).
func canonicalPath(p []byte) []byte { return []byte(httppath.Canonical(string(p))) }

// statusLine returns the status line net/http writes for code on an HTTP/1.1
// response.
func statusLine(code int) []byte {
	if code >= 100 && code < 600 {
		if l := statusLines[code-100].Load(); l != nil {
			return *l
		}
	}
	var b []byte
	if text := http.StatusText(code); text != "" {
		b = append(b, "HTTP/1.1 "...)
		b = strconv.AppendInt(b, int64(code), 10)
		b = append(b, ' ')
		b = append(b, text...)
		b = append(b, "\r\n"...)
	} else {
		b = append(b, "HTTP/1.1 "...)
		b = append(b, []byte(padStatus(code))...)
		b = append(b, " status code "...)
		b = strconv.AppendInt(b, int64(code), 10)
		b = append(b, "\r\n"...)
	}
	if code >= 100 && code < 600 {
		statusLines[code-100].Store(&b)
	}
	return b
}

func padStatus(code int) string {
	s := strconv.Itoa(code)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

var statusLines [500]atomic.Pointer[[]byte]

// defaultErrorPages caches errorhtml.DefaultErrorPage per status code.
var defaultErrorPages sync.Map // int -> []byte

func errorPageBody(s *HTTPServer, code int) []byte {
	if s.ErrorPages != nil {
		if page, ok := s.ErrorPages[code]; ok {
			return page
		}
	}
	return defaultErrorBody(code)
}

// defaultErrorBody returns the page for code when no site has a say: the
// request was not read far enough to know its site.
func defaultErrorBody(code int) []byte {
	if v, ok := defaultErrorPages.Load(code); ok {
		return v.([]byte)
	}
	page := errorhtml.DefaultErrorPage(code)
	defaultErrorPages.Store(code, page)
	return page
}

// dateCache holds the Date header value for the current second.
type dateCache struct {
	sec int64
	buf []byte
}

func (d *dateCache) get(now time.Time) []byte {
	sec := now.Unix()
	if sec != d.sec || d.buf == nil {
		d.sec = sec
		d.buf = now.UTC().AppendFormat(d.buf[:0], http.TimeFormat)
	}
	return d.buf
}

// reqIDSource hands out request ids from a buffer of random bytes, refilled
// from crypto/rand: the same ids as generateRequestID, one getrandom call
// per 256 of them.
type reqIDSource struct {
	buf []byte
	off int
}

func (r *reqIDSource) next(dst []byte) ([]byte, bool) {
	if r.off+requestIDBytes > len(r.buf) {
		if r.buf == nil {
			r.buf = make([]byte, 256*requestIDBytes)
		}
		if _, err := rand.Read(r.buf); err != nil {
			return dst, false
		}
		r.off = 0
	}
	b := r.buf[r.off : r.off+requestIDBytes]
	r.off += requestIDBytes
	n := len(dst)
	dst = append(dst, make([]byte, hex.EncodedLen(requestIDBytes))...)
	hex.Encode(dst[n:], b)
	clear(b)
	return dst, true
}

// isValidRequestIDBytes is isValidRequestID on bytes.
func isValidRequestIDBytes(s []byte) bool {
	if len(s) == 0 || len(s) > maxInboundRequestIDLen {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F', c == '-':
		default:
			return false
		}
	}
	return true
}

// ipTrustedAddr is ipTrusted for a netip.Addr.
func (s *HTTPServer) ipTrustedAddr(a netip.Addr) bool {
	if !a.IsValid() || len(s.TrustedProxies) == 0 {
		return false
	}
	a16 := a.As16()
	ip := net.IP(a16[:])
	for _, cidr := range s.TrustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// parseHopAddr is parseHop without allocating (but on a malformed hop): an
// IP, optionally with a port and/or brackets. The zero Addr if it is none
// of these.
func parseHopAddr(hop []byte) netip.Addr {
	if a, ok := parseIPLikeNet(bstr(hop)); ok {
		return a
	}
	if host, _, err := net.SplitHostPort(bstr(hop)); err == nil {
		a, _ := parseIPLikeNet(host)
		return a
	}
	if len(hop) > 2 && hop[0] == '[' && hop[len(hop)-1] == ']' {
		a, _ := parseIPLikeNet(bstr(hop[1 : len(hop)-1]))
		return a
	}
	return netip.Addr{}
}

// parseIPLikeNet parses an address as net.ParseIP does (no zone). An
// IPv4-mapped IPv6 address prints as IPv4 through appendAddr, as net.IP
// does.
func parseIPLikeNet(s string) (netip.Addr, bool) {
	if s == "" || strings.IndexByte(s, '%') >= 0 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// appendAddr formats a the way net.IP.String does.
func appendAddr(dst []byte, a netip.Addr) []byte {
	if a.Is4In6() {
		a = a.Unmap()
	}
	return a.AppendTo(dst)
}
