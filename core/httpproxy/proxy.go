package httpproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"sync/atomic"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/core/sticky"
	"nvelox/lb"
)

// upstreamRequest is what ServeHTTP hands to proxy for one request.
type upstreamRequest struct {
	backendName  string
	backend      *config.Backend // nil when the backend has no config entry
	balancer     lb.Balancer
	route        *RouteResult // nil when no route matched (default backend)
	routeHeaders *config.HeadersConfig
	reqID        string
	reqIDOn      bool
	cacheKey     string // "" = this response is not cached
	upgrade      bool   // WebSocket upgrade request
	// admission (upgrades) is what the tunnel is admitted with, completed
	// with its server when the backend switches; clientIP is the client
	// the access rules checked.
	admission *tunnelAdmission
	clientIP  net.IP
}

// errRetryStatus is returned by ModifyResponse to turn a 502 / 503 that
// retry.on lists into a retry on another server. ModifyResponse has already
// counted it as one failure.
var errRetryStatus = errors.New("httpproxy: retry on upstream status")

// errBadSwitch is returned by ModifyResponse for a 101 Switching Protocols
// that does not answer a WebSocket upgrade with a switch to WebSocket.
var errBadSwitch = errors.New("httpproxy: backend switched protocols without a WebSocket upgrade to answer")

// attemptOutcome is how one proxy attempt ended.
type attemptOutcome int

const (
	outcomeDone           attemptOutcome = iota // the client has its response (or the tunnel ran)
	outcomeRetry                                // try another server
	outcomeBadGateway                           // backend failure, not retried: 502
	outcomeClientGone                           // the client went away: nothing is sent, logged as 499
	outcomeTooLarge                             // the request body is over max_body_size: 413
	outcomeBodyTimeout                          // the client's body stalled past the read limit: 408
	outcomeGatewayTimeout                       // the backend did not start answering within timeouts.response_header: 504
	outcomeBadRequest                           // the request (or its body) cannot be sent upstream: 400
)

// proxy sends r to a server of u.backendName and relays the answer,
// retrying on another server when the backend's retry policy allows it.
//
// Accounting: the circuit breaker is asked right before each attempt, and
// each attempt reports exactly one outcome to it and to passive health —
// success (the backend answered), failure (it did not, or answered with a
// status retry.on lists and the request is retried) or, when the attempt
// says nothing about the backend (the client went away, its body was too
// large or could not be read, the request could not be sent), no outcome:
// the breaker's slot is released and passive health is not touched.
func (s *HTTPServer) proxy(w http.ResponseWriter, r *http.Request, rec *statusRecorder, u *upstreamRequest, upstream *string) {
	policy := newRetryPolicy(u.backend)
	body := trackBody(r, policy.attempts > 1)
	defer body.release()
	st := s.stickyLookup(r, u)

	out := w
	var cacheW *cacheWriter
	if u.upgrade {
		// The tunnel's lifetime is bounded by this context: the idle timeout
		// and Close cancel it, which makes ReverseProxy close the backend
		// connection too.
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		r = r.WithContext(ctx)
		rec.closeUnlessSwitching = true
		rec.onHijack = func(c net.Conn) *tunnelConn {
			var adm *tunnelAdmission
			if u.admission != nil {
				a := *u.admission
				a.target = *upstream // the server of the attempt that switched
				adm = &a
			}
			return s.trackTunnel(c, cancel, adm, u.clientIP)
		}
	} else {
		// Writer chain: proxy -> cache -> compression -> recorder. The cache
		// stores the backend's own bytes and headers; compression applies to
		// fresh responses and to cache hits alike (serveCached).
		if shouldCompress(r, s.Compression) {
			cw := newCompressWriter(out, s.Compression)
			defer cw.Close()
			out = cw
		}
		if u.cacheKey != "" {
			cacheW = newCacheWriter(out, s.ResponseCache.MaxEntrySize())
			out = cacheW
		}
	}

	var excluded []string
	for attempt := 0; ; attempt++ {
		var target string
		var err error
		switch {
		case attempt == 0 && st != nil && st.target != "":
			target = st.target
		case attempt == 0:
			target, err = u.balancer.Next()
		default:
			target, err = u.balancer.NextExcluding(excluded)
		}
		if err != nil {
			s.serveError(w, http.StatusServiceUnavailable)
			return
		}
		if cb := s.CircuitBreakers[u.backendName]; cb != nil && !cb.Allow() {
			s.serveError(w, http.StatusServiceUnavailable)
			return
		}
		*upstream = target

		canRetry := attempt+1 < policy.attempts
		outcome, perr := s.proxyOnce(out, r, rec, u, target, policy, canRetry, body, st, cacheW)
		switch outcome {
		case outcomeRetry:
			excluded = append(excluded, target)
			logging.Warn("[HTTP] Retry %d/%d for %s: %v", attempt+1, policy.attempts, logging.SanitizeLogField(r.URL.Path), perr)
			continue
		case outcomeBadGateway:
			logging.Error("[HTTP] Upstream %s failed for %s: %v", target, logging.SanitizeLogField(r.URL.Path), perr)
			s.serveError(w, http.StatusBadGateway)
		case outcomeTooLarge:
			s.serveError(w, http.StatusRequestEntityTooLarge)
		case outcomeBodyTimeout:
			s.serveError(w, http.StatusRequestTimeout)
		case outcomeGatewayTimeout:
			logging.Error("[HTTP] Upstream %s did not answer %s in time: %v", target, logging.SanitizeLogField(r.URL.Path), perr)
			s.serveError(w, http.StatusGatewayTimeout)
		case outcomeBadRequest:
			s.serveError(w, http.StatusBadRequest)
		case outcomeClientGone:
			rec.logStatus = statusClientClosedRequest
		}
		return
	}
}

// proxyOnce makes one attempt against target. It writes the response to
// out when the backend answered (outcomeDone) and writes nothing otherwise.
func (s *HTTPServer) proxyOnce(out http.ResponseWriter, r *http.Request, rec *statusRecorder, u *upstreamRequest, target string,
	policy retryPolicy, canRetry bool, body *bodyTracker, st *stickyState, cacheW *cacheWriter) (attemptOutcome, error) {

	ph := s.PassiveHealth[u.backendName]
	cb := s.CircuitBreakers[u.backendName]
	reported := false
	report := func(ok bool) {
		reported = true
		if ok {
			if ph != nil {
				ph.RecordSuccess(target)
			}
			if cb != nil {
				cb.RecordSuccess()
			}
			return
		}
		if ph != nil {
			ph.RecordFailure(target)
		}
		if cb != nil {
			cb.RecordFailure()
		}
	}
	u.balancer.OnConnect(target)
	defer u.balancer.OnDisconnect(target) // after the body (or the tunnel), not at the response headers
	defer func() {
		if !reported && cb != nil {
			cb.Release()
		}
	}()

	transport, scheme := s.backendTransport, "http"
	if t, ok := s.backendTransports[u.backendName]; ok {
		transport, scheme = t, s.backendSchemes[u.backendName]
	} else if t, ok := s.plainTransports[u.backendName]; ok {
		transport = t
	}

	var (
		connStarted atomic.Bool // the transport began getting a connection
		sent        atomic.Bool // the request headers went out to the backend
		answered    bool        // the backend's response reached ModifyResponse
		proxyErr    error
		retryStatus int
		cacheHdr    http.Header
		respBody    *eofReader
	)
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		// Rewrite, not Director: the request's hop-by-hop headers —
		// including any a client names in Connection: — are removed before
		// it runs, so nothing set here can be stripped by the client, and
		// ReverseProxy does not append the peer to X-Forwarded-For again.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = scheme
			pr.Out.URL.Host = target
			pr.Out.Host = pr.In.Host
			// Keep the query string exactly as the client sent it (Rewrite
			// re-encodes one it cannot parse; nvelox never interprets it).
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			if !u.upgrade {
				// Only a WebSocket upgrade may switch protocols: an h2c (or
				// any other) upgrade would tunnel past every check here.
				pr.Out.Header.Del("Upgrade")
				pr.Out.Header.Del("Connection")
			}
			s.applyForwardedHeaders(pr.Out.Header, pr.In)
			if u.reqIDOn {
				pr.Out.Header.Set(requestIDHeader, u.reqID)
			}
			applyRequestHeaders(pr.Out, &s.Listener.Headers)
			if u.routeHeaders != nil {
				applyRequestHeaders(pr.Out, u.routeHeaders)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			answered = true
			if resp.StatusCode == http.StatusSwitchingProtocols && !(u.upgrade && switchesToWebSocket(resp.Header)) {
				report(false)
				return errBadSwitch
			}
			if canRetry && policy.retriesStatus(resp.StatusCode) && replayable(r, body, true) {
				report(false) // counted once: the retry path adds nothing
				retryStatus = resp.StatusCode
				return errRetryStatus
			}
			report(true)
			applyResponseHeaders(resp.Header, &s.Listener.Headers)
			if u.routeHeaders != nil {
				applyResponseHeaders(resp.Header, u.routeHeaders)
			}
			if st != nil {
				st.bind(resp.Header, target, r.TLS != nil)
			}
			// The backend's timeouts.read: the longest it may stay silent
			// once it has started answering. Never on a protocol switch
			// (ReverseProxy needs the connection itself as the body; a
			// tunnel has the idle timeout).
			if d := backendSilenceLimit(u.backend); d > 0 && resp.StatusCode != http.StatusSwitchingProtocols && resp.Body != http.NoBody {
				resp.Body = newSilenceBody(resp.Body, d, target)
			}
			if cacheW != nil && cacheableResponse(resp, cacheW.limit) {
				cacheHdr = cacheHeaders(resp.Header)
				respBody = &eofReader{ReadCloser: resp.Body}
				resp.Body = respBody
				cacheW.capture = true
			}
			return nil
		},
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) {
			// Nothing is written here: proxy answers once the attempt is
			// classified (and a hijacked connection has nobody to answer).
			if err != errRetryStatus {
				proxyErr = err
			}
		},
	}
	if s.BufferPool != nil {
		proxy.BufferPool = s.BufferPool
	}

	trace := &httptrace.ClientTrace{
		GetConn:      func(string) { connStarted.Store(true) },
		WroteHeaders: func() { sent.Store(true) },
	}
	proxy.ServeHTTP(out, r.WithContext(httptrace.WithClientTrace(r.Context(), trace)))

	switch {
	case rec.tunnel != nil:
		// Upgraded: the tunnel ran and has ended. Errors after the switch
		// belong to the tunnel, not to the backend.
		return outcomeDone, nil
	case retryStatus != 0:
		return outcomeRetry, fmt.Errorf("status %d", retryStatus)
	case proxyErr == nil:
		if cacheW != nil && cacheW.complete() && respBody.done() {
			s.ResponseCache.Put(u.cacheKey, &CacheEntry{
				StatusCode: http.StatusOK,
				Headers:    cacheHdr,
				Body:       cacheW.body.Bytes(),
				CreatedAt:  time.Now(),
			})
		}
		return outcomeDone, nil
	}

	// No response went to the client. Decide whose fault it was.
	var tooLarge *http.MaxBytesError
	bodyErr := body.err()
	switch {
	case answered:
		// The backend answered (already reported) but its answer could not
		// be relayed: a rejected protocol switch, or the switch itself
		// failed on the client side. Not retried.
		return outcomeBadGateway, proxyErr
	case errors.As(proxyErr, &tooLarge) || errors.As(bodyErr, &tooLarge):
		return outcomeTooLarge, proxyErr
	case bodyErr != nil && isTimeout(bodyErr):
		return outcomeBodyTimeout, bodyErr
	case r.Context().Err() != nil:
		return outcomeClientGone, proxyErr
	case bodyErr != nil:
		// Reading the client's body failed but the client is still there.
		return outcomeBadRequest, bodyErr
	case !connStarted.Load():
		// ReverseProxy refused the request before contacting the backend
		// (e.g. an Upgrade value that is not a printable token).
		return outcomeBadRequest, proxyErr
	case sent.Load() && isTimeout(proxyErr):
		// The request reached the backend, which did not start answering
		// within its timeouts.response_header: a backend failure, answered
		// 504 and not retried (the backend may still be working on it).
		report(false)
		return outcomeGatewayTimeout, proxyErr
	}
	report(false)
	if canRetry && policy.onConnectFailure && replayable(r, body, sent.Load()) {
		return outcomeRetry, proxyErr
	}
	return outcomeBadGateway, proxyErr
}

// stickyState is one request's session-persistence lookup.
type stickyState struct {
	mode   string // "cookie", "header" or "ip_hash"
	cookie string // cookie name (cookie mode)
	token  string // well-formed server token the client presented (cookie mode)
	key    string // store key (header / ip_hash mode)
	store  *sticky.Store
	target string // server stickiness picked; "" = let the balancer choose
}

// stickyLookup resolves the sticky server for r, or returns nil when the
// backend has no session persistence. In cookie mode the client's cookie is
// only compared with the tokens of the pool's own servers — it never becomes
// a store key — and in header mode the key is a fixed-size hash.
func (s *HTTPServer) stickyLookup(r *http.Request, u *upstreamRequest) *stickyState {
	store, ok := s.StickyStores[u.backendName]
	if !ok || store == nil || u.backend == nil {
		return nil
	}
	cfg := u.backend.StickySession
	st := &stickyState{mode: cfg.Type, store: store}
	switch cfg.Type {
	case "cookie":
		st.cookie = cfg.CookieName
		if st.cookie == "" {
			st.cookie = "NVELOX_SRV"
		}
		st.token = sticky.KeyFromCookie(r, st.cookie)
		if st.token != "" {
			st.target = sticky.ServerForToken(st.token, u.balancer.Servers())
		}
	case "header":
		st.key = sticky.KeyFromHeader(r, cfg.HeaderName)
		if st.key != "" {
			st.target = store.Get(st.key)
		}
	case "ip_hash":
		st.key = sticky.KeyFromIPHash(r)
		st.target = store.Get(st.key)
	default:
		return nil
	}
	if st.target != "" && !u.balancer.IsHealthy(st.target) {
		st.target = "" // sticky server is down, pick new
	}
	return st
}

// bind pins the client to target: cookie mode sets the cookie when the
// client does not already carry target's token; header / ip_hash mode
// records the key in the store.
func (st *stickyState) bind(h http.Header, target string, secure bool) {
	switch st.mode {
	case "cookie":
		if st.token != sticky.ServerToToken(target) {
			h.Add("Set-Cookie", sticky.NewCookie(st.cookie, target, secure).String())
		}
	case "header", "ip_hash":
		if st.key != "" {
			st.store.Set(st.key, target)
		}
	}
}

// serveCached writes a cache hit, through the compressor like a fresh
// response: the cache holds the backend's own bytes and headers.
func (s *HTTPServer) serveCached(w http.ResponseWriter, r *http.Request, entry *CacheEntry) {
	if shouldCompress(r, s.Compression) {
		cw := newCompressWriter(w, s.Compression)
		defer cw.Close()
		w = cw
	}
	ServeCached(w, entry)
}
