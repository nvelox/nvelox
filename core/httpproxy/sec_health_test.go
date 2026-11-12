package httpproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/circuitbreaker"
)

// H4: the proxy's ErrorHandler counted every error against the backend
// (passive health and circuit breaker), including a client that went away
// and a request body over max_body_size — three oversized POSTs ejected a
// backend with max_fails 3. A half-open breaker's probe slot leaked on the
// connection-limit 503, the WebSocket path and the balancer error, wedging
// the breaker. A retried 502/503 was counted as a success and two failures.

// secBreaker counts circuit-breaker calls.
type secBreaker struct {
	mu                                 sync.Mutex
	allows, successes, failures, frees int
}

func (b *secBreaker) Allow() bool    { b.mu.Lock(); b.allows++; b.mu.Unlock(); return true }
func (b *secBreaker) RecordSuccess() { b.mu.Lock(); b.successes++; b.mu.Unlock() }
func (b *secBreaker) RecordFailure() { b.mu.Lock(); b.failures++; b.mu.Unlock() }
func (b *secBreaker) Release()       { b.mu.Lock(); b.frees++; b.mu.Unlock() }

func (b *secBreaker) snapshot() (allows, successes, failures, frees int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.allows, b.successes, b.failures, b.frees
}

// secLimiter is a connection limiter that can be closed and opened.
type secLimiter struct{ full atomic.Bool }

func (l *secLimiter) Acquire() bool { return !l.full.Load() }
func (l *secLimiter) Release()      {}

// TestPassive_OversizedBodyIs413NotFailure: a body over max_body_size is the
// client's fault: 413, and neither passive health nor the breaker hear of it.
func TestPassive_OversizedBodyIs413NotFailure(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}))
	defer backend.Close()
	ph, cb := newSecPassive(), &secBreaker{}
	_, addr := secSite(t, &ListenerConfig{MaxBodySize: "10B"}, []string{secHost(backend)}, secOpts{ph: ph, cb: cb})

	for i := 0; i < 3; i++ {
		resp, _ := secRaw(t, addr, "POST / HTTP/1.1\r\nHost: edge.test\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"+strings.Repeat("A", 100), 2*time.Second)
		if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 413") {
			t.Fatalf("oversized POST %d -> %q, want 413", i, secStatus(resp))
		}
	}
	if n := ph.totalFailures(); n != 0 {
		t.Fatalf("passive health recorded %d failures for oversized client bodies", n)
	}
	if allows, _, failures, frees := cb.snapshot(); failures != 0 || frees != allows {
		t.Fatalf("breaker: allows=%d failures=%d releases=%d, want 0 failures and every allow released", allows, failures, frees)
	}
}

// TestPassive_ClientGoneNotFailure: a client that hangs up while the backend
// is still working is not a backend failure, and a real breaker stays closed.
func TestPassive_ClientGoneNotFailure(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer backend.Close()
	ph := newSecPassive()
	cb := circuitbreaker.New(1, time.Minute, 1)
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{ph: ph, cb: cb})

	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "GET /slow HTTP/1.1\r\nHost: edge.test\r\n\r\n")
		time.Sleep(100 * time.Millisecond)
		c.Close()
	}
	time.Sleep(300 * time.Millisecond)
	if n := ph.totalFailures(); n != 0 {
		t.Fatalf("passive health recorded %d failures for clients that hung up", n)
	}
	if got := cb.State(); got != "closed" {
		t.Fatalf("breaker = %s after clients hung up, want closed", got)
	}
}

// TestBreaker_ProbeReleasedOnConnLimit: a half-open probe slot taken by a
// request the connection limit then rejects is given back.
func TestBreaker_ProbeReleasedOnConnLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer backend.Close()
	cb := circuitbreaker.New(1, 50*time.Millisecond, 1)
	cl := &secLimiter{}
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{cb: cb, cl: cl})

	cb.RecordFailure() // open
	time.Sleep(80 * time.Millisecond)
	cl.full.Store(true)
	if resp, _ := secRaw(t, addr, secGet("/", ""), 2*time.Second); !strings.HasPrefix(secStatus(resp), "HTTP/1.1 503") {
		t.Fatalf("conn-limited request -> %q, want 503", secStatus(resp))
	}
	cl.full.Store(false)
	if resp, _ := secRaw(t, addr, secGet("/", ""), 2*time.Second); !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") {
		t.Fatalf("next request -> %q, want 200 (half-open slot leaked)", secStatus(resp))
	}
	if got := cb.State(); got != "closed" {
		t.Fatalf("breaker = %s, want closed after the probe succeeded", got)
	}
}

// TestBreaker_ProbeReleasedWhenClientGone: a half-open probe whose client
// hangs up says nothing about the backend: the slot is released (not
// counted as a failure that re-opens the breaker).
func TestBreaker_ProbeReleasedWhenClientGone(t *testing.T) {
	var slow atomic.Bool
	slow.Store(true)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slow.Load() {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			return
		}
		io.WriteString(w, "ok")
	}))
	defer backend.Close()
	cb := circuitbreaker.New(1, 500*time.Millisecond, 1)
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{cb: cb})

	cb.RecordFailure()
	time.Sleep(600 * time.Millisecond) // past the open timeout: the next request probes
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: edge.test\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	c.Close()
	time.Sleep(100 * time.Millisecond)

	// Well within the open timeout: a probe counted as a failure would have
	// re-opened the breaker (503); a released one leaves the slot free.
	slow.Store(false)
	if resp, _ := secRaw(t, addr, secGet("/", ""), 2*time.Second); !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") {
		t.Fatalf("request after an abandoned probe -> %q, want 200", secStatus(resp))
	}
	if got := cb.State(); got != "closed" {
		t.Fatalf("breaker = %s, want closed", got)
	}
}

// secStatusBackend answers every request with status and records what it
// received.
type secStatusBackend struct {
	*httptest.Server
	mu   sync.Mutex
	got  []string // "METHOD body"
	hits atomic.Int64
}

func newSecStatusBackend(t *testing.T, status int) *secStatusBackend {
	t.Helper()
	b := &secStatusBackend{}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		b.got = append(b.got, r.Method+" "+string(body))
		b.mu.Unlock()
		b.hits.Add(1)
		w.WriteHeader(status)
		io.WriteString(w, http.StatusText(status))
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *secStatusBackend) requests() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.got...)
}

// TestRetry_StatusCountedOnce: a 503 that is retried is one failure for the
// server that sent it — not a success plus two failures.
func TestRetry_StatusCountedOnce(t *testing.T) {
	a, b := newSecStatusBackend(t, http.StatusServiceUnavailable), newSecStatusBackend(t, http.StatusOK)
	ph, cb := newSecPassive(), &secBreaker{}
	be := &config.Backend{Retry: config.RetryConfig{Attempts: 2, On: "503"}}
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(a.Server), secHost(b.Server)}, secOpts{backend: be, ph: ph, cb: cb})

	resp, _ := secRaw(t, addr, secGet("/", ""), 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") {
		t.Fatalf("GET -> %q, want 200 from the retry", secStatus(resp))
	}
	if f, s := ph.counts(secHost(a.Server)); f != 1 || s != 0 {
		t.Errorf("503 server: failures=%d successes=%d, want 1 and 0", f, s)
	}
	if f, s := ph.counts(secHost(b.Server)); f != 0 || s != 1 {
		t.Errorf("200 server: failures=%d successes=%d, want 0 and 1", f, s)
	}
	if allows, successes, failures, frees := cb.snapshot(); allows != 2 || successes != 1 || failures != 1 || frees != 0 {
		t.Errorf("breaker allows=%d successes=%d failures=%d releases=%d, want 2/1/1/0", allows, successes, failures, frees)
	}
}

// TestRetry_ConsumedBodyNotReplayed: a POST whose body went to a server that
// answered 503 is not replayed (its body is gone): the client gets the 503
// and the other server never sees the request.
func TestRetry_ConsumedBodyNotReplayed(t *testing.T) {
	a, b := newSecStatusBackend(t, http.StatusServiceUnavailable), newSecStatusBackend(t, http.StatusOK)
	be := &config.Backend{Retry: config.RetryConfig{Attempts: 2, On: "503"}}
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(a.Server), secHost(b.Server)}, secOpts{backend: be})

	resp, _ := secRaw(t, addr, "POST /pay HTTP/1.1\r\nHost: edge.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello", 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 503") {
		t.Fatalf("POST -> %q, want the 503 (no replay)", secStatus(resp))
	}
	if got := b.requests(); len(got) != 0 {
		t.Fatalf("POST replayed to the second server: %q", got)
	}
}

// TestRetry_NonIdempotentAfterSendNotReplayed: a server that reads a
// request and drops the connection may have acted on it: a POST is not sent
// again, a GET is.
func TestRetry_NonIdempotentAfterSendNotReplayed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				http.ReadRequest(bufio.NewReader(c))
				c.Close() // read it, never answer
			}(c)
		}
	}()
	b := newSecStatusBackend(t, http.StatusOK)
	be := &config.Backend{Retry: config.RetryConfig{Attempts: 2}}
	newAddr := func() string {
		_, addr := secSite(t, &ListenerConfig{}, []string{ln.Addr().String(), secHost(b.Server)}, secOpts{backend: be})
		return addr
	}

	resp, _ := secRaw(t, newAddr(), "POST /order HTTP/1.1\r\nHost: edge.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 502") {
		t.Fatalf("POST -> %q, want 502 (not replayed)", secStatus(resp))
	}
	if got := b.requests(); len(got) != 0 {
		t.Fatalf("POST replayed after the first server read it: %q", got)
	}

	resp, _ = secRaw(t, newAddr(), secGet("/item", ""), 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") {
		t.Fatalf("GET -> %q, want 200 from the retry", secStatus(resp))
	}
}

// TestRetry_HonorsOn: retry.on "502" does not retry a connect failure.
func TestRetry_HonorsOn(t *testing.T) {
	b := newSecStatusBackend(t, http.StatusOK)
	be := &config.Backend{Retry: config.RetryConfig{Attempts: 2, On: "502"}}
	_, addr := secSite(t, &ListenerConfig{}, []string{"127.0.0.1:1", secHost(b.Server)}, secOpts{backend: be})

	resp, _ := secRaw(t, addr, secGet("/", ""), 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 502") {
		t.Fatalf("GET -> %q, want 502: a connect failure is not in retry.on", secStatus(resp))
	}
	if n := b.hits.Load(); n != 0 {
		t.Fatalf("request retried %d times despite retry.on", n)
	}
}

// TestRetry_ConnectFailureReplaysBody: a POST that never reached a server
// (connection refused) is sent to the next one with its body intact.
func TestRetry_ConnectFailureReplaysBody(t *testing.T) {
	b := newSecStatusBackend(t, http.StatusOK)
	be := &config.Backend{Retry: config.RetryConfig{Attempts: 2, On: "connect_failure"}}
	_, addr := secSite(t, &ListenerConfig{}, []string{"127.0.0.1:1", secHost(b.Server)}, secOpts{backend: be})

	resp, _ := secRaw(t, addr, "POST /pay HTTP/1.1\r\nHost: edge.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello", 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") {
		t.Fatalf("POST -> %q, want 200 from the second server", secStatus(resp))
	}
	if got := b.requests(); len(got) != 1 || got[0] != "POST hello" {
		t.Fatalf("second server got %q, want [\"POST hello\"]", got)
	}
}

// TestProxy_ConnectIsRejected: CONNECT is refused with 405 and never counted
// against the backend (it used to fail inside ReverseProxy as a backend
// error).
func TestProxy_ConnectIsRejected(t *testing.T) {
	b := newSecStatusBackend(t, http.StatusOK)
	ph := newSecPassive()
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(b.Server)}, secOpts{ph: ph})

	resp, _ := secRaw(t, addr, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", 2*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 405") {
		t.Fatalf("CONNECT -> %q, want 405", secStatus(resp))
	}
	if n := ph.totalFailures(); n != 0 || b.hits.Load() != 0 {
		t.Fatalf("CONNECT: %d failures recorded, %d backend hits", n, b.hits.Load())
	}
}

// TestProxy_ReadTimeoutIs504NotFailure: on HTTP/1 net/http cancels the
// request context when the listener's read timeout passes; that is neither
// the client going away nor a backend failure: the client gets a 504 and
// the backend is not penalized (it used to be a 502 counted as a failure).
func TestProxy_ReadTimeoutIs504NotFailure(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer backend.Close()
	ph := newSecPassive()
	l := &ListenerConfig{Timeouts: config.TimeoutConfig{Read: "300ms"}}
	_, addr := secSite(t, l, []string{secHost(backend)}, secOpts{ph: ph})

	resp, _ := secRaw(t, addr, secGet("/slow", ""), 3*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 504") {
		t.Fatalf("slow backend past the read timeout -> %q, want 504", secStatus(resp))
	}
	if n := ph.totalFailures(); n != 0 {
		t.Fatalf("passive health recorded %d failures for the listener's own timeout", n)
	}
}

// TestProxy_StalledBodyIs408NotFailure: a client that stops sending its body
// past the read timeout gets a 408; the backend is not penalized.
func TestProxy_StalledBodyIs408NotFailure(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}))
	defer backend.Close()
	ph := newSecPassive()
	l := &ListenerConfig{Timeouts: config.TimeoutConfig{Read: "300ms"}}
	_, addr := secSite(t, l, []string{secHost(backend)}, secOpts{ph: ph})

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /up HTTP/1.1\r\nHost: edge.test\r\nContent-Length: 100\r\n\r\n0123456789")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no response to a stalled upload: %v", err)
	}
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("stalled upload -> %d, want 408", resp.StatusCode)
	}
	if n := ph.totalFailures(); n != 0 {
		t.Fatalf("passive health recorded %d failures for a stalled client", n)
	}
}
