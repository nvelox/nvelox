package httpproxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"nvelox/config"
)

// retryPolicy is a backend's retry configuration (backends[].retry).
type retryPolicy struct {
	attempts         int  // total attempts, at least 1
	onConnectFailure bool // "connect_failure": the backend gave no response
	on502, on503     bool // "502" / "503": the backend answered with that status
}

// newRetryPolicy parses retry.on as a comma-separated token list
// ("connect_failure,502,503"). An empty retry.on keeps the old default of
// retrying when the backend gives no response (connect_failure); a set one
// is honored as written.
func newRetryPolicy(be *config.Backend) retryPolicy {
	p := retryPolicy{attempts: 1}
	if be == nil || be.Retry.Attempts <= 1 {
		return p
	}
	p.attempts = be.Retry.Attempts
	on := strings.TrimSpace(be.Retry.On)
	if on == "" {
		p.onConnectFailure = true
		return p
	}
	for _, tok := range strings.Split(on, ",") {
		switch strings.ToLower(strings.TrimSpace(tok)) {
		case "connect_failure":
			p.onConnectFailure = true
		case "502":
			p.on502 = true
		case "503":
			p.on503 = true
		}
	}
	return p
}

// retriesStatus reports whether the policy retries a response with code.
func (p retryPolicy) retriesStatus(code int) bool {
	return (code == http.StatusBadGateway && p.on502) || (code == http.StatusServiceUnavailable && p.on503)
}

// idempotentMethods are the methods RFC 9110 section 9.2.2 defines as
// idempotent: sending one twice has the effect of sending it once.
var idempotentMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
}

// replayable reports whether r may be sent again to another server. sent
// says whether this attempt's request headers reached the backend. A request
// with a body is replayed only if nothing of it was sent or read: the body
// is streamed from the client and cannot be sent twice. A request without a
// body is replayed if it never reached the backend, or if its method is
// idempotent.
func replayable(r *http.Request, body *bodyTracker, sent bool) bool {
	if body.hasBody() {
		return !sent && !body.touched()
	}
	return !sent || idempotentMethods[r.Method]
}

// bodyTracker wraps the request body to learn whether it was read (so it
// cannot be replayed) and whether reading it failed (the client's fault —
// it went away, stalled past the read deadline — not the backend's).
type bodyTracker struct {
	rc        io.ReadCloser
	holdOpen  bool // Close is deferred to release: a retry may resend the body
	reads     atomic.Int64
	mu        sync.Mutex
	readErr   error
	closed    bool
	releaseMu sync.Once
}

// trackBody replaces r.Body with a tracker and returns it, or returns nil
// when the request has no body. retries says whether the body may be sent
// again; ReverseProxy and the Transport close the request body after an
// attempt, so the tracker then keeps it open until release.
func trackBody(r *http.Request, retries bool) *bodyTracker {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return nil
	}
	b := &bodyTracker{rc: r.Body, holdOpen: retries}
	r.Body = b
	return b
}

func (b *bodyTracker) Read(p []byte) (int, error) {
	b.reads.Add(1)
	n, err := b.rc.Read(p)
	if err != nil && err != io.EOF {
		b.mu.Lock()
		if !b.closed && b.readErr == nil {
			b.readErr = err
		}
		b.mu.Unlock()
	}
	return n, err
}

func (b *bodyTracker) Close() error {
	b.mu.Lock()
	b.closed = true // a read failing from now on is the close, not the client
	b.mu.Unlock()
	if b.holdOpen {
		return nil
	}
	return b.rc.Close()
}

// release closes the body when Close was deferred. Safe on nil.
func (b *bodyTracker) release() {
	if b == nil || !b.holdOpen {
		return
	}
	b.releaseMu.Do(func() { _ = b.rc.Close() })
}

func (b *bodyTracker) hasBody() bool { return b != nil }

// touched reports whether anything tried to read the body.
func (b *bodyTracker) touched() bool { return b != nil && b.reads.Load() > 0 }

// err is the error reading the body from the client failed with, if any.
func (b *bodyTracker) err() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.readErr
}

// isTimeout reports whether err is a deadline expiry.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// eofReader wraps a response body to learn whether it was read to its end:
// only a body received in full may be cached.
type eofReader struct {
	io.ReadCloser
	eof atomic.Bool
}

func (e *eofReader) Read(p []byte) (int, error) {
	n, err := e.ReadCloser.Read(p)
	if err == io.EOF {
		e.eof.Store(true)
	}
	return n, err
}

// done reports whether the body was read to EOF. False on nil.
func (e *eofReader) done() bool { return e != nil && e.eof.Load() }
