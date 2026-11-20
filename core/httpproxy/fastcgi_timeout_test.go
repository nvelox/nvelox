package httpproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
)

// serveFCGI runs one request through ServeFastCGI and returns what the
// client got; it fails the test when the handler has not returned within
// 8 s (the fake upstream holds an answer 5 s at most).
func serveFCGI(t *testing.T, cfg config.FastCGIConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeFastCGI(rec, r, cfg, nil)
	}()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("the FastCGI handler has not returned after 8 s")
	}
	return rec
}

// slowBody is a request body that gives one byte every gap, n times.
type slowBody struct {
	n   int
	gap time.Duration
}

func (b *slowBody) Read(p []byte) (int, error) {
	if b.n == 0 {
		return 0, io.EOF
	}
	time.Sleep(b.gap)
	b.n--
	p[0] = 'x'
	return 1, nil
}

// TestFastCGI_ResponseHeaderTimeout: an upstream that has the request and
// sends no response head within the route's timeouts.response_header has
// its connection closed, and the client gets a 504 from nvelox without
// anything of the upstream's. The time counts from the end of the request
// body, as for an HTTP backend: an upload that takes longer is not cut, and
// neither is a body that comes slowly after a head in time.
func TestFastCGI_ResponseHeaderTimeout(t *testing.T) {
	if err := logging.Init("error", "", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("info", "", "") })
	cfg, current := fakeFCGIUpstream(t)
	cfg.Timeouts.ResponseHeader = "300ms"

	t.Run("no head", func(t *testing.T) {
		never := make(chan struct{})
		current.Store(&fcgiReply{wait: never, out: []byte("Content-Type: text/plain\r\n\r\nLATE")})
		start := time.Now()
		rec := serveFCGI(t, cfg, httptest.NewRequest("GET", "/index.php", nil))
		if rec.Code != http.StatusGatewayTimeout || strings.Contains(rec.Body.String(), "LATE") {
			t.Fatalf("no head within 300ms: answered %d %q, want 504 without the upstream's answer", rec.Code, rec.Body.String())
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("504 after %v, want about 300ms", took)
		}
	})

	t.Run("slow upload", func(t *testing.T) {
		current.Store(&fcgiReply{out: []byte("Content-Type: text/plain\r\n\r\nok")})
		r := httptest.NewRequest("POST", "/index.php", &slowBody{n: 3, gap: 200 * time.Millisecond})
		if rec := serveFCGI(t, cfg, r); rec.Code != http.StatusOK || rec.Body.String() != "ok" {
			t.Fatalf("a 600ms upload, then an answer at once: %d %q, want 200 \"ok\"", rec.Code, rec.Body.String())
		}
	})

	t.Run("slow body after the head", func(t *testing.T) {
		later := make(chan struct{})
		time.AfterFunc(600*time.Millisecond, func() { close(later) })
		current.Store(&fcgiReply{head: []byte("Content-Type: text/plain\r\n\r\nfirst "), wait: later, out: []byte("then the rest")})
		if rec := serveFCGI(t, cfg, httptest.NewRequest("GET", "/index.php", nil)); rec.Code != http.StatusOK || rec.Body.String() != "first then the rest" {
			t.Fatalf("a head at once, the body 600ms later: %d %q, want 200 with the whole body", rec.Code, rec.Body.String())
		}
	})
}
