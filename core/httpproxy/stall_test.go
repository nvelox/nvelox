package httpproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
)

// stallProtocols runs a test over HTTP/1.1 and over HTTP/2 (TLS): the
// write limit works differently on each (HTTP/2 resets a stream when its
// write deadline passes, also an idle one).
var stallProtocols = []struct {
	name string
	h2   bool
}{{"http1", false}, {"http2", true}}

// stallServe serves a site whose backend runs handler, with listener l and
// backend be (nil: none set), over HTTP/1.1 or HTTP/2. It returns a client
// and the site's base URL.
func stallServe(t *testing.T, h2 bool, l *ListenerConfig, be *config.Backend, handler http.HandlerFunc) (*http.Client, string) {
	t.Helper()
	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)
	site := secNewSite(t, l, []string{secHost(backend)}, secOpts{backend: be})
	g := NewBindGroup(":0", "http")
	g.AddSite(site)
	ts := httptest.NewUnstartedServer(g)
	if h2 {
		ts.EnableHTTP2 = true
		ts.StartTLS()
	} else {
		ts.Start()
	}
	t.Cleanup(ts.Close)
	return ts.Client(), ts.URL
}

func checkProto(t *testing.T, resp *http.Response, h2 bool) {
	t.Helper()
	if want := map[bool]int{false: 1, true: 2}[h2]; resp.ProtoMajor != want {
		t.Fatalf("response over %s, want HTTP/%d", resp.Proto, want)
	}
}

// TestStall_QuietStreamOutlivesLimits: an event stream that stays quiet for
// longer than both limits is not cut. Before, HTTP/2 reset it when the write
// limit passed and HTTP/1 cancelled it when the read limit passed.
func TestStall_QuietStreamOutlivesLimits(t *testing.T) {
	for _, p := range stallProtocols {
		t.Run(p.name, func(t *testing.T) {
			l := &ListenerConfig{Timeouts: config.TimeoutConfig{Read: "300ms", Write: "300ms"}}
			client, url := stallServe(t, p.h2, l, nil, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: first\n\n")
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(1200 * time.Millisecond):
				}
				io.WriteString(w, "data: second\n\n")
			})
			resp, err := client.Get(url + "/events")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			checkProto(t, resp, p.h2)
			body, err := io.ReadAll(resp.Body)
			if err != nil || !strings.Contains(string(body), "data: second") {
				t.Fatalf("quiet stream cut: body %q, err %v", body, err)
			}
		})
	}
}

// TestStall_MovingTransfersOutliveLimits: a download and an upload that keep
// moving run longer than the limits.
func TestStall_MovingTransfersOutliveLimits(t *testing.T) {
	const chunks, size, gap = 8, 2048, 150 * time.Millisecond
	for _, p := range stallProtocols {
		t.Run(p.name+"/download", func(t *testing.T) {
			l := &ListenerConfig{Timeouts: config.TimeoutConfig{Read: "300ms", Write: "300ms"}}
			client, url := stallServe(t, p.h2, l, nil, func(w http.ResponseWriter, r *http.Request) {
				for i := 0; i < chunks; i++ {
					w.Write(bytes.Repeat([]byte{'d'}, size))
					w.(http.Flusher).Flush()
					time.Sleep(gap)
				}
			})
			resp, err := client.Get(url + "/download")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			checkProto(t, resp, p.h2)
			body, err := io.ReadAll(resp.Body)
			if err != nil || len(body) != chunks*size {
				t.Fatalf("download got %d bytes (err %v), want %d", len(body), err, chunks*size)
			}
		})
		t.Run(p.name+"/upload", func(t *testing.T) {
			l := &ListenerConfig{Timeouts: config.TimeoutConfig{Read: "300ms", Write: "300ms"}}
			client, url := stallServe(t, p.h2, l, nil, func(w http.ResponseWriter, r *http.Request) {
				n, err := io.Copy(io.Discard, r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				fmt.Fprint(w, n)
			})
			pr, pw := io.Pipe()
			go func() {
				for i := 0; i < chunks; i++ {
					if _, err := pw.Write(bytes.Repeat([]byte{'u'}, size)); err != nil {
						return
					}
					time.Sleep(gap)
				}
				pw.Close()
			}()
			resp, err := client.Post(url+"/upload", "application/octet-stream", pr)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			checkProto(t, resp, p.h2)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK || string(body) != fmt.Sprint(chunks*size) {
				t.Fatalf("upload -> %d %q, want 200 %q", resp.StatusCode, body, fmt.Sprint(chunks*size))
			}
		})
	}
}

// TestStall_StuckClientIsCut: a client that stops reading is still cut once
// a write has waited for it longer than the write limit.
func TestStall_StuckClientIsCut(t *testing.T) {
	for _, p := range stallProtocols {
		t.Run(p.name, func(t *testing.T) {
			aborted := make(chan struct{})
			var once sync.Once
			l := &ListenerConfig{Timeouts: config.TimeoutConfig{Write: "300ms"}}
			client, url := stallServe(t, p.h2, l, nil, func(w http.ResponseWriter, r *http.Request) {
				chunk := bytes.Repeat([]byte{'x'}, 32<<10)
				for i := 0; i < 8192; i++ { // up to 256 MiB
					if _, err := w.Write(chunk); err != nil {
						once.Do(func() { close(aborted) })
						return
					}
				}
			})
			resp, err := client.Get(url + "/big")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			checkProto(t, resp, p.h2)
			// Read nothing of the body: the proxy's writes block, then fail.
			select {
			case <-aborted:
			case <-time.After(10 * time.Second):
				t.Fatal("a client that stopped reading was not cut")
			}
		})
	}
}

// TestStall_SlowAnswerAfterUpload: once the body is in, the read limit is
// over: a backend may take longer than it to answer. (On HTTP/1 a read
// deadline left set when the body ends would cancel the request through
// net/http's watch for the client going away.)
func TestStall_SlowAnswerAfterUpload(t *testing.T) {
	for _, p := range stallProtocols {
		t.Run(p.name, func(t *testing.T) {
			l := &ListenerConfig{Timeouts: config.TimeoutConfig{Read: "300ms", Write: "300ms"}}
			client, url := stallServe(t, p.h2, l, nil, func(w http.ResponseWriter, r *http.Request) {
				n, _ := io.Copy(io.Discard, r.Body)
				time.Sleep(time.Second)
				fmt.Fprint(w, n)
			})
			resp, err := client.Post(url+"/up", "text/plain", strings.NewReader("0123456789"))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			checkProto(t, resp, p.h2)
			body, err := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK || string(body) != "10" || err != nil {
				t.Fatalf("slow answer after an upload -> %d %q (%v), want 200 \"10\"", resp.StatusCode, body, err)
			}
		})
	}
}

// TestStall_UnreadBodyDiscardIsBounded: no backend takes the request, so its
// body is never read, and the client stalls in the middle of it. Closing the
// body makes net/http discard the rest, which reads from the client: under
// the read limit too, or the handler would wait for the stalled client for
// good. (Retries keep the body open until the handler ends, so the close
// happens in the handler.)
func TestStall_UnreadBodyDiscardIsBounded(t *testing.T) {
	var down []string
	for i := 0; i < 2; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		down = append(down, ln.Addr().String())
		ln.Close() // connection refused
	}
	l := &ListenerConfig{Timeouts: config.TimeoutConfig{Read: "300ms"}}
	be := &config.Backend{Retry: config.RetryConfig{Attempts: 2}}
	_, addr := secSite(t, l, down, secOpts{backend: be})

	start := time.Now()
	resp, _ := secRaw(t, addr, "POST /up HTTP/1.1\r\nHost: edge.test\r\nContent-Length: 100\r\n\r\n0123456789", 4*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 502") {
		t.Fatalf("no backend, stalled body -> %q, want 502", secStatus(resp))
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("answered after %v, want about the 300ms read limit", took)
	}
}

// TestStall_UnreadBodyClosesConnection: a response that goes out while the
// request body is unread (here a static file, for a request that announces
// a body and never sends it) is sent at once, with Connection: close.
// net/http would otherwise read the rest of the body before sending the
// headers, with no limit on how long the client may take.
func TestStall_UnreadBodyClosesConnection(t *testing.T) {
	root := t.TempDir()
	big := bytes.Repeat([]byte("s"), 64<<10)
	if err := os.WriteFile(filepath.Join(root, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	l := &ListenerConfig{
		Timeouts: config.TimeoutConfig{Read: "300ms"},
		Routes:   []config.RouteConfig{{Match: config.RouteMatch{PathPrefix: "/"}, Static: config.StaticConfig{Root: root}}},
	}
	_, addr := secSite(t, l, []string{"127.0.0.1:1"}, secOpts{})

	start := time.Now()
	resp, _ := secRaw(t, addr, "GET /big.bin HTTP/1.1\r\nHost: edge.test\r\nContent-Length: 100\r\n\r\n", 4*time.Second)
	if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 200") || len(secBody(resp)) != len(big) {
		t.Fatalf("static file, body announced but not sent -> %q with %d body bytes, want 200 with %d",
			secStatus(resp), len(secBody(resp)), len(big))
	}
	if !strings.Contains(resp, "\r\nConnection: close\r\n") {
		t.Fatalf("no Connection: close with the request body unread:\n%s", resp[:strings.Index(resp, "\r\n\r\n")])
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("answered after %v, want at once", took)
	}
}

// TestStall_StalledUploadCutHTTP2: a body that stops coming is cut (408)
// over HTTP/2 as well (HTTP/1: TestProxy_StalledBodyIs408NotFailure).
func TestStall_StalledUploadCutHTTP2(t *testing.T) {
	l := &ListenerConfig{Timeouts: config.TimeoutConfig{Read: "300ms"}}
	client, url := stallServe(t, true, l, nil, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	})
	pr, pw := io.Pipe()
	defer pw.Close()
	go pw.Write([]byte("0123456789")) // then nothing more
	start := time.Now()
	resp, err := client.Post(url+"/up", "application/octet-stream", pr)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("stalled upload -> %d, want 408", resp.StatusCode)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("408 after %v, want about the 300ms read limit", took)
	}
}

// TestProxy_BackendSilenceCutsResponse: a backend that goes silent mid-
// response for longer than its timeouts.read has the response cut.
func TestProxy_BackendSilenceCutsResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "start ")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
		}
		io.WriteString(w, "end")
	}))
	defer backend.Close()
	be := &config.Backend{Timeouts: config.TimeoutConfig{Read: "300ms"}}
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{backend: be})

	start := time.Now()
	resp, _ := secRaw(t, addr, secGet("/silent", ""), 3*time.Second)
	if !strings.Contains(resp, "start") || strings.Contains(resp, "end") {
		t.Fatalf("silent backend -> %q, want the start and a cut", resp)
	}
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("cut after %v, want about the 300ms read limit", took)
	}
}

// TestProxy_BackendSilenceAllowsMovingBody: the backend's timeouts.read is
// the longest silence, not the longest response: a body that keeps coming
// runs past it.
func TestProxy_BackendSilenceAllowsMovingBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 6; i++ {
			io.WriteString(w, "chunk ")
			w.(http.Flusher).Flush()
			time.Sleep(150 * time.Millisecond)
		}
		io.WriteString(w, "end")
	}))
	defer backend.Close()
	be := &config.Backend{Timeouts: config.TimeoutConfig{Read: "300ms"}}
	_, addr := secSite(t, &ListenerConfig{}, []string{secHost(backend)}, secOpts{backend: be})

	resp, _ := secRaw(t, addr, secGet("/moving", ""), 3*time.Second)
	if !strings.Contains(resp, "end") {
		t.Fatalf("moving body under a 300ms backend read limit -> %q, want it whole", resp)
	}
}

// TestProxy_BackendSilenceLeavesTunnels: the backend's timeouts.read does not
// apply to a WebSocket tunnel (ReverseProxy needs the backend connection
// itself as the body; a tunnel has the idle timeout).
func TestProxy_BackendSilenceLeavesTunnels(t *testing.T) {
	b := secStartWSBackend(t)
	be := &config.Backend{Timeouts: config.TimeoutConfig{Read: "200ms"}}
	_, addr := secSite(t, &ListenerConfig{}, []string{b.addr}, secOpts{backend: be})
	conn, br, resp := secUpgrade(t, addr, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade -> %d, want 101", resp.StatusCode)
	}
	time.Sleep(600 * time.Millisecond) // quiet past the backend's read limit
	io.WriteString(conn, "ping")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel after a quiet period: %q, %v", buf, err)
	}
}

func TestBackendTimeouts(t *testing.T) {
	tests := []struct {
		name          string
		l             *ListenerConfig
		be            *config.Backend
		connect, resp time.Duration
	}{
		{"defaults", nil, nil, 10 * time.Second, 60 * time.Second},
		{"listener connect", &ListenerConfig{Timeouts: config.TimeoutConfig{Connect: "2s"}}, &config.Backend{}, 2 * time.Second, 60 * time.Second},
		{"backend wins", &ListenerConfig{Timeouts: config.TimeoutConfig{Connect: "2s"}},
			&config.Backend{Timeouts: config.TimeoutConfig{Connect: "1s", ResponseHeader: "5s"}}, time.Second, 5 * time.Second},
		{"zero is no limit", nil, &config.Backend{Timeouts: config.TimeoutConfig{Connect: "0", ResponseHeader: "0"}}, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connect, resp := backendTimeouts(tt.l, tt.be)
			if connect != tt.connect || resp != tt.resp {
				t.Fatalf("backendTimeouts = %v, %v; want %v, %v", connect, resp, tt.connect, tt.resp)
			}
			if got := newBackendTransport(tt.l, tt.be, nil).ResponseHeaderTimeout; got != tt.resp {
				t.Fatalf("transport ResponseHeaderTimeout = %v, want %v", got, tt.resp)
			}
		})
	}
}

// stallEvents is a fake server writer that records the deadline changes
// around what is done to it.
type stallEvents struct {
	mu        sync.Mutex
	events    []string
	h         http.Header
	failNext  error // the next Write / Read / ReadFrom fails with it
	readFroms []*io.LimitedReader
}

func (e *stallEvents) add(ev string) { e.mu.Lock(); e.events = append(e.events, ev); e.mu.Unlock() }

func (e *stallEvents) take() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := strings.Join(e.events, " ")
	e.events = nil
	return s
}

func (e *stallEvents) fail() error { err := e.failNext; e.failNext = nil; return err }

func mark(prefix string, t time.Time) string {
	if t.IsZero() {
		return prefix + "0"
	}
	return prefix + "+"
}

func (e *stallEvents) Header() http.Header {
	if e.h == nil {
		e.h = http.Header{}
	}
	return e.h
}
func (e *stallEvents) WriteHeader(code int)               { e.add(fmt.Sprintf("header%d", code)) }
func (e *stallEvents) Write(b []byte) (int, error)        { e.add("write"); return len(b), e.fail() }
func (e *stallEvents) FlushError() error                  { e.add("flush"); return e.fail() }
func (e *stallEvents) SetWriteDeadline(t time.Time) error { e.add(mark("wd", t)); return nil }
func (e *stallEvents) SetReadDeadline(t time.Time) error  { e.add(mark("rd", t)); return nil }
func (e *stallEvents) Read(p []byte) (int, error)         { e.add("read"); return 0, e.fail() }
func (e *stallEvents) Close() error                       { e.add("close"); return nil }
func (e *stallEvents) ReadFrom(r io.Reader) (int64, error) {
	lr := r.(*io.LimitedReader)
	e.readFroms = append(e.readFroms, &io.LimitedReader{R: lr.R, N: lr.N})
	e.add("readfrom")
	return io.Copy(io.Discard, lr)
}

func newStallTest(read, write string) (*stallEvents, *stallLimits) {
	e := &stallEvents{}
	l := newStallLimits(e, httptest.NewRequest("POST", "/", nil), &ListenerConfig{Timeouts: config.TimeoutConfig{Read: read, Write: write}})
	return e, l
}

// TestStallLimits_Deadlines: each write and read is bracketed by its
// deadline; a failed one leaves it set for good; finish sets both once and
// ends all changes.
func TestStallLimits_Deadlines(t *testing.T) {
	e, l := newStallTest("1s", "1s")
	w := l.writer(e)
	body := l.wrapBody(e)

	w.Write([]byte("x"))
	if got := e.take(); got != "wd+ write wd0" {
		t.Fatalf("write: %q", got)
	}
	w.(http.Flusher).Flush()
	if got := e.take(); got != "wd+ flush wd0" {
		t.Fatalf("flush: %q", got)
	}
	w.WriteHeader(http.StatusEarlyHints)
	if got := e.take(); got != "wd+ header103 wd0" {
		t.Fatalf("1xx header: %q", got)
	}
	w.WriteHeader(http.StatusOK)
	if got := e.take(); got != "header200" {
		t.Fatalf("final header (buffered, not written): %q", got)
	}
	body.Read(make([]byte, 4))
	if got := e.take(); got != "rd+ read rd0" {
		t.Fatalf("read: %q", got)
	}

	// A failed write leaves the deadline set and nothing re-arms it.
	e.failNext = errors.New("timeout")
	w.Write([]byte("x"))
	if got := e.take(); got != "wd+ write" {
		t.Fatalf("failed write: %q", got)
	}
	w.Write([]byte("x"))
	if got := e.take(); got != "write" {
		t.Fatalf("write after a failed one: %q", got)
	}
	// Same for reads, Close included.
	e.failNext = errors.New("timeout")
	body.Read(make([]byte, 4))
	if got := e.take(); got != "rd+ read" {
		t.Fatalf("failed read: %q", got)
	}
	body.Close()
	if got := e.take(); got != "close" {
		t.Fatalf("close after a failed read: %q", got)
	}
	// Both broken: finish sets nothing.
	l.finish()
	if got := e.take(); got != "" {
		t.Fatalf("finish after failures: %q", got)
	}
}

func TestStallLimits_Finish(t *testing.T) {
	e, l := newStallTest("1s", "1s")
	w, body := l.writer(e), l.wrapBody(e)
	l.finish()
	if got := e.take(); got != "wd+ rd+" {
		t.Fatalf("finish: %q", got)
	}
	// After finish nothing changes the deadlines (net/http owns them now).
	w.Write([]byte("x"))
	body.Read(make([]byte, 4))
	body.Close()
	l.finish()
	if got := e.take(); got != "write read close" {
		t.Fatalf("after finish: %q", got)
	}
}

func TestStallLimits_Off(t *testing.T) {
	if l := newStallLimits(&stallEvents{}, httptest.NewRequest("GET", "/", nil), &ListenerConfig{Timeouts: config.TimeoutConfig{Read: "0", Write: "0"}}); l != nil {
		t.Fatal("limits with read and write 0")
	}
	e, l := newStallTest("0", "")
	if _, ok := l.writer(e).(*stallWriter); !ok {
		t.Fatal("the default write limit is not applied")
	}
	if b := l.wrapBody(e); b != io.ReadCloser(e) {
		t.Fatal("read 0 wraps the body")
	}
	if b := l.wrapBody(http.NoBody); b != http.NoBody {
		t.Fatal("no body wrapped")
	}
}

// TestStallWriter_UnreadBodyCloses: on HTTP/1 a final response written while
// the request body is unread asks to close the connection; once the body is
// read to its end, or over HTTP/2, it does not.
func TestStallWriter_UnreadBodyCloses(t *testing.T) {
	for _, c := range []struct {
		name      string
		proto     int
		readFirst bool
		want      string
	}{
		{"http1 unread", 1, false, "close"},
		{"http1 read", 1, true, ""},
		{"http2 unread", 2, false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := &stallEvents{}
			r := httptest.NewRequest("POST", "/", strings.NewReader("x"))
			r.ProtoMajor = c.proto
			// Write limit off: the body is guarded all the same.
			l := newStallLimits(e, r, &ListenerConfig{Timeouts: config.TimeoutConfig{Write: "0"}})
			w, body := l.writer(e), l.wrapBody(io.NopCloser(strings.NewReader("x")))
			if c.readFirst {
				io.ReadAll(body)
			}
			w.WriteHeader(http.StatusOK)
			if got := e.Header().Get("Connection"); got != c.want {
				t.Fatalf("Connection = %q, want %q", got, c.want)
			}
		})
	}
}

// TestStallWriter_ReadFromSteps: sendfile runs in stallChunk steps, each
// under the write limit, over the file itself (one LimitedReader deep) and
// keeping the caller's LimitedReader count right.
func TestStallWriter_ReadFromSteps(t *testing.T) {
	e, l := newStallTest("", "1s")
	w := l.writer(e).(io.ReaderFrom)
	file := bytes.NewReader(make([]byte, 200<<10))
	src := &io.LimitedReader{R: file, N: 150 << 10}
	n, err := w.ReadFrom(src)
	if err != nil || n != 150<<10 || src.N != 0 {
		t.Fatalf("ReadFrom = %d, %v; left %d", n, err, src.N)
	}
	if got := e.take(); got != "wd+ readfrom wd0 wd+ readfrom wd0 wd+ readfrom wd0" {
		t.Fatalf("steps: %q", got)
	}
	want := []int64{stallChunk, stallChunk, 150<<10 - 2*stallChunk}
	for i, lr := range e.readFroms {
		if lr.R != file || lr.N != want[i] {
			t.Fatalf("step %d: reader %T over %v, N %d; want the file, N %d", i, lr.R, lr.R == file, lr.N, want[i])
		}
	}
}
