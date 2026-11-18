//go:build linux

package httpproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
)

// Tests of TLS to backends (backend_tls) on the event loops: the same
// results as the net/http path, the same certificate checks, and the
// connection handling of plain backends.

// tlsBackend is a TLS server for these tests. It serves scripted raw
// responses (as scriptBackend) and records what the handshakes showed.
type tlsBackend struct {
	*scriptBackend
	certFile string // its self-signed certificate (a site's ca_cert)

	// abrupt: the backend ends a connection with a bare FIN, without the
	// TLS close_notify.
	abrupt bool

	mu      sync.Mutex
	resumed []bool
	names   []string // the SNI of each handshake
	certs   []int    // client certificates presented, per handshake
}

const tlsBackendName = "backend.test"

// newTLSBackend starts a TLS backend whose certificate is for
// tlsBackendName. mutate may change its TLS config.
func newTLSBackend(t *testing.T, script func(path string) (string, bool), mutate func(*tls.Config)) *tlsBackend {
	t.Helper()
	certFile, keyFile := genCertWithCN(t, t.TempDir(), tlsBackendName)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	b := &tlsBackend{certFile: certFile}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
	if mutate != nil {
		mutate(cfg)
	}
	b.scriptBackend = newScriptBackendOn(t, script, func(c net.Conn) (net.Conn, bool) {
		tc := tls.Server(c, cfg)
		tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			return nil, false
		}
		tc.SetDeadline(time.Time{})
		st := tc.ConnectionState()
		b.mu.Lock()
		b.resumed = append(b.resumed, st.DidResume)
		b.names = append(b.names, st.ServerName)
		b.certs = append(b.certs, len(st.PeerCertificates))
		b.mu.Unlock()
		if b.abrupt {
			return abruptConn{tc, c}, true
		}
		return tc, true
	})
	return b
}

// abruptConn closes the TCP connection under a TLS one without saying so
// in TLS.
type abruptConn struct {
	*tls.Conn
	raw net.Conn
}

func (a abruptConn) Close() error { return a.raw.Close() }

func (b *tlsBackend) handshakes() (resumed []bool, names []string, certs []int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]bool(nil), b.resumed...), append([]string(nil), b.names...), append([]int(nil), b.certs...)
}

// newScriptBackendOn is newScriptBackend whose accepted connections go
// through wrap first (a TLS handshake); a false result drops the
// connection.
func newScriptBackendOn(t *testing.T, script func(path string) (string, bool), wrap func(net.Conn) (net.Conn, bool)) *scriptBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &scriptBackend{ln: ln, script: script, served: map[string]int{}, written: make(chan string, 64)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns++
			b.mu.Unlock()
			go func() {
				wc, ok := wrap(c)
				if !ok {
					c.Close()
					return
				}
				b.serve(wc)
			}()
		}
	}()
	return b
}

// tlsBackendSite is a site whose backend "be" talks TLS to servers.
func tlsBackendSite(servers []string, btls config.BackendTLSConfig, be config.Backend) *HTTPServer {
	btls.Enabled = true
	be.Servers, be.BackendTLS = servers, btls
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	return fastTestSite(l, &be)
}

func goodBackendTLS(b *tlsBackend) config.BackendTLSConfig {
	return config.BackendTLSConfig{CACert: b.certFile, ServerName: tlsBackendName}
}

// errorLogTo sends the error log to a file of the test and returns its
// path.
func errorLogTo(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "error.log")
	if err := logging.Init("warning", filepath.Join(t.TempDir(), "access.log"), p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("warning", "", "") })
	return p
}

// lastUpstreamReason returns what the error log gave as the reason of the
// last failed attempt (after the request path), "" when none.
func lastUpstreamReason(t *testing.T, logPath string) string {
	t.Helper()
	data, _ := os.ReadFile(logPath)
	return upstreamReason(string(data))
}

// upstreamReason is lastUpstreamReason for the text of a log.
func upstreamReason(log string) string {
	lines := strings.Split(strings.TrimSpace(log), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if j := strings.Index(lines[i], " failed for "); j >= 0 {
			if k := strings.Index(lines[i][j:], ": "); k >= 0 {
				return lines[i][j+k+2:]
			}
		}
	}
	return ""
}

// Requests to a TLS backend give the same results through the fast path as
// through the net/http path: bodies both ways, HEAD, chunked and
// close-delimited bodies, informational responses, and response heads past
// a loop's limits.
func TestBackendTLS_MatchesNetHTTP(t *testing.T) {
	quietLog(t)
	// A handler backend for bodies, a scripted one for exact response bytes.
	big := bytes.Repeat([]byte("0123456789abcdef"), 2<<20/16)
	hs := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Got", fmt.Sprintf("%s %s %d %08x", r.Method, r.URL.RequestURI(), len(body), crc32.ChecksumIEEE(body)))
		w.Header().Set("X-Proto", r.Proto)
		switch r.URL.Path {
		case "/big":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(big)
		case "/stream":
			w.Header().Set("Content-Type", "text/plain")
			for i := 0; i < 5; i++ {
				fmt.Fprintf(w, "part %d\n", i)
				w.(http.Flusher).Flush()
			}
		default:
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "hello")
		}
	}))
	hs.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	hs.StartTLS()
	defer hs.Close()
	hsCA := filepath.Join(t.TempDir(), "hs-ca.pem")
	if err := os.WriteFile(hsCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hs.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := newTLSBackend(t, bigHeadScript(), nil)

	upload := strings.Repeat("u", 1<<20)
	type tc struct {
		name, req string
		methods   []string
	}
	handlerCases := []tc{
		{"get", bhGet("/ok?a=1"), []string{"GET"}},
		{"head", "HEAD /ok HTTP/1.1\r\nHost: example.test\r\n\r\n", []string{"HEAD"}},
		{"post", "POST /post HTTP/1.1\r\nHost: example.test\r\nContent-Length: 11\r\n\r\nhello world", []string{"POST"}},
		{"upload", fmt.Sprintf("POST /post HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\n\r\n%s", len(upload), upload), []string{"POST"}},
		{"large body", bhGet("/big"), []string{"GET"}},
		{"streamed", bhGet("/stream"), []string{"GET"}},
		{"keep-alive", bhGet("/a") + bhGet("/b") + bhGet("/c"), []string{"GET", "GET", "GET"}},
	}
	rawCases := []tc{
		{"many fields", bhGet("/many"), []string{"GET"}},
		{"large field", bhGet("/large"), []string{"GET"}},
		{"chunked", bhGet("/chunked"), []string{"GET"}},
		{"trailer", bhGet("/trailer", "TE: trailers\r\n"), []string{"GET"}},
		{"close delimited", bhGet("/close"), []string{"GET"}},
		{"204", bhGet("/204"), []string{"GET"}},
		{"103 big, then small", bhGet("/103-big-small"), []string{"GET", "GET"}},
		{"malformed after many", bhGet("/bad-after-many"), []string{"GET"}},
	}
	run := func(fast bool, site *HTTPServer, cases []tc) map[string][]*http.Response {
		addr := startTestGroup(t, site, fast)
		out := map[string][]*http.Response{}
		for _, c := range cases {
			out[c.name] = exchange(t, addr, c.req, c.methods...)
		}
		return out
	}
	compare := func(cases []tc, slow, fast map[string][]*http.Response) {
		for _, c := range cases {
			for i := range c.methods {
				s, f := slow[c.name][i], fast[c.name][i]
				if s.StatusCode != f.StatusCode || readBody(s) != readBody(f) {
					t.Errorf("%s (response %d): slow %d %q, fast %d %q", c.name, i+1, s.StatusCode, trunc(readBody(s)), f.StatusCode, trunc(readBody(f)))
					continue
				}
				sh, fh := normHeader(s.Header), normHeader(f.Header)
				if s.StatusCode == http.StatusEarlyHints {
					sh, fh = http.Header{"Link": sh["Link"]}, http.Header{"Link": fh["Link"]}
				}
				if c.name == "chunked" || c.name == "trailer" || c.name == "close delimited" || c.name == "streamed" {
					sh.Del("Content-Length")
					fh.Del("Content-Length")
				}
				if !reflect.DeepEqual(sh, fh) {
					t.Errorf("%s (response %d): headers differ:\n slow %s\n fast %s", c.name, i+1, trunc(fmt.Sprint(sh)), trunc(fmt.Sprint(fh)))
				}
				if !reflect.DeepEqual(s.Trailer, f.Trailer) {
					t.Errorf("%s: trailers differ: slow %v, fast %v", c.name, s.Trailer, f.Trailer)
				}
			}
		}
	}
	hsSite := func() *HTTPServer {
		return tlsBackendSite([]string{hs.Listener.Addr().String()}, config.BackendTLSConfig{CACert: hsCA}, config.Backend{})
	}
	rawSite := func() *HTTPServer {
		return tlsBackendSite([]string{raw.addr()}, goodBackendTLS(raw), config.Backend{})
	}
	slowH, fastH := run(false, hsSite(), handlerCases), run(true, hsSite(), handlerCases)
	compare(handlerCases, slowH, fastH)
	slowR, fastR := run(false, rawSite(), rawCases), run(true, rawSite(), rawCases)
	compare(rawCases, slowR, fastR)

	// What the cases are about did happen on the fast path.
	if got := fastH["upload"][0].Header.Get("X-Got"); got != fmt.Sprintf("POST /post %d %08x", len(upload), crc32.ChecksumIEEE([]byte(upload))) {
		t.Errorf("upload: backend got %q", got)
	}
	if got := readBody(fastH["large body"][0]); got != string(big) {
		t.Errorf("large body: %d bytes, want %d", len(got), len(big))
	}
	if p := fastH["get"][0].Header.Get("X-Proto"); p != "HTTP/1.1" {
		t.Errorf("backend saw %q", p)
	}
	if r := fastR["many fields"][0]; r.Header.Get("X-F-299") != "v299" {
		t.Errorf("many fields: X-F-299 = %q", r.Header.Get("X-F-299"))
	}
}

// The backend's certificate is checked as the net/http path checks it, with
// the same answer and the same reason in the log; the name sent and checked
// is backend_tls.server_name, else the server address's host.
func TestBackendTLS_Verification(t *testing.T) {
	be := newTLSBackend(t, bigHeadScript(), nil)
	for _, tc := range []struct {
		name   string
		cfg    config.BackendTLSConfig
		status int
		sni    string
	}{
		{"checked against server_name", goodBackendTLS(be), 200, tlsBackendName},
		{"unknown authority", config.BackendTLSConfig{ServerName: tlsBackendName}, 502, tlsBackendName},
		{"another name", config.BackendTLSConfig{CACert: be.certFile, ServerName: "other.test"}, 502, "other.test"},
		{"the address is not in the certificate", config.BackendTLSConfig{CACert: be.certFile}, 502, ""},
		{"insecure", config.BackendTLSConfig{Insecure: true}, 200, ""},
	} {
		var status [2]int
		var reason [2]string
		for i, fast := range []bool{false, true} {
			logPath := errorLogTo(t)
			addr := startTestGroup(t, tlsBackendSite([]string{be.addr()}, tc.cfg, config.Backend{}), fast)
			before, _, _ := be.handshakes()
			status[i] = exchange(t, addr, bhGet("/ok"), "GET")[0].StatusCode
			reason[i] = lastUpstreamReason(t, logPath)
			if _, names, _ := be.handshakes(); len(names) > len(before) && names[len(names)-1] != tc.sni {
				t.Errorf("%s (fast=%v): SNI %q, want %q", tc.name, fast, names[len(names)-1], tc.sni)
			}
		}
		if status[0] != tc.status || status[1] != tc.status {
			t.Errorf("%s: status net/http %d, fast %d, want %d", tc.name, status[0], status[1], tc.status)
		}
		if reason[0] != reason[1] || (tc.status == 502) != (reason[1] != "") {
			t.Errorf("%s: logged reason\n net/http %q\n fast     %q", tc.name, reason[0], reason[1])
		}
	}
}

// A backend that asks for a client certificate gets the site's.
func TestBackendTLS_ClientCertificate(t *testing.T) {
	quietLog(t)
	be := newTLSBackend(t, bigHeadScript(), func(c *tls.Config) { c.ClientAuth = tls.RequireAnyClientCert })
	clientCert, clientKey := genCertWithCN(t, t.TempDir(), "client.test")
	with := goodBackendTLS(be)
	with.ClientCert, with.ClientKey = clientCert, clientKey
	for _, fast := range []bool{false, true} {
		addr := startTestGroup(t, tlsBackendSite([]string{be.addr()}, with, config.Backend{}), fast)
		if st := exchange(t, addr, bhGet("/ok"), "GET")[0].StatusCode; st != 200 {
			t.Errorf("fast=%v: with a client certificate: status %d", fast, st)
		}
		if _, _, certs := be.handshakes(); len(certs) == 0 || certs[len(certs)-1] != 1 {
			t.Errorf("fast=%v: the backend saw client certificates %v", fast, certs)
		}
		addr = startTestGroup(t, tlsBackendSite([]string{be.addr()}, goodBackendTLS(be), config.Backend{}), fast)
		if st := exchange(t, addr, bhGet("/ok"), "GET")[0].StatusCode; st != 502 {
			t.Errorf("fast=%v: without a client certificate: status %d, want 502", fast, st)
		}
	}
}

// A new connection to a backend resumes the TLS session of an earlier one
// of the same site; another site (as after a reload) starts afresh.
func TestBackendTLS_Resumption(t *testing.T) {
	quietLog(t)
	// Every response closes its connection, so each request handshakes.
	be := newTLSBackend(t, func(string) (string, bool) {
		return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", true
	}, nil)
	get := func(addr string) {
		t.Helper()
		if st := exchange(t, addr, bhGet("/ok"), "GET")[0].StatusCode; st != 200 {
			t.Fatalf("status %d", st)
		}
	}
	a := startTestGroup(t, tlsBackendSite([]string{be.addr()}, goodBackendTLS(be), config.Backend{}), true)
	get(a)
	get(a)
	get(a)
	b := startTestGroup(t, tlsBackendSite([]string{be.addr()}, goodBackendTLS(be), config.Backend{}), true)
	get(b)
	resumed, _, _ := be.handshakes()
	if want := []bool{false, true, true, false}; !reflect.DeepEqual(resumed, want) {
		t.Fatalf("handshakes resumed: %v, want %v", resumed, want)
	}
}

// A handshake that fails is a connect failure: retried on the next server
// under the retry policy, and the request body with it.
func TestBackendTLS_HandshakeFailureRetried(t *testing.T) {
	quietLog(t)
	// Accepts and hangs up: the handshake ends in EOF.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	go func() {
		for {
			c, err := dead.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	be := newTLSBackend(t, bigHeadScript(), nil)
	for _, fast := range []bool{false, true} {
		site := tlsBackendSite([]string{dead.Addr().String(), be.addr()}, goodBackendTLS(be), config.Backend{Retry: config.RetryConfig{Attempts: 2}})
		addr := startTestGroup(t, site, fast)
		for i := 0; i < 4; i++ {
			r := exchange(t, addr, "POST /ok HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello", "POST")[0]
			if r.StatusCode != 200 {
				t.Fatalf("fast=%v request %d: status %d, want the second server's 200", fast, i, r.StatusCode)
			}
		}
	}
}

// gRPC needs HTTP/2 to the backend: such a request stays on the net/http
// path, which speaks it; everything else goes over the loop's HTTP/1.1.
func TestBackendTLS_GRPCStaysOnNetHTTP(t *testing.T) {
	quietLog(t)
	hs := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Proto", r.Proto)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	}))
	hs.EnableHTTP2 = true
	hs.StartTLS()
	defer hs.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hs.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := startTestGroup(t, tlsBackendSite([]string{hs.Listener.Addr().String()}, config.BackendTLSConfig{CACert: ca}, config.Backend{}), true)
	for _, tc := range []struct{ ct, proto string }{
		{"text/plain", "HTTP/1.1"},
		{"application/grpc-web+proto", "HTTP/1.1"},
		{"application/grpc", "HTTP/2.0"},
		{"application/grpc+proto", "HTTP/2.0"},
	} {
		r := exchange(t, addr, "POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Type: "+tc.ct+"\r\nContent-Length: 2\r\n\r\nhi", "POST")[0]
		if r.StatusCode != 200 || r.Header.Get("X-Proto") != tc.proto {
			t.Errorf("%s: status %d, the backend saw %q, want %s", tc.ct, r.StatusCode, r.Header.Get("X-Proto"), tc.proto)
		}
	}
}

// Connections to a TLS backend are pooled and reused like plain ones; one
// the backend closed while it was idle is not used again.
func TestBackendTLS_PoolAndIdleClose(t *testing.T) {
	quietLog(t)
	be := newTLSBackend(t, bigHeadScript(), nil)
	addr := startTestGroup(t, tlsBackendSite([]string{be.addr()}, goodBackendTLS(be), config.Backend{}), true)
	// One client connection (one loop, one pool): five requests, then a
	// close-delimited answer, which ends the backend's connection, then
	// three more.
	raw := strings.Repeat(bhGet("/ok"), 5) + bhGet("/close") + strings.Repeat(bhGet("/ok"), 3)
	rs := exchange(t, addr, raw, "GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET")
	for i, r := range rs {
		if r.StatusCode != 200 {
			t.Fatalf("response %d: status %d", i+1, r.StatusCode)
		}
	}
	if b := readBody(rs[5]); b != "until the end" {
		t.Fatalf("close-delimited body %q", b)
	}
	if n := be.connCount(); n != 2 {
		t.Fatalf("backend connections: %d, want 2 (one reused for the first six requests, one for the rest)", n)
	}
}

// The name checked for a backend whose servers are re-resolved is the name
// they were configured with.
func TestCommonServerHost(t *testing.T) {
	for _, tc := range []struct {
		servers []string
		host    string
		ok      bool
	}{
		{[]string{"app.internal:8443"}, "app.internal", true},
		{[]string{"app.internal:8443", "APP.internal:8444"}, "app.internal", true},
		{[]string{"a.internal:8443", "b.internal:8443"}, "", false},
		{[]string{"10.0.0.1:8443"}, "", false},
		{[]string{"[::1]:8443"}, "", false},
		{[]string{"app.internal"}, "app.internal", true},
		{nil, "", false},
	} {
		if h, ok := commonServerHost(tc.servers); h != tc.host || ok != tc.ok {
			t.Errorf("%v: %q %v, want %q %v", tc.servers, h, ok, tc.host, tc.ok)
		}
	}
	// And it becomes the TLS name on both engines' configs.
	certFile, _ := genCertWithCN(t, t.TempDir(), "app.internal")
	s := tlsBackendSite([]string{"app.internal:8443"}, config.BackendTLSConfig{CACert: certFile}, config.Backend{ResolveInterval: "30s"})
	if n := s.backendFastTLS["be"].ServerName; n != "app.internal" {
		t.Errorf("fast path TLS name %q", n)
	}
	if n := s.backendTransports["be"].TLSClientConfig.ServerName; n != "app.internal" {
		t.Errorf("net/http TLS name %q", n)
	}
}

// A body that ends with the connection, from a backend that says goodbye
// in TLS (close_notify) or just closes: both end the response for the
// client as on the net/http path. (crypto/tls takes a connection closed
// between two records for its end, as many servers close that way.)
func TestBackendTLS_CloseDelimitedEndsLikeNetHTTP(t *testing.T) {
	quietLog(t)
	for _, abrupt := range []bool{false, true} {
		be := newTLSBackend(t, bigHeadScript(), nil)
		be.abrupt = abrupt
		type result struct {
			status   int
			body     string
			complete bool
		}
		var got [2]result
		for i, fast := range []bool{false, true} {
			addr := startTestGroup(t, tlsBackendSite([]string{be.addr()}, goodBackendTLS(be), config.Backend{}), fast)
			st, _, body, complete := exchangeLoose(t, addr, bhGet("/close"), "GET")
			got[i] = result{st, body, complete}
		}
		if got[0] != got[1] || got[1].status != 200 || got[1].body != "until the end" {
			t.Errorf("abrupt=%v: net/http %+v, fast %+v", abrupt, got[0], got[1])
		}
	}
}

// A backend that refuses HTTP/1.1 in the handshake (its ALPN list has
// neither it nor h2) cannot be used: 502, with the reason in the log.
func TestBackendTLS_ALPNRefused(t *testing.T) {
	be := newTLSBackend(t, bigHeadScript(), func(c *tls.Config) { c.NextProtos = []string{"h3"} })
	logPath := errorLogTo(t)
	addr := startTestGroup(t, tlsBackendSite([]string{be.addr()}, goodBackendTLS(be), config.Backend{}), true)
	if st := exchange(t, addr, bhGet("/ok"), "GET")[0].StatusCode; st != 502 {
		t.Fatalf("status %d, want 502", st)
	}
	if r := lastUpstreamReason(t, logPath); !strings.Contains(r, "application protocol") {
		t.Fatalf("logged reason %q", r)
	}
}
