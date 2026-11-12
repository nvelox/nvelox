package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"nvelox/core/denylist"
	"nvelox/core/logging"
	"nvelox/lb"
)

func init() {
	logging.Init("debug", "", "")
}

const testAPIKey = "test-secret-key-12345"

func newTestServer(balancers map[string]lb.Balancer) *Server {
	return NewServer("127.0.0.1:0", testAPIKey, balancers, denylist.New())
}

func authedRequest(method, url string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	req.Header.Set("X-API-Key", testAPIKey)
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

func localRequest(method, url string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

// serve runs req through the server's full handler chain (peer and Host
// checks, cross-origin protection, routing, auth, Content-Type check).
func serve(s *Server, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	return w
}

func TestAdminAPI_Unauthorized(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{
		"be": lb.NewRoundRobin([]string{"s1:80"}),
	})

	// No API key (from localhost)
	req := localRequest("GET", "/api/v1/stats")
	w := httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without API key, got %d", w.Code)
	}
}

func TestAdminAPI_WrongKey(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{
		"be": lb.NewRoundRobin([]string{"s1:80"}),
	})

	for _, key := range []string{"wrong-key", testAPIKey + "x", testAPIKey[:5]} {
		req := localRequest("GET", "/api/v1/stats")
		req.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		srv.authenticate(srv.handleStats)(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("key %q: expected 401, got %d", key, w.Code)
		}
	}
}

func TestAdminAPI_Authorized(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{
		"be1": lb.NewRoundRobin([]string{"s1:80"}),
		"be2": lb.NewRoundRobin([]string{"s2:80"}),
	})

	w := httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, authedRequest("GET", "/api/v1/stats"))

	if w.Code != 200 {
		t.Errorf("expected 200 with valid key, got %d", w.Code)
	}

	var resp StatsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Backends != 2 {
		t.Errorf("expected 2 backends, got %d", resp.Backends)
	}
}

// TestAdminAPI_NoKeyConfiguredRefuses: without an API key the server refuses
// to start, and its handlers authorize nothing — not even a request that
// also sends an empty key. (It used to serve everyone with a warning.)
func TestAdminAPI_NoKeyConfiguredRefuses(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "", map[string]lb.Balancer{
		"be": lb.NewRoundRobin([]string{"s1:80"}),
	}, denylist.New())

	if err := srv.Start(); err == nil || !strings.Contains(err.Error(), "api_key is required") {
		t.Fatalf("Start without a key: err = %v, want an api_key error", err)
	}

	for _, set := range []bool{false, true} {
		req := localRequest("GET", "/api/v1/stats")
		if set {
			req.Header.Set("X-API-Key", "")
		}
		w := httptest.NewRecorder()
		srv.authenticate(srv.handleStats)(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("no key configured (header set=%v): expected 401, got %d", set, w.Code)
		}
	}
}

// TestAdminAPI_StartRejectsBadBind: an unparsable bind is a Start error, not
// a silent fall-through to some other address.
func TestAdminAPI_StartRejectsBadBind(t *testing.T) {
	for _, bind := range []string{"9091", "127.0.0.1", "127.0.0.1:x"} {
		if err := NewServer(bind, testAPIKey, nil, nil).Start(); err == nil {
			t.Errorf("Start with bind %q: want an error", bind)
		}
	}
}

// TestAdminAPI_EmptyBindDefaultsToLoopback: an empty bind listens on
// 127.0.0.1:9091 (not net/http's ":http" = every interface, port 80) and is
// treated as a loopback bind, so a non-loopback peer is refused.
func TestAdminAPI_EmptyBindDefaultsToLoopback(t *testing.T) {
	srv := NewServer("", testAPIKey, map[string]lb.Balancer{}, denylist.New())
	if srv.httpServer.Addr != DefaultBind || DefaultBind != "127.0.0.1:9091" {
		t.Fatalf("empty bind: Addr = %q, want 127.0.0.1:9091", srv.httpServer.Addr)
	}

	req := authedRequest("GET", "http://127.0.0.1:9091/api/v1/stats")
	if w := serve(srv, req); w.Code != http.StatusOK {
		t.Fatalf("loopback peer: expected 200, got %d", w.Code)
	}
	for _, peer := range []string{"10.1.2.3:5555", "not-an-address"} {
		req = authedRequest("GET", "http://127.0.0.1:9091/api/v1/stats")
		req.RemoteAddr = peer
		if w := serve(srv, req); w.Code != http.StatusForbidden {
			t.Errorf("peer %q on a loopback bind: expected 403, got %d", peer, w.Code)
		}
	}
}

// TestAdminAPI_HostHeaderMustNameBind (DNS rebinding): a request whose Host
// is not the bind address is refused even with a valid key.
func TestAdminAPI_HostHeaderMustNameBind(t *testing.T) {
	cases := []struct {
		bind  string
		ok    []string
		notOK []string
	}{
		{"10.0.0.130:9091",
			[]string{"10.0.0.130:9091", "10.0.0.130", "[::ffff:10.0.0.130]:9091"},
			[]string{"attacker.example:9091", "attacker.example", "localhost:9091", "127.0.0.1:9091", "10.0.0.131:9091", ""}},
		{"127.0.0.1:9091",
			[]string{"127.0.0.1:9091", "localhost:9091", "LOCALHOST", "[::1]:9091"},
			[]string{"attacker.example:9091", "10.0.0.130:9091", "localhost.attacker.example:9091"}},
		{"[::1]:9091",
			[]string{"[::1]:9091", "localhost:9091", "[::1]"},
			[]string{"attacker.example:9091"}},
		{":9091",
			[]string{"10.0.0.130:9091", "192.0.2.1", "[2001:db8::1]:9091", "localhost:9091"},
			[]string{"attacker.example:9091", "gw.internal:9091"}},
		{"gw.internal:9091",
			[]string{"gw.internal:9091", "GW.internal"},
			[]string{"10.0.0.130:9091", "attacker.example:9091", "localhost:9091"}},
	}
	for _, c := range cases {
		srv := NewServer(c.bind, testAPIKey, map[string]lb.Balancer{}, denylist.New())
		try := func(host string) int {
			req := authedRequest("GET", "/api/v1/stats")
			req.Host = host
			return serve(srv, req).Code
		}
		for _, h := range c.ok {
			if code := try(h); code != http.StatusOK {
				t.Errorf("bind %s, Host %q: expected 200, got %d", c.bind, h, code)
			}
		}
		for _, h := range c.notOK {
			if code := try(h); code != http.StatusForbidden {
				t.Errorf("bind %s, Host %q: expected 403, got %d", c.bind, h, code)
			}
		}
	}
}

// TestAdminAPI_CrossOriginRefused (CSRF): a browser request marked
// cross-site, or carrying a foreign Origin, cannot change state even if it
// somehow carries the key. Non-browser clients (no such headers) are fine.
func TestAdminAPI_CrossOriginRefused(t *testing.T) {
	srv := NewServer("10.0.0.130:9091", testAPIKey, map[string]lb.Balancer{}, denylist.New())
	post := func(hdr map[string]string) int {
		req := httptest.NewRequest("POST", "http://10.0.0.130:9091/api/v1/denylist", strings.NewReader(`{"ip":"203.0.113.7","ttl_seconds":60}`))
		req.RemoteAddr = "10.0.0.5:40000"
		req.Header.Set("X-API-Key", testAPIKey)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		return serve(srv, req).Code
	}
	for _, hdr := range []map[string]string{
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Origin": "http://attacker.example"},
		{"Origin": "null"},
	} {
		if code := post(hdr); code != http.StatusForbidden {
			t.Errorf("POST with %v: expected 403, got %d", hdr, code)
		}
	}
	if srv.dynDeny.Blocked(net.ParseIP("203.0.113.7")) {
		t.Fatal("a cross-origin POST changed the denylist")
	}
	if code := post(nil); code != http.StatusOK {
		t.Fatalf("POST without browser headers (sentinel, curl): expected 200, got %d", code)
	}
	if code := post(map[string]string{"Sec-Fetch-Site": "same-origin"}); code != http.StatusOK {
		t.Errorf("same-origin POST: expected 200, got %d", code)
	}
}

// TestAdminAPI_RequiresJSONContentType: a state-changing request needs
// Content-Type: application/json, so an HTML form (urlencoded, multipart,
// text/plain) can never drive the API — including the body-less backend
// actions that take their target from the query. A body-less DELETE
// ?cidr= (what ngris-sentinel sends to unblock) needs none.
func TestAdminAPI_RequiresJSONContentType(t *testing.T) {
	balancers := map[string]lb.Balancer{"web": lb.NewRoundRobin([]string{"s1:80", "s2:80"})}
	srv := NewServer("10.0.0.130:9091", testAPIKey, balancers, denylist.New())
	do := func(method, target, ctype, body string) int {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, "http://10.0.0.130:9091"+target, rd)
		req.RemoteAddr = "10.0.0.5:40000"
		req.Header.Set("X-API-Key", testAPIKey)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		return serve(srv, req).Code
	}

	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"} {
		if code := do("POST", "/api/v1/denylist", ct, `{"ip":"203.0.113.7"}`); code != http.StatusUnsupportedMediaType {
			t.Errorf("denylist POST with Content-Type %q: expected 415, got %d", ct, code)
		}
		if code := do("POST", "/api/v1/backends/web/drain?server=s1:80", ct, ""); code != http.StatusUnsupportedMediaType {
			t.Errorf("drain POST with Content-Type %q: expected 415, got %d", ct, code)
		}
	}
	if srv.dynDeny.Blocked(net.ParseIP("203.0.113.7")) || !balancers["web"].IsHealthy("s1:80") {
		t.Fatal("a non-JSON request changed state")
	}

	if code := do("POST", "/api/v1/denylist", "application/json; charset=utf-8", `{"ip":"203.0.113.7"}`); code != http.StatusOK {
		t.Fatalf("JSON denylist POST: expected 200, got %d", code)
	}
	if code := do("POST", "/api/v1/backends/web/drain?server=s1:80", "application/json", ""); code != http.StatusOK || balancers["web"].IsHealthy("s1:80") {
		t.Fatalf("JSON drain POST: code %d, drained=%v", code, !balancers["web"].IsHealthy("s1:80"))
	}
	if code := do("DELETE", "/api/v1/denylist", "text/plain", `{"ip":"203.0.113.7"}`); code != http.StatusUnsupportedMediaType {
		t.Errorf("DELETE with a text/plain body: expected 415, got %d", code)
	}
	if code := do("DELETE", "/api/v1/denylist?cidr=203.0.113.7", "", ""); code != http.StatusOK {
		t.Errorf("body-less DELETE ?cidr=: expected 200, got %d", code)
	}
	if srv.dynDeny.Blocked(net.ParseIP("203.0.113.7")) {
		t.Error("DELETE ?cidr= did not unblock")
	}
}

func TestAdminAPI_Denylist(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{"s1:80"})})

	post := func(jsonBody string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/denylist", strings.NewReader(jsonBody))
		req.Header.Set("X-API-Key", testAPIKey)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		srv.authenticate(srv.handleDenylist)(w, req)
		return w
	}

	// Add a block.
	if w := post(`{"ip":"203.0.113.7","ttl_seconds":3600}`); w.Code != 200 {
		t.Fatalf("POST add: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !srv.dynDeny.Blocked(net.ParseIP("203.0.113.7")) {
		t.Error("203.0.113.7 should be blocked after POST")
	}

	// List shows it.
	wl := httptest.NewRecorder()
	srv.authenticate(srv.handleDenylist)(wl, authedRequest("GET", "/api/v1/denylist"))
	if wl.Code != 200 {
		t.Fatalf("GET list: expected 200, got %d", wl.Code)
	}
	var listResp struct {
		Entries []denylist.Entry `json:"entries"`
	}
	json.NewDecoder(wl.Body).Decode(&listResp)
	if len(listResp.Entries) != 1 || listResp.Entries[0].CIDR != "203.0.113.7" {
		t.Errorf("list should contain 203.0.113.7, got %+v", listResp.Entries)
	}

	// Delete via query param.
	wd := httptest.NewRecorder()
	srv.authenticate(srv.handleDenylist)(wd, authedRequest("DELETE", "/api/v1/denylist?cidr=203.0.113.7"))
	if wd.Code != 200 {
		t.Fatalf("DELETE: expected 200, got %d", wd.Code)
	}
	if srv.dynDeny.Blocked(net.ParseIP("203.0.113.7")) {
		t.Error("203.0.113.7 should be unblocked after DELETE")
	}

	// Invalid IP is rejected.
	if w := post(`{"ip":"not-an-ip"}`); w.Code != http.StatusBadRequest {
		t.Errorf("invalid IP should be 400, got %d", w.Code)
	}

	// Ranges that cover everything (or more than a /8 v4, /16 v6) are
	// refused, permanent (ttl 0) or not, and block nothing.
	for _, ip := range []string{"0.0.0.0/0", "::/0", "::ffff:0:0/96", "64.0.0.0/2", "2000::/3"} {
		for _, ttl := range []int{0, 60} {
			if w := post(fmt.Sprintf(`{"ip":%q,"ttl_seconds":%d}`, ip, ttl)); w.Code != http.StatusBadRequest {
				t.Errorf("POST %s ttl=%d: expected 400, got %d", ip, ttl, w.Code)
			}
		}
	}
	for _, ip := range []string{"198.51.100.1", "100.64.0.1", "2001:db8::9"} {
		if srv.dynDeny.Blocked(net.ParseIP(ip)) {
			t.Errorf("%s blocked after refused block-all requests", ip)
		}
	}
}

// TestAdminAPI_SentinelClientCompat replays ngris-sentinel's exact client
// calls (worker/enforce.go Block/Unblock, worker/apiserver.go pingGateway)
// over real HTTP/1.1 against an admin API configured like the gateways:
// bound to a private IP with an API key, reached by that IP.
func TestAdminAPI_SentinelClientCompat(t *testing.T) {
	srv := NewServer("10.0.0.130:9091", testAPIKey, map[string]lb.Balancer{}, denylist.New())
	ts := httptest.NewServer(srv.httpServer.Handler)
	defer ts.Close()
	// Every dial goes to the test server; the URL (and so the Host header)
	// stays the gateway's http://10.0.0.130:9091, as in sentinel's config.
	tr := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	const base = "http://10.0.0.130:9091"

	do := func(req *http.Request, key string) int {
		t.Helper()
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", req.Method, req.URL, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	// Block (enforce.go Block).
	payload, _ := json.Marshal(map[string]interface{}{"ip": "198.51.100.23", "ttl_seconds": 3600})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/denylist", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if code := do(req, testAPIKey); code != http.StatusOK {
		t.Fatalf("sentinel Block: status %d", code)
	}
	if !srv.dynDeny.Blocked(net.ParseIP("198.51.100.23")) {
		t.Fatal("sentinel Block did not block")
	}

	// Gateway ping (apiserver.go pingGateway).
	req, _ = http.NewRequest(http.MethodGet, base+"/api/v1/denylist", nil)
	if code := do(req, testAPIKey); code != http.StatusOK {
		t.Fatalf("sentinel ping: status %d", code)
	}

	// Unblock (enforce.go Unblock): DELETE ?cidr=, no body, no Content-Type.
	req, _ = http.NewRequest(http.MethodDelete, base+"/api/v1/denylist?cidr="+url.QueryEscape("198.51.100.23"), nil)
	if code := do(req, testAPIKey); code != http.StatusOK {
		t.Fatalf("sentinel Unblock: status %d", code)
	}
	if srv.dynDeny.Blocked(net.ParseIP("198.51.100.23")) {
		t.Fatal("sentinel Unblock did not unblock")
	}

	// Wrong key → 401.
	req, _ = http.NewRequest(http.MethodGet, base+"/api/v1/denylist", nil)
	if code := do(req, "not-the-key"); code != http.StatusUnauthorized {
		t.Errorf("wrong key: status %d, want 401", code)
	}
}

// TestAdminAPI_StartServesOnBind: Start listens on the configured address
// and serves an authenticated request end to end.
func TestAdminAPI_StartServesOnBind(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv := NewServer(addr, testAPIKey, map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{"s1:80"})}, denylist.New())
	if srv.httpServer.ReadHeaderTimeout == 0 || srv.httpServer.MaxHeaderBytes == 0 {
		t.Error("admin server must set ReadHeaderTimeout and MaxHeaderBytes")
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop(context.Background())

	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/api/v1/stats", nil)
		req.Header.Set("X-API-Key", testAPIKey)
		resp, err = http.DefaultClient.Do(req)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET stats: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET stats: status %d", resp.StatusCode)
	}
}

func TestAdminAPI_Backends(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{
		"web": lb.NewRoundRobin([]string{"s1:80"}),
	})

	w := httptest.NewRecorder()
	srv.handleBackends(w, authedRequest("GET", "/api/v1/backends"))

	var backends []BackendStatus
	json.NewDecoder(w.Body).Decode(&backends)
	if len(backends) != 1 {
		t.Errorf("expected 1 backend, got %d", len(backends))
	}
}

func TestAdminAPI_DrainServer(t *testing.T) {
	balancers := map[string]lb.Balancer{
		"web": lb.NewRoundRobin([]string{"s1:80", "s2:80"}),
	}
	srv := newTestServer(balancers)

	w := httptest.NewRecorder()
	srv.handleBackendAction(w, authedRequest("POST", "/api/v1/backends/web/drain?server=s1:80"))

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if balancers["web"].IsHealthy("s1:80") {
		t.Error("s1 should be drained")
	}
}

func TestAdminAPI_EnableDisable(t *testing.T) {
	balancers := map[string]lb.Balancer{
		"web": lb.NewRoundRobin([]string{"s1:80"}),
	}
	srv := newTestServer(balancers)

	// Disable
	w := httptest.NewRecorder()
	srv.handleBackendAction(w, authedRequest("POST", "/api/v1/backends/web/disable?server=s1:80"))
	if balancers["web"].IsHealthy("s1:80") {
		t.Error("s1 should be disabled")
	}

	// Enable
	w = httptest.NewRecorder()
	srv.handleBackendAction(w, authedRequest("POST", "/api/v1/backends/web/enable?server=s1:80"))
	if !balancers["web"].IsHealthy("s1:80") {
		t.Error("s1 should be enabled")
	}
}

func TestAdminAPI_NotFound(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{})

	w := httptest.NewRecorder()
	srv.handleBackendAction(w, authedRequest("POST", "/api/v1/backends/missing/drain?server=s1"))
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// TestAdminAPI_ValidKeyServedDuringLockout (L1): authFailThreshold failed
// attempts from one IP lock that IP's FAILURES out (429 + Retry-After), but a
// request from the same IP with the valid key is still served — an attacker
// sharing an address with the legitimate caller (NAT, SNAT'd pods) cannot
// lock it out.
func TestAdminAPI_ValidKeyServedDuringLockout(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{
		"be": lb.NewRoundRobin([]string{"s1:80"}),
	})

	bad := func() *httptest.ResponseRecorder {
		req := localRequest("GET", "/api/v1/stats")
		req.Header.Set("X-API-Key", "wrong")
		w := httptest.NewRecorder()
		srv.authenticate(srv.handleStats)(w, req)
		return w
	}

	// The first authFailThreshold failures get 401; the last starts the lockout.
	for i := 0; i < authFailThreshold; i++ {
		if w := bad(); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}

	// A good request from the same IP is served.
	w := httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, authedRequest("GET", "/api/v1/stats"))
	if w.Code != http.StatusOK {
		t.Fatalf("valid key after %d failures: expected 200, got %d", authFailThreshold, w.Code)
	}

	// Lock out again; failures during the lockout are throttled.
	for i := 0; i < authFailThreshold; i++ {
		bad()
	}
	w = bad()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("failure during lockout: expected 429, got %d", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("429 without a usable Retry-After (%q)", ra)
	}
	// ...and the valid key is still served during the lockout.
	w = httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, authedRequest("GET", "/api/v1/stats"))
	if w.Code != http.StatusOK {
		t.Errorf("valid key during lockout: expected 200, got %d", w.Code)
	}
}

// TestAdminAPI_SuccessClearsFailures verifies that a successful auth
// resets the failure counter, so one success absolves prior misfires.
func TestAdminAPI_SuccessClearsFailures(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{
		"be": lb.NewRoundRobin([]string{"s1:80"}),
	})

	// A few failures, but below threshold.
	for i := 0; i < 3; i++ {
		req := localRequest("GET", "/api/v1/stats")
		req.Header.Set("X-API-Key", "wrong")
		srv.authenticate(srv.handleStats)(httptest.NewRecorder(), req)
	}

	// One success clears counters.
	srv.authenticate(srv.handleStats)(httptest.NewRecorder(), authedRequest("GET", "/api/v1/stats"))

	// Now we should be able to accumulate full threshold-1 NEW failures.
	for i := 0; i < authFailThreshold-1; i++ {
		req := localRequest("GET", "/api/v1/stats")
		req.Header.Set("X-API-Key", "wrong")
		w := httptest.NewRecorder()
		srv.authenticate(srv.handleStats)(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d after success-clear: expected 401, got %d", i+1, w.Code)
		}
	}

	// Valid key must still work — we haven't hit threshold yet post-clear.
	w := httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, authedRequest("GET", "/api/v1/stats"))
	if w.Code != http.StatusOK {
		t.Errorf("post-clear valid key must succeed, got %d", w.Code)
	}
}

// TestAdminAPI_AuthFailureTableBounded: failures from many source IPs never
// grow the table past authMaxTracked; once full, a failure from a new IP is
// throttled without a record (a valid key from a new IP is still served),
// and expired records are pruned.
func TestAdminAPI_AuthFailureTableBounded(t *testing.T) {
	// Thousands of failures: keep their Warn lines out of the test output.
	logging.Init("error", "", "")
	defer logging.Init("debug", "", "")
	srv := newTestServer(map[string]lb.Balancer{})
	fail := func(ip string) int {
		req := localRequest("GET", "/api/v1/stats")
		req.RemoteAddr = ip + ":1234"
		req.Header.Set("X-API-Key", "wrong")
		w := httptest.NewRecorder()
		srv.authenticate(srv.handleStats)(w, req)
		return w.Code
	}

	for i := 0; i < authMaxTracked+500; i++ {
		fail(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	srv.authMu.Lock()
	n := len(srv.authFailures)
	srv.authMu.Unlock()
	if n > authMaxTracked {
		t.Fatalf("failure table grew to %d entries, cap %d", n, authMaxTracked)
	}
	if code := fail("192.0.2.200"); code != http.StatusTooManyRequests {
		t.Errorf("failure from a new IP with the table full: expected 429, got %d", code)
	}
	req := authedRequest("GET", "/api/v1/stats")
	req.RemoteAddr = "192.0.2.201:1234"
	w := httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("valid key from a new IP with the table full: expected 200, got %d", w.Code)
	}

	// Age every record past its window (none is locked) → the next failure
	// prunes them all.
	srv.authMu.Lock()
	old := time.Now().Add(-authFailWindow - time.Minute)
	for _, a := range srv.authFailures {
		a.firstFailAt = old
	}
	srv.lastPrune = old
	srv.authMu.Unlock()
	if code := fail("192.0.2.202"); code != http.StatusUnauthorized {
		t.Errorf("failure after the prune: expected 401, got %d", code)
	}
	srv.authMu.Lock()
	n = len(srv.authFailures)
	srv.authMu.Unlock()
	if n != 1 {
		t.Errorf("after pruning expired records the table holds %d entries, want 1", n)
	}
}
