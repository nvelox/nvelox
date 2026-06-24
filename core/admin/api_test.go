package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	req := localRequest("GET", "/api/v1/stats")
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong key, got %d", w.Code)
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

func TestAdminAPI_NoKeyConfigured(t *testing.T) {
	// No API key = allow all (with warning logged)
	srv := NewServer("127.0.0.1:0", "", map[string]lb.Balancer{
		"be": lb.NewRoundRobin([]string{"s1:80"}),
	}, denylist.New())

	w := httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, localRequest("GET", "/api/v1/stats"))

	if w.Code != 200 {
		t.Errorf("expected 200 when no API key configured, got %d", w.Code)
	}
}

func TestAdminAPI_Denylist(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{"s1:80"})})

	post := func(jsonBody string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/denylist", strings.NewReader(jsonBody))
		req.Header.Set("X-API-Key", testAPIKey)
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

// TestAdminAPI_LockoutAfterFailures fires authFailThreshold failed auth
// attempts from one source IP and verifies subsequent requests from that
// IP get 429 (Too Many Requests) regardless of whether they use a valid key.
// Prevents online brute-force of the API key.
func TestAdminAPI_LockoutAfterFailures(t *testing.T) {
	srv := newTestServer(map[string]lb.Balancer{
		"be": lb.NewRoundRobin([]string{"s1:80"}),
	})

	// Fire threshold-1 failures: still accept further attempts.
	for i := 0; i < authFailThreshold-1; i++ {
		req := localRequest("GET", "/api/v1/stats")
		req.Header.Set("X-API-Key", "wrong")
		w := httptest.NewRecorder()
		srv.authenticate(srv.handleStats)(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}

	// The Nth failure triggers lockout.
	req := localRequest("GET", "/api/v1/stats")
	req.Header.Set("X-API-Key", "wrong")
	w := httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("final failure: expected 401, got %d", w.Code)
	}

	// Now even a VALID key from the same IP must be rejected with 429.
	w = httptest.NewRecorder()
	srv.authenticate(srv.handleStats)(w, authedRequest("GET", "/api/v1/stats"))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("locked-out IP with valid key: expected 429, got %d", w.Code)
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
