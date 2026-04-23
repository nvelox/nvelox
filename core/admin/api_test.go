package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"nvelox/lb"
)

func TestAdminAPI_Stats(t *testing.T) {
	balancers := map[string]lb.Balancer{
		"be1": lb.NewRoundRobin([]string{"s1:80"}),
		"be2": lb.NewRoundRobin([]string{"s2:80"}),
	}

	srv := NewServer(":0", balancers)
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp StatsResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Backends != 2 {
		t.Errorf("expected 2 backends, got %d", resp.Backends)
	}
	if resp.Uptime == "" {
		t.Error("expected uptime")
	}
}

func TestAdminAPI_Backends(t *testing.T) {
	balancers := map[string]lb.Balancer{
		"web": lb.NewRoundRobin([]string{"s1:80"}),
	}

	srv := NewServer(":0", balancers)
	req := httptest.NewRequest("GET", "/api/v1/backends", nil)
	w := httptest.NewRecorder()
	srv.handleBackends(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

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

	srv := NewServer(":0", balancers)
	req := httptest.NewRequest("POST", "/api/v1/backends/web/drain?server=s1:80", nil)
	w := httptest.NewRecorder()
	srv.handleBackendAction(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// s1 should be drained (unhealthy)
	if balancers["web"].IsHealthy("s1:80") {
		t.Error("s1 should be drained")
	}
	if !balancers["web"].IsHealthy("s2:80") {
		t.Error("s2 should still be healthy")
	}
}

func TestAdminAPI_EnableDisable(t *testing.T) {
	balancers := map[string]lb.Balancer{
		"web": lb.NewRoundRobin([]string{"s1:80"}),
	}

	srv := NewServer(":0", balancers)

	// Disable
	req := httptest.NewRequest("POST", "/api/v1/backends/web/disable?server=s1:80", nil)
	w := httptest.NewRecorder()
	srv.handleBackendAction(w, req)

	if balancers["web"].IsHealthy("s1:80") {
		t.Error("s1 should be disabled")
	}

	// Enable
	req = httptest.NewRequest("POST", "/api/v1/backends/web/enable?server=s1:80", nil)
	w = httptest.NewRecorder()
	srv.handleBackendAction(w, req)

	if !balancers["web"].IsHealthy("s1:80") {
		t.Error("s1 should be enabled")
	}
}

func TestAdminAPI_NotFound(t *testing.T) {
	srv := NewServer(":0", map[string]lb.Balancer{})

	req := httptest.NewRequest("POST", "/api/v1/backends/missing/drain?server=s1", nil)
	w := httptest.NewRecorder()
	srv.handleBackendAction(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
