package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounter(t *testing.T) {
	r := &Registry{}
	c := r.GetCounter("requests_total", map[string]string{"method": "GET"})

	c.Inc()
	c.Inc()
	c.Inc()

	if c.Get() != 3 {
		t.Errorf("expected 3, got %d", c.Get())
	}
}

func TestGauge(t *testing.T) {
	r := &Registry{}
	g := r.GetGauge("active_connections", map[string]string{"listener": "web"})

	g.Inc()
	g.Inc()
	g.Dec()

	if g.Get() != 1 {
		t.Errorf("expected 1, got %d", g.Get())
	}
}

func TestHistogram(t *testing.T) {
	r := &Registry{}
	h := r.GetHistogram("request_duration_ms")

	h.Observe(5)
	h.Observe(15)
	h.Observe(150)

	if h.count != 3 {
		t.Errorf("expected count 3, got %d", h.count)
	}
	if h.sum != 170 {
		t.Errorf("expected sum 170, got %f", h.sum)
	}
}

func TestHandler_Output(t *testing.T) {
	r := &Registry{}
	r.GetCounter("http_requests_total", map[string]string{"status": "200"}).Add(42)
	r.GetGauge("active_conns", map[string]string{"listener": "web"}).Set(5)
	h := r.GetHistogram("latency_ms")
	h.Observe(10)
	h.Observe(100)

	handler := r.Handler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	if !strings.Contains(output, "http_requests_total") {
		t.Error("missing counter in output")
	}
	if !strings.Contains(output, "42") {
		t.Error("missing counter value 42")
	}
	if !strings.Contains(output, "active_conns") {
		t.Error("missing gauge in output")
	}
	if !strings.Contains(output, "latency_ms_bucket") {
		t.Error("missing histogram buckets")
	}
	if !strings.Contains(output, "latency_ms_count 2") {
		t.Error("missing histogram count")
	}
}

func TestGetCounter_SameKey(t *testing.T) {
	r := &Registry{}
	c1 := r.GetCounter("test", map[string]string{"a": "1"})
	c2 := r.GetCounter("test", map[string]string{"a": "1"})

	c1.Inc()
	if c2.Get() != 1 {
		t.Error("same key should return same counter")
	}
}

func TestGetCounter_DifferentLabels(t *testing.T) {
	r := &Registry{}
	c1 := r.GetCounter("test", map[string]string{"a": "1"})
	c2 := r.GetCounter("test", map[string]string{"a": "2"})

	c1.Inc()
	if c2.Get() != 0 {
		t.Error("different labels should be different counters")
	}
}
