package metrics

import (
	"fmt"
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

// TestCardinalityCap_Counter verifies that once MaxSeriesPerMetricType
// distinct counter series are registered, additional label combinations
// are served by the shared overflow counter and the drop counter grows.
// Protects against an attacker inflating cardinality via user-controlled
// labels (paths, user-agents, etc.) to exhaust memory.
func TestCardinalityCap_Counter(t *testing.T) {
	r := &Registry{}
	// Fill up to the cap with distinct labels.
	for i := 0; i < MaxSeriesPerMetricType; i++ {
		r.GetCounter("cap_test", map[string]string{"id": fmt.Sprintf("%d", i)}).Inc()
	}
	if r.DroppedSeries() != 0 {
		t.Fatalf("expected 0 drops while filling, got %d", r.DroppedSeries())
	}

	// Beyond the cap: the next 100 unique labels must all share the overflow sink.
	var first *Counter
	for i := 0; i < 100; i++ {
		c := r.GetCounter("cap_test", map[string]string{"id": fmt.Sprintf("overflow-%d", i)})
		if first == nil {
			first = c
		} else if c != first {
			t.Fatal("overflow labels must share the same overflow counter instance")
		}
		c.Inc()
	}
	if r.DroppedSeries() != 100 {
		t.Errorf("expected 100 dropped series, got %d", r.DroppedSeries())
	}
	// Existing series still work (re-lookup of a known label).
	r.GetCounter("cap_test", map[string]string{"id": "0"}).Inc()
	if r.DroppedSeries() != 100 {
		t.Errorf("existing-series lookup must not count as a drop; got %d", r.DroppedSeries())
	}
}

func TestCardinalityCap_Gauge(t *testing.T) {
	r := &Registry{}
	for i := 0; i < MaxSeriesPerMetricType; i++ {
		r.GetGauge("cap_gauge", map[string]string{"id": fmt.Sprintf("%d", i)}).Inc()
	}
	g := r.GetGauge("cap_gauge", map[string]string{"id": "overflow"})
	g2 := r.GetGauge("cap_gauge", map[string]string{"id": "overflow-b"})
	if g != g2 {
		t.Error("overflow gauges must share the same instance")
	}
	if r.DroppedSeries() < 2 {
		t.Errorf("expected >=2 dropped gauges, got %d", r.DroppedSeries())
	}
}
