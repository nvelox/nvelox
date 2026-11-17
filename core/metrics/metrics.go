package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// MaxSeriesPerMetricType caps the number of distinct label combinations
// per metric type (counters, gauges) to prevent an attacker from inflating
// cardinality with user-controlled labels (e.g. paths, user-agents) and
// exhausting memory. Series beyond the cap are dropped and counted via
// the "metrics_dropped_series_total" counter.
const MaxSeriesPerMetricType = 10000

// Registry holds all metrics for Prometheus exposition.
type Registry struct {
	counters      sync.Map // name+labels -> *Counter
	gauges        sync.Map // name+labels -> *Gauge
	histograms    sync.Map // name -> *Histogram
	counterCount  int64
	gaugeCount    int64
	droppedSeries uint64 // counter of attempts rejected due to cardinality cap
}

// Global registry
var Default = &Registry{}

// DroppedSeries returns the number of times a series was rejected due to
// cardinality overflow. Useful for monitoring if the cap is hit in prod.
func (r *Registry) DroppedSeries() uint64 {
	return atomic.LoadUint64(&r.droppedSeries)
}

// Counter is a monotonically increasing counter.
type Counter struct {
	value uint64
}

func (c *Counter) Inc()          { atomic.AddUint64(&c.value, 1) }
func (c *Counter) Add(n uint64)  { atomic.AddUint64(&c.value, n) }
func (c *Counter) Get() uint64   { return atomic.LoadUint64(&c.value) }

// Gauge is a value that can go up and down.
type Gauge struct {
	value int64
}

func (g *Gauge) Inc()         { atomic.AddInt64(&g.value, 1) }
func (g *Gauge) Dec()         { atomic.AddInt64(&g.value, -1) }
func (g *Gauge) Set(v int64)  { atomic.StoreInt64(&g.value, v) }
func (g *Gauge) Get() int64   { return atomic.LoadInt64(&g.value) }

// Histogram tracks value distributions in fixed buckets.
type Histogram struct {
	mu      sync.Mutex
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

func NewHistogram(buckets []float64) *Histogram {
	sort.Float64s(buckets)
	return &Histogram{
		buckets: buckets,
		counts:  make([]uint64, len(buckets)),
	}
}

func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.count++
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
}

// overflow sinks shared by all label combinations rejected due to the
// cardinality cap. Increments still happen so traffic isn't lost, but no
// new series is created in the registry.
var (
	overflowCounter = &Counter{}
	overflowGauge   = &Gauge{}
)

// GetCounter returns or creates a counter with the given name and labels.
// If creating a new series would exceed MaxSeriesPerMetricType, a shared
// overflow counter is returned and droppedSeries is incremented.
func (r *Registry) GetCounter(name string, labels map[string]string) *Counter {
	key := metricKey(name, labels)
	if v, ok := r.counters.Load(key); ok {
		return v.(*Counter)
	}
	if atomic.LoadInt64(&r.counterCount) >= MaxSeriesPerMetricType {
		atomic.AddUint64(&r.droppedSeries, 1)
		return overflowCounter
	}
	c := &Counter{}
	actual, loaded := r.counters.LoadOrStore(key, c)
	if !loaded {
		atomic.AddInt64(&r.counterCount, 1)
	}
	return actual.(*Counter)
}

// GetGauge returns or creates a gauge with the given name and labels.
// If creating a new series would exceed MaxSeriesPerMetricType, a shared
// overflow gauge is returned and droppedSeries is incremented.
func (r *Registry) GetGauge(name string, labels map[string]string) *Gauge {
	key := metricKey(name, labels)
	if v, ok := r.gauges.Load(key); ok {
		return v.(*Gauge)
	}
	if atomic.LoadInt64(&r.gaugeCount) >= MaxSeriesPerMetricType {
		atomic.AddUint64(&r.droppedSeries, 1)
		return overflowGauge
	}
	g := &Gauge{}
	actual, loaded := r.gauges.LoadOrStore(key, g)
	if !loaded {
		atomic.AddInt64(&r.gaugeCount, 1)
	}
	return actual.(*Gauge)
}

// GetHistogram returns or creates a histogram.
func (r *Registry) GetHistogram(name string) *Histogram {
	if v, ok := r.histograms.Load(name); ok {
		return v.(*Histogram)
	}
	h := NewHistogram([]float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 10000})
	actual, _ := r.histograms.LoadOrStore(name, h)
	return actual.(*Histogram)
}

// Handler returns an http.Handler that exposes metrics in Prometheus text format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var sb strings.Builder

		// Counters
		r.counters.Range(func(key, value interface{}) bool {
			k := key.(string)
			c := value.(*Counter)
			name, labels := parseKey(k)
			fmt.Fprintf(&sb, "%s{%s} %d\n", name, labels, c.Get())
			return true
		})

		// Gauges
		r.gauges.Range(func(key, value interface{}) bool {
			k := key.(string)
			g := value.(*Gauge)
			name, labels := parseKey(k)
			fmt.Fprintf(&sb, "%s{%s} %d\n", name, labels, g.Get())
			return true
		})

		// Histograms
		r.histograms.Range(func(key, value interface{}) bool {
			name := key.(string)
			h := value.(*Histogram)
			h.mu.Lock()
			defer h.mu.Unlock()
			cumulative := uint64(0)
			for i, b := range h.buckets {
				cumulative += h.counts[i]
				fmt.Fprintf(&sb, "%s_bucket{le=\"%.0f\"} %d\n", name, b, cumulative)
			}
			fmt.Fprintf(&sb, "%s_bucket{le=\"+Inf\"} %d\n", name, h.count)
			fmt.Fprintf(&sb, "%s_sum %f\n", name, h.sum)
			fmt.Fprintf(&sb, "%s_count %d\n", name, h.count)
			return true
		})

		w.Write([]byte(sb.String()))
	})
}

func metricKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name + "|"
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(name)
	sb.WriteByte('|')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%s=\"%s\"", k, labels[k])
	}
	return sb.String()
}

func parseKey(key string) (string, string) {
	idx := strings.Index(key, "|")
	if idx == -1 {
		return key, ""
	}
	return key[:idx], key[idx+1:]
}
