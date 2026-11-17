package core

import (
	"net/http"
	"time"
)

// defaultMetricsBind is where the metrics endpoint listens when metrics.bind
// is empty: loopback only. (Before, an empty bind fell through to net/http's
// ":http" — every interface on port 80.)
const defaultMetricsBind = "127.0.0.1:9090"

// newMetricsServer builds the Prometheus endpoint's HTTP server. A scrape is
// one small GET, so the limits are tight: a client that trickles its headers
// or body, sends oversized headers, or never reads the response is cut off
// instead of holding a connection and a goroutine open indefinitely.
func newMetricsServer(bind string, h http.Handler) *http.Server {
	if bind == "" {
		bind = defaultMetricsBind
	}
	return &http.Server{
		Addr:              bind,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}
