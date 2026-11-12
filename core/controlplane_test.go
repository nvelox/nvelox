package core

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestNewMetricsServer_Hardened: the metrics endpoint gets read/write/idle
// timeouts and an 8 KiB header cap (it had none), and an empty bind means
// loopback 127.0.0.1:9090 (it meant every interface on port 80).
func TestNewMetricsServer_Hardened(t *testing.T) {
	s := newMetricsServer("", http.NotFoundHandler())
	if s.Addr != "127.0.0.1:9090" {
		t.Errorf("empty bind: Addr = %q, want 127.0.0.1:9090", s.Addr)
	}
	if s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != 10*time.Second ||
		s.WriteTimeout != 10*time.Second || s.IdleTimeout != 30*time.Second {
		t.Errorf("timeouts = header %v read %v write %v idle %v, want 5s/10s/10s/30s",
			s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout)
	}
	if s.MaxHeaderBytes != 8<<10 {
		t.Errorf("MaxHeaderBytes = %d, want 8192", s.MaxHeaderBytes)
	}
	if got := newMetricsServer("10.0.0.130:9090", http.NotFoundHandler()).Addr; got != "10.0.0.130:9090" {
		t.Errorf("explicit bind rewritten to %q", got)
	}
}

// TestMetricsServer_RejectsOversizedHeaders serves the real metrics server on
// a socket: a scrape works, a request with 32 KiB of headers is refused (431)
// instead of being buffered up to net/http's 1 MiB default.
func TestMetricsServer_RejectsOversizedHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "up 1") })
	srv := newMetricsServer(ln.Addr().String(), mux)
	go srv.Serve(ln)
	defer srv.Close()

	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape: status %d", resp.StatusCode)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /metrics HTTP/1.1\r\nHost: x\r\nX-Pad: %s\r\n\r\n", strings.Repeat("a", 32<<10))
	r, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("oversized headers: %v", err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("32 KiB of headers: status %d, want 431", r.StatusCode)
	}
}
