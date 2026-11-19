package core

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nvelox/ngx"

	"nvelox/core/logging"
	"nvelox/core/metrics"
)

// A panic the event loops recovered from is counted by protocol, every
// protocol's series being there from the start, and written to the error
// log with its stack; its value cannot start a log line of its own.
func TestReportPanic(t *testing.T) {
	rec := httptest.NewRecorder()
	metrics.Default.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, p := range panicProtocols {
		if !strings.Contains(rec.Body.String(), `nvelox_recovered_panics_total{protocol="`+p+`"} `) {
			t.Fatalf("no series for %s before any panic:\n%s", p, rec.Body.String())
		}
	}

	errPath := filepath.Join(t.TempDir(), "error.log")
	if err := logging.Init("error", "", errPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("info", "", "") })

	udp := metrics.Default.GetCounter(panicMetric, map[string]string{"protocol": "udp"})
	tcp := metrics.Default.GetCounter(panicMetric, map[string]string{"protocol": "tcp"})
	udpBefore, tcpBefore := udp.Get(), tcp.Get()
	func() {
		defer func() {
			if r := recover(); r != nil {
				ngx.ReportPanic("udp", "datagram from 192.0.2.1:5000", r)
			}
		}()
		panicWith("a client's bytes\nERR a line it forged")
	}()
	if got := udp.Get() - udpBefore; got != 1 {
		t.Fatalf("the udp series moved by %d, want 1", got)
	}
	if got := tcp.Get() - tcpBefore; got != 0 {
		t.Fatalf("the tcp series moved by %d, want 0", got)
	}

	b, err := os.ReadFile(errPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(b)
	if !strings.Contains(log, `[UDP] datagram from 192.0.2.1:5000: panic: a client's bytes\nERR a line it forged (that connection is closed; the others go on)`) {
		t.Fatalf("the error log does not have the panic's line:\n%s", log)
	}
	if strings.Contains(log, "\nERR a line it forged") {
		t.Fatalf("the panic's value started a log line of its own:\n%s", log)
	}
	if !strings.Contains(log, "panicWith") {
		t.Fatalf("the error log does not have the stack down to the panic:\n%s", log)
	}
}

func panicWith(v string) { panic(v) }

func TestPanicLogTag(t *testing.T) {
	for p, want := range map[string]string{"http": "HTTP", "http2": "HTTP", "http3": "HTTP", "quic": "HTTP", "tcp": "CONN", "udp": "UDP"} {
		if got := panicLogTag(p); got != want {
			t.Errorf("panicLogTag(%q) = %q, want %q", p, got, want)
		}
	}
}
