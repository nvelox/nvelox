package httpproxy

import (
	"net/http/httptest"
	"strings"
	"testing"

	"nvelox/core/metrics"
)

// A QUIC client's first packet that an event loop drops because its address
// has server.http3.handshakes_per_source handshakes running is counted in
// nvelox_h3_handshakes_refused_total{reason="per_source"}, which the metrics
// endpoint exports; a reason nvelox does not know is not counted.
func TestHTTP3_HandshakeRefusedCounted(t *testing.T) {
	before := h3RefusedPerSource.Get()
	h3HandshakeRefused("per_source")
	h3HandshakeRefused("per_source")
	h3HandshakeRefused("something else")
	if got := h3RefusedPerSource.Get() - before; got != 2 {
		t.Fatalf("two refusals for the address counted as %d", got)
	}
	rec := httptest.NewRecorder()
	metrics.Default.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `nvelox_h3_handshakes_refused_total{reason="per_source"}`) {
		t.Fatalf("the metrics endpoint does not export the refusals:\n%s", rec.Body.String())
	}
}
