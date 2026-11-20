package core

import (
	"fmt"

	"github.com/nvelox/ngx"

	"nvelox/core/logging"
	"nvelox/core/metrics"
)

// A panic in the code that serves one connection on the event loops (an
// HTTP/1.1, HTTP/2, HTTP/3 or QUIC connection, a TCP or UDP session) ends
// that connection and no other: the engine recovers where a loop enters a
// connection's code. nvelox writes the panic to the error log, with its
// stack, and counts it in nvelox_recovered_panics_total{protocol}. Every
// protocol's series exists from the start, at 0, so that an alert on its
// increase fires on the first panic.

// panicMetric counts the panics the event loops recovered from.
const panicMetric = "nvelox_recovered_panics_total"

// panicProtocols are the values of the metric's protocol label.
var panicProtocols = []string{"http", "http2", "http3", "quic", "tcp", "udp"}

func init() {
	for _, p := range panicProtocols {
		metrics.Default.GetCounter(panicMetric, map[string]string{"protocol": p})
	}
	ngx.OnPanic(reportPanic)
}

// reportPanic writes a panic the event loops recovered from to the error
// log and counts it. The panic's value may hold bytes a client sent: like
// every such field, it is written without its control characters, so that
// it cannot start a log line of its own.
func reportPanic(p ngx.Panic) {
	metrics.Default.GetCounter(panicMetric, map[string]string{"protocol": p.Protocol}).Inc()
	logging.Error("[%s] %s: panic: %s (that connection is closed; the others go on)\n%s",
		panicLogTag(p.Protocol), logging.SanitizeLogField(p.What), logging.SanitizeLogField(fmt.Sprint(p.Value)), p.Stack)
}

// panicLogTag is the tag of the error-log line: the one the protocol's
// other lines carry.
func panicLogTag(protocol string) string {
	switch protocol {
	case "tcp":
		return "CONN"
	case "udp":
		return "UDP"
	}
	return "HTTP"
}
