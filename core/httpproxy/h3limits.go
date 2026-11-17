package httpproxy

import (
	"sync/atomic"

	"nvelox/config"
)

// h3Limits is server.http3 as the engine last gave it (SetHTTP3Limits);
// nil until it has: the defaults are in use.
var h3Limits atomic.Pointer[config.HTTP3Limits]

// h3DefaultLimits is server.http3 with nothing set.
var h3DefaultLimits = config.HTTP3Config{}.Resolve()

// SetHTTP3Limits makes l the limits of the HTTP/3 connections of the
// process (server.http3). The engine calls it when it starts and at every
// reload. The two totals apply at once. A connection keeps the limits it
// was opened with, and the connections opened from now on have l's. (The
// quic-go server, which serves HTTP/3 where there are no event loops,
// takes its limits when its bind address starts.)
func SetHTTP3Limits(l config.HTTP3Limits) {
	h3Limits.Store(&l)
	applyHTTP3Memory(&l)
}

// HTTP3Limits returns the limits in use.
func HTTP3Limits() config.HTTP3Limits { return *http3Limits() }

// http3Limits returns the limits in use. The pointer is the same for as
// long as they are: a loop compares it to tell that they changed.
func http3Limits() *config.HTTP3Limits {
	if l := h3Limits.Load(); l != nil {
		return l
	}
	return &h3DefaultLimits
}
