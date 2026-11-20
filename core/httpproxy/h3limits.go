package httpproxy

import (
	"sync/atomic"

	"github.com/nvelox/ngx/web"

	"nvelox/config"
)

// h3Set is server.http3 as the engine gave it (SetHTTP3Limits): as the
// configuration has it, and the same in the form the event loops take it.
type h3Set struct {
	cfg  config.HTTP3Limits
	fast web.H3Limits
}

func newH3Set(l config.HTTP3Limits) *h3Set {
	return &h3Set{cfg: l, fast: web.H3Limits{
		MaxHeaderSize:              l.MaxHeaderSize,
		MaxSendBuffer:              l.MaxSendBuffer,
		MaxStreamReceiveWindow:     l.MaxStreamReceiveWindow,
		MaxConnectionReceiveWindow: l.MaxConnectionReceiveWindow,
		MaxSendMemory:              l.MaxSendMemory,
		MaxReceiveMemory:           l.MaxReceiveMemory,
		SocketBuffer:               l.SocketBuffer,
		HandshakesPerSource:        l.HandshakesPerSource,
	}}
}

// h3Limits is server.http3 as the engine last gave it; nil until it has:
// the defaults are in use.
var h3Limits atomic.Pointer[h3Set]

// h3DefaultLimits is server.http3 with nothing set.
var h3DefaultLimits = newH3Set(config.HTTP3Config{}.Resolve())

// SetHTTP3Limits makes l the limits of the HTTP/3 connections of the
// process (server.http3). The engine calls it when it starts and at every
// reload. The two totals apply at once. A connection keeps the limits it
// was opened with, and the connections opened from now on have l's. (The
// quic-go server, which serves HTTP/3 where there are no event loops,
// takes its limits when its bind address starts.)
func SetHTTP3Limits(l config.HTTP3Limits) {
	s := newH3Set(l)
	h3Limits.Store(s)
	web.SetH3Memory(&s.fast)
}

// HTTP3Limits returns the limits in use.
func HTTP3Limits() config.HTTP3Limits { return *http3Limits() }

// http3Limits returns the limits in use.
func http3Limits() *config.HTTP3Limits { return &h3LimitsNow().cfg }

// fastH3Limits returns the limits in use as the event loops take them
// (Hooks.H3Limits). The pointer is the same for as long as they are: a
// loop compares it to tell that they changed.
func fastH3Limits() *web.H3Limits { return &h3LimitsNow().fast }

func h3LimitsNow() *h3Set {
	if s := h3Limits.Load(); s != nil {
		return s
	}
	return h3DefaultLimits
}
