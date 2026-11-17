package core

import (
	"sync/atomic"

	"github.com/nvelox/ngx"
)

// udpFastOff turns the event-loop UDP engine (udpfast_linux.go) off for
// engines started from now on: the nbio engine serves UDP then, as it does
// where event loops are not supported (tests run both).
var udpFastOff atomic.Bool

func udpFastEnabled() bool { return ngx.Supported() && !udpFastOff.Load() }
