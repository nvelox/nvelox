//go:build linux

package core

import (
	"runtime"
	"sync"

	"github.com/nvelox/ngx"
)

var (
	schedulerSlotsOnce sync.Once
	// slotsBefore is GOMAXPROCS as the process started with it.
	slotsBefore int
)

// SpareSchedulerSlots gives Go's scheduler as many slots (Ps) again as
// there are event loops, once per process. main calls it before anything
// is served.
//
// A loop keeps its slot while it sleeps in epoll_wait, and the runtime
// takes a sleeping thread's slot back only after 10 to 20 ms on a quiet
// process. With one slot and one loop per CPU, whatever runs beside the
// loops (a TLS handshake, a request handed to net/http, a health check)
// waited that long whenever every slot was a sleeping loop's: up to 20 ms
// for about one in a hundred handed-over requests on two cores, none
// with slots of its own (1,000 requests each, the same process switching
// between the two).
//
// The loops are started here, one per CPU as before. The extra slots are
// threads only while there is work beside the loops.
func SpareSchedulerSlots() {
	schedulerSlotsOnce.Do(func() {
		slotsBefore = runtime.GOMAXPROCS(0)
		addSchedulerSlots(slotsBefore)
	})
}

// addSchedulerSlots gives the scheduler the slots it had and one more per
// event loop.
func addSchedulerSlots(had int) {
	runtime.GOMAXPROCS(had + len(ngx.Default().Loops()))
}
