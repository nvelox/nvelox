//go:build linux

package core

import (
	"runtime"
	"testing"

	"github.com/nvelox/ngx"
)

// The scheduler gets the slots it started with and one more per event loop,
// there is one loop per slot it started with, and asking again adds none.
// The test leaves the process with the slots it started with, so it can
// run again in the same process and the other tests are not touched.
func TestSpareSchedulerSlots(t *testing.T) {
	SpareSchedulerSlots() // the first call of the process, or nothing
	had := slotsBefore
	loops := len(ngx.Default().Loops())
	if loops != had {
		t.Fatalf("%d event loops for %d slots at start: one loop per slot is the rule", loops, had)
	}
	t.Cleanup(func() { runtime.GOMAXPROCS(had) })
	runtime.GOMAXPROCS(had) // as a process starts
	addSchedulerSlots(had)
	if got, want := runtime.GOMAXPROCS(0), had+loops; got != want {
		t.Fatalf("the scheduler has %d slots, want %d (the %d it started with and one per loop)", got, want, had)
	}
	SpareSchedulerSlots()
	if got, want := runtime.GOMAXPROCS(0), had+loops; got != want {
		t.Fatalf("asked again, the scheduler has %d slots, want %d", got, want)
	}
}
