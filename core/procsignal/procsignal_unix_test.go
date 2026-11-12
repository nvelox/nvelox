//go:build !windows

package procsignal

import (
	"os"
	"syscall"
	"testing"
)

// TestControlSignals: main subscribes run's signal loop to SIGHUP and
// SIGUSR1, and SIGUSR1 is the reopen-only signal.
func TestControlSignals(t *testing.T) {
	has := map[os.Signal]bool{}
	for _, s := range Control {
		has[s] = true
	}
	if !has[syscall.SIGHUP] || !has[syscall.SIGUSR1] {
		t.Errorf("Control = %v, want SIGHUP and SIGUSR1", Control)
	}
	if Reopen != syscall.SIGUSR1 {
		t.Errorf("Reopen = %v, want SIGUSR1", Reopen)
	}
}
