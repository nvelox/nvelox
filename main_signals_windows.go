//go:build windows

package main

import (
	"os"
	"syscall"
)

// Windows has no SIGUSR1: log files are reopened on SIGHUP only.
var reopenSignal os.Signal

var controlSignals = []os.Signal{syscall.SIGHUP}
