//go:build !windows

package main

import (
	"os"
	"syscall"
)

// reopenSignal makes nvelox reopen its log files (logrotate postrotate:
// kill -USR1). SIGHUP reopens them too, then reloads the config.
var reopenSignal os.Signal = syscall.SIGUSR1

// controlSignals are the signals main forwards to run's signal loop.
var controlSignals = []os.Signal{syscall.SIGHUP, syscall.SIGUSR1}
