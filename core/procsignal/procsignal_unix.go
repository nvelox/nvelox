//go:build !windows

package procsignal

import (
	"os"
	"syscall"
)

// Reopen makes nvelox reopen its log files (logrotate postrotate:
// kill -USR1). SIGHUP reopens them too, then reloads the config.
var Reopen os.Signal = syscall.SIGUSR1

// Control are the signals main forwards to run's signal loop.
var Control = []os.Signal{syscall.SIGHUP, syscall.SIGUSR1}
