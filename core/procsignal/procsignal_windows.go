//go:build windows

package procsignal

import (
	"os"
	"syscall"
)

// Windows has no SIGUSR1: log files are reopened on SIGHUP only.
var Reopen os.Signal

var Control = []os.Signal{syscall.SIGHUP}
