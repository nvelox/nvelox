//go:build !windows

package config

import (
	"os"
	"syscall"
)

// openNoWait opens path for reading without waiting for a writer: a FIFO
// opens at once, so that ReadNamedFile can see what it is and refuse it.
// A terminal does not become the process's controlling one.
func openNoWait(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
}
