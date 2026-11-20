//go:build windows

package config

import "os"

// openNoWait opens path for reading (a named pipe is no file name here).
func openNoWait(path string) (*os.File, error) {
	return os.Open(path)
}
