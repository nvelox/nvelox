//go:build windows

package pidfile

import "os"

// closeBeforeRename: an open file cannot be renamed on Windows.
const closeBeforeRename = true

// openNoFollow opens path for reading. A link needs a privilege to make on
// Windows; the stop then checks that the file is the one written.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
