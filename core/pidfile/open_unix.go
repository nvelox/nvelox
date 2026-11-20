//go:build !windows

package pidfile

import (
	"os"
	"syscall"
)

// closeBeforeRename: the written file is held open across the rename, so that
// its inode is not free for another file to take.
const closeBeforeRename = false

// openNoFollow opens path for reading without following a link (a link at
// the path fails to open) and without waiting on a FIFO or a device.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
