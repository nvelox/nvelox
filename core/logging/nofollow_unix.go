//go:build unix

package logging

import (
	"errors"
	"os"
	"syscall"
)

// noFollow makes OpenFile fail on a symbolic link at the last path element.
const noFollow = syscall.O_NOFOLLOW

// isSymlinkRefusal reports whether err is OpenFile's answer to noFollow
// meeting a symbolic link.
func isSymlinkRefusal(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}

func runningAsRoot() bool { return os.Geteuid() == 0 }

// linkCount is the number of hard links of the file fi describes.
func linkCount(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}
