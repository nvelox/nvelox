// Package pidfile writes server.pid_file: the process ID of the running
// nvelox, for a supervisor or a companion (the Kubernetes ingress
// controller reads it to know which process to signal).
//
// nvelox writes it as the user it was started as, before it switches to
// server.user, so the file may live in a directory only root writes to.
// That makes the write a privileged one: it goes to a new file that is then
// renamed over the path, so a link someone planted at the path is replaced
// and never written through. The directory may also be one that others
// write to (the server.user's own, so that the stop can remove the file):
// then a name can be swapped for a link at any moment, so nothing is done
// to the file by its name once it is created. Its mode is set on the open
// file, and after the rename the file at the path must be the very file
// written.
package pidfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// afterWritten is called with the temporary name once the file is written
// and closed, before the rename: the moment someone who can write to the
// directory could swap that name for a link. A test makes the swap here.
var afterWritten = func(tmp string) {}

// errNotOurs: the file at the path after the rename is not the one written.
var errNotOurs = errors.New("the file at the path is not the one nvelox wrote (it was replaced meanwhile); refused")

// Write writes the process ID to path and returns the function that takes
// the file away again at a clean stop. That function removes the file only
// while it is still the file this process wrote and holds its ID (a newer
// instance may have written its own), and gives up without a word when the
// process may no longer remove it (it switched to server.user and the
// directory is root's).
func Write(path string) (remove func(), err error) {
	pid := os.Getpid()
	dir := filepath.Dir(path)
	// O_EXCL: the temporary name must not exist, whether as a file or as a
	// link, so nothing is ever written through a path someone else made.
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.%d.tmp", filepath.Base(path), pid))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		// Left behind by an earlier process that had this ID and died
		// between the write and the rename (or a link someone planted:
		// removing a link removes the link, not what it points to).
		if rmErr := os.Remove(tmp); rmErr != nil {
			return nil, rmErr
		}
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	}
	if err != nil {
		return nil, err
	}
	content := strconv.Itoa(pid) + "\n"
	// The mode the file is created with is cut by the umask; a pid file is
	// for others to read. It is set on the open file: by its name it could
	// already be a link to another file.
	werr := f.Chmod(0o644)
	if werr == nil {
		_, werr = f.WriteString(content)
	}
	var written os.FileInfo
	if werr == nil {
		written, werr = f.Stat()
	}
	// The file stays open until it is known to be at the path: while it is
	// open its inode cannot be given to a file made in its place, which
	// would then pass for it.
	open := true
	closeFile := func() error {
		if !open {
			return nil
		}
		open = false
		return f.Close()
	}
	defer closeFile()
	if werr == nil && closeBeforeRename {
		werr = closeFile()
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return nil, werr
	}
	afterWritten(tmp)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	// Whatever was at the temporary name has just been renamed to the path:
	// it must be the file written above, a regular file, not a link.
	if now, err := os.Lstat(path); err != nil || !now.Mode().IsRegular() || !os.SameFile(written, now) {
		_ = os.Remove(path) // what was put there in its place (a link is removed, not followed)
		if err != nil {
			return nil, err
		}
		return nil, errNotOurs
	}
	if err := closeFile(); err != nil {
		return nil, err
	}
	return func() {
		if stillOurs(path, written, content) {
			_ = os.Remove(path)
		}
	}, nil
}

// stillOurs reports whether the file at path is the file written (same
// file, not a link) and still holds content. It does not follow a link and
// does not wait on a FIFO or a device; it reads a few bytes at most.
func stillOurs(path string, written os.FileInfo, content string) bool {
	f, err := openNoFollow(path)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || !os.SameFile(written, st) {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(len(content))+1))
	return err == nil && strings.TrimSpace(string(b)) == strings.TrimSpace(content)
}
