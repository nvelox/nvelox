// Package pidfile writes server.pid_file: the process ID of the running
// nvelox, for a supervisor or a companion (the Kubernetes ingress
// controller reads it to know which process to signal).
//
// nvelox writes it as the user it was started as, before it switches to
// server.user, so the file may live in a directory only root writes to.
// That makes the write a privileged one: it goes to a new file that is then
// renamed over the path, so a link someone planted at the path is replaced
// and never written through.
package pidfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Write writes the process ID to path and returns the function that takes
// the file away again at a clean stop. That function removes the file only
// while it still holds this process's ID (a newer instance may have written
// its own), and gives up without a word when the process may no longer
// remove it (it switched to server.user and the directory is root's).
func Write(path string) (remove func(), err error) {
	pid := os.Getpid()
	dir := filepath.Dir(path)
	// O_EXCL: the temporary name must not exist, whether as a file or as a
	// link, so nothing is ever written through a path someone else made.
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.%d.tmp", filepath.Base(path), pid))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		// Left behind by an earlier process that had this ID and died
		// between the write and the rename.
		if rmErr := os.Remove(tmp); rmErr != nil {
			return nil, rmErr
		}
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	}
	if err != nil {
		return nil, err
	}
	_, werr := f.WriteString(strconv.Itoa(pid) + "\n")
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		// The mode the file is created with is cut by the umask; a pid
		// file is for others to read.
		werr = os.Chmod(tmp, 0o644)
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return nil, werr
	}
	return func() {
		b, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(pid) {
			return
		}
		_ = os.Remove(path)
	}, nil
}
