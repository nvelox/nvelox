//go:build !windows

package pidfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// At the stop the process runs as server.user. A link planted at the path,
// to a FIFO (or /dev/zero), must neither hold the stop nor be read; it is
// left as it is.
func TestRemove_DoesNotFollowALinkOrWaitOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nvelox.pid")
	remove, err := Write(path)
	if err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, path); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { remove(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stop waits on the FIFO a planted link points to")
	}
	if st, err := os.Lstat(path); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the planted link was removed or replaced (%v): it is not the file written", err)
	}
}
