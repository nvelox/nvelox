package pidfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestWrite_HoldsThePIDAndIsRemovedAtStop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nvelox.pid")
	remove, err := Write(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := strconv.Itoa(os.Getpid()) + "\n"; string(b) != want {
		t.Fatalf("the pid file holds %q, want %q", b, want)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o644 {
			t.Errorf("mode %v, want 0644: a pid file is for others to read", st.Mode().Perm())
		}
	}
	// Nothing else is left in the directory (the temporary file is gone).
	if names := list(t, dir); len(names) != 1 || names[0] != "nvelox.pid" {
		t.Fatalf("the directory holds %q, want only nvelox.pid", names)
	}
	remove()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("after the stop the pid file is still there (%v)", err)
	}
	remove() // a second call is harmless
}

// A newer instance wrote its own ID to the same path: the stop of this one
// leaves that file alone.
func TestWrite_RemoveLeavesAnotherProcessFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nvelox.pid")
	remove, err := Write(path)
	if err != nil {
		t.Fatal(err)
	}
	other := strconv.Itoa(os.Getpid()+1) + "\n"
	if err := os.WriteFile(path, []byte(other), 0o644); err != nil {
		t.Fatal(err)
	}
	remove()
	b, err := os.ReadFile(path)
	if err != nil || string(b) != other {
		t.Fatalf("the other process's pid file: %q, %v; want it untouched", b, err)
	}
}

// The write is made by root before privileges are dropped. A link planted at
// the path must be replaced, never written through: otherwise whoever can
// write to the directory picks a file for root to overwrite.
func TestWrite_ReplacesALinkAndDoesNotWriteThroughIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	const precious = "do not overwrite\n"
	if err := os.WriteFile(victim, []byte(precious), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nvelox.pid")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	remove, err := Write(path)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if b, _ := os.ReadFile(victim); string(b) != precious {
		t.Fatalf("the file the link pointed to now holds %q: the pid was written through the link", b)
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the path is still a link: it was not replaced by the pid file")
	}
	if b, _ := os.ReadFile(path); string(b) != strconv.Itoa(os.Getpid())+"\n" {
		t.Fatalf("the pid file holds %q", b)
	}
}

// The same for the temporary name the write goes through: a link planted
// there is removed, not followed.
func TestWrite_TemporaryNameIsNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	const precious = "do not overwrite\n"
	if err := os.WriteFile(victim, []byte(precious), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nvelox.pid")
	tmp := filepath.Join(dir, ".nvelox.pid."+strconv.Itoa(os.Getpid())+".tmp")
	if err := os.Symlink(victim, tmp); err != nil {
		t.Fatal(err)
	}
	remove, err := Write(path)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if b, _ := os.ReadFile(victim); string(b) != precious {
		t.Fatalf("the file the temporary link pointed to now holds %q", b)
	}
	if b, _ := os.ReadFile(path); string(b) != strconv.Itoa(os.Getpid())+"\n" {
		t.Fatalf("the pid file holds %q", b)
	}
}

func TestWrite_DirectoryMissing(t *testing.T) {
	_, err := Write(filepath.Join(t.TempDir(), "no-such-dir", "nvelox.pid"))
	if err == nil {
		t.Fatal("a pid file in a directory that does not exist: want an error")
	}
}

func list(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}
