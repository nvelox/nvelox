//go:build unix

package logging

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestHandOver_UsesTheOpenFile: the log file the logger has open is handed
// over, not whatever its path names by then. Here the path has been turned
// into a symbolic link to another file after the open; that file must keep
// its group. (A supplementary group of the test user stands in for the new
// owner, so no root is needed.)
func TestHandOver_UsesTheOpenFile(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Skip(err)
	}
	newGID := -1
	for _, g := range groups {
		if g != os.Getegid() {
			newGID = g
			break
		}
	}
	if newGID < 0 {
		t.Skip("the test user has no supplementary group")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "error.log")
	if err := Init("info", "", path); err != nil {
		t.Fatal(err)
	}
	defer Init("info", "", "")
	rotated, victim := filepath.Join(dir, "error.log.1"), filepath.Join(dir, "victim")
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}

	if err := HandOver(-1, newGID); err != nil {
		t.Fatal(err)
	}
	gid := func(p string) int {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		return int(st.Gid)
	}
	if got := gid(rotated); got != newGID {
		t.Errorf("open log file: gid %d, want %d", got, newGID)
	}
	if got := gid(victim); got == newGID {
		t.Error("the file the log path now points to was handed over")
	}
}

// TestOpenLogFile_RootDoesNotFollowSymlinks: running as root, a log path
// that is a symbolic link is refused (outside /dev and /proc); not as root,
// it is followed as before.
func TestOpenLogFile_RootDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "access.log")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openLogFileAs(link, true); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("as root, a symlinked log path: err %v, want a refusal", err)
	}
	for _, p := range []string{target, filepath.Join(dir, "new.log"), "/dev/null", "/dev/stdout"} {
		if _, err := os.Lstat(p); err != nil && p == "/dev/stdout" {
			continue
		}
		f, _, err := openLogFileAs(p, true)
		if err != nil {
			t.Errorf("as root, %s: %v", p, err)
			continue
		}
		f.Close()
	}
	f, _, err := openLogFileAs(link, false)
	if err != nil {
		t.Fatalf("not as root, a symlinked log path: %v", err)
	}
	f.Close()
}

// TestOpenLogFile_RootRefusesHardLinks: running as root, a log file with
// another hard link (it could be any file of the system's) is refused.
func TestOpenLogFile_RootRefusesHardLinks(t *testing.T) {
	dir := t.TempDir()
	other, log := filepath.Join(dir, "other"), filepath.Join(dir, "error.log")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(other, log); err != nil {
		t.Skip(err)
	}
	if _, _, err := openLogFileAs(log, true); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("as root, a hard-linked log file: err %v, want a refusal", err)
	}
	f, _, err := openLogFileAs(log, false)
	if err != nil {
		t.Fatalf("not as root: %v", err)
	}
	f.Close()
}
