package logging

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestInit_LogFilePermissions (L2): new log files are created 0640 in 0750
// directories (they were 0644 / 0755, readable by every local user), and an
// existing file is tightened to at most 0640 — never loosened.
func TestInit_LogFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs", "nvelox")
	access := filepath.Join(dir, "access.log")
	errLog := filepath.Join(dir, "error.log")
	if err := Init("info", access, errLog); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{access, errLog} {
		if m := perm(t, p); m&^0o640 != 0 {
			t.Errorf("new %s: mode %04o, want at most 0640", filepath.Base(p), m)
		}
	}
	for _, d := range []string{dir, filepath.Dir(dir)} {
		if m := perm(t, d); m&^0o750 != 0 {
			t.Errorf("new dir %s: mode %04o, want at most 0750", d, m)
		}
	}

	// Existing files: 0644 and 0666 are tightened to 0640, 0600 is kept.
	for _, c := range []struct{ before, after os.FileMode }{{0o644, 0o640}, {0o666, 0o640}, {0o604, 0o600}, {0o600, 0o600}} {
		p := filepath.Join(t.TempDir(), "access.log")
		if err := os.WriteFile(p, []byte("old line\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, c.before); err != nil {
			t.Fatal(err)
		}
		if err := Init("info", p, ""); err != nil {
			t.Fatal(err)
		}
		if m := perm(t, p); m != c.after {
			t.Errorf("existing file %04o: mode after Init %04o, want %04o", c.before, m, c.after)
		}
		Access("new line")
		if got := readFile(t, p); got != "old line\nnew line\n" {
			t.Errorf("existing file %04o: content %q, want the old line kept and the new one appended", c.before, got)
		}
	}
}

// TestOpenLogFile_LeavesNonRegularFilesAlone: a device path such as
// /dev/null (or /dev/stdout) is opened but never chmod-ed.
func TestOpenLogFile_LeavesNonRegularFilesAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root a broken guard would really chmod /dev/null")
	}
	before := perm(t, "/dev/null")
	f, warn, err := openLogFile("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if warn != "" {
		t.Errorf("openLogFile(/dev/null) tried to change its mode: %s", warn)
	}
	if after := perm(t, "/dev/null"); after != before {
		t.Errorf("/dev/null mode changed %04o -> %04o", before, after)
	}
}

// TestReopen_AfterRename (L3): after logrotate renames the logs away,
// Reopen makes nvelox write to fresh files at the configured paths (0640);
// before it, lines keep going to the renamed files.
func TestReopen_AfterRename(t *testing.T) {
	dir := t.TempDir()
	access := filepath.Join(dir, "access.log")
	errLog := filepath.Join(dir, "error.log")
	if err := Init("info", access, errLog); err != nil {
		t.Fatal(err)
	}
	Access("access before rotate")
	Info("error before rotate")

	for _, p := range []string{access, errLog} {
		if err := os.Rename(p, p+".1"); err != nil {
			t.Fatal(err)
		}
	}
	Access("access between rotate and reopen")

	if err := Reopen(); err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	Access("access after reopen")
	Info("error after reopen")

	rotatedAccess := readFile(t, access+".1")
	if !strings.Contains(rotatedAccess, "access before rotate") || !strings.Contains(rotatedAccess, "access between rotate and reopen") {
		t.Errorf("rotated access log lost lines: %q", rotatedAccess)
	}
	if strings.Contains(rotatedAccess, "after reopen") {
		t.Errorf("rotated access log still written after Reopen: %q", rotatedAccess)
	}
	if got := readFile(t, access); got != "access after reopen\n" {
		t.Errorf("new access log = %q, want only the post-reopen line", got)
	}
	newErr := readFile(t, errLog)
	if !strings.Contains(newErr, "[INFO] error after reopen") || strings.Contains(newErr, "before rotate") {
		t.Errorf("new error log = %q", newErr)
	}
	if strings.Contains(readFile(t, errLog+".1"), "after reopen") {
		t.Error("rotated error log still written after Reopen")
	}
	for _, p := range []string{access, errLog} {
		if m := perm(t, p); m&^0o640 != 0 {
			t.Errorf("reopened %s: mode %04o, want at most 0640", filepath.Base(p), m)
		}
	}
}

// TestReopen_FailureKeepsCurrentFiles: if either path cannot be opened,
// Reopen returns the error and BOTH loggers keep writing to their current
// files (no half-rotated state, no lost lines).
func TestReopen_FailureKeepsCurrentFiles(t *testing.T) {
	dir := t.TempDir()
	access := filepath.Join(dir, "access.log")
	errLog := filepath.Join(dir, "error.log")
	if err := Init("info", access, errLog); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{access, errLog} {
		if err := os.Rename(p, p+".1"); err != nil {
			t.Fatal(err)
		}
	}
	// The access log path is now a directory: it cannot be opened.
	if err := os.Mkdir(access, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := Reopen(); err == nil {
		t.Fatal("Reopen succeeded although the access log path is a directory")
	}
	Access("access after failed reopen")
	Info("error after failed reopen")
	if !strings.Contains(readFile(t, access+".1"), "access after failed reopen") {
		t.Error("access line lost after a failed Reopen")
	}
	if !strings.Contains(readFile(t, errLog+".1"), "error after failed reopen") {
		t.Error("error log was swapped although Reopen failed")
	}
}

// TestReopen_ConcurrentWritesLoseNothing: lines logged from many goroutines
// while the files are rotated and reopened repeatedly all land, once, in
// one of the files.
func TestReopen_ConcurrentWritesLoseNothing(t *testing.T) {
	dir := t.TempDir()
	access := filepath.Join(dir, "access.log")
	if err := Init("info", access, ""); err != nil {
		t.Fatal(err)
	}
	const writers, lines = 8, 4000

	var wg sync.WaitGroup
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < lines; i++ {
				Access("g%d-%d", g, i)
			}
		}(g)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	// Rotate as fast as possible for as long as the writers run.
rotate:
	for r := 1; ; r++ {
		select {
		case <-done:
			break rotate
		default:
		}
		if err := os.Rename(access, fmt.Sprintf("%s.%d", access, r)); err != nil {
			t.Fatal(err)
		}
		if err := Reopen(); err != nil {
			t.Fatalf("Reopen %d: %v", r, err)
		}
	}

	seen := make(map[string]bool, writers*lines)
	files, _ := filepath.Glob(access + "*")
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if seen[sc.Text()] {
				t.Errorf("line %q written twice", sc.Text())
			}
			seen[sc.Text()] = true
		}
		f.Close()
	}
	if len(seen) != writers*lines {
		t.Errorf("found %d distinct lines across %d files, want %d", len(seen), len(files), writers*lines)
	}
}

// TestReopen_StdStreamsNoop: with no log files configured there is nothing
// to reopen.
func TestReopen_StdStreamsNoop(t *testing.T) {
	if err := Init("info", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := Reopen(); err != nil {
		t.Errorf("Reopen with stdout/stderr logging: %v", err)
	}
}
