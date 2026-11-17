package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Log files hold client IPs, request paths, User-Agents and backend
// addresses, so they are not world-readable: the owner writes, the owner's
// group may read (e.g. a log shipper), others get nothing.
const (
	logFileMode os.FileMode = 0o640
	logDirMode  os.FileMode = 0o750
)

// fileMu serializes Init and Reopen, the two places that open log files.
var fileMu sync.Mutex

// logFile is a log destination whose open file Reopen can replace while the
// loggers keep writing to it. Writes and the swap hold mu, so no line is
// written to a file that is being closed and none is lost.
type logFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// Write holds mu for the whole write: releasing it before f.Write would let
// Reopen close f under an in-flight write and drop that line.
func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Write(p)
}

// swap installs f and returns the file it replaces.
func (l *logFile) swap(f *os.File) *os.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	old := l.f
	l.f = f
	return old
}

// openLogFile opens path for appending, creating it with mode 0640 (and any
// missing parent directory with 0750). An existing regular file keeps its
// owner but loses every permission bit beyond 0640; it is never loosened.
// Failing to tighten it is not fatal (nvelox may not own a file it can write
// to): that comes back as warn for the caller to log.
//
// Running as root, it does not follow a symbolic link at path (outside /dev
// and /proc, whose links only the system makes, e.g. /dev/stdout), and it
// refuses a file with more than one hard link. The log directory is usually
// writable by the user nvelox switches to (server.user), who could otherwise
// point a log at any file for root to create or append to — and later have
// it handed over (HandOver).
func openLogFile(path string) (f *os.File, warn string, err error) {
	return openLogFileAs(path, runningAsRoot())
}

func openLogFileAs(path string, root bool) (f *os.File, warn string, err error) {
	if err := os.MkdirAll(filepath.Dir(path), logDirMode); err != nil {
		return nil, "", fmt.Errorf("failed to create log dir: %w", err)
	}
	flags := os.O_APPEND | os.O_CREATE | os.O_WRONLY
	if root && !systemPath(path) {
		flags |= noFollow
	}
	f, err = os.OpenFile(path, flags, logFileMode)
	if err != nil {
		if isSymlinkRefusal(err) {
			return nil, "", fmt.Errorf("%s is a symbolic link: running as root, nvelox does not follow one for a log file; set the path of the file itself", path)
		}
		return nil, "", err
	}
	fi, err := f.Stat()
	if err != nil {
		if root {
			f.Close()
			return nil, "", fmt.Errorf("log file %s: %w", path, err)
		}
		return f, fmt.Sprintf("log file %s: cannot check its permissions: %v", path, err), nil
	}
	if n := linkCount(fi); root && fi.Mode().IsRegular() && n > 1 {
		f.Close()
		return nil, "", fmt.Errorf("%s has %d hard links: running as root, nvelox writes a log only to a file with one", path, n)
	}
	// Only regular files: a path like /dev/stdout or a pipe must not be
	// chmod-ed.
	if m := fi.Mode(); m.IsRegular() && m.Perm()&^logFileMode != 0 {
		if err := f.Chmod(m.Perm() & logFileMode); err != nil {
			return f, fmt.Sprintf("log file %s: mode %04o is wider than %04o and could not be tightened: %v", path, m.Perm(), logFileMode, err), nil
		}
	}
	return f, "", nil
}

// systemPath reports whether path is under /dev or /proc.
func systemPath(path string) bool {
	clean := filepath.Clean(path)
	return strings.HasPrefix(clean, "/dev/") || strings.HasPrefix(clean, "/proc/")
}

// HandOver gives the open log files to uid and gid (-1 leaves one unchanged)
// through their open descriptors, never by path: privdrop calls it while
// still root, and a path in a directory the new user can write to could by
// then name another file. Only regular files: not a terminal or a pipe.
func HandOver(uid, gid int) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	s := current.Load()
	for _, lf := range []*logFile{s.errorFile, s.accessFile} {
		if lf == nil {
			continue
		}
		lf.mu.Lock()
		fi, err := lf.f.Stat()
		if err == nil && fi.Mode().IsRegular() {
			err = lf.f.Chown(uid, gid)
		}
		lf.mu.Unlock()
		if err != nil {
			return fmt.Errorf("handing %s to the new user: %w", lf.path, err)
		}
	}
	return nil
}

// Reopen re-opens the access and error log files at their configured paths,
// swaps the new files in under the running loggers and closes the old ones.
// Send SIGUSR1 (or SIGHUP) after logrotate has moved the files away;
// otherwise nvelox keeps appending to the rotated file. Both files are opened
// before anything is swapped, so on error the loggers keep their current
// files. A log that goes to stdout/stderr is left alone.
func Reopen() error {
	fileMu.Lock()
	defer fileMu.Unlock()

	s := current.Load()
	targets := []*logFile{s.errorFile, s.accessFile}
	opened := make([]*os.File, len(targets))
	var warnings []string
	for i, lf := range targets {
		if lf == nil {
			continue
		}
		f, warn, err := openLogFile(lf.path)
		if err != nil {
			for _, o := range opened {
				if o != nil {
					o.Close()
				}
			}
			return fmt.Errorf("reopen %s: %w", lf.path, err)
		}
		if warn != "" {
			warnings = append(warnings, warn)
		}
		opened[i] = f
	}
	for i, lf := range targets {
		if lf != nil {
			lf.swap(opened[i]).Close()
		}
	}
	for _, w := range warnings {
		Warn("%s", w)
	}
	return nil
}
