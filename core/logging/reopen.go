package logging

import (
	"fmt"
	"os"
	"path/filepath"
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
func openLogFile(path string) (f *os.File, warn string, err error) {
	if err := os.MkdirAll(filepath.Dir(path), logDirMode); err != nil {
		return nil, "", fmt.Errorf("failed to create log dir: %w", err)
	}
	f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, logFileMode)
	if err != nil {
		return nil, "", err
	}
	fi, err := f.Stat()
	if err != nil {
		return f, fmt.Sprintf("log file %s: cannot check its permissions: %v", path, err), nil
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
