package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

// loggerState bundles the three pieces of logger config so they can be
// swapped atomically. Without this, a second Init() call races with
// in-flight log calls reading level/accessLog/errorLog as separate
// globals — which is how test A's still-draining engine goroutine
// races with test B's Init.
type loggerState struct {
	accessLog *log.Logger
	errorLog  *log.Logger
	level     Level
}

// current holds the active logger state. Init swaps a fresh state in
// atomically; all read helpers take a snapshot pointer with Load.
var current atomic.Pointer[loggerState]

func init() {
	// Safe defaults so logging doesn't panic if a helper is called before
	// Init (e.g. unit-test paths that forget to init).
	current.Store(&loggerState{
		accessLog: log.New(os.Stdout, "", 0),
		errorLog:  log.New(os.Stderr, "", log.LstdFlags),
		level:     WarnLevel,
	})
}

// Init initializes the logger with config.
func Init(logLevel string, accessPath, errorPath string) error {
	next := &loggerState{}

	// Parse Level
	switch strings.ToLower(logLevel) {
	case "debug":
		next.level = DebugLevel
	case "info":
		next.level = InfoLevel
	case "warning":
		next.level = WarnLevel
	case "error":
		next.level = ErrorLevel
	default:
		next.level = WarnLevel
	}

	// Setup Error Log
	var errWriter io.Writer = os.Stderr
	if errorPath != "" {
		if err := os.MkdirAll(filepath.Dir(errorPath), 0755); err != nil {
			return fmt.Errorf("failed to create log dir: %w", err)
		}
		f, err := os.OpenFile(errorPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open error log: %w", err)
		}
		errWriter = f
	}
	next.errorLog = log.New(errWriter, "", log.LstdFlags) // Prefix handled in helpers

	// Setup Access Log
	var accessWriter io.Writer = os.Stdout
	if accessPath != "" {
		if err := os.MkdirAll(filepath.Dir(accessPath), 0755); err != nil {
			return fmt.Errorf("failed to create log dir: %w", err)
		}
		f, err := os.OpenFile(accessPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open access log: %w", err)
		}
		accessWriter = f // Access log usually file only or stdout
	}
	next.accessLog = log.New(accessWriter, "", 0) // Raw format

	// Atomic swap: concurrent readers see either the old or the new
	// state in full — never a torn mix.
	current.Store(next)
	return nil
}

func Debug(format string, v ...interface{}) {
	s := current.Load()
	if s.level <= DebugLevel {
		s.errorLog.Output(2, fmt.Sprintf("[DEBUG] "+format, v...))
	}
}

func Info(format string, v ...interface{}) {
	s := current.Load()
	if s.level <= InfoLevel {
		s.errorLog.Output(2, fmt.Sprintf("[INFO] "+format, v...))
	}
}

func Warn(format string, v ...interface{}) {
	s := current.Load()
	if s.level <= WarnLevel {
		s.errorLog.Output(2, fmt.Sprintf("[WARN] "+format, v...))
	}
}

func Error(format string, v ...interface{}) {
	s := current.Load()
	if s.level <= ErrorLevel {
		s.errorLog.Output(2, fmt.Sprintf("[ERR] "+format, v...))
	}
}

func Access(format string, v ...interface{}) {
	current.Load().accessLog.Printf(format, v...)
}

// SanitizeLogField strips CR/LF/tab and other control characters from strings
// that may contain user-controlled input (request path, method, headers, …)
// before they are written to a log line. Without this an attacker can inject
// fake log lines via %0A in the URL path and fool SIEM/monitoring.
func SanitizeLogField(s string) string {
	if s == "" {
		return s
	}
	// Fast path: scan for anything that needs replacing. Avoids allocating
	// a new string for the common case of clean ASCII paths.
	needs := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c == '\t':
			b = append(b, '\\', 't')
		case c < 0x20 || c == 0x7f:
			b = append(b, '?') // other control chars → '?'
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

// AccessHTTP logs an HTTP request in CLF-like format. Every variable field is
// sanitized against CRLF log injection. clientIP comes from the server's
// trusted-proxy-aware resolver (always a validated IP — the real client behind
// a trusted proxy, else the connection peer), so sanitizing it is normally a
// no-op; we do it anyway as defense-in-depth against future callers passing a
// less-validated value. host is the requested vhost (r.Host); an empty host is
// logged as "-".
func AccessHTTP(clientIP, host, method, path, proto string, status int, bytes int64, duration float64, backend string) {
	if host == "" {
		host = "-"
	}
	current.Load().accessLog.Printf("%s - %s \"%s %s %s\" %d %d %.3fms -> %s",
		SanitizeLogField(clientIP),
		SanitizeLogField(host),
		SanitizeLogField(method),
		SanitizeLogField(path),
		SanitizeLogField(proto),
		status, bytes, duration,
		SanitizeLogField(backend))
}

func Fatal(format string, v ...interface{}) {
	current.Load().errorLog.Output(2, fmt.Sprintf("[FATAL] "+format, v...))
	os.Exit(1)
}
