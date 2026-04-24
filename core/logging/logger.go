package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

var (
	accessLog *log.Logger
	errorLog  *log.Logger
	level     Level
	mu        sync.Mutex
)

// Init initializes the logger with config.
func Init(logLevel string, accessPath, errorPath string) error {
	mu.Lock()
	defer mu.Unlock()

	// Parse Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = DebugLevel
	case "info":
		level = InfoLevel
	case "warning":
		level = WarnLevel
	case "error":
		level = ErrorLevel
	default:
		level = WarnLevel
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
	errorLog = log.New(errWriter, "", log.LstdFlags) // Prefix handled in helpers

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
	accessLog = log.New(accessWriter, "", 0) // Raw format

	return nil
}

func Debug(format string, v ...interface{}) {
	if level <= DebugLevel {
		errorLog.Output(2, fmt.Sprintf("[DEBUG] "+format, v...))
	}
}

func Info(format string, v ...interface{}) {
	if level <= InfoLevel {
		errorLog.Output(2, fmt.Sprintf("[INFO] "+format, v...))
	}
}

func Warn(format string, v ...interface{}) {
	if level <= WarnLevel {
		errorLog.Output(2, fmt.Sprintf("[WARN] "+format, v...))
	}
}

func Error(format string, v ...interface{}) {
	if level <= ErrorLevel {
		errorLog.Output(2, fmt.Sprintf("[ERR] "+format, v...))
	}
}

func Access(format string, v ...interface{}) {
	accessLog.Printf(format, v...)
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

// AccessHTTP logs an HTTP request in CLF-like format. User-controlled
// fields (method, path, proto, backend) are sanitized against CRLF log
// injection; clientIP is produced by net.SplitHostPort and is trusted.
func AccessHTTP(clientIP, method, path, proto string, status int, bytes int64, duration float64, backend string) {
	accessLog.Printf("%s - \"%s %s %s\" %d %d %.3fms -> %s",
		clientIP,
		SanitizeLogField(method),
		SanitizeLogField(path),
		SanitizeLogField(proto),
		status, bytes, duration,
		SanitizeLogField(backend))
}

func Fatal(format string, v ...interface{}) {
	errorLog.Output(2, fmt.Sprintf("[FATAL] "+format, v...))
	os.Exit(1)
}
