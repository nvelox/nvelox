package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// maxUALogLen bounds the User-Agent written to the access log. The UA is
// attacker-controlled and effectively only capped by the server's max header size
// (~1MB), so without a clip a single request could emit a multi-KB log line. Because
// the UA is the LAST field, an oversized line that a downstream shipper truncates
// would lose its closing quote and corrupt the record — an attacker could pad their UA
// to push their own request past the shipper's per-line limit and evade log-based
// detection entirely. 512 bytes is ample for any legitimate UA.
const maxUALogLen = 512

// clipUA bounds s to at most maxUALogLen bytes without splitting a UTF-8 rune.
func clipUA(s string) string {
	if len(s) <= maxUALogLen {
		return s
	}
	cut := maxUALogLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// maxFetchMetaLen bounds a logged Fetch Metadata header value. Browsers send short
// lowercase tokens ("cross-site", "same-origin", "image", "document", ...); any
// other value is client-chosen.
const maxFetchMetaLen = 32

// fetchMetaToken renders a Sec-Fetch-* request header value as a single access-log
// token: "-" when the header is absent or empty, otherwise the value clipped to
// maxFetchMetaLen bytes with every byte outside [A-Za-z0-9._-] replaced by '_', so
// a client-chosen value can neither split the token nor forge another key=value
// token. A present value that would read as "-" is logged as "_".
func fetchMetaToken(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	if len(v) > maxFetchMetaLen {
		v = v[:maxFetchMetaLen]
	}
	b := []byte(v)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			b[i] = '_'
		}
	}
	if len(b) == 1 && b[0] == '-' {
		return "_"
	}
	return string(b)
}

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
	// accessFile / errorFile are the files behind accessLog / errorLog (nil
	// when that log goes to stdout / stderr). Reopen swaps the open file
	// inside them (log rotation).
	accessFile *logFile
	errorFile  *logFile
	// accessW is what accessLog writes to: accessFile, or stdout behind a
	// mutex. AccessHTTP and WriteAccess write whole lines to it directly.
	accessW io.Writer
}

// lockedWriter serializes writes to a shared stream (stdout), so that lines
// written through it are never interleaved.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// stdoutAccess is the access log's destination when it has no file.
var stdoutAccess = &lockedWriter{w: os.Stdout}

// current holds the active logger state. Init swaps a fresh state in
// atomically; all read helpers take a snapshot pointer with Load.
var current atomic.Pointer[loggerState]

func init() {
	// Safe defaults so logging doesn't panic if a helper is called before
	// Init (e.g. unit-test paths that forget to init).
	current.Store(&loggerState{
		accessLog: log.New(stdoutAccess, "", 0),
		accessW:   stdoutAccess,
		errorLog:  log.New(os.Stderr, "", log.LstdFlags),
		level:     WarnLevel,
	})
	empty := ""
	gatewayID.Store(&empty)
}

// gatewayID is this process's gateway identity, stamped on every HTTP access-log
// line as gw=<id>. Set once at startup via SetGateway. Stored as an atomic
// pointer so it stays race-free alongside the hot-swappable logger state.
var gatewayID atomic.Pointer[string]

// SetGateway records the gateway identity for the access log. An empty id falls
// back to os.Hostname() so operators get a sensible value with zero config.
func SetGateway(id string) {
	if id == "" {
		if h, err := os.Hostname(); err == nil {
			id = h
		}
	}
	gatewayID.Store(&id)
}

func gateway() string {
	if p := gatewayID.Load(); p != nil {
		return *p
	}
	return ""
}

// Init initializes the logger with config. Log files are opened for
// appending with mode 0640 (directories 0750); an existing file is tightened
// to at most 0640. Reopen re-opens them after log rotation.
func Init(logLevel string, accessPath, errorPath string) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	next := &loggerState{}
	var warnings []string

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
		f, warn, err := openLogFile(errorPath)
		if err != nil {
			return fmt.Errorf("failed to open error log: %w", err)
		}
		if warn != "" {
			warnings = append(warnings, warn)
		}
		next.errorFile = &logFile{path: errorPath, f: f}
		errWriter = next.errorFile
	}
	next.errorLog = log.New(errWriter, "", log.LstdFlags) // Prefix handled in helpers

	// Setup Access Log
	var accessWriter io.Writer = stdoutAccess
	if accessPath != "" {
		f, warn, err := openLogFile(accessPath)
		if err != nil {
			if next.errorFile != nil {
				next.errorFile.f.Close()
			}
			return fmt.Errorf("failed to open access log: %w", err)
		}
		if warn != "" {
			warnings = append(warnings, warn)
		}
		next.accessFile = &logFile{path: accessPath, f: f}
		accessWriter = next.accessFile // Access log usually file only or stdout
	}
	next.accessLog = log.New(accessWriter, "", 0) // Raw format
	next.accessW = accessWriter

	// Atomic swap: concurrent readers see either the old or the new
	// state in full — never a torn mix.
	current.Store(next)
	for _, w := range warnings {
		Warn("%s", w)
	}
	return nil
}

// Enabled reports whether messages of level l are logged now.
func Enabled(l Level) bool { return current.Load().level <= l }

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

// escapeQuoted escapes the two bytes that could end or bend a quoted
// access-log field: '"' becomes \x22 and '\' becomes \x5C (nginx's
// escaping), so a value can never close its quotes and forge the fields that
// follow. Control characters are left to SanitizeLogField, which runs after
// this and so cannot be confused with an escaped backslash.
func escapeQuoted(s string) string {
	if !strings.ContainsAny(s, "\"\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			b.WriteString(`\x22`)
		case '\\':
			b.WriteString(`\x5C`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// AccessHTTP logs an HTTP request in CLF-like format. Every variable field is
// sanitized against CRLF log injection. clientIP comes from the server's
// trusted-proxy-aware resolver (always a validated IP — the real client behind
// a trusted proxy, else the connection peer), so sanitizing it is normally a
// no-op; we do it anyway as defense-in-depth against future callers passing a
// less-validated value. host is the requested vhost (r.Host); an empty host is
// logged as "-". path is the request path as the server's callers pass it
// (the escaped canonical path, so a decoded '"' or space never reaches the
// line); like the User-Agent it additionally has '"' and '\' escaped (see
// escapeQuoted). An empty backend (the request was answered without an
// upstream: a deny, a redirect, a cache hit, ...) is logged as "-".
// fetchSite / fetchDest are the request's Sec-Fetch-Site / Sec-Fetch-Dest
// headers ("" when absent) and tls whether it arrived over TLS (HTTPS,
// including HTTP/3).
func AccessHTTP(clientIP, host, method, path, proto string, status int, bytes int64, duration float64, backend, userAgent, fetchSite, fetchDest string, tls bool, requestID, site string) {
	bp := lineBufs.Get().(*[]byte)
	b := AppendAccessHTTP((*bp)[:0], clientIP, host, method, path, proto, status, bytes, duration, backend, userAgent,
		fetchSite, fetchDest, tls, requestID, site)
	WriteAccess(b)
	*bp = b
	lineBufs.Put(bp)
}

var lineBufs = sync.Pool{New: func() any { b := make([]byte, 0, 512); return &b }}

// WriteAccess writes complete access-log lines (each ending in a newline)
// to the access log in one write.
func WriteAccess(p []byte) {
	if len(p) == 0 {
		return
	}
	_, _ = current.Load().accessW.Write(p)
}

// AppendAccessHTTP appends the line AccessHTTP logs, newline included, to b.
// The format: CLF-like, then the backend, the User-Agent and trailing
// key=value tokens.
//
// User-Agent is appended as a quoted field; the browser Fetch Metadata
// (fetch_site, fetch_dest — "-" when absent), the scheme, the correlation id
// (rid), the gateway identity (gw) and the site/listener name follow as
// trailing key=value tokens. All are appended LAST so a consumer can treat
// them as optional and stay back-compatible with the old format; rid, gw and
// site stay the final three, so a consumer anchored on that tail keeps
// matching. CRLF-sanitized like the rest; the UA, the Fetch Metadata and an
// inbound-derived rid are attacker-influenced.
func AppendAccessHTTP(b []byte, clientIP, host, method, path, proto string, status int, bytes int64, duration float64, backend, userAgent, fetchSite, fetchDest string, tls bool, requestID, site string) []byte {
	b = AppendAccessHTTPHead(b, clientIP, host, method, path, proto)
	b = AppendAccessHTTPMid(b, status, bytes, duration, backend)
	return AppendAccessHTTPTail(b, userAgent, fetchSite, fetchDest, tls, requestID, site)
}

// AppendAccessHTTPHead appends the part of the AccessHTTP line known when a
// request arrives, up to the status: `client - host "METHOD path proto" `.
func AppendAccessHTTPHead(b []byte, clientIP, host, method, path, proto string) []byte {
	if host == "" {
		host = "-"
	}
	b = appendSanitized(b, clientIP)
	b = append(b, " - "...)
	b = appendSanitized(b, host)
	b = append(b, ' ', '"')
	b = appendSanitized(b, method)
	b = append(b, ' ')
	b = appendQuotedField(b, path)
	b = append(b, ' ')
	b = appendSanitized(b, proto)
	return append(b, '"', ' ')
}

// AppendAccessHTTPMid appends the outcome part of the AccessHTTP line:
// `status bytes durationms -> backend`.
func AppendAccessHTTPMid(b []byte, status int, bytes int64, duration float64, backend string) []byte {
	if backend == "" {
		backend = "-"
	}
	b = strconv.AppendInt(b, int64(status), 10)
	b = append(b, ' ')
	b = strconv.AppendInt(b, bytes, 10)
	b = append(b, ' ')
	b = strconv.AppendFloat(b, duration, 'f', 3, 64)
	b = append(b, "ms -> "...)
	return appendSanitized(b, backend)
}

// AppendAccessHTTPTail appends the rest of the AccessHTTP line: the
// User-Agent and the key=value tokens, then the newline.
func AppendAccessHTTPTail(b []byte, userAgent, fetchSite, fetchDest string, tls bool, requestID, site string) []byte {
	if requestID == "" {
		requestID = "-"
	}
	if site == "" {
		site = "-"
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	b = append(b, ' ', '"')
	b = appendQuotedField(b, clipUA(userAgent))
	b = append(b, "\" fetch_site="...)
	b = appendFetchMetaToken(b, fetchSite)
	b = append(b, " fetch_dest="...)
	b = appendFetchMetaToken(b, fetchDest)
	b = append(b, " scheme="...)
	b = append(b, scheme...)
	b = append(b, " rid="...)
	b = appendSanitized(b, requestID)
	b = append(b, " gw="...)
	b = appendSanitized(b, gateway())
	b = append(b, " site="...)
	b = appendSanitized(b, site)
	return append(b, '\n')
}

// appendSanitized appends SanitizeLogField(s).
func appendSanitized(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 0x20 && c != 0x7f:
			b = append(b, c)
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c == '\t':
			b = append(b, '\\', 't')
		default:
			b = append(b, '?')
		}
	}
	return b
}

// appendQuotedField appends SanitizeLogField(escapeQuoted(s)).
func appendQuotedField(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			b = append(b, `\x22`...)
		case '\\':
			b = append(b, `\x5C`...)
		default:
			b = appendSanitized(b, s[i:i+1])
		}
	}
	return b
}

// appendFetchMetaToken appends fetchMetaToken(v).
func appendFetchMetaToken(b []byte, v string) []byte {
	v = strings.TrimSpace(v)
	if v == "" {
		return append(b, '-')
	}
	if len(v) > maxFetchMetaLen {
		v = v[:maxFetchMetaLen]
	}
	if v == "-" {
		return append(b, '_')
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	return b
}

// AccessL4 logs one raw TCP/UDP connection (or rejection) to the SAME access log
// as AccessHTTP, so the existing shipper/queue/consumer pick it up unchanged. The
// ` - l4 ` marker distinguishes it from an HTTP record:
//
//	<clientIP> - l4 <proto>/<dstPort> <status> <bytesIn> <bytesOut> <durMs>ms
//	  e.g. 203.0.113.5 - l4 tcp/7000 no_route 0 0 0.400ms
//
// clientIP MUST be the real client (the PROXY-protocol-decoded source behind
// a relay, not the relay). proto is "tcp"|"udp"; status is a short token
// (ok|no_route|refused|ratelimited|timeout|error). Fields are CRLF-sanitized.
func AccessL4(clientIP, proto string, dstPort int, status string, bytesIn, bytesOut int64, durationMs float64) {
	current.Load().accessLog.Printf("%s - l4 %s/%d %s %d %d %.3fms",
		SanitizeLogField(clientIP),
		SanitizeLogField(proto),
		dstPort,
		SanitizeLogField(status),
		bytesIn, bytesOut, durationMs)
}

func Fatal(format string, v ...interface{}) {
	current.Load().errorLog.Output(2, fmt.Sprintf("[FATAL] "+format, v...))
	os.Exit(1)
}
