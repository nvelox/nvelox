package httpproxy

import (
	"bufio"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nvelox/config"
)

// StaticHandler serves static files from a document root.
type StaticHandler struct {
	root      string
	index     []string
	autoindex bool
}

// NewStaticHandler creates a static file handler.
func NewStaticHandler(cfg config.StaticConfig) *StaticHandler {
	idx := cfg.Index
	if len(idx) == 0 {
		idx = []string{"index.html"}
	}
	return &StaticHandler{
		root:      cfg.Root,
		index:     idx,
		autoindex: cfg.Autoindex,
	}
}

// staticFile is a request path resolved to a file under a static root.
type staticFile struct {
	path    string // real path on disk, symlinks resolved
	urlPath string // URL path naming the file: the request path, or the directory path plus the index file name
	script  bool   // a script (see isScriptFile): never served as a file
}

// Resolve maps urlPath to a file under the document root: dotfile segments
// are refused, the path must stay inside the root before and after symlink
// resolution (on a separator boundary), and a directory resolves to the first
// existing entry of the index list.
//
// Script files (.php, .phtml, .phar) are returned only when scripts is true —
// the route can hand them to FastCGI — and then with script set; otherwise
// they count as missing, also as directory index candidates, so a static
// handler can never answer with a script's source.
func (h *StaticHandler) Resolve(urlPath string, scripts bool) (staticFile, bool) {
	// Rooted before cleaning, so the result can never climb above the root.
	reqPath := path.Clean("/" + urlPath)

	// Dotfile protection: refuse any path whose last segment or any segment
	// starts with '.'. Prevents serving /.env, /.git/config, /.htaccess, etc.
	// RFC 3986 well-known paths (/.well-known/...) remain accessible via the
	// explicit allowlist in hasDotfileSegment.
	if hasDotfileSegment(reqPath) {
		return staticFile{}, false
	}

	cleanRoot := filepath.Clean(h.root)
	fullPath := filepath.Join(cleanRoot, filepath.FromSlash(reqPath))
	if !withinRoot(cleanRoot, fullPath) {
		return staticFile{}, false
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return staticFile{}, false
	}

	// Security: resolve symlinks and re-check the path is still within root.
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		realRoot = cleanRoot
	}
	realPath, err := filepath.EvalSymlinks(fullPath)
	if err != nil || !withinRoot(realRoot, realPath) {
		return staticFile{}, false // symlink points outside document root
	}

	if !info.IsDir() {
		script := isScriptFile(fullPath) || isScriptFile(realPath)
		if script && !scripts {
			return staticFile{}, false
		}
		return staticFile{path: realPath, urlPath: urlPath, script: script}, true
	}

	// Directory: the first index file that exists inside the root.
	for _, idx := range h.index {
		indexPath := filepath.Join(fullPath, idx)
		realIdx, err := filepath.EvalSymlinks(indexPath)
		if err != nil || !withinRoot(realRoot, realIdx) {
			continue
		}
		fi, err := os.Stat(realIdx)
		if err != nil || fi.IsDir() {
			continue
		}
		script := isScriptFile(indexPath) || isScriptFile(realIdx)
		if script && !scripts {
			continue
		}
		return staticFile{path: realIdx, urlPath: path.Join(reqPath, idx), script: script}, true
	}
	return staticFile{}, false
}

// Serve writes the resolved file. The Content-Type comes from the file
// extension, application/octet-stream when the extension is unknown — never
// from content sniffing, which would serve an uploaded .md / .log /
// extension-less file that contains HTML as text/html.
func (h *StaticHandler) Serve(w http.ResponseWriter, r *http.Request, f staticFile) {
	ctype := mime.TypeByExtension(filepath.Ext(f.path))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	http.ServeFile(w, r, f.path)
}

// ServeFile tries to serve a static file. Returns true if served, false if not
// found. Script files are never served (see Resolve).
func (h *StaticHandler) ServeFile(w http.ResponseWriter, r *http.Request) bool {
	f, ok := h.Resolve(r.URL.Path, false)
	if !ok {
		return false
	}
	h.Serve(w, r, f)
	return true
}

// isScriptFile reports whether name has a server-side script extension
// (.php, .phtml, .phar — the set Debian's Apache hands to PHP), compared
// case-insensitively. Such files run under FastCGI or are refused; they are
// never sent as files.
func isScriptFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".php", ".phtml", ".phar":
		return true
	}
	return false
}

// withinRoot reports whether the clean path p is root itself or lies below
// it, on a path-separator boundary — /var/www/html-old is not inside
// /var/www/html (a plain string-prefix test says it is).
func withinRoot(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// unsafeTargetPath reports whether a URL path that nvelox is about to act on
// internally (a try_files target, a FastCGI script name) has a "." or ".."
// segment, a backslash or a NUL byte.
func unsafeTargetPath(p string) bool {
	if strings.ContainsAny(p, "\\\x00") {
		return true
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// hasDotfileSegment reports whether any path segment starts with '.'
// (other than "." and ".." which filepath.Clean already resolves).
// /.well-known/ is allowed: operators who need ACME challenges / TLS
// provisioning rely on it, and it's the RFC-sanctioned well-known prefix.
func hasDotfileSegment(p string) bool {
	// Normalize backslashes to forward slashes defensively; filepath.Clean
	// on Linux leaves them literal, but a backslash in a path segment is
	// a suspicious signal anyway — treating it as a separator is safer.
	p = strings.ReplaceAll(p, "\\", "/")
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		if seg[0] == '.' && seg != ".well-known" {
			return true
		}
	}
	return false
}

// TryFiles implements nginx-style try_files logic.
// Supported variables in file patterns:
//
//	$uri — the request path
//	$is_args — "?" if query string exists, empty otherwise
//	$args — the raw query string
//	$uri/ — try as directory (append / and look for index)
//
// Each candidate is expanded and cut at its first '?' — only the path part
// names a file — then checked on disk under root. The first one that exists
// is returned as its path, with isFallback false. Otherwise the expanded
// fallback is returned unsplit with isFallback true (a "=code" status, or a
// URI the caller turns into an internal redirect, splitting path and query
// itself), or "" when no fallback is configured.
func TryFiles(root string, r *http.Request, files []string, fallback string) (target string, isFallback bool) {
	uri := r.URL.Path
	args := r.URL.RawQuery
	isArgs := ""
	if args != "" {
		isArgs = "?"
	}

	cleanRoot := filepath.Clean(root)
	for _, pattern := range files {
		resolved, _, _ := strings.Cut(expandTryFileVars(pattern, uri, isArgs, args), "?")

		// Rooted before cleaning, so a candidate can never leave root.
		fullPath := filepath.Join(cleanRoot, filepath.FromSlash(path.Clean("/"+resolved)))
		if !withinRoot(cleanRoot, fullPath) {
			continue
		}

		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}

		if info.IsDir() {
			// Try index files in directory
			indexPath := filepath.Join(fullPath, "index.html")
			if _, err := os.Stat(indexPath); err == nil {
				return resolved, false
			}
			continue
		}

		return resolved, false
	}

	// Fallback
	if fallback != "" {
		return expandTryFileVars(fallback, uri, isArgs, args), true
	}
	return "", false
}

func expandTryFileVars(pattern, uri, isArgs, args string) string {
	result := pattern
	result = strings.ReplaceAll(result, "$uri", uri)
	result = strings.ReplaceAll(result, "$is_args", isArgs)
	result = strings.ReplaceAll(result, "$args", args)
	return result
}

// SetExpires sets Cache-Control and Expires headers based on the expires config value.
// Formats: "1y" (1 year), "30d" (30 days), "1h" (1 hour), "10m" (10 minutes),
// "-1" (no cache), "off" (don't set), "epoch" (expired)
func SetExpires(w http.ResponseWriter, expires string) {
	setExpiresHeader(w.Header(), expires)
}

func setExpiresHeader(h http.Header, expires string) {
	if expires == "" || expires == "off" {
		return
	}

	if expires == "-1" {
		h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		h.Set("Pragma", "no-cache")
		h.Set("Expires", "0")
		return
	}

	if expires == "epoch" {
		h.Set("Expires", "Thu, 01 Jan 1970 00:00:01 GMT")
		h.Set("Cache-Control", "no-cache")
		return
	}

	duration := parseExpiresDuration(expires)
	if duration > 0 {
		h.Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(duration.Seconds())))
		h.Set("Expires", time.Now().Add(duration).UTC().Format(http.TimeFormat))
	}
}

// expiresStatus reports whether a response with this status may carry a
// route's expires policy — nginx's list: 200, 201, 204, 206, 301, 302, 303,
// 304, 307, 308. Errors (a 404, a 502 from a dead upstream) never become
// cacheable.
func expiresStatus(code int) bool {
	switch code {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent, http.StatusPartialContent,
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusNotModified,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// applyExpires sets a route's expires policy on the headers of a response
// with the given status: only for the statuses in expiresStatus, and never
// over a Cache-Control or Expires the upstream set itself — a PHP page's
// "private, no-store" must not turn into "public, max-age=31536000".
func applyExpires(h http.Header, code int, expires string) {
	if expires == "" || !expiresStatus(code) || h.Get("Cache-Control") != "" || h.Get("Expires") != "" {
		return
	}
	setExpiresHeader(h, expires)
}

// expiresWriter applies a route's expires policy (applyExpires) when the
// response status is written — by the static handler, FastCGI, or the
// reverse proxy.
type expiresWriter struct {
	http.ResponseWriter
	expires     string
	wroteHeader bool
}

// newExpiresWriter wraps w so the route's expires policy is applied at
// WriteHeader time; w itself when the route sets no expires.
func newExpiresWriter(w http.ResponseWriter, expires string) http.ResponseWriter {
	if expires == "" {
		return w
	}
	return &expiresWriter{ResponseWriter: w, expires: expires}
}

func (e *expiresWriter) WriteHeader(code int) {
	if !e.wroteHeader && code >= 200 {
		e.wroteHeader = true
		applyExpires(e.Header(), code, e.expires)
	}
	e.ResponseWriter.WriteHeader(code)
}

func (e *expiresWriter) Write(b []byte) (int, error) {
	if !e.wroteHeader {
		e.WriteHeader(http.StatusOK)
	}
	return e.ResponseWriter.Write(b)
}

// Flush writes the header first if needed (with the expires policy), as
// net/http's own Flush would, then flushes the underlying writer.
func (e *expiresWriter) Flush() {
	if !e.wroteHeader {
		e.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(e.ResponseWriter).Flush()
}

// Hijack hands the connection over (WebSocket upgrades).
func (e *expiresWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(e.ResponseWriter).Hijack()
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (e *expiresWriter) Unwrap() http.ResponseWriter { return e.ResponseWriter }

// parseExpiresDuration parses "1y", "30d", etc. into time.Duration.
// time.Duration is nanoseconds int64 — "292y" already overflows. Guard
// against attacker-supplied configs like "9999y" by capping at ~100 years
// which is already well beyond any reasonable cache lifetime and leaves
// plenty of headroom below math.MaxInt64.
func parseExpiresDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return 0
	}

	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	num, err := strconv.Atoi(numStr)
	if err != nil {
		// Try Go duration format
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0
		}
		return d
	}
	if num < 0 {
		return 0
	}

	// 100 years in nanoseconds = ~3.15e18, safely under MaxInt64 (~9.2e18).
	// Anything past this is either a typo or a hostile config — clamp so we
	// never produce a negative Duration via overflow, which would disable
	// Cache-Control entirely in SetExpires.
	const maxYears = 100
	if num > maxYears {
		num = maxYears
	}

	switch unit {
	case 'y':
		return time.Duration(num) * 365 * 24 * time.Hour
	case 'd':
		return time.Duration(num) * 24 * time.Hour
	case 'h':
		return time.Duration(num) * time.Hour
	case 'm':
		return time.Duration(num) * time.Minute
	case 's':
		return time.Duration(num) * time.Second
	default:
		return 0
	}
}
