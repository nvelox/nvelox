package httpproxy

import (
	"fmt"
	"net/http"
	"os"
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

// ServeFile tries to serve a static file. Returns true if served, false if not found.
func (h *StaticHandler) ServeFile(w http.ResponseWriter, r *http.Request) bool {
	reqPath := filepath.Clean(r.URL.Path)
	if reqPath == "" {
		reqPath = "/"
	}

	fullPath := filepath.Join(h.root, reqPath)

	// Security: prevent directory traversal (pre-symlink check)
	cleanRoot := filepath.Clean(h.root)
	if !strings.HasPrefix(filepath.Clean(fullPath), cleanRoot) {
		return false
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return false
	}

	// Security: resolve symlinks and re-check path is still within root
	realPath, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return false
	}
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		realRoot = cleanRoot
	}
	if !strings.HasPrefix(realPath, realRoot) {
		return false // symlink points outside document root
	}

	// If directory, try index files
	if info.IsDir() {
		for _, idx := range h.index {
			indexPath := filepath.Join(fullPath, idx)
			// Check index file also resolves within root
			if realIdx, err := filepath.EvalSymlinks(indexPath); err == nil {
				if !strings.HasPrefix(realIdx, realRoot) {
					continue
				}
				if fi, err := os.Stat(realIdx); err == nil && !fi.IsDir() {
					http.ServeFile(w, r, realIdx)
					return true
				}
			}
		}
		return false
	}

	http.ServeFile(w, r, realPath)
	return true
}

// TryFiles implements nginx-style try_files logic.
// Supported variables in file patterns:
//   $uri — the request path
//   $is_args — "?" if query string exists, empty otherwise
//   $args — the raw query string
//   $uri/ — try as directory (append / and look for index)
//
// Returns the resolved path to serve, or empty string if nothing found.
func TryFiles(root string, r *http.Request, files []string, fallback string) string {
	uri := r.URL.Path
	args := r.URL.RawQuery
	isArgs := ""
	if args != "" {
		isArgs = "?"
	}

	for _, pattern := range files {
		resolved := expandTryFileVars(pattern, uri, isArgs, args)

		// Check if it's a file on disk
		fullPath := filepath.Join(root, filepath.Clean(resolved))

		// Security check
		if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(root)) {
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
				return resolved
			}
			continue
		}

		return resolved
	}

	// Fallback
	if fallback != "" {
		return expandTryFileVars(fallback, uri, isArgs, args)
	}
	return ""
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
	if expires == "" || expires == "off" {
		return
	}

	if expires == "-1" {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		return
	}

	if expires == "epoch" {
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:01 GMT")
		w.Header().Set("Cache-Control", "no-cache")
		return
	}

	duration := parseExpiresDuration(expires)
	if duration > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(duration.Seconds())))
		w.Header().Set("Expires", time.Now().Add(duration).UTC().Format(http.TimeFormat))
	}
}

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
