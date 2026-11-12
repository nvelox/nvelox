package httpproxy

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"nvelox/config"
)

var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		return gzip.NewWriter(io.Discard)
	},
}

// compressWriter wraps http.ResponseWriter to apply gzip compression.
type compressWriter struct {
	http.ResponseWriter
	gw          *gzip.Writer
	cfg         config.CompressionConfig
	wroteHeader bool
	compressed  bool
	types       map[string]bool
}

func newCompressWriter(w http.ResponseWriter, cfg config.CompressionConfig) *compressWriter {
	types := make(map[string]bool)
	for _, t := range cfg.Types {
		types[strings.ToLower(t)] = true
	}
	if len(types) == 0 {
		// Default compressible types
		types["text/html"] = true
		types["text/css"] = true
		types["text/plain"] = true
		types["application/json"] = true
		types["application/javascript"] = true
		types["text/xml"] = true
		types["application/xml"] = true
	}
	return &compressWriter{
		ResponseWriter: w,
		cfg:            cfg,
		types:          types,
	}
}

func (w *compressWriter) WriteHeader(code int) {
	// 1xx informational responses (100 Continue, 103 Early Hints) precede
	// the response: pass them on without deciding anything.
	if code >= 100 && code < 200 {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	// No body to compress.
	if code == http.StatusNoContent || code == http.StatusNotModified {
		w.ResponseWriter.WriteHeader(code)
		return
	}

	// compression.min_length: like nginx's gzip_min_length, decided from the
	// Content-Length header; a response without one is compressed.
	if w.cfg.MinLength > 0 {
		if cl := w.ResponseWriter.Header().Get("Content-Length"); cl != "" {
			if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n < int64(w.cfg.MinLength) {
				w.ResponseWriter.WriteHeader(code)
				return
			}
		}
	}

	// Check if content type is compressible
	ct := w.ResponseWriter.Header().Get("Content-Type")
	if ct == "" {
		ct = "text/html"
	}
	// Extract base type (ignore charset etc)
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}

	// BREACH mitigation: don't compress responses with secrets/tokens
	if w.ResponseWriter.Header().Get("Set-Cookie") != "" {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	// Don't double-compress
	if w.ResponseWriter.Header().Get("Content-Encoding") != "" {
		w.ResponseWriter.WriteHeader(code)
		return
	}

	if w.types[strings.ToLower(ct)] {
		w.compressed = true
		w.ResponseWriter.Header().Set("Content-Encoding", "gzip")
		w.ResponseWriter.Header().Del("Content-Length") // length changes with compression
		// The encoding depends on the request's Accept-Encoding: say so to
		// any cache downstream.
		if !headerHasToken(w.ResponseWriter.Header(), "Vary", "accept-encoding") {
			w.ResponseWriter.Header().Add("Vary", "Accept-Encoding")
		}
		gw := gzipWriterPool.Get().(*gzip.Writer)
		gw.Reset(w.ResponseWriter)
		w.gw = gw
	}

	w.ResponseWriter.WriteHeader(code)
}

func (w *compressWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.compressed && w.gw != nil {
		return w.gw.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *compressWriter) Close() {
	if w.gw != nil {
		w.gw.Close()
		gzipWriterPool.Put(w.gw)
	}
}

// Implement http.Flusher
func (w *compressWriter) Flush() {
	if w.gw != nil {
		w.gw.Flush()
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the writers below.
func (w *compressWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// headerHasToken reports whether a comma-separated header lists token
// (case-insensitively).
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// shouldCompress checks if the request accepts gzip encoding.
func shouldCompress(r *http.Request, cfg config.CompressionConfig) bool {
	if !cfg.Enabled {
		return false
	}
	ae := r.Header.Get("Accept-Encoding")
	return strings.Contains(ae, "gzip")
}
