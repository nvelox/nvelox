package httpproxy

import (
	"compress/gzip"
	"io"
	"net/http"
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
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

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
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// shouldCompress checks if the request accepts gzip encoding.
func shouldCompress(r *http.Request, cfg config.CompressionConfig) bool {
	if !cfg.Enabled {
		return false
	}
	ae := r.Header.Get("Accept-Encoding")
	return strings.Contains(ae, "gzip")
}
