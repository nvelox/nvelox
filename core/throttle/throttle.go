package throttle

import (
	"io"
	"sync"
	"time"
)

// Reader wraps an io.Reader with bandwidth throttling.
type Reader struct {
	r         io.Reader
	bytesPerSec int64
	mu        sync.Mutex
	tokens    float64
	lastTime  time.Time
}

// NewReader creates a throttled reader with the given bytes/sec limit.
func NewReader(r io.Reader, bytesPerSec int64) *Reader {
	return &Reader{
		r:           r,
		bytesPerSec: bytesPerSec,
		tokens:      float64(bytesPerSec), // start with 1 second of burst
		lastTime:    time.Now(),
	}
}

func (t *Reader) Read(p []byte) (int, error) {
	t.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(t.lastTime).Seconds()
	t.lastTime = now
	t.tokens += elapsed * float64(t.bytesPerSec)
	if t.tokens > float64(t.bytesPerSec) {
		t.tokens = float64(t.bytesPerSec)
	}

	// Limit read size to available tokens
	maxRead := int(t.tokens)
	if maxRead <= 0 {
		t.mu.Unlock()
		time.Sleep(time.Millisecond) // yield before retry
		return 0, nil
	}
	if maxRead > len(p) {
		maxRead = len(p)
	}
	t.mu.Unlock()

	n, err := t.r.Read(p[:maxRead])

	t.mu.Lock()
	t.tokens -= float64(n)
	t.mu.Unlock()

	return n, err
}

// Writer wraps an io.Writer with bandwidth throttling.
type Writer struct {
	w           io.Writer
	bytesPerSec int64
	mu          sync.Mutex
	tokens      float64
	lastTime    time.Time
}

// NewWriter creates a throttled writer with the given bytes/sec limit.
func NewWriter(w io.Writer, bytesPerSec int64) *Writer {
	return &Writer{
		w:           w,
		bytesPerSec: bytesPerSec,
		tokens:      float64(bytesPerSec),
		lastTime:    time.Now(),
	}
}

func (t *Writer) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		t.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(t.lastTime).Seconds()
		t.lastTime = now
		t.tokens += elapsed * float64(t.bytesPerSec)
		if t.tokens > float64(t.bytesPerSec) {
			t.tokens = float64(t.bytesPerSec)
		}

		chunk := int(t.tokens)
		if chunk <= 0 {
			t.mu.Unlock()
			time.Sleep(time.Millisecond)
			continue
		}
		remaining := len(p) - written
		if chunk > remaining {
			chunk = remaining
		}
		t.tokens -= float64(chunk)
		t.mu.Unlock()

		n, err := t.w.Write(p[written : written+chunk])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// ParseRate parses a rate string like "10MB/s" into bytes per second.
func ParseRate(s string) int64 {
	if s == "" {
		return 0
	}
	// Remove "/s" suffix
	s = s[:len(s)-2] // assumes format like "10MB/s"
	if len(s) == 0 {
		return 0
	}

	multiplier := int64(1)
	if len(s) >= 2 {
		suffix := s[len(s)-2:]
		switch suffix {
		case "KB", "kb":
			multiplier = 1024
			s = s[:len(s)-2]
		case "MB", "mb":
			multiplier = 1024 * 1024
			s = s[:len(s)-2]
		case "GB", "gb":
			multiplier = 1024 * 1024 * 1024
			s = s[:len(s)-2]
		}
	}

	n := int64(0)
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int64(c-'0')
		}
	}
	return n * multiplier
}
