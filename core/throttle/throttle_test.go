package throttle

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRate(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"10MB/s", 10 * 1024 * 1024},
		{"1KB/s", 1024},
		{"5GB/s", 5 * 1024 * 1024 * 1024},
		{"100/s", 100},
	}

	for _, tt := range tests {
		got := ParseRate(tt.input)
		if got != tt.want {
			t.Errorf("ParseRate(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestThrottledReader(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)
	r := NewReader(bytes.NewReader(data), 10000) // 10KB/s

	buf, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if len(buf) != 1000 {
		t.Errorf("expected 1000 bytes, got %d", len(buf))
	}
}

func TestThrottledWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, 10000) // 10KB/s

	data := bytes.Repeat([]byte("y"), 500)
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}
	if n != 500 {
		t.Errorf("expected 500 written, got %d", n)
	}
	if buf.Len() != 500 {
		t.Errorf("expected 500 in buffer, got %d", buf.Len())
	}
}

// infiniteXReader is a thread-safe source of 'x' bytes. bytes.Reader is
// NOT goroutine-safe; using it as the source for a concurrent-reads test
// trips the race detector on the underlying reader, not on our throttle.
type infiniteXReader struct{}

func (infiniteXReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// TestThrottledReader_ConcurrentNoOverConsumption spins up many concurrent
// readers against one Reader and verifies that total bytes consumed in a
// short window cannot exceed the cap + one burst. Previously, readers
// could each reserve-after-syscall, briefly driving tokens negative and
// over-consuming.
func TestThrottledReader_ConcurrentNoOverConsumption(t *testing.T) {
	const rate = int64(10000) // 10 KB/s cap
	r := NewReader(infiniteXReader{}, rate)

	var wg sync.WaitGroup
	var total atomic.Int64
	start := time.Now()
	deadline := start.Add(100 * time.Millisecond)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 4096)
			for time.Now().Before(deadline) {
				n, err := r.Read(buf)
				if err != nil && err != io.EOF {
					return
				}
				total.Add(int64(n))
			}
		}()
	}
	wg.Wait()

	// Over 100ms at 10KB/s we accrue 1KB. Plus the initial 10KB burst
	// (tokens start full). So upper bound ≈ 11KB. Allow a small
	// scheduler slack (20%) → 13.2KB. Over-consumption past this would
	// indicate the reservation logic regressed.
	consumed := total.Load()
	if consumed > 13200 {
		t.Errorf("consumed %d bytes in 100ms at 10KB/s cap — reservation logic regressed", consumed)
	}
	if consumed < 5000 {
		t.Errorf("consumed only %d bytes — readers starved", consumed)
	}
}

func TestThrottledReader_RefundOnShortRead(t *testing.T) {
	// Source returns at most 10 bytes per Read call to simulate short reads.
	src := &shortReader{data: bytes.Repeat([]byte{'x'}, 10000), max: 10}
	r := NewReader(src, 1000)

	// Reserve 100, get back 10 → refund 90.
	buf := make([]byte, 100)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("read err: %v", err)
	}
	if n != 10 {
		t.Fatalf("expected 10 bytes from shortReader, got %d", n)
	}
	// After this, we should have tokens ≈ 1000 - 10 = 990 (reservation
	// was 100, actual was 10, refund 90). Not exactly testable without
	// exposing internals; the next call should succeed immediately
	// without a sleep stall.
	start := time.Now()
	n2, _ := r.Read(buf)
	if time.Since(start) > 5*time.Millisecond {
		t.Errorf("next Read stalled — refund didn't restore tokens (took %v)", time.Since(start))
	}
	if n2 <= 0 {
		t.Error("next Read returned no bytes after refund")
	}
}

type shortReader struct {
	data []byte
	pos  int
	max  int
}

func (s *shortReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := len(p)
	if n > s.max {
		n = s.max
	}
	if s.pos+n > len(s.data) {
		n = len(s.data) - s.pos
	}
	copy(p, s.data[s.pos:s.pos+n])
	s.pos += n
	return n, nil
}
