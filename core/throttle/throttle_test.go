package throttle

import (
	"bytes"
	"io"
	"testing"
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
