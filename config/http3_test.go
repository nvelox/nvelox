package config

import (
	"runtime"
	"strings"
	"testing"
)

// server.http3: the limits of HTTP/3 connections. Not set, each has its
// default; set, each is a size in its range.
func TestHTTP3_Defaults(t *testing.T) {
	cfg, err := loadWithServer(t, "")
	if err != nil {
		t.Fatal(err)
	}
	want := HTTP3Limits{MaxHeaderSize: 64 << 10, MaxSendBuffer: 16 << 20, MaxStreamReceiveWindow: 6 << 20, MaxConnectionReceiveWindow: 15 << 20,
		SocketBuffer: 4 << 20}
	if got := cfg.Server.HTTP3.Resolve(); got != want {
		t.Errorf("nothing set: %+v, want %+v (the two totals 0: a share of the memory)", got, want)
	}
	// An empty block is the same.
	if cfg, err = loadWithServer(t, "server:\n  http3: {}\n"); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Server.HTTP3.Resolve(); got != want {
		t.Errorf("an empty block: %+v, want %+v", got, want)
	}
}

// Every key is read into its own limit.
func TestHTTP3_EveryKey(t *testing.T) {
	cfg, err := loadWithServer(t, `server:
  http3:
    max_header_size: "32KB"
    max_send_buffer: "8MB"
    max_stream_receive_window: "2MB"
    max_connection_receive_window: "4MB"
    max_send_memory: "512MB"
    max_receive_memory: "3GB"
    socket_buffer: "1MB"
`)
	if err != nil {
		t.Fatal(err)
	}
	want := HTTP3Limits{MaxHeaderSize: 32 << 10, MaxSendBuffer: 8 << 20, MaxStreamReceiveWindow: 2 << 20,
		MaxConnectionReceiveWindow: 4 << 20, MaxSendMemory: 512 << 20, MaxReceiveMemory: 3 << 30, SocketBuffer: 1 << 20}
	if got := cfg.Server.HTTP3.Resolve(); got != want {
		t.Errorf("resolved to %+v, want %+v", got, want)
	}
	// One key set leaves the others at their defaults.
	if cfg, err = loadWithServer(t, "server:\n  http3:\n    max_send_buffer: \"4MB\"\n"); err != nil {
		t.Fatal(err)
	}
	want = HTTP3Limits{MaxHeaderSize: 64 << 10, MaxSendBuffer: 4 << 20, MaxStreamReceiveWindow: 6 << 20, MaxConnectionReceiveWindow: 15 << 20,
		SocketBuffer: 4 << 20}
	if got := cfg.Server.HTTP3.Resolve(); got != want {
		t.Errorf("one key set: %+v, want %+v", got, want)
	}
}

// The range of each key: its two ends are taken, a byte past either is
// refused with an error that names the key and the range.
func TestHTTP3_Ranges(t *testing.T) {
	for _, tc := range []struct {
		key      string
		min, max int64
		named    string
	}{
		{"max_header_size", 1 << 10, 1 << 20, "1KB to 1MB"},
		{"max_send_buffer", 256 << 10, 1 << 30, "256KB to 1GB"},
		{"max_stream_receive_window", 1 << 20, 1 << 30, "1MB to 1GB"},
		{"max_connection_receive_window", 1 << 20, 1 << 30, "1MB to 1GB"},
		{"max_send_memory", 1 << 20, 1 << 40, "1MB to 1024GB"},
		{"max_receive_memory", 1 << 20, 1 << 40, "1MB to 1024GB"},
		{"socket_buffer", 64 << 10, 64 << 20, "64KB to 64MB"},
	} {
		load := func(n int64) (HTTP3Limits, error) {
			cfg, err := loadWithServer(t, "server:\n  http3:\n    "+tc.key+": \""+formatSize(n)+"\"\n")
			if err != nil {
				return HTTP3Limits{}, err
			}
			return cfg.Server.HTTP3.Resolve(), nil
		}
		value := func(l HTTP3Limits) int64 {
			return map[string]int64{"max_header_size": l.MaxHeaderSize, "max_send_buffer": l.MaxSendBuffer,
				"max_stream_receive_window": l.MaxStreamReceiveWindow, "max_connection_receive_window": l.MaxConnectionReceiveWindow,
				"max_send_memory": l.MaxSendMemory, "max_receive_memory": l.MaxReceiveMemory, "socket_buffer": l.SocketBuffer}[tc.key]
		}
		for _, n := range []int64{tc.min, tc.max} {
			if l, err := load(n); err != nil || value(l) != n {
				t.Errorf("%s: %d bytes, an end of its range: resolved to %d, err %v", tc.key, n, value(l), err)
			}
		}
		for _, n := range []int64{tc.min - 1, tc.max + 1} {
			_, err := load(n)
			if err == nil || !strings.Contains(err.Error(), "server.http3."+tc.key+":") || !strings.Contains(err.Error(), tc.named) {
				t.Errorf("%s: %d bytes: Load err = %v, want an error naming server.http3.%s and %q", tc.key, n, err, tc.key, tc.named)
			}
		}
	}
}

// What is not a size is refused, zero included: "0" lifts a limit
// elsewhere in a config, and these bound what clients can make nvelox
// hold.
func TestHTTP3_NotASize(t *testing.T) {
	for _, key := range []string{"max_header_size", "max_send_buffer", "max_stream_receive_window",
		"max_connection_receive_window", "max_send_memory", "max_receive_memory", "socket_buffer"} {
		for _, val := range []string{"0", "0MB", "-1MB", "64KiB", "1.5MB", "MB", "lots", "64 K B", "8MBs", "0x10MB", "+8MB", "99999999999GB"} {
			_, err := loadWithServer(t, "server:\n  http3:\n    "+key+": \""+val+"\"\n")
			if err == nil || !strings.Contains(err.Error(), "server.http3."+key+":") {
				t.Errorf("%s: %q: Load err = %v, want an error naming server.http3.%s", key, val, err, key)
			}
		}
	}
	// A config that did not come through Load never yields a limit that
	// was not checked: such a value resolves to the default.
	got := HTTP3Config{MaxHeaderSize: "0", MaxSendBuffer: "lots", MaxStreamReceiveWindow: "1KB",
		MaxConnectionReceiveWindow: "4096GB", MaxSendMemory: "1", MaxReceiveMemory: "-1", SocketBuffer: "1KB"}.Resolve()
	if want := (HTTP3Config{}).Resolve(); got != want {
		t.Errorf("unchecked values resolve to %+v, want the defaults %+v", got, want)
	}
}

// The notation: a whole number with B, KB, MB or GB in either case, or a
// bare number of bytes.
func TestHTTP3_Notation(t *testing.T) {
	for val, want := range map[string]int64{"65536": 65536, "65536B": 65536, "64KB": 64 << 10, "64kb": 64 << 10, "64Kb": 64 << 10,
		" 64 KB ": 64 << 10, "1MB": 1 << 20, "1mb": 1 << 20, "1GB": 1 << 30, "0": 0, "007KB": 7 << 10} {
		if got, err := parseSize(val); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", val, got, err, want)
		}
	}
	for _, val := range []string{"", " ", "KB", "B", "-1", "1 0KB", "1e3", "1,5MB", "1TB", "9223372036854775807KB", "9223372036854775808"} {
		if got, err := parseSize(val); err == nil {
			t.Errorf("parseSize(%q) = %d, want an error", val, got)
		}
	}
	for n, want := range map[int64]string{1 << 10: "1KB", 256 << 10: "256KB", 1 << 20: "1MB", 15 << 20: "15MB", 1 << 30: "1GB",
		1 << 40: "1024GB", 1500: "1500B", 1<<20 + 1: "1048577B", 1<<20 + 1<<10: "1025KB"} {
		if got := formatSize(n); got != want {
			t.Errorf("formatSize(%d) = %q, want %q", n, got, want)
		}
		if back, err := parseSize(formatSize(n)); err != nil || back != n {
			t.Errorf("formatSize(%d) reads back as %d, %v", n, back, err)
		}
	}
}

// The four keys of nvelox's own QUIC transport change nothing where the
// quic-go server serves HTTP/3: set there, each gets a startup warning.
func TestHTTP3_Warnings(t *testing.T) {
	all := HTTP3Config{MaxHeaderSize: "32KB", MaxSendBuffer: "8MB", MaxStreamReceiveWindow: "2MB",
		MaxConnectionReceiveWindow: "4MB", MaxSendMemory: "512MB", MaxReceiveMemory: "3GB", SocketBuffer: "1MB"}
	if w := http3Warnings(all, "linux"); len(w) != 0 {
		t.Errorf("on Linux every key applies; warnings: %q", w)
	}
	w := http3Warnings(all, "darwin")
	if len(w) != 4 {
		t.Fatalf("on darwin: %d warnings, want one for each of max_send_buffer, max_send_memory, max_receive_memory, socket_buffer: %q", len(w), w)
	}
	for i, key := range []string{"max_send_buffer", "max_send_memory", "max_receive_memory", "socket_buffer"} {
		if !strings.Contains(w[i], "server.http3."+key+" ") || !strings.Contains(w[i], "darwin") {
			t.Errorf("warning %d: %q, want one naming server.http3.%s and the platform", i, w[i], key)
		}
	}
	if w := http3Warnings(HTTP3Config{MaxHeaderSize: "32KB", MaxStreamReceiveWindow: "2MB", MaxConnectionReceiveWindow: "4MB"}, "darwin"); len(w) != 0 {
		t.Errorf("the keys that apply everywhere got warnings on darwin: %q", w)
	}
	if w := http3Warnings(HTTP3Config{}, "darwin"); len(w) != 0 {
		t.Errorf("nothing set: warnings %q", w)
	}
	// The startup warnings carry them, behind those of the other keys.
	got := serverWarnings(ServerConfig{PidFile: "/run/nvelox.pid", HTTP3: all}, "darwin")
	if len(got) != 5 || !strings.Contains(got[0], "server.pid_file") || !strings.Contains(got[3], "server.http3.max_receive_memory") ||
		!strings.Contains(got[4], "server.http3.socket_buffer") {
		t.Errorf("the startup warnings on darwin: %q, want server.pid_file's and the four of server.http3", got)
	}
	if got := ServerWarnings(ServerConfig{HTTP3: all}); len(got) != len(http3Warnings(all, runtime.GOOS)) {
		t.Errorf("ServerWarnings on this platform: %q", got)
	}
}
