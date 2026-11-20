package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// HTTP3Config is server.http3: the limits of the HTTP/3 (QUIC) connections
// of every listener with http3. Each is a size, a whole number followed by
// B, KB, MB or GB ("64KB", "16MB", "2GB"; KB is 1024 bytes), but for
// handshakes_per_source, a count. One that is not set has its default. A reload applies them: the two totals at once,
// the socket buffer to the bind addresses started after it, the others to
// the connections opened after it.
//
// MaxSendBuffer, MaxSendMemory, MaxReceiveMemory, SocketBuffer and
// HandshakesPerSource belong to the QUIC transport nvelox runs on Linux.
// Where the quic-go server serves HTTP/3 (other platforms) the other three
// apply, to the bind addresses started after they were set.
type HTTP3Config struct {
	// MaxHeaderSize is the largest header section a request may have,
	// counted as HTTP/3 counts it (names, values and 32 bytes a field); a
	// larger one is answered 431. A connection may have 100 requests open
	// and so hold 100 heads on their way: 6.4 MiB with the default, 100 MiB
	// with 1MB. 1KB to 1MB, default 64KB.
	MaxHeaderSize string `yaml:"max_header_size,omitempty"`
	// MaxSendBuffer is the most one connection holds of its answers that
	// the client has not acknowledged: what it holds follows what its
	// path carries, up to this, so it is also the most a download moves
	// per round trip. 256KB to 1GB, default 16MB.
	MaxSendBuffer string `yaml:"max_send_buffer,omitempty"`
	// How far the window for one request's body grows. A window starts at
	// 1 MiB and doubles while the backend takes an upload as fast as the
	// path brings it, so this is the most one upload moves per round trip,
	// and the most nvelox holds of it when the backend stops taking. 1MB
	// (nothing grows) to 1GB, default 6MB.
	MaxStreamReceiveWindow string `yaml:"max_stream_receive_window,omitempty"`
	// How far the window for all the request bodies of one connection
	// together grows, as max_stream_receive_window does for one: the most
	// a connection's uploads move per round trip. 1MB (nothing grows) to
	// 1GB, default 15MB.
	MaxConnectionReceiveWindow string `yaml:"max_connection_receive_window,omitempty"`
	// The most all connections together hold to send; past it a
	// connection takes 16 KiB at a time. 1MB to 1024GB. Default: an eighth
	// of the memory nvelox may use (the machine's, or its control group's
	// limit), 64 MiB at the least.
	MaxSendMemory string `yaml:"max_send_memory,omitempty"`
	// The most all connections together are granted to receive beyond
	// their first windows; past it no window grows. 1MB to 1024GB. Default:
	// an eighth of the memory nvelox may use, 64 MiB at the least.
	MaxReceiveMemory string `yaml:"max_receive_memory,omitempty"`
	// SocketBuffer is what nvelox asks the kernel for as the receive and
	// as the send buffer of each UDP socket of an HTTP/3 listener: there
	// is one socket per event loop. A burst of a fast client's datagrams
	// waits in the receive buffer until its loop reads it, and what does
	// not fit is dropped, which slows an upload down. The kernel grants
	// up to net.core.rmem_max and wmem_max, and the whole of it to a
	// process started with CAP_NET_ADMIN; a listener whose sockets got
	// less says so in a startup warning. 64KB to 64MB, default 4MB.
	SocketBuffer string `yaml:"socket_buffer,omitempty"`
	// HandshakesPerSource is how many QUIC handshakes one client address
	// (an IPv4 address, or an IPv6 /64) may have running at once on each
	// event loop; behind a trusted relay, the address the relay names.
	// It counts the clients that proved their address: they came back
	// with the token of the server's Retry packet (through a relay, a
	// token made for the client the relay names). A client taken on trust
	// is not counted, so first packets with a made-up source take no
	// address's places; the server runs at most 128 handshakes with
	// clients taken on trust (shared out among its event loops) and sends
	// further new clients a Retry. The first packets of an address's
	// further clients are dropped, and counted in
	// nvelox_h3_handshakes_refused_total{reason="per_source"}, until one of
	// its handshakes completes or is given up (after 10 s); a client sends
	// them again. Clients behind one address, a company's NAT say, share
	// it. 0 (no limit) to 4096 (all of a loop's handshakes), default 32.
	HandshakesPerSource *int `yaml:"handshakes_per_source,omitempty"`
}

// The defaults of server.http3.
const (
	DefaultHTTP3MaxHeaderSize              = 64 << 10
	DefaultHTTP3MaxSendBuffer              = 16 << 20
	DefaultHTTP3MaxStreamReceiveWindow     = 6 << 20
	DefaultHTTP3MaxConnectionReceiveWindow = 15 << 20
	DefaultHTTP3SocketBuffer               = 4 << 20
	DefaultHTTP3HandshakesPerSource        = 32
	maxHTTP3HandshakesPerSource            = 4096
)

// HTTP3Limits is server.http3 in bytes, defaults filled in.
type HTTP3Limits struct {
	MaxHeaderSize              int64
	MaxSendBuffer              int64
	MaxStreamReceiveWindow     int64
	MaxConnectionReceiveWindow int64
	// 0: the default, a share of the memory, which is worked out where
	// the totals are applied.
	MaxSendMemory    int64
	MaxReceiveMemory int64
	SocketBuffer     int64
	// HandshakesPerSource is a count; 0: no limit.
	HandshakesPerSource int
}

// A sizeRule is a size setting: its key, the range it accepts, and its
// default (0: none that is a fixed number).
type sizeRule struct {
	key      string
	min, max int64
	def      int64
}

// The smallest window is the one every connection starts with
// (core/httpproxy, h3StreamWindow and h3ConnWindow), and the smallest send
// buffer what a connection may hold whatever its path carries (ngx/quic,
// sendBufferMin).
var (
	http3HeaderSize    = sizeRule{"max_header_size", 1 << 10, 1 << 20, DefaultHTTP3MaxHeaderSize}
	http3SendBuffer    = sizeRule{"max_send_buffer", 256 << 10, 1 << 30, DefaultHTTP3MaxSendBuffer}
	http3StreamWindow  = sizeRule{"max_stream_receive_window", 1 << 20, 1 << 30, DefaultHTTP3MaxStreamReceiveWindow}
	http3ConnWindow    = sizeRule{"max_connection_receive_window", 1 << 20, 1 << 30, DefaultHTTP3MaxConnectionReceiveWindow}
	http3SendMemory    = sizeRule{"max_send_memory", 1 << 20, 1 << 40, 0}
	http3ReceiveMemory = sizeRule{"max_receive_memory", 1 << 20, 1 << 40, 0}
	http3SocketBuffer  = sizeRule{"socket_buffer", 64 << 10, 64 << 20, DefaultHTTP3SocketBuffer}
)

// http3Setting is one key of server.http3 with the value a config gives it.
type http3Setting struct {
	rule sizeRule
	val  string
}

// settings returns the keys of server.http3 in the order they are
// documented, each with its value in h.
func (h HTTP3Config) settings() []http3Setting {
	return []http3Setting{
		{http3HeaderSize, h.MaxHeaderSize},
		{http3SendBuffer, h.MaxSendBuffer},
		{http3StreamWindow, h.MaxStreamReceiveWindow},
		{http3ConnWindow, h.MaxConnectionReceiveWindow},
		{http3SendMemory, h.MaxSendMemory},
		{http3ReceiveMemory, h.MaxReceiveMemory},
		{http3SocketBuffer, h.SocketBuffer},
	}
}

// parseSize reads a size: a whole number followed by B, KB, MB or GB in
// either case (KB is 1024 bytes), or a bare number of bytes. Anything
// else is an error: a size that was misread would be a limit nobody chose.
func parseSize(s string) (int64, error) {
	v := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(v, "KB"):
		mult, v = 1<<10, v[:len(v)-2]
	case strings.HasSuffix(v, "MB"):
		mult, v = 1<<20, v[:len(v)-2]
	case strings.HasSuffix(v, "GB"):
		mult, v = 1<<30, v[:len(v)-2]
	case strings.HasSuffix(v, "B"):
		v = v[:len(v)-1]
	}
	v = strings.TrimSpace(v)
	if v == "" || strings.Trim(v, "0123456789") != "" {
		return 0, fmt.Errorf("%q is not a size (a whole number followed by B, KB, MB or GB, like \"64KB\")", s)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n > math.MaxInt64/mult {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return n * mult, nil
}

// formatSize writes n the way a config gives a size.
func formatSize(n int64) string {
	for _, u := range []struct {
		size int64
		name string
	}{{1 << 30, "GB"}, {1 << 20, "MB"}, {1 << 10, "KB"}} {
		if n >= u.size && n%u.size == 0 {
			return strconv.FormatInt(n/u.size, 10) + u.name
		}
	}
	return strconv.FormatInt(n, 10) + "B"
}

// check returns what val gives the setting: its default when val is empty,
// and an error for what is not a size or is outside the setting's range.
// Zero is refused like any other size below the range rather than given a
// meaning: elsewhere in a config "0" lifts a limit, and each of these
// bounds memory that clients can make nvelox hold.
func (r sizeRule) check(val string) (int64, error) {
	if val == "" {
		return r.def, nil
	}
	n, err := parseSize(val)
	if err != nil {
		return 0, err
	}
	if n < r.min || n > r.max {
		return 0, fmt.Errorf("%q is outside %s to %s", val, formatSize(r.min), formatSize(r.max))
	}
	return n, nil
}

// validateHTTP3 checks server.http3: every key unset, or a size in its
// range, and handshakes_per_source a count in its range.
func validateHTTP3(h HTTP3Config) error {
	for _, s := range h.settings() {
		if _, err := s.rule.check(s.val); err != nil {
			return fmt.Errorf("server.http3.%s: %v", s.rule.key, err)
		}
	}
	if n := h.HandshakesPerSource; n != nil && (*n < 0 || *n > maxHTTP3HandshakesPerSource) {
		return fmt.Errorf("server.http3.handshakes_per_source: %d is outside 0 (no limit) to %d", *n, maxHTTP3HandshakesPerSource)
	}
	return nil
}

// Resolve returns server.http3 in bytes: every key that is not set at its
// default (as is, in a config that did not come through Load, one that is
// not a size in its range).
func (h HTTP3Config) Resolve() HTTP3Limits {
	var v [7]int64
	for i, s := range h.settings() {
		n, err := s.rule.check(s.val)
		if err != nil {
			n = s.rule.def
		}
		v[i] = n
	}
	perSource := DefaultHTTP3HandshakesPerSource
	if n := h.HandshakesPerSource; n != nil && *n >= 0 && *n <= maxHTTP3HandshakesPerSource {
		perSource = *n
	}
	return HTTP3Limits{
		MaxHeaderSize:              v[0],
		MaxSendBuffer:              v[1],
		MaxStreamReceiveWindow:     v[2],
		MaxConnectionReceiveWindow: v[3],
		MaxSendMemory:              v[4],
		MaxReceiveMemory:           v[5],
		SocketBuffer:               v[6],
		HandshakesPerSource:        perSource,
	}
}

// http3Warnings returns one warning per key of server.http3 that is set
// and changes nothing on the platform goos: the five that belong to the
// QUIC transport nvelox runs on Linux.
func http3Warnings(h HTTP3Config, goos string) []string {
	if goos == "linux" {
		return nil
	}
	var out []string
	for _, s := range []http3Setting{{http3SendBuffer, h.MaxSendBuffer}, {http3SendMemory, h.MaxSendMemory}, {http3ReceiveMemory, h.MaxReceiveMemory}, {http3SocketBuffer, h.SocketBuffer}} {
		if s.val != "" {
			out = append(out, fmt.Sprintf("server.http3.%s (%q) is set and changes nothing on %s: it applies on Linux, where nvelox runs its own QUIC transport", s.rule.key, s.val, goos))
		}
	}
	if n := h.HandshakesPerSource; n != nil {
		out = append(out, fmt.Sprintf("server.http3.handshakes_per_source (%d) is set and changes nothing on %s: it applies on Linux, where nvelox runs its own QUIC transport", *n, goos))
	}
	return out
}
