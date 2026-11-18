//go:build linux

package httpproxy

import (
	"github.com/nvelox/ngx/web"

	"bytes"
	"io"
	"testing"

	"nvelox/config"

	nvquic "github.com/nvelox/ngx/quic"

	"github.com/nvelox/ngx/h3"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// useHTTP3Limits gives the process the limits of cfg, as the engine does
// with server.http3 at a start and at a reload, and the defaults back when
// the test is over.
func useHTTP3Limits(t *testing.T, cfg config.HTTP3Config) {
	t.Helper()
	SetHTTP3Limits(cfg.Resolve())
	t.Cleanup(func() {
		SetHTTP3Limits(h3DefaultLimits.cfg) // the totals of the defaults, at once
		h3Limits.Store(nil)
	})
}

// serverSettings returns the settings the server sent on its control
// stream.
func serverSettings(t *testing.T, conn *quic.Conn) map[uint64]uint64 {
	t.Helper()
	ctx := testCtx(t)
	for range 3 { // its control stream and the two of QPACK
		str, err := conn.AcceptUniStream(ctx)
		if err != nil {
			t.Fatalf("the server's streams: %v", err)
		}
		r := quicvarint.NewReader(str)
		if typ, err := quicvarint.Read(r); err != nil || typ != h3.StreamControl {
			continue
		}
		frame, _ := quicvarint.Read(r)
		length, err := quicvarint.Read(r)
		if err != nil || frame != h3.FrameSettings {
			t.Fatalf("the control stream begins with frame %#x (%v), want SETTINGS", frame, err)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			t.Fatalf("the SETTINGS frame: %v", err)
		}
		settings := map[uint64]uint64{}
		for b := bytes.NewReader(payload); b.Len() > 0; {
			id, _ := quicvarint.Read(b)
			val, err := quicvarint.Read(b)
			if err != nil {
				t.Fatalf("the SETTINGS frame % x: %v", payload, err)
			}
			settings[id] = val
		}
		return settings
	}
	t.Fatal("the server opened no control stream")
	return nil
}

// server.http3.max_header_size is the largest head a request may have, on
// both servers of HTTP/3: lowered, a head that the default would take is
// answered 431; raised, one that the default would refuse is served. (The
// quic-go server goes by the size of the frame, the loops by the size
// HTTP/3 defines; the heads here are far enough from the limit for both.)
func TestHTTP3Limits_HeaderSize(t *testing.T) {
	onBothH3Servers(t, func(t *testing.T) {
		for _, tc := range []struct {
			setting string
			limit   int
		}{{"8KB", 8 << 10}, {"128KB", 128 << 10}} {
			useHTTP3Limits(t, config.HTTP3Config{MaxHeaderSize: tc.setting})
			pki := newCAPKI(t, "h3-limits-ca")
			addr := freeAddr(t)
			g := startGroup(t, addr, h3Site(t, pki, h3RawBackend))
			conn := rawH3(t, addr, pki)
			for _, req := range []struct {
				size int
				want string
			}{{tc.limit * 3 / 4, "200"}, {tc.limit * 2, "431"}, {tc.limit * 3 / 4, "200"}} {
				status, _, err := rawExchange(t, conn, h3HeadersFrame(h3SizedFields(req.size, 4<<10)...))
				if err != nil || status != req.want {
					t.Errorf("max_header_size %s: a head of %d bytes: status %q, err %v; want %s", tc.setting, req.size, status, err, req.want)
				}
			}
			if g.http3Server != nil {
				if got := g.http3Server.MaxHeaderBytes; got != tc.limit {
					t.Errorf("max_header_size %s: the quic-go server takes heads of %d bytes", tc.setting, got)
				}
				continue
			}
			// The loops count a head as HTTP/3 defines its size: to the byte.
			for _, req := range []struct {
				size int
				want string
			}{{tc.limit, "200"}, {tc.limit + 1, "431"}} {
				status, _, err := rawExchange(t, conn, h3HeadersFrame(h3SizedFields(req.size, 4<<10)...))
				if err != nil || status != req.want {
					t.Errorf("max_header_size %s on the loops: a head of %d bytes: status %q, err %v; want %s", tc.setting, req.size, status, err, req.want)
				}
			}
			// A frame that announces more than the limit is answered at
			// its header, before its bytes: two of them are sent.
			str, err := conn.OpenStreamSync(testCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			str.Write(append(h3.AppendFrameHeader(nil, h3.FrameHeaders, uint64(tc.limit+1)), 0, 0))
			if status, _, err := rawAnswer(t, str); status != "431" {
				t.Errorf("max_header_size %s on the loops: a frame that announces %d bytes: status %q, err %v; want 431 at its header", tc.setting, tc.limit+1, status, err)
			}
			// And the limit is what the server's settings tell its clients.
			if got := serverSettings(t, conn)[0x6]; got != uint64(tc.limit) {
				t.Errorf("max_header_size %s: the server's settings announce heads of %d bytes", tc.setting, got)
			}
		}
	})
}

// The quic-go server, which serves HTTP/3 where there are no event loops,
// takes the three limits it has: the largest head, and how far its receive
// windows grow. 0-RTT stays off.
func TestHTTP3Limits_QuicGoServer(t *testing.T) {
	quicGoPath(t)
	pki := newCAPKI(t, "h3-limits-ca")
	for _, tc := range []struct {
		cfg                config.HTTP3Config
		head               int
		stream, connection uint64
	}{
		{config.HTTP3Config{}, 64 << 10, 6 << 20, 15 << 20},
		{config.HTTP3Config{MaxHeaderSize: "8KB", MaxStreamReceiveWindow: "2MB", MaxConnectionReceiveWindow: "3MB"}, 8 << 10, 2 << 20, 3 << 20},
	} {
		useHTTP3Limits(t, tc.cfg)
		g := startGroup(t, freeAddr(t), h3Site(t, pki, h3RawBackend))
		srv := g.http3Server
		if srv == nil {
			t.Fatal("the group has no quic-go server")
		}
		if srv.MaxHeaderBytes != tc.head || srv.QUICConfig.MaxStreamReceiveWindow != tc.stream || srv.QUICConfig.MaxConnectionReceiveWindow != tc.connection {
			t.Errorf("%+v: heads of %d bytes, windows that grow to %d and %d; want %d, %d and %d", tc.cfg,
				srv.MaxHeaderBytes, srv.QUICConfig.MaxStreamReceiveWindow, srv.QUICConfig.MaxConnectionReceiveWindow, tc.head, tc.stream, tc.connection)
		}
		if srv.QUICConfig.Allow0RTT {
			t.Errorf("%+v: the quic-go server takes 0-RTT", tc.cfg)
		}
	}
}

// server.http3 reaches the loops as it is configured: each of its sizes, in
// the form they take them; the two totals apply at once; and they are told
// by the pointer that the limits changed, never when they did not.
func TestHTTP3Limits_ReachTheLoops(t *testing.T) {
	defaults := web.H3Limits{MaxHeaderSize: 64 << 10, MaxSendBuffer: 16 << 20, MaxStreamReceiveWindow: 6 << 20, MaxConnectionReceiveWindow: 15 << 20, SocketBuffer: 4 << 20}
	if got := *fastH3Limits(); got != defaults {
		t.Errorf("with nothing configured the loops are given %+v, want %+v", got, defaults)
	}
	first := fastH3Limits()
	if fastH3Limits() != first {
		t.Error("limits that did not change are another pointer the second time: every connection would take them for new ones")
	}
	useHTTP3Limits(t, config.HTTP3Config{MaxHeaderSize: "8KB", MaxSendBuffer: "1MB", MaxStreamReceiveWindow: "2MB",
		MaxConnectionReceiveWindow: "3MB", MaxSendMemory: "128MB", MaxReceiveMemory: "256MB", SocketBuffer: "128KB"})
	want := web.H3Limits{MaxHeaderSize: 8 << 10, MaxSendBuffer: 1 << 20, MaxStreamReceiveWindow: 2 << 20,
		MaxConnectionReceiveWindow: 3 << 20, MaxSendMemory: 128 << 20, MaxReceiveMemory: 256 << 20, SocketBuffer: 128 << 10}
	if got := *fastH3Limits(); got != want {
		t.Errorf("the loops are given %+v, want %+v", got, want)
	}
	if fastH3Limits() == first {
		t.Error("the limits changed and the loops are given the pointer they had")
	}
	if send, receive := nvquic.SendMemoryLimit(), nvquic.ReceiveMemoryLimit(); send != 128<<20 || receive != 256<<20 {
		t.Errorf("the totals are %d to send and %d to receive, want 128 MiB and 256 MiB at once", send, receive)
	}
	// A configuration that names no totals has them at their default
	// again: a share of the memory, the same for both, 64 MiB at the least.
	useHTTP3Limits(t, config.HTTP3Config{MaxSendBuffer: "4MB"})
	if send, receive := nvquic.SendMemoryLimit(), nvquic.ReceiveMemoryLimit(); send != receive || send < 64<<20 || send == 128<<20 {
		t.Errorf("after a configuration without totals they are %d and %d, want the default share for both", send, receive)
	}
	if got := fastH3Limits().MaxSendBuffer; got != 4<<20 {
		t.Errorf("max_send_buffer 4MB reaches the loops as %d", got)
	}
}

// The smallest max_stream_receive_window and max_connection_receive_window
// a configuration may name (1MB, config/http3.go) are the windows every
// request and connection on the loops starts with (1 MiB, the loops' own
// TestHTTP3Limits_FirstWindows): at 1MB nothing grows.
func TestHTTP3Limits_SmallestWindowsAreTheFirst(t *testing.T) {
	l := config.HTTP3Config{MaxStreamReceiveWindow: "1MB", MaxConnectionReceiveWindow: "1MB"}.Resolve()
	if l.MaxStreamReceiveWindow != 1<<20 || l.MaxConnectionReceiveWindow != 1<<20 {
		t.Errorf("1MB resolves to %d and %d; the loops' first windows are 1 MiB each", l.MaxStreamReceiveWindow, l.MaxConnectionReceiveWindow)
	}
}
