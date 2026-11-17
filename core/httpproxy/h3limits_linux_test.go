//go:build linux

package httpproxy

// server.http3: the limits of HTTP/3 connections as settings.

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"nvelox/config"
	"nvelox/core/h3"
	"nvelox/core/logging"
	nvquic "nvelox/core/quic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/sys/unix"
)

// useHTTP3Limits gives the process the limits of cfg, as the engine does
// with server.http3 at a start and at a reload, and the defaults back when
// the test is over.
func useHTTP3Limits(t *testing.T, cfg config.HTTP3Config) {
	t.Helper()
	SetHTTP3Limits(cfg.Resolve())
	t.Cleanup(func() {
		h3Limits.Store(nil)
		setQUICMemory(&h3DefaultLimits)
	})
}

// h3ConnLimit is what one HTTP/3 connection on the loops was opened with.
type h3ConnLimit struct {
	maxHead                uint32
	sendBuffer             int64
	streamWindow, connWind uint64
}

// h3ConnLimits returns the limits of every HTTP/3 connection the group has
// open, by the port of its client.
func h3ConnLimits(g *BindGroup) map[uint16]h3ConnLimit {
	out := map[uint16]h3ConnLimit{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, l := range g.fast.group.Loops() {
		wg.Add(1)
		l.Post(func() {
			defer wg.Done()
			for c := g.fast.h3lists[l.ID()]; c != nil; c = c.lnext {
				cfg := c.q.Config()
				mu.Lock()
				out[c.qc.peer.Port()] = h3ConnLimit{c.maxHead, cfg.MaxSendBuffer, cfg.MaxStreamWindow, cfg.MaxConnWindow}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return out
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

func clientPort(t *testing.T, conn *quic.Conn) uint16 {
	t.Helper()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
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

// A connection has the limits server.http3 had when it was opened, and
// keeps them: after a reload that changes them, the connections opened
// before it go on as they were, and the ones opened after it have the new
// limits. The two totals of the process change at once.
func TestHTTP3Limits_FollowAReload(t *testing.T) {
	addr, g, pki := startH3Loops(t, h3RawBackend)
	get := func(conn *quic.Conn, size int) string {
		t.Helper()
		status, _, err := rawExchange(t, conn, h3HeadersFrame(h3SizedFields(size, 4<<10)...))
		if err != nil {
			t.Fatalf("a request with a head of %d bytes: %v", size, err)
		}
		return status
	}
	before := rawH3(t, addr, pki)
	if got := get(before, 32<<10); got != "200" {
		t.Fatalf("a head of 32 KiB under the defaults: status %s", got)
	}
	defaults := h3ConnLimit{64 << 10, 16 << 20, 6 << 20, 15 << 20}
	if got := h3ConnLimits(g)[clientPort(t, before)]; got != defaults {
		t.Errorf("a connection opened with nothing set: %+v, want the defaults %+v", got, defaults)
	}
	if send, receive := nvquic.SendMemoryLimit(), nvquic.ReceiveMemoryLimit(); send != quicSendMemory() || receive != quicSendMemory() {
		t.Errorf("with nothing set the totals are %d to send and %d to receive, want %d each (an eighth of the memory)", send, receive, quicSendMemory())
	}

	// The reload.
	useHTTP3Limits(t, config.HTTP3Config{MaxHeaderSize: "8KB", MaxSendBuffer: "1MB", MaxStreamReceiveWindow: "2MB",
		MaxConnectionReceiveWindow: "3MB", MaxSendMemory: "128MB", MaxReceiveMemory: "256MB"})
	if send, receive := nvquic.SendMemoryLimit(), nvquic.ReceiveMemoryLimit(); send != 128<<20 || receive != 256<<20 {
		t.Errorf("after the reload the totals are %d to send and %d to receive, want 128 MiB and 256 MiB at once", send, receive)
	}
	after := rawH3(t, addr, pki)
	if got := get(after, 32<<10); got != "431" {
		t.Errorf("a head of 32 KiB on a connection opened after max_header_size became 8KB: status %s, want 431", got)
	}
	if got := get(before, 32<<10); got != "200" {
		t.Errorf("a head of 32 KiB on the connection opened before the reload: status %s; it was told 64 KiB and keeps that", got)
	}
	limits := h3ConnLimits(g)
	if got := limits[clientPort(t, before)]; got != defaults {
		t.Errorf("the connection opened before the reload now has %+v, want what it was opened with, %+v", got, defaults)
	}
	if got, want := limits[clientPort(t, after)], (h3ConnLimit{8 << 10, 1 << 20, 2 << 20, 3 << 20}); got != want {
		t.Errorf("the connection opened after the reload has %+v, want %+v", got, want)
	}

	// A reload that names no totals has them at their default again.
	useHTTP3Limits(t, config.HTTP3Config{MaxSendBuffer: "4MB"})
	if send, receive := nvquic.SendMemoryLimit(), nvquic.ReceiveMemoryLimit(); send != quicSendMemory() || receive != quicSendMemory() {
		t.Errorf("after a reload without totals they are %d and %d, want %d each", send, receive, quicSendMemory())
	}
	third := rawH3(t, addr, pki)
	if got := get(third, 32<<10); got != "200" {
		t.Errorf("a head of 32 KiB after max_header_size was unset again: status %s", got)
	}
	if got, want := h3ConnLimits(g)[clientPort(t, third)], (h3ConnLimit{64 << 10, 4 << 20, 6 << 20, 15 << 20}); got != want {
		t.Errorf("a connection opened after the second reload has %+v, want %+v", got, want)
	}
}

// The totals the engine gave stand when a server binds afterwards: only a
// process whose engine gave none gets them from its first bind.
func TestHTTP3Limits_TotalsAndTheFirstBind(t *testing.T) {
	share := quicSendMemory()
	t.Cleanup(func() {
		h3Limits.Store(nil)
		quicMemoryOnce = sync.Once{}
		quicMemoryOnce.Do(func() {})
		setQUICMemory(&h3DefaultLimits)
	})
	// The engine first, then the bind.
	quicMemoryOnce = sync.Once{}
	SetHTTP3Limits(config.HTTP3Config{MaxSendMemory: "128MB", MaxReceiveMemory: "256MB"}.Resolve())
	startH3Loops(t, h3RawBackend)
	if send, receive := nvquic.SendMemoryLimit(), nvquic.ReceiveMemoryLimit(); send != 128<<20 || receive != 256<<20 {
		t.Errorf("a bind after the engine set the totals: %d to send and %d to receive, want the 128 MiB and 256 MiB it set", send, receive)
	}
	// One total set: the other is the share.
	SetHTTP3Limits(config.HTTP3Config{MaxReceiveMemory: "256MB"}.Resolve())
	if send, receive := nvquic.SendMemoryLimit(), nvquic.ReceiveMemoryLimit(); send != share || receive != 256<<20 {
		t.Errorf("with max_receive_memory alone: %d to send and %d to receive, want %d and 256 MiB", send, receive, share)
	}
	// No engine: the first bind gives the transport its totals.
	quicMemoryOnce = sync.Once{}
	h3Limits.Store(nil)
	nvquic.SetSendMemory(1)
	nvquic.SetReceiveMemory(1)
	startH3Loops(t, h3RawBackend)
	if send, receive := nvquic.SendMemoryLimit(), nvquic.ReceiveMemoryLimit(); send != share || receive != share || share < 64<<20 {
		t.Errorf("a first bind with nothing set: %d to send and %d to receive, want %d each (64 MiB at the least)", send, receive, share)
	}
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

// The loops start every request and every connection with a window of
// 1 MiB, which is what the smallest max_stream_receive_window and
// max_connection_receive_window a config may name stand for (config,
// http3.go): at 1MB nothing grows.
func TestHTTP3Limits_FirstWindows(t *testing.T) {
	if h3StreamWindow != 1<<20 || h3ConnWindow != 1<<20 {
		t.Errorf("the first windows are %d and %d; the config takes 1MB as the smallest limit for both", h3StreamWindow, h3ConnWindow)
	}
	l := config.HTTP3Config{MaxStreamReceiveWindow: "1MB", MaxConnectionReceiveWindow: "1MB"}.Resolve()
	if l.MaxStreamReceiveWindow != h3StreamWindow || l.MaxConnectionReceiveWindow != h3ConnWindow {
		t.Errorf("1MB resolves to %d and %d", l.MaxStreamReceiveWindow, l.MaxConnectionReceiveWindow)
	}
	_, g, _ := startH3Loops(t, h3RawBackend)
	p := g.h3loops.cfg.Params
	if p.InitialMaxStreamDataBidiRemote != 1<<20 || p.InitialMaxData != 1<<20 {
		t.Errorf("the first windows a client is told: %d per request and %d per connection, want 1 MiB each", p.InitialMaxStreamDataBidiRemote, p.InitialMaxData)
	}
}

// kernelLimit reads a size limit of the kernel (net.core.rmem_max, wmem_max).
func kernelLimit(t *testing.T, name string) int {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/core/" + name)
	if err != nil {
		t.Skipf("no /proc/sys/net/core/%s: %v", name, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// server.http3.socket_buffer is what each loop's UDP socket asks the kernel
// for, to receive and to send. A size within the kernel's limits is what
// every socket has; the default is 4 MiB, cut to the kernel's limit unless
// the process may ask past it.
func TestHTTP3Limits_SocketBuffer(t *testing.T) {
	buffers := func(g *BindGroup) (rcv, snd []int) {
		for _, s := range g.h3loops.socks {
			r, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
			if err != nil {
				t.Fatal(err)
			}
			w, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
			if err != nil {
				t.Fatal(err)
			}
			rcv, snd = append(rcv, r), append(snd, w)
		}
		return rcv, snd
	}
	// 128 KiB is within the limits of any kernel (their default is 208 KiB):
	// every socket has it. The kernel reports twice what it granted.
	useHTTP3Limits(t, config.HTTP3Config{SocketBuffer: "128KB"})
	_, g, _ := startH3Loops(t, h3RawBackend)
	rcv, snd := buffers(g)
	if len(rcv) == 0 {
		t.Fatal("the listener has no sockets")
	}
	for i := range rcv {
		if rcv[i] != 2*128<<10 || snd[i] != 2*128<<10 {
			t.Errorf("socket %d with socket_buffer 128KB: %d to receive and %d to send, want %d each", i, rcv[i], snd[i], 2*128<<10)
		}
	}
	// A listener bound later has the size in force then.
	SetHTTP3Limits(config.HTTP3Config{SocketBuffer: "64KB"}.Resolve())
	_, g2, _ := startH3Loops(t, h3RawBackend)
	rcv2, snd2 := buffers(g2)
	for i := range rcv2 {
		if rcv2[i] != 2*64<<10 || snd2[i] != 2*64<<10 {
			t.Errorf("socket %d bound with socket_buffer 64KB: %d to receive and %d to send, want %d each", i, rcv2[i], snd2[i], 2*64<<10)
		}
	}
	if again, _ := buffers(g); again[0] != 2*128<<10 {
		t.Errorf("the listener bound before has %d now, want the %d it was bound with", again[0], 2*128<<10)
	}
	// Nothing set: 4 MiB is asked for. The kernel grants up to its limit;
	// a process that may ask past it (root with CAP_NET_ADMIN) has all of it.
	h3Limits.Store(nil)
	_, g3, _ := startH3Loops(t, h3RawBackend)
	rcv3, snd3 := buffers(g3)
	wantR, wantS := 2*min(4<<20, kernelLimit(t, "rmem_max")), 2*min(4<<20, kernelLimit(t, "wmem_max"))
	for i := range rcv3 {
		okR := rcv3[i] == wantR || (os.Geteuid() == 0 && rcv3[i] == 2*4<<20)
		okS := snd3[i] == wantS || (os.Geteuid() == 0 && snd3[i] == 2*4<<20)
		if !okR || !okS {
			t.Errorf("socket %d with nothing set: %d to receive and %d to send, want %d and %d (4 MiB asked for, the kernel's limits applied)", i, rcv3[i], snd3[i], wantR, wantS)
		}
	}
	// Limits that were not resolved from a config name no size: the default
	// is asked for, never a buffer of nothing.
	SetHTTP3Limits(config.HTTP3Limits{MaxHeaderSize: 64 << 10, MaxSendBuffer: 16 << 20, MaxStreamReceiveWindow: 6 << 20, MaxConnectionReceiveWindow: 15 << 20})
	_, g4, _ := startH3Loops(t, h3RawBackend)
	if rcv4, snd4 := buffers(g4); rcv4[0] != rcv3[0] || snd4[0] != snd3[0] {
		t.Errorf("limits that name no socket buffer: %d to receive and %d to send, want the default's %d and %d", rcv4[0], snd4[0], rcv3[0], snd3[0])
	}
}

// The order a buffer is asked for in: the plain request; the forced one
// only when the plain one left the socket with less than was asked for;
// and what the socket has in the end is what is reported.
func TestHTTP3Limits_AskBuffer(t *testing.T) {
	const size = 4 << 20
	for _, tc := range []struct {
		name      string
		plain     int   // what the kernel grants to the plain request
		forceErr  error // what the forced request returns
		want      int
		wantCalls string
	}{
		{"the limit allows it", size, nil, 2 * size, "plain get"},
		{"the socket has more than was asked for", 2 * size, errors.New("not to be called"), 4 * size, "plain get"},
		{"cut by the limit, the forced request granted", 212992, nil, 2 * size, "plain get forced get"},
		{"cut by the limit, the forced request refused", 212992, unix.EPERM, 2 * 212992, "plain get forced"},
		{"one byte short of what was asked", size - 1, unix.EPERM, 2 * (size - 1), "plain get forced"},
	} {
		has, calls := 0, []string{}
		got := askBuffer(size,
			func(forced bool) error {
				if forced {
					calls = append(calls, "forced")
					if tc.forceErr == nil {
						has = 2 * size
					}
					return tc.forceErr
				}
				calls = append(calls, "plain")
				has = 2 * tc.plain
				return nil
			},
			func() int { calls = append(calls, "get"); return has })
		if got != tc.want || strings.Join(calls, " ") != tc.wantCalls {
			t.Errorf("%s: the socket is reported to have %d after %q, want %d after %q", tc.name, got, strings.Join(calls, " "), tc.want, tc.wantCalls)
		}
	}
	// Against the kernel: a request within its limits is granted by the
	// plain form, and reported doubled.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if got := socketBuffer(fd, unix.SO_RCVBUF, unix.SO_RCVBUFFORCE, 96<<10); got != 2*96<<10 {
		t.Errorf("a receive buffer of 96 KiB: the socket has %d, want %d", got, 2*96<<10)
	}
	if got := socketBuffer(fd, unix.SO_SNDBUF, unix.SO_SNDBUFFORCE, 80<<10); got != 2*80<<10 {
		t.Errorf("a send buffer of 80 KiB: the socket has %d, want %d", got, 2*80<<10)
	}
	if r, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); r != 2*96<<10 {
		t.Errorf("asking for the send buffer changed the receive buffer to %d", r)
	}
}

// A process that may ask past the kernel's limit (CAP_NET_ADMIN) is
// granted what it asks for. Skipped where the process may not.
func TestHTTP3Limits_SocketBufferPastTheLimit(t *testing.T) {
	limit := kernelLimit(t, "rmem_max")
	probe, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(probe)
	if err := unix.SetsockoptInt(probe, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, limit+4096); err != nil {
		t.Skipf("this process may not ask past the kernel's limit: %v", err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	size := limit + 64<<10
	if got := socketBuffer(fd, unix.SO_RCVBUF, unix.SO_RCVBUFFORCE, size); got != 2*size {
		t.Errorf("a receive buffer of %d bytes, past the kernel's limit of %d: the socket has %d, want %d", size, limit, got, 2*size)
	}
}

// A listener whose sockets got less than was asked for says so once, in a
// startup warning that names the listener, both sizes and what to do; one
// whose sockets have what was asked for says nothing.
func TestHTTP3Limits_SocketBufferWarning(t *testing.T) {
	if w := quicBufferWarning("127.0.0.1:443", 4<<20, 2*4<<20); w != "" {
		t.Errorf("sockets that have what was asked for: warning %q", w)
	}
	if w := quicBufferWarning("127.0.0.1:443", 4<<20, 2*8<<20); w != "" {
		t.Errorf("sockets that have more than was asked for: warning %q", w)
	}
	w := quicBufferWarning("127.0.0.1:443", 4<<20, 2*212992)
	for _, part := range []string{"127.0.0.1:443", "208 KiB", "4096 KiB", "server.http3.socket_buffer", "net.core.rmem_max", "CAP_NET_ADMIN"} {
		if !strings.Contains(w, part) {
			t.Errorf("the warning %q does not name %q", w, part)
		}
	}
	if w := quicBufferWarning("[::]:8443", 4<<20, 2*4<<20-1); w == "" {
		t.Error("a socket one byte short of what was asked for: no warning")
	}

	// At a bind: the kernel, stood in for, grants each socket less than the
	// one before; the warning names the smallest, once for the listener.
	errLog := filepath.Join(t.TempDir(), "error.log")
	if err := logging.Init("warning", "", errLog); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("warning", "", "") })
	grants := 0
	quicSocketBuffer = func(fd, opt, force, size int) int {
		if opt != unix.SO_RCVBUF {
			return 2 * size
		}
		grants++
		return 2 * (300<<10 - grants<<10) // 299 KiB, then 298 KiB, ...
	}
	t.Cleanup(func() { quicSocketBuffer = socketBuffer })
	useHTTP3Limits(t, config.HTTP3Config{SocketBuffer: "2MB"})
	addr, g, _ := startH3Loops(t, h3RawBackend)
	logged := func() string {
		b, err := os.ReadFile(errLog)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	n := len(g.h3loops.socks)
	out := logged()
	if strings.Count(out, "server.http3.socket_buffer") != 1 {
		t.Fatalf("a listener whose %d sockets got less than asked: the log has %q, want one warning", n, out)
	}
	_, port, _ := net.SplitHostPort(addr)
	for _, part := range []string{"[WARN]", ":" + port, strconv.Itoa(300-n) + " KiB", "2048 KiB"} {
		if !strings.Contains(out, part) {
			t.Errorf("the warning %q does not name %q (the smallest of the %d sockets, and what was asked for)", out, part, n)
		}
	}
	// Sockets that have what was asked for: nothing more is logged.
	quicSocketBuffer = func(fd, opt, force, size int) int { return 2 * size }
	startH3Loops(t, h3RawBackend)
	if again := logged(); strings.Count(again, "server.http3.socket_buffer") != 1 {
		t.Errorf("a listener whose sockets have what was asked for logged a warning too: %q", strings.TrimPrefix(again, out))
	}
}
