//go:build linux

package httpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nvquic "github.com/nvelox/ngx/quic"

	"unsafe"

	"github.com/nvelox/ngx"
	"github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

// QUIC on the event loops, without HTTP/3: a server whose protocol sends
// back what arrives on a stream, and quic-go as the client.

const echoALPN = "nvelox-echo-test"

// echoApp answers every bidirectional stream with what the client sends on
// it.
type echoApp struct {
	opened, closed atomic.Int64
	mu             sync.Mutex
	locals         []string // the local address each connection's client sent to
	movedTo        []string // the address each move of a client took it to
}

type echoConn struct {
	app     *echoApp
	c       *qconn
	pending map[uint64][]byte // received, not yet taken by the stream
	fin     map[uint64]bool   // the client's end arrived
}

func (a *echoApp) open(c *qconn) qconnHandler {
	a.opened.Add(1)
	a.mu.Lock()
	a.locals = append(a.locals, c.local.String())
	a.mu.Unlock()
	return &echoConn{app: a, c: c, pending: map[uint64][]byte{}, fin: map[uint64]bool{}}
}

// echoPanic, sent on a stream, makes the echo server's code panic.
const echoPanic = "panic in the application, please"

func (e *echoConn) streamData(id uint64, data []byte, fin bool) {
	if string(data) == echoPanic {
		panic("test: the application's code failed")
	}
	e.c.q.StreamConsumed(id, len(data))
	if id&2 != 0 {
		return // unidirectional: nothing to answer on
	}
	e.pending[id] = append(e.pending[id], data...)
	if fin {
		e.fin[id] = true
	}
	e.push(id)
}

func (e *echoConn) push(id uint64) {
	p := e.pending[id]
	n := e.c.q.StreamWrite(id, p, e.fin[id])
	if n == len(p) {
		delete(e.pending, id)
		if e.fin[id] {
			delete(e.fin, id)
		}
	} else {
		e.pending[id] = p[n:]
	}
	e.c.wake()
}

func (e *echoConn) inputDone() {}
func (e *echoConn) moved() {
	e.app.mu.Lock()
	e.app.movedTo = append(e.app.movedTo, e.c.peer.String())
	e.app.mu.Unlock()
}
func (e *echoConn) streamWritable(id uint64) { e.push(id) }
func (e *echoConn) streamReset(id, _ uint64) { delete(e.pending, id); delete(e.fin, id) }
func (e *echoConn) streamStop(id, _ uint64)  { delete(e.pending, id); delete(e.fin, id) }
func (e *echoConn) closed(error)             { e.app.closed.Add(1) }

// startEcho starts an echo server on addr and returns it with its port.
func startEcho(t *testing.T, addr string, idle time.Duration) (*quicServer, *echoApp, int) {
	return startEchoTLS(t, addr, idle, nil)
}

// startEchoTLS is startEcho with a say in the server's TLS configuration.
func startEchoTLS(t *testing.T, addr string, idle time.Duration, tweak func(*tls.Config)) (*quicServer, *echoApp, int) {
	t.Helper()
	pki := newCAPKI(t, "quic-loop-ca")
	cert, err := tls.LoadX509KeyPair(pki.srvCert, pki.srvKey)
	if err != nil {
		t.Fatal(err)
	}
	app := &echoApp{}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{echoALPN}, MinVersion: tls.VersionTLS13}
	if tweak != nil {
		tweak(tlsCfg)
	}
	qs, err := bindQUIC(addr, nvquic.Config{
		TLS: tlsCfg,
		Params: nvquic.Params{MaxIdleTimeout: idle, InitialMaxData: 1 << 20, InitialMaxStreamDataBidiRemote: 256 << 10,
			InitialMaxStreamDataUni: 256 << 10, InitialMaxStreamsBidi: 100, InitialMaxStreamsUni: 3,
			AckDelayExponent: 3, MaxAckDelay: 25 * time.Millisecond, ActiveConnectionIDLimit: 4},
	}, app)
	if err != nil {
		t.Fatal(err)
	}
	qs.serve()
	t.Cleanup(func() { qs.stop(0, "") })
	return qs, app, qs.local.Port
}

var echoClientTLS = &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{echoALPN}}

// ipv6Loopback reports whether this host has an IPv6 loopback address to
// bind and to dial. A container often has none; a server bound to every
// address has IPv4 sockets there, and the tests leave their IPv6 part out.
func ipv6Loopback() bool {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// echoOnce sends payload on a new stream of conn and checks that it comes
// back.
func echoOnce(ctx context.Context, conn *quic.Conn, payload []byte) error {
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if by, ok := ctx.Deadline(); ok {
		str.SetDeadline(by)
	}
	go func() {
		str.Write(payload)
		str.Close()
	}()
	got, err := io.ReadAll(str)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func waitCount(t *testing.T, what string, get func() int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for get() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d, want %d", what, get(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Connections from many clients, each with several streams at once and
// more data than a stream's window: everything comes back, and when the
// clients have closed, the server holds no connection.
func TestQUICLoop_Echo(t *testing.T) {
	qs, app, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	const clients, streams = 12, 6
	payload := make([]byte, 700<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	var wg sync.WaitGroup
	errs := make(chan error, clients*streams)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := quic.DialAddr(ctx, addr, echoClientTLS, nil)
			if err != nil {
				errs <- err
				return
			}
			defer conn.CloseWithError(0, "")
			var sw sync.WaitGroup
			for j := 0; j < streams; j++ {
				sw.Add(1)
				go func(j int) {
					defer sw.Done()
					if err := echoOnce(ctx, conn, payload[:len(payload)-i*1000-j]); err != nil {
						errs <- err
					}
				}(j)
			}
			sw.Wait()
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("echo: %v", err)
	}
	if n := app.opened.Load(); n != clients {
		t.Errorf("%d connections opened, want %d", n, clients)
	}
	if n := qs.retries.Load(); n != 0 {
		t.Errorf("%d clients were sent back to prove their address, with %d handshakes at most running", n, clients)
	}
	waitCount(t, "connections still open after the clients closed", qs.conns.Load, 0)
	waitCount(t, "connections the application was told are over", app.closed.Load, clients)
}

func itoa(n int) string {
	var b [8]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		if n /= 10; n == 0 {
			return string(b[i:])
		}
	}
}

// unknownVersion returns a datagram of size bytes that starts like a first
// flight in a version nobody speaks.
func unknownVersion(dcid, scid []byte, size int) []byte {
	pkt := []byte{0xc3}
	pkt = binary.BigEndian.AppendUint32(pkt, 0x1a2a3a4a)
	pkt = append(append(pkt, byte(len(dcid))), dcid...)
	pkt = append(append(pkt, byte(len(scid))), scid...)
	if size > len(pkt) {
		pkt = append(pkt, make([]byte, size-len(pkt))...)
	}
	return pkt
}

// A server bound to every address answers from the address its client
// spoke to: a client drops what comes from another one. A client at
// 127.0.0.1 speaks to 127.0.0.2, where an answer left to the kernel's
// choice would come from 127.0.0.1. Both kinds of answer are looked at: a
// connection's packets, and the one that belongs to no connection.
func TestQUICLoop_WildcardAnswersFromTheAddressSpokenTo(t *testing.T) {
	old := quicHandshakeTimeout
	quicHandshakeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { quicHandshakeTimeout = old })
	for _, bind := range []string{":0", "0.0.0.0:0"} {
		_, _, port := startEcho(t, bind, 30*time.Second)
		spokenTo := net.IPv4(127, 0, 0, 2)
		to := &net.UDPAddr{IP: spokenTo, Port: port}
		buf := make([]byte, 2048)
		for what, dgram := range map[string][]byte{
			"a connection's first answer":      firstFlight(t),
			"the answer to an unknown version": unknownVersion([]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9}, 1200),
		} {
			cl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			cl.WriteToUDP(dgram, to)
			cl.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, from, err := cl.ReadFromUDP(buf)
			cl.Close()
			if err != nil {
				t.Errorf("bound to %s, %s: %v", bind, what, err)
				continue
			}
			if !from.IP.Equal(spokenTo) {
				t.Errorf("bound to %s, %s came from %s, want %s, the address the client spoke to", bind, what, from.IP, spokenTo)
			}
		}
	}
}

// On a host without IPv6 a server bound to every address has an IPv4
// socket, where the kernel names the local address in another message than
// on a socket for both families (which is what the tests above get). That
// message, from a real socket: the address is read from it, and what is
// made from it sends the answer from that address.
func TestReplyControl_IPv4Socket(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	rc, err := srv.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1) })
	if serr != nil {
		t.Fatal(serr)
	}
	cl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	spokenTo := net.IPv4(127, 0, 0, 2)
	cl.WriteToUDP([]byte("to .2"), &net.UDPAddr{IP: spokenTo, Port: srv.LocalAddr().(*net.UDPAddr).Port})

	buf, oob := make([]byte, 64), make([]byte, 128)
	srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, oobn, _, from, err := srv.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	var reply [quicCtlSize]byte
	n, local := replyControl(&reply, oob[:oobn])
	if n == 0 || local.String() != "127.0.0.2" {
		t.Fatalf("the datagram's local address: %v (control message of %d bytes), want 127.0.0.2", local, n)
	}
	source := func(ctl []byte) net.IP {
		t.Helper()
		if _, _, err := srv.WriteMsgUDP([]byte("answer"), ctl, from); err != nil {
			t.Fatal(err)
		}
		cl.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, src, err := cl.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return src.IP
	}
	if src := source(reply[:n]); !src.Equal(spokenTo) {
		t.Errorf("the answer came from %s, want %s", src, spokenTo)
	}
	// Without the message the kernel picks another address: the test can
	// tell the two apart.
	if src := source(nil); src.Equal(spokenTo) {
		t.Errorf("an answer without the control message also came from %s: this test proves nothing here", src)
	}
}

// A first packet in a datagram shorter than a first flight is dropped: answering it would send a stranger more than it sent. The same
// packet at full size opens a connection.
func TestQUICLoop_ShortFirstPacketDropped(t *testing.T) {
	old := quicHandshakeTimeout
	quicHandshakeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { quicHandshakeTimeout = old })
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// An Initial packet's header (version 1, an 8-byte destination ID, no
	// token) with a body of size bytes that nobody can open.
	initial := func(size int) []byte {
		pkt := []byte{0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0}
		body := size - len(pkt) - 2
		pkt = append(pkt, 0x40|byte(body>>8), byte(body))
		return append(pkt, make([]byte, body)...)
	}
	c.Write(initial(600))
	time.Sleep(150 * time.Millisecond)
	if n := qs.conns.Load(); n != 0 {
		t.Fatalf("a first packet in a 600-byte datagram opened %d connection", n)
	}
	c.Write(initial(1200))
	waitCount(t, "connections after the same packet at full size", qs.conns.Load, 1)
	waitCount(t, "connections once that handshake was given up", qs.conns.Load, 0)
}

// A server bound to every address serves IPv4 and IPv6 clients on one
// socket per loop and knows which of its addresses each spoke to.
func TestQUICLoop_WildcardKnowsTheAddressSpokenTo(t *testing.T) {
	every := []string{"127.0.0.1", "127.0.0.2", "127.9.8.7", "::1"}
	if !ipv6Loopback() {
		every = every[:3]
	}
	for bind, want := range map[string][]string{
		":0":        every,
		"0.0.0.0:0": {"127.0.0.1", "127.0.0.2"},
	} {
		_, app, port := startEcho(t, bind, 30*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		for _, host := range want {
			conn, err := quic.DialAddr(ctx, net.JoinHostPort(host, itoa(port)), echoClientTLS, nil)
			if err != nil {
				t.Fatalf("bound to %s, %s: %v", bind, host, err)
			}
			if err := echoOnce(ctx, conn, []byte("which address did I speak to")); err != nil {
				t.Errorf("bound to %s, %s: %v", bind, host, err)
			}
			conn.CloseWithError(0, "")
		}
		cancel()
		app.mu.Lock()
		got := append([]string(nil), app.locals...)
		app.mu.Unlock()
		if len(got) != len(want) {
			t.Fatalf("bound to %s: local addresses seen: %v, want %v", bind, got, want)
		}
		for i, host := range want {
			if got[i] != host {
				t.Errorf("bound to %s, connection %d: the server took its local address for %s, want %s", bind, i, got[i], host)
			}
		}
	}
}

// A first flight in a version the server does not speak is answered with
// the one it does, the connection IDs swapped; a datagram too short to be a
// first flight is not answered at all.
func TestQUICLoop_VersionNegotiation(t *testing.T) {
	_, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dcid, scid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0xa, 0xb, 0xc}
	short, pkt := unknownVersion(dcid, scid, 0), unknownVersion(dcid, scid, 1200)

	c.Write(short)
	c.Write(pkt)
	buf := make([]byte, 2048)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer to a first flight in an unknown version: %v", err)
	}
	got := buf[:n]
	want := []byte{0, 0, 0, 0}
	want = append(append(want, byte(len(scid))), scid...)
	want = append(append(want, byte(len(dcid))), dcid...)
	want = binary.BigEndian.AppendUint32(want, 1)
	if len(got) < 1 || got[0]&0x80 == 0 || !bytes.Equal(got[1:], want) {
		t.Errorf("answer % x, want a long header with % x", got, want)
	}
	// One answer only: none to the short datagram.
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c.Read(buf); err == nil {
		t.Errorf("a second answer (% x): the short datagram was answered too", buf[:n])
	}
}

// A client that starts a handshake and says nothing more: its state is
// dropped when the time a handshake may take is over.
func TestQUICLoop_HandshakeGivenUp(t *testing.T) {
	old := quicHandshakeTimeout
	quicHandshakeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { quicHandshakeTimeout = old })
	qs, app, port := startEcho(t, "127.0.0.1:0", 30*time.Second)

	// quic-go's first datagram, taken off the wire and sent on its own.
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(firstFlight(t))

	waitCount(t, "connections after a client's first flight", qs.conns.Load, 1)
	waitCount(t, "connections once the handshake was given up", qs.conns.Load, 0)
	if n := app.opened.Load(); n != 0 {
		t.Errorf("the application was told of %d connections: the handshake never completed", n)
	}
}

// firstFlight returns the first datagram a quic-go client sends.
func firstFlight(t *testing.T) []byte {
	t.Helper()
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go quic.DialAddr(ctx, sink.LocalAddr().String(), echoClientTLS, nil)
	first := make([]byte, 2048)
	sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := sink.ReadFrom(first)
	if err != nil {
		t.Fatal(err)
	}
	return first[:n]
}

// No more handshakes run at once on a loop than its limit: the first
// packets of further clients are dropped, and a client that comes when
// there is room again is served.
func TestQUICLoop_HandshakeLimit(t *testing.T) {
	oldMax, oldTO := quicMaxHandshakes, quicHandshakeTimeout
	quicMaxHandshakes, quicHandshakeTimeout = 2, time.Second
	t.Cleanup(func() { quicMaxHandshakes, quicHandshakeTimeout = oldMax, oldTO })
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	// One client socket: all its datagrams reach the same loop.
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 5; i++ {
		c.Write(firstFlight(t)) // five clients' first packets, each its own connection
	}
	waitCount(t, "handshakes running", qs.conns.Load, 2)
	time.Sleep(100 * time.Millisecond)
	if n := qs.conns.Load(); n != 2 {
		t.Fatalf("%d handshakes run at once, the limit is 2", n)
	}
	waitCount(t, "handshakes once they were given up", qs.conns.Load, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", itoa(port)), echoClientTLS, nil)
	if err != nil {
		t.Fatalf("a client after the limit was reached: %v", err)
	}
	defer conn.CloseWithError(0, "")
	if err := echoOnce(ctx, conn, []byte("room again")); err != nil {
		t.Error(err)
	}
}

// A failure in the code that serves a connection ends that connection
// only: the loop goes on, the other connections with it, and nothing of
// the failed one is left on the books.
func TestQUICLoop_PanicEndsOneConnection(t *testing.T) {
	qs, app, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	// Several bystanders, so that some share the failing one's loop.
	var others []*quic.Conn
	for i := 0; i < 6; i++ {
		conn, err := quic.DialAddr(ctx, addr, echoClientTLS, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseWithError(0, "")
		if err := echoOnce(ctx, conn, []byte("before")); err != nil {
			t.Fatal(err)
		}
		others = append(others, conn)
	}
	bad, err := quic.DialAddr(ctx, addr, echoClientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.CloseWithError(0, "")
	before := loopPanics.Load()
	str, err := bad.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	str.Write([]byte(echoPanic))
	waitCount(t, "connections after one failed", qs.conns.Load, int64(len(others)))
	if got := loopPanics.Load() - before; got != 1 {
		t.Errorf("%d panics recorded, want 1", got)
	}
	if n := app.closed.Load(); n != 1 {
		t.Errorf("the application was told of %d connections ending, want the failed one", n)
	}
	for i, conn := range others {
		if err := echoOnce(ctx, conn, []byte("after")); err != nil {
			t.Errorf("bystander %d after the failure: %v", i, err)
		}
	}
}

// rovingConn is a client's UDP socket whose datagrams can leave from
// another one: they then come from another port, as when a NAT maps the
// client's flow anew. What the server sends to the socket in use reaches
// the client; what it sends to one the client has left is lost, as it
// would be, and so is what it sends to a spy's.
type rovingConn struct {
	net.PacketConn // where the client is at first

	mu       sync.Mutex
	now      net.PacketConn   // where its datagrams leave from
	spies    []net.PacketConn // when set: each datagram leaves from one of them first, a copy, in turn
	turn     int
	named    []byte                 // the connection ID of the server's that the client's 1-RTT packets name
	first    []byte                 // the one its first 1-RTT packet named
	sent     map[net.PacketConn]int // datagrams sent from each socket
	got      map[net.PacketConn][]int
	socks    []net.PacketConn
	deadline time.Time
	kick     chan struct{}
	in       chan rovingDatagram
	// holding: so many of the next datagrams are kept back instead of
	// sent (held), for the test to send later; everywhere: what the server
	// sends to any of the sockets reaches the client.
	holding    int
	held       [][]byte
	everywhere bool
}

type rovingDatagram struct {
	b    []byte
	from net.Addr
}

func newRovingConn(t *testing.T) *rovingConn {
	t.Helper()
	c := &rovingConn{sent: map[net.PacketConn]int{}, got: map[net.PacketConn][]int{},
		kick: make(chan struct{}, 1), in: make(chan rovingDatagram, 4096)}
	c.PacketConn = c.open(t, "127.0.0.1")
	c.now = c.PacketConn
	t.Cleanup(func() { c.Close() })
	return c
}

// open opens a socket at ip and has what arrives on it recorded, and
// passed to the client while it is the socket in use.
func (c *rovingConn) open(t *testing.T, ip string) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.socks = append(c.socks, pc)
	c.mu.Unlock()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			c.mu.Lock()
			c.got[pc] = append(c.got[pc], n)
			live := c.now == pc || c.everywhere
			c.mu.Unlock()
			if live {
				select {
				case c.in <- rovingDatagram{append([]byte(nil), buf[:n]...), from}:
				default:
				}
			}
		}
	}()
	return pc
}

// move takes the client to a new address, which it returns: another port
// of 127.0.0.1.
func (c *rovingConn) move(t *testing.T) net.PacketConn { return c.moveTo(t, "127.0.0.1") }

// moveTo takes the client to a new address at ip, which it returns.
func (c *rovingConn) moveTo(t *testing.T, ip string) net.PacketConn {
	pc := c.open(t, ip)
	c.mu.Lock()
	c.now = pc
	c.mu.Unlock()
	return pc
}

// copies has each of the client's datagrams sent from a third party's
// address too, ahead of the client's own; it returns that address's
// socket. Called again, it adds an address: the copies then come from each
// in turn.
func (c *rovingConn) copies(t *testing.T) net.PacketConn {
	pc := c.open(t, "127.0.0.1")
	c.mu.Lock()
	c.spies = append(c.spies, pc)
	c.mu.Unlock()
	return pc
}

// serverCID returns the connection ID of the server's that the client's
// last 1-RTT packet named, as anyone on the way reads it off the packet,
// and the one its first 1-RTT packet named; nil before the client has sent
// one.
func (c *rovingConn) serverCID() (now, first []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.named...), append([]byte(nil), c.first...)
}

// arrived returns the sizes of the datagrams the server sent to pc.
func (c *rovingConn) arrived(pc net.PacketConn) []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.got[pc]...)
}

func (c *rovingConn) left(pc net.PacketConn) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent[pc]
}

// hold keeps the client's next n datagrams back: to the server they are
// packets still on their way.
func (c *rovingConn) hold(n int) {
	c.mu.Lock()
	c.holding = n
	c.mu.Unlock()
}

// waitHeld waits for the n datagrams of hold and returns them.
func (c *rovingConn) waitHeld(t *testing.T, n int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.mu.Lock()
		held := c.held
		c.mu.Unlock()
		if len(held) >= n {
			return held
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d datagrams were kept back, want %d", len(held), n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (c *rovingConn) WriteTo(p []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	if c.holding > 0 {
		c.holding--
		c.held = append(c.held, append([]byte(nil), p...))
		c.mu.Unlock()
		return len(p), nil
	}
	now := c.now
	var spy net.PacketConn
	if len(c.spies) > 0 {
		spy = c.spies[c.turn%len(c.spies)]
		c.turn++
		c.sent[spy]++
	}
	c.sent[now]++
	// The first 1-RTT packet often shares its datagram with a packet of
	// the handshake, which it then follows.
	for d := p; len(d) > 0; {
		h, err := nvquic.ParseHeader(d, nvquic.CIDLen)
		if err != nil {
			break
		}
		if h.Type == nvquic.PacketShort {
			c.named = append(c.named[:0], h.DCID...)
			if c.first == nil {
				c.first = append([]byte(nil), h.DCID...)
			}
			break
		}
		d = d[h.End:]
	}
	c.mu.Unlock()
	if spy != nil {
		// The copy is well ahead, whichever of the server's sockets the
		// two reach.
		spy.WriteTo(p, a)
		time.Sleep(time.Millisecond)
	}
	return now.WriteTo(p, a)
}

func (c *rovingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		by := c.deadline
		c.mu.Unlock()
		var timeout <-chan time.Time
		if !by.IsZero() {
			t := time.NewTimer(time.Until(by))
			defer t.Stop()
			timeout = t.C
		}
		select {
		case d := <-c.in:
			return copy(p, d.b), d.from, nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.kick:
		}
	}
}

func (c *rovingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return nil
}

func (c *rovingConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *rovingConn) Close() error {
	c.mu.Lock()
	socks := c.socks
	c.socks = nil
	c.mu.Unlock()
	for _, pc := range socks {
		pc.Close()
	}
	return c.SetReadDeadline(time.Now())
}

// dialRoving connects a client that can move to the echo server at port.
func dialRoving(t *testing.T, ctx context.Context, port int) (*rovingConn, *quic.Conn) {
	t.Helper()
	pc := newRovingConn(t)
	raddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	conn, err := quic.Dial(ctx, pc, raddr, echoClientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	return pc, conn
}

// A client whose address changes under it, as when a NAT maps its flow
// anew, is followed. Its packets are served from the first that comes from
// the new address, where it is sent a challenge; once it has answered,
// the connection's datagrams go there, and what the server had sent to the
// address the client left is sent again. Move after move: the kernel hands
// the datagrams of some of the new addresses to another loop's socket,
// which passes them on to the connection's loop.
func TestQUICLoop_ClientMoves(t *testing.T) {
	qs, app, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pc, conn := dialRoving(t, ctx, port)
	if err := echoOnce(ctx, conn, []byte("from the first address")); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 300<<10)
	for i := range big {
		big[i] = byte(i * 13)
	}
	const moves = 16
	var want []string
	for i := 1; i <= moves; i++ {
		before := pc.now
		at := pc.move(t)
		want = append(want, at.LocalAddr().String())
		payload := []byte("from address " + itoa(i))
		if i%4 == 1 {
			payload = big // more than a few datagrams each way
		}
		if err := echoOnce(ctx, conn, payload); err != nil {
			t.Fatalf("move %d: %v", i, err)
		}
		waitCount(t, "moves of the connection after the client's move "+itoa(i), qs.moves.Load, int64(i))
		// From here on nothing goes to the address the client left.
		time.Sleep(20 * time.Millisecond)
		n := len(pc.arrived(before))
		if err := echoOnce(ctx, conn, payload); err != nil {
			t.Fatalf("after move %d: %v", i, err)
		}
		if m := len(pc.arrived(before)); m != n {
			t.Errorf("after move %d the server sent %d more datagrams to the address the client left", i, m-n)
		}
	}
	app.mu.Lock()
	got := append([]string(nil), app.movedTo...)
	app.mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("the application was told of %d moves (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("move %d: the application was told the client is at %s, want %s", i+1, got[i], want[i])
		}
	}
	if n := app.opened.Load(); n != 1 {
		t.Errorf("%d connections opened, want the one that moved", n)
	}
	if len(qs.socks) > 1 && qs.passed.Load() == 0 {
		t.Errorf("%d moves and no datagram reached another loop's socket (%d loops)", moves, len(qs.socks))
	}
	if cerr := context.Cause(conn.Context()); cerr != nil {
		t.Errorf("the client's connection ended: %v", cerr)
	}
}

// Copies of a client's packets that come from another address, ahead of
// the client's own, as a third party on the way can send them, move no
// connection. Each is served (it is the client's packet), the answer goes
// to the client, and the address the copies came from gets challenges
// only, few of them: it cannot answer one.
func TestQUICLoop_CopiedPacketsMoveNothing(t *testing.T) {
	qs, app, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pc, conn := dialRoving(t, ctx, port)
	if err := echoOnce(ctx, conn, []byte("before")); err != nil {
		t.Fatal(err)
	}
	spy := pc.copies(t)
	payload := make([]byte, 20<<10)
	began := time.Now()
	for i := 0; time.Since(began) < 1500*time.Millisecond || i < 20; i++ {
		if err := echoOnce(ctx, conn, payload); err != nil {
			t.Fatalf("echo %d with copies on the way: %v", i, err)
		}
	}
	if n := qs.moves.Load(); n != 0 {
		t.Errorf("the connection moved %d times, to an address that only copies came from", n)
	}
	app.mu.Lock()
	told := len(app.movedTo)
	app.mu.Unlock()
	if told != 0 {
		t.Errorf("the application was told of %d moves", told)
	}
	copies, probes := pc.left(spy), pc.arrived(spy)
	if copies < 40 {
		t.Fatalf("only %d copies were sent: the test did not do its work", copies)
	}
	if len(probes) == 0 {
		t.Error("the address the copies came from was never challenged")
	}
	// A challenge when the address shows up, then one each time the answer
	// is overdue, twice as long each time (and never longer than a couple
	// of seconds).
	if most := 8 + int(time.Since(began)/time.Second); len(probes) > most {
		t.Errorf("the server sent %d datagrams to the address of %d copies, want %d at most", len(probes), copies, most)
	}
	for _, n := range probes {
		if n != 1200 {
			t.Errorf("a datagram of %d bytes went to the address the copies came from, want challenges of 1200 only (%v)", n, probes)
			break
		}
	}
	if cerr := context.Cause(conn.Context()); cerr != nil {
		t.Errorf("the client's connection ended: %v", cerr)
	}
}

// booked returns the connection IDs the server has on its books.
func booked(qs *quicServer) map[[nvquic.CIDLen]byte]bool {
	qs.ownersMu.RLock()
	defer qs.ownersMu.RUnlock()
	m := map[[nvquic.CIDLen]byte]bool{}
	for cid := range qs.owners {
		m[cid] = true
	}
	return m
}

func waitBooked(t *testing.T, qs *quicServer, what string, want int) {
	t.Helper()
	waitCount(t, what, func() int64 { return int64(len(booked(qs))) }, int64(want))
}

// newTransport returns a quic-go transport on a socket of its own: a
// client that dials through one uses connection IDs, and can move to
// another.
func newTransport(t *testing.T) (*quic.Transport, *net.UDPConn) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { tr.Close(); pc.Close() })
	return tr, pc
}

// namedConn is a client's socket that notes which of the client's
// connection IDs the server's 1-RTT packets name (a transport's connection
// IDs are four bytes long).
type namedConn struct {
	net.PacketConn
	mu    sync.Mutex
	names map[[4]byte]bool
}

func (c *namedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(p)
	if err == nil && n >= 5 && p[0]&0x80 == 0 {
		c.mu.Lock()
		c.names[[4]byte(p[1:5])] = true
		c.mu.Unlock()
	}
	return n, from, err
}

func (c *namedConn) named() map[[4]byte]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := map[[4]byte]bool{}
	for k := range c.names {
		m[k] = true
	}
	return m
}

// newNamedTransport is newTransport on a namedConn.
func newNamedTransport(t *testing.T) (*quic.Transport, *namedConn) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nc := &namedConn{PacketConn: pc, names: map[[4]byte]bool{}}
	tr := &quic.Transport{Conn: nc}
	t.Cleanup(func() { tr.Close(); pc.Close() })
	return tr, nc
}

// peerCIDs returns, for the server's one connection, how many of the
// client's connection IDs are to spare and how many are chosen for other
// addresses of the client.
func peerCIDs(t *testing.T, qs *quicServer) (spare, chosen int) {
	t.Helper()
	type counts struct{ conns, spare, chosen int }
	ch := make(chan counts, len(qs.socks))
	for _, s := range qs.socks {
		s.l.Post(func() {
			var n counts
			for c := s.head; c != nil; c = c.lnext {
				n.conns++
				n.spare, n.chosen = c.q.PeerCIDs()
			}
			ch <- n
		})
	}
	conns := 0
	for range qs.socks {
		n := <-ch
		if n.conns > 0 {
			conns += n.conns
			spare, chosen = n.spare, n.chosen
		}
	}
	if conns != 1 {
		t.Fatalf("the server has %d connections, want one", conns)
	}
	return spare, chosen
}

// A client that moves on purpose, to another network. It needs connection
// IDs it has not used yet: it is given three more when the handshake is
// complete. It tries the new path first, and is answered there (with a
// connection ID of its own that was not used before: the server holds
// four of the client's, so that one is to spare for each move); the
// connection stays where it is until the client switches, and then follows
// it. Move after move: three of them, which is as many paths as this
// client tries on one connection (it keeps the connection ID it took for
// each, and holds four).
func TestQUICLoop_ClientMovesOnPurpose(t *testing.T) {
	qs, app, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	raddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	tr, before := newNamedTransport(t)
	conn, err := tr.Dial(ctx, raddr, echoClientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if err := echoOnce(ctx, conn, []byte("from the first network")); err != nil {
		t.Fatal(err)
	}
	// The handshake's connection ID and three spare ones.
	waitBooked(t, qs, "connection IDs on the books after the handshake", 4)
	big := make([]byte, 300<<10)
	for i := range big {
		big[i] = byte(i * 11)
	}
	const moves = 3
	var want []string
	for i := 1; i <= moves; i++ {
		// What the server's packets named on the path the client is about
		// to leave. (Taken now: a packet of the client's that leaves from
		// there after the move has that address challenged, with the
		// connection ID in use by then.)
		there := before.named()
		ntr, pc := newNamedTransport(t)
		path, err := conn.AddPath(ntr)
		if err != nil {
			t.Fatalf("move %d: %v", i, err)
		}
		probe, stop := context.WithTimeout(ctx, 10*time.Second)
		err = path.Probe(probe)
		stop()
		if err != nil {
			t.Fatalf("move %d: the client's probe of its new path was not answered: %v", i, err)
		}
		// Trying a path moves nothing.
		if err := echoOnce(ctx, conn, []byte("still on the path before")); err != nil {
			t.Fatalf("move %d, before the switch: %v", i, err)
		}
		if n := qs.moves.Load(); n != int64(i-1) {
			t.Fatalf("move %d: the connection moved %d times before the client switched", i, n)
		}
		if err := path.Switch(); err != nil {
			t.Fatalf("move %d: switch: %v", i, err)
		}
		want = append(want, pc.PacketConn.LocalAddr().String())
		if err := echoOnce(ctx, conn, big); err != nil {
			t.Fatalf("after move %d: %v", i, err)
		}
		waitCount(t, "moves of the connection after the client's move "+itoa(i), qs.moves.Load, int64(i))
		if err := echoOnce(ctx, conn, []byte("from network "+itoa(i))); err != nil {
			t.Fatalf("after move %d: %v", i, err)
		}
		if n := len(booked(qs)); n > 4 {
			t.Errorf("after move %d the server has %d connection IDs on its books, want 4 at most", i, n)
		}
		// What the server sends to the new address names one connection
		// ID of the client's, and not one it named on the path before:
		// nobody on the way can tell that the two are one connection.
		here := pc.named()
		if len(here) != 1 {
			t.Errorf("after move %d the server's packets to the new address name %d of the client's connection IDs, want one", i, len(here))
		}
		for name := range here {
			if there[name] {
				t.Errorf("after move %d the server's packets name the connection ID % x, as on the path before", i, name)
			}
		}
		before = pc
	}
	// The connection IDs chosen for the paths are in use or given back:
	// none is still set aside.
	if _, chosen := peerCIDs(t, qs); chosen != 0 {
		t.Errorf("%d of the client's connection IDs are still set aside for an address", chosen)
	}
	app.mu.Lock()
	got := append([]string(nil), app.movedTo...)
	app.mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("the application was told of %d moves (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("move %d: the application was told the client is at %s, want %s", i+1, got[i], want[i])
		}
	}
	if cerr := context.Cause(conn.Context()); cerr != nil {
		t.Errorf("the client's connection ended: %v", cerr)
	}
	conn.CloseWithError(0, "")
	waitBooked(t, qs, "connection IDs on the books after the client closed", 0)
}

// A client tries two paths and moves to the second. The connection ID of
// the client's that was set aside for the first is given back to it (it
// was seen on that path and is not used anywhere else), and the client
// replaces it: the server has as many to spare as before.
func TestQUICLoop_PathTriedAndNotTaken(t *testing.T) {
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	raddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	tr, _ := newTransport(t)
	conn, err := tr.Dial(ctx, raddr, echoClientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if err := echoOnce(ctx, conn, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	waitBooked(t, qs, "connection IDs on the books after the handshake", 4)
	// The client holds four of its own with the server: one in use, three
	// to spare.
	waitCount(t, "connection IDs of the client's to spare", func() int64 { n, _ := peerCIDs(t, qs); return int64(n) }, 3)
	var paths [2]*quic.Path
	for i := range paths {
		ntr, _ := newTransport(t)
		if paths[i], err = conn.AddPath(ntr); err != nil {
			t.Fatal(err)
		}
		probe, stop := context.WithTimeout(ctx, 10*time.Second)
		err = paths[i].Probe(probe)
		stop()
		if err != nil {
			t.Fatalf("path %d: the client's probe was not answered: %v", i+1, err)
		}
	}
	if spare, chosen := peerCIDs(t, qs); spare != 1 || chosen != 2 {
		t.Fatalf("with two paths tried: %d to spare, %d set aside; want 1 and 2", spare, chosen)
	}
	if err := paths[1].Switch(); err != nil {
		t.Fatal(err)
	}
	if err := echoOnce(ctx, conn, []byte("from the second of the two")); err != nil {
		t.Fatal(err)
	}
	waitCount(t, "moves of the connection", qs.moves.Load, 1)
	// The one set aside for the path not taken was given back, and so was
	// the one in use before (the client's first, which it does not
	// replace): two to spare again once the client has sent the
	// replacement.
	deadline := time.Now().Add(10 * time.Second)
	for {
		spare, chosen := peerCIDs(t, qs)
		if spare == 2 && chosen == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the move: %d of the client's connection IDs to spare, %d set aside; want 2 and none", spare, chosen)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := echoOnce(ctx, conn, []byte("and after")); err != nil {
		t.Error(err)
	}
}

// sinkConn is a socket nothing leaves from.
type sinkConn struct{ net.PacketConn }

func (sinkConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

// A client gives a connection ID back (here: the one it had taken for a
// path that turned out dead). It is taken off the server's books, and the
// client is given a new one in its place.
func TestQUICLoop_ConnectionIDGivenBack(t *testing.T) {
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	raddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	tr, _ := newTransport(t)
	conn, err := tr.Dial(ctx, raddr, echoClientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if err := echoOnce(ctx, conn, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	waitBooked(t, qs, "connection IDs on the books after the handshake", 4)
	before := booked(qs)

	// A path whose packets never arrive: the probe fails, the client
	// closes the path and gives back the connection ID it took for it.
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dtr := &quic.Transport{Conn: sinkConn{dead}}
	defer func() { dtr.Close(); dead.Close() }()
	path, err := conn.AddPath(dtr)
	if err != nil {
		t.Fatal(err)
	}
	probe, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	err = path.Probe(probe)
	stop()
	if err == nil {
		t.Fatal("a probe whose packets go nowhere was answered")
	}
	if err := path.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		now := booked(qs)
		gone, added := 0, 0
		for cid := range before {
			if !now[cid] {
				gone++
			}
		}
		for cid := range now {
			if !before[cid] {
				added++
			}
		}
		if gone == 1 && added == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("of the server's connection IDs %d are gone and %d are new, want one given back and one in its place", gone, added)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := qs.moves.Load(); n != 0 {
		t.Errorf("the connection moved %d times", n)
	}
	if err := echoOnce(ctx, conn, []byte("after")); err != nil {
		t.Errorf("after the connection ID was given back: %v", err)
	}
}

// A datagram is never fragmented on its way out: every socket says so to
// the kernel, for the IP versions it speaks. QUIC forbids fragments, and a
// connection that finds out how large a datagram its path carries relies
// on it: a size that arrived in pieces would be taken for one the path
// carries.
func TestQUICLoop_SocketsNeverFragment(t *testing.T) {
	for _, tt := range []struct {
		bind   string
		v4, v6 bool
	}{{"127.0.0.1:0", true, false}, {"[::1]:0", false, true}, {":0", true, true}} {
		if tt.v6 && !ipv6Loopback() {
			// Nothing to bind, or IPv4 sockets for every address.
			if tt.v6 = false; !tt.v4 {
				continue
			}
		}
		qs, _, _ := startEcho(t, tt.bind, 30*time.Second)
		if len(qs.socks) == 0 {
			t.Fatalf("bound to %s: no socket", tt.bind)
		}
		for i, s := range qs.socks {
			if tt.v4 {
				if v, err := unix.GetsockoptInt(s.fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER); err != nil || v != unix.IP_PMTUDISC_DO {
					t.Errorf("bound to %s, socket %d: IP_MTU_DISCOVER is %d (%v), want %d: never a fragment", tt.bind, i, v, err, unix.IP_PMTUDISC_DO)
				}
			}
			if tt.v6 {
				if v, err := unix.GetsockoptInt(s.fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER); err != nil || v != unix.IPV6_PMTUDISC_DO {
					t.Errorf("bound to %s, socket %d: IPV6_MTU_DISCOVER is %d (%v), want %d: never a fragment", tt.bind, i, v, err, unix.IPV6_PMTUDISC_DO)
				}
			}
		}
	}
}

// What the QUIC connections of the process hold to send is bounded: by an
// eighth of the memory the process may use, set when a server binds. With
// a bound that small that eight clients reach it, which ask for much and
// take nothing, the connections hold little more than the bound together;
// and when the clients do read, everything arrives.
func TestQUICLoop_SendMemoryBound(t *testing.T) {
	// An eighth of the memory the process may use: the machine's, or the
	// lowest limit of its control groups; 64 MiB at the least.
	for _, tc := range []struct {
		total  int64
		limits []int64
		want   int64
	}{
		{32 << 30, nil, 4 << 30},
		{32 << 30, []int64{8 << 30, 2 << 30, 16 << 30}, 256 << 20},
		{32 << 30, []int64{64 << 30}, 4 << 30},
		{256 << 20, nil, 64 << 20},
		{32 << 30, []int64{100 << 20}, 64 << 20},
	} {
		if got := sendMemoryOf(tc.total, tc.limits); got != tc.want {
			t.Errorf("with %d bytes of memory and the limits %v the bound is %d, want %d", tc.total, tc.limits, got, tc.want)
		}
	}
	// This process: the limits found are those of its own control groups
	// (the test runs under one when it runs in the capped lane).
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var kb int64
		fmt.Sscanf(string(b), "MemTotal: %d kB", &kb)
		if got := machineMemory(); kb > 0 && (got < kb<<10*9/10 || got > kb<<10*11/10) {
			t.Errorf("the machine's memory is taken for %d bytes, /proc/meminfo says %d kB", got, kb)
		}
	}
	for _, l := range memoryLimits() {
		if l <= 0 {
			t.Errorf("a limit of %d bytes was read", l)
		}
	}
	_, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	limit := nvquic.SendMemoryLimit()
	if limit != quicSendMemory() || limit < 64<<20 || limit > machineMemory()/8 {
		t.Fatalf("the bound is %d after a server bound, want %d (an eighth of the memory, 64 MiB at least)", limit, quicSendMemory())
	}
	const bound, clients, size = 1 << 20, 8, 2 << 20
	base := nvquic.SendMemory()
	nvquic.SetSendMemory(base + bound)
	defer nvquic.SetSendMemory(limit)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	var streams []*quic.Stream
	start := make(chan struct{})
	for i := 0; i < clients; i++ {
		// A client that lets the server send a megabyte per stream at
		// once, and does not read.
		conn, err := quic.DialAddr(ctx, addr, echoClientTLS, &quic.Config{InitialStreamReceiveWindow: 1 << 20, InitialConnectionReceiveWindow: 2 << 20})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseWithError(0, "")
		str, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			<-start
			str.Write(payload)
			str.Close()
		}()
		streams = append(streams, str)
	}
	// They ask at the same time, when all of them are connected: what
	// one is sent is acknowledged within milliseconds here, and clients
	// that came one after the other would seldom hold much together.
	close(start)
	// The most the connections hold while nobody reads.
	most := int64(0)
	for until := time.Now().Add(1500 * time.Millisecond); time.Now().Before(until); time.Sleep(time.Millisecond) {
		most = max(most, nvquic.SendMemory()-base)
	}
	// Past the bound a connection takes 16 KiB at a time, and reports
	// what it holds in steps of 32 KiB.
	if slack := int64(clients * (48 << 10)); most > bound+slack {
		t.Errorf("the connections held %d bytes to send, with a bound of %d (and %d of slack)", most, bound, slack)
	}
	if most < bound/2 {
		t.Errorf("the connections held %d bytes at most: the bound of %d was never near, the test did not do its work", most, bound)
	}
	for i, str := range streams {
		str.SetReadDeadline(time.Now().Add(30 * time.Second))
		got, err := io.ReadAll(str)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("client %d read %d bytes, %v", i, len(got), err)
		}
	}
}

// Anyone can send a datagram that names a connection. From an address the
// connection does not send to, one that is not the client's (it does not
// open with the connection's keys) is not answered: the address gets no
// challenge.
func TestQUICLoop_ForgedDatagramNotAnswered(t *testing.T) {
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pc, conn := dialRoving(t, ctx, port)
	if err := echoOnce(ctx, conn, []byte("before")); err != nil {
		t.Fatal(err)
	}
	// The connection's ID, as anyone on the way reads it off a packet;
	// what follows it is made up. This client names another connection ID
	// soon after the handshake and gives the handshake's back: the one
	// taken is the one it names once that has happened (or the
	// handshake's, from a client that keeps it).
	_, first := pc.serverCID()
	if len(first) != nvquic.CIDLen {
		t.Fatalf("the client's first 1-RTT packet named the connection ID % x", first)
	}
	for i := 0; i < 200 && qs.owner([nvquic.CIDLen]byte(first)) != nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if err := echoOnce(ctx, conn, []byte("once more")); err != nil {
		t.Fatal(err)
	}
	cid, _ := pc.serverCID()
	if len(cid) != nvquic.CIDLen || qs.owner([nvquic.CIDLen]byte(cid)) == nil {
		t.Fatalf("the client's 1-RTT packets name the connection ID % x, which is not on the server's books", cid)
	}
	forged := make([]byte, 300)
	for i := range forged {
		forged[i] = byte(i*29 + 7)
	}
	forged[0] = 0x45 // a 1-RTT packet
	copy(forged[1:], cid)
	elsewhere, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer elsewhere.Close()
	server, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	for i := 0; i < 5; i++ {
		forged[len(forged)-1] = byte(i)
		elsewhere.WriteTo(forged, server)
	}
	elsewhere.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := elsewhere.ReadFrom(make([]byte, 2048)); err == nil {
		t.Errorf("the server sent %d bytes to the address a forged datagram came from", n)
	}
	if qs.owner([nvquic.CIDLen]byte(cid)) == nil {
		t.Errorf("the connection ID the forged datagrams named was given back meanwhile: they tested nothing")
	}
	if n := qs.moves.Load(); n != 0 {
		t.Errorf("the connection moved %d times", n)
	}
	if err := echoOnce(ctx, conn, []byte("after")); err != nil {
		t.Errorf("after the forged datagrams: %v", err)
	}
}

// Copies of a client's packets from many addresses at once: the server
// challenges quicPaths of them and leaves the others alone, for as long as
// packets keep coming from the ones it looks at.
func TestQUICLoop_FewAddressesChallengedAtATime(t *testing.T) {
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pc, conn := dialRoving(t, ctx, port)
	if err := echoOnce(ctx, conn, []byte("before")); err != nil {
		t.Fatal(err)
	}
	const addresses = 8
	var spies []net.PacketConn
	for i := 0; i < addresses; i++ {
		spies = append(spies, pc.copies(t))
	}
	payload := make([]byte, 20<<10)
	began := time.Now()
	for i := 0; time.Since(began) < time.Second || i < 10; i++ {
		if err := echoOnce(ctx, conn, payload); err != nil {
			t.Fatalf("echo %d with copies on the way: %v", i, err)
		}
	}
	if time.Since(began) > quicPathIdle-time.Second {
		t.Skipf("the echoes took %v: addresses may have given way to new ones by now", time.Since(began))
	}
	challenged := 0
	for _, spy := range spies {
		if pc.left(spy) < 5 {
			t.Fatalf("an address sent %d copies only: the test did not do its work", pc.left(spy))
		}
		if len(pc.arrived(spy)) > 0 {
			challenged++
		}
	}
	if challenged != quicPaths {
		t.Errorf("%d of %d addresses were challenged, want %d", challenged, addresses, quicPaths)
	}
	if n := qs.moves.Load(); n != 0 {
		t.Errorf("the connection moved %d times", n)
	}
}

// Packets of the client's that were overtaken on their way arrive from the
// address it has left, after the connection moved: they are served, and
// they move nothing back, even when the client can still be reached at
// that address and has proven it. Only the client's newest packet says
// where it is.
func TestQUICLoop_OvertakenPacketsMoveNothing(t *testing.T) {
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pc, conn := dialRoving(t, ctx, port)
	if err := echoOnce(ctx, conn, []byte("from the first address")); err != nil {
		t.Fatal(err)
	}
	// Two packets that stay on their way (the client sends what they held
	// again, in later ones).
	pc.hold(2)
	if err := echoOnce(ctx, conn, []byte("with two packets held up")); err != nil {
		t.Fatal(err)
	}
	late := pc.waitHeld(t, 2)
	home := pc.PacketConn
	server, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", itoa(port)))

	away := pc.move(t)
	if err := echoOnce(ctx, conn, []byte("from the second address")); err != nil {
		t.Fatal(err)
	}
	waitCount(t, "moves of the connection", qs.moves.Load, 1)

	// The first late packet arrives from the address the client left. That
	// address is challenged; the client, which still hears there, answers.
	pc.mu.Lock()
	pc.everywhere = true
	pc.mu.Unlock()
	sent, challenged := pc.left(away), len(pc.arrived(home))
	home.WriteTo(late[0], server)
	deadline := time.Now().Add(10 * time.Second)
	for len(pc.arrived(home)) == challenged || pc.left(away) == sent {
		if time.Now().After(deadline) {
			t.Fatalf("the address the late packet came from was sent %d datagrams, and the client answered with %d",
				len(pc.arrived(home))-challenged, pc.left(away)-sent)
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // the answer is with the server
	// The second one: from an address that has proven itself, with more
	// than probes in it, and overtaken long ago.
	home.WriteTo(late[1], server)
	time.Sleep(100 * time.Millisecond)
	if n := qs.moves.Load(); n != 1 {
		t.Errorf("the connection moved %d times: a packet that was overtaken took it back to the address the client left", n)
	}
	for _, n := range pc.arrived(home)[challenged:] {
		if n != 1200 {
			t.Errorf("a datagram of %d bytes went to the address the client left, want challenges only", n)
		}
	}
	pc.mu.Lock()
	pc.everywhere = false
	pc.mu.Unlock()
	if err := echoOnce(ctx, conn, []byte("still at the second address")); err != nil {
		t.Errorf("after the late packets: %v", err)
	}
}

// A client that goes silent: its connection ends when the idle time is
// over, and the application is told.
func TestQUICLoop_IdleConnectionEnds(t *testing.T) {
	qs, app, port := startEcho(t, "127.0.0.1:0", 400*time.Millisecond)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	pc := &silentConn{PacketConn: udp}
	raddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, pc, raddr, echoClientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := echoOnce(ctx, conn, []byte("still here")); err != nil {
		t.Fatal(err)
	}
	pc.silent.Store(true)
	waitCount(t, "connections once the client has been silent for the idle time", qs.conns.Load, 0)
	waitCount(t, "connections the application was told are over", app.closed.Load, 1)
}

// Stopping the server tells its clients and gives the port back.
func TestQUICLoop_Stop(t *testing.T) {
	qs, app, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", itoa(port)), echoClientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := echoOnce(ctx, conn, []byte("before the stop")); err != nil {
		t.Fatal(err)
	}
	qs.stop(0x77, "going away")
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the client was not told that the server stopped")
	}
	var appErr *quic.ApplicationError
	if err := context.Cause(conn.Context()); !asAppError(err, &appErr) || appErr.ErrorCode != 0x77 || !appErr.Remote {
		t.Errorf("the client's connection ended with %v, want the server's close with code 0x77", err)
	}
	if n := qs.conns.Load(); n != 0 || app.closed.Load() != 1 {
		t.Errorf("after the stop: %d connections, %d told over", n, app.closed.Load())
	}
	// The port is free again.
	pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatalf("the port is still held: %v", err)
	}
	pc.Close()
}

func asAppError(err error, target **quic.ApplicationError) bool {
	for err != nil {
		if e, ok := err.(*quic.ApplicationError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// With more handshakes running than the server takes on trust, a new
// client is sent back to prove its address and served when it returns:
// here every client is, over IPv4 and IPv6. The client checks what the
// server then says of the two connection IDs involved, so a handshake that
// completes was done right.
func TestQUICLoop_Retry(t *testing.T) {
	old := quicRetryAfter
	quicRetryAfter = 0
	t.Cleanup(func() { quicRetryAfter = old })
	qs, app, port := startEcho(t, ":0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hosts := []string{"127.0.0.1", "::1", "127.0.0.2", "127.0.0.1", "::1"}
	if !ipv6Loopback() {
		hosts = []string{"127.0.0.1", "127.0.0.2", "127.0.0.1"}
	}
	for _, host := range hosts {
		conn, err := quic.DialAddr(ctx, net.JoinHostPort(host, itoa(port)), echoClientTLS, nil)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if err := echoOnce(ctx, conn, bytes.Repeat([]byte("after a retry "), 20000)); err != nil {
			t.Errorf("%s: %v", host, err)
		}
		conn.CloseWithError(0, "")
	}
	// (A client's first flight can be two datagrams, each sent back.)
	if n := qs.retries.Load(); n < int64(len(hosts)) {
		t.Errorf("%d Retry packets for %d clients: not every client was sent back", n, len(hosts))
	}
	if n := app.opened.Load(); n != int64(len(hosts)) {
		t.Errorf("%d connections opened, want %d", n, len(hosts))
	}
	waitCount(t, "connections after the clients closed", qs.conns.Load, 0)
}

// While few handshakes run, clients are taken on trust; past the number
// the server allows, the next one's first packet is answered with a Retry
// packet and opens nothing.
func TestQUICLoop_RetryOnlyPastTheThreshold(t *testing.T) {
	oldAfter, oldTO := quicRetryAfter, quicHandshakeTimeout
	quicRetryAfter, quicHandshakeTimeout = 1, 2*time.Second // one unproven handshake per loop
	t.Cleanup(func() { quicRetryAfter, quicHandshakeTimeout = oldAfter, oldTO })
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 2048)
	// The first client: taken on trust, its handshake begins (the answer
	// is the server's first flight, an Initial packet).
	c.Write(firstFlight(t))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil || n < 1 || buf[0]&0xb0 != 0x80 {
		t.Fatalf("the first client's answer: %d bytes, first byte %#x, err %v; want an Initial packet", n, buf[0], err)
	}
	waitCount(t, "handshakes running", qs.conns.Load, 1)
	if qs.retries.Load() != 0 {
		t.Fatalf("the first client was sent back")
	}
	// The second, from the same address (the same loop): sent back.
	c.Write(firstFlight(t))
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("no Retry packet for the second client: %v", err)
		}
		if n > 0 && buf[0]&0xf0 == 0xf0 {
			if n >= 1200 {
				t.Errorf("the Retry packet is %d bytes: as long as what it answers", n)
			}
			break // a long header of type Retry
		}
	}
	if qs.retries.Load() != 1 || qs.conns.Load() != 1 {
		t.Errorf("%d clients sent back and %d connections, want 1 and 1", qs.retries.Load(), qs.conns.Load())
	}
}

// What counts toward the number is handshakes with an unproven client. A
// client whose handshake proved its address counts no more, however long
// its connection stays: with one unproven handshake allowed per loop and
// four connections kept open for every loop, no later client is sent back.
func TestQUICLoop_ProvenClientsDoNotCount(t *testing.T) {
	old := quicRetryAfter
	quicRetryAfter = 1
	t.Cleanup(func() { quicRetryAfter = old })
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	clients := 4 * len(qs.socks)
	for i := 0; i < clients; i++ {
		conn, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", itoa(port)), echoClientTLS, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseWithError(0, "")
		if err := echoOnce(ctx, conn, []byte("proven by now")); err != nil {
			t.Fatal(err)
		}
	}
	if n := qs.retries.Load(); n != 0 {
		t.Errorf("%d clients were sent back although no handshake was running when they came", n)
	}
	if n := qs.conns.Load(); n != int64(clients) {
		t.Errorf("%d connections open, want %d", n, clients)
	}
}

// A Retry's token is good for the client it was made for and nobody else,
// for the connection ID that client was told to use, and for a few
// seconds.
func TestQUICLoop_RetryToken(t *testing.T) {
	qs, _, _ := startEcho(t, "127.0.0.1:0", 30*time.Second)
	name := func(ip [4]byte, port uint16) *unix.RawSockaddrInet6 {
		var n unix.RawSockaddrInet6
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(&n))
		sa4.Family = unix.AF_INET
		sa4.Addr = ip
		sa4.Port = port<<8 | port>>8
		return &n
	}
	client := name([4]byte{192, 0, 2, 7}, 4433)
	odcid, cid := []byte{9, 8, 7, 6, 5, 4, 3, 2, 1}, []byte{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := []byte("twelve bytes")
	made := time.Now()
	token := qs.sealToken(nonce, odcid, cid, client, made)
	if got, ok := qs.openToken(token, cid, client, made.Add(time.Second)); !ok || !bytes.Equal(got, odcid) {
		t.Fatalf("the token does not open for its own client: %v, % x", ok, got)
	}
	flipped := append([]byte(nil), token...)
	flipped[len(flipped)-1] ^= 1
	for what, tc := range map[string]struct {
		token []byte
		cid   []byte
		name  *unix.RawSockaddrInet6
		at    time.Time
	}{
		"from another address":     {token, cid, name([4]byte{192, 0, 2, 8}, 4433), made},
		"from another port":        {token, cid, name([4]byte{192, 0, 2, 7}, 4434), made},
		"for another connection":   {token, []byte{1, 2, 3, 4, 5, 6, 7, 9}, client, made},
		"once it is too old":       {token, cid, client, made.Add(quicTokenAge + time.Second)},
		"from before it was made":  {token, cid, client, made.Add(-time.Second)},
		"with a byte changed":      {flipped, cid, client, made},
		"cut short":                {token[:len(token)-1], cid, client, made},
		"that is something else":   {[]byte("a token another server gave the client, long enough"), cid, client, made},
		"that is empty (no token)": {nil, cid, client, made},
	} {
		if _, ok := qs.openToken(tc.token, tc.cid, tc.name, tc.at); ok {
			t.Errorf("a token opens %s", what)
		}
	}
	// Another server's key opens nothing of this one's.
	other, _, _ := startEcho(t, "127.0.0.1:0", 30*time.Second)
	if _, ok := other.openToken(token, cid, client, made); ok {
		t.Error("a token opens on a server that did not make it")
	}
}

// A handshake's cryptography runs off the loops: while one takes 400 ms
// (a certificate that is slow to come, here), no loop is held up by it.
// Every loop is asked to run a small task again and again meanwhile, and
// none takes long to get to it.
func TestQUICLoop_HandshakeDoesNotHoldItsLoop(t *testing.T) {
	const slow = 400 * time.Millisecond
	qs, _, port := startEchoTLS(t, "127.0.0.1:0", 30*time.Second, func(c *tls.Config) {
		cert := c.Certificates[0]
		c.Certificates = nil
		c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			time.Sleep(slow)
			return &cert, nil
		}
	})
	var worst atomic.Int64
	stop := make(chan struct{})
	var probes sync.WaitGroup
	for _, sock := range qs.socks {
		probes.Add(1)
		go func(l *ngx.Loop) {
			defer probes.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				began := time.Now()
				done := make(chan struct{})
				l.Post(func() { close(done) })
				<-done
				if d := int64(time.Since(began)); d > worst.Load() {
					worst.Store(d)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}(sock.l)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	began := time.Now()
	conn, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", itoa(port)), echoClientTLS, nil)
	took := time.Since(began)
	close(stop)
	probes.Wait()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if took < slow {
		t.Fatalf("the handshake took %v: the slow certificate was not in it", took)
	}
	if w := time.Duration(worst.Load()); w > slow/2 {
		t.Errorf("a loop took %v to get to a task while a handshake of %v ran: the handshake held it up", w, took)
	}
	if err := echoOnce(ctx, conn, []byte("after a slow handshake")); err != nil {
		t.Error(err)
	}
}

// Stopping the server while handshakes run ends them: nothing waits for a
// client to finish one, and the port is free at once.
func TestQUICLoop_StopDuringHandshakes(t *testing.T) {
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 5; i++ {
		c.Write(firstFlight(t))
	}
	waitCount(t, "handshakes running", qs.conns.Load, 5)
	began := time.Now()
	qs.stop(0, "")
	if d := time.Since(began); d > 2*time.Second {
		t.Errorf("the stop took %v with five handshakes running", d)
	}
	if n := qs.conns.Load(); n != 0 {
		t.Errorf("%d connections after the stop", n)
	}
	pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatalf("the port is still held: %v", err)
	}
	pc.Close()
}

// A failure in the code that runs a handshake ends that handshake only.
func TestQUICLoop_PanicInHandshake(t *testing.T) {
	qs, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	var armed atomic.Bool
	probe := func(point string) {
		if point == "quic-handshake" && armed.CompareAndSwap(true, false) {
			panic("test: panic in a handshake")
		}
	}
	loopPanicProbe.Store(&probe)
	t.Cleanup(func() { loopPanicProbe.Store(nil) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	good, err := quic.DialAddr(ctx, addr, echoClientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer good.CloseWithError(0, "")
	// (Its own handshake is over on the server too once it is served.)
	if err := echoOnce(ctx, good, []byte("served")); err != nil {
		t.Fatal(err)
	}
	before := loopPanics.Load()
	armed.Store(true)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(firstFlight(t))
	deadline := time.Now().Add(5 * time.Second)
	for loopPanics.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("the handshake's code did not run")
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitCount(t, "connections after the failed handshake", qs.conns.Load, 1)
	if err := echoOnce(ctx, good, []byte("still served")); err != nil {
		t.Errorf("the other connection after the failure: %v", err)
	}
	// And the next client's handshake is as good as ever.
	next, err := quic.DialAddr(ctx, addr, echoClientTLS, nil)
	if err != nil {
		t.Fatalf("a client after the failure: %v", err)
	}
	next.CloseWithError(0, "")
}

// joiningRelay stands between one client and the server and joins a
// client's datagram that ends with a Handshake packet with the one that
// follows it, as a client may send them itself (and sometimes does): the
// packet that completes the handshake then shares a datagram with the
// client's first request. shared counts the datagrams that reached the
// server with a Handshake packet and a 1-RTT packet in them; big counts
// the client's 1-RTT packets of 600 bytes and more: the ones that carry
// its stream's data.
type joiningRelay struct {
	front, back *net.UDPConn
	shared, big atomic.Int64
}

// datagramShape reports what a client's datagram holds: whether it has a
// Handshake packet, and how long its 1-RTT packet is (0: none; a 1-RTT
// packet is always the last).
func datagramShape(d []byte) (handshake bool, short int) {
	for len(d) > 0 {
		if d[0]&0x80 == 0 {
			return handshake, len(d)
		}
		h, err := nvquic.ParseHeader(d, nvquic.CIDLen)
		if err != nil {
			return handshake, 0
		}
		handshake = handshake || h.Type == nvquic.PacketHandshake
		d = d[h.End:]
	}
	return handshake, 0
}

func newJoiningRelay(t *testing.T, server *net.UDPAddr) *joiningRelay {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp4", nil, server)
	if err != nil {
		t.Fatal(err)
	}
	r := &joiningRelay{front: front, back: back}
	t.Cleanup(func() { front.Close(); back.Close() })
	var client atomic.Pointer[net.UDPAddr]
	go func() { // client to server
		buf := make([]byte, 4096)
		for {
			front.SetReadDeadline(time.Time{})
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			client.Store(from)
			handshake, short := datagramShape(buf[:n])
			if short >= 600 {
				r.big.Add(1)
			}
			if handshake && short == 0 {
				// It ends with a Handshake packet: the next one is joined.
				front.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				if m, _, err := front.ReadFromUDP(buf[n:]); err == nil {
					if _, short = datagramShape(buf[n : n+m]); short >= 600 {
						r.big.Add(1)
					}
					n += m
				}
			}
			if short > 0 && handshake {
				r.shared.Add(1)
			}
			back.Write(buf[:n])
		}
	}()
	go func() { // server to client
		buf := make([]byte, 4096)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			if to := client.Load(); to != nil {
				front.WriteToUDP(buf[:n], to)
			}
		}
	}()
	return r
}

// The packet that completes a handshake can share its datagram with the
// client's first request. The handshake's goroutine stops at that packet,
// and the loop serves what follows it when it takes the connection over:
// the client's request is answered from that one datagram, and the client
// never has to send it again.
func TestQUICLoop_RequestInTheHandshakesLastDatagram(t *testing.T) {
	_, _, port := startEcho(t, "127.0.0.1:0", 30*time.Second)
	relay := newJoiningRelay(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, relay.front.LocalAddr().String(), echoClientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	body := bytes.Repeat([]byte("in the handshake's last datagram "), 21) // 693 bytes: one packet
	if err := echoOnce(ctx, conn, body); err != nil {
		t.Fatal(err)
	}
	if relay.shared.Load() == 0 {
		t.Fatal("no datagram held a Handshake packet and a 1-RTT packet: the case was not exercised")
	}
	if n := relay.big.Load(); n != 1 {
		t.Errorf("the client sent its request's data %d times, want once: what followed the handshake's last packet was not served", n)
	}
}
