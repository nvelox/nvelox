package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// echoHandler answers every bidirectional stream with what it received,
// once the stream's end has arrived, and records what else happens. It is
// used under the test server's lock.
type echoHandler struct {
	streams map[*Conn]map[uint64]*echoStream
	uni     map[uint64][]byte // what arrived on the client's unidirectional streams
	resets  map[uint64]uint64 // stream -> the code of its RESET_STREAM
	stops   map[uint64]uint64 // stream -> the code of its STOP_SENDING
}

type echoStream struct {
	in  []byte
	out []byte
	off int
	fin bool
}

func newEchoHandler() *echoHandler {
	return &echoHandler{streams: map[*Conn]map[uint64]*echoStream{}, uni: map[uint64][]byte{}, resets: map[uint64]uint64{}, stops: map[uint64]uint64{}}
}

func (h *echoHandler) stream(c *Conn, id uint64) *echoStream {
	m := h.streams[c]
	if m == nil {
		m = map[uint64]*echoStream{}
		h.streams[c] = m
	}
	st := m[id]
	if st == nil {
		st = &echoStream{}
		m[id] = st
	}
	return st
}

func (h *echoHandler) StreamData(c *Conn, id uint64, data []byte, fin bool) {
	c.StreamConsumed(id, len(data))
	if id&streamUni != 0 {
		h.uni[id] = append(h.uni[id], data...)
		return
	}
	st := h.stream(c, id)
	st.in = append(st.in, data...)
	if fin {
		st.out, st.fin = st.in, true
		h.flush(c, id, st)
	}
}

func (h *echoHandler) flush(c *Conn, id uint64, st *echoStream) {
	st.off += c.StreamWrite(id, st.out[st.off:], true)
}

func (h *echoHandler) StreamWritable(c *Conn, id uint64) {
	if st := h.stream(c, id); st.fin {
		h.flush(c, id, st)
	}
}

// A client that gives up its request gets no answer: the stream's other
// direction is given up too, as an application does.
func (h *echoHandler) StreamReset(c *Conn, id uint64, code uint64) {
	h.resets[id] = code
	c.StreamReset(id, 0x10c)
}
func (h *echoHandler) StreamStop(c *Conn, id uint64, code uint64) { h.stops[id] = code }

func newEchoServer(t *testing.T, setup func(*testServer)) (*testServer, *echoHandler) {
	h := newEchoHandler()
	s := newTestServer(t, func(s *testServer) {
		s.cfg.Handler = h
		if setup != nil {
			setup(s)
		}
	})
	return s, h
}

func dialClient(t *testing.T, s *testServer) *quicgo.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cc, err := quicgo.DialAddr(ctx, s.addr(), clientTLS, &quicgo.Config{})
	if err != nil {
		t.Fatalf("the client's handshake: %v", err)
	}
	t.Cleanup(func() { cc.CloseWithError(0, "") })
	return cc
}

// echo sends body on a new stream of cc and returns what comes back.
func echo(cc *quicgo.Conn, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := cc.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	st.SetDeadline(time.Now().Add(30 * time.Second))
	go func() {
		st.Write(body)
		st.Close()
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		return got, fmt.Errorf("read: %w", err)
	}
	return got, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// A real client's streams: what it sends on one comes back whole, from
// nothing at all to more than every window (the stream's, the
// connection's, the send buffer), so the limits are extended as the data
// is consumed and acknowledged.
func TestStreams_Echo(t *testing.T) {
	s, _ := newEchoServer(t, nil)
	cc := dialClient(t, s)
	for _, n := range []int{0, 1, 1000, 100 << 10, 3 << 20} {
		body := randomBytes(n)
		got, err := echo(cc, body)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("%d bytes: %d came back, %v", n, len(got), err)
		}
	}
	c := s.conn(0)
	if _, _, err := s.state(c); err != nil {
		t.Errorf("the connection after the transfers: %v", err)
	}
	// Every stream is finished and let go of.
	s.waitFor("the streams to be let go of", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(c.streams) == 0 })
	// The congestion window grew with the transfers, and once everything
	// is acknowledged nothing is counted as in flight any more.
	s.waitFor("nothing to be in flight", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return c.cc.inFlight == 0 })
	s.mu.Lock()
	cwnd, sent := c.cc.cwnd, len(c.spaces[LevelApplication].sent)
	s.mu.Unlock()
	if cwnd <= initialWindowPackets*maxDatagram || sent != 0 {
		t.Errorf("after 3 MiB: congestion window %d (initial %d), %d packets still waited for", cwnd, initialWindowPackets*maxDatagram, sent)
	}
}

// More streams than the client may have open at once, one after another
// (the limit moves on as they finish), and many at the same time.
func TestStreams_Many(t *testing.T) {
	s, _ := newEchoServer(t, nil)
	cc := dialClient(t, s)
	for i := 0; i < 250; i++ {
		body := []byte(fmt.Sprintf("request %d", i))
		got, err := echo(cc, body)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("stream %d: %q, %v", i, got, err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 80)
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := randomBytes(1000 + 37*i)
			got, err := echo(cc, body)
			if err != nil || !bytes.Equal(got, body) {
				errs <- fmt.Errorf("concurrent stream %d: %d of %d bytes, %v", i, len(got), len(body), err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// Datagrams are lost in both directions, one in every eleven the server
// sends and one in every thirteen it receives: the data still arrives
// whole, both ways.
func TestStreams_UnderLoss(t *testing.T) {
	s, _ := newEchoServer(t, func(s *testServer) {
		s.drop = func(n int) bool { return n > 8 && n%11 == 0 }
		s.dropIn = func(n int) bool { return n > 8 && n%13 == 0 }
	})
	cc := dialClient(t, s)
	for _, n := range []int{5000, 400 << 10} {
		body := randomBytes(n)
		got, err := echo(cc, body)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("%d bytes with loss: %d came back, %v", n, len(got), err)
		}
	}
	c := s.conn(0)
	if _, _, err := s.state(c); err != nil {
		t.Errorf("the connection after the transfers: %v", err)
	}
	// The losses were taken as congestion, and what was lost is not
	// counted as in flight for ever.
	s.waitFor("nothing to be in flight", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return c.cc.inFlight == 0 })
	s.mu.Lock()
	reduced := c.cc.recoveryStart != 0
	s.mu.Unlock()
	if !reduced {
		t.Errorf("datagrams were lost and the congestion window was never reduced")
	}
}

// Key updates from both sides: the client starts one after its first 100
// packets (quic-go does), and the server one every 60 packets here. A
// megabyte each way crosses dozens of them.
func TestStreams_KeyUpdates(t *testing.T) {
	old := keyUpdateInterval
	keyUpdateInterval = 60
	t.Cleanup(func() { keyUpdateInterval = old })
	s, _ := newEchoServer(t, nil)
	cc := dialClient(t, s)
	body := randomBytes(1 << 20)
	got, err := echo(cc, body)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("1 MiB across key updates: %d came back, %v", len(got), err)
	}
	c := s.conn(0)
	s.mu.Lock()
	sent, since := c.spaces[LevelApplication].nextPN, c.spaces[LevelApplication].nextPN-c.phaseSendFirst
	cerr := c.Err()
	s.mu.Unlock()
	if cerr != nil {
		t.Errorf("the connection: %v", cerr)
	}
	// The last update of ours is recent: the keys did change along the
	// way (with no update, everything sent would be in the first phase).
	if sent < 500 || since > 200 {
		t.Errorf("%d packets sent, %d of them since the last key update", sent, since)
	}
}

// Unidirectional streams, each way: the server opens one and writes to it,
// the client reads it; the client opens one, and its data reaches the
// handler.
func TestStreams_Unidirectional(t *testing.T) {
	msg := []byte("from the server, one way")
	s, h := newEchoServer(t, func(s *testServer) {
		s.established = func(c *Conn) {
			id, ok := c.OpenUniStream()
			if !ok || c.StreamWrite(id, msg, true) != len(msg) {
				s.t.Errorf("the server's unidirectional stream: opened %v", ok)
			}
		}
	})
	cc := dialClient(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rs, err := cc.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(rs); err != nil || !bytes.Equal(got, msg) {
		t.Errorf("the server's unidirectional stream: %q, %v", got, err)
	}
	ws, err := cc.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	up := randomBytes(70000)
	ws.Write(up)
	ws.Close()
	s.waitFor("the client's unidirectional data", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return bytes.Equal(h.uni[uint64(ws.StreamID())], up)
	})
}

// A client that gives up sending (RESET_STREAM) and one that wants no more
// (STOP_SENDING): the handler is told with the client's codes, and the
// stream the client stopped is reset with that code.
func TestStreams_ResetAndStop(t *testing.T) {
	s, h := newEchoServer(t, nil)
	cc := dialClient(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, err := cc.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte("half a request"))
	st.CancelWrite(7)
	id := uint64(st.StreamID())
	s.waitFor("the client's reset", func() bool { s.mu.Lock(); defer s.mu.Unlock(); _, ok := h.resets[id]; return ok })
	s.mu.Lock()
	code := h.resets[id]
	s.mu.Unlock()
	if code != 7 {
		t.Errorf("RESET_STREAM code %d, want 7", code)
	}

	// A large echo that the client stops reading in the middle.
	st2, err := cc.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st2.SetDeadline(time.Now().Add(10 * time.Second))
	st2.Write(randomBytes(600 << 10))
	st2.Close()
	buf := make([]byte, 4096)
	if _, err := io.ReadFull(st2, buf); err != nil {
		t.Fatalf("the start of the echo: %v", err)
	}
	st2.CancelRead(9)
	id2 := uint64(st2.StreamID())
	s.waitFor("the client's STOP_SENDING", func() bool { s.mu.Lock(); defer s.mu.Unlock(); _, ok := h.stops[id2]; return ok })
	s.mu.Lock()
	code = h.stops[id2]
	s.mu.Unlock()
	if code != 9 {
		t.Errorf("STOP_SENDING code %d, want 9", code)
	}
	// Both streams are let go of, and the connection goes on.
	c := s.conn(0)
	s.waitFor("the two streams to be let go of", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(c.streams) == 0 })
	if got, err := echo(cc, []byte("still there")); err != nil || string(got) != "still there" {
		t.Errorf("a stream after the reset ones: %q, %v", got, err)
	}
}

// What a client must not do with streams, as frames given to an
// established connection: each closes it with the error the RFC names.
func TestStreams_Violations(t *testing.T) {
	bidiWindow := uint64(1 << 18)
	cases := []struct {
		name string
		f    Frame
		do   func(c *Conn, now int64, f *Frame) bool
		want TransportError
	}{
		{"data past the stream's limit", Frame{Type: FrameStream, StreamID: 0, Offset: bidiWindow, Data: []byte{1}}, (*Conn).onStream, FlowControlError},
		{"a stream past the stream limit", Frame{Type: FrameStream, StreamID: 100 * 4, Data: []byte{1}}, (*Conn).onStream, StreamLimitError},
		{"a unidirectional stream past its limit", Frame{Type: FrameStream, StreamID: 100*4 + 2, Data: []byte{1}}, (*Conn).onStream, StreamLimitError},
		{"data on a stream of the server's", Frame{Type: FrameStream, StreamID: 3, Data: []byte{1}}, (*Conn).onStream, StreamStateError},
		{"a bidirectional stream of the server's", Frame{Type: FrameStream, StreamID: 1, Data: []byte{1}}, (*Conn).onStream, StreamStateError},
		{"RESET_STREAM for a stream of the server's", Frame{Type: FrameResetStream, StreamID: 3}, (*Conn).onResetStream, StreamStateError},
		{"MAX_STREAM_DATA for the client's own one-way stream", Frame{Type: FrameMaxStreamData, StreamID: 2, Max: 10}, (*Conn).onMaxStreamData, StreamStateError},
		{"MAX_STREAM_DATA for a stream the server has not opened", Frame{Type: FrameMaxStreamData, StreamID: 3 + 4*50, Max: 10}, (*Conn).onMaxStreamData, StreamStateError},
		{"STOP_SENDING for the client's own one-way stream", Frame{Type: FrameStopSending, StreamID: 2}, (*Conn).onStopSending, StreamStateError},
	}
	for _, tc := range cases {
		s, _ := newEchoServer(t, nil)
		dialClient(t, s)
		c := s.conn(0)
		s.waitFor("the handshake", func() bool { e, _, _ := s.state(c); return e })
		s.mu.Lock()
		ok := tc.do(c, time.Now().UnixNano(), &tc.f)
		err := c.Err()
		s.mu.Unlock()
		if ok || !errors.Is(err, tc.want) {
			t.Errorf("%s: went on=%v, error %v; want %v", tc.name, ok, err, tc.want)
		}
	}
	// Final sizes: data past the end, an end before data already sent, two
	// different ends, a reset that names another size.
	final := []struct {
		name   string
		frames []Frame
	}{
		{"data past the end", []Frame{{Type: FrameStream | 1, StreamID: 0, Offset: 0, Data: []byte("abc"), Fin: true}, {Type: FrameStream, StreamID: 0, Offset: 3, Data: []byte("d")}}},
		{"an end before data already sent", []Frame{{Type: FrameStream, StreamID: 0, Offset: 5, Data: []byte("fgh")}, {Type: FrameStream | 1, StreamID: 0, Offset: 0, Data: []byte("abc"), Fin: true}}},
		{"two different ends", []Frame{{Type: FrameStream | 1, StreamID: 0, Offset: 5, Data: []byte("abc"), Fin: true}, {Type: FrameStream | 1, StreamID: 0, Offset: 5, Data: []byte("abcd"), Fin: true}}},
		{"a reset that names another size", []Frame{{Type: FrameStream | 1, StreamID: 0, Offset: 5, Data: []byte("abc"), Fin: true}, {Type: FrameResetStream, StreamID: 0, FinalSize: 7}}},
	}
	for _, tc := range final {
		s, _ := newEchoServer(t, nil)
		dialClient(t, s)
		c := s.conn(0)
		s.waitFor("the handshake", func() bool { e, _, _ := s.state(c); return e })
		s.mu.Lock()
		now := time.Now().UnixNano()
		ok := true
		for i := range tc.frames {
			f := &tc.frames[i]
			if f.Type == FrameResetStream {
				ok = c.onResetStream(now, f)
			} else {
				ok = c.onStream(now, f)
			}
			if !ok {
				break
			}
		}
		err := c.Err()
		s.mu.Unlock()
		if ok || !errors.Is(err, FinalSizeError) {
			t.Errorf("%s: went on=%v, error %v; want %v", tc.name, ok, err, FinalSizeError)
		}
	}
	// The connection's window: more in all than it allows, spread over
	// streams that each stay inside their own.
	s, _ := newEchoServer(t, func(s *testServer) { s.cfg.Params.InitialMaxData = 1000 })
	dialClient(t, s)
	c := s.conn(0)
	s.waitFor("the handshake", func() bool { e, _, _ := s.state(c); return e })
	s.mu.Lock()
	now := time.Now().UnixNano()
	// The handler consumes the first 600 bytes at once, which moves the
	// connection's limit from 1000 to 1600: a frame that takes the total to
	// 1601 is one byte too many (it is refused before any of it is
	// delivered).
	ok := c.onStream(now, &Frame{Type: FrameStream, StreamID: 0, Data: make([]byte, 600)})
	if !ok {
		t.Errorf("600 bytes with a limit of 1000: %v", c.Err())
	}
	ok = ok && c.onStream(now, &Frame{Type: FrameStream, StreamID: 4, Data: make([]byte, 1001)})
	err := c.Err()
	s.mu.Unlock()
	if ok || !errors.Is(err, FlowControlError) {
		t.Errorf("more than the connection's window: went on=%v, error %v", ok, err)
	}
}

// The packet that completes a handshake can share its datagram with the
// client's first packets after it. RecvHandshake stops at that packet and
// tells the stream handler nothing (the test server checks that for every
// test); what follows it in the datagram is Recv's, and is served: here
// the client's datagrams are joined that way on purpose, and what it sent
// on its first stream comes back.
func TestRecvHandshake_RestOfTheDatagram(t *testing.T) {
	s, _ := newEchoServer(t, func(s *testServer) { s.coalesce = true })
	body := randomBytes(700)
	for i := 0; i < 8; i++ {
		cc := dialClient(t, s)
		got, err := echo(cc, body)
		if err != nil || string(got) != string(body) {
			t.Fatalf("client %d: %d bytes back of %d, %v", i, len(got), len(body), err)
		}
	}
	s.mu.Lock()
	n := s.afterHandshake
	s.mu.Unlock()
	if n == 0 {
		t.Fatal("no datagram carried the handshake's last packet together with what follows it: the case was not exercised")
	}
	t.Logf("%d datagrams carried the handshake's last packet and more", n)
}
