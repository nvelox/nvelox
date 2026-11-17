package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"
)

// fuzzHandler is an application whose every step is read off a tape: what
// it does with stream data, with a reset, with a stream it may write to
// again. It does what an application may do from within the connection's
// calls: write, reset, stop, consume or leave unconsumed, open streams.
type fuzzHandler struct {
	tape []byte
	at   int
	data []byte
}

func (h *fuzzHandler) next() byte {
	if len(h.tape) == 0 {
		return 0
	}
	b := h.tape[h.at%len(h.tape)]
	h.at++
	return b
}

func (h *fuzzHandler) StreamData(c *Conn, id uint64, data []byte, fin bool) {
	switch b := h.next(); b % 8 {
	case 0, 1: // echo
		c.StreamConsumed(id, len(data))
		c.StreamWrite(id, data, fin)
	case 2: // an answer larger than what came
		c.StreamConsumed(id, len(data))
		c.StreamWrite(id, h.data[:min(len(h.data), int(b)<<8)], fin)
	case 3: // refused
		c.StreamConsumed(id, len(data))
		c.StreamStopSending(id, uint64(b))
		c.StreamReset(id, uint64(b))
	case 4: // left unconsumed: the client's windows stay as they are
	case 5: // consumed, nothing said
		c.StreamConsumed(id, len(data))
	case 6: // a stream of the server's own
		c.StreamConsumed(id, len(data))
		if uni, ok := c.OpenUniStream(); ok {
			c.StreamWrite(uni, h.data[:min(len(h.data), int(b)<<6)], b&0x10 != 0)
		}
	case 7: // more than was given back is never said to be consumed
		c.StreamConsumed(id, len(data)/2)
	}
}

func (h *fuzzHandler) StreamReset(c *Conn, id uint64, code uint64) {
	if h.next()%2 == 0 {
		c.StreamReset(id, code)
	}
}

func (h *fuzzHandler) StreamStop(c *Conn, id uint64, code uint64) {
	if h.next()%4 == 0 {
		c.StreamWrite(id, h.data[:100], true)
	}
}

func (h *fuzzHandler) StreamWritable(c *Conn, id uint64) {
	switch b := h.next(); b % 4 {
	case 0, 1:
		c.StreamWrite(id, h.data[:min(len(h.data), int(b)<<9)], b&0x10 != 0)
	case 2:
		c.StreamReset(id, uint64(b))
	}
}

// counts checks what a connection keeps count of, in any state: what its
// streams hold to send and what they have taken of the client's limit are
// what the streams themselves say, nothing was sent that was not taken or
// that the client did not allow, nothing is consumed that did not arrive,
// and the congestion controller's numbers are numbers.
func (tc *testClient) counts(when string) {
	tc.t.Helper()
	c := tc.c
	if c.streams == nil {
		// Over: its streams are let go of, and nothing is held for them.
		if c.sendHeld != 0 || len(c.waiting) != 0 {
			tc.t.Fatalf("%s: a connection without streams counts %d bytes held to send and %d streams in line", when, c.sendHeld, len(c.waiting))
		}
		return
	}
	if c.mtu < maxDatagram || c.mtu > MaxDatagramSize || uint64(c.mtu) > max(c.peer.MaxUDPPayloadSize, maxDatagram) || c.cc.mds != int64(c.mtu) {
		tc.t.Fatalf("%s: datagrams of %d bytes (the client takes %d; the window counts in %d)", when, c.mtu, c.peer.MaxUDPPayloadSize, c.cc.mds)
	}
	for _, size := range tc.sizes {
		if size > MaxDatagramSize {
			tc.t.Fatalf("%s: a datagram of %d bytes", when, size)
		}
	}
	if c.state < stateClosing {
		flying := int64(0)
		for l := range c.spaces {
			sent := c.spaces[l].sent
			for i := range sent {
				if i > 0 && sent[i].pn <= sent[i-1].pn {
					tc.t.Fatalf("%s: level %d: packet %d waits for its acknowledgement behind packet %d", when, l, sent[i].pn, sent[i-1].pn)
				}
				if sent[i].pn >= c.spaces[l].nextPN {
					tc.t.Fatalf("%s: level %d: packet %d waits for its acknowledgement and was never sent (next is %d)", when, l, sent[i].pn, c.spaces[l].nextPN)
				}
				flying += int64(sent[i].size)
			}
		}
		if flying != c.cc.inFlight {
			tc.t.Fatalf("%s: %d bytes counted in flight, the packets that wait weigh %d", when, c.cc.inFlight, flying)
		}
	}
	held, unsent, wait := 0, uint64(0), 0
	for _, s := range c.streams {
		// A client is never allowed further ahead of what was taken than
		// the stream's window, and that window never past its limit.
		if s.recvMax > s.consumed+s.rwin || s.rwin > max(c.cfg.MaxStreamWindow, c.cfg.Params.InitialMaxStreamDataBidiRemote, c.cfg.Params.InitialMaxStreamDataUni) {
			tc.t.Fatalf("%s: stream %d: the client may send to %d, %d was taken, the window is %d", when, s.id, s.recvMax, s.consumed, s.rwin)
		}
		held += s.buffered()
		if s.wantWrite {
			wait++
		}
		if s.reset == ctlNone {
			end := s.sbase + uint64(s.buffered())
			if s.snext < s.sbase || s.snext > end || end > s.smax {
				tc.t.Fatalf("%s: stream %d: acknowledged to %d, sent to %d, holds to %d, may send to %d", when, s.id, s.sbase, s.snext, end, s.smax)
			}
			unsent += end - s.snext
		}
	}
	switch {
	case c.sendHeld != held:
		tc.t.Fatalf("%s: the connection counts %d bytes held to send, its streams hold %d", when, c.sendHeld, held)
	case c.sendTaken != c.sentData+unsent:
		tc.t.Fatalf("%s: %d bytes taken of the client's limit, but %d sent and %d waiting to be sent", when, c.sendTaken, c.sentData, unsent)
	case c.sendTaken > c.sendMaxData:
		tc.t.Fatalf("%s: %d bytes taken, the client allows %d", when, c.sendTaken, c.sendMaxData)
	case c.recvMaxData > c.consumedData+c.rwin || c.rwin > max(c.cfg.MaxConnWindow, c.cfg.Params.InitialMaxData) || c.rwinCounted != int64(c.rwin-c.cfg.Params.InitialMaxData):
		tc.t.Fatalf("%s: the client may send %d bytes in all, %d were taken, the window is %d (%d of it counted as granted)", when, c.recvMaxData, c.consumedData, c.rwin, c.rwinCounted)
	case c.consumedData > c.recvData:
		tc.t.Fatalf("%s: %d bytes consumed, %d arrived", when, c.consumedData, c.recvData)
	case c.state < stateClosing && c.recvData > c.recvMaxData:
		tc.t.Fatalf("%s: the client sent %d bytes, past its limit of %d, and the connection goes on", when, c.recvData, c.recvMaxData)
	case c.cc.inFlight < 0 || c.cc.cwnd < minWindowPackets*c.cc.mds || c.cc.cwnd > maxWindowPackets*c.cc.mds:
		tc.t.Fatalf("%s: %d bytes in flight, a window of %d", when, c.cc.inFlight, c.cc.cwnd)
	case len(c.waiting) != wait:
		tc.t.Fatalf("%s: %d streams are in line to write, %d of the connection's streams wait", when, len(c.waiting), wait)
	}
	for _, s := range c.waiting {
		if !s.wantWrite || c.streams[s.id] != s {
			tc.t.Fatalf("%s: stream %d is in line to write and does not wait, or is not the connection's any more", when, s.id)
		}
	}
}

// An application cannot say it is done with more than arrived: not on a
// stream, not on the connection, not for a stream that does not exist. The
// windows given to the client move by what it sent and no further.
func TestStream_ConsumedIsBoundedByWhatArrived(t *testing.T) {
	h := &fuzzHandler{tape: []byte{4}} // it leaves what arrives unconsumed
	tc := newTestClient(t, func(cfg *Config) { cfg.Handler = h })
	c := tc.c
	limit := c.recvMaxData
	tc.send(append(AppendStreamHeader(nil, 0, 0, 100, false), make([]byte, 100)...))
	if c.Unconsumed() != 100 {
		t.Fatalf("%d bytes arrived and are not consumed, want 100", c.Unconsumed())
	}
	s := c.streams[0]
	streamLimit := s.recvMax
	c.StreamConsumed(404, 10) // a stream that does not exist: its bytes are the connection's
	c.StreamConsumed(0, 40)
	if c.Unconsumed() != 50 || s.consumed != 40 {
		t.Fatalf("after 10 bytes for a stream that is not there and 40 for stream 0: %d unconsumed, %d consumed on the stream; want 50 and 40", c.Unconsumed(), s.consumed)
	}
	c.StreamConsumed(0, 1<<20)
	c.StreamConsumed(0, 1<<20)
	c.StreamConsumed(404, 1<<20)
	if c.Unconsumed() != 0 || c.consumedData != 100 {
		t.Errorf("after the application said a megabyte more than arrived: %d bytes consumed of 100", c.consumedData)
	}
	if s.consumed > 100 {
		t.Errorf("stream 0 counts %d bytes consumed, 100 arrived", s.consumed)
	}
	if c.recvMaxData != limit || s.recvMax != streamLimit {
		t.Errorf("the client's limits moved from %d and %d to %d and %d for 100 bytes", limit, streamLimit, c.recvMaxData, s.recvMax)
	}
	// With bytes of another stream unconsumed, a stream still counts no
	// more than its own.
	tc.send(append(AppendStreamHeader(nil, 4, 0, 100, false), make([]byte, 100)...))
	tc.send(append(AppendStreamHeader(nil, 8, 0, 100, false), make([]byte, 100)...))
	c.StreamConsumed(4, 150)
	if got := c.streams[4].consumed; got != 100 {
		t.Errorf("stream 4 counts %d bytes consumed after the application said 150, 100 arrived on it", got)
	}
	if c.Unconsumed() != 100 {
		t.Errorf("%d bytes are unconsumed on the connection, want the 100 of the other stream", c.Unconsumed())
	}
}

// fuzzStep encodes one step of a fuzz input: what to do (op) and the bytes
// to do it with.
func fuzzStep(op byte, p []byte) []byte {
	return append([]byte{op<<4 | byte(len(p)>>8), byte(len(p))}, p...)
}

// FuzzConn: whatever a client sends once its handshake is complete, in
// packets that open with the connection's keys or in datagrams that do
// not, at whatever times, and whatever the application does from within
// the connection's calls and between them, the connection does not panic,
// what it keeps count of stays right, what it sends the client can read,
// and when it is over it holds nothing.
//
// The input is a list of steps, two bytes and what follows them: the first
// four bits say what happens, the next twelve how many bytes belong to it.
// The tape is what the application does, step by step.
func FuzzConn(f *testing.F) {
	stream := func(id, off uint64, data string, fin bool) []byte {
		return append(AppendStreamHeader(nil, id, off, len(data), fin), data...)
	}
	join := func(steps ...[]byte) (all []byte) {
		for _, s := range steps {
			all = append(all, s...)
		}
		return all
	}
	// A request and its echo, acknowledged.
	f.Add(join(fuzzStep(0, stream(0, 0, "hello", true)), fuzzStep(1, nil), fuzzStep(1, nil)), []byte{0})
	// Streams out of order, a gap filled later, the same bytes twice.
	f.Add(join(fuzzStep(0, stream(8, 5, "world", true)), fuzzStep(0, stream(8, 0, "hello", false)), fuzzStep(0, stream(8, 0, "hello", false)), fuzzStep(1, nil)), []byte{0, 2})
	// The client's limits move; it resets and stops streams.
	f.Add(join(fuzzStep(0, stream(4, 0, "abc", false)), fuzzStep(0, AppendFrame1(nil, FrameMaxData, 1<<21)), fuzzStep(0, AppendFrame2(nil, FrameMaxStreamData, 4, 1<<21)),
		fuzzStep(0, AppendResetStream(nil, 4, 7, 3)), fuzzStep(0, AppendFrame2(nil, FrameStopSending, 4, 9)), fuzzStep(1, nil)), []byte{2, 6, 0, 3})
	// Large answers against time: timers, loss, the pacer.
	f.Add(join(fuzzStep(0, stream(0, 0, "get", true)), fuzzStep(2, []byte{5}), fuzzStep(2, []byte{200}), fuzzStep(1, nil), fuzzStep(2, []byte{255}), fuzzStep(1, nil)), []byte{2, 255, 1, 255})
	// Frames a client may not send, and ones that make no sense.
	f.Add(join(fuzzStep(0, AppendAck(nil, 0, [][2]uint64{{1000, 2000}})), fuzzStep(0, []byte{FrameHandshakeDone})), []byte{0})
	f.Add(join(fuzzStep(0, stream(3, 0, "to a stream of the server's", false)), fuzzStep(0, AppendFrame1(nil, FrameMaxStreams, 1<<62))), []byte{4})
	f.Add(join(fuzzStep(0, AppendNewConnectionID(nil, 1, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8}, make([]byte, 16))), fuzzStep(0, AppendFrame1(nil, FrameRetireConnectionID, 0)),
		fuzzStep(0, append([]byte{FramePathChallenge}, "12345678"...)), fuzzStep(5, append([]byte{FramePathChallenge}, "abcdefgh"...))), []byte{0})
	// The application acts between the client's packets; garbage arrives.
	f.Add(join(fuzzStep(3, []byte("server data")), fuzzStep(4, []byte{0, 1}), fuzzStep(6, []byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}),
		fuzzStep(0, AppendConnectionClose(nil, true, 3, 0, "bye")), fuzzStep(2, []byte{255}), fuzzStep(2, []byte{255})), []byte{6, 0x1f, 7})

	// A frame of a kind that does not exist behind a request whose answer
	// is large: the connection is closed while it holds the answer.
	f.Add(join(fuzzStep(0, append(stream(0, 0, "", true), 0x30)), fuzzStep(2, []byte{48}), fuzzStep(2, []byte{255})), []byte{0x32})

	// The client moves to a connection ID of another length, from another
	// address.
	f.Add(join(fuzzStep(5, AppendNewConnectionID(nil, 48, 48, []byte{0x30}, []byte("0000000000000000"))), fuzzStep(0, stream(0, 0, "after", true)), fuzzStep(1, nil)), []byte{0})
	// Answers large enough for larger datagrams to be tried (64,000 bytes
	// for each request), acknowledged as they go.
	more := join(fuzzStep(1, nil), fuzzStep(2, []byte{1}))
	f.Add(join(fuzzStep(0, stream(0, 0, "a", true)), more, more, fuzzStep(0, stream(4, 0, "b", true)), more, more, more, more, more, more, more, more,
		fuzzStep(0, stream(8, 0, "c", true)), more, more, more, more), []byte{250})
	// The application says it is done with bytes that never arrived.
	f.Add(join(fuzzStep(4, []byte{0, 0x37}), fuzzStep(0, stream(0, 0, "abc", false)), fuzzStep(4, []byte{0, 0xff})), []byte{4, 7})

	payload := make([]byte, 1<<16)
	for i := range payload {
		payload[i] = byte(i)
	}
	f.Fuzz(func(t *testing.T, steps, tape []byte) {
		before := SendMemory()
		h := &fuzzHandler{tape: tape, data: payload}
		tc := newTestClient(t, func(cfg *Config) { cfg.Handler = h })
		tc.large = true
		c := tc.c
		buf := make([]byte, maxDatagram)
		for n := 0; len(steps) >= 2 && n < 256; n++ {
			op, size := steps[0]>>4, int(steps[0]&0x0f)<<8|int(steps[1])
			steps = steps[2:]
			size = min(size, len(steps), 1300)
			p := steps[:size]
			steps = steps[size:]
			switch op % 7 {
			case 0: // a packet of the client's with these frames
				tc.send(p)
			case 1: // the client acknowledges what it was sent
				tc.acknowledge()
			case 2: // time passes: up to a second and a quarter per step
				ms := int64(1)
				if len(p) > 0 {
					ms = int64(p[0]) * 5
				}
				tc.now += ms * int64(time.Millisecond)
				if at := c.Deadline(); at != 0 && at <= tc.now {
					c.OnTimer(tc.now)
				}
				tc.pump()
			case 3: // the application writes on a new stream of its own
				if id, ok := c.OpenUniStream(); ok {
					c.StreamWrite(id, p, len(p)%2 == 0)
				}
				tc.pump()
			case 4: // the application does something to a stream by its number
				if len(p) >= 2 {
					id := uint64(p[0])
					switch p[1] % 4 {
					case 0:
						c.StreamReset(id, uint64(p[1]))
					case 1:
						c.StreamStopSending(id, uint64(p[1]))
					case 2:
						c.StreamWrite(id, payload[:int(p[1])<<4], p[1]&0x80 != 0)
					case 3:
						c.StreamConsumed(id, int(p[1]))
					}
				}
				tc.pump()
			case 5: // a packet of the client's from another address
				info := c.RecvFrom(tc.now, tc.packet(tc.dcid, p))
				if info.HasChallenge {
					c.AppendProbe(buf, nil, &info.Challenge, -1)
				}
				tc.pump()
			case 6: // a datagram that is not one of the client's packets
				c.Recv(tc.now, p)
				tc.pump()
			}
			// What the socket layer does after every datagram: the
			// connection IDs the client may be given, and the ones it gave
			// back.
			for i := 0; c.WantCIDs() > 0 && i < 8; i++ {
				if !c.AddCID(randomBytes(CIDLen), randomBytes(16)) {
					t.Fatalf("step %d: the connection wants %d connection IDs and takes none", n, c.WantCIDs())
				}
			}
			for c.CIDsChanged() {
				if _, ok := c.RetiredCID(); !ok {
					t.Fatalf("step %d: connection IDs were given back, and there is none to take", n)
				}
			}
			tc.counts(fmt.Sprintf("after step %d (kind %d)", n, op%7))
			if c.Closed() {
				break
			}
		}
		// The end: a connection that is closing or draining is over within
		// its time, one that is neither is let go of; either way nothing
		// stays counted.
		for i := 0; i < 8 && !c.Closed() && c.state >= stateClosing; i++ {
			tc.now += int64(10 * time.Second)
			c.OnTimer(tc.now)
		}
		if c.state >= stateClosing && !c.Closed() {
			t.Fatalf("a connection that was closed is not over after 80 s (state %d)", c.state)
		}
		c.Abandon()
		if got := SendMemory(); got != before {
			t.Fatalf("after the connection the process counts %d bytes held to send, %d before it", got, before)
		}
	})
}

// firstFlight returns the handshake data of a client's first flight (its
// ClientHello), for a client whose connection ID is scid.
func firstFlight(tb testing.TB, scid []byte) []byte {
	tb.Helper()
	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "example.test",
		NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}})
	params := appendParamBytes(nil, paramInitialSCID, scid)
	for _, id := range []uint64{paramInitialMaxData, paramMaxStreamDataBidiLoc, paramMaxStreamDataBidiRem, paramMaxStreamDataUni} {
		params = appendParam(params, id, 1<<20)
	}
	params = appendParam(params, paramInitialMaxStreamsBidi, 100)
	params = appendParam(params, paramInitialMaxStreamsUni, 100)
	q.SetTransportParameters(params)
	if err := q.Start(context.Background()); err != nil {
		tb.Fatal(err)
	}
	defer q.Close()
	var hello []byte
	for {
		ev := q.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			return hello
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelInitial {
			hello = append(hello, ev.Data...)
		}
	}
}

// FuzzHandshake: whatever a client sends before its handshake is complete,
// in Initial packets (their keys are no secret: anybody can make them) or
// in datagrams that are no packets at all, the connection does not panic,
// and it sends no more than three times what came from an address that
// has not been proven.
//
// The input is a list of steps as in FuzzConn.
func FuzzHandshake(f *testing.F) {
	scid := []byte{0xc1, 1, 2, 3, 4, 5, 6, 7}
	hello := firstFlight(f, scid)
	cut := min(len(hello), 1100)
	join := func(steps ...[]byte) (all []byte) {
		for _, s := range steps {
			all = append(all, s...)
		}
		return all
	}
	// A real first flight, whole; then out of order, twice, overlapping.
	f.Add(join(fuzzStep(0, AppendCrypto(nil, 0, hello[:cut])), fuzzStep(0, AppendCrypto(nil, uint64(cut), hello[cut:])), fuzzStep(2, []byte{50}), fuzzStep(2, []byte{255})))
	f.Add(join(fuzzStep(1, AppendCrypto(nil, uint64(cut), hello[cut:])), fuzzStep(1, AppendCrypto(nil, 0, hello[:cut])), fuzzStep(0, AppendCrypto(nil, 10, hello[10:cut]))))
	// Handshake data that is none; far away; frames that have no place.
	f.Add(join(fuzzStep(0, AppendCrypto(nil, 0, []byte("not a ClientHello at all, but long enough to be read as one"))), fuzzStep(2, []byte{10})))
	f.Add(join(fuzzStep(0, AppendCrypto(nil, 1<<40, hello[:100])), fuzzStep(0, append(AppendStreamHeader(nil, 0, 0, 5, true), "hello"...))))
	f.Add(join(fuzzStep(0, AppendAck(nil, 0, [][2]uint64{{0, 5}})), fuzzStep(0, AppendConnectionClose(nil, false, 1, 0, "no")), fuzzStep(2, []byte{255})))
	f.Add(join(fuzzStep(3, []byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1, 2}), fuzzStep(3, []byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27})))

	cert := testCert(f)
	f.Fuzz(func(t *testing.T, steps []byte) {
		cfg := &Config{
			TLS: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
			Params: Params{MaxIdleTimeout: time.Minute, InitialMaxData: 1 << 20, InitialMaxStreamDataBidiRemote: 1 << 18,
				InitialMaxStreamDataUni: 1 << 18, InitialMaxStreamsBidi: 100, InitialMaxStreamsUni: 100,
				AckDelayExponent: defaultAckDelayExponent, MaxAckDelay: defaultMaxAckDelay, ActiveConnectionIDLimit: 4},
			Handler:         newEchoHandler(),
			MaxStreamWindow: 1 << 20, MaxConnWindow: 3 << 20,
		}
		odcid := []byte{0xd0, 9, 8, 7, 6, 5, 4, 3}
		cid := []byte{0x5e, 1, 1, 1, 1, 1, 1, 1}
		wk, _ := InitialKeys(odcid)
		now := int64(1e15)
		c, err := Accept(cfg, now, odcid, scid, cid, make([]byte, 16))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Abandon()
		got, sent, pn := 0, 0, int64(0)
		buf := make([]byte, maxDatagram)
		for n := 0; len(steps) >= 2 && n < 64 && !c.Closed(); n++ {
			op, size := steps[0]>>4, int(steps[0]&0x0f)<<8|int(steps[1])
			steps = steps[2:]
			size = min(size, len(steps), 1150)
			p := steps[:size]
			steps = steps[size:]
			switch op % 4 {
			case 0, 1: // an Initial packet of the client's with these frames
				to := odcid
				if op&4 != 0 {
					to = cid
				}
				b, lenOff, pnOff := AppendLongHeader(make([]byte, 0, 1500), PacketInitial, to, scid, nil, pn, 2)
				b = append(b, p...)
				for len(b)+Overhead < MinInitialSize {
					b = append(b, FramePadding)
				}
				SetLength(b, lenOff, pnOff)
				d := wk.Seal(b, pnOff, 2, pn)
				pn++
				got += len(d)
				if op%4 == 0 {
					c.Recv(now, d)
				} else {
					c.RecvHandshake(now, d)
				}
			case 2: // time passes
				ms := int64(1)
				if len(p) > 0 {
					ms = int64(p[0]) * 20
				}
				now += ms * int64(time.Millisecond)
				if at := c.Deadline(); at != 0 && at <= now {
					c.OnTimer(now)
				}
			case 3: // a datagram that is no packet of the client's
				got += len(p)
				c.Recv(now, p)
			}
			for i := 0; i < 64; i++ {
				k := c.Send(now, buf)
				if k == 0 {
					break
				}
				sent += k
			}
			if !c.AddressValidated() && sent > 3*got {
				t.Fatalf("step %d: %d bytes were sent to an address that is not proven and sent %d", n, sent, got)
			}
			if c.Established() {
				t.Fatalf("step %d: the handshake is complete, and the client never had its keys", n)
			}
		}
	})
}
