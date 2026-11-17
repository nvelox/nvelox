package quic

import (
	"bytes"
	"testing"
	"time"
)

// A connection is moved to another address of its client: what was sent
// and is not acknowledged went to the address the client left, so it is
// sent again at once, not when a timer gives it up; and the round-trip
// estimate and the congestion window, which were the old path's, start
// over.
func TestConn_MigratedSendsAgain(t *testing.T) {
	dropping := false
	s, _ := newEchoServer(t, func(s *testServer) { s.drop = func(int) bool { return dropping } })
	cc := dialClient(t, s)
	big := randomBytes(200 << 10)
	if got, err := echo(cc, big); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("echo: %d bytes, %v", len(got), err)
	}
	c := s.conn(0)
	s.mu.Lock()
	sampled, grown := c.rttSampled, c.cc.cwnd
	dropping = true // from here on the server's datagrams are lost
	s.mu.Unlock()
	if !sampled {
		t.Fatal("no round-trip sample after an echo of 200 KiB")
	}

	// A request whose answer does not arrive.
	body := []byte("the answer to this is lost on its way")
	answer := make(chan error, 1)
	go func() {
		got, err := echo(cc, body)
		if err == nil && !bytes.Equal(got, body) {
			err = errDropped
		}
		answer <- err
	}()
	waiting := func() bool {
		for i := range c.spaces[LevelApplication].sent {
			if c.spaces[LevelApplication].sent[i].nrec > 0 {
				return true
			}
		}
		return false
	}
	s.waitFor("the answer to be sent", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return waiting() })

	s.mu.Lock()
	now := time.Now().UnixNano()
	buf := make([]byte, 2048)
	for c.Send(now, buf[:maxDatagram]) > 0 {
	}
	if !waiting() {
		s.mu.Unlock()
		t.Fatal("the answer is no longer waited for")
	}
	c.Migrated(now, -1)
	n := c.Send(now, buf[:maxDatagram])
	sampled, cwnd, flying := c.rttSampled, c.cc.cwnd, len(c.spaces[LevelApplication].sent)
	var fresh congestion
	fresh.init(maxDatagram)
	dropping = false
	s.mu.Unlock()
	if n == 0 {
		t.Error("after the move nothing was sent: what went to the address the client left waits for a timer")
	}
	if flying != 1 {
		t.Errorf("%d packets wait for an acknowledgement after the move, want the one just sent", flying)
	}
	if sampled {
		t.Error("the round-trip estimate of the path the client left was kept")
	}
	if cwnd != fresh.cwnd || grown == fresh.cwnd {
		t.Errorf("the congestion window is %d after the move (it was %d before), want that of a new path, %d", cwnd, grown, fresh.cwnd)
	}
	// The connection is none the worse: the answer arrives.
	select {
	case err := <-answer:
		if err != nil {
			t.Errorf("the answer after the move: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Error("the answer never arrived after the move")
	}
}

// A PATH_RESPONSE answers a challenge. From a client that was sent none it
// is that client's error, as it is for the quic-go server.
func TestPath_ResponseToNoChallenge(t *testing.T) {
	tc := newTestClient(t, nil)
	tc.send(AppendPath(nil, FramePathResponse, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	if !closedWith(tc.c, ProtocolViolation) {
		t.Errorf("after a PATH_RESPONSE to no challenge: %v, want PROTOCOL_VIOLATION", tc.c.Err())
	}
}

// Datagrams from another address than the one the connection sends to:
// what RecvFrom says of them, the probe that goes back, and the client's
// answer to it.
func TestPath_AnotherAddress(t *testing.T) {
	tc := newTestClient(t, nil)
	other := func(frames []byte) PathInfo { return tc.c.RecvFrom(tc.now, tc.packet(tc.dcid, frames)) }

	// Not the client's: it does not open.
	forged := tc.packet(tc.dcid, []byte{FramePing})
	forged[len(forged)-1] ^= 0xff
	if info := tc.c.RecvFrom(tc.now, forged); info != (PathInfo{}) {
		t.Errorf("a datagram that does not open: %+v, want nothing", info)
	}

	// The client tries the path: a challenge and nothing else. It is not
	// answered by the connection's path.
	theirs := [8]byte{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8}
	info := other(AppendPath(nil, FramePathChallenge, theirs))
	if want := (PathInfo{Packets: true, Newest: true, Challenge: theirs, HasChallenge: true}); info != want {
		t.Errorf("the client's challenge from another address: %+v, want %+v", info, want)
	}
	tc.pump()
	if frames, _ := tc.take(); len(frames) != 0 {
		t.Errorf("after a challenge from another address the connection sent %d frames by its own path: %+v", len(frames), frames)
	}

	// The probe: this side's challenge and the answer to the client's, in
	// a datagram as long as a path must carry.
	mine := [8]byte{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58}
	tc.recv(tc.buf[:tc.c.AppendProbe(tc.buf, &mine, &info.Challenge, -1)])
	frames, sizes := tc.take()
	if f, ok := has(frames, FramePathChallenge); !ok || f.PathData != mine {
		t.Errorf("the probe's challenge: %+v (%v), want %x", f.PathData, ok, mine)
	}
	if f, ok := has(frames, FramePathResponse); !ok || f.PathData != theirs {
		t.Errorf("the probe's answer: %+v (%v), want %x", f.PathData, ok, theirs)
	}
	if len(sizes) != 1 || sizes[0] != maxDatagram {
		t.Errorf("the probe's datagram: %v bytes, want one of %d", sizes, maxDatagram)
	}
	if tc.c.AppendProbe(tc.buf, nil, nil, -1) != 0 {
		t.Error("a probe with nothing in it was made")
	}

	// The client's answer, by whichever path.
	if _, ok := tc.c.PathResponse(); ok {
		t.Error("an answer before the client sent one")
	}
	tc.send(AppendPath(nil, FramePathResponse, mine))
	if data, ok := tc.c.PathResponse(); !ok || data != mine {
		t.Errorf("the client's answer: %x (%v), want %x", data, ok, mine)
	}
	if _, ok := tc.c.PathResponse(); ok {
		t.Error("one answer is reported twice")
	}
	if err := tc.c.Err(); err != nil {
		t.Fatalf("the connection: %v", err)
	}

	// More than probes; a packet that was overtaken; one seen before.
	if info := other([]byte{FramePing}); !info.Packets || !info.Newest || !info.NonProbing || info.HasChallenge || info.OtherCID {
		t.Errorf("a PING from another address: %+v", info)
	}
	early, late := tc.packet(tc.dcid, []byte{FramePing}), tc.packet(tc.dcid, []byte{FramePing})
	again := append([]byte(nil), early...)
	tc.c.Recv(tc.now, late)
	if info := tc.c.RecvFrom(tc.now, early); !info.Packets || info.Newest || !info.NonProbing {
		t.Errorf("a packet that was overtaken, from another address: %+v", info)
	}
	if info := tc.c.RecvFrom(tc.now, again); info != (PathInfo{}) {
		t.Errorf("a packet that came before, from another address: %+v, want nothing", info)
	}

	// A challenge by the connection's own path is answered there.
	tc.pump()
	tc.take()
	tc.send(AppendPath(nil, FramePathChallenge, theirs))
	frames, sizes = tc.take()
	if f, ok := has(frames, FramePathResponse); !ok || f.PathData != theirs || sizes[len(sizes)-1] != maxDatagram {
		t.Errorf("a challenge by the connection's path: answer %x (%v) in datagrams of %v bytes", f.PathData, ok, sizes)
	}
}
