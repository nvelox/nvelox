package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"sort"
	"testing"
	"time"
)

// testClient is a QUIC client in memory, just enough of one for the tests
// that need a say in every frame: it completes a handshake with a Conn,
// without sockets or timers, then sends 1-RTT packets with the frames a
// test gives it and tells what the server's packets hold.
type testClient struct {
	t    testing.TB
	c    *Conn // the server's connection
	tls  *tls.QUICConn
	scid []byte // the client's connection ID (CIDLen bytes)
	dcid []byte // the server's
	now  int64

	rk, wk  [3]*Keys
	crypto  [3]CryptoRecv
	out     [3][]byte // handshake data, and how far it was sent
	outOff  [3]uint64
	nextPN  [3]int64
	largest [3]int64
	done    bool

	// What the server sent since take: the frames of its 1-RTT packets
	// (PADDING, ACK and CRYPTO left out), the size of each datagram, and
	// the connection ID its last 1-RTT packet named.
	frames []Frame
	sizes  []int
	named  []byte
	// The numbers of the server's 1-RTT packets, for acknowledge.
	seen []uint64
	buf  []byte
	// large: the client takes datagrams of any size the server may send
	// (pump gives Send room for them). Without it Send has room for
	// maxDatagram bytes, and the server never tries a larger size: the
	// datagrams of a test are then of one size, whatever it sends.
	large bool
	// drop, when set, says which of the server's datagrams never arrive:
	// the client does not see them, and so never acknowledges them.
	drop func(size int) bool
}

// newTestClient returns a client whose handshake with a new server
// connection is complete. setup, when given, changes the server's
// configuration first. The client's connection ID is CIDLen bytes long,
// and it lets the server hold four of its connection IDs. It lets the
// server send 1 MiB on each stream and on all together; limits, when given,
// has other values for those transport parameters.
func newTestClient(t testing.TB, setup func(*Config), limits ...map[uint64]uint64) *testClient {
	t.Helper()
	cfg := &Config{
		TLS: &tls.Config{Certificates: []tls.Certificate{testCert(t)}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		Params: Params{MaxIdleTimeout: time.Minute, InitialMaxData: 1 << 20, InitialMaxStreamDataBidiRemote: 1 << 18,
			InitialMaxStreamDataUni: 1 << 18, InitialMaxStreamsBidi: 100, InitialMaxStreamsUni: 100,
			AckDelayExponent: defaultAckDelayExponent, MaxAckDelay: defaultMaxAckDelay, ActiveConnectionIDLimit: 4},
		Handler: newEchoHandler(),
	}
	if setup != nil {
		setup(cfg)
	}
	tc := &testClient{t: t, now: time.Now().UnixNano(), buf: make([]byte, 2048), largest: [3]int64{-1, -1, -1}}
	odcid := randomBytes(8)
	tc.scid, tc.dcid = randomBytes(CIDLen), odcid
	tc.tls = tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "example.test",
		NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}})
	params := appendParamBytes(nil, paramInitialSCID, tc.scid)
	for _, id := range []uint64{paramInitialMaxData, paramMaxStreamDataBidiLoc, paramMaxStreamDataBidiRem, paramMaxStreamDataUni} {
		v := uint64(1 << 20)
		if len(limits) > 0 {
			if other, ok := limits[0][id]; ok {
				v = other
			}
		}
		params = appendParam(params, id, v)
	}
	if len(limits) > 0 {
		if v, ok := limits[0][paramMaxUDPPayloadSize]; ok {
			params = appendParam(params, paramMaxUDPPayloadSize, v)
		}
	}
	params = appendParam(params, paramInitialMaxStreamsBidi, 100)
	params = appendParam(params, paramInitialMaxStreamsUni, 100)
	params = appendParam(params, paramActiveCIDLimit, 4)
	tc.tls.SetTransportParameters(params)
	if err := tc.tls.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tc.tls.Close() })
	tc.wk[LevelInitial], tc.rk[LevelInitial] = InitialKeys(odcid)
	tc.events()
	flight := tc.flight()
	var err error
	if tc.c, err = Accept(cfg, tc.now, odcid, tc.scid, randomBytes(CIDLen), randomBytes(16)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tc.c.Abandon)
	for round := 0; !tc.done || !tc.c.Established(); round++ {
		if round > 20 {
			t.Fatalf("the handshake does not complete (client done: %v, server: %v, %v)", tc.done, tc.c.Established(), tc.c.Err())
		}
		for _, d := range flight {
			tc.c.Recv(tc.now, d)
		}
		tc.pump()
		flight = tc.flight()
	}
	tc.pump()
	tc.acknowledge()
	tc.take()
	return tc
}

// events takes what crypto/tls has to say: keys and handshake data.
func (tc *testClient) events() {
	tc.t.Helper()
	for {
		ev := tc.tls.NextEvent()
		switch ev.Kind {
		case tls.QUICNoEvent:
			return
		case tls.QUICSetReadSecret, tls.QUICSetWriteSecret:
			lvl, ok := levelOf(ev.Level)
			if !ok {
				continue
			}
			k, err := NewKeys(ev.Suite, ev.Data)
			if err != nil {
				tc.t.Fatal(err)
			}
			if ev.Kind == tls.QUICSetReadSecret {
				tc.rk[lvl] = k
			} else {
				tc.wk[lvl] = k
			}
		case tls.QUICWriteData:
			if lvl, ok := levelOf(ev.Level); ok {
				tc.out[lvl] = append(tc.out[lvl], ev.Data...)
			}
		case tls.QUICHandshakeDone:
			tc.done = true
		case tls.QUICErrorEvent:
			tc.t.Fatalf("the client's handshake: %v", ev.Err)
		}
	}
}

// flight returns the datagrams that carry the handshake data not sent yet:
// one packet each, an Initial packet's padded to full size.
func (tc *testClient) flight() [][]byte {
	var dgrams [][]byte
	for lvl := LevelInitial; lvl <= LevelHandshake; lvl++ {
		typ := uint8(PacketInitial)
		if lvl == LevelHandshake {
			typ = PacketHandshake
		}
		for tc.wk[lvl] != nil && tc.outOff[lvl] < uint64(len(tc.out[lvl])) {
			off := tc.outOff[lvl]
			n := min(uint64(len(tc.out[lvl]))-off, 1000)
			pn := tc.nextPN[lvl]
			tc.nextPN[lvl]++
			b, lenOff, pnOff := AppendLongHeader(make([]byte, 0, 1500), typ, tc.dcid, tc.scid, nil, pn, 2)
			b = AppendCrypto(b, off, tc.out[lvl][off:off+n])
			for lvl == LevelInitial && len(b)+Overhead < MinInitialSize {
				b = append(b, FramePadding)
			}
			SetLength(b, lenOff, pnOff)
			dgrams = append(dgrams, tc.wk[lvl].Seal(b, pnOff, 2, pn))
			tc.outOff[lvl] = off + n
		}
	}
	return dgrams
}

// pump takes everything the server has to send now.
func (tc *testClient) pump() {
	tc.t.Helper()
	for {
		size := maxDatagram
		if tc.large {
			size = MaxDatagramSize
		}
		n := tc.c.Send(tc.now, tc.buf[:size])
		if n == 0 {
			return
		}
		if tc.drop != nil && tc.drop(n) {
			continue
		}
		tc.recv(tc.buf[:n])
	}
}

// recv reads a datagram of the server's.
func (tc *testClient) recv(d []byte) {
	tc.t.Helper()
	tc.sizes = append(tc.sizes, len(d))
	for len(d) > 0 {
		// A short header does not say how long its connection ID is: the
		// client knows its own. It is the one the server sends to now (a
		// test may have given the server another, of another length).
		h, err := ParseHeader(d, len(tc.c.dcid))
		if err != nil {
			tc.t.Fatalf("a packet of the server's: %v", err)
		}
		pkt := d[:h.End]
		d = d[h.End:]
		var lvl Level
		switch h.Type {
		case PacketInitial:
			lvl = LevelInitial
		case PacketHandshake:
			lvl = LevelHandshake
		case PacketShort:
			lvl = LevelApplication
			tc.named = append(tc.named[:0], h.DCID...)
		default:
			tc.t.Fatalf("a packet of type %d from the server", h.Type)
		}
		if h.Type != PacketShort && string(h.DCID) != string(tc.scid) {
			tc.t.Fatalf("a packet for the connection ID % x, the client's is % x", h.DCID, tc.scid)
		}
		if lvl == LevelInitial {
			tc.dcid = append([]byte(nil), h.SCID...) // the server's, from its first packet on
		}
		if tc.rk[lvl] == nil {
			tc.t.Fatalf("a packet of level %d before its keys", lvl)
		}
		payload, pn, _, err := tc.rk[lvl].Open(pkt, h.PNOff, tc.largest[lvl])
		if err != nil {
			tc.t.Fatalf("a packet of level %d does not open: %v", lvl, err)
		}
		tc.largest[lvl] = max(tc.largest[lvl], pn)
		if lvl == LevelApplication {
			tc.seen = append(tc.seen, uint64(pn))
		}
		for len(payload) > 0 {
			var f Frame
			n, err := ParseFrame(payload, &f)
			if err != nil {
				tc.t.Fatalf("a frame of the server's: %v", err)
			}
			payload = payload[n:]
			switch f.Type {
			case FramePadding, FrameAck, FrameAck + 1:
				continue
			case FrameCrypto:
				if err := tc.crypto[lvl].Push(f.Offset, f.Data, func(p []byte) error {
					return tc.tls.HandleData(tlsLevel(lvl), p)
				}); err != nil {
					tc.t.Fatalf("the server's handshake data: %v", err)
				}
				tc.events()
				continue
			}
			if lvl == LevelApplication {
				f.CID, f.ResetToken, f.Data = append([]byte(nil), f.CID...), append([]byte(nil), f.ResetToken...), append([]byte(nil), f.Data...)
				tc.frames = append(tc.frames, f)
			}
		}
	}
}

// take returns what the server sent since it was last called: the frames
// of its 1-RTT packets and the sizes of its datagrams.
func (tc *testClient) take() (frames []Frame, sizes []int) {
	frames, sizes = tc.frames, tc.sizes
	tc.frames, tc.sizes = nil, nil
	return frames, sizes
}

// packet returns a datagram with one 1-RTT packet for the server's
// connection ID to, holding frames.
func (tc *testClient) packet(to []byte, frames []byte) []byte {
	pn := tc.nextPN[LevelApplication]
	tc.nextPN[LevelApplication]++
	b, pnOff := AppendShortHeader(make([]byte, 0, 1500), to, false, pn, 2)
	b = append(b, frames...)
	for len(b)-pnOff < 8 {
		b = append(b, FramePadding)
	}
	return tc.wk[LevelApplication].Seal(b, pnOff, 2, pn)
}

// send has the server receive a 1-RTT packet with frames, by the
// connection's path, and takes what it sends then.
func (tc *testClient) send(frames []byte) {
	tc.t.Helper()
	tc.c.Recv(tc.now, tc.packet(tc.dcid, frames))
	tc.pump()
}

// acknowledge has the server receive an acknowledgement of all its 1-RTT
// packets so far, but for the ones numbered in except.
func (tc *testClient) acknowledge(except ...uint64) {
	tc.t.Helper()
	skip := map[uint64]bool{}
	for _, pn := range except {
		skip[pn] = true
	}
	var pns []uint64
	for _, pn := range tc.seen {
		if !skip[pn] {
			pns = append(pns, pn)
		}
	}
	if len(pns) == 0 {
		return
	}
	sort.Slice(pns, func(i, j int) bool { return pns[i] > pns[j] })
	var ranges [][2]uint64
	for _, pn := range pns {
		if n := len(ranges); n > 0 && ranges[n-1][0] == pn+1 {
			ranges[n-1][0] = pn
		} else if n == 0 || ranges[n-1][0] != pn {
			ranges = append(ranges, [2]uint64{pn, pn})
		}
	}
	tc.send(AppendAck(nil, 0, ranges))
}

// closedWith reports whether the connection was closed for the transport
// error code.
func closedWith(c *Conn, code TransportError) bool {
	var te TransportError
	return c.state == stateClosing && errors.As(c.Err(), &te) && te == code
}

// has reports whether frames holds one of type typ, and returns the first.
func has(frames []Frame, typ uint64) (Frame, bool) {
	for _, f := range frames {
		if f.Type == typ {
			return f, true
		}
	}
	return Frame{}, false
}

// The test client itself: it completes a handshake, and what it sends on a
// stream comes back from the server's echo handler.
func TestTestClient(t *testing.T) {
	tc := newTestClient(t, nil)
	if !tc.c.Established() || tc.c.ConnectionState().NegotiatedProtocol != "h3" {
		t.Fatalf("after the handshake: established %v, protocol %q", tc.c.Established(), tc.c.ConnectionState().NegotiatedProtocol)
	}
	body := []byte("through the test client")
	b := AppendStreamHeader(nil, 0, 0, len(body), true)
	tc.send(append(b, body...))
	frames, _ := tc.take()
	var f Frame
	for _, g := range frames {
		if g.Type >= FrameStream && g.Type <= FrameStream+7 {
			f = g
		}
	}
	if string(f.Data) != string(body) || !f.Fin {
		t.Fatalf("the echo: %+v (of %d frames), want the body back", f, len(frames))
	}
}
