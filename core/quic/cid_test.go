package quic

import (
	"crypto/tls"
	"testing"
	"time"
)

// cidConn is a connection for the bookkeeping of connection IDs: accepted,
// taken for established, its client using clientCID. limit is how many of
// the client's connection IDs this side holds (0: the default, two).
func cidConn(t *testing.T, clientCID []byte, limit uint64) *Conn {
	t.Helper()
	cfg := &Config{
		TLS:    &tls.Config{Certificates: []tls.Certificate{testCert(t)}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		Params: Params{MaxIdleTimeout: time.Minute, ActiveConnectionIDLimit: limit},
	}
	cid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	token := make([]byte, 16)
	c, err := Accept(cfg, time.Now().UnixNano(), []byte{9, 9, 9, 9, 9, 9, 9, 9}, clientCID, cid, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Abandon)
	c.state = stateEstablished
	c.peer.ActiveConnectionIDLimit = 4
	return c
}

func newCID(seq, retirePriorTo uint64, cid ...byte) *Frame {
	return &Frame{Type: FrameNewConnectionID, Seq: seq, RetirePriorTo: retirePriorTo, CID: cid, ResetToken: make([]byte, 16)}
}

// The client's spare connection IDs are kept, as many as this side said it
// holds; one more is the client's error, and so is another connection ID
// under a sequence number already seen.
func TestCID_ClientsSpareOnes(t *testing.T) {
	c := cidConn(t, []byte{0xc0, 0xc1, 0xc2, 0xc3}, 3)
	now := time.Now().UnixNano()
	if !c.onNewConnectionID(now, newCID(1, 0, 0xa1)) || !c.onNewConnectionID(now, newCID(2, 0, 0xa2)) {
		t.Fatalf("two spare connection IDs with a limit of three: %v", c.Err())
	}
	// Frames that arrive again change nothing, the client's first one
	// included.
	if !c.onNewConnectionID(now, newCID(2, 0, 0xa2)) || !c.onNewConnectionID(now, newCID(0, 0, 0xc0, 0xc1, 0xc2, 0xc3)) {
		t.Fatalf("a frame that arrived twice: %v", c.Err())
	}
	if len(c.spare) != 2 || string(c.dcid) != "\xc0\xc1\xc2\xc3" || len(c.retire) != 0 {
		t.Fatalf("spare %d, in use % x, to give back %v; want 2 spare, the first one in use, none given back", len(c.spare), c.dcid, c.retire)
	}
	if c.onNewConnectionID(now, newCID(3, 0, 0xa3)) || !closedWith(c, ConnectionIDLimitError) {
		t.Errorf("a fourth connection ID with a limit of three: %v, want CONNECTION_ID_LIMIT_ERROR", c.Err())
	}

	c = cidConn(t, []byte{0xc0}, 3)
	c.onNewConnectionID(now, newCID(1, 0, 0xa1))
	if c.onNewConnectionID(now, newCID(1, 0, 0xee)) || !closedWith(c, ProtocolViolation) {
		t.Errorf("another connection ID under a sequence number already used: %v, want PROTOCOL_VIOLATION", c.Err())
	}
	c = cidConn(t, []byte{0xc0}, 3)
	if c.onNewConnectionID(now, newCID(0, 0, 0xee)) || !closedWith(c, ProtocolViolation) {
		t.Errorf("another connection ID under the first one's sequence number: %v, want PROTOCOL_VIOLATION", c.Err())
	}
	// A client that uses no connection IDs has none to give.
	c = cidConn(t, nil, 3)
	if c.onNewConnectionID(now, newCID(1, 0, 0xa1)) || !closedWith(c, ProtocolViolation) {
		t.Errorf("a connection ID from a client that uses none: %v, want PROTOCOL_VIOLATION", c.Err())
	}
}

// Retire Prior To: the client takes its older connection IDs out of use.
// This side gives them back, stops using the one in use when it is among
// them, and gives back at once one that arrives late.
func TestCID_ClientRetiresItsOwn(t *testing.T) {
	c := cidConn(t, []byte{0xc0}, 4)
	now := time.Now().UnixNano()
	c.onNewConnectionID(now, newCID(1, 0, 0xa1))
	c.onNewConnectionID(now, newCID(3, 0, 0xa3))
	// Everything below 3 is out of use: 0 (in use) and 1 (spare).
	if !c.onNewConnectionID(now, newCID(4, 3, 0xa4)) {
		t.Fatalf("Retire Prior To: %v", c.Err())
	}
	if string(c.dcid) != "\xa3" || c.dcidSeq != 3 {
		t.Errorf("in use after Retire Prior To 3: % x (sequence number %d), want a3 (3)", c.dcid, c.dcidSeq)
	}
	if len(c.spare) != 1 || c.spare[0].seq != 4 {
		t.Errorf("spare after Retire Prior To 3: %+v, want the one with sequence number 4", c.spare)
	}
	gave := map[uint64]bool{}
	for _, s := range c.retire {
		gave[s] = true
	}
	if len(c.retire) != 2 || !gave[0] || !gave[1] {
		t.Errorf("given back: %v, want 0 and 1", c.retire)
	}
	// Sequence number 2 arrives after the frame that took it out of use.
	if !c.onNewConnectionID(now, newCID(2, 0, 0xa2)) {
		t.Fatalf("a late frame: %v", c.Err())
	}
	if len(c.spare) != 1 || len(c.retire) != 3 || c.retire[2] != 2 {
		t.Errorf("after the late frame: spare %+v, given back %v; want it given back, not kept", c.spare, c.retire)
	}
	// And once more: it is given back once.
	c.onNewConnectionID(now, newCID(2, 0, 0xa2))
	if len(c.retire) != 3 {
		t.Errorf("the late frame, twice: given back %v", c.retire)
	}
	if c.goneBelow != 3 || len(c.goneExtra) != 0 {
		t.Errorf("given back in all: below %d and %v, want everything below 3", c.goneBelow, c.goneExtra)
	}
}

// The client gives back connection IDs of this side: the owner of the
// sockets is told, and may give a new one. One that was never given, or
// the one the frame's own packet came for, is the client's error.
func TestCID_ClientGivesBack(t *testing.T) {
	c := cidConn(t, []byte{0xc0}, 0)
	now := time.Now().UnixNano()
	// As many as the client said it holds, the handshake's included, and
	// four at most.
	for limit, want := range map[uint64]int{2: 1, 3: 2, 4: 3, 8: 3} {
		c.peer.ActiveConnectionIDLimit = limit
		if n := c.WantCIDs(); n != want {
			t.Errorf("a client that holds %d may be given %d more after the handshake, want %d", limit, n, want)
		}
	}
	c.peer.ActiveConnectionIDLimit = 4
	second := []byte{2, 2, 2, 2, 2, 2, 2, 2}
	for i := 0; i < 3; i++ {
		if !c.AddCID([]byte{2, 2, 2, 2, 2, 2, 2, byte(2 + i)}, make([]byte, 16)) {
			t.Fatalf("connection ID %d not taken", i+1)
		}
	}
	if c.AddCID([]byte{7, 7, 7, 7, 7, 7, 7, 7}, make([]byte, 16)) || c.WantCIDs() != 0 {
		t.Errorf("a fifth connection ID was taken for a client that holds four")
	}
	if !c.localSend {
		t.Error("no NEW_CONNECTION_ID is to be sent")
	}
	// The client gives back the handshake's (sequence number 0), in a
	// packet that came for the second one.
	if !c.onRetireConnectionID(now, &Frame{Type: FrameRetireConnectionID, Seq: 0}, second) {
		t.Fatalf("RETIRE_CONNECTION_ID: %v", c.Err())
	}
	if !c.CIDsChanged() {
		t.Fatal("the owner of the sockets is not told")
	}
	cid, ok := c.RetiredCID()
	if !ok || cid != [CIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8} {
		t.Errorf("given back: % x (%v), want the handshake's", cid, ok)
	}
	if _, ok := c.RetiredCID(); ok || c.CIDsChanged() {
		t.Error("one connection ID was given back, two are reported")
	}
	if n := c.WantCIDs(); n != 1 {
		t.Errorf("after one was given back the client may be given %d, want 1", n)
	}
	// Given back again: nothing happens.
	if !c.onRetireConnectionID(now, &Frame{Type: FrameRetireConnectionID, Seq: 0}, second) || c.CIDsChanged() {
		t.Errorf("a RETIRE_CONNECTION_ID that arrived twice: %v", c.Err())
	}
	// The one the packet itself came for.
	if c.onRetireConnectionID(now, &Frame{Type: FrameRetireConnectionID, Seq: 1}, second) || !closedWith(c, ProtocolViolation) {
		t.Errorf("the packet's own connection ID given back: %v, want PROTOCOL_VIOLATION", c.Err())
	}
	c = cidConn(t, []byte{0xc0}, 0)
	if c.onRetireConnectionID(now, &Frame{Type: FrameRetireConnectionID, Seq: 1}, second) || !closedWith(c, ProtocolViolation) {
		t.Errorf("a connection ID that was never given, given back: %v, want PROTOCOL_VIOLATION", c.Err())
	}
}

// The connection ID of the client's that packets to another of its
// addresses name: the one in use when the client's address changed under
// it, a spare one (the lowest) when it moved on purpose, none when it has
// none to spare. One that was chosen and not moved to is given back, and
// does not come back with a frame that arrives again; a move takes the
// chosen one into use and gives back the one before.
func TestCID_ForAnotherAddress(t *testing.T) {
	c := cidConn(t, []byte{0xc0}, 4)
	now := time.Now().UnixNano()
	if seq, ok := c.PathCID(false); !ok || seq != -1 {
		t.Errorf("an address that changed under the client: %d, %v; want the connection ID in use", seq, ok)
	}
	if _, ok := c.PathCID(true); ok {
		t.Error("a move on purpose by a client with no spare connection ID was given one")
	}
	c.onNewConnectionID(now, newCID(2, 0, 0xa2))
	c.onNewConnectionID(now, newCID(1, 0, 0xa1))
	c.onNewConnectionID(now, newCID(3, 0, 0xa3))
	first, ok := c.PathCID(true)
	if !ok || first != 1 {
		t.Fatalf("a move on purpose: %d, %v; want the lowest spare one, 1", first, ok)
	}
	if cid, ok := c.pathCID(first); !ok || string(cid) != "\xa1" {
		t.Errorf("the chosen connection ID: % x, %v", cid, ok)
	}
	second, _ := c.PathCID(true)
	// The first address is given up.
	c.DropPathCID(first)
	if len(c.retire) != 1 || c.retire[0] != 1 {
		t.Errorf("given back after the address was given up: %v, want 1", c.retire)
	}
	if _, ok := c.pathCID(first); ok {
		t.Error("the connection ID of an address that was given up can still be used")
	}
	if !c.onNewConnectionID(now, newCID(1, 0, 0xa1)) || len(c.spare) != 1 {
		t.Errorf("its frame, arriving again, brought it back: spare %+v", c.spare)
	}
	// The connection moves to the second address.
	c.Migrated(now, second)
	if string(c.dcid) != "\xa2" || c.dcidSeq != 2 {
		t.Errorf("in use after the move: % x (%d), want a2 (2)", c.dcid, c.dcidSeq)
	}
	if len(c.retire) != 2 || c.retire[1] != 0 {
		t.Errorf("given back after the move: %v, want 1 and 0", c.retire)
	}
	if c.goneBelow != 2 || len(c.goneExtra) != 0 || len(c.pathCIDs) != 0 {
		t.Errorf("after the move: given back below %d and %v, %d still chosen", c.goneBelow, c.goneExtra, len(c.pathCIDs))
	}
	// A client that uses no connection IDs is answered with none, on
	// purpose or not.
	c = cidConn(t, nil, 4)
	if seq, ok := c.PathCID(true); !ok || seq != -1 {
		t.Errorf("a client without connection IDs: %d, %v", seq, ok)
	}
}

// resend makes the server's probe timeout fire, as when what it sent last
// was lost, and takes what it sends then.
func (tc *testClient) resend() {
	tc.t.Helper()
	at := tc.c.Deadline()
	if at == 0 {
		tc.t.Fatal("the server waits for nothing")
	}
	tc.now = at
	tc.c.OnTimer(tc.now)
	tc.pump()
}

// Connection IDs on the wire, this side's: the client is sent the ones it
// is given, again when they are lost; what it gives back is told to the
// owner of the sockets; and a packet that names another one than the
// client used so far is one sent on purpose from where it comes from.
func TestCID_OnTheWire(t *testing.T) {
	tc := newTestClient(t, nil)
	first := append([]byte(nil), tc.dcid...)
	if n := tc.c.WantCIDs(); n != 3 {
		t.Fatalf("after the handshake the client may be given %d connection IDs, want 3", n)
	}
	var cids, tokens [3][]byte
	for i := range cids {
		cids[i], tokens[i] = randomBytes(CIDLen), randomBytes(16)
		if !tc.c.AddCID(cids[i], tokens[i]) {
			t.Fatalf("connection ID %d not taken", i+1)
		}
	}
	check := func(what string) {
		t.Helper()
		frames, _ := tc.take()
		n := 0
		for _, f := range frames {
			if f.Type != FrameNewConnectionID {
				continue
			}
			if n < 3 && (f.Seq != uint64(n+1) || f.RetirePriorTo != 0 || string(f.CID) != string(cids[n]) || string(f.ResetToken) != string(tokens[n])) {
				t.Errorf("%s: NEW_CONNECTION_ID %d: sequence number %d, Retire Prior To %d, % x, token % x", what, n+1, f.Seq, f.RetirePriorTo, f.CID, f.ResetToken)
			}
			n++
		}
		if n != 3 {
			t.Errorf("%s: %d NEW_CONNECTION_ID frames, want 3", what, n)
		}
	}
	tc.pump()
	check("sent")
	tc.resend()
	check("sent again after a loss")
	tc.acknowledge()
	tc.pump()
	if frames, _ := tc.take(); len(frames) != 0 {
		t.Errorf("after the acknowledgement the server sent %+v", frames)
	}

	// The client gives back the handshake's, in a packet for another one.
	tc.c.Recv(tc.now, tc.packet(cids[0], AppendFrame1(nil, FrameRetireConnectionID, 0)))
	if cid, ok := tc.c.RetiredCID(); !ok || string(cid[:]) != string(first) {
		t.Errorf("given back: % x (%v), want the handshake's % x", cid, ok, first)
	}
	if n := tc.c.WantCIDs(); n != 1 {
		t.Errorf("after one was given back the client may be given %d, want 1", n)
	}
	// From another address: with the connection ID the client uses by
	// now, and with one it has not used.
	if info := tc.c.RecvFrom(tc.now, tc.packet(cids[0], []byte{FramePing})); !info.Packets || info.OtherCID {
		t.Errorf("a packet with the connection ID in use, from another address: %+v", info)
	}
	if info := tc.c.RecvFrom(tc.now, tc.packet(cids[1], []byte{FramePing})); !info.Packets || !info.OtherCID {
		t.Errorf("a packet with another connection ID, from another address: %+v", info)
	}
	if err := tc.c.Err(); err != nil {
		t.Errorf("the connection: %v", err)
	}
}

// Connection IDs on the wire, the client's: when the client takes the one
// in use out of use, this side's packets name the next one and the client
// is told the old one is done with, again when that was lost; a probe to
// another address names the one chosen for it, and so does everything
// after the connection has moved there.
func TestCID_ClientsOnTheWire(t *testing.T) {
	tc := newTestClient(t, nil)
	second, third := randomBytes(CIDLen), randomBytes(CIDLen)
	retired := func(what string, seq uint64) {
		t.Helper()
		frames, _ := tc.take()
		if f, ok := has(frames, FrameRetireConnectionID); !ok || f.Seq != seq {
			t.Errorf("%s: RETIRE_CONNECTION_ID %+v (%v), want one for sequence number %d", what, f.Seq, ok, seq)
		}
	}
	tc.send(AppendNewConnectionID(nil, 1, 1, second, randomBytes(16)))
	retired("after Retire Prior To 1", 0)
	if string(tc.named) != string(second) {
		t.Errorf("after Retire Prior To 1 the server's packets name % x, want % x", tc.named, second)
	}
	tc.resend()
	retired("again after a loss", 0)
	tc.acknowledge()
	tc.pump()
	if frames, _ := tc.take(); len(frames) != 0 {
		t.Errorf("after the acknowledgement the server sent %+v", frames)
	}

	// The client moves on purpose: the probe to its new address names a
	// connection ID that was not used before.
	tc.send(AppendNewConnectionID(nil, 2, 1, third, randomBytes(16)))
	seq, ok := tc.c.PathCID(true)
	if !ok || seq != 2 {
		t.Fatalf("the connection ID for a move on purpose: %d, %v; want 2", seq, ok)
	}
	challenge := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	tc.recv(tc.buf[:tc.c.AppendProbe(tc.buf, &challenge, nil, seq)])
	if string(tc.named) != string(third) {
		t.Errorf("the probe names % x, want the connection ID chosen for the address, % x", tc.named, third)
	}
	tc.take()
	tc.pump()
	if frames, _ := tc.take(); len(frames) != 0 || string(tc.named) != string(third) {
		// nothing was sent by the connection's path: named is still the probe's
		t.Errorf("before the move the connection's own path carried %+v", frames)
	}
	tc.c.Migrated(tc.now, seq)
	tc.pump()
	retired("after the move", 1)
	if string(tc.named) != string(third) {
		t.Errorf("after the move the server's packets name % x, want % x", tc.named, third)
	}
	if err := tc.c.Err(); err != nil {
		t.Errorf("the connection: %v", err)
	}
}
