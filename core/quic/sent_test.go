package quic

import (
	"testing"
)

// The packets that wait for their acknowledgement leave at the front and
// join at the back. Their buffer does not grow with how many pass through
// it, only with how many wait at once (twice that, at the most four times
// after the window has shrunk), and one that a large window left behind is
// let go of when nothing waits.
func TestSpace_PacketsThatWait(t *testing.T) {
	var sp space
	next := int64(0)
	check := func(when string, first int64, n int) {
		t.Helper()
		if len(sp.sent) != n {
			t.Fatalf("%s: %d packets wait, want %d", when, len(sp.sent), n)
		}
		for i := range sp.sent {
			if sp.sent[i].pn != first+int64(i) {
				t.Fatalf("%s: packet %d waits in place %d, want packet %d", when, sp.sent[i].pn, i, first+int64(i))
			}
		}
	}
	// A window of 1,000: a hundred thousand packets pass, ten at a time.
	for ; next < 1000; next++ {
		sp.push(sentPacket{pn: next})
	}
	check("after the first thousand", 0, 1000)
	for first := int64(0); first < 100000; first += 10 {
		sp.settle(0, 10) // the ten at the front are acknowledged
		for i := 0; i < 10; i++ {
			sp.push(sentPacket{pn: next})
			next++
		}
	}
	check("after a hundred thousand", 100000, 1000)
	if c := cap(sp.sentBuf); c < 1000 || c > 4096 {
		t.Errorf("the buffer has room for %d packets with 1,000 waiting, want no more than four times that", c)
	}
	// Some of the first ten stay (they were not acknowledged): they keep
	// their order, in front of the rest.
	sp.sent[1], sp.sent[2] = sp.sent[4], sp.sent[7] // the caller moved the ones that stay to the front: 0, 4, 7
	sp.settle(3, 10)
	if len(sp.sent) != 993 || sp.sent[0].pn != 100000 || sp.sent[1].pn != 100004 || sp.sent[2].pn != 100007 || sp.sent[3].pn != 100010 || sp.sent[992].pn != 100999 {
		t.Fatalf("after seven of the first ten were acknowledged: %d wait, the first are %d, %d, %d, %d", len(sp.sent), sp.sent[0].pn, sp.sent[1].pn, sp.sent[2].pn, sp.sent[3].pn)
	}
	// All acknowledged: the large buffer goes; a small one stays.
	sp.settle(0, len(sp.sent))
	if sp.sent != nil || sp.sentBuf != nil {
		t.Errorf("nothing waits, and a buffer for %d packets is kept", cap(sp.sentBuf))
	}
	for i := int64(0); i < 20; i++ {
		sp.push(sentPacket{pn: next + i})
	}
	sp.settle(0, 20)
	if cap(sp.sentBuf) == 0 || cap(sp.sentBuf) > sentKeep {
		t.Errorf("after 20 packets a buffer for %d is kept, want a small one", cap(sp.sentBuf))
	}
	sp.push(sentPacket{pn: 7})
	check("one more", 7, 1)
}

// Acknowledgements that come out of order, for packets in the middle of
// those that wait: the acknowledged ones are settled, the ones sent three
// or more before the largest acknowledged are given up, the one or two
// just before it stay, in order, and what was sent after it is untouched.
// What is counted in flight is what the packets that wait weigh, at every
// step; and in the end all of the stream arrives.
func TestConn_AcknowledgedOutOfOrder(t *testing.T) {
	sendBaseline(t)
	tc, _ := sendClient(t)
	c := tc.c
	c.cc.ssthresh, c.cc.cwnd = 0, 40*c.cc.mds
	id := openUni(t, c)
	const size = 100 << 10
	if n := c.StreamWrite(id, make([]byte, size), true); n != size {
		t.Fatalf("the stream took %d of %d bytes", n, size)
	}
	tc.now += 1e6
	tc.pump()
	sp := &c.spaces[LevelApplication]
	var pns []int64
	for i := range sp.sent {
		pns = append(pns, sp.sent[i].pn)
	}
	if len(pns) < 38 || pns[len(pns)-1]-pns[0] != int64(len(pns)-1) {
		t.Fatalf("%d packets wait, numbered %d to %d; the test needs about 40 in a row", len(pns), pns[0], pns[len(pns)-1])
	}
	waits := map[int64]bool{}
	for _, pn := range pns {
		waits[pn] = true
	}
	largest := int64(-1)
	ack := func(lo, hi int) {
		t.Helper()
		c.Recv(tc.now, tc.packet(tc.dcid, AppendAck(nil, 0, [][2]uint64{{uint64(pns[lo]), uint64(pns[hi])}})))
		if err := c.Err(); err != nil {
			t.Fatalf("after the acknowledgement of %d to %d: %v", lo, hi, err)
		}
		largest = max(largest, pns[hi])
		for pn := range waits {
			if pn >= pns[lo] && pn <= pns[hi] || largest-pn >= packetThreshold {
				delete(waits, pn)
			}
		}
		flying, last := int64(0), int64(-1)
		for i := range sp.sent {
			p := &sp.sent[i]
			if !waits[p.pn] || p.pn <= last {
				t.Fatalf("after the acknowledgement of %d to %d: packet %d waits (behind %d), want %d packets, in order: %v", lo, hi, p.pn-pns[0], last-pns[0], len(waits), waits)
			}
			last = p.pn
			flying += int64(p.size)
		}
		if len(sp.sent) != len(waits) {
			t.Fatalf("after the acknowledgement of %d to %d: %d packets wait, want %d", lo, hi, len(sp.sent), len(waits))
		}
		if flying != c.cc.inFlight {
			t.Fatalf("after the acknowledgement of %d to %d: %d bytes counted in flight, the packets that wait weigh %d", lo, hi, c.cc.inFlight, flying)
		}
	}
	ack(10, 14) // 0 to 9 are given up; 15 on wait
	ack(30, 31) // 15 to 28 are given up; 29 stays, 32 on wait
	if len(waits) != len(pns)-32+1 {
		t.Fatalf("the test's own count: %d wait", len(waits))
	}
	ack(29, 29)                 // the one that stayed
	ack(12, 13)                 // acknowledged before: nothing changes
	ack(33, 33)                 // 32 stays: one before the largest
	ack(len(pns)-1, len(pns)-1) // the last: all before it but two are given up
	if len(sp.sent) != 2 {
		t.Fatalf("%d packets wait at the end, want the two before the last", len(sp.sent))
	}
	// What was given up is sent again, and all of the stream arrives.
	for i := 0; i < 300 && c.sendHeld > 0; i++ {
		tc.round()
	}
	if c.sendHeld != 0 || len(sp.sent) != 0 || c.cc.inFlight != 0 {
		t.Errorf("at the end %d bytes are held, %d packets wait, %d bytes are in flight", c.sendHeld, len(sp.sent), c.cc.inFlight)
	}
}

// Only packets sent before one that is acknowledged are given up for
// being old: one sent after the largest acknowledged packet is not, however
// long ago that was (the probe timeout is what covers it). Ten packets go
// out together; the second is acknowledged; when the first is given up for
// its age, the eight behind the acknowledged one, just as old, still wait.
func TestConn_OnlyPacketsBeforeAnAcknowledgedOneAreGivenUp(t *testing.T) {
	sendBaseline(t)
	tc, _ := sendClient(t)
	c := tc.c
	c.cc.ssthresh, c.cc.cwnd = 0, 10*c.cc.mds
	id := openUni(t, c)
	if n := c.StreamWrite(id, make([]byte, 64<<10), false); n != 64<<10 {
		t.Fatalf("the stream took %d bytes", n)
	}
	tc.now += 1e6
	tc.pump()
	sp := &c.spaces[LevelApplication]
	if len(sp.sent) < 9 {
		t.Fatalf("%d packets wait, the test needs about ten", len(sp.sent))
	}
	first, n := sp.sent[0].pn, len(sp.sent)
	// The second packet is acknowledged 10 ms later: the first stays (it
	// is one before the largest, and not old enough yet).
	tc.now += 10e6
	c.Recv(tc.now, tc.packet(tc.dcid, AppendAck(nil, 0, [][2]uint64{{uint64(first + 1), uint64(first + 1)}})))
	if len(sp.sent) != n-1 || sp.sent[0].pn != first || sp.lossAt == 0 {
		t.Fatalf("after the second packet was acknowledged: %d of %d wait, the first is %d (want %d), its time to be given up is %d", len(sp.sent), n, sp.sent[0].pn, first, sp.lossAt)
	}
	window := c.cc.cwnd
	// Its time comes; the probe timeout's has not.
	if sp.lossAt >= c.ptoAt {
		t.Fatalf("the first packet is given up at %d, the probe timeout is at %d: the test needs the first before the second", sp.lossAt, c.ptoAt)
	}
	tc.now = sp.lossAt
	c.OnTimer(tc.now)
	if len(sp.sent) != n-2 {
		t.Fatalf("after the first packet's time %d packets wait, want the %d sent after the acknowledged one", len(sp.sent), n-2)
	}
	if sp.sent[0].pn != first+2 {
		t.Fatalf("after the first packet's time packet %d is the first that waits, want %d", sp.sent[0].pn, first+2)
	}
	if c.cc.cwnd >= window {
		t.Errorf("the window is %d after a packet was given up, %d before", c.cc.cwnd, window)
	}
}
