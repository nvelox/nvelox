package quic

import (
	"math"
	"testing"
)

// download has the server send n bytes on a new stream of its own, round
// by round (a millisecond each: its timers run, the client takes what is
// sent and acknowledges it), until all of it is acknowledged. It returns
// the sizes of the datagrams that reached the client. each, when given,
// is called at the end of every round.
func (tc *testClient) download(n int, each ...func()) (sizes []int) {
	tc.t.Helper()
	c := tc.c
	id := openUni(tc.t, c)
	data := make([]byte, n)
	off := 0
	for i := 0; off < n || c.sendHeld > 0; i++ {
		if i == 20000 {
			tc.t.Fatalf("after %d ms %d of %d bytes are written and %d wait for their acknowledgement (datagrams of %d bytes, state %d)", i, off, n, c.sendHeld, c.DatagramSize(), c.state)
		}
		off += c.StreamWrite(id, data[off:], true)
		tc.now += 1e6
		if at := c.Deadline(); at != 0 && at <= tc.now {
			c.OnTimer(tc.now)
		}
		tc.pump()
		tc.acknowledge()
		_, s := tc.take()
		sizes = append(sizes, s...)
		for _, f := range each {
			f()
		}
	}
	return sizes
}

// largeClient is a sendClient that takes datagrams of any size the server
// may send, and whose largest it says it takes is maxPayload (0: it says
// nothing).
func largeClient(t *testing.T, maxPayload uint64) *testClient {
	t.Helper()
	limits := map[uint64]uint64{paramMaxStreamDataUni: 64 << 20, paramInitialMaxData: 64 << 20}
	if maxPayload != 0 {
		limits[paramMaxUDPPayloadSize] = maxPayload
	}
	tc := newTestClient(t, func(cfg *Config) { cfg.Handler = &writers{} }, limits)
	tc.large = true
	return tc
}

// The sizes tried: the largest a datagram may have first, each smaller
// than the one before it, and every one more than every path carries (a
// size that is not could not be told from what is sent anyway, and would
// be tried for ever).
func TestMTU_Sizes(t *testing.T) {
	if mtuSizes[0] != MaxDatagramSize {
		t.Errorf("the first size tried is %d, want the largest a datagram may have, %d", mtuSizes[0], MaxDatagramSize)
	}
	for i, s := range mtuSizes {
		if s <= maxDatagram || i > 0 && s >= mtuSizes[i-1] {
			t.Errorf("size %d of those tried is %d: want more than %d, and less than the one before it", i, s, maxDatagram)
		}
	}
}

// A connection that sends more than a few datagrams finds out that its
// path carries larger ones, and uses them: one datagram of the largest
// size with nothing in it, after the first 64 KiB, and when that is
// acknowledged every full datagram is of that size.
func TestMTU_APathThatCarriesMoreIsUsed(t *testing.T) {
	sendBaseline(t)
	tc := largeClient(t, 0)
	sizes := tc.download(1 << 20)
	if got := tc.c.DatagramSize(); got != MaxDatagramSize {
		t.Fatalf("after a megabyte the connection sends datagrams of %d bytes, want %d", got, MaxDatagramSize)
	}
	first, before, large := -1, 0, 0
	for i, s := range sizes {
		switch {
		case s > MaxDatagramSize:
			t.Fatalf("a datagram of %d bytes", s)
		case s > maxDatagram:
			if first < 0 {
				first = i
			}
			large++
		case first < 0:
			before += s
		}
	}
	if first < 0 || sizes[first] != MaxDatagramSize {
		t.Fatalf("the first datagram above %d bytes is number %d of %d, want one of %d", maxDatagram, first, len(sizes), MaxDatagramSize)
	}
	if before < mtuAfter || before > mtuAfter+256<<10 {
		t.Errorf("the first large datagram came after %d bytes, want it soon after the first %d", before, mtuAfter)
	}
	// What follows is the megabyte's rest in datagrams of the larger size.
	if want := (1<<20 - before) / MaxDatagramSize; large < want*9/10 {
		t.Errorf("%d datagrams above %d bytes, want about %d", large, maxDatagram, want)
	}
	if tc.c.cc.mds != MaxDatagramSize {
		t.Errorf("the congestion window still counts in datagrams of %d bytes", tc.c.cc.mds)
	}
	// The size is found: nothing more is tried, and nothing but full
	// datagrams of data is that large.
	if !tc.c.done || tc.c.flying {
		t.Errorf("the connection goes on trying sizes after it found one (nothing more is tried: %v, a size is being tried: %v)", tc.c.done, tc.c.flying)
	}
}

// A path that carries less than the largest size: the datagram that tries
// it is lost, twice, which is no sign of congestion (the window is not
// reduced), and the next smaller size, which arrives, is what the
// connection uses.
func TestMTU_APathThatCarriesLess(t *testing.T) {
	sendBaseline(t)
	tc := largeClient(t, 0)
	var dropped []int
	tc.drop = func(size int) bool {
		if size > 1400 {
			dropped = append(dropped, size)
			return true
		}
		return false
	}
	sizes := tc.download(1 << 20)
	c := tc.c
	if got := c.DatagramSize(); got != 1392 {
		t.Fatalf("on a path that carries 1,400 bytes the connection sends datagrams of %d, want 1392", got)
	}
	if len(dropped) != mtuTries || dropped[0] != MaxDatagramSize || dropped[1] != MaxDatagramSize {
		t.Errorf("datagrams the path did not carry: %v, want %d of %d bytes", dropped, mtuTries, MaxDatagramSize)
	}
	if c.cc.ssthresh != math.MaxInt64 {
		t.Errorf("the window was reduced (slow start ended at %d bytes) though nothing but the two trial datagrams was lost", c.cc.ssthresh)
	}
	for _, s := range sizes {
		if s > 1392 {
			t.Fatalf("a datagram of %d bytes arrived", s)
		}
	}
}

// The client says how large a datagram it takes: nothing larger is tried.
// One that takes 1,300 bytes gets 1,300; one that takes 1,200 gets what
// every path carries, and nothing is tried at all.
func TestMTU_NothingTheClientDoesNotTake(t *testing.T) {
	sendBaseline(t)
	for _, tt := range []struct {
		takes uint64
		want  int
	}{{1300, 1300}, {1451, 1392}, {1200, maxDatagram}, {1251, maxDatagram}} {
		tc := largeClient(t, tt.takes)
		sizes := tc.download(512 << 10)
		if got := tc.c.DatagramSize(); got != tt.want {
			t.Errorf("a client that takes %d bytes is sent datagrams of %d, want %d", tt.takes, got, tt.want)
		}
		for _, s := range sizes {
			if uint64(s) > tt.takes {
				t.Fatalf("a client that takes %d bytes was sent a datagram of %d", tt.takes, s)
			}
		}
		if !tc.c.done {
			t.Errorf("a client that takes %d bytes: the connection is still trying sizes after half a megabyte", tt.takes)
		}
	}
}

// The datagram that tries a larger size is held back by what holds data
// back: while the congestion window has no room it waits, and it leaves
// when there is room for a datagram.
func TestMTU_TheTryWaitsForRoomInTheWindow(t *testing.T) {
	sendBaseline(t)
	tc := largeClient(t, 0)
	c := tc.c
	id := openUni(t, c)
	data := make([]byte, 256<<10)
	// A window with room for one datagram at a time, until enough is sent
	// for a larger size to be tried. The datagram that got there fills the
	// window, and is not acknowledged yet.
	for i, off := 0, 0; c.sentData-c.from < mtuAfter; i++ {
		if i == 5000 {
			t.Fatalf("after 5 s %d bytes are sent", c.sentData)
		}
		c.cc.cwnd = 0
		tc.acknowledge()
		off += c.StreamWrite(id, data[off:], false)
		c.cc.cwnd = c.cc.inFlight + c.cc.mds
		tc.now += 1e6
		if at := c.Deadline(); at != 0 && at <= tc.now {
			c.OnTimer(tc.now)
		}
		tc.pump()
	}
	if c.flying || c.cc.inFlight == 0 {
		t.Fatalf("the test wants no larger size tried yet and a datagram in flight: a size is being tried: %v, %d bytes in flight", c.flying, c.cc.inFlight)
	}
	tc.take()
	c.cc.cwnd = c.cc.inFlight // no room
	for i := 0; i < 3; i++ {
		tc.now += 1e6
		tc.pump()
	}
	if _, sizes := tc.take(); c.flying || len(sizes) != 0 {
		t.Fatalf("with no room in the window the connection sent datagrams of %v bytes (a size is being tried: %v)", sizes, c.flying)
	}
	c.cc.cwnd = c.cc.inFlight + c.cc.mds // room for a datagram
	tc.now += 1e6
	tc.pump()
	if _, sizes := tc.take(); !c.flying || len(sizes) != 1 || sizes[0] != MaxDatagramSize {
		t.Fatalf("with room in the window the connection sent datagrams of %v bytes (a size is being tried: %v), want one of %d that tries it", sizes, c.flying, MaxDatagramSize)
	}
}

// A caller that has room for less than the largest datagram gets none
// that is larger than its room: nothing is tried, and the download is what
// it would have been.
func TestMTU_NoMoreThanThereIsRoomFor(t *testing.T) {
	sendBaseline(t)
	tc := largeClient(t, 0)
	tc.large = false
	sizes := tc.download(512 << 10)
	for _, s := range sizes {
		if s > maxDatagram {
			t.Fatalf("a datagram of %d bytes for a caller with room for %d", s, maxDatagram)
		}
	}
	if got := tc.c.DatagramSize(); got != maxDatagram {
		t.Errorf("the connection sends datagrams of %d bytes, want %d", got, maxDatagram)
	}
	// And when the size was found with room for it, a call with less room
	// still gets no more than its room.
	tc.large = true
	tc.download(256 << 10)
	if got := tc.c.DatagramSize(); got != MaxDatagramSize {
		t.Fatalf("with room for them the connection sends datagrams of %d bytes, want %d", got, MaxDatagramSize)
	}
	tc.large = false
	for _, s := range tc.download(256 << 10) {
		if s > maxDatagram {
			t.Fatalf("a datagram of %d bytes for a caller with room for %d, after the path was found to carry more", s, maxDatagram)
		}
	}
}

// A connection that answers small requests tries nothing: three hundred
// answers, and no datagram above the size every path carries.
func TestMTU_SmallAnswersAreLeftAlone(t *testing.T) {
	sendBaseline(t)
	tc := newTestClient(t, nil) // the echo handler
	tc.large = true
	for i := 0; i < 300; i++ {
		body := make([]byte, 100)
		tc.send(append(AppendStreamHeader(nil, uint64(4*i), 0, len(body), true), body...))
		tc.round()
	}
	_, sizes := tc.take()
	for _, s := range sizes {
		if s > maxDatagram {
			t.Fatalf("a datagram of %d bytes on a connection that sent %d bytes in all", s, tc.c.sentData)
		}
	}
	if tc.c.sentData >= mtuAfter || tc.c.DatagramSize() != maxDatagram {
		t.Errorf("the connection sent %d bytes (the test wants fewer than %d) in datagrams of %d", tc.c.sentData, mtuAfter, tc.c.DatagramSize())
	}
}

// A path that stops carrying the larger size. When nothing arrives any
// more, two probe timeouts take the connection back to what every path
// carries; when smaller datagrams still arrive and are acknowledged, eight
// large ones lost in a row do. Either way the download is completed, and
// nothing larger is tried on that path again.
func TestMTU_APathThatStopsCarryingMore(t *testing.T) {
	sendBaseline(t)
	for _, name := range []string{"nothing arrives any more", "small datagrams still arrive"} {
		tc := largeClient(t, 0)
		c := tc.c
		tc.download(256 << 10)
		if got := c.DatagramSize(); got != MaxDatagramSize {
			t.Fatalf("%s: before the path changed the connection sent datagrams of %d bytes", name, got)
		}
		// What the connection sends above the size it went back to, and how
		// many probe timeouts in a row had fired when it went back.
		after, timeouts := 0, -1
		tc.drop = func(size int) bool {
			if c.DatagramSize() == maxDatagram {
				if timeouts < 0 {
					timeouts = c.ptoCount
				}
				if size > maxDatagram {
					after++
				}
			} else if name == "nothing arrives any more" {
				// Nothing does: not the stream's short last datagram
				// either, which a window that holds the whole download
				// sends in the same flight as the large ones.
				return true
			}
			return size > maxDatagram
		}
		if name == "small datagrams still arrive" {
			// A stream that sends a piece at a time, each a few full
			// datagrams and a short one behind them. The short ones arrive
			// and are acknowledged, so no probe timeout comes to the rescue:
			// the full ones, lost one after the other, are what tells.
			id := openUni(t, c)
			piece := make([]byte, 3000)
			for i := 0; c.DatagramSize() > maxDatagram; i++ {
				if i == 2000 {
					t.Fatalf("%s: after 2 s the connection still sends datagrams of %d bytes (%d lost in a row)", name, c.DatagramSize(), c.lostLarge)
				}
				c.cc.cwnd = 100 * c.cc.mds // the window is not what holds the stream back
				c.StreamWrite(id, piece, false)
				tc.now += 1e6
				if at := c.Deadline(); at != 0 && at <= tc.now {
					c.OnTimer(tc.now)
				}
				tc.pump()
				tc.acknowledge()
			}
			if c.ptoCount != 0 {
				t.Errorf("%s: %d probe timeouts in a row; the test wants the datagrams lost in a row to be what tells", name, c.ptoCount)
			}
		}
		sizes := tc.download(256 << 10)
		if got := c.DatagramSize(); got != maxDatagram {
			t.Errorf("%s: the connection sends datagrams of %d bytes, want %d", name, got, maxDatagram)
		}
		if !c.done {
			t.Errorf("%s: the connection would try larger datagrams on this path again", name)
		}
		if c.cc.mds != maxDatagram {
			t.Errorf("%s: the congestion window still counts in datagrams of %d bytes", name, c.cc.mds)
		}
		if after != 0 {
			t.Errorf("%s: %d datagrams of more than %d bytes were sent after the connection went back to that size", name, after, maxDatagram)
		}
		if want := map[string]int{"nothing arrives any more": 2, "small datagrams still arrive": 0}[name]; timeouts != want {
			t.Errorf("%s: the connection went back after %d probe timeouts in a row, want %d", name, timeouts, want)
		}
		for _, s := range sizes {
			if s > maxDatagram {
				t.Fatalf("%s: a datagram of %d bytes arrived", name, s)
			}
		}
	}
}

// A client that moves while a larger size is being tried: the datagram
// that tried it went to the address the client has left. Acknowledged or
// not, it says nothing about the new path, where the search starts over.
func TestMTU_AClientThatMovesWhileASizeIsTried(t *testing.T) {
	sendBaseline(t)
	tc := largeClient(t, 0)
	c := tc.c
	id := openUni(t, c)
	data := make([]byte, 512<<10)
	// Until the datagram that tries the larger size has reached the client,
	// which has not acknowledged it yet.
	for i, off, tried := 0, 0, false; !tried; i++ {
		if i == 2000 {
			t.Fatalf("after 2 s no larger datagram was tried (%d bytes sent)", c.sentData)
		}
		off += c.StreamWrite(id, data[off:], false)
		tc.now += 1e6
		if at := c.Deadline(); at != 0 && at <= tc.now {
			c.OnTimer(tc.now)
		}
		tc.pump()
		_, sizes := tc.take()
		for _, s := range sizes {
			tried = tried || s > maxDatagram
		}
		if !tried {
			tc.acknowledge()
		}
	}
	if !c.flying || c.DatagramSize() != maxDatagram {
		t.Fatalf("the test wants a larger size being tried: it is %v, with datagrams of %d bytes", c.flying, c.DatagramSize())
	}
	c.Migrated(tc.now, -1)
	tc.acknowledge() // everything the client has, the datagram that tried included
	if got := c.DatagramSize(); got != maxDatagram || c.flying || c.done {
		t.Fatalf("after the move the connection sends datagrams of %d bytes (a size is being tried: %v, nothing more is tried: %v); want %d, and the search to start over", got, c.flying, c.done, maxDatagram)
	}
	// On the new path the search starts over, and finds what it carries.
	for i := 0; !c.done; i++ {
		if i == 100 {
			t.Fatalf("after a hundred downloads on the new path the connection is still trying (size %d of %d, tried %d times)", c.next, len(mtuSizes), c.tried)
		}
		tc.download(256 << 10)
	}
	if got := c.DatagramSize(); got != MaxDatagramSize {
		t.Errorf("on the new path the connection sends datagrams of %d bytes, want %d", got, MaxDatagramSize)
	}
}

// Loss that is congestion is not a path that stopped carrying the larger
// size, however many datagrams it takes at once. Twenty lost in a row in
// the middle of a download are told of by the acknowledgement of the large
// datagrams sent after them, which arrived: none of the twenty counts. And
// when everything is lost for a moment at the end of an answer, and a
// small datagram behind it is what tells, the lost ones do count, but
// what is sent again arrives: the connection keeps its size.
func TestMTU_CongestionIsNotAPathThatStoppedCarrying(t *testing.T) {
	sendBaseline(t)
	t.Run("in the middle of a download", func(t *testing.T) {
		tc := largeClient(t, 0)
		c := tc.c
		tc.download(256 << 10)
		if got := c.DatagramSize(); got != MaxDatagramSize {
			t.Fatalf("before the loss the connection sent datagrams of %d bytes", got)
		}
		large, lost, worst := 0, 0, 0
		tc.drop = func(size int) bool {
			if size <= maxDatagram {
				return false
			}
			if large++; large > 50 && large <= 70 {
				lost++
				return true
			}
			return false
		}
		tc.download(1<<20, func() { worst = max(worst, c.lostLarge) })
		if lost != 20 || c.cc.ssthresh == math.MaxInt64 {
			t.Fatalf("%d datagrams were lost and the window was reduced: %v; the test wants twenty lost, and that to be congestion", lost, c.cc.ssthresh != math.MaxInt64)
		}
		if worst != 0 {
			t.Errorf("%d of the lost datagrams counted toward a path that stopped carrying them, though large datagrams sent after them arrived", worst)
		}
		if got := c.DatagramSize(); got != MaxDatagramSize {
			t.Errorf("after twenty datagrams lost at once the connection sends datagrams of %d bytes, want %d", got, MaxDatagramSize)
		}
	})
	t.Run("at the end of an answer", func(t *testing.T) {
		tc := largeClient(t, 0)
		c := tc.c
		tc.download(256 << 10)
		if got := c.DatagramSize(); got != MaxDatagramSize {
			t.Fatalf("before the loss the connection sent datagrams of %d bytes", got)
		}
		round := func() {
			tc.now += 1e6
			if at := c.Deadline(); at != 0 && at <= tc.now {
				c.OnTimer(tc.now)
			}
			tc.pump()
		}
		// Forty KiB, all of it lost on the way.
		all, large := true, 0
		tc.drop = func(size int) bool {
			if all && size > maxDatagram {
				large++
			}
			return all
		}
		a := openUni(t, c)
		c.cc.cwnd = 100 * c.cc.mds // the window is not what holds the answer back
		if n := c.StreamWrite(a, make([]byte, 40<<10), true); n != 40<<10 {
			t.Fatalf("%d of 40 KiB written", n)
		}
		for i := 0; i < 5; i++ {
			round()
		}
		if large < 20 || c.ptoCount != 0 {
			t.Fatalf("%d large datagrams were lost and %d probe timeouts fired; the test wants at least twenty and none", large, c.ptoCount)
		}
		// A small datagram behind them arrives, and its acknowledgement tells.
		all = false
		b := openUni(t, c)
		c.StreamWrite(b, []byte("a small answer"), true)
		round()
		tc.acknowledge()
		if c.lostLarge < mtuBlackHole {
			t.Fatalf("%d large datagrams are known to be lost; the test wants at least %d, told of by a small one", c.lostLarge, mtuBlackHole)
		}
		if got := c.DatagramSize(); got != MaxDatagramSize {
			t.Fatalf("with %d large datagrams lost at once, and nothing sent again yet, the connection sends datagrams of %d bytes", c.lostLarge, got)
		}
		// What is sent again arrives.
		for i := 0; c.sendHeld > 0; i++ {
			if i == 2000 {
				t.Fatalf("after 2 s %d bytes still wait for their acknowledgement", c.sendHeld)
			}
			round()
			tc.acknowledge()
		}
		if got := c.DatagramSize(); got != MaxDatagramSize || c.lostLarge != 0 {
			t.Errorf("after the answer arrived the connection sends datagrams of %d bytes, with %d large ones counted as lost; want %d and none", got, c.lostLarge, MaxDatagramSize)
		}
	})
}

// The rule that tells a path that stopped carrying the larger size from
// congestion, packet by packet. (The packets are made up: only their
// numbers, their sizes and what became of them matter to the rule.)
func TestMTU_TheRuleByPacketNumber(t *testing.T) {
	sendBaseline(t)
	tc := largeClient(t, 0)
	c := tc.c
	tc.download(256 << 10)
	if got := c.DatagramSize(); got != MaxDatagramSize {
		t.Fatalf("the connection sends datagrams of %d bytes", got)
	}
	sp := &c.spaces[LevelApplication]
	n := sp.nextPN // the first of the made-up packets
	const large, small = MaxDatagramSize, 300
	count := func(when string, want int) {
		t.Helper()
		if c.lostLarge != want || c.DatagramSize() != MaxDatagramSize {
			t.Fatalf("%s: %d large datagrams count as lost (want %d), and the connection sends datagrams of %d bytes", when, c.lostLarge, want, c.DatagramSize())
		}
	}
	sp.nextPN = n + 100 // a hundred packets are sent
	c.mtuSettled(n+10, large, false)
	count("a large datagram arrived", 0)
	c.mtuSettled(n+3, large, true)
	count("a large datagram sent before the last that arrived is lost", 0)
	for i := int64(0); i < 7; i++ {
		c.mtuSettled(n+12+i, large, true)
	}
	count("seven large datagrams sent after it are lost", 7)
	c.mtuSettled(n+11, small, true)
	c.mtuSettled(n+40, small, false)
	count("small datagrams are lost and arrive", 7)
	c.mtuSettled(n+5, large, false)
	count("a large datagram sent before the last that arrived is acknowledged late", 7)
	// More of what was sent before the loss was known: however many they
	// are, the path is not given up for them.
	for i := int64(0); i < 20; i++ {
		c.mtuSettled(n+50+i, large, true)
	}
	count("twenty more of the packets sent before the loss was known are lost", 27)
	// A large datagram sent after all of them arrives: congestion it was.
	c.mtuSettled(n+99, large, false)
	count("a large datagram sent after all of them arrived", 0)
	// Once more, and now what is sent when the loss is known is lost too:
	// the eighth datagram is what tells, not the seventh.
	sp.nextPN = n + 200
	for i := int64(0); i < 6; i++ {
		c.mtuSettled(n+100+i, large, true)
	}
	count("six large datagrams are lost, all of them sent before the loss was known", 6)
	c.mtuSettled(n+200, large, true)
	count("a seventh is lost, sent when the loss was known", 7)
	c.mtuSettled(n+201, large, true)
	if got := c.DatagramSize(); got != maxDatagram || !c.done {
		t.Fatalf("an eighth is lost, sent when the loss was known: the connection sends datagrams of %d bytes (nothing more is tried: %v), want %d", got, c.done, maxDatagram)
	}
}

// A client that moves has a new path, about which nothing is known: the
// connection sends what every path carries, and finds out again.
func TestMTU_AClientThatMovesStartsOver(t *testing.T) {
	sendBaseline(t)
	tc := largeClient(t, 0)
	c := tc.c
	tc.download(256 << 10)
	if got := c.DatagramSize(); got != MaxDatagramSize {
		t.Fatalf("before the move the connection sent datagrams of %d bytes", got)
	}
	c.Migrated(tc.now, -1)
	if got := c.DatagramSize(); got != maxDatagram || c.cc.mds != maxDatagram {
		t.Fatalf("after the move the connection sends datagrams of %d bytes (window counted in %d), want %d", got, c.cc.mds, maxDatagram)
	}
	// The new path carries 1,300 bytes: three sizes are tried in vain,
	// twice each, before the fourth arrives. That takes a few round trips;
	// the connection goes on sending meanwhile.
	moved, first := c.sentData, uint64(0)
	tc.drop = func(size int) bool {
		if size > maxDatagram && first == 0 {
			first = c.sentData - moved
		}
		return size > 1300
	}
	for i := 0; !c.done; i++ {
		if i == 100 {
			t.Fatalf("after a hundred downloads on the new path the connection is still trying (size %d of %d, tried %d times)", c.next, len(mtuSizes), c.tried)
		}
		tc.download(256 << 10)
	}
	if got := c.DatagramSize(); got != 1300 {
		t.Errorf("on the new path, which carries 1,300 bytes, the connection sends datagrams of %d", got)
	}
	if first < mtuAfter {
		t.Errorf("on the new path a larger datagram was tried after %d bytes, want none before %d", first, mtuAfter)
	}
}
