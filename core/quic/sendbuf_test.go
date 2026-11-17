package quic

import (
	"testing"
)

// writers is a handler that notes which streams were told they may write
// again, in order, and takes whatever arrives.
type writers struct {
	told []uint64
	// write, when set, is what a stream writes when it is told.
	write func(c *Conn, id uint64)
}

func (w *writers) StreamData(c *Conn, id uint64, data []byte, fin bool) {
	c.StreamConsumed(id, len(data))
}
func (w *writers) StreamReset(c *Conn, id uint64, code uint64) {}
func (w *writers) StreamStop(c *Conn, id uint64, code uint64)  {}
func (w *writers) StreamWritable(c *Conn, id uint64) {
	w.told = append(w.told, id)
	if w.write != nil {
		w.write(c, id)
	}
}

// sendBaseline returns the process's count of what connections hold to
// send as it is before a test, and checks at the test's end, when its
// connections are gone, that it is that again.
func sendBaseline(t testing.TB) int64 {
	t.Helper()
	before := SendMemory()
	t.Cleanup(func() {
		SetSendMemory(0)
		if got := SendMemory(); got != before {
			t.Errorf("the process's connections hold %d bytes to send after the test, %d before it", got, before)
		}
	})
	return before
}

// sendClient is a test client whose server tells w about its streams. Its
// own limits are far away (64 MiB for a stream and for all together): what
// holds the server's streams back is the buffer.
func sendClient(t testing.TB) (*testClient, *writers) {
	t.Helper()
	return limitedClient(t, 64<<20, 64<<20)
}

// round lets a millisecond pass, in which the client takes what the server
// sends and acknowledges it.
func (tc *testClient) round() {
	tc.t.Helper()
	tc.now += 1e6
	tc.pump()
	tc.acknowledge()
}

// openUni opens a stream of the server's to write on.
func openUni(t testing.TB, c *Conn) uint64 {
	t.Helper()
	id, ok := c.OpenUniStream()
	if !ok {
		t.Fatal("the client allows no stream")
	}
	return id
}

// The most a connection holds is no less than the largest window there is:
// else such a window could not be in flight whole, and the buffer, not the
// path, would be what holds a download back.
func TestSend_BufferHoldsTheLargestWindow(t *testing.T) {
	if largest := maxWindowPackets * MaxDatagramSize; sendBufferMax < largest {
		t.Errorf("a connection holds at most %d bytes, and the largest window is %d", sendBufferMax, largest)
	}
}

// The upper end of the buffer is the configuration's (Config.MaxSendBuffer):
// with a window however large a connection holds that much and no more,
// whether it is less than sendBufferMax or more. It is never less than
// sendBufferMin, which a connection may hold whatever its window is, and
// with nothing configured it is sendBufferMax.
func TestSend_BufferConfigured(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int64
		want       int
	}{
		{"less than the default", 1 << 20, 1 << 20},
		{"more than the default", 24 << 20, 24 << 20},
		{"nothing configured", 0, sendBufferMax},
		{"less than a connection always may hold", 4 << 10, sendBufferMin},
	} {
		base := sendBaseline(t)
		w := &writers{}
		c := newTestClient(t, func(cfg *Config) { cfg.Handler, cfg.MaxSendBuffer = w, tc.configured },
			map[uint64]uint64{paramMaxStreamDataUni: 64 << 20, paramInitialMaxData: 64 << 20}).c
		data := make([]byte, 32<<20)
		id := openUni(t, c)
		if n := c.StreamWrite(id, data, false); n != sendBufferMin {
			t.Errorf("%s: a new connection took %d bytes, want %d", tc.name, n, sendBufferMin)
		}
		c.cc.cwnd = 64 << 20
		c.StreamWrite(id, data, false)
		if c.sendHeld != tc.want {
			t.Errorf("%s: with a window of 64 MiB the connection holds %d bytes, want %d", tc.name, c.sendHeld, tc.want)
		}
		if n := c.StreamWrite(id, data, false); n != 0 {
			t.Errorf("%s: a full buffer took %d more bytes", tc.name, n)
		}
		// Under the process's bound a connection takes what is left, and
		// no more of it than its own buffer holds.
		c.Abandon()
		SetSendMemory(base + 48<<20)
		c = newTestClient(t, func(cfg *Config) { cfg.Handler, cfg.MaxSendBuffer = w, tc.configured },
			map[uint64]uint64{paramMaxStreamDataUni: 64 << 20, paramInitialMaxData: 64 << 20}).c
		c.cc.cwnd = 64 << 20
		c.StreamWrite(openUni(t, c), data, false)
		if c.sendHeld != tc.want {
			t.Errorf("%s: with 48 MiB left under the process's bound the connection holds %d bytes, want %d", tc.name, c.sendHeld, tc.want)
		}
		c.Abandon()
		SetSendMemory(0)
	}
}

// What a connection's streams hold together to send follows its
// congestion window: twice the window, at least sendBufferMin, at most
// sendBufferMax. A stream alone may hold all of it (a download is not held
// to a fixed amount per round trip); two streams share it.
func TestSend_BufferFollowsTheWindow(t *testing.T) {
	base := sendBaseline(t)
	tc, _ := sendClient(t)
	c := tc.c
	data := make([]byte, 16<<20)
	a := openUni(t, c)
	if n := c.StreamWrite(a, data, false); n != sendBufferMin {
		t.Fatalf("a new connection (window %d) took %d bytes, want %d", c.cc.cwnd, n, sendBufferMin)
	}
	if n := c.StreamWrite(a, data, false); n != 0 {
		t.Errorf("a full buffer took %d more bytes", n)
	}
	// The window grows, as it does when a client takes what it is sent.
	c.cc.cwnd = 1 << 20
	if n := c.StreamWrite(a, data, false); n != 2<<20-sendBufferMin {
		t.Errorf("with a window of 1 MiB the stream took %d more bytes, want up to twice the window in all (%d more)", n, 2<<20-sendBufferMin)
	}
	// Another stream of the connection finds it full, and gets what the
	// window adds.
	b := openUni(t, c)
	if n := c.StreamWrite(b, data, false); n != 0 {
		t.Errorf("a second stream took %d bytes of a full buffer", n)
	}
	c.cc.cwnd = 64 << 20
	if n := c.StreamWrite(b, data, false); n != sendBufferMax-2<<20 {
		t.Errorf("with a window of 64 MiB the second stream took %d bytes, want the rest of %d", n, sendBufferMax)
	}
	if c.sendHeld != sendBufferMax {
		t.Errorf("the connection holds %d bytes, want %d", c.sendHeld, sendBufferMax)
	}
	if got := SendMemory() - base; got < sendBufferMax-sendStep || got > sendBufferMax+sendStep {
		t.Errorf("the process's count went up by %d, the connection holds %d", got, sendBufferMax)
	}
	// A window that shrinks takes nothing back; nothing more is taken.
	c.cc.cwnd = 12000
	if n := c.StreamWrite(b, data, false); n != 0 {
		t.Errorf("after the window shrank a stream took %d more bytes", n)
	}
}

// All the connections of a process together hold no more than
// SetSendMemory allows: a connection takes what is left under the bound,
// and past it sendBufferLow at a time, so that it still gets somewhere.
func TestSend_ProcessBound(t *testing.T) {
	sendBaseline(t)
	tc, _ := sendClient(t)
	other, _ := sendClient(t)
	data := make([]byte, 1<<20)
	a := openUni(t, tc.c)
	if n := tc.c.StreamWrite(a, data, false); n != sendBufferMin {
		t.Fatalf("the first connection took %d bytes, want %d", n, sendBufferMin)
	}
	SetSendMemory(SendMemory()) // the bound is reached
	b := openUni(t, other.c)
	if n := other.c.StreamWrite(b, data, false); n != sendBufferLow {
		t.Errorf("past the bound a connection that holds nothing took %d bytes, want %d", n, sendBufferLow)
	}
	if n := other.c.StreamWrite(b, data, false); n != 0 {
		t.Errorf("past the bound a connection that holds %d took %d more", sendBufferLow, n)
	}
	if n := tc.c.StreamWrite(a, data, false); n != 0 {
		t.Errorf("past the bound the connection that holds most took %d more", n)
	}
	SetSendMemory(0)
	if n := other.c.StreamWrite(b, data, false); n != sendBufferMin-sendBufferLow {
		t.Errorf("with the bound lifted the connection took %d more bytes, want %d", n, sendBufferMin-sendBufferLow)
	}
	// With room for 100 KiB under the bound, a connection takes that.
	third, _ := sendClient(t)
	SetSendMemory(SendMemory() + 100<<10)
	if n := third.c.StreamWrite(openUni(t, third.c), data, false); n != 100<<10 {
		t.Errorf("with 100 KiB left under the bound a connection took %d bytes", n)
	}
}

// Streams that found the buffer full are told when there is room again:
// the one that waits longest first, and not one that was reset in the
// meantime. Room the client makes (it acknowledges) is told of at once;
// room the application makes itself (it resets a stream) is told of from
// OnTimer, due at once, never from within the application's own call.
func TestSend_WaitingStreamsAreTold(t *testing.T) {
	sendBaseline(t)
	tc, w := sendClient(t)
	c := tc.c
	data := make([]byte, 1<<20)
	a, b, d := openUni(t, c), openUni(t, c), openUni(t, c)
	if n := c.StreamWrite(a, data, false); n != sendBufferMin {
		t.Fatalf("the first stream took %d bytes", n)
	}
	// Stream a found the buffer full with its first write; b and d find
	// it full now.
	for _, id := range []uint64{b, d, a} {
		if n := c.StreamWrite(id, data[:100], false); n != 0 {
			t.Fatalf("stream %d took %d bytes of a full buffer", id, n)
		}
	}
	if len(c.waiting) != 3 {
		t.Errorf("%d streams are in line for room, want 3: one that asks again while it waits is in line once", len(c.waiting))
	}
	// The client takes what is sent and acknowledges it, until there is
	// room for more.
	for i := 0; i < 50 && len(w.told) == 0; i++ {
		tc.round()
	}
	if len(w.told) != 3 || w.told[0] != a || w.told[1] != b || w.told[2] != d {
		t.Fatalf("told to write again: streams %v, want %d, %d, %d: in the order they found the buffer full", w.told, a, b, d)
	}
	if room := c.sendBudget() - c.sendHeld; room < sendWake {
		t.Errorf("streams were told with room for %d bytes, want %d at least", room, sendWake)
	}
	w.told = nil
	// Full again, all three waiting, a first. The application resets b,
	// which holds nothing: no room is made.
	c.cc.cwnd = 12000
	c.StreamWrite(a, data, false)
	if c.StreamWrite(b, data[:100], false) != 0 || c.StreamWrite(d, data[:100], false) != 0 {
		t.Fatal("a full buffer took more")
	}
	c.StreamReset(b, 7)
	if at := c.Deadline(); len(w.told) != 0 || at == 1 {
		t.Fatalf("after a reset that made no room: streams %v told, timer due at %d", w.told, at)
	}
	// Then it resets a, which holds all there is.
	c.StreamReset(a, 7)
	if len(w.told) != 0 {
		t.Fatalf("streams %v were told from within the application's StreamReset", w.told)
	}
	if at := c.Deadline(); at == 0 || at > tc.now {
		t.Fatalf("room was made and streams wait, but the connection's timer is not due (%d, now %d)", at, tc.now)
	}
	c.OnTimer(tc.now)
	if len(w.told) != 1 || w.told[0] != d {
		t.Errorf("told after the resets: streams %v, want %d only (stream %d was reset)", w.told, d, b)
	}
	if c.sendHeld != 0 {
		t.Errorf("the connection holds %d bytes after its streams were reset", c.sendHeld)
	}
}

// A stream that is told writes at once, and takes the room: the next one
// in line waits for more. Nobody is told twice for one wait.
func TestSend_RoomGoesToTheFirstInLine(t *testing.T) {
	sendBaseline(t)
	tc, w := sendClient(t)
	c := tc.c
	data := make([]byte, 1<<20)
	a, b := openUni(t, c), openUni(t, c)
	c.StreamWrite(a, data, false)
	if c.StreamWrite(a, data, false) != 0 || c.StreamWrite(b, data, false) != 0 {
		t.Fatal("a full buffer took more")
	}
	w.write = func(c *Conn, id uint64) { c.StreamWrite(id, data, false) }
	for i := 0; i < 50 && len(w.told) == 0; i++ {
		tc.round()
	}
	if len(w.told) != 1 || w.told[0] != a {
		t.Fatalf("told: %v, want stream %d alone: it took the room there was", w.told, a)
	}
	for i := 0; i < 50 && len(w.told) < 2; i++ {
		tc.round()
	}
	if len(w.told) < 2 || w.told[1] != b {
		t.Errorf("told next: %v, want stream %d, which waits longest now", w.told, b)
	}
}

// limitedClient is a sendClient that lets the server send perStream bytes
// on each of its streams and total on all together.
func limitedClient(t testing.TB, perStream, total uint64) (*testClient, *writers) {
	t.Helper()
	w := &writers{}
	return newTestClient(t, func(cfg *Config) { cfg.Handler = w },
		map[uint64]uint64{paramMaxStreamDataUni: perStream, paramInitialMaxData: total}), w
}

// arrived returns how many bytes of each stream the client was sent since
// the last take.
func (tc *testClient) arrived() map[uint64]int {
	got := map[uint64]int{}
	frames, _ := tc.take()
	for _, f := range frames {
		if f.Type >= FrameStream && f.Type <= FrameStream+7 {
			got[f.StreamID] += len(f.Data)
		}
	}
	return got
}

// A stream takes to send only what the client's limits let it send. One
// whose client does not read (it sent all its limit allows) holds nothing
// of the connection's buffer, however much its application has for it, so
// that the connection's other streams go on; and it is told to write again
// when the client raises its limit, not when there is room in the buffer.
func TestSend_StreamHeldBackByItsClientHoldsUpNoOther(t *testing.T) {
	sendBaseline(t)
	tc, w := limitedClient(t, 64<<10, 16<<20)
	c := tc.c
	data := make([]byte, 1<<20)
	a := openUni(t, c)
	// The application of stream a writes whenever it is told it may.
	w.write = func(c *Conn, id uint64) {
		if id == a {
			c.StreamWrite(a, data, false)
		}
	}
	if n := c.StreamWrite(a, data, false); n != 64<<10 {
		t.Errorf("a stream whose client lets it send 64 KiB took %d bytes", n)
	}
	// The client takes what is sent and acknowledges it, and raises no
	// limit: stream a has sent all it may.
	sent := 0
	for i := 0; i < 100; i++ {
		tc.round()
		sent += tc.arrived()[a]
	}
	if sent != 64<<10 {
		t.Fatalf("the client was sent %d bytes of a stream it lets send %d", sent, 64<<10)
	}
	if c.sendHeld != 0 {
		t.Errorf("the connection holds %d bytes of a stream that may send no more", c.sendHeld)
	}
	if len(w.told) != 0 {
		t.Errorf("streams %v were told to write while the client's limit holds stream %d", w.told, a)
	}
	// Another stream of the connection is none the worse.
	b := openUni(t, c)
	if n := c.StreamWrite(b, data[:50<<10], true); n != 50<<10 {
		t.Fatalf("beside a stream its client holds back, another took %d of %d bytes", n, 50<<10)
	}
	got := 0
	for i := 0; i < 100 && got < 50<<10; i++ {
		tc.round()
		got += tc.arrived()[b]
	}
	if got != 50<<10 {
		t.Errorf("the client was sent %d of the other stream's %d bytes", got, 50<<10)
	}
	if len(w.told) != 0 {
		t.Errorf("streams %v were told to write: room in the buffer is not what stream %d waits for", w.told, a)
	}
	// Nor is a stream that waits behind it for room in the buffer. Streams
	// of 64 KiB fill the buffer; the one that finds it full is told when
	// the client has acknowledged what the others sent.
	var e uint64
	for i := 0; e == 0; i++ {
		if i == 80 {
			t.Fatal("eighty streams of 64 KiB did not fill the buffer")
		}
		id := openUni(t, c)
		if n := c.StreamWrite(id, data[:64<<10], false); n < 64<<10 {
			e = id
		}
	}
	for i := 0; i < 100 && len(w.told) == 0; i++ {
		tc.round()
	}
	if len(w.told) != 1 || w.told[0] != e {
		t.Fatalf("told %v, want stream %d, which waits for room behind stream %d, which waits for its client", w.told, e, a)
	}
	w.told = nil
	// The client reads stream a and raises its limit: the stream is told,
	// and sends up to the new limit.
	tc.send(AppendFrame2(nil, FrameMaxStreamData, a, 200<<10))
	if len(w.told) != 1 || w.told[0] != a {
		t.Fatalf("after the client raised stream %d's limit: told %v, want that stream", a, w.told)
	}
	sent = 0
	for i := 0; i < 100; i++ {
		tc.round()
		sent += tc.arrived()[a]
	}
	if sent != 200<<10-64<<10 {
		t.Errorf("after its limit went from 64 KiB to 200 KiB the stream sent %d more bytes, want %d", sent, 200<<10-64<<10)
	}
}

// The client's limit for all streams together holds every stream; when it
// is raised they are told in the order they came, each takes what there is
// then, and one that still waits keeps its place.
func TestSend_ConnectionLimitOfTheClient(t *testing.T) {
	sendBaseline(t)
	tc, w := limitedClient(t, 1<<20, 100<<10)
	c := tc.c
	data := make([]byte, 1<<20)
	a, b := openUni(t, c), openUni(t, c)
	w.write = func(c *Conn, id uint64) {
		switch id {
		case a:
			c.StreamWrite(a, data[:150<<10], false)
		case b:
			c.StreamWrite(b, data[:1000], false)
		}
	}
	if n := c.StreamWrite(a, data, false); n != 100<<10 {
		t.Fatalf("with 100 KiB allowed on all streams together a stream took %d bytes", n)
	}
	if n := c.StreamWrite(b, data[:1000], false); n != 0 {
		t.Fatalf("with nothing left of the client's limit a second stream took %d bytes", n)
	}
	for i := 0; i < 100; i++ {
		tc.round()
	}
	if len(w.told) != 0 || c.sendHeld != 0 {
		t.Fatalf("with the client's limit used up: streams %v told, %d bytes held", w.told, c.sendHeld)
	}
	// 150 KiB more: stream a came first and takes all of it; stream b
	// still waits, and is in front when there is more.
	tc.send(AppendFrame1(nil, FrameMaxData, 250<<10))
	if len(w.told) != 1 || w.told[0] != a {
		t.Fatalf("after the client raised its limit: told %v, want stream %d, which came first", w.told, a)
	}
	w.told = nil
	for i := 0; i < 100; i++ {
		tc.round()
	}
	if len(w.told) != 0 {
		t.Fatalf("told %v with nothing left of the client's limit", w.told)
	}
	tc.send(AppendFrame1(nil, FrameMaxData, 300<<10))
	if len(w.told) != 1 || w.told[0] != b {
		t.Fatalf("after the client raised its limit again: told %v, want stream %d alone, which waits longest", w.told, b)
	}
	got := map[uint64]int{}
	for i := 0; i < 100; i++ {
		tc.round()
		for id, n := range tc.arrived() {
			got[id] += n
		}
	}
	if got[b] != 1000 {
		t.Errorf("the client was sent %d bytes of the stream that waited, want 1000", got[b])
	}
}

// A stream that is reset gives back what it took of the client's limit and
// never sent: the client does not count that, and would never make room
// for it.
func TestSend_ResetGivesTheClientsLimitBack(t *testing.T) {
	sendBaseline(t)
	tc, _ := limitedClient(t, 1<<20, 100<<10)
	c := tc.c
	data := make([]byte, 1<<20)
	a, b := openUni(t, c), openUni(t, c)
	if n := c.StreamWrite(a, data, false); n != 100<<10 {
		t.Fatalf("with 100 KiB allowed on all streams together a stream took %d bytes", n)
	}
	// Some of it is sent, none of that acknowledged yet; then the
	// application gives the stream up.
	tc.now += 1e6
	tc.pump()
	sent := tc.arrived()[a]
	if sent == 0 || sent >= 100<<10 {
		t.Fatalf("%d of the stream's 100 KiB were sent at first; the test needs some, not all", sent)
	}
	c.StreamReset(a, 7)
	if n := c.StreamWrite(b, data, false); n != 100<<10-sent {
		t.Errorf("after a stream that had sent %d of its 100 KiB was reset, another took %d bytes, want the %d the client's limit has left", sent, n, 100<<10-sent)
	}
}

// A stream that waits to write and is reset is out of the line at once,
// also when nothing is acknowledged or raised afterwards that would have
// the line gone through: a client that lets its streams send nothing and
// stops each one leaves nothing behind.
func TestSend_ResetStreamLeavesTheLine(t *testing.T) {
	sendBaseline(t)
	tc, w := limitedClient(t, 0, 16<<20)
	c := tc.c
	data := make([]byte, 4<<10)
	for i := 0; i < 60; i++ {
		id := openUni(t, c)
		if n := c.StreamWrite(id, data, false); n != 0 {
			t.Fatalf("a stream its client lets send nothing took %d bytes", n)
		}
		if len(c.waiting) != 1 {
			t.Fatalf("%d streams wait to write, want the one that was just cut short", len(c.waiting))
		}
		if i%2 == 0 {
			c.StreamReset(id, 7)
		} else {
			// The client stops it; the connection resets it then.
			tc.send(AppendFrame2(nil, FrameStopSending, id, 9))
		}
		if len(c.waiting) != 0 {
			t.Fatalf("after stream %d was reset %d streams still wait to write", id, len(c.waiting))
		}
	}
	for i := 0; i < 10; i++ {
		tc.round()
	}
	if len(w.told) != 0 || len(c.waiting) != 0 || c.sendHeld != 0 {
		t.Errorf("after sixty streams that were cut short and reset: streams %v told, %d wait, %d bytes held", w.told, len(c.waiting), c.sendHeld)
	}
}

// The line may change while it is gone through: an application that is
// told a stream may write resets another one, which stood before it in the
// line. The stream behind is told all the same, in the same pass: nothing
// more may ever be acknowledged that would have the line gone through
// again.
func TestSend_LineChangesWhileItIsGoneThrough(t *testing.T) {
	sendBaseline(t)
	tc, w := limitedClient(t, 64<<10, 16<<20)
	c := tc.c
	data := make([]byte, 1<<20)
	// Stream h has sent all its client lets it send and waits for more.
	h := openUni(t, c)
	if n := c.StreamWrite(h, data, false); n != 64<<10 {
		t.Fatalf("a stream whose client lets it send 64 KiB took %d bytes", n)
	}
	for i := 0; i < 100 && c.sendHeld > 0; i++ {
		tc.round()
	}
	// Streams fill the buffer; a finds it full, b after it.
	var a uint64
	for i := 0; a == 0; i++ {
		if i == 80 {
			t.Fatal("eighty streams of 64 KiB did not fill the buffer")
		}
		id := openUni(t, c)
		if n := c.StreamWrite(id, data[:64<<10], false); n < 64<<10 {
			a = id
		}
	}
	b := openUni(t, c)
	if n := c.StreamWrite(b, data[:1000], false); n != 0 {
		t.Fatalf("a stream took %d bytes of a full buffer", n)
	}
	if len(c.waiting) != 3 || c.waiting[0].id != h || c.waiting[1].id != a || c.waiting[2].id != b {
		t.Fatalf("the line is %d long, want streams %d, %d, %d", len(c.waiting), h, a, b)
	}
	// When a is told, its application gives h up, and writes nothing.
	round, toldIn := 0, map[uint64]int{}
	w.write = func(c *Conn, id uint64) {
		toldIn[id] = round
		if id == a {
			c.StreamReset(h, 7)
		}
	}
	for round = 1; round <= 100 && c.sendHeld > 0; round++ {
		tc.round()
	}
	if len(w.told) != 2 || w.told[0] != a || w.told[1] != b {
		t.Fatalf("told %v, want streams %d and %d", w.told, a, b)
	}
	if toldIn[a] != toldIn[b] {
		t.Errorf("stream %d was told with acknowledgement %d, stream %d behind it only with acknowledgement %d: the line changed under it and it was passed over", a, toldIn[a], b, toldIn[b])
	}
	if len(c.waiting) != 0 {
		t.Errorf("%d streams are still in line", len(c.waiting))
	}
}

// A connection that answers many small requests does not grow its window:
// after an answer large enough to use it (and grow it), three hundred
// small ones leave the window where it was.
func TestConn_SmallAnswersDoNotGrowTheWindow(t *testing.T) {
	sendBaseline(t)
	tc := newTestClient(t, nil) // the echo handler
	c := tc.c
	// A large amount from the server, taken and acknowledged round by
	// round: the window is in use and grows.
	id := openUni(t, c)
	data := make([]byte, 200<<10)
	if n := c.StreamWrite(id, data, true); n != len(data) {
		t.Fatalf("the stream took %d of %d bytes", n, len(data))
	}
	first := c.cc.cwnd
	for i := 0; i < 200 && c.sendHeld > 0; i++ {
		tc.round()
	}
	if c.sendHeld != 0 {
		t.Fatalf("%d bytes were never acknowledged", c.sendHeld)
	}
	grown := c.cc.cwnd
	if grown <= first {
		t.Fatalf("a download that used the window left it at %d bytes (it began at %d)", grown, first)
	}
	// Small requests, each answered and acknowledged.
	for i := 0; i < 300; i++ {
		body := []byte("a small request")
		tc.send(append(AppendStreamHeader(nil, uint64(4*i), 0, len(body), true), body...))
		tc.round()
		if err := c.Err(); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if c.cc.cwnd != grown {
		t.Errorf("three hundred small answers changed the window from %d to %d bytes", grown, c.cc.cwnd)
	}
}

// What a connection has sent of an answer before its client acknowledged
// any of it is the first window: 32 full datagrams, the quic-go server's
// number, and not one more until an acknowledgement arrives.
func TestSend_FirstFlight(t *testing.T) {
	tc, _ := sendClient(t)
	c := tc.c
	tc.acknowledge()
	if c.cc.inFlight != 0 || c.cc.cwnd != 32*maxDatagram {
		t.Fatalf("after the handshake: %d bytes in flight and a window of %d; want none, and 32 datagrams, %d", c.cc.inFlight, c.cc.cwnd, 32*maxDatagram)
	}
	id := openUni(t, c)
	if n := c.StreamWrite(id, make([]byte, 1<<20), true); n < 64<<10 {
		t.Fatalf("the stream took %d bytes", n)
	}
	tc.take()
	// The pacer lets ten out at once and the rest in the round trip's time.
	for i := 0; i < 1000 && c.cc.canSend(); i++ {
		tc.now += 1e6
		if at := c.Deadline(); at != 0 && at <= tc.now {
			c.OnTimer(tc.now)
		}
		tc.pump()
	}
	_, sizes := tc.take()
	full := 0
	for _, size := range sizes {
		if size > maxDatagram-8 { // a stream frame's own header leaves a byte or two unused
			full++
		}
	}
	if full != 32 || len(sizes) != full || c.cc.inFlight > 32*maxDatagram || c.cc.inFlight <= 31*maxDatagram {
		t.Errorf("before any acknowledgement the server sent %d datagrams, %d of them full, %d bytes in flight; want 32 full ones", len(sizes), full, c.cc.inFlight)
	}
	tc.pump()
	if _, more := tc.take(); len(more) != 0 {
		t.Errorf("%d more datagrams with the window full and nothing acknowledged", len(more))
	}
}
