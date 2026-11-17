package quic

import (
	"testing"
	"time"
)

// The receive windows: how much of an upload a client may have sent that
// the application has not taken (stream.go, "The receive windows").

const (
	testWindow    = 1 << 20  // the first window of a stream and of a connection in these tests
	testStreamMax = 6 << 20  // how far a stream's may grow
	testConnMax   = 15 << 20 // and the connection's
)

// uploader is a client that sends on one of its streams whatever the
// server's limits allow, and follows the limits the server sends.
type uploader struct {
	tc         *testClient
	id         uint64
	sent       uint64
	smax, cmax uint64 // the limits it was told: for the stream, for all streams
	rtt        int64  // the round-trip time the server is to go by
}

// uploadClient returns a client of a server whose handler takes every byte
// as it arrives, with the first windows above and a round-trip time of rtt.
// maxStream and maxConn are how far the server's windows may grow.
func uploadClient(t *testing.T, rtt time.Duration, maxStream, maxConn uint64) *uploader {
	t.Helper()
	tc := newTestClient(t, func(cfg *Config) {
		cfg.Handler = &writers{}
		cfg.Params.InitialMaxData, cfg.Params.InitialMaxStreamDataBidiRemote, cfg.Params.InitialMaxStreamDataUni = testWindow, testWindow, testWindow
		cfg.MaxStreamWindow, cfg.MaxConnWindow = maxStream, maxConn
	})
	return &uploader{tc: tc, smax: testWindow, cmax: testWindow, rtt: int64(rtt)}
}

// room is how much more the client may send now.
func (u *uploader) room() uint64 { return min(u.smax, u.cmax) - u.sent }

// send has the client send n more bytes, which it must have room for, and
// take the limits the server answers with.
func (u *uploader) send(n uint64) {
	u.tc.t.Helper()
	if n > u.room() {
		u.tc.t.Fatalf("the test sends %d bytes with room for %d", n, u.room())
	}
	// The test's clock stands still between a packet and its
	// acknowledgement: the round-trip time is given, not measured.
	c := u.tc.c
	c.rttMin, c.rttSmoothed, c.rttVar, c.rttLatest = u.rtt, u.rtt, u.rtt/2, u.rtt
	chunk := make([]byte, 1100)
	for n > 0 {
		k := min(n, uint64(len(chunk)))
		u.tc.send(append(AppendStreamHeader(nil, u.id, u.sent, int(k), false), chunk[:k]...))
		u.sent += k
		n -= k
	}
	u.tc.acknowledge()
	frames, _ := u.tc.take()
	for _, f := range frames {
		switch {
		case f.Type == FrameMaxData:
			u.cmax = max(u.cmax, f.Max)
		case f.Type == FrameMaxStreamData && f.StreamID == u.id:
			u.smax = max(u.smax, f.Max)
		}
	}
}

// upload sends total bytes, as much at a time as there is room for and no
// more than a quarter of a first window, with pause between the pieces.
func (u *uploader) upload(total uint64, pause time.Duration) {
	u.tc.t.Helper()
	for end := u.sent + total; u.sent < end; {
		n := min(end-u.sent, u.room(), testWindow/4)
		if n == 0 {
			u.tc.t.Fatalf("after %d bytes the client has no room: it may send to %d on its stream and to %d in all", u.sent, u.smax, u.cmax)
		}
		u.send(n)
		u.tc.now += int64(pause)
	}
}

func (u *uploader) windows() (stream, conn uint64) {
	c := u.tc.c
	return c.streams[u.id].rwin, c.rwin
}

// An upload that the application takes as fast as the path brings it has
// its window doubled, again and again, up to what the configuration
// allows; the connection's window is at least one and a half of the
// stream's; and the client is told every time: it may be a window ahead of
// what was taken, on its stream and in all, and never has less than three
// quarters of one to go on with.
func TestReceive_WindowGrowsForAFastUpload(t *testing.T) {
	before := ReceiveMemory()
	u := uploadClient(t, 100*time.Millisecond, testStreamMax, testConnMax)
	c := u.tc.c
	var last uint64 = testWindow
	for i := 0; i < 64; i++ { // 64 MiB, a quarter of a mebibyte every millisecond
		u.upload(testWindow, time.Millisecond)
		s, conn := u.windows()
		if s < last || s > testStreamMax || conn < s+s/2 && s > testWindow || conn > testConnMax {
			t.Fatalf("after %d MiB: a stream window of %d (it was %d) and a connection window of %d", i+1, s, last, conn)
		}
		last = s
		if ahead := u.smax - c.streams[u.id].consumed; ahead > s || ahead < s-s/4 {
			t.Fatalf("after %d MiB: the client may be %d bytes ahead on its stream, the window is %d", i+1, ahead, s)
		}
		if ahead := u.cmax - c.consumedData; ahead > conn || ahead < conn-conn/4 {
			t.Fatalf("after %d MiB: the client may be %d bytes ahead in all, the window is %d", i+1, ahead, conn)
		}
	}
	s, conn := u.windows()
	if s != testStreamMax || conn != testConnMax {
		t.Errorf("after 64 MiB taken at once: a stream window of %d and a connection window of %d, want %d and %d", s, conn, testStreamMax, testConnMax)
	}
	// What the connection was granted is what the process counts, until
	// the connection ends.
	if got := ReceiveMemory() - before; got != int64(conn-testWindow) {
		t.Errorf("the process counts %d bytes granted, the connection's window grew by %d", got, conn-testWindow)
	}
	c.Abandon()
	if got := ReceiveMemory(); got != before {
		t.Errorf("after the connection ended the process counts %d bytes granted, %d before it began", got, before)
	}
}

// A client is given its next limit when it has used a quarter of its
// window, on its stream and in all: not before, and not later. The limit
// is a window ahead of what was taken.
func TestReceive_NextLimitAfterAQuarter(t *testing.T) {
	u := uploadClient(t, 100*time.Millisecond, 0, 0) // nothing grows: the windows stay as they start
	u.send(testWindow/4 - 1100)
	if u.smax != testWindow || u.cmax != testWindow {
		t.Fatalf("with %d bytes used, less than a quarter of the window, the client was told it may send to %d on its stream and to %d in all; want the first limits still (%d)",
			u.sent, u.smax, u.cmax, testWindow)
	}
	u.send(1100)
	if want := uint64(testWindow/4 + testWindow); u.smax != want || u.cmax != want {
		t.Errorf("with a quarter of the window used (%d bytes) the client may send to %d on its stream and to %d in all; want %d for both, a window ahead of what was taken",
			u.sent, u.smax, u.cmax, want)
	}
	// And so on: every further quarter brings the next limit.
	for i := 2; i <= 8; i++ {
		u.send(testWindow / 4)
		if want := uint64(i*testWindow/4 + testWindow); u.smax != want || u.cmax != want {
			t.Fatalf("after %d quarters the client may send to %d on its stream and to %d in all, want %d", i, u.smax, u.cmax, want)
		}
	}
}

// An upload that arrives slowly leaves the windows as they are: the path,
// or the client, is what holds it back, and a larger window would only be
// more to hold.
func TestReceive_ASlowUploadLeavesTheWindows(t *testing.T) {
	before := ReceiveMemory()
	u := uploadClient(t, 100*time.Millisecond, testStreamMax, testConnMax)
	// A quarter of a window every quarter of a second: more than half a
	// window takes three quarters of a second, and four round trips' share
	// of that much is 300 ms.
	u.upload(16*testWindow, 250*time.Millisecond)
	if s, conn := u.windows(); s != testWindow || conn != testWindow {
		t.Errorf("after a slow upload: a stream window of %d and a connection window of %d, want the first ones, %d", s, conn, testWindow)
	}
	if got := ReceiveMemory(); got != before {
		t.Errorf("the process counts %d bytes granted more than before", got-before)
	}
}

// Without a limit above the first window nothing grows (what a
// configuration that names none gets), a stream's window does not grow
// when the connection's may not be one and a half of it, and a stream of
// one direction, which carries no upload, keeps its window.
func TestReceive_WhereNothingGrows(t *testing.T) {
	for _, tc := range []struct {
		name                string
		maxStream, maxConn  uint64
		uni                 bool
		wantStream, wantAll uint64
	}{
		{"no limits named", 0, 0, false, testWindow, testWindow},
		{"the connection's window may not grow", testStreamMax, 0, false, testWindow, testWindow},
		{"the connection's may grow to less than one and a half of two windows", testStreamMax, 2 * testWindow, false, testWindow, 2 * testWindow},
		{"a stream of one direction", testStreamMax, testConnMax, true, testWindow, testConnMax},
	} {
		u := uploadClient(t, 100*time.Millisecond, tc.maxStream, tc.maxConn)
		if tc.uni {
			u.id = 2 // the client's first unidirectional stream
		}
		u.upload(40*testWindow, time.Millisecond)
		if s, conn := u.windows(); s != tc.wantStream || conn != tc.wantAll {
			t.Errorf("%s: a stream window of %d and a connection window of %d, want %d and %d", tc.name, s, conn, tc.wantStream, tc.wantAll)
		}
	}
}

// The connections of a process are granted no more together than the
// bound says. One that is refused keeps the window it has, and its upload
// goes on with that; when a connection ends, what it was granted is there
// for the others.
func TestReceive_ProcessBound(t *testing.T) {
	before := ReceiveMemory()
	SetReceiveMemory(before + 3*testWindow)
	t.Cleanup(func() { SetReceiveMemory(0) })
	a := uploadClient(t, 100*time.Millisecond, testStreamMax, testConnMax)
	a.upload(24*testWindow, time.Millisecond)
	as, aconn := a.windows()
	granted := ReceiveMemory() - before
	if granted != int64(aconn-testWindow) || granted > 3*testWindow || aconn == testWindow || as > aconn {
		t.Fatalf("the first connection: windows of %d and %d, %d bytes granted of %d", as, aconn, granted, 3*testWindow)
	}
	// It took what there was (a doubling more would have been past the
	// bound), and the second gets what is left: nothing, or too little
	// for a stream's window to double.
	b := uploadClient(t, 100*time.Millisecond, testStreamMax, testConnMax)
	b.upload(24*testWindow, time.Millisecond)
	if bs, _ := b.windows(); bs != testWindow {
		t.Errorf("the second connection's stream window grew to %d with %d of %d bytes granted", bs, ReceiveMemory()-before, 3*testWindow)
	}
	if got := ReceiveMemory() - before; got > 3*testWindow {
		t.Errorf("%d bytes granted, the bound is %d", got, 3*testWindow)
	}
	a.tc.c.Abandon()
	b.upload(24*testWindow, time.Millisecond)
	if bs, bconn := b.windows(); bs == testWindow || bconn < bs+bs/2 {
		t.Errorf("after the first connection ended the second's windows are %d and %d: nothing grew", bs, bconn)
	}
	if got := ReceiveMemory() - before; got > 3*testWindow || got <= 0 {
		t.Errorf("%d bytes granted, the bound is %d", got, 3*testWindow)
	}
}

// The limit a client was told is the limit it is held to, whatever the
// window has grown to: one byte past it ends the connection.
func TestReceive_GrownWindowIsEnforced(t *testing.T) {
	u := uploadClient(t, 100*time.Millisecond, testStreamMax, testConnMax)
	u.upload(32*testWindow, time.Millisecond)
	if s, _ := u.windows(); s != testStreamMax {
		t.Fatalf("the stream's window is %d, the test wants it grown to %d", s, testStreamMax)
	}
	c := u.tc.c
	limit := c.streams[u.id].recvMax
	if u.smax > limit || limit-c.streams[u.id].consumed > testStreamMax {
		t.Fatalf("the client was told it may send to %d, the server holds it to %d, %d past what was taken", u.smax, limit, limit-c.streams[u.id].consumed)
	}
	// The last byte before the limit is taken, the one behind it is not.
	u.tc.send(append(AppendStreamHeader(nil, u.id, limit-1, 1, false), 0))
	if c.state != stateEstablished {
		t.Fatalf("the byte before the limit of %d ended the connection: %v", limit, c.Err())
	}
	u.tc.send(append(AppendStreamHeader(nil, u.id, limit, 1, false), 0))
	if !closedWith(c, FlowControlError) {
		t.Errorf("a byte past the stream's limit of %d: the connection goes on (state %d, %v)", limit, c.state, c.Err())
	}
}
