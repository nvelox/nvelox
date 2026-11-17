package quic

import (
	"testing"
	"time"
)

const testMDS = 1200

// Slow start: the window starts at 32 datagrams, the quic-go server's
// number, and grows by what is acknowledged, but only while the window is
// what holds the sender back.
func TestCongestion_SlowStart(t *testing.T) {
	var cc congestion
	cc.init(testMDS)
	const first = 32
	if cc.cwnd != first*testMDS {
		t.Fatalf("initial window %d, want %d datagrams, %d", cc.cwnd, first, first*testMDS)
	}
	now := int64(time.Second)
	// The application has less to send than the window: no growth.
	cc.onSent(testMDS)
	cc.acking()
	cc.onAck(testMDS, now, now+1000, 1000)
	if cc.cwnd != first*testMDS || cc.inFlight != 0 {
		t.Errorf("an application-limited round grew the window to %d (in flight %d)", cc.cwnd, cc.inFlight)
	}
	// A full window in flight, the sender held back: every acknowledged
	// datagram adds one.
	for i := 0; i < first; i++ {
		if !cc.canSend() {
			t.Fatalf("no room for datagram %d of the first window", i)
		}
		cc.onSent(testMDS)
	}
	if cc.canSend() {
		t.Fatalf("room for one datagram more than the first window's %d", first)
	}
	cc.acking()
	for i := 0; i < first; i++ {
		cc.onAck(testMDS, now, now+1000, 1000)
	}
	if cc.cwnd != 2*first*testMDS {
		t.Errorf("after a round of slow start the window is %d, want %d", cc.cwnd, 2*first*testMDS)
	}
}

// The window grows only while it is in use, however often it was in use
// before: after a round that filled it, a hundred rounds of one datagram
// leave it where it is. In use means: in slow start, more than half of it
// is in flight; after that, all of it but three datagrams at most. And it
// never grows past ten thousand datagrams.
func TestCongestion_UnusedWindowDoesNotGrow(t *testing.T) {
	var cc congestion
	cc.init(testMDS)
	cc.cwnd = 10 * testMDS // the rounds below are counted from a window of ten
	now := int64(time.Second)
	round := func(n int) {
		for i := 0; i < n; i++ {
			cc.onSent(testMDS)
		}
		cc.acking()
		for i := 0; i < n; i++ {
			cc.onAck(testMDS, now, now+1000, 1000)
		}
		now += 2000
	}
	round(10)
	if cc.cwnd != 20*testMDS {
		t.Fatalf("after a round that filled the window it is %d, want %d", cc.cwnd, 20*testMDS)
	}
	for i := 0; i < 100; i++ {
		round(1)
	}
	if cc.cwnd != 20*testMDS {
		t.Errorf("a hundred rounds of one datagram grew a window of 20 datagrams to %d bytes", cc.cwnd)
	}
	// Slow start: half the window in flight is not enough, more is.
	round(10)
	if cc.cwnd != 20*testMDS {
		t.Errorf("a round that half filled the window grew it to %d bytes", cc.cwnd)
	}
	round(11)
	if cc.cwnd != 31*testMDS {
		t.Errorf("a round that filled more than half of the window left it at %d bytes, want %d", cc.cwnd, 31*testMDS)
	}
	// After slow start: all of it but three datagrams.
	cc.ssthresh = cc.cwnd
	before := cc.cwnd
	round(27)
	if cc.cwnd != before {
		t.Errorf("past slow start a round four datagrams short of the window grew it from %d to %d", before, cc.cwnd)
	}
	round(28)
	if cc.cwnd <= before {
		t.Errorf("past slow start a round three datagrams short of the window left it at %d", cc.cwnd)
	}
	// The largest window.
	cc.ssthresh = 1 << 62
	cc.cwnd = maxWindowPackets*testMDS - 2*testMDS
	round(9000)
	if cc.cwnd != maxWindowPackets*testMDS {
		t.Errorf("the window grew to %d bytes, want it to stop at %d", cc.cwnd, maxWindowPackets*testMDS)
	}
}

// CUBIC's curve runs with the time the window is in use. A minute in which
// the application sent little is not on it: the first round that fills the
// window after that minute grows it as a round at the curve's beginning
// does, by a datagram or so, not by the half of itself that the curve allows
// a minute further on.
func TestCongestion_QuietTimeIsNotOnTheCurve(t *testing.T) {
	var cc congestion
	cc.init(testMDS)
	cc.cwnd = 100 * testMDS
	rtt := int64(50 * time.Millisecond)
	now := int64(100 * time.Second)
	cc.onLost(testMDS, now-1, now) // the window is 70 datagrams, the peak 100
	round := func(n int) {
		now += rtt
		for i := 0; i < n; i++ {
			cc.onSent(testMDS)
		}
		cc.acking()
		for i := 0; i < n; i++ {
			cc.onAck(testMDS, now-rtt, now, rtt)
		}
	}
	full := func() int { return int(cc.cwnd / testMDS) }
	// A second of rounds that fill the window: it climbs the curve.
	for i := 0; i < 20; i++ {
		round(full())
	}
	climbed := cc.cwnd
	if climbed < 80*testMDS || climbed > 95*testMDS {
		t.Fatalf("a second after the loss the window is %d datagrams, want about 87", climbed/testMDS)
	}
	// A minute of one datagram per round.
	for i := 0; i < 1200; i++ {
		round(1)
	}
	if cc.cwnd != climbed {
		t.Fatalf("a minute of one datagram per round changed the window from %d to %d bytes", climbed, cc.cwnd)
	}
	round(full())
	grew := cc.cwnd - climbed
	if grew <= 0 {
		t.Errorf("the first round that filled the window after a quiet minute did not grow it")
	}
	if grew > 3*testMDS {
		t.Errorf("the first round that filled the window after a quiet minute grew it by %d datagrams (to %d): the minute was counted as time on CUBIC's curve", grew/testMDS, cc.cwnd/testMDS)
	}
	// And it climbs on from there, toward the peak it had before the loss.
	for i := 0; i < 20; i++ {
		round(full())
	}
	if got, was := cc.cwnd/testMDS, climbed/testMDS; got < was+5 || got > 105 {
		t.Errorf("a second after the quiet minute the window is %d datagrams, want it to have climbed on from %d toward the peak, 100", got, was)
	}
}

// A loss: the window goes to 0.7 of what it was, once for all the losses
// of one round, and never below two datagrams.
func TestCongestion_Loss(t *testing.T) {
	var cc congestion
	cc.init(testMDS)
	cc.cwnd = 100 * testMDS
	now := int64(10 * time.Second)
	for i := 0; i < 5; i++ {
		cc.onSent(testMDS)
	}
	cc.onLost(testMDS, now-1000, now)
	if cc.cwnd != 70*testMDS || cc.ssthresh != 70*testMDS {
		t.Fatalf("after a loss: window %d, threshold %d; want %d", cc.cwnd, cc.ssthresh, 70*testMDS)
	}
	// More losses of packets sent before the reduction: the same event.
	cc.onLost(testMDS, now-500, now+10)
	cc.onLost(testMDS, now, now+20)
	if cc.cwnd != 70*testMDS {
		t.Errorf("losses of the same round reduced the window again: %d", cc.cwnd)
	}
	// One sent after it: a new event.
	cc.onLost(testMDS, now+5, now+30)
	if cc.cwnd != 49*testMDS {
		t.Errorf("a loss in the next round: window %d, want %d", cc.cwnd, 49*testMDS)
	}
	// Acknowledgements of packets sent before the reduction do not grow it.
	cc.limited = true
	before := cc.cwnd
	cc.onAck(testMDS, now-100, now+40, 1000)
	if cc.cwnd != before {
		t.Errorf("an old packet's acknowledgement grew the window during recovery")
	}
	cc.cwnd = 2 * testMDS
	cc.onLost(testMDS, now+100, now+200)
	if cc.cwnd != 2*testMDS {
		t.Errorf("the window went below two datagrams: %d", cc.cwnd)
	}
	cc.collapse()
	if cc.cwnd != 2*testMDS {
		t.Errorf("after persistent congestion the window is %d", cc.cwnd)
	}
}

// Congestion avoidance follows CUBIC's curve. After a loss at a window of
// 100 datagrams the window is back there after K = cbrt(30/0.4) seconds,
// about 4.2 s: steep at first, flat around the old peak, steeper again past
// it. With a short round-trip time Reno's straight line is above that curve
// and the window follows it instead.
func TestCongestion_Cubic(t *testing.T) {
	run := func(rtt time.Duration) map[int]float64 {
		var cc congestion
		cc.init(testMDS)
		cc.cwnd = 100 * testMDS
		start := int64(100 * time.Second)
		cc.onLost(testMDS, start-1, start)
		now := start
		at := map[int]float64{}
		perSecond := int(time.Second / rtt)
		for step := 1; step <= 8*perSecond; step++ {
			now += int64(rtt)
			// A round: the whole window is acknowledged, the sender held
			// back.
			n := int(cc.cwnd / testMDS)
			for i := 0; i < n; i++ {
				cc.limited = true
				cc.onAck(testMDS, now-int64(rtt), now, int64(rtt))
			}
			if step%perSecond == 0 {
				at[step/perSecond] = float64(cc.cwnd) / testMDS
			}
		}
		for s := 2; s <= 8; s++ {
			if at[s] < at[s-1] {
				t.Errorf("rtt %v: the window shrank without a loss: %.1f at %d s, %.1f at %d s", rtt, at[s-1], s-1, at[s], s)
			}
		}
		return at
	}
	// 200 ms round trips: Reno adds 2.6 datagrams a second, CUBIC's curve
	// is above it all the way.
	at := run(200 * time.Millisecond)
	if w := at[1]; w < 80 || w > 92 {
		t.Errorf("1 s after the loss the window is %.1f datagrams, want about 87", w)
	}
	if w := at[4]; w < 97 || w > 103 {
		t.Errorf("4 s after the loss the window is %.1f datagrams, want about 100 (the plateau)", w)
	}
	if at[8] < 115 || at[8]-at[6] < 3*(at[5]-at[4]) {
		t.Errorf("past the plateau the window does not take off: %.1f at 4 s, %.1f at 5 s, %.1f at 6 s, %.1f at 8 s", at[4], at[5], at[6], at[8])
	}
	// 20 ms round trips: Reno adds 26 a second and is the faster one.
	fast := run(20 * time.Millisecond)
	if fast[2] < 110 {
		t.Errorf("with 20 ms round trips the window is %.1f after 2 s, below Reno's line", fast[2])
	}
}

// The pacer lets a burst of ten datagrams out at once and then spreads
// the window over the round trip, at 1.25 windows per round trip.
func TestCongestion_Pacing(t *testing.T) {
	var cc congestion
	cc.init(testMDS)
	cc.cwnd = 100 * testMDS
	rtt := int64(100 * time.Millisecond)
	now := int64(time.Second)
	sent := 0
	send := func() bool {
		ok, _ := cc.ready(now, rtt)
		if ok {
			cc.paced(testMDS)
			sent++
		}
		return ok
	}
	for send() {
	}
	if sent != pacingBurst {
		t.Fatalf("%d datagrams at once, want a burst of %d", sent, pacingBurst)
	}
	ok, at := cc.ready(now, rtt)
	// One datagram's time at 125 datagrams per 100 ms: 0.8 ms.
	if ok || at-now < int64(700*time.Microsecond) || at-now > int64(900*time.Microsecond) {
		t.Errorf("the next datagram may go %v after the burst, want about 0.8 ms", time.Duration(at-now))
	}
	// Over the next round trip about 125 go out.
	sent = 0
	for end := now + rtt; now < end; now += int64(100 * time.Microsecond) {
		for send() {
		}
	}
	if sent < 120 || sent > 130 {
		t.Errorf("%d datagrams in one round trip, want about 125", sent)
	}
	// After a pause what may go at once is ten datagrams again, also at
	// this rate, at which two milliseconds give less than three.
	now += int64(50 * time.Millisecond)
	sent = 0
	for send() {
	}
	if sent != pacingBurst {
		t.Errorf("%d datagrams at once after a pause, want a burst of %d", sent, pacingBurst)
	}
	// On a fast path ten datagrams per wake-up would leave it idle: what
	// may go at once is what the rate gives in two milliseconds. A window
	// of 10,000 datagrams over 100 ms is 125 per millisecond.
	var fast congestion
	fast.init(testMDS)
	fast.cwnd = 10000 * testMDS
	burst := func(gap time.Duration) (n int) {
		now += int64(gap)
		for {
			if ok, _ := fast.ready(now, rtt); !ok {
				return n
			}
			fast.paced(testMDS)
			n++
		}
	}
	burst(time.Second) // whatever had gathered
	if n := burst(10 * time.Millisecond); n < 245 || n > 255 {
		t.Errorf("after 10 ms without a wake-up %d datagrams went at once, want two milliseconds' worth, 250", n)
	}
	if n := burst(time.Millisecond); n < 120 || n > 130 {
		t.Errorf("one millisecond later %d datagrams went, want one millisecond's worth, 125", n)
	}
	// Before a round-trip time is known nothing is held back.
	var fresh congestion
	fresh.init(testMDS)
	for i := 0; i < 50; i++ {
		if ok, _ := fresh.ready(now, 0); !ok {
			t.Fatalf("held back before any round-trip sample")
		}
		fresh.paced(testMDS)
	}
}
