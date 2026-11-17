package quic

import (
	"math"
	"time"
)

// Congestion control: how much may be on its way to the peer at once
// (RFC 9002, section 7), with the window grown by CUBIC (RFC 9438), which
// is what the QUIC library nvelox used before (quic-go) does, and what
// TCP on Linux does. Sizes are in bytes, times in nanoseconds.

// CUBIC's constants (RFC 9438, section 5).
const (
	cubicC    = 0.4
	cubicBeta = 0.7
	// The window a flow of the same age would have under Reno grows by
	// this much per round trip, in datagrams, while it is below the window
	// at the last loss, and by one above it.
	cubicAlpha = 3 * (1 - cubicBeta) / (1 + cubicBeta)
)

// How the window is sized (RFC 9002, section 7.2).
const (
	// initialWindowPackets is the window a connection starts with, in
	// datagrams: the number of the quic-go server and of Chromium. RFC
	// 9002 recommends ten (14,720 bytes at most). What a server may send
	// before it has heard from its client decides how many round trips an
	// answer takes: measured against the quic-go server over paths of 50
	// to 200 ms, a window of ten made the first answer of a connection, 64
	// KiB to 1 MiB large, take 1.3 to 2.2 round trips longer (29 to 40%
	// more time); with 32 it is within a quarter of a round trip.
	initialWindowPackets = 32
	minWindowPackets     = 2
	// maxWindowPackets is the largest window, in datagrams: quic-go's.
	maxWindowPackets = 10000
	// usedSlack: a window counts as in use when what is in flight fills it
	// to within this many datagrams (the pacer holds a few back).
	usedSlack = 3
	// pacingBurst is how many datagrams may go out together at the least:
	// the pacer spreads the rest of a window over the round-trip time.
	// pacingSpan is the time whose worth of the pacing rate may go out
	// together when that is more. A sender is woken when a timer fires or
	// acknowledgements arrive, which is not more precise than that; what
	// it may not send when it is woken, it never sends, and at ten
	// datagrams per wake-up a fast path is left idle. Both numbers are
	// those of quic-go's pacer.
	pacingBurst = 10
	pacingSpan  = 2 * time.Millisecond
)

// congestion is one connection's congestion controller.
type congestion struct {
	mds      int64 // the size of a full datagram
	cwnd     int64 // how much may be in flight
	ssthresh int64 // slow start ends when the window reaches it
	inFlight int64 // what is in flight: sent, not acknowledged, not given up

	// recoveryStart is when the last reduction happened: losses of packets
	// sent before it belong to that same event.
	recoveryStart int64
	// limited says that the window was in use when the acknowledgement
	// being taken arrived (acking): only then does it grow.
	limited bool

	// CUBIC, in datagrams and seconds: the window at the last loss, the
	// time it takes to get back to it, when the current avoidance period
	// began (0: not yet), and the Reno-equivalent window.
	wMax, k    float64
	epochStart int64
	wEst       float64

	// The pacer: tokens are bytes that may be sent now; they refill at the
	// pacing rate, up to a burst.
	tokens   int64
	paceTime int64
}

func (cc *congestion) init(mds int64) {
	cc.mds = mds
	cc.cwnd = initialWindowPackets * mds
	cc.ssthresh = math.MaxInt64
	cc.tokens = pacingBurst * mds
}

// canSend reports whether the window has room for another full datagram.
func (cc *congestion) canSend() bool { return cc.inFlight+cc.mds <= cc.cwnd }

// acking is called when an acknowledgement arrives, before what it
// acknowledges is taken out of flight. It notes whether the window is in
// use: what is in flight fills it to within a few datagrams, or, in slow
// start, more than half of it (the rule of quic-go and Chromium). Only a
// window in use grows (RFC 9002, section 7.8). One that grew while the
// application sent little would say nothing about the path any more, and
// the day the application has much to send, the pacer would let it out at
// a rate the path was never seen to carry.
func (cc *congestion) acking() {
	cc.limited = cc.cwnd-cc.inFlight <= usedSlack*cc.mds || cc.cwnd < cc.ssthresh && cc.inFlight > cc.cwnd/2
}

func (cc *congestion) onSent(size int64) { cc.inFlight += size }

// forget takes size bytes out of flight without judging the path: packets
// of keys that are discarded, and content sent again at a probe timeout.
func (cc *congestion) forget(size int64) { cc.inFlight = max(cc.inFlight-size, 0) }

// onAck: a packet of size bytes, sent at sentAt, was acknowledged at now;
// rtt is the smoothed round-trip time.
func (cc *congestion) onAck(size, sentAt, now, rtt int64) {
	cc.inFlight = max(cc.inFlight-size, 0)
	if sentAt <= cc.recoveryStart {
		return // sent before the last reduction: that event is still being repaired
	}
	if !cc.limited {
		// The application sends less than the window allows. The window
		// stays, and so does CUBIC's clock: its curve runs with the time
		// the window is in use (RFC 9438, section 5.8), and begins again,
		// from where the window is, when it is in use again.
		cc.epochStart = 0
		return
	}
	if cc.cwnd < cc.ssthresh {
		cc.cwnd += size // slow start: the window doubles every round trip
	} else {
		cc.avoid(size, now, rtt)
	}
	cc.cwnd = min(cc.cwnd, maxWindowPackets*cc.mds)
}

// avoid grows the window in congestion avoidance (RFC 9438, section 4).
func (cc *congestion) avoid(size, now, rtt int64) {
	mds := float64(cc.mds)
	w := float64(cc.cwnd) / mds
	if cc.epochStart == 0 {
		cc.epochStart = now
		if cc.wMax < w {
			cc.wMax, cc.k = w, 0 // slow start ended without a loss
		} else {
			cc.k = math.Cbrt((cc.wMax - w) / cubicC)
		}
		cc.wEst = w
	}
	acked := float64(size) / mds
	// The Reno-equivalent window.
	alpha := cubicAlpha
	if cc.wEst >= cc.wMax {
		alpha = 1
	}
	cc.wEst += alpha * acked / w
	// Where CUBIC's curve will be one round trip from now.
	t := float64(now-cc.epochStart+rtt) / float64(time.Second)
	d := t - cc.k
	target := cubicC*d*d*d + cc.wMax
	target = min(max(target, w), 1.5*w)
	next := w + (target-w)/w*acked
	// Never slower than Reno would be.
	if tNow := float64(now-cc.epochStart) / float64(time.Second); cubicC*(tNow-cc.k)*(tNow-cc.k)*(tNow-cc.k)+cc.wMax < cc.wEst {
		next = max(next, cc.wEst)
	}
	cc.cwnd = int64(next * mds)
}

// onLost: a packet of size bytes, sent at sentAt, was given up as lost at
// now. The first loss of packets sent after the last reduction reduces the
// window.
func (cc *congestion) onLost(size, sentAt, now int64) {
	cc.inFlight = max(cc.inFlight-size, 0)
	if sentAt <= cc.recoveryStart {
		return
	}
	cc.recoveryStart = now
	w := float64(cc.cwnd) / float64(cc.mds)
	// Fast convergence: a flow that was still below its last peak gives
	// more room to the others.
	if w < cc.wMax {
		cc.wMax = w * (1 + cubicBeta) / 2
	} else {
		cc.wMax = w
	}
	cc.cwnd = max(cc.cwnd*7/10, minWindowPackets*cc.mds) // cubicBeta, in whole bytes
	cc.ssthresh = cc.cwnd
	cc.epochStart = 0
}

// collapse: the path carried nothing for a long time (persistent
// congestion: RFC 9002, section 7.6): the window starts over.
func (cc *congestion) collapse() {
	cc.cwnd = minWindowPackets * cc.mds
	cc.recoveryStart = 0
	cc.epochStart = 0
}

// ready reports whether the pacer lets a full datagram out now; else it
// returns when to ask again. rtt is the smoothed round-trip time (0: not
// known yet, and nothing to spread a window over). What is then sent is
// taken off with paced.
func (cc *congestion) ready(now, rtt int64) (ok bool, at int64) {
	if rtt <= 0 {
		return true, 0
	}
	// 1.25 windows per round trip, so that pacing does not hold the window
	// back while it grows.
	rate := float64(cc.cwnd) * 1.25 / float64(rtt) // bytes per nanosecond
	if cc.paceTime == 0 {
		cc.paceTime = now
	}
	if elapsed := now - cc.paceTime; elapsed > 0 {
		burst := max(int64(rate*float64(pacingSpan)), pacingBurst*cc.mds)
		cc.tokens = min(cc.tokens+int64(float64(elapsed)*rate), burst)
		cc.paceTime = now
	}
	if cc.tokens >= cc.mds {
		return true, 0
	}
	return false, now + int64(float64(cc.mds-cc.tokens)/rate) + 1
}

// paced takes the size of a datagram that was sent off the pacer's tokens.
func (cc *congestion) paced(size int64) { cc.tokens -= size }
