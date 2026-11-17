//go:build linux

package httpproxy

// HTTP/3 on the event loops: the fast path's exchange core on QUIC streams
// (quicloop_linux.go, core/quic), with the wire format of core/h3. A
// request stream is to the exchange core what an HTTP/2 stream is
// (h2stream_linux.go), and the request head goes through the same header
// block rules (h2req.go).

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/nvelox/ngx"

	"nvelox/core/h3"
	"nvelox/core/logging"
	"nvelox/core/quic"
)

// h3OnLoops serves a group's HTTP/3 from the event loops, on nvelox's own
// QUIC transport (core/quic), in place of the quic-go server, which serves
// it where there are no event loops. A variable for the tests, which also
// run what the quic-go server does: nothing else sets it.
var h3OnLoops = true

const (
	// h3MaxStreams is how many requests a client may have open at once.
	h3MaxStreams = 100
	// h3MaxUni is how many unidirectional streams a client may open: its
	// control stream and its two QPACK streams, and room for the ones a
	// client opens to exercise the protocol's extension points.
	h3MaxUni = 8
	// The windows for what a client sends: per request body, for the
	// connection, and per unidirectional stream. With them alone an
	// upload moves no more than a mebibyte per round trip; how far the
	// first two grow for an upload that its backend takes as fast as
	// the path brings it (core/quic, the receive windows) is the
	// configuration's: server.http3.max_stream_receive_window and
	// max_connection_receive_window, by default the quic-go server's
	// numbers.
	h3StreamWindow = 1 << 20
	h3ConnWindow   = 1 << 20
	h3UniWindow    = 64 << 10
	// h3IdleDefault is the idle timeout when the listener sets none.
	h3IdleDefault = 30 * time.Second
	// h3MaxString is the longest field name or value taken from a field
	// section; the block's own budgets are those of an HTTP/2 block.
	h3MaxString = h2MaxHeaderList
	// h3DecideWait is how long a request whose head came without the
	// stream's end, and without a Content-Length, waits for what follows:
	// the end (it has no body, and the loops serve it) or a body. A client
	// sends the end right behind the head, but not always in the same
	// packet. After the wait the request starts as one a body may follow.
	h3DecideWait = 10 * time.Millisecond
)

// h3LocalAnswerLimit is how long a client may take none of an answer the
// server gave before it had read the request's head (431, 408): such a
// request has no site whose write limit would apply. After it the stream
// is reset. A variable for the tests only.
var h3LocalAnswerLimit = defaultWriteTimeout

// h3Loop is a loop's HTTP/3 scratch.
type h3Loop struct {
	free   *h3stream // streams to reuse
	nfree  int
	date   []byte // the date field, encoded
	dateOf int64
	qpack  []byte // a decoded string
	size   uint32 // the field section being decoded, as HTTP/3 counts its size
	limit  uint32 // and the largest its connection takes
	// emit gives a decoded field to the loop's header block (made once).
	emit func(name, value []byte) error
}

// h3App is the HTTP/3 of a bind group, as the application of its QUIC
// server.
type h3App struct{ g *BindGroup }

// h3Params are the transport parameters of a group's HTTP/3.
func h3Params(idle time.Duration) quic.Params {
	if idle <= 0 {
		idle = h3IdleDefault
	}
	return quic.Params{
		MaxIdleTimeout:                 idle,
		InitialMaxData:                 h3ConnWindow,
		InitialMaxStreamDataBidiRemote: h3StreamWindow,
		InitialMaxStreamDataUni:        h3UniWindow,
		InitialMaxStreamsBidi:          h3MaxStreams,
		InitialMaxStreamsUni:           h3MaxUni,
		AckDelayExponent:               3,
		MaxAckDelay:                    25 * time.Millisecond,
		// As many connection IDs of a client's as the quic-go server
		// holds: enough for a client that moves to use a new one each time.
		ActiveConnectionIDLimit: 4,
	}
}

// h3TLSConfig returns base for QUIC: HTTP/3 as the one protocol offered,
// TLS 1.3, also on the configs base chooses per client.
func h3TLSConfig(base *tls.Config) *tls.Config {
	c := base.Clone()
	c.NextProtos = []string{"h3"}
	c.MinVersion = tls.VersionTLS13
	if get := base.GetConfigForClient; get != nil {
		c.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			sub, err := get(hi)
			if err != nil || sub == nil {
				return sub, err
			}
			sub = sub.Clone()
			sub.NextProtos = []string{"h3"}
			sub.MinVersion = tls.VersionTLS13
			return sub, nil
		}
	}
	return c
}

// bindH3Loops binds the group's HTTP/3 to the event loops when h3OnLoops
// is set, and reports whether it did. Nothing is served before
// serveH3Loops.
func (g *BindGroup) bindH3Loops(tlsCfg *tls.Config, idle time.Duration) (bool, error) {
	if !h3OnLoops {
		return false, nil
	}
	qs, err := bindQUIC(g.addr, quic.Config{TLS: h3TLSConfig(tlsCfg), Params: h3Params(idle)}, h3App{g})
	if err != nil {
		return false, err
	}
	// The relays the group trusts, as they are at each datagram: a reload
	// that changes them applies at once.
	qs.trust, qs.refused = g.proxyTrust, g.proxyRejected
	g.h3loops = qs
	logging.Info("[HTTP3] QUIC listener started on %s (event loops)", g.addr)
	return true, nil
}

// serveH3Loops starts serving the group's HTTP/3 on the loops, when the
// group serves (the serve gate). The group's fast server exists by now:
// its connections are that server's.
func (g *BindGroup) serveH3Loops() {
	qs := g.h3loops
	if qs == nil {
		return
	}
	go func() {
		if !g.serveGate.Wait(g.gateDone) {
			qs.stop(uint64(h3.ErrNoError), "")
			return
		}
		qs.serve()
	}()
}

// stopH3Loops gives back the sockets of the group's HTTP/3 on the loops;
// the connections still open are closed.
func (g *BindGroup) stopH3Loops() {
	if qs := g.h3loops; qs != nil {
		qs.stop(uint64(h3.ErrNoError), "")
	}
}

// A client's unidirectional stream, by what its first byte said it is.
const (
	h3uUnknown = iota // the type has not arrived yet
	h3uControl
	h3uQPACK   // an encoder or decoder stream: nothing in it matters with a table of size 0
	h3uIgnored // a type this server does not know: asked to stop
)

type h3uni struct {
	kind  uint8
	first bool     // a control stream: its first frame is still to come
	hdr   [16]byte // a frame header that arrived in pieces
	hdrN  int
	left  uint64 // of the frame being read
	body  []byte // a SETTINGS frame's payload
	keep  bool   // the frame being read is one to act on (SETTINGS)
}

// h3conn is one HTTP/3 connection on its loop.
type h3conn struct {
	fs *fastServer
	fl *fastLoop
	l  *ngx.Loop
	qc *qconn
	q  *quic.Conn
	// maxHead is the largest field section a request of this connection
	// may have (server.http3.max_header_size when it was opened).
	maxHead uint32

	peer   netip.Addr
	peerIP net.IP
	peerS  string
	peerB  []byte
	// For the requests net/http's handlers serve (h3bridge_linux.go): the
	// client's address as a request names it, the connection's TLS state,
	// the handlers running and the requests that wait for one, their
	// context, made with the first one, and the backend connections of the
	// connection's requests to send_proxy_v2 backends on that path.
	remote    string
	tlsState  *tls.ConnectionState
	handlers  int
	unstarted []*h2Bridge
	slowCtx   context.Context
	cb        *clientBackends
	// live: the addresses of addrs as they are now, for cb, which is asked
	// from other goroutines (set with cb, and again when the client moves).
	live atomic.Pointer[h3Addrs]

	streams map[uint64]*h3stream
	uni     map[uint64]*h3uni
	// The client's critical streams, once: its control stream and its two
	// QPACK streams.
	hasControl, hasEncoder, hasDecoder bool
	settled                            bool   // its SETTINGS frame arrived
	control                            uint64 // this server's control stream
	hasOut                             bool   // it is open
	// ctl is what the control stream has to send that the client's limits
	// did not let through yet (controlWrite, streamWritable).
	ctl []byte
	// Which request streams were seen (a stream that was seen and is not
	// listed is over; what still arrives for it is dropped). Streams need
	// not arrive in the order of their IDs: next is the lowest ID never
	// seen, ahead the IDs above it that were, and top is past the highest
	// one seen (what GOAWAY names).
	next, top uint64
	ahead     map[uint64]struct{}
	// goAway: the client was told that no new request is served; stopping:
	// the server is stopping, and the connection closes once what its
	// requests sent is delivered. lastAnswer is when its last answer went
	// to the transport.
	goAway, stopping bool
	lastAnswer       int64
	over             bool // the connection is over

	// undecided: requests whose head is here while it is open whether a
	// body follows (dt ends their wait); startq: requests to start once
	// this input is dealt with.
	undecided []*h3stream
	dt        h3DecideTimer
	startq    []*h3stream

	own   ownConns
	timer ngx.Timer // no request for the idle timeout

	lprev, lnext *h3conn
}

// setPeer takes the client's address from the transport (the one a
// trusted relay named, when the connection came through one): as the
// requests that begin from here on name it.
func (c *h3conn) setPeer() {
	client := c.qc.client()
	c.peer = client.Addr()
	a16 := c.peer.As16()
	c.peerIP = net.IP(a16[:])
	c.peerB = appendAddr(nil, c.peer)
	c.peerS = string(c.peerB)
	c.remote = client.String()
}

// moved: the client is at another address now (it has proven that it
// receives there). The requests that begin from here on are that
// address's: in the forwarding headers, in the access log and in the PROXY
// header of a backend connection opened for them. Requests already begun
// stay with the address they began at, and so do the backend connections
// already open.
func (c *h3conn) moved() {
	c.setPeer()
	c.own.clientMoved()
	if c.cb != nil {
		c.live.Store(c.liveAddrs())
	}
}

// h3Addrs is the client's address and the one it sent to, as addrs gives
// them.
type h3Addrs struct{ client, local net.Addr }

func (c *h3conn) liveAddrs() *h3Addrs {
	a := &h3Addrs{}
	a.client, a.local = c.addrs()
	return a
}

// open: a client completed its handshake.
func (a h3App) open(qc *qconn) qconnHandler {
	fs := a.g.fast
	if fs == nil || fs.closing.Load() {
		qc.close(uint64(h3.ErrNoError), "")
		return nil
	}
	l := qc.s.l
	c := &h3conn{fs: fs, fl: fastLoopOf(l), l: l, qc: qc, q: qc.q}
	// The largest head of a request is what server.http3 says now, for as
	// long as the connection lives: it is what the settings below tell
	// the client.
	c.maxHead = uint32(http3Limits().MaxHeaderSize)
	c.setPeer()
	st := c.q.ConnectionState()
	c.tlsState = &st
	c.timer.F = c
	c.dt.c = c
	c.dt.F = &c.dt
	fs.active.Add(1)
	head := &fs.h3lists[l.ID()]
	c.lnext = *head
	if *head != nil {
		(*head).lprev = c
	}
	*head = c

	// This side's streams: control, with the settings (the largest field
	// section a request may have), and the two of QPACK, on which nothing
	// is ever sent: the dynamic table stays empty.
	id, ok := c.q.OpenUniStream()
	if !ok {
		c.fail(h3.ErrStreamCreation, "no control stream allowed")
		return c
	}
	c.control, c.hasOut = id, true
	b := h3.AppendVarint(c.fl.out[:0], h3.StreamControl)
	set := h3.AppendSetting(nil, h3.SettingMaxFieldSectionSize, uint64(c.maxHead))
	b = h3.AppendFrameHeader(b, h3.FrameSettings, uint64(len(set)))
	b = append(b, set...)
	c.controlWrite(b)
	c.fl.out = b[:0]
	for _, typ := range [...]uint64{h3.StreamQPACKEncoder, h3.StreamQPACKDecoder} {
		if id, ok := c.q.OpenUniStream(); ok {
			// The stream's type is all it ever carries. A client whose
			// limits do not let even that through has a stream without
			// one, which it must put up with.
			var t [8]byte
			c.q.StreamWrite(id, h3.AppendVarint(t[:0], typ), false)
		}
	}
	c.idle()
	return c
}

// fail ends the connection for a protocol error of the client.
func (c *h3conn) fail(code h3.Error, reason string) {
	if c.over {
		return
	}
	c.qc.close(uint64(code), reason)
}

// recover keeps a panic in the code of one connection from ending the
// process: the connection ends, the others go on.
func (c *h3conn) recover() {
	r := recover()
	if r == nil {
		return
	}
	logLoopPanic("HTTP/3 connection from "+c.peerS, r)
	c.endBroken()
}

// endBroken ends a connection whose code failed: at once, without a word,
// and through the socket layer, which gives back what it holds and then
// calls closed.
func (c *h3conn) endBroken() {
	func() {
		defer func() { _ = recover() }()
		c.q.Abandon()
	}()
	func() {
		defer func() { _ = recover() }()
		c.qc.remove()
	}()
	if !c.over {
		c.over = true
		c.unlist()
	}
}

// unlist takes the connection out of the server's list and count (once:
// closed is set by its callers).
func (c *h3conn) unlist() {
	head := &c.fs.h3lists[c.l.ID()]
	if c.lprev != nil {
		c.lprev.lnext = c.lnext
	} else if *head == c {
		*head = c.lnext
	}
	if c.lnext != nil {
		c.lnext.lprev = c.lprev
	}
	c.lprev, c.lnext = nil, nil
	c.l.Stop(&c.timer)
	c.l.Stop(&c.dt.Timer)
	c.fs.active.Add(-1)
	c.fs.checkDrained()
}

// closed: the connection is over (qconnHandler). Its requests are
// cancelled.
func (c *h3conn) closed(error) {
	if c.over {
		return
	}
	c.over = true
	for id, s := range c.streams {
		func() {
			defer func() { _ = recover() }()
			s.cancel(statusClientClosedRequest)
		}()
		delete(c.streams, id)
		func() {
			defer func() { _ = recover() }()
			c.release(s)
		}()
	}
	c.undecided, c.startq, c.unstarted = nil, nil, nil
	func() {
		defer func() { _ = recover() }()
		c.own.closeAll()
	}()
	if cb := c.cb; cb != nil {
		c.cb = nil
		cb.closeFromLoop()
	}
	c.unlist()
}

// idle: the connection has no request. It closes when it is being stopped
// and everything is delivered; else the idle timeout starts.
func (c *h3conn) idle() {
	if c.over || len(c.streams) > 0 {
		return
	}
	if c.goAway {
		c.closeWhenDelivered()
		return
	}
	if d := c.fs.idleTO; d > 0 {
		c.l.Arm(&c.timer, d)
	}
}

// OnTimer: no request for the idle timeout.
func (c *h3conn) OnTimer() {
	if c.over {
		return
	}
	defer c.recover()
	if len(c.streams) == 0 {
		c.shutdown(false)
	}
}

// shutdown stops the connection gracefully: the client is told that no
// new request is served (GOAWAY), the open ones finish, and when what
// they sent is delivered the connection closes.
func (c *h3conn) shutdown(stop bool) {
	if c.over {
		return
	}
	if stop {
		c.stopping = true
	}
	if !c.goAway {
		c.goAway = true
		if c.hasOut {
			var b [24]byte
			f := h3.AppendFrameHeader(b[:0], h3.FrameGoAway, uint64(h3.VarintLen(c.top)))
			f = h3.AppendVarint(f, c.top)
			c.controlWrite(f)
			c.qc.wake()
		}
	}
	c.idle()
}

// closeWhenDelivered closes a connection that is done once the client has
// everything its requests were answered with: closing a QUIC connection
// drops what is not delivered yet. A client that is gone never
// acknowledges its last answer, so a server that is stopping gives a
// connection h3StopLinger from its last answer and no longer.
func (c *h3conn) closeWhenDelivered() {
	if c.over || len(c.streams) > 0 {
		return
	}
	if c.q.ClientStreams() > 0 {
		if !c.stopping {
			return // the transport's idle timeout bounds this wait
		}
		if due := c.lastAnswer + int64(h3StopLinger); c.l.Now() < due {
			c.l.ArmAt(&c.timer, due)
			return
		}
	}
	if c.stopping {
		c.qc.closeNow(uint64(h3.ErrNoError), "")
		return
	}
	c.qc.close(uint64(h3.ErrNoError), "")
}

// beginShutdown: the server is stopping. abortNow: its stop ran out of
// time.
func (c *h3conn) beginShutdown() {
	if c.over {
		return
	}
	defer c.recover()
	c.shutdown(true)
}

func (c *h3conn) abortNow() {
	if c.over {
		return
	}
	defer c.recover()
	c.qc.close(uint64(h3.ErrNoError), "")
}

// h3DecideTimer ends the wait of the requests in c.undecided.
type h3DecideTimer struct {
	ngx.Timer
	c *h3conn
}

func (t *h3DecideTimer) OnTimer() {
	c := t.c
	if c.over {
		return
	}
	defer c.recover()
	now := c.l.Now()
	var next int64
	n := 0
	for i, s := range c.undecided {
		c.undecided[i] = nil
		if s == nil || !s.waiting || s.closed {
			continue
		}
		if due := s.headAt + int64(h3DecideWait); due > now {
			c.undecided[n] = s
			n++
			if next == 0 || due < next {
				next = due
			}
			continue
		}
		// Nothing followed the head: a body may still come.
		s.waiting = false
		s.begin(false)
		if c.over {
			return
		}
	}
	c.undecided = c.undecided[:n]
	if next != 0 {
		c.l.ArmAt(&t.Timer, next)
	}
	c.inputDone()
	c.qc.wake()
}

// inputDone: a datagram, or a timer, has been dealt with (qconnHandler):
// the first attempt of every request that became ready starts now.
func (c *h3conn) inputDone() {
	if c.over {
		return
	}
	for i := 0; i < len(c.startq); i++ {
		s := c.startq[i]
		c.startq[i] = nil
		if s == nil {
			continue
		}
		s.queued = false
		if !s.closed && !s.done {
			s.x.attempt()
			if c.over {
				return
			}
		}
	}
	c.startq = c.startq[:0]
	if c.goAway {
		c.closeWhenDelivered()
	}
}

// ---- the client's streams ----

func (c *h3conn) streamData(id uint64, data []byte, fin bool) {
	if c.over {
		return
	}
	if id&2 != 0 {
		c.uniData(id, data, fin)
		return
	}
	if id&1 != 0 {
		c.fail(h3.ErrStreamCreation, "a bidirectional stream of the server's")
		return
	}
	s := c.streams[id]
	if s == nil {
		if !c.firstSight(id) {
			// A request that is over: what its client still sends is
			// dropped.
			c.q.StreamConsumed(id, len(data))
			return
		}
		if c.goAway {
			// Not processed: the client may send it elsewhere.
			c.q.StreamConsumed(id, len(data))
			c.q.StreamStopSending(id, uint64(h3.ErrRequestRejected))
			c.q.StreamReset(id, uint64(h3.ErrRequestRejected))
			return
		}
		c.l.Stop(&c.timer) // the idle timeout
		s = c.newStream(id)
	}
	s.recv(data, fin)
}

// firstSight reports whether request stream id is seen for the first time,
// and notes it.
func (c *h3conn) firstSight(id uint64) bool {
	if id < c.next {
		return false
	}
	if _, seen := c.ahead[id]; seen {
		return false
	}
	c.top = max(c.top, id+4)
	if id != c.next {
		// The streams below it are still to come.
		if c.ahead == nil {
			c.ahead = make(map[uint64]struct{})
		}
		c.ahead[id] = struct{}{}
		return true
	}
	c.next += 4
	for len(c.ahead) > 0 {
		if _, seen := c.ahead[c.next]; !seen {
			break
		}
		delete(c.ahead, c.next)
		c.next += 4
	}
	return true
}

func (c *h3conn) streamReset(id uint64, _ uint64) {
	if c.over {
		return
	}
	if id&2 != 0 {
		c.uniEnded(id)
		return
	}
	if s := c.streams[id]; s != nil {
		if s.done {
			// Its answer is complete and on its way to the client. The
			// client ended its own side of the stream early, as one does
			// that was asked to stop: that takes nothing from the answer
			// (RFC 9114, section 4.1.1). A client that wants no answer
			// says so (streamStop).
			s.recvEnd = true
			return
		}
		// The client gave its request up.
		s.cancel(statusClientClosedRequest)
		c.q.StreamReset(id, uint64(h3.ErrRequestCancelled))
		c.closeStream(s)
	}
}

func (c *h3conn) streamStop(id uint64, _ uint64) {
	if c.over {
		return
	}
	if s := c.streams[id]; s != nil {
		// The client wants no answer any more (the transport resets this
		// side of the stream itself).
		s.cancel(statusClientClosedRequest)
		if !s.recvEnd {
			c.q.StreamStopSending(id, uint64(h3.ErrRequestCancelled))
		}
		c.closeStream(s)
	}
}

func (c *h3conn) streamWritable(id uint64) {
	if c.over {
		return
	}
	if id == c.control && c.hasOut {
		if n := c.q.StreamWrite(id, c.ctl, false); n > 0 {
			c.ctl = c.ctl[:copy(c.ctl, c.ctl[n:])]
			c.qc.wake()
		}
		return
	}
	if s := c.streams[id]; s != nil {
		s.flushPend()
	}
}

// controlWrite sends frames on this server's control stream. What the
// client's limits do not let through at once waits, in order, until they
// do: the settings and a GOAWAY are not to be lost.
func (c *h3conn) controlWrite(frames []byte) {
	if len(c.ctl) == 0 {
		frames = frames[c.q.StreamWrite(c.control, frames, false):]
	}
	c.ctl = append(c.ctl, frames...)
}

// uniData takes bytes of a unidirectional stream of the client's.
func (c *h3conn) uniData(id uint64, p []byte, fin bool) {
	c.q.StreamConsumed(id, len(p))
	u := c.uni[id]
	if u == nil {
		if c.uni == nil {
			c.uni = make(map[uint64]*h3uni)
		}
		u = &h3uni{}
		c.uni[id] = u
	}
	if u.kind == h3uUnknown && len(p) > 0 {
		// The stream's type. Every type this server knows is one byte.
		typ := uint64(p[0])
		if p[0] >= 0x40 {
			typ = h3.MaxVarint // longer than a byte: none it knows
		}
		p = p[1:]
		switch typ {
		case h3.StreamControl:
			if c.hasControl {
				c.fail(h3.ErrStreamCreation, "a second control stream")
				return
			}
			c.hasControl, u.kind, u.first = true, h3uControl, true
		case h3.StreamQPACKEncoder, h3.StreamQPACKDecoder:
			seen := &c.hasEncoder
			if typ == h3.StreamQPACKDecoder {
				seen = &c.hasDecoder
			}
			if *seen {
				c.fail(h3.ErrStreamCreation, "a second QPACK stream of one kind")
				return
			}
			*seen, u.kind = true, h3uQPACK
		case h3.StreamPush:
			c.fail(h3.ErrStreamCreation, "a push stream from a client")
			return
		default:
			u.kind = h3uIgnored
			c.q.StreamStopSending(id, uint64(h3.ErrStreamCreation))
		}
	}
	if u.kind == h3uControl {
		c.controlData(u, p)
		if c.over {
			return
		}
	}
	if fin {
		c.uniEnded(id)
	}
}

// uniEnded: a unidirectional stream of the client's ended or was reset.
// Its control and QPACK streams must stay open.
func (c *h3conn) uniEnded(id uint64) {
	u := c.uni[id]
	if u == nil {
		return
	}
	if u.kind == h3uControl || u.kind == h3uQPACK {
		c.fail(h3.ErrClosedCriticalStream, "a critical stream was closed")
		return
	}
	delete(c.uni, id)
}

// controlData takes bytes of the client's control stream: its SETTINGS
// frame first, then frames that ask nothing of a server without push.
func (c *h3conn) controlData(u *h3uni, p []byte) {
	for len(p) > 0 {
		if u.left == 0 {
			k := copy(u.hdr[u.hdrN:], p)
			typ, length, n := h3.FrameHeader(u.hdr[:u.hdrN+k])
			if n == 0 {
				u.hdrN += k
				return
			}
			p = p[n-u.hdrN:]
			u.hdrN = 0
			known, err := h3.ControlFrame(typ, u.first)
			if err != nil {
				c.fail(err.(h3.Error), "control stream")
				return
			}
			u.first = false
			u.keep = known && typ == h3.FrameSettings
			if u.keep {
				if length > 4096 {
					c.fail(h3.ErrExcessiveLoad, "SETTINGS frame too long")
					return
				}
				u.body = u.body[:0]
			}
			u.left = length
			if length == 0 && u.keep {
				c.settings(u)
				if c.over {
					return
				}
			}
			continue
		}
		n := min(uint64(len(p)), u.left)
		if u.keep {
			u.body = append(u.body, p[:n]...)
		}
		p = p[n:]
		u.left -= n
		if u.left == 0 && u.keep {
			c.settings(u)
			if c.over {
				return
			}
		}
	}
}

// settings takes the client's SETTINGS frame. Nothing in it changes what
// this server sends: it uses no dynamic table and sends no field section
// near any limit a client sets.
func (c *h3conn) settings(u *h3uni) {
	u.keep = false
	if c.settled {
		c.fail(h3.ErrFrameUnexpected, "a second SETTINGS frame")
		return
	}
	c.settled = true
	if err := h3.Settings(u.body, func(uint64, uint64) {}); err != nil {
		code, ok := err.(h3.Error)
		if !ok {
			code = h3.ErrSettings
		}
		c.fail(code, "SETTINGS")
	}
	u.body = nil
}

// ---- requests ----

// newStream opens the request stream id.
func (c *h3conn) newStream(id uint64) *h3stream {
	hl := &c.fl.h3
	s := hl.free
	if s != nil {
		hl.free = s.fnext
		hl.nfree--
		x := s.x
		*s = h3stream{}
		s.x = x
	} else {
		s = &h3stream{}
	}
	s.timer.F = s
	s.wt.s = s
	s.wt.F = &s.wt
	s.c, s.id = c, id
	s.born = c.l.Now()
	s.declared = -1
	// The request's head is to be here within the listener's time for it,
	// as on its other protocols: a stream that is opened and then left
	// alone is not kept.
	if d := c.fs.readHeaderTO; d > 0 {
		c.l.Arm(&s.timer, d)
	}
	s.x.d, s.x.fs, s.x.fl, s.x.l = s, c.fs, c.fl, c.l
	s.x.own = &c.own
	if c.streams == nil {
		c.streams = make(map[uint64]*h3stream)
	}
	c.streams[id] = s
	return s
}

// closeStream ends stream s: it is no longer the connection's.
func (c *h3conn) closeStream(s *h3stream) {
	if s.closed {
		return
	}
	delete(c.streams, s.id)
	c.release(s)
	c.idle()
}

// release lets go of what a stream holds and keeps it for reuse.
func (c *h3conn) release(s *h3stream) {
	s.closed = true
	c.l.Stop(&s.timer)
	c.l.Stop(&s.wt.Timer)
	if s.queued {
		s.queued = false
		for i := range c.startq {
			if c.startq[i] == s {
				c.startq[i] = nil
			}
		}
	}
	if s.waiting {
		s.waiting = false
		for i := range c.undecided {
			if c.undecided[i] == s {
				c.undecided[i] = nil
			}
		}
	}
	// Body bytes nobody read: their room in the windows goes back.
	if n := len(s.body); n > 0 && !c.over {
		c.q.StreamConsumed(s.id, n)
	}
	if b := s.br; b != nil {
		s.br = nil
		err := b.closeErr
		if err == nil {
			err = errH2StreamClosed
		}
		if n := b.streamClosed(err); n > 0 && !c.over {
			c.q.StreamConsumed(s.id, n)
		}
	}
	releaseBuf(&s.pend)
	s.pendAt = 0
	releaseBuf(&s.body)
	releaseBuf(&s.hdr)
	releaseBuf(&s.hbuf)
	s.x.u = nil
	if hl := &c.fl.h3; hl.nfree < 1024 {
		s.c = nil
		s.fnext = hl.free
		hl.free = s
		hl.nfree++
	}
}

// endStream: the response of s is out (in the transport's hands). A
// client that has not finished its request is told to stop, without an
// error.
func (c *h3conn) endStream(s *h3stream) {
	c.lastAnswer = c.l.Now()
	if !s.recvEnd && !c.over {
		c.q.StreamStopSending(s.id, uint64(h3.ErrNoError))
	}
	c.closeStream(s)
}

// reject refuses a request the loops do not serve. It was not processed:
// the client may send it again.
func (c *h3conn) reject(s *h3stream, code h3.Error) {
	if !s.recvEnd {
		c.q.StreamStopSending(s.id, uint64(code))
	}
	c.q.StreamReset(s.id, uint64(code))
	c.qc.wake()
	s.done = true
	c.closeStream(s)
}

// addrs: the client's address and the one it sent to (downstream), for a
// PROXY header to a backend.
func (c *h3conn) addrs() (client, local net.Addr) {
	client = net.UDPAddrFromAddrPort(c.qc.client())
	if a := c.qc.local; a.IsValid() {
		local = &net.UDPAddr{IP: a.AsSlice(), Port: c.qc.s.qs.local.Port}
	}
	return client, local
}
