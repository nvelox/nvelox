package quic

// Streams (RFC 9000, sections 2 to 4): ordered byte streams inside a
// connection, opened by either side, in both directions or one. A stream
// ID says who opened it (its lowest bit: 1 for the server) and whether it
// is unidirectional (the next bit). Each direction of a stream and the
// connection as a whole are flow controlled: a receiver says how far the
// sender may go, and extends that as its application consumes data.

import "sync/atomic"

// Handler is told what happens on a connection's streams. Its methods are
// called from Recv and OnTimer, never from Send, and may call the
// connection's stream methods.
type Handler interface {
	// StreamData: the next bytes of stream id, in order. data is valid
	// during the call only. fin says the stream's data ends with it. The
	// bytes stay counted against the windows given to the peer until
	// StreamConsumed says they are done with.
	StreamData(c *Conn, id uint64, data []byte, fin bool)
	// StreamReset: the peer gave up sending on stream id (RESET_STREAM);
	// nothing more comes on it.
	StreamReset(c *Conn, id uint64, code uint64)
	// StreamStop: the peer wants nothing more on stream id (STOP_SENDING).
	// After the call the connection resets the stream's sending side with
	// the same code.
	StreamStop(c *Conn, id uint64, code uint64)
	// StreamWritable: stream id, whose StreamWrite took less than it was
	// given, takes data again.
	StreamWritable(c *Conn, id uint64)
}

// The send buffer. What the streams of a connection hold together that
// the peer has not acknowledged, sent or not, is bounded by a budget that
// follows the congestion window: twice the window, so that a window's
// worth is in flight and as much again waits to follow it. It is never
// less than sendBufferMin (a window starts small, and a response that fits
// lets go of its backend at once) and never more than the configuration
// allows (Config.MaxSendBuffer). Where that names nothing it is
// sendBufferMax, which holds the largest window there is (maxWindowPackets
// datagrams of MaxDatagramSize): what a connection holds is the most it
// moves per round trip, whatever its path carries. 256 KiB per stream, as
// it once was, is 20 Mbit/s at 100 ms; 4 MiB, what a Linux TCP socket's
// send buffer grows to by default, held a download at 100 ms to 270 Mbit/s.
//
// The connections of a process are bounded together as well
// (SetSendMemory): a connection takes no more than is left under that
// bound, and past it no more than sendBufferLow at a time, so that clients
// which ask for much and read nothing cannot make a server hold more than
// it was sized for.
//
// A stream takes only what the client's limits let it send (credit): its
// own limit and the one for all streams together. So everything in the
// buffer waits for the congestion window and for nothing else, and a
// stream whose client does not read it holds none of the buffer: the
// other streams of its connection go on.
const (
	sendBufferMin = 256 << 10
	sendBufferMax = 16 << 20
	sendBufferLow = 16 << 10
	// sendWake is the room there must be before a stream that waits to
	// write is told to go on.
	sendWake = 16 << 10
	// sendStep: a connection reports what it holds to the process's count
	// when that has changed by this much, or is back at nothing.
	sendStep = 32 << 10
)

// sendMemory is what the connections of the process hold to send, as they
// reported it, and sendMemoryMax the bound on it (0: none).
var sendMemory, sendMemoryMax atomic.Int64

// The receive windows. A client may have sent, on a stream and on all its
// streams together, one window more than the application has taken: that
// is what a server may have to hold for it while a backend is slow to take
// an upload, and, over a path with delay, the most an upload moves per
// round trip. The next limit goes out when a quarter of a window is used
// (windowUsed), so a client always has three quarters of a window to go
// on with while that limit is on its way. A window of 1 MiB whose next
// limit went out at half of it held an upload at 100 ms to 39 Mbit/s.
//
// A window starts as Params give it and, where the configuration allows
// more (Config.MaxStreamWindow, MaxConnWindow), grows by quic-go's rule
// (its internal/flowcontrol): when the application took more than half a
// window in less than four round trips' share of that window, the window
// doubles. So it grows only as fast as the application takes what
// arrives: for an upload that a backend takes as fast as the path brings
// it (and for a body nobody waits for any more, which is taken at once),
// never for one that a backend is slow to take. How far a client can get
// it either way is the configuration's and, for all connections together,
// the process's bound below.
// The window of all streams together is at least one and a half of the
// largest stream's (quic-go's rule, Chromium's number), and a stream's
// grows only when that is granted.
//
// What the connections of a process were granted beyond their first
// windows is bounded together (SetReceiveMemory): past the bound no window
// grows, and uploads move as they do with the first window. A connection
// keeps what it was granted until it ends.
var recvMemory, recvMemoryMax atomic.Int64

// windowUsed reports whether so much of a receive window of size w is
// used that the client is to be given its next limit: left is how far the
// limit it has is ahead of what the application took. A quarter of the
// window, as in quic-go (its WindowUpdateThreshold): at half, a client a
// round trip away went on with half a window at a time, and an upload over
// 200 ms moved a fifth less than through the quic-go server.
func windowUsed(left, w uint64) bool { return left <= w-w/4 }

// SetReceiveMemory bounds what the connections of the process may be
// granted together beyond their first receive windows; 0 lifts the bound.
func SetReceiveMemory(max int64) { recvMemoryMax.Store(max) }

// ReceiveMemory returns what the connections of the process were granted
// beyond their first receive windows; ReceiveMemoryLimit the bound on it
// (0: none).
func ReceiveMemory() int64      { return recvMemory.Load() }
func ReceiveMemoryLimit() int64 { return recvMemoryMax.Load() }

// tuned returns the size a receive window of size w has from now on: w, or
// twice w and no more than limit when the application took more than half
// of it since the window's round began (at *at, with *from consumed), in
// less than four round trips' share of w. A round ends with every answer;
// without a round-trip time, or a limit above w, there is none.
func (c *Conn) tuned(w uint64, at *int64, from *uint64, consumed, limit uint64) uint64 {
	took := consumed - *from
	if took <= w/2 || w >= limit || c.rttSmoothed <= 0 {
		return w
	}
	grown := w
	if float64(c.clock-*at) < 4*float64(took)/float64(w)*float64(c.rttSmoothed) {
		grown = min(2*w, limit)
	}
	*at, *from = c.clock, consumed
	return grown
}

// widen makes the connection's receive window at least want bytes (no
// more than Config.MaxConnWindow), if the process's bound has room for
// the difference, and reports whether the window is that wide now.
func (c *Conn) widen(want uint64) bool {
	if want <= c.rwin {
		return true
	}
	if want > c.cfg.MaxConnWindow {
		return false
	}
	d := int64(want - c.rwin)
	if m := recvMemoryMax.Load(); m > 0 && recvMemory.Load()+d > m {
		return false
	}
	recvMemory.Add(d)
	c.rwinCounted += d
	c.rwin = want
	c.recvMaxData = c.consumedData + c.rwin
	c.maxDataDirty = true
	return true
}

// SetSendMemory bounds what the connections of the process hold together
// to send; 0 lifts the bound.
func SetSendMemory(max int64) { sendMemoryMax.Store(max) }

// SendMemory returns what the connections of the process hold to send, to
// within sendStep for each; SendMemoryLimit the bound on it (0: none).
func SendMemory() int64      { return sendMemory.Load() }
func SendMemoryLimit() int64 { return sendMemoryMax.Load() }

// sendBudget is how much the connection's streams may hold together now:
// what its window gives it, and no more than what it holds already plus
// what is left under the process's bound (sendBufferLow in any case).
func (c *Conn) sendBudget() int {
	most := c.sendBufferMost()
	budget := int(min(max(2*c.cc.cwnd, sendBufferMin), most))
	if m := sendMemoryMax.Load(); m > 0 {
		left := max(m-sendMemory.Load(), 0)
		budget = min(budget, max(c.sendHeld+int(min(left, most)), sendBufferLow))
	}
	return budget
}

// sendBufferMost is the upper end of the connection's send buffer: what
// its configuration names, and sendBufferMin at the least (a buffer below
// sendWake would never wake a stream that waits to write); sendBufferMax
// where the configuration names nothing.
func (c *Conn) sendBufferMost() int64 {
	if m := c.cfg.MaxSendBuffer; m > 0 {
		return max(m, sendBufferMin)
	}
	return sendBufferMax
}

// held notes that the connection's streams hold n more bytes to send, or,
// negative, fewer: some were acknowledged or given up. Streams that wait
// to write are told at the end of the Recv or OnTimer in progress, or of
// the next one.
func (c *Conn) held(n int) {
	c.sendHeld += n
	if d := int64(c.sendHeld) - c.sendCounted; d >= sendStep || d <= -sendStep || c.sendHeld == 0 && d != 0 {
		sendMemory.Add(d)
		c.sendCounted = int64(c.sendHeld)
	}
	if n < 0 && len(c.waiting) > 0 {
		c.wakeDue = true
	}
}

// credit is how many more bytes stream s may take to send by the client's
// limits: the stream's, and the connection's less what all streams have
// taken.
func (c *Conn) credit(s *stream) int {
	end := s.sbase + uint64(s.buffered())
	if end >= s.smax || c.sendTaken >= c.sendMaxData {
		return 0
	}
	return int(min(s.smax-end, c.sendMaxData-c.sendTaken, 1<<30))
}

// wakeWriters tells the streams that wait to write, the one that waits
// longest first, while there is room for more. A stream that the client's
// limits hold, not the buffer, is not told and keeps its place: its turn
// comes when the client raises a limit.
func (c *Conn) wakeWriters() {
	c.wakeDue = false
	for i := 0; i < len(c.waiting) && c.state == stateEstablished && c.sendBudget()-c.sendHeld >= sendWake; {
		s := c.waiting[i]
		gone := !s.wantWrite || c.streams[s.id] != s // not what leaveLine leaves behind; kept for safety
		if !gone && c.credit(s) == 0 {
			i++
			continue
		}
		c.waiting = append(c.waiting[:i], c.waiting[i+1:]...)
		if !gone {
			s.wantWrite = false
			c.cfg.Handler.StreamWritable(c, s.id)
			// The application may have reset streams or written to
			// others: the line is not what it was. From its front again.
			i = 0
		}
	}
	if len(c.waiting) == 0 {
		c.waiting = nil
	}
}

// Stream ID bits.
const (
	streamServer = 0x1 // opened by the server
	streamUni    = 0x2 // unidirectional
)

// stream is one stream of a connection.
type stream struct {
	id uint64

	// Receiving.
	rb        reassembly
	recvMax   uint64 // how far the peer may send: the limit it was given
	recvHigh  uint64 // the highest offset it has sent to
	finalSize int64  // the stream's length once known, else -1
	consumed  uint64 // what the application has consumed
	recvDone  bool   // the end was delivered, or the peer reset the stream, or it is send-only
	finTold   bool   // the handler was told the end
	maxDirty  bool   // MAX_STREAM_DATA is to be sent
	// The stream's receive window as it is now, and the round its growth
	// is judged by (tuned).
	rwin, rwinFrom uint64
	rwinAt         int64

	// Sending. sbuf holds the bytes from offset sbase on that are not
	// acknowledged (sbuf[shead:] of them: what is before was acknowledged
	// and waits for the next compaction).
	sbuf     []byte
	shead    int
	sbase    uint64     // the stream offset of sbuf[shead]
	snext    uint64     // the next offset never sent
	smax     uint64     // how far the peer lets us send
	lost     byteRanges // ranges to send again, before new data
	sacked   byteRanges // acknowledged ranges past sbase
	fin      bool       // the application has written the stream's end
	finSent  bool
	finAcked bool
	// A reset of the sending side (RESET_STREAM) and a request to the peer
	// to stop sending (STOP_SENDING): 0 none, 1 to send, 2 sent, 3
	// acknowledged.
	reset, stop         uint8
	resetCode, stopCode uint64
	sendDone            bool // the end, or the reset, is acknowledged, or the stream is receive-only
	wantWrite           bool // a StreamWrite was cut short
	queued              bool // in the connection's send queue
}

const (
	ctlNone = iota
	ctlSend
	ctlSent
	ctlAcked
)

// Kinds of things a sent packet carried that matter when it is
// acknowledged or lost.
const (
	recData = iota + 1 // STREAM data: off, n, fin
	recMaxStreamData
	recReset
	recStop
)

// streamRec is one such thing.
type streamRec struct {
	id   uint64
	off  uint64
	n    uint32
	kind uint8
	fin  bool
}

// maxStreamRecs is how many of them one packet carries.
const maxStreamRecs = 4

func (s *stream) buffered() int { return len(s.sbuf) - s.shead }

// pending reports whether the stream has anything to put in a packet.
func (s *stream) pending() bool {
	if s.reset == ctlSend || s.stop == ctlSend || s.maxDirty {
		return true
	}
	if s.reset != ctlNone {
		return false // a stream that was reset sends no more data
	}
	return len(s.lost) > 0 || s.snext < s.sbase+uint64(s.buffered()) || s.fin && !s.finSent
}

// ---- the connection's side ----

// initStreams sets the connection's own limits from its configuration.
func (c *Conn) initStreams() {
	p := &c.cfg.Params
	if c.cfg.Handler == nil {
		return // nobody to give streams to: none are allowed
	}
	c.maxBidi, c.maxUni = p.InitialMaxStreamsBidi, p.InitialMaxStreamsUni
	c.recvMaxData, c.rwin = p.InitialMaxData, p.InitialMaxData
	c.streams = make(map[uint64]*stream)
}

func (c *Conn) queue(s *stream) {
	if !s.queued {
		s.queued = true
		c.sendq = append(c.sendq, s)
	}
}

// newStream makes the stream with the given ID.
func (c *Conn) newStream(id uint64) *stream {
	var s *stream
	if n := len(c.free); n > 0 {
		s = c.free[n-1]
		c.free = c.free[:n-1]
		sbuf, ranges := s.sbuf[:0], s.rb.ranges[:0]
		*s = stream{sbuf: sbuf}
		s.rb.ranges = ranges
	} else {
		s = &stream{}
	}
	s.id, s.finalSize = id, -1
	mine, uni := id&streamServer != 0, id&streamUni != 0
	switch {
	case mine && uni:
		s.recvDone = true // send-only
		s.smax = c.peer.InitialMaxStreamDataUni
	case uni:
		s.sendDone = true // receive-only
		s.recvMax = c.cfg.Params.InitialMaxStreamDataUni
		s.rwin = s.recvMax
	default:
		c.clientBidi++
		// A stream the client opened in both directions: it sends up to
		// the limit we gave for such streams, we send up to the one it
		// gave for the streams it opens.
		s.recvMax = c.cfg.Params.InitialMaxStreamDataBidiRemote
		s.rwin = s.recvMax
		s.smax = c.peer.InitialMaxStreamDataBidiLocal
	}
	c.streams[id] = s
	return s
}

// clientStream returns the client-opened stream id for a frame that
// arrived on it, opening it (and every lower one of its kind) when the
// frame is the first for it. It returns nil for a stream that is finished
// (the frame is late and is dropped), and false after closing the
// connection: a stream past the limit given to the client.
func (c *Conn) clientStream(now int64, id uint64, frameType uint64) (*stream, bool) {
	idx := id >> 2
	opened, limit := &c.openedBidi, c.maxBidi
	if id&streamUni != 0 {
		opened, limit = &c.openedUni, c.maxUni
	}
	if idx >= limit {
		c.closeWith(now, StreamLimitError, frameType, "")
		return nil, false
	}
	for i := *opened; i <= idx; i++ {
		c.newStream(i<<2 | id&streamUni)
	}
	if idx >= *opened {
		*opened = idx + 1
	}
	return c.streams[id], true
}

// recvSide returns the stream a frame about its receiving side (STREAM,
// RESET_STREAM, STREAM_DATA_BLOCKED) is for. Our own unidirectional
// streams have none, and the server opens no bidirectional ones.
func (c *Conn) recvSide(now int64, id uint64, frameType uint64) (*stream, bool) {
	if id&streamServer != 0 {
		c.closeWith(now, StreamStateError, frameType, "")
		return nil, false
	}
	return c.clientStream(now, id, frameType)
}

// sendSide returns the stream a frame about its sending side
// (MAX_STREAM_DATA, STOP_SENDING) is for: a bidirectional stream of the
// client's, or one of our unidirectional ones that exists.
func (c *Conn) sendSide(now int64, id uint64, frameType uint64) (*stream, bool) {
	switch id & 3 {
	case 0:
		return c.clientStream(now, id, frameType)
	case streamServer | streamUni:
		if id>>2 < c.nextUni {
			return c.streams[id], true
		}
	}
	c.closeWith(now, StreamStateError, frameType, "")
	return nil, false
}

// onStream takes a STREAM frame.
func (c *Conn) onStream(now int64, f *Frame) bool {
	s, ok := c.recvSide(now, f.StreamID, f.Type)
	if !ok || s == nil {
		return ok
	}
	end := f.Offset + uint64(len(f.Data))
	if !c.recvUpTo(now, s, end, f.Fin, f.Type) {
		return false
	}
	if s.recvDone {
		return true // reset before: what still arrives is dropped
	}
	if !s.rb.push(f.Offset, f.Data, streamMaxRanges, func(d []byte) {
		fin := s.finalSize >= 0 && s.rb.next == uint64(s.finalSize)
		s.finTold = s.finTold || fin
		c.cfg.Handler.StreamData(c, s.id, d, fin)
	}) {
		// More separate pieces than a path that merely loses and reorders
		// packets leaves.
		c.closeWith(now, ProtocolViolation, f.Type, "stream data in too many pieces")
		return false
	}
	if c.state >= stateClosing {
		return false // the handler closed the connection
	}
	if s.finalSize >= 0 && s.rb.next == uint64(s.finalSize) {
		if !s.finTold {
			// The end came by itself, after the data.
			s.finTold = true
			c.cfg.Handler.StreamData(c, s.id, nil, true)
		}
		s.recvDone = true
		s.rb.release()
		c.streamDone(s)
	}
	return c.state < stateClosing
}

// recvUpTo accounts for the peer having sent stream s up to offset end
// (fin: and no further), against the stream's and the connection's limits
// and the stream's final size.
func (c *Conn) recvUpTo(now int64, s *stream, end uint64, fin bool, frameType uint64) bool {
	if s.finalSize >= 0 && (end > uint64(s.finalSize) || fin && end != uint64(s.finalSize)) || fin && end < s.recvHigh {
		c.closeWith(now, FinalSizeError, frameType, "")
		return false
	}
	if fin {
		s.finalSize = int64(end)
	}
	if end > s.recvHigh {
		c.recvData += end - s.recvHigh
		s.recvHigh = end
		if end > s.recvMax || c.recvData > c.recvMaxData {
			c.closeWith(now, FlowControlError, frameType, "")
			return false
		}
	}
	return true
}

// onResetStream takes a RESET_STREAM frame: the peer gives up sending.
func (c *Conn) onResetStream(now int64, f *Frame) bool {
	s, ok := c.recvSide(now, f.StreamID, f.Type)
	if !ok || s == nil {
		return ok
	}
	if !c.recvUpTo(now, s, f.FinalSize, true, f.Type) {
		return false
	}
	if s.recvDone {
		return true
	}
	// What the peer sent and the application will never see is done with,
	// for the connection's window.
	c.consumed(uint64(s.finalSize) - s.rb.next)
	s.recvDone = true
	s.rb.release()
	c.cfg.Handler.StreamReset(c, s.id, f.ErrorCode)
	if c.state >= stateClosing {
		return false
	}
	c.streamDone(s)
	return true
}

// onStopSending takes a STOP_SENDING frame: the peer wants no more.
func (c *Conn) onStopSending(now int64, f *Frame) bool {
	s, ok := c.sendSide(now, f.StreamID, f.Type)
	if !ok || s == nil {
		return ok
	}
	if s.sendDone || s.reset != ctlNone {
		return true
	}
	c.cfg.Handler.StreamStop(c, s.id, f.ErrorCode)
	if c.state >= stateClosing {
		return false
	}
	c.resetStream(s, f.ErrorCode)
	return true
}

// onMaxStreamData takes a MAX_STREAM_DATA frame.
func (c *Conn) onMaxStreamData(now int64, f *Frame) bool {
	s, ok := c.sendSide(now, f.StreamID, f.Type)
	if !ok || s == nil {
		return ok
	}
	if f.Max > s.smax {
		s.smax = f.Max
		if s.pending() {
			c.queue(s)
		}
		if s.wantWrite {
			c.wakeDue = true
		}
	}
	return true
}

// consumed gives n bytes of the connection's receive window back.
func (c *Conn) consumed(n uint64) {
	if c.consumedData == 0 {
		c.rwinAt = c.clock // the first round begins with the first byte taken
	}
	c.consumedData += n
	if windowUsed(c.recvMaxData-c.consumedData, c.rwin) {
		if w := c.tuned(c.rwin, &c.rwinAt, &c.rwinFrom, c.consumedData, c.cfg.MaxConnWindow); w > c.rwin {
			c.widen(w)
		}
		c.recvMaxData = c.consumedData + c.rwin
		c.maxDataDirty = true
	}
}

// StreamConsumed says that the application is done with n more bytes it
// was given on stream id: the peer may send that much more.
func (c *Conn) StreamConsumed(id uint64, n int) {
	if n <= 0 || c.state >= stateClosing {
		return
	}
	// Never more than arrived and is not consumed yet, on the stream and
	// on the connection: the windows bound what a client can have the
	// server hold, and an application that counts wrong must not widen
	// them.
	s := c.streams[id]
	if s != nil && !s.recvDone {
		n = int(min(uint64(n), s.rb.next-s.consumed))
	}
	if n = int(min(uint64(n), c.recvData-c.consumedData)); n == 0 {
		return
	}
	c.consumed(uint64(n))
	if s == nil || s.recvDone {
		return // finished: only the connection's window is extended
	}
	if s.consumed == 0 {
		s.rwinAt = c.clock
	}
	s.consumed += uint64(n)
	if windowUsed(s.recvMax-s.consumed, s.rwin) {
		// A stream the client opened in both directions carries its
		// request's body: its window may grow, when the connection's can
		// be one and a half of it.
		if id&streamUni == 0 {
			if w := c.tuned(s.rwin, &s.rwinAt, &s.rwinFrom, s.consumed, c.cfg.MaxStreamWindow); w > s.rwin && c.widen(w+w/2) {
				s.rwin = w
			}
		}
		s.recvMax = s.consumed + s.rwin
		s.maxDirty = true
		c.queue(s)
	}
}

// StreamWrite gives the connection data to send on stream id, and with
// fin the stream's end. It returns how much of data it took: less than all
// of it when the connection's streams hold as much as they may that the
// peer has not acknowledged, or when the client's limits let the stream
// send no more (StreamWritable then tells when to go on; the end is not
// taken either), and 0 for a stream that cannot be written to: unknown,
// finished, reset, or the client's own unidirectional one.
func (c *Conn) StreamWrite(id uint64, data []byte, fin bool) int {
	s := c.streams[id]
	if s == nil || s.sendDone || s.fin || s.reset != ctlNone || c.state >= stateClosing {
		return 0
	}
	n := min(len(data), max(c.sendBudget()-c.sendHeld, 0), c.credit(s))
	if n < len(data) {
		if !s.wantWrite {
			s.wantWrite = true
			c.waiting = append(c.waiting, s)
		}
		fin = false
	}
	if n > 0 {
		if s.shead > 0 && s.shead >= len(s.sbuf)/2 {
			// Let go of what was acknowledged.
			s.sbuf = s.sbuf[:copy(s.sbuf, s.sbuf[s.shead:])]
			s.shead = 0
		}
		s.sbuf = append(s.sbuf, data[:n]...)
		c.sendTaken += uint64(n)
		c.held(n)
	}
	s.fin = fin
	if n > 0 || fin {
		c.queue(s)
	}
	return n
}

// StreamReset gives up sending on stream id: the peer is told with
// RESET_STREAM and what was not delivered is dropped.
func (c *Conn) StreamReset(id uint64, code uint64) {
	if s := c.streams[id]; s != nil && !s.sendDone && s.reset == ctlNone && c.state < stateClosing {
		c.resetStream(s, code)
	}
}

func (c *Conn) resetStream(s *stream, code uint64) {
	s.reset, s.resetCode = ctlSend, code
	// What the stream took and never sent is the client's to give again:
	// the client counts a reset stream as far as it was sent.
	c.sendTaken -= s.sbase + uint64(s.buffered()) - s.snext
	c.held(-s.buffered())
	s.sbuf, s.shead, s.lost = s.sbuf[:0], 0, nil
	c.leaveLine(s)
	c.queue(s)
}

// leaveLine: stream s waits to write no longer (it was reset, or is over).
// It is out of the line now, not when the line is next gone through: a
// client that stops stream after stream it lets send nothing would make
// the line grow without end.
func (c *Conn) leaveLine(s *stream) {
	if !s.wantWrite {
		return
	}
	s.wantWrite = false
	for i, w := range c.waiting {
		if w == s {
			c.waiting = append(c.waiting[:i], c.waiting[i+1:]...)
			break
		}
	}
}

// StreamStopSending asks the peer to send no more on stream id
// (STOP_SENDING). What it still sends is dropped.
func (c *Conn) StreamStopSending(id uint64, code uint64) {
	if s := c.streams[id]; s != nil && !s.recvDone && s.stop == ctlNone && c.state < stateClosing {
		s.stop, s.stopCode = ctlSend, code
		c.queue(s)
	}
}

// Unconsumed returns how many bytes the client has sent on its streams
// that the application has not said it is done with (StreamConsumed): what
// it holds, and what counts against the windows given to the client.
func (c *Conn) Unconsumed() uint64 { return c.recvData - c.consumedData }

// ClientStreams returns how many bidirectional streams of the client are
// not over yet: one is over when the client's side has ended and what this
// side sent on it, to its end, is acknowledged.
func (c *Conn) ClientStreams() int { return c.clientBidi }

// OpenUniStream opens a unidirectional stream to the client. ok is false
// when the client allows no more of them now.
func (c *Conn) OpenUniStream() (id uint64, ok bool) {
	if c.streams == nil || c.nextUni >= c.peerMaxUni || c.state >= stateClosing {
		return 0, false
	}
	id = c.nextUni<<2 | streamServer | streamUni
	c.nextUni++
	c.newStream(id)
	return id, true
}

// streamDone lets go of a stream whose both directions are finished, and
// lets the client open another in its place.
func (c *Conn) streamDone(s *stream) {
	if !s.recvDone || !s.sendDone {
		return
	}
	c.leaveLine(s)
	delete(c.streams, s.id)
	if s.id&streamServer == 0 {
		if s.id&streamUni != 0 {
			c.maxUni++
			c.maxUniDirty = true
		} else {
			c.clientBidi--
			c.maxBidi++
			c.maxBidiDirty = true
		}
	}
	if !s.queued && len(c.free) < 64 {
		// Kept for the next stream, without a large buffer.
		if cap(s.sbuf) > 16<<10 {
			s.sbuf = nil
		}
		c.free = append(c.free, s)
	}
}

// ackStream settles what an acknowledged packet carried for a stream.
func (c *Conn) ackStream(r *streamRec) {
	s := c.streams[r.id]
	if s == nil {
		return
	}
	switch r.kind {
	case recData:
		if s.reset != ctlNone {
			return
		}
		if r.fin {
			s.finAcked = true
		}
		if r.n > 0 {
			s.sacked.add(r.off, r.off+uint64(r.n))
			if end := s.sacked.from(s.sbase); end > s.sbase {
				c.held(-int(end - s.sbase))
				s.shead += int(end - s.sbase)
				s.sbase = end
				for len(s.sacked) > 0 && s.sacked[0][1] <= s.sbase {
					s.sacked = s.sacked[1:]
				}
				if s.shead == len(s.sbuf) {
					s.sbuf, s.shead = s.sbuf[:0], 0
				}
			}
		}
		if s.fin && s.finAcked && s.buffered() == 0 {
			s.sendDone = true
			c.streamDone(s)
		}
	case recReset:
		if s.reset == ctlSent {
			s.reset = ctlAcked
			s.sendDone = true
			c.streamDone(s)
		}
	case recStop:
		if s.stop == ctlSent {
			s.stop = ctlAcked
		}
	}
}

// lostStream queues again what a lost packet carried for a stream.
func (c *Conn) lostStream(r *streamRec) {
	s := c.streams[r.id]
	if s == nil {
		return
	}
	switch r.kind {
	case recData:
		if s.reset != ctlNone {
			return
		}
		if r.n > 0 && r.off+uint64(r.n) > s.sbase {
			s.lost.add(max(r.off, s.sbase), r.off+uint64(r.n))
		}
		if r.fin && !s.finAcked {
			s.finSent = false
		}
	case recMaxStreamData:
		s.maxDirty = !s.recvDone
	case recReset:
		if s.reset == ctlSent {
			s.reset = ctlSend
		}
	case recStop:
		if s.stop == ctlSent {
			s.stop = ctlSend
		}
	}
	if s.pending() {
		c.queue(s)
	}
}

// appendStreams puts what the queued streams have to send into the packet
// b, which may grow to limit bytes: their control frames, the data that
// was lost, then new data as far as the stream's and the connection's
// limits go. It records in p what the packet carries.
func (c *Conn) appendStreams(b []byte, limit int, p *sentPacket) []byte {
	// A STREAM frame needs room for its header and something behind it.
	const minRoom = 32
	n := len(c.sendq)
	for i := 0; i < n && int(p.nrec) < maxStreamRecs && limit-len(b) >= minRoom; i++ {
		s := c.sendq[0]
		c.sendq = c.sendq[:copy(c.sendq, c.sendq[1:])]
		s.queued = false
		if c.streams[s.id] != s {
			continue // finished meanwhile
		}
		b = c.appendStream(b, limit, s, p)
		if s.pending() && c.canSend(s) {
			c.queue(s) // more for the next packet: behind the others
		}
	}
	return b
}

// canSend reports whether stream s can put something in a packet now:
// control frames always, data when its limits leave room.
func (c *Conn) canSend(s *stream) bool {
	if s.reset == ctlSend || s.stop == ctlSend || s.maxDirty || len(s.lost) > 0 {
		return true
	}
	if s.reset != ctlNone {
		return false
	}
	end := s.sbase + uint64(s.buffered())
	if s.snext < end {
		return s.snext < s.smax && c.sentData < c.sendMaxData
	}
	return s.fin && !s.finSent
}

func (c *Conn) appendStream(b []byte, limit int, s *stream, p *sentPacket) []byte {
	rec := func(kind uint8, off uint64, n int, fin bool) {
		p.recs[p.nrec] = streamRec{id: s.id, off: off, n: uint32(n), kind: kind, fin: fin}
		p.nrec++
	}
	if s.reset == ctlSend && int(p.nrec) < maxStreamRecs {
		// The final size is how far the stream was ever sent.
		b = AppendResetStream(b, s.id, s.resetCode, s.snext)
		s.reset = ctlSent
		rec(recReset, 0, 0, false)
	}
	if s.stop == ctlSend && int(p.nrec) < maxStreamRecs {
		b = AppendFrame2(b, FrameStopSending, s.id, s.stopCode)
		s.stop = ctlSent
		rec(recStop, 0, 0, false)
	}
	if s.maxDirty && int(p.nrec) < maxStreamRecs {
		s.maxDirty = false
		if !s.recvDone {
			b = AppendFrame2(b, FrameMaxStreamData, s.id, s.recvMax)
			rec(recMaxStreamData, 0, 0, false)
		}
	}
	if s.reset != ctlNone {
		return b
	}
	end := s.sbase + uint64(s.buffered())
	for int(p.nrec) < maxStreamRecs {
		// What to send next: a lost range first, else new data.
		var off, upTo uint64
		retransmit := false
		for len(s.lost) > 0 {
			r := s.lost[0]
			// Not what was acknowledged meanwhile.
			r[0] = max(s.sacked.from(max(r[0], s.sbase)), s.sbase)
			if r[0] >= r[1] {
				s.lost = s.lost[1:]
				continue
			}
			off, upTo, retransmit = r[0], r[1], true
			// Up to the next acknowledged part.
			for _, a := range s.sacked {
				if a[0] > off {
					upTo = min(upTo, a[0])
					break
				}
			}
			break
		}
		if !retransmit {
			off = s.snext
			upTo = min(end, s.smax)
			if c.sendMaxData-c.sentData < upTo-off && upTo > off {
				upTo = off + (c.sendMaxData - c.sentData)
			}
		}
		n := 0
		if upTo > off {
			n = int(upTo - off)
		}
		fin := s.fin && !s.finSent && off+uint64(n) == end && (retransmit || s.snext+uint64(n) == end)
		if n == 0 && !fin {
			break
		}
		room := limit - len(b) - StreamHeaderLen(s.id, off, n)
		if room <= 0 || n > 0 && room < 1 {
			break
		}
		if n > room {
			n, fin = room, false
		}
		b = AppendStreamHeader(b, s.id, off, n, fin)
		b = append(b, s.sbuf[s.shead+int(off-s.sbase):s.shead+int(off-s.sbase)+n]...)
		rec(recData, off, n, fin)
		if retransmit {
			if s.lost[0][0] = off + uint64(n); s.lost[0][0] >= s.lost[0][1] {
				s.lost = s.lost[1:]
			}
		} else {
			s.snext += uint64(n)
			c.sentData += uint64(n)
		}
		if fin {
			s.finSent = true
		}
		if limit-len(b) < 32 {
			break
		}
	}
	return b
}

// releaseStreams drops every stream: the connection is over.
func (c *Conn) releaseStreams() {
	c.streams, c.sendq, c.free, c.waiting = nil, nil, nil, nil
	sendMemory.Add(-c.sendCounted)
	c.sendHeld, c.sendCounted, c.wakeDue = 0, 0, false
	recvMemory.Add(-c.rwinCounted)
	c.rwinCounted = 0
}
