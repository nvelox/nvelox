//go:build linux

package httpproxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"

	"nvelox/core/h2"
)

// An HTTP/2 stream is one exchange of the fast path: h2stream is its client
// side (downstream), the way fconn is for an HTTP/1.1 connection. The
// exchange and its backend connection decide what is sent; the stream puts
// it in frames, under the client's flow control.

const (
	hsOpen       = iota // the client may still send (a body, trailers)
	hsHalfRemote        // the client has sent END_STREAM
)

type h2stream struct {
	c     *h2conn
	id    uint32
	state uint8
	// closed: no longer a stream of its connection (it may be reused).
	// done: its exchange is over (answered or cancelled); a stream that is
	// done and not closed still has output waiting for a window.
	closed, done bool
	active       bool // an exchange was begun on it
	queued       bool // in c.startq
	ended        bool // END_STREAM is out
	gotTrailers  bool
	responded    bool  // a HEADERS frame went out
	born         int64 // the loop's time when the stream was opened

	x fastExchange

	// The response.
	sendWin int64  // what the stream may still send
	pend    []byte // body bytes waiting for a window: pend[pendAt:]
	pendAt  int
	endPend bool   // the stream ends after pend
	trail   []byte // the trailers' header block, to go out after pend
	hdr     []byte // the header block, while its Content-Type waits for the first body bytes
	blocked bool   // in the connection's list of streams waiting for its window
	bnext   *h2stream
	wt      h2StreamWriteTimer

	// br is set for a request a net/http handler serves (h2bridge_linux.go):
	// the stream then has no exchange.
	br *h2Bridge
	// wlimit is how long the client may open no window for the stream's
	// data (the request's write limit; 0 for a handler's stream, which sets
	// its own deadlines).
	wlimit time.Duration

	// The request body.
	inflow   h2Inflow
	declared int64     // its Content-Length, -1: none
	got      int64     // body bytes the client sent
	body     []byte    // received, not yet taken by the backend
	timer    ngx.Timer // the client's pause while sending it (the read limit)
}

// h2StreamWriteTimer resets a stream whose client opens no window for its
// data for the write limit.
type h2StreamWriteTimer struct {
	ngx.Timer
	s *h2stream
}

func (wt *h2StreamWriteTimer) OnTimer() {
	s := wt.s
	if s.closed || s.c == nil {
		return
	}
	defer s.c.recover()
	s.abort(0)
}

var (
	h2NameDate   = []byte("date")
	h2NameCT     = []byte("content-type")
	h2NameCL     = []byte("content-length")
	h2NameAltSvc = []byte("alt-svc")
	h2NameReqID  = []byte("x-request-id")
	h2Nosniff    = h2.AppendField(nil, []byte("x-content-type-options"), []byte("nosniff"))
	h2HTMLType   = h2.AppendField(nil, h2NameCT, []byte("text/html; charset=utf-8"))
)

// h2Date returns the date field of a response, encoded.
func (fl *fastLoop) h2Date() []byte {
	d := fl.date.get(fl.l.Wall())
	hl := &fl.h2
	if hl.date == nil || hl.dateOf != fl.date.sec {
		hl.dateOf = fl.date.sec
		hl.date = h2.AppendField(hl.date[:0], h2NameDate, d)
	}
	return hl.date
}

// h2AppendField appends a response field to a header block, as HTTP/2
// carries it: its name in lower case (lower is scratch for that). Left out,
// as by Go's server: the fields that belong to an HTTP/1.1 connection, and
// a name or value HTTP/2 does not allow. connClose reports a "Connection:
// close", which asks for the connection to be closed.
func h2AppendField(b []byte, lower *[]byte, name, value []byte) (_ []byte, connClose bool) {
	switch headerKind(name) {
	case hkConnection:
		return b, string(value) == "close"
	case hkKeepAlive, hkProxyConnection, hkTransferEncoding, hkUpgrade:
		return b, false
	}
	n := appendLowerASCII((*lower)[:0], name)
	*lower = n[:0]
	if !h2ValidName(n) {
		return b, false
	}
	for _, c := range value {
		if !isValueChar[c] {
			return b, false
		}
	}
	return h2.AppendField(b, n, value), false
}

// h2AppendLen appends a content-length field.
func h2AppendLen(b []byte, n int64) []byte {
	var tmp [20]byte
	return h2.AppendField(b, h2NameCL, strconv.AppendInt(tmp[:0], n, 10))
}

// h2AppendInformational appends the header block of the 1xx response h.
func h2AppendInformational(b []byte, lower *[]byte, h *respHead) []byte {
	b = h2.AppendStatus(b, h.status)
	for i := range h.headers {
		hd := &h.headers[i]
		if hd.drop || hd.kind == hkContentLength {
			continue
		}
		b, _ = h2AppendField(b, lower, hd.name, hd.value)
	}
	return b
}

// h2AppendTrailers appends the trailer lines of a chunked body (each
// "Name: value\r\n") to a header block.
func h2AppendTrailers(b []byte, lower *[]byte, lines []byte) []byte {
	for len(lines) > 0 {
		e := bytes.Index(lines, crlf)
		if e < 0 {
			break
		}
		line := lines[:e]
		lines = lines[e+2:]
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		switch k := headerKind(line[:colon]); {
		case hopByHop(k), k == hkContentLength:
			continue // never a trailer
		}
		b, _ = h2AppendField(b, lower, line[:colon], trimOWS(line[colon+1:]))
	}
	return b
}

// buildH2 builds, off the loop, what an HTTP/2 client gets of the response
// head j.h: the header block up to the backend's last field.
func (j *bigHead) buildH2() {
	h := &j.h
	var lower []byte
	if h.status >= 100 && h.status < 200 && h.status != http.StatusSwitchingProtocols {
		j.list = h2AppendInformational(make([]byte, 0, h.headLen+64), &lower, h)
		return
	}
	b := make([]byte, 0, h.headLen+len(j.common)+1024)
	b = h2.AppendStatus(b, h.status)
	b = append(b, h2Nosniff...)
	b = append(b, j.common...)
	if len(j.rules[0]) == 0 && len(j.rules[1]) == 0 {
		fl := respFlags{h2: true}
		code := h.status
		bodyAllowed := !(code >= 100 && code < 200) && code != 204 && code != 304
		for i := range h.headers {
			hd := &h.headers[i]
			if hd.drop && !(hd.kind == hkTrailer && h.chunked) {
				continue
			}
			if !fl.out(hd.kind, hd.value, code, j.isHead, bodyAllowed) {
				continue
			}
			b, _ = h2AppendField(b, &lower, hd.name, hd.value)
		}
		j.hasCT, j.hasCE, j.hasDate = fl.hasCT, fl.hasCE, fl.hasDate
	} else {
		hs, hasCT, hasCE, hasDate := respFields(make([]outHeader, 0, len(h.headers)+8), h, j.isHead, &j.rules, true)
		j.hasCT, j.hasCE, j.hasDate = hasCT, hasCE, hasDate
		for i := range hs {
			if !hs[i].drop {
				b, _ = h2AppendField(b, &lower, hs[i].name, hs[i].value)
			}
		}
	}
	if cap(b)-len(b) < 512 {
		b = append(make([]byte, 0, len(b)+512), b...)
	}
	j.list = b
}

// ---- the stream's life ----

// newStream opens stream id (endStream: the request has no body).
func (c *h2conn) newStream(id uint32, endStream bool) *h2stream {
	hl := &c.fl.h2
	s := hl.free
	if s != nil {
		hl.free = s.bnext
		hl.nfree--
	} else {
		s = &h2stream{}
		s.timer.F = s
		s.wt.s = s
		s.wt.F = &s.wt
	}
	s.c, s.id, s.bnext = c, id, nil
	s.state = hsOpen
	if endStream {
		s.state = hsHalfRemote
	}
	s.closed, s.done, s.active, s.queued, s.ended, s.gotTrailers = false, false, false, false, false, false
	s.endPend, s.blocked = false, false
	s.br, s.wlimit = nil, 0
	s.responded, s.born = false, c.l.Now()
	s.sendWin = c.peerWindow
	s.inflow = h2Inflow{avail: h2StreamWindow}
	s.declared, s.got = -1, 0
	s.x.d, s.x.fs, s.x.fl, s.x.l = s, c.fs, c.fl, c.l
	s.x.own = &c.own
	if c.streams == nil {
		c.streams = make(map[uint32]*h2stream)
	}
	c.streams[id] = s
	return s
}

// closeStream ends stream s: it is no longer the connection's.
func (c *h2conn) closeStream(s *h2stream) {
	if s.closed {
		return
	}
	delete(c.streams, s.id)
	c.closedStreams++
	c.release(s)
	if len(c.streams) == 0 {
		c.idle()
	}
}

// release lets go of what a stream holds and keeps it for reuse.
func (c *h2conn) release(s *h2stream) {
	s.closed = true
	c.l.Stop(&s.timer)
	c.l.Stop(&s.wt.Timer)
	c.unblock(s)
	if s.queued {
		s.queued = false
		for i := range c.startq {
			if c.startq[i] == s {
				c.startq[i] = nil
			}
		}
	}
	if c.dataTo == s {
		// The rest of the DATA frame being read is dropped as it comes.
		c.dataTo, c.dataDrop = nil, true
	}
	// Body bytes nobody read: their room in the connection's window goes
	// back to the client.
	c.credit(nil, len(s.body))
	if b := s.br; b != nil {
		s.br = nil
		err := b.closeErr
		if err == nil {
			err = errH2StreamClosed
		}
		c.credit(nil, b.streamClosed(err))
	}
	releaseBuf(&s.pend)
	s.pendAt = 0
	releaseBuf(&s.body)
	releaseBuf(&s.hdr)
	releaseBuf(&s.trail)
	s.x.u = nil
	if hl := &c.fl.h2; hl.nfree < 1024 {
		s.c = nil
		s.bnext = hl.free
		hl.free = s
		hl.nfree++
	}
}

// endStream: the response of s is out. A client that has not finished its
// request is told to stop, with a reset that is no error (Go's server does
// the same when a handler is done before the request's body).
func (c *h2conn) endStream(s *h2stream) {
	if s.state == hsOpen {
		c.reserve(h2.FrameHeaderLen + 4)
		c.out = h2.AppendRSTStream(c.out, s.id, h2.ErrNo)
		c.wantFlush()
	}
	c.closeStream(s)
}

// start serves the request whose header block is blk.
func (s *h2stream) start(blk *h2Block, endStream bool) {
	c := s.c
	req := &c.fl.req
	x := &s.x
	if !blk.fastRequest(req, endStream) || !x.plan(c.fs.g, req) {
		c.slowRequest(s, blk, endStream)
		return
	}
	s.active = true
	s.declared = req.contentLength
	x.peer, x.peerIP, x.peerS, x.peerB, x.secure = c.peer, c.peerIP, c.peerS, c.peerB, true
	x.begin(req, "HTTP/2.0")
	s.wlimit = x.writeLimit
	c.noteWriteLimit(x.writeLimit)
	if !x.prepare(req) {
		return // answered already
	}
	// The first attempt starts once this input is processed (startQueued).
	s.queued = true
	c.startq = append(c.startq, s)
}

// cancel ends the stream's exchange without an answer: its backend
// connection is closed and the request logged, with logStatus when nothing
// was sent.
func (s *h2stream) cancel(logStatus int) {
	if s.done || !s.active {
		s.done = true
		return
	}
	s.done = true
	x := &s.x
	r := &x.fastReq
	if u := r.u; u != nil {
		u.x = nil
		u.close()
	}
	if r.onConnect || r.cbHeld {
		x.endAttempt()
	}
	if !r.sentHead && logStatus != 0 {
		r.logStatus = logStatus
	}
	x.logRequest()
	if r.connLimiter != nil {
		r.connLimiter.Release()
		r.connLimiter = nil
	}
}

// OnTimer: the client paused sending its request body for the read limit.
func (s *h2stream) OnTimer() {
	c := s.c
	if s.closed || c == nil || s.done {
		return
	}
	defer c.recover()
	if r := &s.x.fastReq; r.bodyLeft > 0 && !r.sentHead {
		s.bodyFailed(http.StatusRequestTimeout) // as stall.go answers
		return
	}
	s.abort(0)
}

// ---- the request body ----

// bodyData takes body bytes of the request as they arrive.
func (s *h2stream) bodyData(p []byte) {
	c := s.c
	if b := s.br; b != nil {
		// A handler's request: into its pipe; the client gets its windows
		// back as the handler reads.
		if !b.feed(p) {
			c.credit(nil, len(p))
		}
		return
	}
	r := &s.x.fastReq
	if s.done || !s.active || r.bodyLeft == 0 {
		// Nobody reads the body any more: dropped, and its room in the
		// connection's window given back.
		c.credit(nil, len(p))
		return
	}
	u := r.u
	if len(s.body) > 0 || u == nil || u.state != usSending || !r.sent || len(u.pend) > 0 || u.job != nil {
		// The backend is not ready for it: it waits in the stream, and the
		// client gets its credit when the backend has taken it.
		appendBuf(&s.body, p)
		if u != nil && u.state == usSending && r.sent && s.pumpBody(u) {
			u.bodySent()
		}
		return
	}
	// Straight to the backend.
	c.l.Stop(&s.timer)
	r.bodyTouched = true
	r.bodyLeft -= int64(len(p))
	c.credit(nil, len(p))
	if s.state == hsOpen {
		c.credit(s, len(p))
	}
	w, errno := u.write(p)
	if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR {
		u.failBody(os.NewSyscallError("write", errno))
		return
	}
	if errno != 0 {
		w = 0
	}
	if w < len(p) {
		appendBuf(&u.pend, p[w:])
		u.writable = false
		return
	}
	if r.bodyLeft == 0 {
		u.bodySent()
	}
}

// endBody: the client ended its side of the stream.
func (s *h2stream) endBody() {
	if s.state != hsOpen {
		return
	}
	s.state = hsHalfRemote
	if b := s.br; b != nil {
		var err error = io.EOF
		if s.declared >= 0 && s.got != s.declared {
			err = fmt.Errorf("request declared a Content-Length of %d but only wrote %d bytes", s.declared, s.got)
		}
		b.endBody(err, b.gotTrailer)
		return
	}
	if s.done || !s.active {
		return
	}
	if r := &s.x.fastReq; r.bodyLeft > 0 && s.got < s.declared {
		// Shorter than its Content-Length: the request is answered 400,
		// like an HTTP/1.1 body that breaks off.
		s.bodyFailed(http.StatusBadRequest)
	}
}

// bodyFailed answers a request whose body did not come (downstream's
// counterpart of fconn.bodyFailed).
func (s *h2stream) bodyFailed(code int) {
	r := &s.x.fastReq
	if u := r.u; u != nil {
		u.x = nil
		u.close()
	}
	s.x.endAttempt()
	s.errorPage(code)
}

// pumpBody sends the request body to the backend connection u: what the
// backend has not taken yet, then what the stream holds. True once all of
// it is out (downstream).
func (s *h2stream) pumpBody(u *uconn) bool {
	c := s.c
	r := &s.x.fastReq
	if u.job != nil {
		c.l.Stop(&s.timer)
		return false
	}
	for {
		for len(u.pend) > 0 {
			n, errno := u.write(u.pend)
			if errno == unix.EAGAIN {
				u.writable = false
				return false
			}
			if errno == unix.EINTR {
				continue
			}
			if errno != 0 {
				u.failBody(os.NewSyscallError("write", errno))
				return false
			}
			u.pend = u.pend[:copy(u.pend, u.pend[n:])]
		}
		releaseBuf(&u.pend)
		if r.bodyLeft == 0 {
			c.l.Stop(&s.timer)
			return true
		}
		if len(s.body) == 0 {
			// Waiting for the client: its read limit runs from here.
			if s.state == hsOpen && r.readLimit > 0 && !s.timer.Armed() {
				c.l.Arm(&s.timer, r.readLimit)
			}
			return false
		}
		c.l.Stop(&s.timer)
		r.bodyTouched = true
		chunk := s.body
		if int64(len(chunk)) > r.bodyLeft {
			chunk = chunk[:r.bodyLeft]
		}
		w, errno := u.write(chunk)
		switch {
		case errno == unix.EAGAIN || errno == unix.EINTR:
			w = 0
		case errno != 0:
			u.failBody(os.NewSyscallError("write", errno))
			return false
		}
		if w < len(chunk) {
			appendBuf(&u.pend, chunk[w:])
			u.writable = false
		}
		n := len(chunk)
		r.bodyLeft -= int64(n)
		s.body = s.body[:copy(s.body, s.body[n:])]
		if len(s.body) == 0 {
			releaseBuf(&s.body)
		}
		c.credit(nil, n)
		if s.state == hsOpen {
			c.credit(s, n)
		}
	}
}

// ---- downstream ----

func (s *h2stream) serving() bool { return !s.closed && !s.done }

// broken: the code serving this stream's request panicked. What it left
// half done may be the connection's, so the connection ends.
func (s *h2stream) broken() {
	if c := s.c; c != nil && !s.closed {
		c.endBroken()
	}
}
func (s *h2stream) proto() uint8   { return protoH2 }
func (s *h2stream) mustClose()     {} // endStream resets a stream whose request is unfinished
func (s *h2stream) stopBodyTimer() { s.c.l.Stop(&s.timer) }

// backlog: the stream's own data waits for a window, or the connection has
// too much output waiting for the client.
func (s *h2stream) backlog() bool {
	if len(s.pend) > 0 {
		return true
	}
	if c := s.c; c.outBacklog() > h2OutHigh {
		c.backlogged = true
		return true
	}
	return false
}

// appendCommon appends the fields nvelox puts on every response.
func (s *h2stream) appendCommon(b []byte) []byte {
	r := &s.x.fastReq
	if r.site != nil && r.site.altSvcHeader != "" {
		hl := &s.c.fl.h2
		v := append(hl.name[:0], r.site.altSvcHeader...)
		hl.name = v[:0]
		b = h2.AppendField(b, h2NameAltSvc, v)
	}
	if r.reqIDOn {
		b = h2.AppendField(b, h2NameReqID, r.reqID)
	}
	return b
}

func (s *h2stream) commonHead() []byte { return s.appendCommon(nil) }

func (s *h2stream) informational(h *respHead, pre *bigHead) {
	if s.closed {
		return
	}
	c := s.c
	if pre != nil {
		c.writeHeaders(s, pre.list, false)
		return
	}
	b := h2AppendInformational(c.fl.out[:0], &c.fl.h2.name, h)
	c.fl.out = b[:0]
	c.writeHeaders(s, b, false)
}

// head starts the response: its header block, from the backend's head.
func (s *h2stream) head(u *uconn, h *respHead, pre *bigHead, noBody bool) bool {
	if s.closed {
		return false
	}
	c := s.c
	fl := c.fl
	r := &s.x.fastReq
	var b []byte
	var hasCT, hasCE, hasDate, connClose bool
	if pre != nil {
		b, hasCT, hasCE, hasDate = pre.list, pre.hasCT, pre.hasCE, pre.hasDate
	} else {
		var hs []outHeader
		hs, hasCT, hasCE, hasDate = respFields(fl.hdrs[:0], h, r.isHead, &r.respRules, true)
		fl.hdrs = hs[:0]
		b = h2.AppendStatus(fl.out[:0], h.status)
		b = append(b, h2Nosniff...)
		b = s.appendCommon(b)
		for i := range hs {
			if hs[i].drop {
				continue
			}
			var cc bool
			b, cc = h2AppendField(b, &fl.h2.name, hs[i].name, hs[i].value)
			connClose = connClose || cc
		}
	}
	if !noBody && h.framing == bodyLength {
		b = h2AppendLen(b, h.contentLength)
	}
	if !hasDate {
		b = append(b, fl.h2Date()...)
	}
	// net/http sniffs a Content-Type from the first body bytes when the
	// response has none (and no Content-Encoding): the block then waits
	// for them. A body without a length is flushed head first, unsniffed.
	empty := h.framing == bodyLength && h.contentLength == 0
	if !noBody && !empty && !hasCT && !hasCE && h.framing == bodyLength {
		if pre != nil {
			s.hdr = b
		} else {
			s.hdr = append(getBuf(len(b)+64), b...)
			fl.out = b[:0]
		}
	} else {
		c.writeHeaders(s, b, noBody || empty)
		if pre == nil {
			fl.out = b[:0]
		}
	}
	if connClose {
		c.shutdown(false)
	}
	return !s.closed
}

// data relays body bytes of the response.
func (s *h2stream) data(u *uconn, p []byte) bool {
	if s.closed {
		return false
	}
	if len(p) == 0 {
		return true
	}
	c := s.c
	if s.hdr != nil {
		b := s.hdr
		s.hdr = nil
		hl := &c.fl.h2
		ct := append(hl.name[:0], http.DetectContentType(p)...)
		hl.name = ct[:0]
		b = h2.AppendField(b, h2NameCT, ct)
		c.writeHeaders(s, b, false)
		putBuf(b)
	}
	s.sendData(p, u.framing == bodyLength && int64(len(p)) >= u.remain)
	return true
}

// end ends a body that had no length; trailers are a chunked body's.
func (s *h2stream) end(u *uconn, trailers []byte) bool {
	if s.closed {
		return false
	}
	c := s.c
	var b []byte
	if len(trailers) > 0 {
		b = h2AppendTrailers(c.fl.out[:0], &c.fl.h2.name, trailers)
		c.fl.out = b[:0]
	}
	switch {
	case len(b) == 0:
		s.sendData(nil, true)
	case len(s.pend) > 0:
		s.trail = append(getBuf(len(b)), b...)
		s.endPend = true
	default:
		c.writeHeaders(s, b, true)
	}
	return true
}

// sendData sends body bytes of the response, or keeps what the windows do
// not allow yet; end: the stream ends with them. While other streams wait
// for the connection's window, the bytes wait behind them: a stream that
// has more to send never jumps their turn.
func (s *h2stream) sendData(p []byte, end bool) {
	c := s.c
	if len(s.pend) == 0 && (c.bhead == nil || len(p) == 0) {
		n := c.writeData(s, p, end, len(p))
		if n == len(p) {
			return
		}
		p = p[n:]
	}
	first := len(s.pend) == 0
	appendBuf(&s.pend, p)
	s.endPend = s.endPend || end
	if first {
		if s.sendWin > 0 {
			c.block(s) // it is the connection's window that is used up
		}
		if s.wlimit > 0 {
			c.l.Arm(&s.wt.Timer, s.wlimit)
		}
	}
}

// flushPend sends what waits in the stream, as far as the windows allow
// now. With other streams waiting for the connection's window too, it sends
// one frame and takes its place behind them.
func (s *h2stream) flushPend() {
	c := s.c
	for len(s.pend) > s.pendAt {
		limit := len(s.pend) - s.pendAt
		if c.bhead != nil {
			limit = c.peerFrame
		}
		n := c.writeData(s, s.pend[s.pendAt:], s.endPend && s.trail == nil, limit)
		if n == 0 {
			break
		}
		// What was sent stays in front of the rest until all of it is
		// sent: a client that opens its window a byte at a time has that
		// byte dealt with, and not everything behind it moved.
		s.pendAt += n
		if s.wlimit > 0 {
			c.l.Arm(&s.wt.Timer, s.wlimit) // the client took some
		}
		if c.bhead != nil {
			break
		}
	}
	if len(s.pend) > s.pendAt {
		if s.sendWin > 0 {
			c.block(s)
		}
		return
	}
	releaseBuf(&s.pend)
	s.pendAt = 0
	c.l.Stop(&s.wt.Timer)
	if s.trail != nil {
		c.writeHeaders(s, s.trail, true)
		releaseBuf(&s.trail)
	}
	s.endPend = false
	if s.done {
		c.endStream(s)
		return
	}
	if b := s.br; b != nil {
		b.answer(nil) // its handler writes on
		return
	}
	if u := s.x.u; u != nil && u.paused {
		u.resume()
	}
}

// errorPage answers the request with nvelox's page for a status.
func (s *h2stream) errorPage(code int) {
	if s.closed {
		return
	}
	c := s.c
	fl := c.fl
	r := &s.x.fastReq
	body := errorPageBody(r.site, code)
	b := h2.AppendStatus(fl.out[:0], code)
	b = append(b, h2HTMLType...)
	b = append(b, h2Nosniff...)
	b = s.appendCommon(b)
	b = h2AppendLen(b, int64(len(body)))
	b = append(b, fl.h2Date()...)
	fl.out = b[:0]
	r.sentHead, r.status = true, code
	if r.isHead || len(body) == 0 {
		c.writeHeaders(s, b, true)
	} else {
		c.writeHeaders(s, b, false)
		s.sendData(body, true)
	}
	r.bytes = int64(len(body))
	s.finish()
}

// finish: the response is complete. The stream closes once all of it is
// out.
func (s *h2stream) finish() {
	if s.closed || s.done {
		return
	}
	s.done = true
	c := s.c
	x := &s.x
	r := &x.fastReq
	c.l.Stop(&s.timer)
	x.logRequest()
	if r.connLimiter != nil {
		r.connLimiter.Release()
		r.connLimiter = nil
	}
	if !s.ended && !s.endPend {
		s.sendData(nil, true)
	}
	if len(s.pend) == 0 {
		c.l.Stop(&s.wt.Timer)
		c.endStream(s)
	}
}

// abort: the response cannot be completed. The stream is reset (as Go's
// server resets one whose handler gave up), its request cancelled.
func (s *h2stream) abort(logStatus int) {
	if s.closed {
		return
	}
	c := s.c
	s.cancel(logStatus)
	if c.state < hcDraining {
		c.reserve(h2.FrameHeaderLen + 4)
		c.out = h2.AppendRSTStream(c.out, s.id, h2.ErrInternal)
		c.wantFlush()
	}
	c.closeStream(s)
}
