//go:build linux

package httpproxy

// A request stream of an HTTP/3 connection on the loops: the frames of the
// request, and the client's side of the exchange (downstream). It follows
// h2stream_linux.go; what differs is the wire (frames on a QUIC stream,
// QPACK) and who keeps the windows (the transport).

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"time"

	"github.com/nvelox/ngx"
	"github.com/nvelox/ngx/h3"
	"golang.org/x/sys/unix"
)

// What the payload of the frame being read is.
const (
	h3fSkip = iota // a frame type this server does not know: dropped
	h3fData
	h3fHead
)

type h3stream struct {
	c  *h3conn
	id uint64
	// closed: no longer a stream of its connection (it may be reused).
	// done: its exchange is over (answered or cancelled); a stream that is
	// done and not closed still has output the transport has not taken.
	closed, done bool
	active       bool // an exchange was begun on it
	queued       bool // in c.startq
	waiting      bool // its head is here, and whether a body follows is open (c.undecided)
	recvEnd      bool // the client's side of the stream ended
	gotHead      bool // the request's field section arrived
	gotTrailers  bool
	ended        bool // this side's end is in the transport's hands
	// refused: the request was answered before its head was read (too
	// large, or not here in time); what the client still sends of it is
	// dropped.
	refused bool
	born    int64 // the loop's time when the stream was opened
	headAt  int64 // and when its head was complete (a request that waits)

	x fastExchange

	// The frame being read.
	fhdr  [16]byte // its header, when it arrived in pieces
	fhdrN int
	fleft uint64 // what is to come of its payload
	fkind uint8
	hbuf  []byte // a HEADERS frame's payload

	// The response.
	pend    []byte // what the transport has not taken yet: pend[pendAt:]
	pendAt  int
	endPend bool   // the stream ends after pend
	hdr     []byte // the field section, while its Content-Type waits for the first body bytes
	wt      h3StreamWriteTimer
	// wlimit is how long the client may take none of the stream's data
	// (the request's write limit; 0 for a handler's stream, which sets its
	// own deadlines).
	wlimit time.Duration
	// br is set for a request a net/http handler serves
	// (h3bridge_linux.go): the stream then has no exchange.
	br *h2Bridge

	// The request body.
	declared int64     // its Content-Length, -1: none
	got      int64     // body bytes the client announced in DATA frames
	body     []byte    // received, not yet taken by the backend
	timer    ngx.Timer // the client's pause while sending it (the read limit)

	fnext *h3stream // the loop's list of streams to reuse
}

// h3StreamWriteTimer resets a stream whose client takes none of its data
// for the write limit.
type h3StreamWriteTimer struct {
	ngx.Timer
	s *h3stream
}

func (wt *h3StreamWriteTimer) OnTimer() {
	s := wt.s
	if s.closed || s.c == nil {
		return
	}
	defer s.c.recover()
	s.abort(0)
}

var (
	h3Nosniff  = h3.AppendField(nil, []byte("x-content-type-options"), []byte("nosniff"))
	h3HTMLType = h3.AppendField(nil, h2NameCT, []byte("text/html; charset=utf-8"))
)

// h3Date returns the date field of a response, encoded.
func (fl *fastLoop) h3Date() []byte {
	d := fl.date.get(fl.l.Wall())
	hl := &fl.h3
	if hl.date == nil || hl.dateOf != fl.date.sec {
		hl.dateOf = fl.date.sec
		hl.date = h3.AppendField(hl.date[:0], h2NameDate, d)
	}
	return hl.date
}

// h3AppendField appends a response field to a field section, under the
// rules of h2AppendField: its name in lower case, and left out what belongs
// to an HTTP/1.1 connection or is not a valid name or value. connClose
// reports a "Connection: close".
func h3AppendField(b []byte, lower *[]byte, name, value []byte) (_ []byte, connClose bool) {
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
	return h3.AppendField(b, n, value), false
}

func h3AppendLen(b []byte, n int64) []byte {
	var tmp [20]byte
	return h3.AppendField(b, h2NameCL, strconv.AppendInt(tmp[:0], n, 10))
}

// h3AppendInformational appends the field section of the 1xx response h.
func h3AppendInformational(b []byte, lower *[]byte, h *respHead) []byte {
	b = h3.AppendStatus(h3.AppendPrefix(b), h.status)
	for i := range h.headers {
		hd := &h.headers[i]
		if hd.drop || hd.kind == hkContentLength {
			continue
		}
		b, _ = h3AppendField(b, lower, hd.name, hd.value)
	}
	return b
}

// h3AppendTrailers appends the trailer lines of a chunked body (each
// "Name: value\r\n") as a field section.
func h3AppendTrailers(b []byte, lower *[]byte, lines []byte) []byte {
	b = h3.AppendPrefix(b)
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
		b, _ = h3AppendField(b, lower, line[:colon], trimOWS(line[colon+1:]))
	}
	return b
}

// buildH3 builds, off the loop, what an HTTP/3 client gets of the response
// head j.h: the field section up to the backend's last field (buildH2's
// counterpart).
func (j *bigHead) buildH3() {
	h := &j.h
	var lower []byte
	if h.status >= 100 && h.status < 200 && h.status != http.StatusSwitchingProtocols {
		j.list = h3AppendInformational(make([]byte, 0, h.headLen+64), &lower, h)
		return
	}
	b := make([]byte, 0, h.headLen+len(j.common)+1024)
	b = h3.AppendStatus(h3.AppendPrefix(b), h.status)
	b = append(b, h3Nosniff...)
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
			b, _ = h3AppendField(b, &lower, hd.name, hd.value)
		}
		j.hasCT, j.hasCE, j.hasDate = fl.hasCT, fl.hasCE, fl.hasDate
	} else {
		hs, hasCT, hasCE, hasDate := respFields(make([]outHeader, 0, len(h.headers)+8), h, j.isHead, &j.rules, true)
		j.hasCT, j.hasCE, j.hasDate = hasCT, hasCE, hasDate
		for i := range hs {
			if !hs[i].drop {
				b, _ = h3AppendField(b, &lower, hs[i].name, hs[i].value)
			}
		}
	}
	if cap(b)-len(b) < 512 {
		b = append(make([]byte, 0, len(b)+512), b...)
	}
	j.list = b
}

// ---- the request's frames ----

// recv takes bytes of the request stream; fin: the client's side ends with
// them.
func (s *h3stream) recv(p []byte, fin bool) {
	c, id := s.c, s.id
	// The stream can end while its input is served, and be given to
	// another request: it is this request's while it is listed.
	alive := func() bool { return !c.over && c.streams[id] == s }
	// refused: the request was answered before its head was read, and its
	// client asked to stop. What still arrives is no longer looked at: not
	// what follows in p, and not the end of the stream, which may come in
	// the middle of a frame.
	refused := func() bool {
		if !s.refused {
			return false
		}
		s.recvEnd = s.recvEnd || fin
		c.dropInput(id, len(p))
		return true
	}
	if refused() {
		return
	}
	for len(p) > 0 {
		if s.fleft == 0 {
			// A frame header: two integers of up to eight bytes each.
			k := copy(s.fhdr[s.fhdrN:], p)
			typ, length, n := h3.FrameHeader(s.fhdr[:s.fhdrN+k])
			if n == 0 {
				s.fhdrN += k
				c.q.StreamConsumed(id, k)
				p = p[k:]
				continue
			}
			used := n - s.fhdrN
			s.fhdrN = 0
			c.q.StreamConsumed(id, used)
			p = p[used:]
			s.frame(typ, length, fin && len(p) == 0)
			if !alive() {
				c.dropInput(id, len(p))
				return
			}
			if refused() {
				return
			}
			continue
		}
		n := int(min(uint64(len(p)), s.fleft))
		chunk := p[:n]
		p = p[n:]
		s.fleft -= uint64(n)
		switch s.fkind {
		case h3fData:
			s.bodyData(chunk) // its room in the windows goes back as the backend takes it
		case h3fHead:
			appendBuf(&s.hbuf, chunk)
			c.q.StreamConsumed(id, n)
		default:
			c.q.StreamConsumed(id, n)
		}
		if alive() && s.fleft == 0 && s.fkind == h3fHead {
			s.headers(fin && len(p) == 0)
		}
		if !alive() {
			c.dropInput(id, len(p))
			return
		}
		if refused() {
			return
		}
	}
	if fin {
		s.inputEnd()
	}
}

// dropInput gives back the room of n bytes that arrived for a request that
// is over.
func (c *h3conn) dropInput(id uint64, n int) {
	if !c.over && n > 0 {
		c.q.StreamConsumed(id, n)
	}
}

// frame begins a frame of the request stream; last: nothing follows it on
// the stream.
func (s *h3stream) frame(typ, length uint64, last bool) {
	panicProbe("h3-frame")
	c := s.c
	known, err := h3.RequestFrame(typ)
	if err != nil {
		code, ok := err.(h3.Error)
		if !ok {
			code = h3.ErrFrameUnexpected
		}
		c.fail(code, "request stream")
		return
	}
	switch {
	case !known:
		s.fkind = h3fSkip
	case typ == h3.FrameData:
		if !s.gotHead || s.gotTrailers {
			c.fail(h3.ErrFrameUnexpected, "a DATA frame out of place")
			return
		}
		if s.waiting {
			// A body follows the head.
			s.waiting = false
			s.begin(false)
			if s.closed || c.over {
				return
			}
		}
		if length > 1<<60 {
			s.malformed()
			return
		}
		s.got += int64(length)
		if s.declared >= 0 && s.got > s.declared {
			s.malformed() // longer than its Content-Length
			return
		}
		s.fkind = h3fData
	default: // HEADERS
		if s.gotTrailers {
			c.fail(h3.ErrFrameUnexpected, "a HEADERS frame after the trailers")
			return
		}
		if length > uint64(c.maxHead) {
			// More than the largest field section this server takes, which
			// its settings announce: answered here, at the frame's header,
			// not after the bytes it announces (a client may never send
			// them).
			if s.gotHead {
				s.refuse(h3.ErrExcessiveLoad) // trailers
			} else {
				s.answerLocal(http.StatusRequestHeaderFieldsTooLarge, h3.ErrExcessiveLoad)
			}
			return
		}
		// The payload is kept as it arrives: nothing is set aside for what
		// a frame header merely announces.
		s.fkind = h3fHead
		releaseBuf(&s.hbuf)
		if length == 0 {
			s.fleft = 0
			s.headers(last)
			return
		}
	}
	s.fleft = length
}

// headers: a HEADERS frame is complete: the request's head, or its
// trailers. last: the stream ended with it.
func (s *h3stream) headers(last bool) {
	c := s.c
	if !s.gotHead {
		s.gotHead = true
		c.l.Stop(&s.timer) // the head is here in time
		if last {
			s.begin(true)
			return
		}
		// The stream goes on. With a Content-Length the request is what
		// its head says. Without one, what comes next tells: the stream's
		// end (no body) or a body; the request waits for it, for
		// h3DecideWait at most.
		blk := c.decode(s, true)
		if c.over {
			return
		}
		if blk.truncated {
			releaseBuf(&s.hbuf)
			s.serve(blk, false) // more than the server takes: answered now
			return
		}
		for i := range blk.fields {
			if string(blk.fieldName(i)) == "content-length" {
				releaseBuf(&s.hbuf)
				s.serve(blk, false)
				return
			}
		}
		s.waiting, s.headAt = true, c.l.Now()
		c.undecided = append(c.undecided, s)
		if !c.dt.Armed() {
			c.l.Arm(&c.dt.Timer, h3DecideWait)
		}
		return
	}
	// Trailers end the body. Only a request that announced them keeps
	// any, and that one is a handler's; for the others they are checked
	// and dropped.
	s.gotTrailers = true
	blk := c.decode(s, false)
	if c.over || s.closed {
		return
	}
	if blk.truncated {
		s.refuse(h3.ErrExcessiveLoad) // more than the server takes
		return
	}
	if pseudo, ok := blk.pseudos(); blk.invalid || !ok || pseudo != 0 {
		s.malformed()
		return
	}
	if b := s.br; b != nil && b.wantsTrailers {
		tr := http.Header{}
		for i := range blk.fields {
			key := textproto.CanonicalMIMEHeaderKey(string(blk.fieldName(i)))
			if !h2ValidTrailer(key) {
				s.malformed()
				return
			}
			tr[key] = append(tr[key], string(blk.fieldValue(i)))
		}
		b.gotTrailer = tr
	}
}

// decode reads the field section in s.hbuf into the loop's block, and
// lets go of s.hbuf unless keep is set. On a section that cannot be
// decoded the connection ends.
func (c *h3conn) decode(s *h3stream, keep bool) *h2Block {
	fl := c.fl
	blk := &fl.h2.blk
	blk.resetLimit(h2MaxHeaderList)
	hl := &fl.h3
	hl.size, hl.limit = 0, c.maxHead
	if hl.emit == nil {
		hl.emit = func(name, value []byte) error {
			// A section's size is its names and values and 32 bytes for
			// each field (RFC 9114, section 4.2.2), all of its fields in
			// one count: past the connection's limit nothing more is
			// kept, and the request is answered 431. (The block's own
			// budgets, an HTTP/2 block's, are wider and count a trailer
			// field apart.)
			if hl.size += uint32(len(name)) + uint32(len(value)) + h2FieldOverhead; hl.size > hl.limit {
				blk.truncated = true
				return nil
			}
			blk.add(name, value)
			return nil
		}
	}
	err := h3.DecodeFields(s.hbuf, &hl.qpack, h3MaxString, hl.emit)
	if !keep || err != nil {
		releaseBuf(&s.hbuf)
	}
	if err != nil {
		c.fail(h3.ErrQPACKDecompression, "field section")
	}
	return blk
}

// begin serves the request whose head is in s.hbuf; endStream: it has no
// body.
func (s *h3stream) begin(endStream bool) {
	c := s.c
	blk := c.decode(s, false)
	if c.over {
		return
	}
	s.serve(blk, endStream)
}

// serve serves the request whose head was decoded into blk.
func (s *h3stream) serve(blk *h2Block, endStream bool) {
	c := s.c
	if blk.truncated {
		// Larger than the server takes once decoded (a frame holds its
		// fields compressed): the answer of a frame that announces as
		// much, whatever else the head says.
		s.answerLocal(http.StatusRequestHeaderFieldsTooLarge, h3.ErrExcessiveLoad)
		return
	}
	if _, ok := blk.pseudos(); blk.invalid || !ok {
		s.malformed()
		return
	}
	req := &c.fl.req
	x := &s.x
	if !blk.fastRequest(req, endStream) || !x.plan(c.fs.g, req) {
		c.slowRequest(s, blk, endStream)
		return
	}
	s.active = true
	s.declared = req.contentLength
	x.peer, x.peerIP, x.peerS, x.peerB, x.secure = c.peer, c.peerIP, c.peerS, c.peerB, true
	x.begin(req, "HTTP/3.0")
	s.wlimit = x.writeLimit
	if !x.prepare(req) {
		return // answered already
	}
	// The first attempt starts once this input is dealt with (inputDone).
	s.queued = true
	c.startq = append(c.startq, s)
}

// h3Malformed reports whether the request in blk, whose pseudo-header
// fields are well formed as a set, breaks a rule a request is held to
// before anything serves it. They are the rules of the HTTP/2 connections
// (h2conn.slowRequest): no extended CONNECT, the pseudo-header fields its
// method needs, no user information in the authority, a path that begins
// with a slash, and one Content-Length, which is 0 for a request without a
// body.
func h3Malformed(blk *h2Block, endStream bool) bool {
	var method, scheme, path, authority []byte
	hasProtocol := false
	i := 0
	for ; i < len(blk.fields); i++ {
		name := blk.fieldName(i)
		if name[0] != ':' {
			break
		}
		v := blk.fieldValue(i)
		switch string(name) {
		case ":method":
			method = v
		case ":scheme":
			scheme = v
		case ":path":
			path = v
		case ":authority":
			authority = v
		case ":protocol":
			hasProtocol = true
		}
	}
	isConnect := string(method) == "CONNECT"
	web := string(scheme) == "https" || string(scheme) == "http"
	bad := hasProtocol
	if isConnect {
		bad = bad || len(path) > 0 || len(scheme) > 0 || len(authority) == 0
	} else {
		bad = bad || len(method) == 0 || len(path) == 0 || !web
	}
	host, hostSet := authority, len(authority) > 0
	declared, hasCL, dupCL := int64(-1), false, false
	var firstCL []byte
	for ; i < len(blk.fields); i++ {
		name, v := blk.fieldName(i), blk.fieldValue(i)
		switch headerKind(name) {
		case hkHost:
			if !hostSet {
				host, hostSet = v, true
			}
		case hkContentLength:
			if !hasCL {
				hasCL, firstCL = true, v
				declared, _ = parseRespContentLength(v) // not a number: counts as 0
			} else if !bytes.Equal(v, firstCL) {
				dupCL = true
			}
		}
	}
	bad = bad || web && bytes.IndexByte(host, '@') >= 0
	if !isConnect && !bad {
		bad = path[0] != '/' && string(path) != "*"
	}
	return bad || hasCL && (dupCL || endStream && declared != 0)
}

// inputEnd: the client's side of the stream ended.
func (s *h3stream) inputEnd() {
	c := s.c
	s.recvEnd = true
	if s.fleft > 0 || s.fhdrN > 0 {
		c.fail(h3.ErrFrame, "a frame cut short by the end of its stream")
		return
	}
	if !s.gotHead {
		c.reject(s, h3.ErrRequestIncomplete)
		return
	}
	if s.waiting {
		s.waiting = false
		s.begin(true)
		if s.closed || c.over {
			return
		}
	}
	s.endBody()
}

// malformed ends a request that broke the rules of a message: the stream
// is reset, the connection goes on.
func (s *h3stream) malformed() { s.refuse(h3.ErrMessage) }

// refuse resets the stream with code and cancels what was begun on it.
func (s *h3stream) refuse(code h3.Error) {
	c := s.c
	s.cancel(http.StatusBadRequest)
	c.reject(s, code)
}

// cancel ends the stream's exchange without an answer: its backend
// connection is closed and the request logged, with logStatus when nothing
// was sent.
func (s *h3stream) cancel(logStatus int) {
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

// OnTimer: the request's head is not here within the time the listener
// gives it, or the client paused sending its body for the read limit.
func (s *h3stream) OnTimer() {
	c := s.c
	if s.closed || c == nil || s.done {
		return
	}
	defer c.recover()
	if !s.gotHead {
		s.answerLocal(http.StatusRequestTimeout, h3.ErrNoError)
		return
	}
	if r := &s.x.fastReq; r.bodyLeft > 0 && !r.sentHead {
		s.bodyFailed(http.StatusRequestTimeout)
		return
	}
	s.abort(0)
}

// ---- the request body ----

// bodyData takes body bytes of the request as they arrive. Their room in
// the client's windows goes back when the backend has taken them.
func (s *h3stream) bodyData(p []byte) {
	c := s.c
	if b := s.br; b != nil {
		// A handler's request: into its pipe; the client gets the room
		// back as the handler reads.
		if !b.feed(p) {
			c.q.StreamConsumed(s.id, len(p))
		}
		return
	}
	r := &s.x.fastReq
	if s.done || !s.active || r.bodyLeft == 0 {
		c.q.StreamConsumed(s.id, len(p)) // nobody reads the body any more
		return
	}
	u := r.u
	if len(s.body) > 0 || u == nil || u.state != usSending || !r.sent || len(u.pend) > 0 || u.job != nil {
		// The backend is not ready for it: it waits in the stream.
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
	c.q.StreamConsumed(s.id, len(p))
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
func (s *h3stream) endBody() {
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
		// Shorter than its Content-Length: answered 400, like an HTTP/1.1
		// body that breaks off.
		s.bodyFailed(http.StatusBadRequest)
	}
}

// bodyFailed answers a request whose body did not come.
func (s *h3stream) bodyFailed(code int) {
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
func (s *h3stream) pumpBody(u *uconn) bool {
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
			if !s.recvEnd && r.readLimit > 0 && !s.timer.Armed() {
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
		c.q.StreamConsumed(s.id, n)
		c.qc.wake() // the client learns of the room
	}
}

// ---- downstream ----

func (s *h3stream) serving() bool { return !s.closed && !s.done }

// broken: the code serving this stream's request panicked. What it left
// half done may be the connection's, so the connection ends.
func (s *h3stream) broken() {
	if c := s.c; c != nil && !s.closed {
		c.endBroken()
	}
}
func (s *h3stream) proto() uint8   { return protoH3 }
func (s *h3stream) mustClose()     {} // endStream asks a client whose request is unfinished to stop
func (s *h3stream) stopBodyTimer() { s.c.l.Stop(&s.timer) }

func (s *h3stream) addrs() (client, local net.Addr) {
	if c := s.c; c != nil {
		return c.addrs()
	}
	return nil, nil
}

// backlog: the transport has not taken all of the stream's data.
func (s *h3stream) backlog() bool { return len(s.pend) > 0 }

// appendCommon appends the fields nvelox puts on every response.
func (s *h3stream) appendCommon(b []byte) []byte {
	r := &s.x.fastReq
	if r.site != nil && r.site.altSvcHeader != "" {
		hl := &s.c.fl.h2
		v := append(hl.name[:0], r.site.altSvcHeader...)
		hl.name = v[:0]
		b = h3.AppendField(b, h2NameAltSvc, v)
	}
	if r.reqIDOn {
		b = h3.AppendField(b, h2NameReqID, r.reqID)
	}
	return b
}

func (s *h3stream) commonHead() []byte { return s.appendCommon(nil) }

// out gives bytes of the stream to the transport (frames, as they go on
// the wire); what it does not take waits in s.pend. fin: the stream ends
// with them.
func (s *h3stream) out(p []byte, fin bool) {
	if s.closed {
		return
	}
	c := s.c
	if len(s.pend) == 0 && !s.endPend {
		n := c.q.StreamWrite(s.id, p, fin)
		c.qc.wake()
		if n == len(p) {
			if fin {
				s.ended = true
			}
			return
		}
		p = p[n:]
		if s.wlimit > 0 {
			c.l.Arm(&s.wt.Timer, s.wlimit)
		}
	}
	appendBuf(&s.pend, p)
	s.endPend = s.endPend || fin
}

// writeHeaders sends a HEADERS frame whose payload is the field section
// block.
func (s *h3stream) writeHeaders(block []byte, fin bool) {
	var fh [16]byte
	s.out(h3.AppendFrameHeader(fh[:0], h3.FrameHeaders, uint64(len(block))), false)
	s.out(block, fin)
}

// sendData sends body bytes of the response as a DATA frame; end: the
// stream ends with them.
func (s *h3stream) sendData(p []byte, end bool) {
	if len(p) > 0 {
		var fh [16]byte
		s.out(h3.AppendFrameHeader(fh[:0], h3.FrameData, uint64(len(p))), false)
	}
	if len(p) > 0 || end {
		s.out(p, end)
	}
}

// flushPend: the transport takes data again (streamWritable).
func (s *h3stream) flushPend() {
	c := s.c
	if len(s.pend) > 0 || s.endPend {
		n := c.q.StreamWrite(s.id, s.pend[s.pendAt:], s.endPend)
		c.qc.wake()
		if s.pendAt+n < len(s.pend) {
			// What was taken stays in front of the rest until all of it is
			// taken: a client that raises its limit a byte at a time has
			// that byte dealt with, and not everything behind it moved.
			s.pendAt += n
			if n > 0 && s.wlimit > 0 {
				c.l.Arm(&s.wt.Timer, s.wlimit) // the client took some
			}
			return
		}
		if s.endPend {
			s.ended = true
		}
		releaseBuf(&s.pend)
		s.pendAt = 0
		s.endPend = false
		c.l.Stop(&s.wt.Timer)
	}
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

func (s *h3stream) informational(h *respHead, pre *bigHead) {
	if s.closed {
		return
	}
	if pre != nil {
		s.writeHeaders(pre.list, false)
		return
	}
	fl := s.c.fl
	b := h3AppendInformational(fl.out[:0], &fl.h2.name, h)
	fl.out = b[:0]
	s.writeHeaders(b, false)
}

// head starts the response: its field section, from the backend's head.
func (s *h3stream) head(u *uconn, h *respHead, pre *bigHead, noBody bool) bool {
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
		b = h3.AppendStatus(h3.AppendPrefix(fl.out[:0]), h.status)
		b = append(b, h3Nosniff...)
		b = s.appendCommon(b)
		for i := range hs {
			if hs[i].drop {
				continue
			}
			var cc bool
			b, cc = h3AppendField(b, &fl.h2.name, hs[i].name, hs[i].value)
			connClose = connClose || cc
		}
	}
	if !noBody && h.framing == bodyLength {
		b = h3AppendLen(b, h.contentLength)
	}
	if !hasDate {
		b = append(b, fl.h3Date()...)
	}
	// net/http sniffs a Content-Type from the first body bytes when the
	// response has none (and no Content-Encoding): the section then waits
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
		s.writeHeaders(b, noBody || empty)
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
func (s *h3stream) data(u *uconn, p []byte) bool {
	if s.closed {
		return false
	}
	if len(p) == 0 {
		return true
	}
	if s.hdr != nil {
		b := s.hdr
		s.hdr = nil
		hl := &s.c.fl.h2
		ct := append(hl.name[:0], http.DetectContentType(p)...)
		hl.name = ct[:0]
		b = h3.AppendField(b, h2NameCT, ct)
		s.writeHeaders(b, false)
		putBuf(b)
	}
	s.sendData(p, u.framing == bodyLength && int64(len(p)) >= u.remain)
	return true
}

// end ends a body that had no length; trailers are a chunked body's.
func (s *h3stream) end(u *uconn, trailers []byte) bool {
	if s.closed {
		return false
	}
	if len(trailers) > 0 {
		fl := s.c.fl
		b := h3AppendTrailers(fl.out[:0], &fl.h2.name, trailers)
		fl.out = b[:0]
		if len(b) > 2 { // more than the section's prefix
			s.writeHeaders(b, true)
			return true
		}
	}
	s.sendData(nil, true)
	return true
}

// errorPage answers the request with nvelox's page for a status.
func (s *h3stream) errorPage(code int) {
	if s.closed {
		return
	}
	fl := s.c.fl
	r := &s.x.fastReq
	body := errorPageBody(r.site, code)
	b := h3.AppendStatus(h3.AppendPrefix(fl.out[:0]), code)
	b = append(b, h3HTMLType...)
	b = append(b, h3Nosniff...)
	b = s.appendCommon(b)
	b = h3AppendLen(b, int64(len(body)))
	b = append(b, fl.h3Date()...)
	fl.out = b[:0]
	r.sentHead, r.status = true, code
	if r.isHead || len(body) == 0 {
		s.writeHeaders(b, true)
	} else {
		s.writeHeaders(b, false)
		s.sendData(body, true)
	}
	r.bytes = int64(len(body))
	s.finish()
}

// answerLocal answers a request that is not read to its end, with the
// status code and its page, and asks the client to send no more of it
// (with the error code stop): a head larger than the server takes, or one
// that was not here in time. Nothing of the request was served and none is
// logged: its site and its path are not known.
func (s *h3stream) answerLocal(code int, stop h3.Error) {
	if s.closed || s.done {
		return
	}
	c := s.c
	fl := c.fl
	body := defaultErrorBody(code)
	b := h3.AppendStatus(h3.AppendPrefix(fl.out[:0]), code)
	b = append(b, h3HTMLType...)
	b = append(b, h3Nosniff...)
	b = h3AppendLen(b, int64(len(body)))
	b = append(b, fl.h3Date()...)
	fl.out = b[:0]
	s.refused, s.done = true, true
	s.wlimit = h3LocalAnswerLimit
	c.l.Stop(&s.timer)
	releaseBuf(&s.hbuf)
	if !s.recvEnd {
		// (The transport takes the first request to stop: the one without
		// an error that follows when the answer is out changes nothing.)
		c.q.StreamStopSending(s.id, uint64(stop))
	}
	s.writeHeaders(b, false)
	s.sendData(body, true)
	if len(s.pend) == 0 && !s.endPend {
		c.endStream(s)
	}
}

// finish: the response is complete. The stream closes once all of it is in
// the transport's hands.
func (s *h3stream) finish() {
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
		s.out(nil, true)
	}
	if len(s.pend) == 0 && !s.endPend {
		c.l.Stop(&s.wt.Timer)
		c.endStream(s)
	}
}

// abort: the response cannot be completed. The stream is reset, its
// request cancelled.
func (s *h3stream) abort(logStatus int) {
	if s.closed {
		return
	}
	c := s.c
	s.cancel(logStatus)
	c.reject(s, h3.ErrInternal)
}
