//go:build linux

package httpproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"time"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"

	"nvelox/core/h2"
	"nvelox/core/logging"
)

// HTTP/2 on the event loops. A connection that negotiated "h2" is served by
// its loop: frames are read and written here, every stream is one exchange
// of the fast path (h2stream_linux.go) on the same backend pools as
// HTTP/1.1, and what leaves for the client in one pass of the loop is
// encrypted and written once, at the end of that pass. The rules of the
// protocol, the limits and the error a broken rule gets are those of Go's
// HTTP/2 server (net/http/internal/http2), which served these connections
// before.

const (
	// What the client is told (SETTINGS), as Go's server tells it; the
	// frame size and the header table are left at the protocol's defaults.
	h2MaxStreams   = 250
	h2StreamWindow = 1 << 20
	h2ConnWindow   = 1 << 20

	h2PrefaceTimeout  = 10 * time.Second
	h2SettingsTimeout = 2 * time.Second
	// h2GoAwayWait is how long a connection stays open after its last
	// GOAWAY, so that the client reads it before the close (a close with
	// unread input resets the connection and can destroy the frame).
	h2GoAwayWait = time.Second

	// h2MinRefresh: window credit is announced once it is at least this
	// much, or as much as the window that is left.
	h2MinRefresh = 4 << 10
	// h2MaxSettings bounds the parameters of one SETTINGS frame.
	h2MaxSettings = 100

	// h2OutHigh: with more output than this waiting for the client, no
	// backend of the connection is read.
	h2OutHigh = 64 << 10
	// h2InputPause: with more output than this waiting, no frame is read
	// from the client either. Answers to its frames (PING, SETTINGS, resets)
	// can then never pile up without bound.
	h2InputPause = 256 << 10
	// h2ReadRound is how much input one connection takes before it gives
	// way to the loop's other connections.
	h2ReadRound = 64 << 10
	// h2FlushChunk is how much output is encrypted in one go.
	h2FlushChunk = 64 << 10

	// Three limits Go's server does not have. On a loop, what one
	// connection wastes is taken from every connection of that loop.
	//
	// A client that resets its requests before they are answered, each
	// within h2EarlyReset of opening it, is cut off (ENHANCE_YOUR_CALM)
	// once half of h2EarlyResetStreams streams ended that way, or, past
	// that many streams, half of all its streams (Envoy's rule and
	// numbers).
	h2EarlyReset        = time.Second
	h2EarlyResetStreams = 500
	// Frames that do nothing (an empty DATA frame that does not end its
	// stream, an empty CONTINUATION frame, frames for a stream that is
	// closed) are counted: more than h2Glitches of them, and more than the
	// streams the connection completed, and it is cut off too.
	h2Glitches = 1000
)

const (
	hcPreface  = iota // waiting for the client's preface
	hcSettings        // waiting for its first SETTINGS frame
	hcOpen
	hcDraining // GOAWAY sent, input ignored: closing after h2GoAwayWait
	hcClosed
)

// h2Inflow is a receive window: what the client may still send, and the
// credit it has not been told about yet.
type h2Inflow struct{ avail, unsent int32 }

func (f *h2Inflow) take(n uint32) bool {
	if n > uint32(f.avail) {
		return false
	}
	f.avail -= int32(n)
	return true
}

// add gives n bytes of credit back; it returns what to announce now (0:
// later, together with more).
func (f *h2Inflow) add(n int) int32 {
	unsent := int64(f.unsent) + int64(n)
	f.unsent = int32(unsent)
	if f.unsent < h2MinRefresh && f.unsent < f.avail {
		return 0
	}
	f.avail += f.unsent
	f.unsent = 0
	return int32(unsent)
}

// h2Loop is what a loop keeps for its HTTP/2 connections.
type h2Loop struct {
	blk    h2Block   // the header block being decoded
	free   *h2stream // streams to reuse
	nfree  int
	dirty  []*h2conn // connections with output for the end of this pass
	hook   int
	hooked bool
	name   []byte // a field name in lower case
	date   []byte // the date field, encoded
	dateOf int64
}

// h2conn is one HTTP/2 connection on a loop.
type h2conn struct {
	fs  *fastServer
	fl  *fastLoop
	l   *ngx.Loop
	fd  int
	reg ngx.Reg
	tls *fastTLS

	state    int
	unlisted bool // no longer counted among the server's connections
	// own: the connection's idle connections to send_proxy_v2 backends
	// (proxysend.go), shared by its streams.
	own          ownConns
	lprev, lnext *h2conn
	peer         netip.Addr
	peerIP       net.IP
	peerS        string
	peerB        []byte

	readable, writable, rdhup bool
	reading                   bool // inside onReadable
	flushQ                    bool // in the loop's list of connections to flush
	inPaused                  bool // input waits for the output to drain
	laterQ                    bool
	laterFn                   func()

	timer ngx.Timer    // preface, first SETTINGS, idle, or the wait after GOAWAY
	wt    h2WriteTimer // the client takes no output
	hbt   h2BlockTimer // a header block is not finished within the header timeout
	// What the limits above count.
	closedStreams, earlyResets, glitches uint32

	// Input: an incomplete frame, and the DATA frame whose payload is
	// being taken as it arrives.
	in       []byte
	dataLeft uint32    // payload bytes still to come, padding included
	dataPad  uint32    // of those, padding at the end
	dataTo   *h2stream // nil: the data is dropped
	dataEnd  bool      // the frame ends its stream
	dataDrop bool      // its stream ended inside the frame: the rest is given back to the window

	// The header block in progress (HEADERS and its CONTINUATION frames).
	hbStream uint32   // 0: none
	hbEnd    bool     // END_STREAM on its HEADERS frame
	hbSelf   bool     // its HEADERS frame made the stream depend on itself
	saved    *h2Block // the block, while it waits for input across events
	dec      h2.Decoder
	emit     func(name, value []byte, sensitive bool) error

	streams map[uint32]*h2stream
	maxID   uint32      // the highest stream the client opened
	startq  []*h2stream // requests whose first attempt starts after this input

	unacked    int   // our SETTINGS frames not acknowledged yet
	peerWindow int64 // the client's INITIAL_WINDOW_SIZE
	peerFrame  int   // the client's MAX_FRAME_SIZE
	sendWin    int64 // what the connection may still send
	inflow     h2Inflow
	needSize   bool // the next header block starts with a table size update

	out     []byte // frames not encrypted yet
	pending []byte // ciphertext the socket has not taken
	wsince  int
	// writeLimit is the longest write limit of the requests the connection
	// has carried (0: none yet, the default applies; negative: one of them
	// had no limit).
	writeLimit time.Duration
	backlogged bool      // a backend was told to wait for the output to drain
	bhead      *h2stream // streams with data waiting for the connection's window
	btail      *h2stream

	goAway   bool   // GOAWAY sent: no new streams above lastID
	lastID   uint32 // the last stream the GOAWAY allows
	stopping bool   // the server is stopping: close when the streams are done

	// Requests served by net/http handlers (h2bridge_linux.go): the
	// handler goroutines running, and the requests waiting for one.
	handlers  int
	unstarted []*h2Bridge
	// slowCtx is the context of those requests, made with the first one;
	// cb the connection's backends on that path (send_proxy_v2).
	slowCtx  context.Context
	cb       *clientBackends
	remote   string               // the client's address, as a request's RemoteAddr
	tlsState *tls.ConnectionState // for the handlers' requests
}

type h2connList struct{ head *h2conn }

func (l *h2connList) add(c *h2conn) {
	c.lnext, c.lprev = l.head, nil
	if l.head != nil {
		l.head.lprev = c
	}
	l.head = c
}

func (l *h2connList) remove(c *h2conn) {
	if c.lprev != nil {
		c.lprev.lnext = c.lnext
	} else if l.head == c {
		l.head = c.lnext
	}
	if c.lnext != nil {
		c.lnext.lprev = c.lprev
	}
	c.lprev, c.lnext = nil, nil
}

// h2WriteTimer closes a connection whose client takes no output for the
// write limit.
type h2WriteTimer struct {
	ngx.Timer
	c *h2conn
}

func (wt *h2WriteTimer) OnTimer() {
	c := wt.c
	defer c.recover()
	c.close()
}

// h2BlockTimer ends a connection whose client started a header block and
// did not finish it within the bind address's header timeout (Go's server
// waits for as long as the connection may be idle).
type h2BlockTimer struct {
	ngx.Timer
	c *h2conn
}

func (t *h2BlockTimer) OnTimer() {
	c := t.c
	defer c.recover()
	if c.hbStream != 0 {
		c.connError(h2.ErrProtocol)
	}
}

// glitch counts a frame that does nothing.
func (c *h2conn) glitch() {
	if c.glitches++; c.glitches > h2Glitches && c.glitches > c.closedStreams {
		c.connError(h2.ErrEnhanceYourCalm)
	}
}

// earlyReset counts a request the client reset before any answer and
// within h2EarlyReset of opening it.
func (c *h2conn) earlyReset() {
	c.earlyResets++
	if c.closedStreams < h2EarlyResetStreams {
		if c.earlyResets*2 < h2EarlyResetStreams {
			return
		}
	} else if c.earlyResets*2 < c.closedStreams {
		return
	}
	c.connError(h2.ErrEnhanceYourCalm)
}

// h2CipherOK reports whether a TLS connection may carry HTTP/2 here: TLS
// 1.3, or TLS 1.2 with one of its ephemeral AEAD suites. Anything else goes
// to net/http, which refuses it or not by its own list (RFC 9113, 9.2).
func h2CipherOK(st *tls.ConnectionState) bool {
	switch st.Version {
	case tls.VersionTLS13:
		return true
	case tls.VersionTLS12:
		switch st.CipherSuite {
		case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			return true
		}
	}
	return false
}

// addH2Conn starts serving fd, a connection that negotiated HTTP/2, on
// loop l.
func (fs *fastServer) addH2Conn(l *ngx.Loop, fd int, peer netip.Addr, t *fastTLS) {
	if fs.closing.Load() {
		unix.Close(fd)
		return
	}
	fl := fastLoopOf(l)
	c := &h2conn{fs: fs, fl: fl, l: l, fd: fd, tls: t,
		peerWindow: h2.DefaultWindow, peerFrame: h2.DefaultMaxFrameSize, sendWin: h2.DefaultWindow,
		needSize: true}
	c.peer = peer
	a16 := peer.As16()
	c.peerIP = net.IP(a16[:])
	c.peerB = appendAddr(nil, peer)
	c.peerS = string(c.peerB)
	c.remote = t.tt.remote.String()
	st := t.tc.ConnectionState()
	c.tlsState = &st
	c.timer.F = c
	c.wt.c = c
	c.wt.F = &c.wt
	c.hbt.c = c
	c.hbt.F = &c.hbt
	c.dec.MaxString = h2MaxHeaderList
	c.dec.Reset()
	c.emit = c.onField
	t.tt.owner = c
	reg, err := l.Register(fd, c)
	if err != nil {
		unix.Close(fd)
		return
	}
	c.reg = reg
	fs.active.Add(1)
	fs.h2lists[l.ID()].add(c)
	if !fl.h2.hooked {
		fl.h2.hooked = true
		fl.h2.hook = l.OnIterationEnd(fl.h2Flush)
	}
	// The server's side of the preface: its settings, and the connection's
	// window raised from the protocol's 65,535.
	c.reserve(64)
	c.out = h2.AppendSettings(c.out,
		h2.Setting{ID: h2.SettingMaxConcurrentStreams, Val: h2MaxStreams},
		h2.Setting{ID: h2.SettingMaxHeaderListSize, Val: h2MaxHeaderList},
		h2.Setting{ID: h2.SettingInitialWindowSize, Val: h2StreamWindow},
		h2.Setting{ID: h2.SettingNoRFC7540Priorities, Val: 1})
	c.unacked = 1
	c.out = h2.AppendWindowUpdate(c.out, 0, h2ConnWindow-h2.DefaultWindow)
	c.inflow.avail = h2ConnWindow
	c.wantFlush()
	l.Arm(&c.timer, h2PrefaceTimeout)
	// The handshake may have read the client's first frames already.
	c.readable = true
	defer c.recover()
	c.onReadable()
}

// recover keeps a panic in the code of one connection from ending the
// process: the connection is closed, the others go on.
func (c *h2conn) recover() {
	r := recover()
	if r == nil {
		return
	}
	logLoopPanic("HTTP/2 connection from "+c.peerS, r)
	c.endBroken()
}

// endBroken ends a connection after a panic in the code serving it: the
// usual way under its own recover, then whatever that did not get to (the
// panic may have come from there, or come again): the requests still
// listed, each on its own, the socket, and the connection's place among
// the server's.
func (c *h2conn) endBroken() {
	c.fl.tlsDirect = false // a write of the loop may have been cut short
	func() {
		defer func() { _ = recover() }()
		c.close()
	}()
	for id, s := range c.streams {
		delete(c.streams, id)
		// cancel takes the request's backend connection off it first, so
		// the stream can be let go of even when the rest of cancel fails.
		func() {
			defer func() { _ = recover() }()
			s.cancel(statusClientClosedRequest)
		}()
		func() {
			defer func() { _ = recover() }()
			c.release(s)
		}()
	}
	c.bhead, c.btail = nil, nil
	c.startq = nil
	func() {
		defer func() { _ = recover() }()
		c.own.closeAll()
	}()
	if cb := c.cb; cb != nil {
		c.cb = nil
		cb.closeFromLoop()
	}
	c.state = hcClosed
	c.l.Stop(&c.timer)
	c.l.Stop(&c.wt.Timer)
	c.l.Stop(&c.hbt.Timer)
	if c.fd >= 0 {
		c.l.Unregister(c.fd, c.reg)
		unix.Close(c.fd)
		c.fd = -1
	}
	c.unlist()
}

// unlist takes the connection out of the server's list and count (once).
func (c *h2conn) unlist() {
	if c.unlisted {
		return
	}
	c.unlisted = true
	c.fs.h2lists[c.l.ID()].remove(c)
	c.fs.active.Add(-1)
	c.fs.checkDrained()
}

func (c *h2conn) OnEvent(ev uint32) {
	if c.state == hcClosed {
		return
	}
	defer c.recover()
	if ev&(ngx.EvErr|ngx.EvHup) != 0 {
		c.readable, c.writable, c.rdhup = true, true, true
	}
	if ev&ngx.EvRDHUP != 0 {
		c.rdhup = true
	}
	if ev&ngx.EvOut != 0 {
		c.writable = true
		if len(c.pending) > 0 || len(c.out) > 0 {
			c.flush()
			if c.state == hcClosed {
				return
			}
		}
	}
	if ev&(ngx.EvIn|ngx.EvRDHUP) != 0 {
		c.readable = true
	}
	if c.mayRead() {
		c.onReadable()
	}
}

func (c *h2conn) mayRead() bool { return c.readable || c.tls.more }

// tlsOut takes ciphertext the tls.Conn writes (tlsOwner).
func (c *h2conn) tlsOut(p []byte) {
	if c.fl.tlsDirect && len(c.pending) == 0 {
		c.fl.tlsBuf = append(c.fl.tlsBuf, p...)
		return
	}
	// An answer to a post-handshake message, or output behind what the
	// socket has not taken.
	appendBuf(&c.pending, p)
	c.wantFlush()
}

// recv reads plaintext into p: n > 0, or 0 with eof or err set; nothing to
// read now: (0, false, nil).
func (c *h2conn) recv(p []byte) (int, bool, error) {
	f := c.tls
	tt := f.tt
	for {
		c.fl.tlsDirect = false
		n, err := f.tc.Read(p)
		if c.state == hcClosed {
			return 0, false, net.ErrClosed
		}
		if n > 0 {
			f.more = true
			return n, false, nil
		}
		f.more = false
		switch {
		case err == nil:
			continue
		case err == errWouldBlock:
		case errors.Is(err, io.EOF):
			return 0, true, nil
		default:
			return 0, false, err
		}
		if !c.readable {
			return 0, false, nil
		}
		if tt.in == nil {
			tt.in = getBuf(64 << 10)
		}
		if cap(tt.in)-len(tt.in) < 4096 {
			nb := getBuf(len(tt.in) + 64<<10)
			nb = append(nb, tt.in...)
			putBuf(tt.in)
			tt.in = nb
		}
		free := tt.in[len(tt.in):cap(tt.in)]
		m, errno := ngx.Read(c.fd, free)
		switch {
		case errno == unix.EAGAIN:
			c.readable = false
			if len(tt.in) == 0 {
				releaseBuf(&tt.in)
			}
			return 0, false, nil
		case errno == unix.EINTR:
			continue
		case errno != 0:
			return 0, false, errno
		case m == 0:
			tt.eof = true
			continue
		}
		if m < len(free) && !c.rdhup {
			c.readable = false
		}
		tt.in = tt.in[:len(tt.in)+m]
	}
}

// onReadable reads and serves the client's frames. It does not nest, takes
// at most h2ReadRound of input before it gives way, and reads nothing while
// too much output waits for the client.
func (c *h2conn) onReadable() {
	if c.reading {
		return
	}
	c.reading = true
	got := 0
	for c.state != hcClosed && c.mayRead() {
		if c.outBacklog() > h2InputPause {
			c.inPaused = true // flush goes on from here
			break
		}
		if got >= h2ReadRound {
			c.later()
			break
		}
		// Into the loop's second buffer: serving a frame can make a
		// backend be read (a window that opens, a body that ends), and
		// that reads into the first one while frames of this read are
		// still to be served.
		buf := c.l.Scratch2[:ngx.ScratchSize]
		n, eof, err := c.recv(buf)
		if n == 0 {
			if eof || err != nil {
				c.close()
			}
			break
		}
		got += n
		data := buf[:n]
		if len(c.in) > 0 {
			// The rest of a frame that was cut by the end of a read.
			appendBuf(&c.in, data)
			data = c.in
		}
		used := c.frames(data)
		if c.state == hcClosed {
			break
		}
		switch rest := data[used:]; {
		case len(rest) == 0:
			releaseBuf(&c.in)
		case len(c.in) > 0:
			c.in = c.in[:copy(c.in, rest)]
		default:
			appendBuf(&c.in, rest)
		}
	}
	c.reading = false
	if c.state == hcClosed {
		return
	}
	c.startQueued()
	if c.hbStream != 0 && c.saved == nil {
		// The header block goes on in a later event: the loop's scratch
		// is another connection's by then.
		c.saveBlock()
	}
}

// later goes on reading from the loop's task queue, after the events that
// are waiting.
func (c *h2conn) later() {
	if c.laterQ {
		return
	}
	c.laterQ = true
	if c.laterFn == nil {
		c.laterFn = func() {
			c.laterQ = false
			if c.state != hcClosed && c.mayRead() {
				defer c.recover()
				c.onReadable()
			}
		}
	}
	c.l.Post(c.laterFn)
}

// startQueued starts the first backend attempt of the requests this input
// brought, now that all of it is processed: a request the client reset in
// the same input never reaches a backend.
func (c *h2conn) startQueued() {
	for i := 0; i < len(c.startq); i++ {
		s := c.startq[i]
		c.startq[i] = nil
		if s == nil {
			continue
		}
		s.queued = false
		if !s.closed && !s.done {
			s.x.attempt()
			if c.state == hcClosed {
				return
			}
		}
	}
	c.startq = c.startq[:0]
}

// ---- frames ----

// frames serves the frames at the start of p and returns how many bytes it
// took: whole frames, and the payload of a DATA frame as far as it is here.
func (c *h2conn) frames(p []byte) int {
	used := 0
	for c.state < hcDraining {
		if c.dataLeft > 0 {
			n := min(len(p)-used, int(c.dataLeft))
			if n == 0 {
				return used
			}
			c.onData(p[used : used+n])
			used += n
			continue
		}
		rest := p[used:]
		if c.state == hcPreface {
			n := min(len(rest), len(h2.ClientPreface))
			if string(rest[:n]) != h2.ClientPreface[:n] {
				c.close() // not HTTP/2
				return len(p)
			}
			if n < len(h2.ClientPreface) {
				return used
			}
			used += n
			c.state = hcSettings
			c.l.Arm(&c.timer, h2SettingsTimeout)
			continue
		}
		if len(rest) < h2.FrameHeaderLen {
			return used
		}
		fh := h2.ReadFrameHeader(rest)
		if fh.Length > h2.DefaultMaxFrameSize {
			c.connError(h2.ErrFrameSize)
			break
		}
		// Between a HEADERS frame without END_HEADERS and the end of its
		// block only CONTINUATION frames of that stream may come, and a
		// CONTINUATION frame comes nowhere else.
		if c.hbStream != 0 {
			if fh.Type != h2.FrameContinuation || fh.StreamID != c.hbStream {
				c.connError(h2.ErrProtocol)
				break
			}
		} else if fh.Type == h2.FrameContinuation {
			c.connError(h2.ErrProtocol)
			break
		}
		if code, _ := fh.Check(h2.DefaultMaxFrameSize); code != h2.ErrNo {
			c.connError(code)
			break
		}
		if c.state == hcSettings {
			if fh.Type != h2.FrameSettings {
				c.connError(h2.ErrProtocol)
				break
			}
			c.state = hcOpen
			c.idle()
		}
		if fh.Type == h2.FrameData {
			need := h2.FrameHeaderLen
			if fh.Flags&h2.FlagPadded != 0 {
				if fh.Length == 0 {
					c.connError(h2.ErrProtocol)
					break
				}
				need++ // the pad length
			}
			if len(rest) < need {
				return used
			}
			pad := uint32(0)
			if need > h2.FrameHeaderLen {
				pad = uint32(rest[h2.FrameHeaderLen])
			}
			used += need
			c.startData(fh, pad)
			continue
		}
		total := h2.FrameHeaderLen + int(fh.Length)
		if len(rest) < total {
			return used
		}
		used += total
		c.frame(fh, rest[h2.FrameHeaderLen:total])
	}
	return len(p)
}

// frame serves a frame other than DATA.
func (c *h2conn) frame(fh h2.FrameHeader, p []byte) {
	panicProbe("frame")
	switch fh.Type {
	case h2.FrameHeaders:
		c.onHeaders(fh, p)
	case h2.FrameContinuation:
		if len(p) == 0 {
			c.glitch()
		}
		c.fragment(p, fh.Flags&h2.FlagEndHeaders != 0)
	case h2.FrameSettings:
		c.onSettings(fh, p)
	case h2.FrameWindowUpdate:
		c.onWindowUpdate(fh, p)
	case h2.FramePing:
		if fh.Flags&h2.FlagAck == 0 {
			c.reserve(h2.FrameHeaderLen + 8)
			c.out = h2.AppendPing(c.out, true, p)
			c.wantFlush()
		}
	case h2.FrameRSTStream:
		c.onReset(fh)
	case h2.FramePriority:
		// Priorities of RFC 7540 are not used; a stream that depends on
		// itself is still an error of that stream.
		if dep := uint32(p[0]&0x7f)<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3]); dep == fh.StreamID {
			c.streamError(fh.StreamID, h2.ErrProtocol)
		}
	case h2.FrameGoAway:
		// The client is leaving: no new streams, the open ones finish.
		c.shutdown(false)
	}
	// Frames of other types are ignored.
}

// streamState is the state of stream id: its stream when it is open, else
// whether the client opened it before (closed) or never (idle).
func (c *h2conn) streamOf(id uint32) (s *h2stream, idle bool) {
	if s = c.streams[id]; s != nil {
		return s, false
	}
	return nil, id&1 == 0 || id > c.maxID
}

// discards reports whether frames of stream id are dropped: after a GOAWAY,
// those of streams above the last one it allows.
func (c *h2conn) discards(id uint32) bool { return c.goAway && id > c.lastID }

func (c *h2conn) onSettings(fh h2.FrameHeader, p []byte) {
	if fh.Flags&h2.FlagAck != 0 {
		if c.unacked--; c.unacked < 0 {
			c.connError(h2.ErrProtocol)
		}
		return
	}
	if len(p)/6 > h2MaxSettings {
		c.connError(h2.ErrProtocol)
		return
	}
	for i := 6; i < len(p); i += 6 {
		for j := 0; j < i; j += 6 {
			if p[i] == p[j] && p[i+1] == p[j+1] {
				c.connError(h2.ErrProtocol) // one parameter twice
				return
			}
		}
	}
	for i := 0; i < len(p); i += 6 {
		s := h2.ReadSetting(p[i:])
		if code := h2.CheckSetting(s); code != h2.ErrNo {
			c.connError(code)
			return
		}
		switch s.ID {
		case h2.SettingInitialWindowSize:
			// Every stream's window moves by the difference.
			delta := int64(s.Val) - c.peerWindow
			c.peerWindow = int64(s.Val)
			for _, st := range c.streams {
				if st.sendWin += delta; st.sendWin > h2.MaxWindow {
					c.connError(h2.ErrFlowControl)
					return
				}
			}
			if delta > 0 {
				c.windowOpened()
			}
		case h2.SettingMaxFrameSize:
			c.peerFrame = int(s.Val)
		case h2.SettingNoRFC7540Priorities:
			if s.Val > 1 {
				c.connError(h2.ErrProtocol)
				return
			}
		}
	}
	c.reserve(h2.FrameHeaderLen)
	c.out = h2.AppendSettingsAck(c.out)
	c.wantFlush()
}

// windowOpened: stream windows grew (a SETTINGS change): streams with data
// waiting go on.
func (c *h2conn) windowOpened() {
	for _, st := range c.streams {
		if len(st.pend) > 0 && !st.blocked {
			st.flushPend()
			if c.state >= hcDraining {
				return
			}
		}
	}
}

func (c *h2conn) onWindowUpdate(fh h2.FrameHeader, p []byte) {
	incr := (uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])) & 0x7fffffff
	if fh.StreamID == 0 {
		if incr == 0 {
			c.connError(h2.ErrProtocol)
			return
		}
		if !h2.AddWindow(&c.sendWin, incr) {
			c.connError(h2.ErrFlowControl)
			return
		}
		// The streams that waited for the connection's window, in turn,
		// a frame each.
		for c.sendWin > 0 && c.bhead != nil {
			s := c.bhead
			c.unblock(s)
			s.flushPend()
			if c.state >= hcDraining {
				return
			}
		}
		return
	}
	if incr == 0 {
		c.streamError(fh.StreamID, h2.ErrProtocol)
		return
	}
	s, idle := c.streamOf(fh.StreamID)
	if idle {
		c.connError(h2.ErrProtocol)
		return
	}
	if s == nil {
		c.glitch() // a closed stream: the update was on its way
		return
	}
	if !h2.AddWindow(&s.sendWin, incr) {
		c.streamError(fh.StreamID, h2.ErrFlowControl)
		return
	}
	if len(s.pend) > 0 && !s.blocked {
		s.flushPend()
	}
}

func (c *h2conn) onReset(fh h2.FrameHeader) {
	s, idle := c.streamOf(fh.StreamID)
	if idle {
		c.connError(h2.ErrProtocol)
		return
	}
	if s == nil {
		c.glitch() // closed already
		return
	}
	early := !s.responded && c.l.Now()-s.born < int64(h2EarlyReset)
	s.cancel(statusClientClosedRequest)
	c.closeStream(s)
	if early && c.state == hcOpen {
		c.earlyReset()
	}
}

// ---- header blocks ----

// onField takes a decoded field of the block in progress.
func (c *h2conn) onField(name, value []byte, _ bool) error {
	c.fl.h2.blk.add(name, value)
	return nil
}

func (c *h2conn) onHeaders(fh h2.FrameHeader, p []byte) {
	pad := 0
	if fh.Flags&h2.FlagPadded != 0 {
		if len(p) < 1 {
			c.connError(h2.ErrProtocol)
			return
		}
		pad, p = int(p[0]), p[1:]
	}
	self := false
	if fh.Flags&h2.FlagPriority != 0 {
		if len(p) < 5 {
			c.connError(h2.ErrProtocol)
			return
		}
		self = (uint32(p[0]&0x7f)<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])) == fh.StreamID
		p = p[5:]
	}
	if pad > len(p) {
		// More padding than payload. (Go resets the stream and goes on; the
		// block would then be missing from the decoder's table, so here the
		// connection ends, as RFC 9113 6.2 has it.)
		c.connError(h2.ErrProtocol)
		return
	}
	p = p[:len(p)-pad]
	c.hbStream, c.hbEnd, c.hbSelf = fh.StreamID, fh.Flags&h2.FlagEndStream != 0, self
	c.fl.h2.blk.reset()
	c.fragment(p, fh.Flags&h2.FlagEndHeaders != 0)
}

// fragment decodes the next fragment of the header block in progress; end
// says it is the last one.
func (c *h2conn) fragment(p []byte, end bool) {
	blk := &c.fl.h2.blk
	if c.saved != nil {
		// The block started in an earlier event.
		blk.arena = append(blk.arena[:0], c.saved.arena...)
		blk.fields = append(blk.fields[:0], c.saved.fields...)
		blk.remain, blk.remainTrailer = c.saved.remain, c.saved.remainTrailer
		blk.count, blk.countTrailer = c.saved.count, c.saved.countTrailer
		blk.sawRegular, blk.invalid, blk.truncated = c.saved.sawRegular, c.saved.invalid, c.saved.truncated
		c.saved = nil
	}
	// Go's reader: a fragment much longer than what the list may still
	// hold is not decoded, and nothing follows an invalid field.
	if uint64(len(p)) > 2*blk.budget() || blk.invalid {
		c.connError(h2.ErrProtocol)
		return
	}
	if err := c.dec.Write(p, c.emit); err != nil {
		c.connError(h2.ErrCompressionCode)
		return
	}
	if !end {
		// The rest of the block is due within the header timeout.
		if d := c.fs.readHeaderTO; d > 0 && !c.hbt.Armed() {
			c.l.Arm(&c.hbt.Timer, d)
		}
		return
	}
	c.l.Stop(&c.hbt.Timer)
	id, endStream, self := c.hbStream, c.hbEnd, c.hbSelf
	c.hbStream = 0
	if err := c.dec.Close(); err != nil {
		c.connError(h2.ErrCompressionCode)
		return
	}
	c.request(id, endStream, self)
	if cap(blk.arena) > 2*maxFastRequestHead {
		blk.arena = nil // a very long list does not stay with the loop
	}
	if cap(blk.fields) > 2*maxFastHeaders {
		blk.fields = nil
	}
}

// saveBlock moves the header block in progress from the loop's scratch to
// the connection.
func (c *h2conn) saveBlock() {
	blk := &c.fl.h2.blk
	s := *blk
	s.arena = append([]byte(nil), blk.arena...)
	s.fields = append([]h2Field(nil), blk.fields...)
	c.saved = &s
}

// request acts on a complete header block of stream id: a new request, or
// the trailers of one whose body ends with them. The order of the checks is
// that of Go's server.
func (c *h2conn) request(id uint32, endStream, self bool) {
	blk := &c.fl.h2.blk
	if c.discards(id) {
		return // decoded for the table only
	}
	if blk.invalid {
		c.streamError(id, h2.ErrProtocol)
		return
	}
	pseudo, ok := blk.pseudos()
	if !ok {
		c.streamError(id, h2.ErrProtocol)
		return
	}
	if id&1 == 0 {
		c.connError(h2.ErrProtocol)
		return
	}
	if s := c.streams[id]; s != nil {
		if s.state != hsOpen {
			c.streamError(id, h2.ErrStreamClosed)
			return
		}
		// The request's trailers: they end its body. Only a request that
		// announced them keeps any, and that one is a handler's.
		if s.gotTrailers {
			c.connError(h2.ErrProtocol)
			return
		}
		s.gotTrailers = true
		if !endStream || pseudo != 0 || blk.truncated {
			c.streamError(id, h2.ErrProtocol)
			return
		}
		if b := s.br; b != nil && b.wantsTrailers {
			tr := http.Header{}
			for i := range blk.fields {
				key := textproto.CanonicalMIMEHeaderKey(string(blk.fieldName(i)))
				if !h2ValidTrailer(key) {
					c.streamError(id, h2.ErrProtocol)
					return
				}
				tr[key] = append(tr[key], string(blk.fieldValue(i)))
			}
			b.gotTrailer = tr
		}
		s.endBody()
		return
	}
	if id <= c.maxID {
		c.connError(h2.ErrProtocol)
		return
	}
	c.maxID = id
	c.l.Stop(&c.timer) // the idle timer
	if len(c.streams) >= h2MaxStreams {
		// Past what the settings allow; before the client acknowledged
		// them it may not know.
		code := h2.ErrRefusedStream
		if c.unacked == 0 {
			code = h2.ErrProtocol
		}
		c.streamError(id, code)
		c.idleIfEmpty()
		return
	}
	s := c.newStream(id, endStream)
	if self {
		c.streamError(id, h2.ErrProtocol)
		return
	}
	s.start(blk, endStream)
}

// ---- request bodies ----

// startData begins a DATA frame: where its payload goes is decided here,
// before any of it is taken.
func (c *h2conn) startData(fh h2.FrameHeader, pad uint32) {
	id := fh.StreamID
	n := fh.Length // what the frame counts against the windows
	body := n
	if fh.Flags&h2.FlagPadded != 0 {
		body-- // the pad length
		if pad > body {
			c.connError(h2.ErrProtocol)
			return
		}
		body -= pad
	}
	c.dataLeft, c.dataPad, c.dataTo, c.dataEnd, c.dataDrop = body+pad, pad, nil, false, false
	if n == 0 && fh.Flags&h2.FlagEndStream == 0 {
		c.glitch() // an empty frame that ends nothing
		if c.state >= hcDraining {
			return
		}
	}
	if c.discards(id) {
		// After a GOAWAY: dropped, and its room in the connection's window
		// given back.
		if !c.inflow.take(n) {
			c.streamError(id, h2.ErrFlowControl)
		} else {
			c.credit(nil, int(n))
		}
		c.endData()
		return
	}
	s, idle := c.streamOf(id)
	if idle {
		c.connError(h2.ErrProtocol)
		return
	}
	if s == nil || s.state != hsOpen || s.gotTrailers {
		// The stream takes no more data.
		if s == nil {
			c.glitch()
			if c.state >= hcDraining {
				return
			}
		}
		if !c.inflow.take(n) {
			c.streamError(id, h2.ErrFlowControl)
		} else {
			c.credit(nil, int(n))
			c.streamError(id, h2.ErrStreamClosed)
		}
		c.endData()
		return
	}
	if s.declared >= 0 && s.got+int64(body) > s.declared {
		// More than the request's Content-Length.
		if !c.inflow.take(n) {
			c.streamError(id, h2.ErrFlowControl)
		} else {
			c.credit(nil, int(n))
			c.streamError(id, h2.ErrProtocol)
		}
		c.endData()
		return
	}
	if n > 0 {
		if n > uint32(c.inflow.avail) || n > uint32(s.inflow.avail) {
			c.streamError(id, h2.ErrFlowControl)
			c.endData()
			return
		}
		c.inflow.avail -= int32(n)
		s.inflow.avail -= int32(n)
		// Padding (and its length) is never read by anyone: its credit goes
		// back now.
		if extra := int(n - body); extra > 0 {
			c.credit(nil, extra)
			c.credit(s, extra)
		}
	}
	s.got += int64(body)
	c.dataTo, c.dataEnd = s, fh.Flags&h2.FlagEndStream != 0
	c.endData()
}

// endData ends the DATA frame being read once none of it is left to come.
func (c *h2conn) endData() {
	if c.dataLeft > 0 || c.state >= hcDraining {
		return
	}
	s := c.dataTo
	c.dataTo, c.dataDrop = nil, false
	if s != nil && c.dataEnd {
		s.endBody()
	}
}

// onData takes payload bytes of the DATA frame being read.
func (c *h2conn) onData(p []byte) {
	c.dataLeft -= uint32(len(p))
	// The padding is at the end of the frame.
	if over := int(c.dataPad) - int(c.dataLeft); over > 0 {
		if over >= len(p) {
			p = nil
		} else {
			p = p[:len(p)-over]
		}
	}
	if len(p) > 0 {
		if s := c.dataTo; s != nil {
			s.bodyData(p) // may end the stream: release then clears c.dataTo
		} else if c.dataDrop {
			c.credit(nil, len(p))
		}
	}
	c.endData()
}

// credit gives n bytes of window back to the client: the connection's
// (s == nil) or a stream's.
func (c *h2conn) credit(s *h2stream, n int) {
	if n <= 0 || c.state >= hcDraining {
		return
	}
	var id uint32
	var incr int32
	if s == nil {
		incr = c.inflow.add(n)
	} else {
		id, incr = s.id, s.inflow.add(n)
	}
	if incr > 0 {
		c.reserve(h2.FrameHeaderLen + 4)
		c.out = h2.AppendWindowUpdate(c.out, id, uint32(incr))
		c.wantFlush()
	}
}

// ---- errors, GOAWAY and the end of a connection ----

// streamError resets stream id with code: a rule of the protocol was broken
// on it. A request being answered on it is cancelled.
func (c *h2conn) streamError(id uint32, code h2.ErrCode) {
	if c.state >= hcDraining {
		return
	}
	c.reserve(h2.FrameHeaderLen + 4)
	c.out = h2.AppendRSTStream(c.out, id, code)
	c.wantFlush()
	if s := c.streams[id]; s != nil {
		s.cancel(statusClientClosedRequest)
		c.closeStream(s)
	}
}

// connError ends the connection for an error of the protocol: GOAWAY with
// its code, every request cancelled, and the close after h2GoAwayWait.
func (c *h2conn) connError(code h2.ErrCode) {
	if c.state >= hcDraining {
		return
	}
	logging.Debug("[HTTP] HTTP/2 connection error from %s: code %d", c.peerS, code)
	c.sendGoAway(code)
	c.drain()
}

func (c *h2conn) sendGoAway(code h2.ErrCode) {
	c.reserve(h2.FrameHeaderLen + 8)
	c.out = h2.AppendGoAway(c.out, c.maxID, code, nil)
	c.goAway, c.lastID = true, c.maxID
	c.wantFlush()
}

// drain: the last GOAWAY is out. Every request is cancelled, input is
// ignored from here on, and the connection closes after h2GoAwayWait.
func (c *h2conn) drain() {
	if c.state >= hcDraining {
		return
	}
	c.state = hcDraining
	c.dataLeft, c.dataTo, c.hbStream, c.saved = 0, nil, 0, nil
	c.l.Stop(&c.hbt.Timer)
	c.unstarted = nil
	c.cancelStreams()
	releaseBuf(&c.in)
	c.l.Arm(&c.timer, h2GoAwayWait)
}

// shutdown stops the connection gracefully: GOAWAY without an error, the
// open streams finish, new ones are ignored. stop: the server is stopping,
// and the connection closes as soon as its streams are done.
func (c *h2conn) shutdown(stop bool) {
	if c.state >= hcDraining {
		return
	}
	if stop {
		c.stopping = true
	}
	if !c.goAway {
		c.sendGoAway(h2.ErrNo)
	}
	if len(c.streams) == 0 {
		c.idle()
	}
}

// idleIfEmpty and idle: the connection has no stream.
func (c *h2conn) idleIfEmpty() {
	if len(c.streams) == 0 {
		c.idle()
	}
}

func (c *h2conn) idle() {
	switch {
	case c.state != hcOpen:
	case c.stopping:
		c.flush()
		c.close()
	case c.goAway:
		c.drain()
	case c.fs.idleTO > 0:
		c.l.Arm(&c.timer, c.fs.idleTO)
	default:
		c.l.Stop(&c.timer)
	}
}

// OnTimer: the preface or the first SETTINGS frame did not come, the
// connection was idle for the idle timeout, or the wait after GOAWAY is
// over.
func (c *h2conn) OnTimer() {
	if c.state == hcClosed {
		return
	}
	defer c.recover()
	if c.state == hcOpen {
		if len(c.streams) == 0 {
			c.shutdown(false)
		}
		return
	}
	c.close()
}

// cancelStreams cancels every request of the connection.
func (c *h2conn) cancelStreams() {
	for id, s := range c.streams {
		s.cancel(statusClientClosedRequest)
		delete(c.streams, id)
		c.release(s)
	}
	c.bhead, c.btail = nil, nil
	for i := range c.startq {
		c.startq[i] = nil
	}
	c.startq = c.startq[:0]
}

// close releases the connection.
func (c *h2conn) close() {
	if c.state == hcClosed {
		return
	}
	if c.state < hcDraining {
		c.state = hcDraining
	}
	c.cancelStreams()
	c.own.closeAll()
	if cb := c.cb; cb != nil {
		c.cb = nil
		cb.closeFromLoop()
	}
	if c.tls.tt.owner != nil {
		// close_notify, as far as the socket takes it.
		c.fl.tlsDirect = false
		_ = c.tls.tc.CloseWrite()
		for len(c.pending) > 0 {
			n, errno := ngx.Write(c.fd, c.pending)
			if errno != 0 || n <= 0 {
				break
			}
			c.pending = c.pending[:copy(c.pending, c.pending[n:])]
		}
	}
	c.state = hcClosed
	c.l.Stop(&c.timer)
	c.l.Stop(&c.wt.Timer)
	c.l.Stop(&c.hbt.Timer)
	c.l.Unregister(c.fd, c.reg)
	unix.Close(c.fd)
	c.fd = -1
	panicProbe("close")
	releaseBuf(&c.in)
	releaseBuf(&c.out)
	releaseBuf(&c.pending)
	c.saved = nil
	c.tls.release()
	c.unlist()
}

// ---- output ----

// reserve makes room for n more bytes of frames in c.out.
func (c *h2conn) reserve(n int) {
	if c.out == nil {
		c.out = getBuf(max(n, 16<<10))
		return
	}
	if cap(c.out)-len(c.out) >= n {
		return
	}
	nb := getBuf(max(len(c.out)+n, 2*cap(c.out)))
	nb = append(nb, c.out...)
	putBuf(c.out)
	c.out = nb
}

// outBacklog is how much output waits for the client.
func (c *h2conn) outBacklog() int { return len(c.out) + len(c.pending) }

// wantFlush has the connection's output written at the end of this pass of
// the loop.
func (c *h2conn) wantFlush() {
	if c.flushQ || c.state == hcClosed {
		return
	}
	c.flushQ = true
	hl := &c.fl.h2
	hl.dirty = append(hl.dirty, c)
	c.l.RequestIterationEnd(hl.hook)
}

// h2Flush writes the output of the loop's HTTP/2 connections (the end of a
// pass). What a flush itself brings about is for the next pass.
func (fl *fastLoop) h2Flush() {
	hl := &fl.h2
	n := len(hl.dirty)
	for i := 0; i < n; i++ {
		c := hl.dirty[i]
		hl.dirty[i] = nil
		c.flushQ = false
		c.flushSafe()
	}
	rest := copy(hl.dirty, hl.dirty[n:])
	for i := rest; i < len(hl.dirty); i++ {
		hl.dirty[i] = nil
	}
	hl.dirty = hl.dirty[:rest]
	if rest > 0 {
		fl.l.RequestIterationEnd(hl.hook)
	}
}

func (c *h2conn) flushSafe() {
	if c.state == hcClosed {
		return
	}
	defer c.recover()
	c.flush()
}

// flush encrypts and writes the connection's output while the socket takes
// it. When it is all out, backends that waited for it are read again.
func (c *h2conn) flush() {
	if c.state == hcClosed {
		return
	}
	fl := c.fl
	for {
		for len(c.pending) > 0 {
			n, errno := ngx.Write(c.fd, c.pending)
			if errno == unix.EAGAIN {
				c.writable = false
				c.stalled()
				return
			}
			if errno == unix.EINTR {
				continue
			}
			if errno != 0 {
				c.close()
				return
			}
			c.pending = c.pending[:copy(c.pending, c.pending[n:])]
			c.progress(n)
		}
		releaseBuf(&c.pending)
		if len(c.out) == 0 {
			break
		}
		n := min(len(c.out), h2FlushChunk)
		fl.tlsDirect = true
		fl.tlsBuf = fl.tlsBuf[:0]
		_, err := c.tls.tc.Write(c.out[:n])
		fl.tlsDirect = false
		if err != nil {
			c.close()
			return
		}
		c.out = c.out[:copy(c.out, c.out[n:])]
		ct := fl.tlsBuf
		fl.tlsBuf = fl.tlsBuf[:0]
		if cap(ct) > tlsBufKeep {
			fl.tlsBuf = nil
		}
		w, errno := ngx.Write(c.fd, ct)
		if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR {
			c.close()
			return
		}
		w = max(w, 0)
		c.progress(w)
		if w < len(ct) {
			appendBuf(&c.pending, ct[w:])
			c.writable = false
			c.stalled()
			return
		}
	}
	releaseBuf(&c.out)
	c.l.Stop(&c.wt.Timer)
	c.drained()
}

// stalled: the socket takes no more. The write limit runs while output
// waits for it, and restarts with every 32 KiB the client takes (progress),
// as on an HTTP/1.1 connection.
func (c *h2conn) stalled() {
	if limit := c.stallLimit(); !c.wt.Armed() && limit > 0 {
		c.wsince = 0
		c.l.Arm(&c.wt.Timer, limit)
	}
	if c.outBacklog() <= h2OutHigh/2 {
		c.drained()
	}
}

func (c *h2conn) progress(n int) {
	if c.wsince += n; c.wsince >= 32<<10 && c.wt.Armed() {
		c.wsince = 0
		if limit := c.stallLimit(); limit > 0 {
			c.l.Arm(&c.wt.Timer, limit)
		} else {
			c.l.Stop(&c.wt.Timer)
		}
	}
}

// stallLimit is how long the client may take no output.
func (c *h2conn) stallLimit() time.Duration {
	if c.writeLimit == 0 {
		return defaultWriteTimeout
	}
	return c.writeLimit
}

// noteWriteLimit takes the write limit of a request the connection starts.
func (c *h2conn) noteWriteLimit(d time.Duration) {
	switch {
	case d <= 0:
		c.writeLimit = -1
	case c.writeLimit >= 0 && d > c.writeLimit:
		c.writeLimit = d
	}
}

// drained: the output is (nearly) out. Input that waited for it is read,
// and so are the backends of the connection's streams.
func (c *h2conn) drained() {
	if c.inPaused && c.outBacklog() <= h2InputPause/2 {
		c.inPaused = false
		if c.mayRead() {
			c.later()
		}
	}
	if !c.backlogged {
		return
	}
	c.backlogged = false
	for _, s := range c.streams {
		if b := s.br; b != nil {
			// A handler that waited for the output to leave writes on.
			if len(s.pend) == 0 {
				b.answer(nil)
			}
			continue
		}
		if u := s.x.u; u != nil && u.paused && !s.done && len(s.pend) == 0 {
			u.resume()
			if c.state == hcClosed || c.backlogged {
				return
			}
		}
	}
}

// writeHeaders writes a header block of stream s as a HEADERS frame (and
// CONTINUATION frames past the client's frame size). The connection's
// first block starts with a table size update: this end keeps no table,
// which holds whatever size the client allows later.
func (c *h2conn) writeHeaders(s *h2stream, block []byte, endStream bool) {
	if c.needSize {
		c.needSize = false
		block = append(h2.AppendTableSize(make([]byte, 0, len(block)+1), 0), block...)
	}
	c.reserve(len(block) + h2.FrameHeaderLen*(1+len(block)/c.peerFrame))
	c.out = h2.AppendHeaders(c.out, s.id, block, endStream, c.peerFrame)
	s.responded = true
	if endStream {
		s.ended = true
	}
	c.wantFlush()
}

// writeData writes body bytes of stream s as DATA frames, as far as the
// stream's and the connection's windows allow and at most limit bytes; end:
// the stream ends with the last of p. It returns how many bytes it took.
func (c *h2conn) writeData(s *h2stream, p []byte, end bool, limit int) int {
	if len(p) == 0 {
		if end {
			// An empty frame needs no window.
			c.reserve(h2.FrameHeaderLen)
			c.out = h2.AppendDataHeader(c.out, s.id, 0, true)
			s.ended = true
			c.wantFlush()
		}
		return 0
	}
	n := int64(min(len(p), limit))
	n = min(n, s.sendWin, c.sendWin)
	if n <= 0 {
		return 0
	}
	total := int(n)
	c.reserve(total + h2.FrameHeaderLen*(1+total/c.peerFrame))
	for off := 0; off < total; {
		l := min(total-off, c.peerFrame)
		last := end && off+l == len(p)
		c.out = h2.AppendDataHeader(c.out, s.id, l, last)
		c.out = append(c.out, p[off:off+l]...)
		off += l
		if last {
			s.ended = true
		}
	}
	s.sendWin -= n
	c.sendWin -= n
	c.wantFlush()
	return total
}

// block and unblock: the list of streams with data waiting for the
// connection's window, served in turn.
func (c *h2conn) block(s *h2stream) {
	if s.blocked {
		return
	}
	s.blocked, s.bnext = true, nil
	if c.btail != nil {
		c.btail.bnext = s
	} else {
		c.bhead = s
	}
	c.btail = s
}

func (c *h2conn) unblock(s *h2stream) {
	if !s.blocked {
		return
	}
	var prev *h2stream
	for b := c.bhead; b != nil; prev, b = b, b.bnext {
		if b != s {
			continue
		}
		if prev == nil {
			c.bhead = s.bnext
		} else {
			prev.bnext = s.bnext
		}
		if c.btail == s {
			c.btail = prev
		}
		break
	}
	s.blocked, s.bnext = false, nil
}

// ---- the server's connections ----

// beginShutdown: the server is stopping.
func (c *h2conn) beginShutdown() {
	if c.state == hcClosed {
		return
	}
	defer c.recover()
	if c.state != hcOpen {
		c.close()
		return
	}
	c.shutdown(true)
}

// abortNow: the server's stop ran out of time.
func (c *h2conn) abortNow() {
	if c.state == hcClosed {
		return
	}
	defer c.recover()
	c.close()
}
