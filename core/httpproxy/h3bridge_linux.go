//go:build linux

package httpproxy

// Requests of an HTTP/3 connection on the loops that net/http's handlers
// serve: the bridge of h2bridge_linux.go, with an HTTP/3 stream behind it.

import (
	"context"
	"crypto/tls"
	"io"
	"net"

	"nvelox/core/h3"
)

// slowRequest starts a request the loops do not serve. One that breaks a
// rule of a request is refused as malformed (the checks of
// h2conn.slowRequest); any other goes to a handler goroutine.
func (c *h3conn) slowRequest(s *h3stream, blk *h2Block, endStream bool) {
	if h3Malformed(blk, endStream) {
		s.malformed()
		return
	}
	declared, wantsTrailers := int64(-1), false
	for i := range blk.fields {
		name := blk.fieldName(i)
		if name[0] == ':' {
			continue
		}
		switch headerKind(name) {
		case hkTrailer:
			wantsTrailers = wantsTrailers || h2AnnouncesTrailers(blk.fieldValue(i))
		case hkContentLength:
			if declared < 0 {
				declared, _ = parseRespContentLength(blk.fieldValue(i))
			}
		}
	}
	s.declared = declared

	bh := &h3BridgeHost{c: c, id: s.id, from: c.remote}
	b := &h2Bridge{h: bh, endStream: endStream, truncated: blk.truncated, wantsTrailers: wantsTrailers, ack: make(chan error, 1)}
	bh.b = b
	b.arena = append([]byte(nil), blk.arena...)
	b.fields = append([]h2Field(nil), blk.fields...)
	b.cond.L = &b.mu
	if c.slowCtx == nil {
		// The connection's requests to send_proxy_v2 backends go over
		// backend connections of its own (proxysend.go), closed with it.
		// They name the client's address as it is when they are opened
		// (a client may move).
		c.live.Store(c.liveAddrs())
		c.cb = &clientBackends{live: func() (net.Addr, net.Addr) {
			a := c.live.Load()
			return a.client, a.local
		}}
		c.slowCtx = withClientBackends(c.fs.h2Context(), c.cb)
	}
	b.ctx, b.cancel = context.WithCancel(c.slowCtx)
	if endStream {
		b.bodyErr = io.EOF
	}
	s.br = b
	// As many handlers at a time as streams; more wait (a request whose
	// stream was reset still has a handler that has to notice), and too
	// many waiting is a client that resets what it asks for.
	if c.handlers < h3MaxStreams {
		c.handlers++
		go b.run()
		return
	}
	if len(c.unstarted) > 4*h3MaxStreams {
		c.fail(h3.ErrExcessiveLoad, "too many requests given up")
		return
	}
	b.queued = true
	c.unstarted = append(c.unstarted, b)
}

// handlerEnded: a handler goroutine is over; a request that waited for one
// may start.
func (c *h3conn) handlerEnded() {
	c.handlers--
	i := 0
	for ; i < len(c.unstarted); i++ {
		u := c.unstarted[i]
		if u == nil || u.h.(*h3BridgeHost).stream() == nil {
			continue // its stream was reset before it started
		}
		if c.handlers >= h3MaxStreams {
			break
		}
		c.unstarted[i] = nil
		u.queued = false
		c.handlers++
		go u.run()
	}
	c.unstarted = c.unstarted[i:]
	if len(c.unstarted) == 0 {
		c.unstarted = nil
	}
}

// h3BridgeHost is the bridgeHost of a request on an HTTP/3 connection.
type h3BridgeHost struct {
	c  *h3conn
	id uint64
	b  *h2Bridge
	// from is the client's address when the request began (the handler's
	// goroutine reads it; the connection's own may change).
	from string
}

// stream is the bridge's stream, while it is still that (loop only).
func (h *h3BridgeHost) stream() *h3stream {
	if s := h.c.streams[h.id]; s != nil && s.br == h.b {
		return s
	}
	return nil
}

func (h *h3BridgeHost) post(fn func(live bool)) {
	c := h.c
	c.l.Post(func() {
		if c.over {
			fn(false)
			return
		}
		defer c.recover()
		panicProbe("bridge")
		fn(h.stream() != nil)
	})
}

func (h *h3BridgeHost) handlerEnded() { h.c.handlerEnded() }

func (h *h3BridgeHost) writeHeaders(block []byte, end bool) {
	if s := h.stream(); s != nil {
		s.writeHeaders(block, end)
	}
}

func (h *h3BridgeHost) sendData(p []byte, end bool) {
	if s := h.stream(); s != nil {
		s.sendData(p, end)
	}
}

func (h *h3BridgeHost) backlog() bool {
	s := h.stream()
	return s != nil && s.backlog()
}

// credit and dropped: the transport gives the stream's room back while
// the client still sends on it, and the connection's in any case.
func (h *h3BridgeHost) credit(n int) {
	if c := h.c; !c.over && n > 0 {
		c.q.StreamConsumed(h.id, n)
		c.qc.wake()
	}
}

func (h *h3BridgeHost) dropped(n int) { h.credit(n) }

func (h *h3BridgeHost) malformed() {
	if s := h.stream(); s != nil {
		s.malformed()
	}
}

func (h *h3BridgeHost) failed() {
	if s := h.stream(); s != nil {
		h.c.reject(s, h3.ErrInternal)
	}
}

func (h *h3BridgeHost) timedOut() { h.failed() }

func (h *h3BridgeHost) finished() {
	s := h.stream()
	if s == nil {
		return
	}
	s.done = true
	if !s.ended && !s.endPend {
		s.out(nil, true)
	}
	if len(s.pend) == 0 && !s.endPend {
		h.c.endStream(s)
	}
}

func (h *h3BridgeHost) closeConn() { h.c.shutdown(false) }

func (h *h3BridgeHost) remote() string                 { return h.from }
func (h *h3BridgeHost) tlsState() *tls.ConnectionState { return h.c.tlsState }
func (h *h3BridgeHost) server() *fastServer            { return h.c.fs }
func (h *h3BridgeHost) protocol() (string, int)        { return "HTTP/3.0", 3 }

func (h *h3BridgeHost) blockStart(b []byte) []byte             { return h3.AppendPrefix(b) }
func (h *h3BridgeHost) appendStatus(b []byte, code int) []byte { return h3.AppendStatus(b, code) }
func (h *h3BridgeHost) appendField(b, name, value []byte) []byte {
	return h3.AppendField(b, name, value)
}
