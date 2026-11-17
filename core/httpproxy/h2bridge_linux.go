//go:build linux

package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nvelox/ngx/h2"
)

// The bridge: a request of an HTTP/2 connection that the event loops do not
// serve themselves (a static file, FastCGI, a sticky or cached site, a body
// without a length, announced trailers, and whatever else HTTP/1.1 hands to
// net/http) runs in a goroutine through the bind group's net/http handler,
// as it always has. The handler gets the request Go's HTTP/2 server would
// have given it and a ResponseWriter that behaves like that server's; what
// it writes is posted to the loop as frames, and the request's body reaches
// it through a pipe the loop fills. The loop never waits for a handler, and
// a handler waits for the loop only for its own stream's output to leave.

var (
	errH2StreamClosed = errors.New("http2: stream closed")
	errH2BodyClosed   = errors.New("body closed by handler")
)

// bridgeHost is where a handler's request came from: its stream and its
// connection, HTTP/2's (h2BridgeHost) or HTTP/3's (h3BridgeHost). The handler's
// goroutine calls post and the methods listed under "anywhere". The others
// run on the connection's loop, in a function given to post; all of them
// but handlerEnded, credit, dropped and closeConn only while the stream is
// live.
type bridgeHost interface {
	// post runs fn on the connection's loop. live: the stream is still
	// the bridge's (it was not reset, and the connection is open).
	post(fn func(live bool))
	// handlerEnded: the handler's goroutine is over.
	handlerEnded()
	// What the handler writes: a header block, body bytes, and whether
	// output still waits for the client.
	writeHeaders(block []byte, end bool)
	sendData(p []byte, end bool)
	backlog() bool
	// credit: the handler read n body bytes; dropped: it left n unread.
	// The client gets their room back.
	credit(n int)
	dropped(n int)
	// malformed: the request cannot be given to a handler. failed: the
	// handler panicked. timedOut: its write deadline passed. Each resets
	// the stream. finished: the handler returned; the stream ends once its
	// output is out. closeConn: it answered "Connection: close".
	malformed()
	failed()
	timedOut()
	finished()
	closeConn()

	// Anywhere: what the handler's request says of its connection.
	remote() string
	tlsState() *tls.ConnectionState
	server() *fastServer
	protocol() (name string, major int)
	// A header block as the protocol writes it: what it begins with, its
	// status field, a field.
	blockStart(b []byte) []byte
	appendStatus(b []byte, code int) []byte
	appendField(b []byte, name, value []byte) []byte
}

// h2BridgeHost is the bridgeHost of a request on an HTTP/2 connection.
type h2BridgeHost struct {
	c  *h2conn
	id uint32
	b  *h2Bridge
}

// stream is the bridge's stream, while it is still that (loop only).
func (h *h2BridgeHost) stream() *h2stream {
	if s := h.c.streams[h.id]; s != nil && s.br == h.b {
		return s
	}
	return nil
}

func (h *h2BridgeHost) post(fn func(live bool)) {
	c := h.c
	c.l.Post(func() {
		if c.state == hcClosed {
			fn(false)
			return
		}
		defer c.recover()
		panicProbe("bridge")
		fn(h.stream() != nil)
	})
}

func (h *h2BridgeHost) handlerEnded() { h.c.handlerEnded() }

func (h *h2BridgeHost) writeHeaders(block []byte, end bool) {
	if s := h.stream(); s != nil {
		h.c.writeHeaders(s, block, end)
	}
}

func (h *h2BridgeHost) sendData(p []byte, end bool) {
	if s := h.stream(); s != nil {
		s.sendData(p, end)
	}
}

func (h *h2BridgeHost) backlog() bool {
	s := h.stream()
	return s != nil && s.backlog()
}

func (h *h2BridgeHost) credit(n int) {
	c := h.c
	c.credit(nil, n)
	if s := h.stream(); s != nil && s.state == hsOpen {
		c.credit(s, n)
	}
}

func (h *h2BridgeHost) dropped(n int) { h.c.credit(nil, n) }

func (h *h2BridgeHost) malformed() { h.c.streamError(h.id, h2.ErrProtocol) }
func (h *h2BridgeHost) failed()    { h.c.streamError(h.id, h2.ErrInternal) }

func (h *h2BridgeHost) timedOut() {
	c := h.c
	if s := h.stream(); s != nil {
		c.reserve(h2.FrameHeaderLen + 4)
		c.out = h2.AppendRSTStream(c.out, s.id, h2.ErrInternal)
		c.wantFlush()
		c.closeStream(s)
	}
}

func (h *h2BridgeHost) finished() {
	c := h.c
	s := h.stream()
	if s == nil {
		return
	}
	s.done = true
	if !s.ended && !s.endPend {
		s.sendData(nil, true)
	}
	if len(s.pend) == 0 {
		c.endStream(s)
	}
}

func (h *h2BridgeHost) closeConn() { h.c.shutdown(false) }

func (h *h2BridgeHost) remote() string                 { return h.c.remote }
func (h *h2BridgeHost) tlsState() *tls.ConnectionState { return h.c.tlsState }
func (h *h2BridgeHost) server() *fastServer            { return h.c.fs }
func (h *h2BridgeHost) protocol() (string, int)        { return "HTTP/2.0", 2 }

func (h *h2BridgeHost) blockStart(b []byte) []byte             { return b }
func (h *h2BridgeHost) appendStatus(b []byte, code int) []byte { return h2.AppendStatus(b, code) }
func (h *h2BridgeHost) appendField(b, name, value []byte) []byte {
	return h2.AppendField(b, name, value)
}

// h2Bridge is one request served by a handler goroutine.
type h2Bridge struct {
	h bridgeHost

	// The request as the loop received it: a copy of its header block.
	arena     []byte
	fields    []h2Field
	endStream bool // no body follows
	truncated bool // the header list was too long: answered 431

	ctx    context.Context
	cancel context.CancelFunc
	// closed is why the stream ended, once it has (the handler's writes
	// then fail with it).
	closed atomic.Pointer[error]

	// The request body: the loop appends, the handler reads.
	mu        sync.Mutex
	cond      sync.Cond
	body      []byte
	bodyErr   error       // what follows body: io.EOF at its end
	trailer   http.Header // the trailers the client sent with its END_STREAM
	readGone  bool        // the handler closed the body
	unacked   int         // read by the handler, not yet given back to the client's windows
	crediting bool        // a post that gives it back is on its way
	sawEOF    bool        // Read returned io.EOF (handler only)

	needsContinue         atomic.Bool // "Expect: 100-continue": 100 goes out at the first read
	readTimer, writeTimer *time.Timer // the handler's deadlines (guarded by mu)
	req                   *http.Request
	// wantsTrailers: the request announced trailers (its Trailer field),
	// so the ones the client sends are kept for the handler.
	wantsTrailers bool

	// The loop's side.
	ack        chan error // the loop's answer to a posted body write
	pendingAck bool       // a write is posted and not answered yet
	queued     bool       // waits for a handler slot
	closeErr   error      // why the stream is being closed, when it is not the client's doing
	gotTrailer http.Header
}

// h2ValidTrailer is httpguts.ValidTrailerHeader: whether a field (in its
// canonical form) may be a trailer.
func h2ValidTrailer(name string) bool {
	if strings.HasPrefix(name, "If-") {
		return false
	}
	switch name {
	case "Authorization", "Cache-Control", "Connection", "Content-Encoding", "Content-Length", "Content-Range",
		"Content-Type", "Expect", "Host", "Keep-Alive", "Max-Forwards", "Pragma", "Proxy-Authenticate",
		"Proxy-Authorization", "Proxy-Connection", "Range", "Realm", "Te", "Trailer", "Transfer-Encoding", "Www-Authenticate":
		return false
	}
	return true
}

// ---- the loop's side ----

// slowRequest starts a request the loops do not serve: after the checks
// Go's server makes before it runs a handler (each a stream error), it goes
// to a handler goroutine.
func (c *h2conn) slowRequest(s *h2stream, blk *h2Block, endStream bool) {
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
	// Extended CONNECT is not offered, so :protocol has no place.
	bad := hasProtocol
	if isConnect {
		bad = bad || len(path) > 0 || len(scheme) > 0 || len(authority) == 0
	} else {
		bad = bad || len(method) == 0 || len(path) == 0 || !web
	}
	host, hostSet := authority, len(authority) > 0
	declared, hasCL, dupCL := int64(-1), false, false
	wantsTrailers := false
	var firstCL []byte
	for ; i < len(blk.fields); i++ {
		name, v := blk.fieldName(i), blk.fieldValue(i)
		switch headerKind(name) {
		case hkTrailer:
			wantsTrailers = wantsTrailers || h2AnnouncesTrailers(v)
		case hkHost:
			if !hostSet {
				host, hostSet = v, true
			}
		case hkContentLength:
			if !hasCL {
				hasCL, firstCL = true, v
				// A length that is not a number counts as 0.
				declared, _ = parseRespContentLength(v)
			} else if !bytes.Equal(v, firstCL) {
				dupCL = true
			}
		}
	}
	bad = bad || web && bytes.IndexByte(host, '@') >= 0
	if !isConnect && !bad {
		bad = path[0] != '/' && string(path) != "*"
	}
	bad = bad || hasCL && (dupCL || endStream && declared != 0)
	if bad {
		c.streamError(s.id, h2.ErrProtocol)
		return
	}
	s.declared = declared

	bh := &h2BridgeHost{c: c, id: s.id}
	b := &h2Bridge{h: bh, endStream: endStream, truncated: blk.truncated, wantsTrailers: wantsTrailers, ack: make(chan error, 1)}
	bh.b = b
	b.arena = append([]byte(nil), blk.arena...)
	b.fields = append([]h2Field(nil), blk.fields...)
	b.cond.L = &b.mu
	if c.slowCtx == nil {
		// The connection's requests to send_proxy_v2 backends go over
		// backend connections of its own (proxysend.go), closed with it.
		c.cb = &clientBackends{src: c.tls.tt.remote, dst: c.tls.tt.local}
		c.slowCtx = withClientBackends(c.fs.h2Context(), c.cb)
	}
	b.ctx, b.cancel = context.WithCancel(c.slowCtx)
	if endStream {
		b.bodyErr = io.EOF
	}
	s.br = b
	// As many handlers at a time as streams; more wait (requests whose
	// stream was reset still have a handler that has to notice), and too
	// many waiting is a client that resets what it asks for.
	if c.handlers < h2MaxStreams {
		c.handlers++
		go b.run()
		return
	}
	if len(c.unstarted) > 4*h2MaxStreams {
		c.connError(h2.ErrEnhanceYourCalm)
		return
	}
	b.queued = true
	c.unstarted = append(c.unstarted, b)
}

// h2Context is the context of the bind group's requests, as net/http's
// server gives it to them.
func (fs *fastServer) h2Context() context.Context {
	fs.h2CtxOnce.Do(func() {
		ctx := context.WithValue(context.Background(), http.ServerContextKey, fs.g.httpServer)
		fs.h2Ctx = context.WithValue(ctx, http.LocalAddrContextKey, fs.handoff.Addr())
	})
	return fs.h2Ctx
}

// handlerEnded: a handler goroutine is over; one that waited may start.
func (c *h2conn) handlerEnded() {
	c.handlers--
	i := 0
	for ; i < len(c.unstarted); i++ {
		u := c.unstarted[i]
		if u == nil || u.h.(*h2BridgeHost).stream() == nil {
			continue // its stream was reset before it started
		}
		if c.handlers >= h2MaxStreams {
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

// answer gives the handler the result of the write it waits for (loop).
func (b *h2Bridge) answer(err error) {
	if b.pendingAck {
		b.pendingAck = false
		b.ack <- err
	}
}

// streamClosed: the stream ended (loop): the handler's context is
// cancelled, its body reads and writes fail. It returns how many body
// bytes the handler had not read.
func (b *h2Bridge) streamClosed(err error) int {
	b.closed.CompareAndSwap(nil, &err)
	b.cancel()
	b.mu.Lock()
	unread := len(b.body)
	b.body = nil
	if b.bodyErr == nil {
		b.bodyErr = err
	}
	b.stopTimers()
	b.cond.Broadcast()
	b.mu.Unlock()
	b.answer(err)
	return unread
}

func (b *h2Bridge) stopTimers() {
	if b.readTimer != nil {
		b.readTimer.Stop()
	}
	if b.writeTimer != nil {
		b.writeTimer.Stop()
	}
}

// feed gives the handler body bytes (loop). False: nobody reads them.
func (b *h2Bridge) feed(p []byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.readGone || b.bodyErr != nil {
		return false
	}
	b.body = append(b.body, p...)
	b.cond.Signal()
	return true
}

// endBody ends the request body (loop): io.EOF, or why it is incomplete.
func (b *h2Bridge) endBody(err error, trailer http.Header) {
	b.mu.Lock()
	if b.bodyErr == nil {
		b.bodyErr, b.trailer = err, trailer
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

// ---- the handler's side ----

// run serves the request (its own goroutine).
func (b *h2Bridge) run() {
	h := b.h
	w := &h2Writer{b: b}
	w.bw = bufio.NewWriterSize(h2ChunkWriter{w}, 4<<10)
	req, handler, err := b.request()
	if err != nil {
		// A path net/url does not take: a malformed request.
		h.post(func(live bool) {
			h.handlerEnded()
			if live {
				h.malformed()
			}
		})
		return
	}
	w.req, b.req = req, req
	panicked := true
	defer func() {
		b.cancel()
		if req.MultipartForm != nil {
			req.MultipartForm.RemoveAll()
		}
		unread := b.closeBody()
		if panicked {
			// Like net/http: the stream is reset; anything but
			// http.ErrAbortHandler is logged with its stack.
			if e := recover(); e != nil && e != http.ErrAbortHandler {
				buf := make([]byte, 64<<10)
				buf = buf[:runtime.Stack(buf, false)]
				_, major := h.protocol()
				h.server().logf("http%d: panic serving %v: %v\n%s", major, h.remote(), e, buf)
			}
			h.post(func(live bool) {
				h.handlerEnded()
				if live {
					h.dropped(unread)
					h.failed()
				}
			})
			return
		}
		w.finish()
		h.post(func(live bool) {
			h.handlerEnded()
			if !live {
				return
			}
			h.dropped(unread)
			h.finished()
		})
	}()
	panicProbe("handler")
	handler(w, req)
	panicked = false
}

func (b *h2Bridge) name(i int) []byte {
	f := &b.fields[i]
	return b.arena[f.name:f.nameEnd]
}

func (b *h2Bridge) value(i int) []byte {
	f := &b.fields[i]
	return b.arena[f.nameEnd:f.valueEnd]
}

// request builds the handler's request the way Go's HTTP/2 server does
// (newWriterAndRequest, httpcommon.NewServerRequest), and picks the handler:
// the bind group's, or the answer to a request it never sees (a header list
// that is too long, a field HTTP/2 does not allow, "OPTIONS *").
func (b *h2Bridge) request() (*http.Request, func(http.ResponseWriter, *http.Request), error) {
	var method, path, authority string
	header := http.Header{}
	for i := range b.fields {
		name, value := b.name(i), string(b.value(i))
		if name[0] == ':' {
			switch string(name) {
			case ":method":
				method = value
			case ":path":
				path = value
			case ":authority":
				authority = value
			}
			continue
		}
		header.Add(textproto.CanonicalMIMEHeaderKey(string(name)), value)
	}
	if authority == "" {
		authority = header.Get("Host")
	}
	if h2HasToken(header["Expect"], "100-continue") {
		b.needsContinue.Store(true)
		delete(header, "Expect")
	}
	if cookies := header["Cookie"]; len(cookies) > 1 {
		header["Cookie"] = []string{strings.Join(cookies, "; ")}
	}
	var trailer http.Header
	for _, v := range header["Trailer"] {
		for _, key := range strings.Split(v, ",") {
			key = textproto.CanonicalMIMEHeaderKey(textproto.TrimString(key))
			switch key {
			case "Transfer-Encoding", "Trailer", "Content-Length":
			default:
				if trailer == nil {
					trailer = http.Header{}
				}
				trailer[key] = nil
			}
		}
	}
	delete(header, "Trailer")

	var u *url.URL
	requestURI := path
	if method == "CONNECT" {
		u, requestURI = &url.URL{Host: authority}, authority
	} else {
		var err error
		if u, err = url.ParseRequestURI(path); err != nil {
			return nil, nil, err
		}
	}
	var contentLength int64
	if clens, ok := header["Content-Length"]; ok {
		if cl, err := strconv.ParseUint(clens[0], 10, 63); err == nil {
			contentLength = int64(cl)
		}
		header["Content-Length"] = clens[:1]
	} else if !b.endStream {
		contentLength = -1
	}
	proto, major := b.h.protocol()
	req := (&http.Request{
		Method: method, URL: u, Proto: proto, ProtoMajor: major, ProtoMinor: 0,
		Header: header, RequestURI: requestURI, Trailer: trailer, Body: (*h2Body)(b), Host: authority,
		ContentLength: contentLength, RemoteAddr: b.h.remote(), TLS: b.h.tlsState(),
	}).WithContext(b.ctx)

	switch {
	case b.truncated:
		return req, h2TooLarge, nil
	case h2ForbiddenField(header) != nil:
		err := h2ForbiddenField(header)
		return req, func(w http.ResponseWriter, _ *http.Request) {
			h := w.Header()
			h.Del("Content-Length")
			h.Set("Content-Type", "text/plain; charset=utf-8")
			h.Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, err.Error())
		}, nil
	case requestURI == "*" && method == "OPTIONS":
		return req, h2OptionsStar, nil
	}
	return req, b.h.server().g.httpServer.Handler.ServeHTTP, nil
}

// h2HasToken is httpguts.HeaderValuesContainsToken.
func h2HasToken(values []string, token string) bool {
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(textproto.TrimString(t), token) {
				return true
			}
		}
	}
	return false
}

// h2ForbiddenField reports a request field HTTP/2 does not allow (Go's
// checkValidHTTP2RequestHeaders): such a request is answered 400.
func h2ForbiddenField(h http.Header) error {
	for _, k := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade"} {
		if _, ok := h[k]; ok {
			return fmt.Errorf("request header %q is not valid in HTTP/2", k)
		}
	}
	if te := h["Te"]; len(te) > 0 && (len(te) > 1 || (te[0] != "trailers" && te[0] != "")) {
		return errors.New(`request header "TE" may only be "trailers" in HTTP/2`)
	}
	return nil
}

// h2TooLarge answers a request whose header list was too long.
func h2TooLarge(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusRequestHeaderFieldsTooLarge)
	io.WriteString(w, "<h1>HTTP Error 431</h1><p>Request Header Field(s) Too Large</p>")
}

// h2OptionsStar answers "OPTIONS *" as net/http's server does by itself.
func h2OptionsStar(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Length", "0")
	if r.ContentLength != 0 {
		io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 4<<10))
	}
}

// h2Body is the request body the handler reads.
type h2Body h2Bridge

func (r *h2Body) Read(p []byte) (int, error) {
	b := (*h2Bridge)(r)
	if b.needsContinue.CompareAndSwap(true, false) {
		h := b.h
		h.post(func(live bool) {
			if live {
				h.writeHeaders(h.appendStatus(h.blockStart(nil), http.StatusContinue), false)
			}
		})
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sawEOF {
		return 0, io.EOF
	}
	for len(b.body) == 0 && b.bodyErr == nil && !b.readGone {
		b.cond.Wait()
	}
	if b.readGone {
		return 0, errH2BodyClosed
	}
	if len(b.body) == 0 {
		if b.bodyErr == io.EOF {
			b.sawEOF = true
			// The trailers the request announced, now that its body is
			// read to the end.
			for k, vv := range b.trailer {
				if _, ok := b.req.Trailer[k]; ok {
					b.req.Trailer[k] = vv
				}
			}
		}
		return 0, b.bodyErr
	}
	n := copy(p, b.body)
	b.body = b.body[n:]
	if len(b.body) == 0 {
		b.body = nil
	}
	// The client gets its windows back for what was read.
	b.unacked += n
	if !b.crediting {
		b.crediting = true
		b.h.post(b.credit)
	}
	return n, nil
}

// credit gives the client its windows back for what the handler read
// (loop).
func (b *h2Bridge) credit(bool) {
	b.mu.Lock()
	n := b.unacked
	b.unacked, b.crediting = 0, false
	b.mu.Unlock()
	b.h.credit(n)
}

func (r *h2Body) Close() error {
	(*h2Bridge)(r).closeBody()
	return nil
}

// closeBody: the handler reads no more. It returns how many bytes were
// left unread (their room in the connection's window is given back).
func (b *h2Bridge) closeBody() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.readGone {
		return 0
	}
	b.readGone = true
	unread := len(b.body)
	b.body = nil
	b.cond.Broadcast()
	return unread
}

// h2AnnouncesTrailers reports whether a Trailer field's value names a
// trailer the handler's request keeps (any name but the three net/http
// leaves out).
func h2AnnouncesTrailers(v []byte) bool {
	for len(v) > 0 || true {
		var key []byte
		if i := bytes.IndexByte(v, ','); i >= 0 {
			key, v = v[:i], v[i+1:]
		} else {
			key, v = v, nil
		}
		switch textproto.CanonicalMIMEHeaderKey(textproto.TrimString(string(key))) {
		case "Transfer-Encoding", "Trailer", "Content-Length":
		default:
			return true
		}
		if v == nil {
			return false
		}
	}
	return false
}

// h2Writer is the handler's ResponseWriter: the behaviour of Go's HTTP/2
// server's (a 4 KiB buffer, a Content-Length for a response that fits in
// it, a Content-Type sniffed from its first bytes, trailers, deadlines).
type h2Writer struct {
	b   *h2Bridge
	req *http.Request
	bw  *bufio.Writer

	header   http.Header // the handler's
	snap     http.Header // as it was at WriteHeader
	trailers []string
	status   int

	wroteHeader bool // WriteHeader was called (or implied)
	sentHeader  bool // the HEADERS frame went out
	done        bool // the handler has returned

	sentContentLen int64
	wroteBytes     int64
}

type h2ChunkWriter struct{ w *h2Writer }

func (cw h2ChunkWriter) Write(p []byte) (int, error) { return cw.w.writeChunk(p) }

func (w *h2Writer) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *h2Writer) WriteHeader(code int) {
	if !w.done {
		w.setStatus(code)
	}
}

// setStatus is WriteHeader's work (Go's responseWriterState.writeHeader).
func (w *h2Writer) setStatus(code int) {
	if w.wroteHeader {
		return
	}
	if code < 100 || code > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", code))
	}
	if code >= 100 && code <= 199 {
		// An informational response: the header map as it is now, and it
		// stays for the response that follows.
		h := w.header
		_, cl := h["Content-Length"]
		_, te := h["Transfer-Encoding"]
		if cl || te {
			h = h.Clone()
			h.Del("Content-Length")
			h.Del("Transfer-Encoding")
		}
		w.b.writeHeaders(w.b.encodeHeaders(code, h, nil, "", "", ""), false)
		return
	}
	w.wroteHeader = true
	w.status = code
	if len(w.header) > 0 {
		w.snap = w.header.Clone()
	}
}

func (w *h2Writer) Write(p []byte) (int, error) { return w.write(len(p), p, "") }

func (w *h2Writer) WriteString(s string) (int, error) { return w.write(len(s), nil, s) }

func (w *h2Writer) write(n int, dataB []byte, dataS string) (int, error) {
	if w.done {
		return 0, http.ErrHandlerTimeout
	}
	if !w.wroteHeader {
		w.setStatus(http.StatusOK)
	}
	if !h2BodyAllowed(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	w.wroteBytes += int64(n)
	if w.sentContentLen != 0 && w.wroteBytes > w.sentContentLen {
		return 0, errors.New("http2: handler wrote more than declared Content-Length")
	}
	if dataB != nil {
		return w.bw.Write(dataB)
	}
	return w.bw.WriteString(dataS)
}

func h2BodyAllowed(status int) bool {
	return !(status >= 100 && status <= 199) && status != http.StatusNoContent && status != http.StatusNotModified
}

func (w *h2Writer) Flush() { w.FlushError() }

func (w *h2Writer) FlushError() error {
	if w.done {
		return http.ErrHandlerTimeout
	}
	if w.bw.Buffered() > 0 {
		return w.bw.Flush()
	}
	// Nothing buffered: the header (or the stream's end) still goes out.
	if _, err := w.writeChunk(nil); err != nil {
		return err
	}
	if e := w.b.closed.Load(); e != nil {
		return *e
	}
	return nil
}

// EnableFullDuplex: an HTTP/2 stream always is.
func (w *h2Writer) EnableFullDuplex() error { return nil }

// SetReadDeadline: past it, reading the request body fails.
func (w *h2Writer) SetReadDeadline(deadline time.Time) error {
	b := w.b
	timeout := func() { b.endBody(fmt.Errorf("%w", os.ErrDeadlineExceeded), nil) }
	b.mu.Lock()
	if b.readTimer != nil {
		b.readTimer.Stop()
		b.readTimer = nil
	}
	past := !deadline.IsZero() && !deadline.After(time.Now())
	if !deadline.IsZero() && !past && b.closed.Load() == nil {
		b.readTimer = time.AfterFunc(time.Until(deadline), timeout)
	}
	b.mu.Unlock()
	if past {
		timeout()
	}
	return nil
}

// SetWriteDeadline: past it, the stream is reset.
func (w *h2Writer) SetWriteDeadline(deadline time.Time) error {
	b := w.b
	timeout := func() {
		b.h.post(func(live bool) {
			if live {
				b.closeErr = os.ErrDeadlineExceeded
				b.h.timedOut()
			}
		})
	}
	b.mu.Lock()
	if b.writeTimer != nil {
		b.writeTimer.Stop()
		b.writeTimer = nil
	}
	past := !deadline.IsZero() && !deadline.After(time.Now())
	if !deadline.IsZero() && !past && b.closed.Load() == nil {
		b.writeTimer = time.AfterFunc(time.Until(deadline), timeout)
	}
	b.mu.Unlock()
	if past {
		timeout()
	}
	return nil
}

// finish: the handler returned: what it buffered goes out, and the stream
// ends (with its trailers).
func (w *h2Writer) finish() {
	w.done = true
	if w.bw.Buffered() > 0 {
		w.bw.Flush()
	} else {
		w.writeChunk(nil)
	}
}

func (w *h2Writer) declareTrailer(k string) {
	k = textproto.CanonicalMIMEHeaderKey(k)
	if !h2ValidTrailer(k) {
		w.b.h.server().logf("ignoring invalid trailer %q", k)
		return
	}
	if !slices.Contains(w.trailers, k) {
		w.trailers = append(w.trailers, k)
	}
}

// promoteUndeclaredTrailers: header keys with http.TrailerPrefix are
// trailers the handler did not announce.
func (w *h2Writer) promoteUndeclaredTrailers() {
	for k, vv := range w.header {
		if !strings.HasPrefix(k, http.TrailerPrefix) {
			continue
		}
		key := strings.TrimPrefix(k, http.TrailerPrefix)
		w.declareTrailer(key)
		w.header[textproto.CanonicalMIMEHeaderKey(key)] = vv
	}
	if len(w.trailers) > 1 {
		slices.Sort(w.trailers)
	}
}

func (w *h2Writer) hasNonemptyTrailers() bool {
	for _, t := range w.trailers {
		if _, ok := w.header[t]; ok {
			return true
		}
	}
	return false
}

// writeChunk sends what the buffer flushes (or, with nothing, the header
// and the stream's end): Go's responseWriterState.writeChunk.
func (w *h2Writer) writeChunk(p []byte) (int, error) {
	if !w.wroteHeader {
		w.setStatus(http.StatusOK)
	}
	if w.done {
		w.promoteUndeclaredTrailers()
	}
	isHead := w.req.Method == "HEAD"
	if !w.sentHeader {
		w.sentHeader = true
		var ctype, clen string
		if clen = w.snap.Get("Content-Length"); clen != "" {
			w.snap.Del("Content-Length")
			if cl, err := strconv.ParseUint(clen, 10, 63); err == nil {
				w.sentContentLen = int64(cl)
			} else {
				clen = ""
			}
		}
		_, hasContentLength := w.snap["Content-Length"]
		if !hasContentLength && clen == "" && w.done && h2BodyAllowed(w.status) && (len(p) > 0 || !isHead) {
			clen = strconv.Itoa(len(p))
		}
		_, hasContentType := w.snap["Content-Type"]
		if w.snap.Get("Content-Encoding") == "" && !hasContentType && h2BodyAllowed(w.status) && len(p) > 0 {
			ctype = http.DetectContentType(p)
		}
		var date string
		if _, ok := w.snap["Date"]; !ok {
			date = time.Now().UTC().Format(http.TimeFormat)
		}
		for _, v := range w.snap["Trailer"] {
			for _, f := range strings.Split(v, ",") {
				if f = textproto.TrimString(f); f != "" {
					w.declareTrailer(f)
				}
			}
		}
		// "Connection: close" asks for the connection to end once it is idle.
		if _, ok := w.snap["Connection"]; ok {
			v := w.snap.Get("Connection")
			delete(w.snap, "Connection")
			if v == "close" {
				w.b.h.post(func(bool) { w.b.h.closeConn() })
			}
		}
		endStream := (w.done && len(w.trailers) == 0 && len(p) == 0) || isHead
		if err := w.b.writeHeaders(w.b.encodeHeaders(w.status, w.snap, nil, ctype, clen, date), endStream); err != nil {
			return 0, err
		}
		if endStream {
			return 0, nil
		}
	}
	if isHead {
		return len(p), nil
	}
	if len(p) == 0 && !w.done {
		return 0, nil
	}
	trailers := w.hasNonemptyTrailers()
	endStream := w.done && !trailers
	if len(p) > 0 || endStream {
		if err := w.b.writeData(p, endStream); err != nil {
			return 0, err
		}
	}
	if w.done && trailers {
		return len(p), w.b.writeHeaders(w.b.encodeHeaders(0, w.header, w.trailers, "", "", ""), true)
	}
	return len(p), nil
}

// encodeHeaders encodes a response's header block as Go's server orders
// and filters it: the status, the fields of h (keys: only those, else all
// in sorted order) with names in lower case, without names and values
// HTTP/2 cannot carry, then the fields the server adds. The bridge's
// protocol writes the fields.
func (br *h2Bridge) encodeHeaders(status int, h http.Header, keys []string, ctype, clen, date string) []byte {
	host := br.h
	b := host.blockStart(nil)
	if status != 0 {
		b = host.appendStatus(b, status)
	}
	if keys == nil {
		keys = make([]string, 0, len(h))
		for k := range h {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	for _, k := range keys {
		name := []byte(strings.ToLower(k))
		if !h2ValidName(name) {
			continue
		}
		te := string(name) == "transfer-encoding"
		for _, v := range h[k] {
			if te && v != "trailers" || !h2ValidValue(v) {
				continue
			}
			b = host.appendField(b, name, []byte(v))
		}
	}
	if ctype != "" {
		b = host.appendField(b, h2NameCT, []byte(ctype))
	}
	if clen != "" {
		b = host.appendField(b, h2NameCL, []byte(clen))
	}
	if date != "" {
		b = host.appendField(b, h2NameDate, []byte(date))
	}
	return b
}

func h2ValidValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if !isValueChar[v[i]] {
			return false
		}
	}
	return true
}

// writeHeaders posts a header block to the loop.
func (b *h2Bridge) writeHeaders(block []byte, end bool) error {
	if e := b.closed.Load(); e != nil {
		return *e
	}
	b.h.post(func(live bool) {
		if live {
			b.h.writeHeaders(block, end)
		}
	})
	return nil
}

// writeData posts body bytes to the loop and waits until they are in the
// stream and the stream has no output waiting for the client: a handler
// never runs ahead of its client by more than what it writes at a time.
func (b *h2Bridge) writeData(p []byte, end bool) error {
	if e := b.closed.Load(); e != nil {
		return *e
	}
	b.h.post(func(live bool) {
		b.pendingAck = true
		if !live {
			err := errH2StreamClosed
			if e := b.closed.Load(); e != nil {
				err = *e
			}
			b.answer(err)
			return
		}
		b.h.sendData(p, end)
		if !b.h.backlog() {
			b.answer(nil)
		}
		// else: answered when the stream's output is out (flushPend,
		// drained), or when the stream ends.
	})
	return <-b.ack
}
