//go:build linux

package httpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/lb"
	"nvelox/proxy"
)

// The HTTP/1.1 fast path: the bind group's connections are served by the
// event loops of the ngx module instead of a goroutine per connection. It
// proxies the requests it fully understands (see fastparse.go and
// fastIneligible) with the semantics of HTTPServer.ServeHTTP and proxy, and
// hands every other connection — at a request boundary, with the bytes read
// so far — to the bind group's net/http server, which serves it from then on
// exactly as before.

// fastPathEnabled reports whether bind groups serve through the event loops.
func fastPathEnabled() bool { return ngx.Supported() && !fastPathOff.Load() }

// fastPathOff turns the fast path off for bind groups started from now on
// (tests compare it with the net/http path).
var fastPathOff atomic.Bool

// A panic in the code that serves one connection must not end the process,
// which serves every other connection too: net/http recovers a handler's
// panic, and the loops do the same per connection. Every entry from a loop
// into a connection's code (an event, a timer, a posted task) runs under a
// recover: the connection is closed, the request it was serving is ended as
// one whose connection broke, the panic is logged with its stack.

// loopPanicProbe is called at a few points of the loops' code with the
// point's name, when set (tests panic from it).
var loopPanicProbe atomic.Pointer[func(point string)]

func panicProbe(point string) {
	if p := loopPanicProbe.Load(); p != nil {
		(*p)(point)
	}
}

// loopPanics counts the panics recovered on the loops.
var loopPanics atomic.Int64

func logLoopPanic(what string, r any) {
	loopPanics.Add(1)
	logging.Error("[HTTP] %s: panic: %v\n%s", what, r, debug.Stack())
}

// The panic may have come from the code that ends a connection, or come
// again while the connection is ended after it. So ending a connection
// here has two parts: the usual way under its own recover, then the steps
// that give back what the connection holds outside itself (its socket, its
// place among the server's connections), each done once, whichever of the
// two parts gets to it.

// recoverPanic ends an HTTP/1.1 client connection whose code panicked.
func (c *fconn) recoverPanic() {
	r := recover()
	if r == nil {
		return
	}
	logLoopPanic("connection from "+c.peerS, r)
	c.endBroken()
}

// endBroken ends a connection after a panic in the code serving it.
func (c *fconn) endBroken() {
	c.fl.tlsDirect = false // a write of the loop may have been cut short
	func() {
		defer func() { _ = recover() }()
		c.abort(0)
	}()
	func() {
		defer func() { _ = recover() }()
		c.own.closeAll()
	}()
	c.state = csClosed
	c.l.Stop(&c.timer)
	c.l.Stop(&c.wt.Timer)
	if c.fd >= 0 {
		c.l.Unregister(c.fd, c.reg)
		unix.Close(c.fd)
		c.fd = -1
	}
	c.unlist()
}

// recoverPanic ends a backend connection whose code panicked, and the
// request it was serving.
func (u *uconn) recoverPanic() {
	r := recover()
	if r == nil {
		return
	}
	logLoopPanic("backend connection to "+u.key, r)
	u.fl.tlsDirect = false // the panic may have come from the client's side of the request
	x := u.x
	u.x = nil
	func() {
		defer func() { _ = recover() }()
		if u.state == usIdle {
			u.fl.unlinkIdle(u)
		}
		u.close()
	}()
	u.state = usClosed
	u.fl.l.Stop(&u.timer)
	if u.fd >= 0 {
		u.fl.l.Unregister(u.fd, u.reg)
		unix.Close(u.fd)
		u.fd = -1
	}
	if x != nil {
		// Each on its own: the client's connection ends whatever the
		// attempt's bookkeeping does.
		func() {
			defer func() { _ = recover() }()
			x.endAttempt()
		}()
		func() {
			defer func() { _ = recover() }()
			x.d.broken()
		}()
	}
}

// fastServer is the event-loop front end of one bind group.
type fastServer struct {
	g            *BindGroup
	lnfd         int
	group        *ngx.Group
	handoff      *handoffListener
	readHeaderTO time.Duration
	idleTO       time.Duration

	acceptors []*fastAcceptor // by loop id
	lists     []fconnList     // live connections, by loop id (loop goroutine only)
	h2lists   []h2connList    // live HTTP/2 connections, the same way
	h3lists   []*h3conn       // live HTTP/3 connections, the same way (each list through h3conn.lnext)

	started  atomic.Bool
	closing  atomic.Bool
	active   atomic.Int64
	drained  chan struct{}
	drainMu  sync.Once
	stopOnce sync.Once
	lnOnce   sync.Once

	// HTTPS (fasttls_linux.go): the listener its accept goroutine serves,
	// the group's TLS config, and the connections in their handshake.
	isTLS      bool
	tlsLn      net.Listener
	tlsCfg     *tls.Config
	handshakes sync.Map // net.Conn -> struct{}

	// The context of the requests HTTP/2 hands to net/http's handlers
	// (h2bridge_linux.go).
	h2CtxOnce sync.Once
	h2Ctx     context.Context
}

type fconnList struct{ head *fconn }

func (l *fconnList) add(c *fconn) {
	c.lnext = l.head
	c.lprev = nil
	if l.head != nil {
		l.head.lprev = c
	}
	l.head = c
}

func (l *fconnList) remove(c *fconn) {
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

func newFastServer(g *BindGroup, lnfd int, readHeader, idle time.Duration, addr net.Addr) *fastServer {
	grp := ngx.Default()
	fs := &fastServer{
		g:            g,
		lnfd:         lnfd,
		group:        grp,
		handoff:      newHandoffListener(addr),
		readHeaderTO: readHeader,
		idleTO:       idle,
		drained:      make(chan struct{}),
	}
	fs.acceptors = make([]*fastAcceptor, len(grp.Loops()))
	fs.lists = make([]fconnList, len(grp.Loops()))
	fs.h2lists = make([]h2connList, len(grp.Loops()))
	fs.h3lists = make([]*h3conn, len(grp.Loops()))
	return fs
}

// start registers the listening socket with every loop.
func (fs *fastServer) start() {
	if fs.closing.Load() || fs.lnfd < 0 || !fs.started.CompareAndSwap(false, true) {
		return
	}
	var wg sync.WaitGroup
	for _, l := range fs.group.Loops() {
		l := l
		wg.Add(1)
		l.Post(func() {
			defer wg.Done()
			if fs.closing.Load() {
				return
			}
			a := &fastAcceptor{fs: fs, l: l}
			a.timer.F = a
			reg, err := l.RegisterListener(fs.lnfd, a)
			if err != nil {
				logging.Error("[HTTP] fast path: listener %s on loop %d: %v", fs.g.addr, l.ID(), err)
				return
			}
			a.reg = reg
			fs.acceptors[l.ID()] = a
		})
	}
	wg.Wait()
}

// shutdown stops accepting, closes idle connections, ends the others after
// their current response and waits for them until ctx is done; then it
// closes what is left.
func (fs *fastServer) shutdown(done <-chan struct{}) bool {
	fs.stopOnce.Do(func() {
		fs.closing.Store(true)
		var wg sync.WaitGroup
		for _, l := range fs.group.Loops() {
			l := l
			wg.Add(1)
			l.Post(func() {
				defer wg.Done()
				if a := fs.acceptors[l.ID()]; a != nil {
					a.stop()
					fs.acceptors[l.ID()] = nil
				}
				for c := fs.lists[l.ID()].head; c != nil; {
					next := c.lnext
					c.beginShutdown()
					c = next
				}
				for c := fs.h2lists[l.ID()].head; c != nil; {
					next := c.lnext
					c.beginShutdown()
					c = next
				}
				for c := fs.h3lists[l.ID()]; c != nil; {
					next := c.lnext
					c.beginShutdown()
					c = next
				}
			})
		}
		wg.Wait()
		fs.closeListener()
		fs.handoff.Close()
		fs.checkDrained()
	})
	select {
	case <-fs.drained:
		return true
	case <-done:
	}
	// Out of time: close everything still open.
	var wg sync.WaitGroup
	for _, l := range fs.group.Loops() {
		l := l
		wg.Add(1)
		l.Post(func() {
			defer wg.Done()
			for c := fs.lists[l.ID()].head; c != nil; {
				next := c.lnext
				c.abort(statusClientClosedRequest)
				c = next
			}
			for c := fs.h2lists[l.ID()].head; c != nil; {
				next := c.lnext
				c.abortNow()
				c = next
			}
			for c := fs.h3lists[l.ID()]; c != nil; {
				next := c.lnext
				c.abortNow()
				c = next
			}
		})
	}
	wg.Wait()
	return false
}

// closeListener closes the listening socket (once).
func (fs *fastServer) closeListener() {
	fs.lnOnce.Do(func() {
		if fs.tlsLn != nil {
			fs.tlsLn.Close()
			fs.closeHandshakes()
		}
		if fs.lnfd >= 0 {
			unix.Close(fs.lnfd)
		}
	})
}

// startFast serves the plain-HTTP bind group from the event loops; ln is
// its bound socket. Connections the fast path hands over go to httpServer.
func (g *BindGroup) startFast(ln net.Listener, readHeader, idle time.Duration) error {
	addr := ln.Addr()
	fd, err := ngx.DetachListener(ln)
	if err != nil {
		return fmt.Errorf("listen %s: %w", g.addr, err)
	}
	fs := newFastServer(g, fd, readHeader, idle, addr)
	g.fast = fs
	go func() {
		if !g.serveGate.Wait(g.gateDone) {
			fs.closing.Store(true)
			fs.closeListener()
			return
		}
		fs.start()
		if err := g.httpServer.Serve(fs.handoff); err != nil && err != http.ErrServerClosed {
			logging.Error("[HTTP] Server error: %v", err)
		}
	}()
	return nil
}

func (fs *fastServer) checkDrained() {
	if fs.closing.Load() && fs.active.Load() == 0 {
		fs.drainMu.Do(func() { close(fs.drained) })
	}
}

// fastAcceptor accepts connections of one fast server on one loop.
type fastAcceptor struct {
	fs      *fastServer
	l       *ngx.Loop
	reg     ngx.Reg
	timer   ngx.Timer
	backoff time.Duration
	stopped bool
}

func (a *fastAcceptor) OnEvent(uint32) {
	for i := 0; i < 64; i++ {
		nfd, sa, err := unix.Accept4(a.fs.lnfd, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		if err != nil {
			switch err {
			case unix.EAGAIN, unix.EINTR, unix.ECONNABORTED:
				if err == unix.EAGAIN {
					a.backoff = 0
					return
				}
				continue
			}
			// EMFILE, ENFILE, ENOBUFS, ...: stop accepting for a while
			// (the socket stays readable, so a level-triggered loop would
			// spin), as net/http's Serve backs off.
			a.backoff = max(5*time.Millisecond, 2*a.backoff)
			if a.backoff > time.Second {
				a.backoff = time.Second
			}
			logging.Error("[HTTP] Accept error on %s: %v; retrying in %v", a.fs.g.addr, err, a.backoff)
			a.l.Unregister(a.fs.lnfd, a.reg)
			a.reg = ngx.Reg{}
			a.l.Arm(&a.timer, a.backoff)
			return
		}
		a.backoff = 0
		target := a.fs.group.Next()
		fs := a.fs
		if target == a.l {
			fs.newConn(target, nfd, sa)
		} else {
			target.Post(func() { fs.newConn(target, nfd, sa) })
		}
	}
}

// OnTimer re-registers the listener after an accept error.
func (a *fastAcceptor) OnTimer() {
	if a.stopped || a.fs.closing.Load() {
		return
	}
	reg, err := a.l.RegisterListener(a.fs.lnfd, a)
	if err != nil {
		a.l.Arm(&a.timer, time.Second)
		return
	}
	a.reg = reg
}

func (a *fastAcceptor) stop() {
	a.stopped = true
	a.l.Stop(&a.timer)
	if a.reg.Registered() {
		a.l.Unregister(a.fs.lnfd, a.reg)
		a.reg = ngx.Reg{}
	}
}

// fastLoop is the fast path's state on one event loop, shared by every
// fast server; only that loop's goroutine touches it.
type fastLoop struct {
	l       *ngx.Loop
	pools   map[poolKey]*upPool
	sweep   poolSweeper
	addrs   map[string]unix.Sockaddr // parsed upstream addresses
	logBuf  []byte
	logHook int
	date    dateCache
	rid     reqIDSource
	req     reqHead
	resp    respHead
	path    []byte // decoded path scratch
	head    []byte // the head of the request being served
	hdrs    []outHeader
	out     []byte // output scratch
	gather  []byte // the data of one read of a chunked body, when it came in several chunks

	// TLS: plaintext to encrypt in one record, and the ciphertext of the
	// write being encrypted (tlsDirect) before it goes out.
	tlsPlain  []byte
	tlsBuf    []byte
	tlsDirect bool

	h2 h2Loop // HTTP/2 connections (h2conn_linux.go)

	quic *quicLoop // QUIC sockets (quicloop_linux.go), made on first use
	h3   h3Loop    // HTTP/3 connections (h3conn_linux.go)
}

type outHeader struct {
	name, value []byte
	drop        bool
}

var (
	fastLoopsMu sync.Mutex
	fastLoops   []*fastLoop
)

// fastLoopOf returns the fast-path state of loop l (on l's goroutine).
func fastLoopOf(l *ngx.Loop) *fastLoop {
	id := l.ID()
	fastLoopsMu.Lock()
	for len(fastLoops) <= id {
		fastLoops = append(fastLoops, nil)
	}
	fl := fastLoops[id]
	fastLoopsMu.Unlock()
	if fl != nil {
		return fl
	}
	fl = &fastLoop{
		l:     l,
		pools: make(map[poolKey]*upPool),
		addrs: make(map[string]unix.Sockaddr),
		out:   make([]byte, 0, 16<<10),
	}
	fl.logHook = l.OnIterationEnd(fl.flushLog)
	fl.sweep.fl = fl
	fl.sweep.F = &fl.sweep
	l.Arm(&fl.sweep.Timer, poolSweepEvery)
	fastLoopsMu.Lock()
	fastLoops[id] = fl
	fastLoopsMu.Unlock()
	return fl
}

// poolSweepEvery: how often a loop drops the pools that hold no connection,
// idle or in use. A pool is keyed by its site, so this also lets go of the
// sites a reload replaced.
const poolSweepEvery = time.Minute

type poolSweeper struct {
	ngx.Timer
	fl *fastLoop
}

func (ps *poolSweeper) OnTimer() {
	fl := ps.fl
	for k, p := range fl.pools {
		if p.n == 0 && p.inUse == 0 {
			delete(fl.pools, k)
		}
	}
	fl.l.Arm(&ps.Timer, poolSweepEvery)
}

func (fl *fastLoop) flushLog() {
	if len(fl.logBuf) > 0 {
		logging.WriteAccess(fl.logBuf)
		fl.logBuf = fl.logBuf[:0]
	}
}

// Per-connection buffers come from size-class pools; a connection holds one
// only while it has something buffered.
var bufClasses = [...]int{4 << 10, 64 << 10, 256 << 10}

var bufPools [len(bufClasses)]sync.Pool

func getBuf(n int) []byte {
	for i, c := range bufClasses {
		if n <= c {
			if v := bufPools[i].Get(); v != nil {
				return unsafe.Slice(v.(*byte), c)[:0]
			}
			return make([]byte, 0, c)
		}
	}
	return make([]byte, 0, n)
}

// putBuf gives a buffer of one of the classes back. A pool holds the
// buffers by the address of their first byte: a slice in a pool would cost
// an allocation every time one is put back.
func putBuf(b []byte) {
	for i, c := range bufClasses {
		if cap(b) == c {
			bufPools[i].Put(unsafe.SliceData(b[:c]))
			return
		}
	}
}

// appendBuf appends p to *dst, growing it through the pools (doubling
// past the largest class).
func appendBuf(dst *[]byte, p []byte) {
	if len(p) == 0 {
		return
	}
	b := *dst
	if b == nil {
		b = getBuf(len(p))
	}
	if len(b)+len(p) > cap(b) {
		need := len(b) + len(p)
		if need > bufClasses[len(bufClasses)-1] {
			need = max(need, 2*cap(b))
		}
		nb := getBuf(need)
		nb = append(nb, b...)
		putBuf(b)
		b = nb
	}
	*dst = append(b, p...)
}

func releaseBuf(dst *[]byte) {
	if *dst != nil {
		putBuf(*dst)
		*dst = nil
	}
}

// ---- client connections ----

const (
	csRead   = iota // reading a request head
	csProxy         // a request is being answered
	csLinger        // closing: output flushed, waiting for the client's FIN
	csClosed
)

// fconn is one client connection on a loop.
type fconn struct {
	fs     *fastServer
	fl     *fastLoop
	l      *ngx.Loop
	fd     int
	reg    ngx.Reg
	timer  ngx.Timer  // header, idle, request-body stall or linger
	wt     writeTimer // the client stalled taking output (c.pending)
	wsince int        // bytes written since wt was armed
	state  int
	lprev  *fconn
	lnext  *fconn
	peer   netip.Addr
	peerIP net.IP   // 16-byte form of peer
	peerS  string   // peer as net.IP.String prints it
	peerB  []byte   // peerS as bytes
	tls    *fastTLS // nil: plain HTTP

	in       []byte // read but not yet consumed
	pending  []byte // output the socket did not take yet
	readable bool
	writable bool
	// rdhup: the client's FIN (or an error) was reported; a short read then
	// does not mean drained (the end of stream is still to be read and no
	// new edge will announce it).
	rdhup bool
	eof   bool // the client closed its side

	served     int // requests served on this connection
	closeAfter bool
	unlisted   bool // no longer counted among the server's connections
	reading    bool // inside readRequests
	firstByte  bool // the current request's first byte has arrived (header timer runs)

	// x is the request being answered (state csProxy).
	x fastExchange
	// A request body that gave way in the middle of its upload
	// (relayRound) is queued to go on.
	bodyQueued bool
	bodyFn     func()
	// A trusted relay's connection (accept_proxy_from): proxyWait until
	// its PROXY header is read; proxyClient the client it named.
	proxyWait   bool
	proxyClient *net.TCPAddr
	// own: its idle connections to send_proxy_v2 backends.
	own ownConns
}

// downstream is the client side of an exchange: what its request came in on
// and its response goes out on. An HTTP/1.1 connection is one (fconn).
// The exchange and its backend connection decide what is sent (the attempt,
// the retries, the body taken out of the backend's framing); a downstream
// puts it in the client's protocol.
// The protocols a client of the fast path speaks.
const (
	protoH1 uint8 = iota
	protoH2
	protoH3
)

type downstream interface {
	// serving reports whether the client still waits for this exchange.
	serving() bool
	// backlog reports that output waits for the client to take it. Until
	// it is gone nothing more is read from the backend.
	backlog() bool
	// informational passes a 1xx response of the backend on (pre: its
	// lines were built off the loop).
	informational(h *respHead, pre *bigHead)
	// head starts the response from the backend's head h; noBody says that
	// no body follows. False when the client is gone.
	head(u *uconn, h *respHead, pre *bigHead, noBody bool) bool
	// data relays body bytes; with none, a head that waits for nothing
	// goes out. False when the client is gone.
	data(u *uconn, p []byte) bool
	// end ends a body that had no length; trailers are a chunked body's
	// trailer lines. False when the client is gone.
	end(u *uconn, trailers []byte) bool
	// errorPage answers the request with nvelox's page for a status.
	errorPage(code int)
	// commonHead returns the fields nvelox puts on every response, as the
	// client's protocol writes them (for a head built off the loop); proto
	// says which protocol that is (protoH1, protoH2, protoH3).
	commonHead() []byte
	proto() uint8
	// finish: the response is complete.
	finish()
	// abort: the response cannot be completed; the client is cut off, and
	// the request logged with logStatus when nothing was sent yet. broken:
	// the code serving the request panicked: its client's connection ends.
	abort(logStatus int)
	broken()
	// mustClose: after this response the client's connection cannot carry
	// another request (a part of this one's body is unread).
	mustClose()
	// addrs returns the client of the connection (the socket's peer, or
	// the client a trusted relay named) and the address it connected to:
	// what a PROXY header to a backend names. Nil when not known.
	addrs() (client, local net.Addr)
	// pumpBody sends the request body to the backend connection u, never
	// faster than u takes it: true once all of it is out. stopBodyTimer
	// stops the limit on the client's pauses while sending it.
	pumpBody(u *uconn) bool
	stopBodyTimer()
}

// fastExchange is one request being answered: the request, its backend
// attempt and their bookkeeping. It is what a backend connection serves
// (uconn.x); d is its client side.
type fastExchange struct {
	fastReq
	d  downstream
	fs *fastServer
	fl *fastLoop
	l  *ngx.Loop

	// The client, as its side of the connection has it: its address (the
	// socket's peer, or the client a trusted relay named) and whether it
	// came over TLS.
	peer   netip.Addr
	peerIP net.IP
	peerS  string
	peerB  []byte // peerS as bytes
	secure bool
	// own: the client connection's backend connections to send_proxy_v2
	// backends (proxysend.go).
	own *ownConns

	// pl is what plan decided for the request, for begin and run.
	pl fastPlan
}

// fastReq is the state of the request being answered.
type fastReq struct {
	site      *HTTPServer
	cfg       *fastSiteConfig
	route     *fastRoute
	isHead    bool
	method    []byte // copy
	start     int64
	path      []byte // copy of the request path as logged (escaped)
	clientIP  string
	reqID     []byte
	reqIDOn   bool
	logHead   []byte
	logTail   []byte
	upReq     []byte      // the serialized upstream request (kept for retries)
	tlsCfg    *tls.Config // TLS to the backend (backend_tls), nil for a plain one
	hostAt    int         // >= 0: the client's Host was empty; the server's address goes in at this offset
	upReqHost []byte      // upReq with that address, for the current attempt
	sentHead  bool
	status    int
	bytes     int64
	logStatus int

	backendName    string
	backend        *config.Backend
	balancer       lb.Balancer
	policy         retryPolicy
	attempt        int
	excluded       []string
	target         string
	connLimiter    ConnLimiterI
	cb             CircuitBreakerI
	ph             PassiveHealthI
	cbHeld         bool  // cb.Allow() said yes and no outcome was reported yet
	onConnect      bool  // balancer.OnConnect(target) called
	sent           bool  // the request was written to the backend
	replays        int   // transparent retries on reused connections
	hasBody        bool  // the request has a (Content-Length) body
	bodyLeft       int64 // body bytes not yet sent to the backend
	bodyTouched    bool  // body bytes went to the backend (the request cannot be replayed)
	readLimit      time.Duration
	idempotencyKey bool // the request carries an (X-)Idempotency-Key
	writeLimit     time.Duration
	silence        time.Duration
	respHeader     time.Duration
	connect        time.Duration
	respRules      [2][]headerRule

	u *uconn
}

func (fs *fastServer) newConn(l *ngx.Loop, fd int, sa unix.Sockaddr) {
	var peer netip.Addr
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		peer = netip.AddrFrom4(a.Addr)
	case *unix.SockaddrInet6:
		peer = netip.AddrFrom16(a.Addr)
	default:
		unix.Close(fd)
		return
	}
	setSockOpts(fd, 15)
	c := fs.addConn(l, fd, peer, nil)
	if c != nil && fs.g.proxyTrust().TrustsIP(c.peerIP) {
		// A trusted relay: its PROXY header comes first (readProxyHeader).
		c.proxyWait = true
	}
}

// setPeer makes peer the connection's client address: the socket's peer,
// or the client a trusted relay's PROXY header names.
func (c *fconn) setPeer(peer netip.Addr) {
	c.peer = peer
	a16 := peer.As16()
	c.peerIP = net.IP(a16[:])
	c.peerB = appendAddr(nil, peer)
	c.peerS = string(c.peerB)
}

// readProxyHeader reads the PROXY v2 header a trusted relay's connection
// starts with (plain HTTP; over TLS the handshake goroutine reads it). It
// returns true once the header is in and the client it names is the
// connection's peer; false while it waits for more bytes, or after it
// closed the connection (no header, a malformed one, a bad signature). The
// read-header limit armed at the accept bounds it.
func (c *fconn) readProxyHeader() bool {
	tr := c.fs.g.proxyTrust()
	for {
		if !c.readable {
			return false
		}
		if c.in == nil {
			c.in = getBuf(4096)
		}
		if len(c.in) == cap(c.in) {
			if len(c.in) > 16+65535 {
				c.fs.g.proxyRejected(&net.TCPAddr{IP: c.peerIP}, proxyRejectMalformed, proxy.ErrBadHeader)
				c.close()
				return false
			}
			nb := append(getBuf(2*cap(c.in)), c.in...)
			putBuf(c.in)
			c.in = nb
		}
		n, eof, err := c.recv(c.in[len(c.in):cap(c.in)])
		if n == 0 {
			if eof || err != nil {
				if len(c.in) > 0 {
					// The relay gave up in the middle of its header. (One
					// that sent nothing is closed like any silent client.)
					c.fs.g.proxyRejected(&net.TCPAddr{IP: c.peerIP}, proxyRejectMalformed, io.ErrUnexpectedEOF)
				}
				c.close()
			}
			return false
		}
		c.in = c.in[:len(c.in)+n]
		done, hdr, consumed, perr := proxy.ParseStreamStrict(c.in)
		if !done {
			continue
		}
		client, reason, cause := proxyClient(tr, hdr, perr)
		if reason != "" {
			c.fs.g.proxyRejected(&net.TCPAddr{IP: c.peerIP}, reason, cause)
			c.close()
			return false
		}
		if client != nil {
			if a, ok := netip.AddrFromSlice(client.IP); ok {
				c.setPeer(a.Unmap())
				c.proxyClient = client
			}
		}
		rest := copy(c.in, c.in[consumed:])
		c.in = c.in[:rest]
		if rest == 0 {
			releaseBuf(&c.in)
		}
		c.proxyWait = false
		return true
	}
}

// addConn starts serving fd (a client connection, peer its address) on
// loop l; tc is its TLS state when it came through a handshake.
func (fs *fastServer) addConn(l *ngx.Loop, fd int, peer netip.Addr, t *fastTLS) *fconn {
	if fs.closing.Load() {
		unix.Close(fd)
		return nil
	}
	fl := fastLoopOf(l)
	c := &fconn{fs: fs, fl: fl, l: l, fd: fd, tls: t}
	c.x.d, c.x.fs, c.x.fl, c.x.l = c, fs, fl, l
	c.x.own = &c.own
	c.timer.F = c
	c.wt.c = c
	c.wt.F = &c.wt
	c.setPeer(peer)
	if t != nil {
		t.tt.owner = c
	}
	reg, err := l.Register(fd, c)
	if err != nil {
		unix.Close(fd)
		return nil
	}
	c.reg = reg
	fs.active.Add(1)
	fs.lists[l.ID()].add(c)
	c.state = csRead
	c.firstByte = true // net/http times the first request from the accept
	if fs.readHeaderTO > 0 {
		l.Arm(&c.timer, fs.readHeaderTO)
	}
	return c
}

// setSockOpts: TCP_NODELAY and keep-alive probes, like Go's net package for
// accepted (15 s) and dialed (the transport's 30 s) connections.
func setSockOpts(fd int, keepAliveSec int) {
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, keepAliveSec)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, keepAliveSec)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 9)
}

func (c *fconn) OnEvent(ev uint32) {
	if c.state == csClosed {
		return
	}
	defer c.recoverPanic()
	if ev&(ngx.EvErr|ngx.EvHup) != 0 {
		c.readable, c.writable, c.rdhup = true, true, true
	}
	if ev&ngx.EvRDHUP != 0 {
		c.rdhup = true
	}
	if ev&ngx.EvOut != 0 {
		c.writable = true
		if len(c.pending) > 0 {
			c.flush()
			if c.state == csClosed {
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

func (c *fconn) onReadable() {
	switch c.state {
	case csRead:
		c.readRequests()
	case csProxy:
		if u := c.x.u; c.x.bodyLeft > 0 && u != nil && u.state == usSending && c.x.sent {
			if c.pumpBody(u) {
				u.bodySent()
			}
			return
		}
		c.watch()
	case csLinger:
		c.drainLinger()
	}
}

// mayRead reports whether a read could return something: the socket was
// readable, or TLS may hold decrypted data.
func (c *fconn) mayRead() bool { return c.readable || (c.tls != nil && c.tls.more) }

// recv reads from the connection into p (plaintext for TLS): n > 0, or 0
// with eof / err set; would block: (0, false, nil).
func (c *fconn) recv(p []byte) (n int, eof bool, err error) {
	if c.tls != nil {
		return c.recvTLS(p)
	}
	n, errno := ngx.Read(c.fd, p)
	switch {
	case errno == unix.EAGAIN:
		c.readable = false
		return 0, false, nil
	case errno == unix.EINTR:
		return 0, false, nil
	case errno != 0:
		return 0, false, errno
	case n == 0:
		return 0, true, nil
	}
	if n < len(p) && !c.rdhup {
		c.readable = false
	}
	return n, false, nil
}

// readRequests reads and serves requests while the connection is between
// requests. It does not nest: a request answered at once (an error page)
// ends inside serveHead, and this loop goes on with the next one.
func (c *fconn) readRequests() {
	if c.reading {
		return
	}
	c.reading = true
	c.readLoop()
	c.reading = false
}

func (c *fconn) readLoop() {
	for c.state == csRead {
		if c.proxyWait && !c.readProxyHeader() {
			return
		}
		if len(c.pending) > 0 {
			// The client has not taken the last response yet. net/http
			// reads the next request only once the response is flushed;
			// flush comes back here (afterResponse) when it is out, and
			// until then the write limit runs.
			return
		}
		if len(c.in) > 0 {
			switch parseRequest(c.in, &c.fl.req) {
			case parseOK:
				h := c.fl.takeHead(c.in)
				rest := copy(c.in, c.in[len(h):])
				c.in = c.in[:rest]
				if rest == 0 {
					releaseBuf(&c.in)
				}
				c.serveHead(h)
				continue
			case parseHandoff:
				c.handoff(c.in, false)
				return
			}
			// parseMore: read on
		}
		if !c.mayRead() {
			return
		}
		if c.in == nil {
			// Nothing buffered: read into the loop's scratch and parse
			// from there; copy only what is left.
			n, eof, err := c.recv(c.l.Scratch)
			if n == 0 {
				if eof || err != nil {
					c.close()
				}
				return
			}
			c.gotBytes()
			data := c.l.Scratch[:n]
			switch parseRequest(data, &c.fl.req) {
			case parseOK:
				h := c.fl.takeHead(data)
				if len(h) < n {
					appendBuf(&c.in, data[len(h):])
				}
				c.serveHead(h)
				continue
			case parseHandoff:
				c.handoff(data, false)
				return
			}
			appendBuf(&c.in, data)
			continue
		}
		if len(c.in) >= maxFastRequestHead {
			c.handoff(c.in, false)
			return
		}
		// Append-read into the buffered input.
		if cap(c.in)-len(c.in) < 1024 {
			nb := getBuf(maxFastRequestHead + 1024)
			nb = append(nb, c.in...)
			putBuf(c.in)
			c.in = nb
		}
		n, eof, err := c.recv(c.in[len(c.in):cap(c.in)])
		if n == 0 {
			switch {
			case eof:
				// The client ended in the middle of a request head:
				// net/http answers it (400), as for every request it
				// takes over.
				c.handoff(c.in, false)
			case err != nil:
				c.close()
			}
			return
		}
		c.gotBytes()
		c.in = c.in[:len(c.in)+n]
	}
}

// takeHead copies the request head just parsed from src (c.fl.req) into
// the loop's head buffer and points the parsed fields at the copy, so that
// the request stays valid while it is answered whatever happens to src.
func (fl *fastLoop) takeHead(src []byte) []byte {
	hl := fl.req.headLen
	fl.head = append(fl.head[:0], src[:hl]...)
	fl.req.rebase(src, fl.head)
	return fl.head
}

// gotBytes notes the first byte of a request: from now on the header timer
// runs (net/http starts it once the connection is readable again).
func (c *fconn) gotBytes() {
	if !c.firstByte {
		c.firstByte = true
		if c.fs.readHeaderTO > 0 {
			c.l.Arm(&c.timer, c.fs.readHeaderTO)
		} else {
			c.l.Stop(&c.timer)
		}
	}
}

// serveHead answers the request whose head (parsed into c.fl.req) is h.
func (c *fconn) serveHead(h []byte) {
	panicProbe("request")
	req := &c.fl.req
	x := &c.x
	if !x.plan(c.fs.g, req) {
		c.handoff(h, true)
		return
	}
	// From here on the request is the fast path's.
	c.state = csProxy
	c.l.Stop(&c.timer)
	if req.connClose || c.fs.closing.Load() {
		c.closeAfter = true
	}
	x.peer, x.peerIP, x.peerS, x.peerB, x.secure = c.peer, c.peerIP, c.peerS, c.peerB, c.tls != nil
	x.begin(req, "HTTP/1.1")
	// Output queued before this request (TLS post-handshake replies, also
	// on a fresh connection, which had no write limit yet) is timed by this
	// request's write limit, from now.
	c.l.Stop(&c.wt.Timer)
	c.outPending()
	x.run(req)
}

// fastPlan is what plan decides for a request, before any gate.
type fastPlan struct {
	site        *HTTPServer
	cfg         *fastSiteConfig
	route       *fastRoute
	matches     []string
	host        []byte
	path        []byte // as the decisions see it: decoded, canonical
	canonical   bool   // the client sent it in that form
	backendName string
	backend     *config.Backend
	tlsCfg      *tls.Config // TLS to the backend, when it has backend_tls
}

// plan decides whether the request req, received by bind group g, is the
// fast path's: its site, its route and its backend. It runs before any
// gate, so that a request its caller hands to net/http instead (false) is
// not counted twice by a rate limiter. What it found is kept for begin and
// run (it points into req and the loop's scratch).
func (x *fastExchange) plan(g *BindGroup, req *reqHead) bool {
	pl := &x.pl
	*pl = fastPlan{}
	ss := g.sites.Load()
	if ss == nil || len(ss.all) == 0 {
		return false
	}
	host := req.headers[req.host].value
	var site *HTTPServer
	if len(ss.all) == 1 {
		site = ss.all[0]
	} else {
		site = g.siteForHost(ss, bstr(host))
	}
	if site.fastIneligible() {
		return false
	}
	cfg := site.fastConfig()

	// The path as the decisions see it: decoded, canonical.
	path := req.path
	if req.pathHasPct {
		x.fl.path = decodePath(x.fl.path[:0], req.path)
		path = x.fl.path
	}
	canonical := true
	if !isCanonicalPath(path) {
		canonical = false
		path = canonicalPath(path)
	}

	route, matches := cfg.matchFast(host, path)
	backendName := site.router.defaultBackend
	if route != nil {
		if route.slow {
			return false
		}
		backendName = route.r.backend
	}
	var backend *config.Backend
	var tlsCfg *tls.Config
	if backendName != "" {
		backend = site.Backends[backendName]
		if backend != nil && backend.StickySession.Type != "" {
			return false
		}
		if backend != nil && backend.BackendTLS.Enabled {
			// TLS to the backend runs on the loop, HTTP/1.1 only. net/http
			// keeps a backend whose TLS config could not be built (it
			// answers 502, never plaintext) and gRPC, which needs HTTP/2
			// to the backend.
			tlsCfg = site.backendFastTLS[backendName]
			if tlsCfg == nil || isGRPC(req.Get("Content-Type")) {
				return false
			}
		}
		if _, ok := site.StickyStores[backendName]; ok {
			return false
		}
	}

	if req.contentLength > 0 && site.MaxBodySize > 0 && req.contentLength > site.MaxBodySize {
		return false // net/http answers 413 its own way
	}
	pl.site, pl.cfg, pl.route, pl.matches = site, cfg, route, matches
	pl.host, pl.path, pl.canonical = host, path, canonical
	pl.backendName, pl.backend, pl.tlsCfg = backendName, backend, tlsCfg
	return true
}

// begin starts answering the request plan accepted: its limits, who its
// client is, its request id and the start of its access-log line. proto is
// the client's protocol, as the access log names it. The exchange's peer
// fields are set by its caller before.
func (x *fastExchange) begin(req *reqHead, proto string) {
	pl := &x.pl
	site := pl.site
	r := &x.fastReq
	r.reset()
	r.site, r.cfg, r.route = site, pl.cfg, pl.route
	r.start = x.l.Now()
	r.method = append(r.method[:0], req.method...)
	r.isHead = string(req.method) == "HEAD"
	r.idempotencyKey = req.idempotencyKey
	// The listener's write limit: how long the client may stall taking the
	// response.
	r.writeLimit, r.readLimit = defaultWriteTimeout, defaultReadTimeout
	if site.Listener != nil {
		r.writeLimit = site.Listener.Timeouts.ResolveWrite(defaultWriteTimeout)
		r.readLimit = site.Listener.Timeouts.ResolveRead(defaultReadTimeout)
	}
	r.hasBody = req.contentLength > 0
	r.bodyLeft = max(req.contentLength, 0)

	// Client identity (realClientIP).
	r.clientIP = x.clientIP(site, req)

	// Request id. (Emptied also for a site without them: the exchange may
	// have served a request of another site before.)
	r.reqIDOn = site.Listener.RequestID.Enabled
	r.reqID = r.reqID[:0]
	if r.reqIDOn {
		if req.xRequestID >= 0 {
			v := bytes.TrimSpace(req.headers[req.xRequestID].value)
			if isValidRequestIDBytes(v) && (site.Listener.RequestID.TrustInbound || site.ipTrustedAddr(x.peer)) {
				r.reqID = append(r.reqID, v...)
			}
		}
		if len(r.reqID) == 0 {
			r.reqID, _ = x.fl.rid.next(r.reqID)
		}
	}

	// Access-log fields as the request came in.
	logPath := appendEscapedPath(r.path[:0], pl.path)
	r.path = logPath
	ua := []byte(nil)
	if req.userAgent >= 0 {
		ua = req.headers[req.userAgent].value
	}
	var fetchSite, fetchDest []byte
	if req.secFetchSite >= 0 {
		fetchSite = req.headers[req.secFetchSite].value
	}
	if req.secFetchDest >= 0 {
		fetchDest = req.headers[req.secFetchDest].value
	}
	r.logHead = logging.AppendAccessHTTPHead(r.logHead[:0], r.clientIP, bstr(pl.host), bstr(req.method), bstr(logPath), proto)
	r.logTail = logging.AppendAccessHTTPTail(r.logTail[:0], bstr(ua), bstr(fetchSite), bstr(fetchDest), x.secure, bstr(r.reqID), site.Listener.Name)
}

// run takes the request through the gates, in ServeHTTP's order, builds
// the upstream request and starts the first attempt. Whatever it decides,
// the client gets its answer through the exchange's downstream.
func (x *fastExchange) run(req *reqHead) {
	if x.prepare(req) {
		x.attempt()
	}
}

// prepare is run without the first attempt: the gates and the upstream
// request. False: the request was answered (a gate refused it). After it
// the request head is no longer needed, so the attempt can start later
// (an HTTP/2 connection starts it once its input is processed).
func (x *fastExchange) prepare(req *reqHead) bool {
	pl := &x.pl
	site, route, path, backendName := pl.site, pl.route, pl.path, pl.backendName
	r := &x.fastReq
	if st := site.clientStatusIP(x.clientNetIP(r)); st != 0 {
		x.d.errorPage(st)
		return false
	}
	if site.RateLimiter != nil && !site.RateLimiter.Allow() {
		x.d.errorPage(http.StatusTooManyRequests)
		return false
	}
	if site.IPRateLimiter != nil && !site.IPRateLimiter.Allow(r.clientIP) {
		x.d.errorPage(http.StatusTooManyRequests)
		return false
	}
	if site.ACLEngine != nil {
		if action, status := site.ACLEngine.Decide(bstr(req.method), bstr(path), req, x.clientNetIP(r)); action == "deny" {
			if status == 0 {
				status = http.StatusForbidden
			}
			x.d.errorPage(status)
			return false
		}
	}
	if backendName == "" {
		x.d.errorPage(http.StatusServiceUnavailable)
		return false
	}
	balancer, ok := site.Balancers[backendName]
	if !ok {
		x.d.errorPage(http.StatusBadGateway)
		return false
	}
	r.backendName, r.backend, r.balancer = backendName, pl.backend, balancer
	r.tlsCfg = pl.tlsCfg
	if cl, ok := site.ConnLimiters[backendName]; ok {
		if !cl.Acquire() {
			x.d.errorPage(http.StatusServiceUnavailable)
			return false
		}
		r.connLimiter = cl
	}

	// The upstream request.
	upPath := req.path
	upRaw := pl.canonical // the client's spelling of the path goes upstream
	if route != nil && route.r.rewrite.Path != "" {
		np := route.r.rewrite.Path
		if len(pl.matches) > 0 {
			np = ApplyRewrite(np, pl.matches)
		}
		path = []byte(np)
		upRaw = false
	}
	if !upRaw {
		upPath = appendEscapedPath(x.fl.out[:0], path)
		x.fl.out = upPath[:0]
	}
	r.upReq = x.buildUpstreamRequest(r.upReq[:0], site, req, upPath)

	r.policy = newRetryPolicy(pl.backend)
	r.cb = site.CircuitBreakers[backendName]
	r.ph = site.PassiveHealth[backendName]
	r.connect, r.respHeader = backendTimeouts(site.Listener, pl.backend)
	r.silence = backendSilenceLimit(pl.backend)
	r.respRules[0] = pl.cfg.respRules
	if route != nil {
		r.respRules[1] = route.respRules
	}
	return true
}

func (r *fastReq) reset() {
	r.route = nil
	r.sentHead, r.status, r.bytes, r.logStatus = false, 0, 0, 0
	r.backendName, r.backend, r.balancer = "", nil, nil
	r.tlsCfg = nil
	r.attempt = 0
	r.excluded = r.excluded[:0]
	r.target = ""
	r.connLimiter, r.cb, r.ph = nil, nil, nil
	r.cbHeld, r.onConnect, r.sent = false, false, false
	r.replays = 0
	r.hasBody, r.bodyLeft, r.bodyTouched = false, 0, false
	r.respRules = [2][]headerRule{}
	r.u = nil
}

// replayable is retry.go's replayable for the request: one with a body only
// while nothing of it was sent; one without, if it never reached the
// backend or its method is idempotent.
func (r *fastReq) replayable(sent bool) bool {
	if r.hasBody {
		return !sent && !r.bodyTouched
	}
	return !sent || idempotentMethods[string(r.method)]
}

// clientIP is realClientIP for the fast path.
func (x *fastExchange) clientIP(site *HTTPServer, req *reqHead) string {
	if len(site.TrustedProxies) == 0 || !site.ipTrustedAddr(x.peer) {
		return x.peerS
	}
	nearest := x.peer
	for i := req.n - 1; i >= 0; i-- {
		hd := &req.headers[i]
		if hd.kind != hkXForwardedFor {
			continue
		}
		line := hd.value
		for len(line) > 0 {
			var hop []byte
			if j := bytes.LastIndexByte(line, ','); j >= 0 {
				hop, line = line[j+1:], line[:j]
			} else {
				hop, line = line, nil
			}
			hop = bytes.TrimSpace(hop)
			if len(hop) == 0 {
				continue
			}
			a := parseHopAddr(hop)
			if !a.IsValid() {
				return string(appendAddr(nil, nearest))
			}
			if !site.ipTrustedAddr(a) {
				return string(appendAddr(nil, a))
			}
			nearest = a
		}
	}
	if req.xRealIP >= 0 {
		if a := parseHopAddr(bytes.TrimSpace(req.headers[req.xRealIP].value)); a.IsValid() {
			return string(appendAddr(nil, a))
		}
	}
	return x.peerS
}

// clientNetIP is the request's client as a net.IP.
func (x *fastExchange) clientNetIP(r *fastReq) net.IP {
	if r.clientIP == x.peerS {
		return x.peerIP
	}
	return net.ParseIP(r.clientIP)
}

// clientStatusIP is clientStatus for a parsed client address.
func (s *HTTPServer) clientStatusIP(ip net.IP) int {
	if ip == nil {
		return 0
	}
	if len(s.IPDenylist) > 0 && ipInNets(ip, s.IPDenylist) {
		return http.StatusForbidden
	}
	if s.DynDenylist != nil && !s.DynDenylist.Empty() && s.DynDenylist.Blocked(ip) {
		return http.StatusForbidden
	}
	if len(s.IPAllowlist) > 0 && !ipInNets(ip, s.IPAllowlist) {
		return http.StatusForbidden
	}
	return 0
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// sendBytes is the upstream request of the current attempt.
func (r *fastReq) sendBytes() []byte {
	if r.hostAt >= 0 {
		return r.upReqHost
	}
	return r.upReq
}

// buildUpstreamRequest serializes the request as the slow path sends it:
// ReverseProxy's hop-by-hop and forwarding-header removal, the Rewrite of
// proxyOnce (applyForwardedHeaders, the request id, the header rules), then
// net/http's request writer (Host and User-Agent first, Content-Length: 0
// for a body-less POST, PUT or PATCH).
func (x *fastExchange) buildUpstreamRequest(b []byte, site *HTTPServer, req *reqHead, path []byte) []byte {
	r := &x.fastReq
	fl := x.fl
	trusted := site.ipTrustedAddr(x.peer)
	hs := fl.hdrs[:0]
	var xffBuf []byte
	var realIP, fwdProto []byte
	xffSeen, realSeen, protoSeen := false, false, false
	for i := 0; i < req.n; i++ {
		hd := &req.headers[i]
		// The forwarding headers come from the inbound request as
		// applyForwardedHeaders reads them: the first X-Real-IP and
		// X-Forwarded-Proto (even empty), every X-Forwarded-For line, and
		// a trusted peer's Forwarded and X-Forwarded-Host, whether or not
		// its Connection header names them.
		switch hd.kind {
		case hkXForwardedFor:
			if trusted {
				// Joined as strings.Join does: an empty line counts.
				if xffSeen {
					xffBuf = append(xffBuf, ", "...)
				}
				xffSeen = true
				xffBuf = append(xffBuf, hd.value...)
			}
			continue
		case hkXForwardedProto:
			if trusted && !protoSeen {
				protoSeen, fwdProto = true, hd.value
			}
			continue
		case hkXRealIP:
			if trusted && !realSeen {
				realSeen, realIP = true, hd.value
			}
			continue
		case hkForwarded, hkXForwardedHost:
			if trusted {
				hs = append(hs, outHeader{name: hd.name, value: hd.value})
			}
			continue
		}
		if hd.drop {
			continue
		}
		switch hd.kind {
		case hkHost, hkContentLength:
			continue
		case hkUntrustedFwd:
			if !trusted {
				continue
			}
		case hkXRequestID:
			if r.reqIDOn {
				continue
			}
		}
		hs = append(hs, outHeader{name: hd.name, value: hd.value})
	}
	if req.teTrailers {
		hs = append(hs, outHeader{name: hdrTe, value: valTrailers})
	}
	peer := x.peerB
	proto := valHTTP
	if x.secure {
		proto = valHTTPS
	}
	if trusted {
		if len(xffBuf) > 0 {
			xffBuf = append(xffBuf, ", "...)
		}
		xffBuf = append(xffBuf, peer...)
		hs = append(hs, outHeader{name: hdrXForwardedFor, value: xffBuf})
		if len(realIP) == 0 {
			realIP = peer
		}
		hs = append(hs, outHeader{name: hdrXRealIP, value: realIP})
		if len(fwdProto) == 0 {
			fwdProto = proto
		}
		hs = append(hs, outHeader{name: hdrXForwardedProto, value: fwdProto})
	} else {
		hs = append(hs, outHeader{name: hdrXForwardedFor, value: peer},
			outHeader{name: hdrXRealIP, value: peer},
			outHeader{name: hdrXForwardedProto, value: proto})
	}
	if r.reqIDOn {
		hs = append(hs, outHeader{name: hdrXRequestID, value: r.reqID})
	}
	hs = applyRules(hs, r.cfg.reqRules)
	if r.route != nil {
		hs = applyRules(hs, r.route.reqRules)
	}
	fl.hdrs = hs[:0]

	b = append(b, req.method...)
	b = append(b, ' ')
	b = append(b, path...)
	if req.hasQuery {
		b = append(b, '?')
		b = append(b, req.query...)
	}
	b = append(b, " HTTP/1.1\r\nHost: "...)
	r.hostAt = -1
	if host := req.headers[req.host].value; len(host) > 0 {
		b = append(b, host...)
	} else {
		// net/http's Transport sends the server's address for an empty
		// Host: it is put in per attempt (sendBytes).
		r.hostAt = len(b)
	}
	b = append(b, "\r\n"...)
	for i := range hs {
		if !hs[i].drop && equalFoldLower(hs[i].name, "user-agent") {
			if len(hs[i].value) > 0 {
				b = append(b, "User-Agent: "...)
				b = append(b, hs[i].value...)
				b = append(b, "\r\n"...)
			}
			break
		}
	}
	// net/http's request writer: the body's length, and a body-less POST,
	// PUT or PATCH says so.
	if req.contentLength > 0 {
		b = append(b, "Content-Length: "...)
		b = appendInt(b, req.contentLength)
		b = append(b, "\r\n"...)
	} else {
		switch string(req.method) {
		case "POST", "PUT", "PATCH":
			b = append(b, "Content-Length: 0\r\n"...)
		}
	}
	for i := range hs {
		h := &hs[i]
		if h.drop || equalFoldLower(h.name, "user-agent") {
			continue
		}
		b = append(b, h.name...)
		b = append(b, ": "...)
		b = append(b, h.value...)
		b = append(b, "\r\n"...)
	}
	return append(b, "\r\n"...)
}

var (
	hdrTe              = []byte("Te")
	hdrXForwardedFor   = []byte("X-Forwarded-For")
	hdrXRealIP         = []byte("X-Real-Ip")
	hdrXForwardedProto = []byte("X-Forwarded-Proto")
	hdrXRequestID      = []byte("X-Request-Id")
	valTrailers        = []byte("trailers")
	valHTTP            = []byte("http")
	valHTTPS           = []byte("https")
)

// applyRules applies header rules (add / set / remove) to hs.
func applyRules(hs []outHeader, rules []headerRule) []outHeader {
	for i := range rules {
		rl := &rules[i]
		if rl.skip {
			continue
		}
		switch rl.op {
		case ruleAdd:
			hs = append(hs, outHeader{name: []byte(rl.name), value: []byte(rl.value)})
		case ruleSet, ruleRemove:
			for j := range hs {
				if !hs[j].drop && strings.EqualFold(bstr(hs[j].name), rl.name) {
					hs[j].drop = true
				}
			}
			if rl.op == ruleSet {
				hs = append(hs, outHeader{name: []byte(rl.name), value: []byte(rl.value)})
			}
		}
	}
	return hs
}

// ---- attempts against the backend ----

// attempt starts the next attempt of the current request (proxy's loop).
func (x *fastExchange) attempt() {
	r := &x.fastReq
	var target string
	var err error
	if r.attempt == 0 {
		target, err = r.balancer.Next()
	} else {
		target, err = r.balancer.NextExcluding(r.excluded)
	}
	if err != nil {
		x.d.errorPage(http.StatusServiceUnavailable)
		return
	}
	if r.cb != nil && !r.cb.Allow() {
		x.d.errorPage(http.StatusServiceUnavailable)
		return
	}
	r.cbHeld = r.cb != nil
	r.target = target
	if r.hostAt >= 0 {
		r.upReqHost = append(append(append(r.upReqHost[:0], r.upReq[:r.hostAt]...), target...), r.upReq[r.hostAt:]...)
	}
	r.sent = false
	r.balancer.OnConnect(target)
	r.onConnect = true
	x.connectUpstream(false)
}

// connectUpstream gets a connection to r.target (an idle one unless fresh)
// and sends the request.
func (x *fastExchange) connectUpstream(fresh bool) {
	r := &x.fastReq
	var u *uconn
	k := poolKey{site: r.site, backend: r.backendName, target: r.target, tls: r.tlsCfg}
	// A send_proxy_v2 backend's connections carry one client's header:
	// the request uses one of its client connection's own, or a new one.
	var own *ownConns
	if sendsProxy(r.backend) {
		if own = x.own; own == nil {
			x.attemptFailed(&net.OpError{Op: "dial", Net: "tcp", Addr: fakeAddr(r.target), Err: errNoProxyClient}, false, false)
			return
		}
	}
	if !fresh {
		if own != nil {
			u = own.take(k)
		} else {
			u = x.fl.takeIdle(k)
		}
	}
	if u == nil {
		var hdr []byte
		if own != nil {
			var err error
			if hdr, err = own.header(x.d, r.backend.SendProxyKey); err != nil {
				x.attemptFailed(&net.OpError{Op: "dial", Net: "tcp", Addr: fakeAddr(r.target), Err: err}, false, false)
				return
			}
		}
		if r.tlsCfg != nil {
			u = x.fl.dialTLS(k, r.connect, hdr)
		} else {
			var err error
			u, err = x.fl.dial(k, r.connect)
			if err != nil {
				x.attemptFailed(err, false, false)
				return
			}
			u.hdr = hdr
		}
		u.own = own
	}
	if own != nil {
		own.use(u, x.l.Now())
	} else {
		x.fl.poolOf(k).use(u, x.l.Now())
	}
	u.x = x
	r.u = u
	if u.state == usConnecting || u.state == usResolving || u.state == usDialTLS {
		return // sendRequest runs once connected
	}
	u.sendRequest()
}

// attemptFailed classifies a failed attempt the way proxyOnce does: answered
// says the backend's response head arrived (it was then rejected), timeout
// that the response-header timeout expired.
func (x *fastExchange) attemptFailed(err error, answered, timeout bool) {
	r := &x.fastReq
	path := bstr(r.path)
	switch {
	case answered:
		// reported by the caller
		x.endAttempt()
		logging.Error("[HTTP] Upstream %s failed for %s: %v", r.target, logging.SanitizeLogField(path), err)
		x.d.errorPage(http.StatusBadGateway)
		return
	case r.sent && timeout:
		x.report(false)
		x.endAttempt()
		logging.Error("[HTTP] Upstream %s did not answer %s in time: %v", r.target, logging.SanitizeLogField(path), err)
		x.d.errorPage(http.StatusGatewayTimeout)
		return
	}
	x.report(false)
	canRetry := r.attempt+1 < r.policy.attempts
	if canRetry && r.policy.onConnectFailure && r.replayable(r.sent) {
		x.endAttempt()
		logging.Warn("[HTTP] Retry %d/%d for %s: %v", r.attempt+1, r.policy.attempts, logging.SanitizeLogField(path), err)
		r.excluded = append(r.excluded, r.target)
		r.attempt++
		x.attempt()
		return
	}
	x.endAttempt()
	logging.Error("[HTTP] Upstream %s failed for %s: %v", r.target, logging.SanitizeLogField(path), err)
	x.d.errorPage(http.StatusBadGateway)
}

// report records the attempt's outcome with passive health and the
// circuit breaker (once).
func (x *fastExchange) report(ok bool) {
	r := &x.fastReq
	if ok {
		if r.ph != nil {
			r.ph.RecordSuccess(r.target)
		}
		if r.cb != nil && r.cbHeld {
			r.cb.RecordSuccess()
		}
	} else {
		if r.ph != nil {
			r.ph.RecordFailure(r.target)
		}
		if r.cb != nil && r.cbHeld {
			r.cb.RecordFailure()
		}
	}
	r.cbHeld = false
}

// endAttempt closes the attempt's books: the balancer's connection count,
// and the breaker's slot when no outcome was reported.
func (x *fastExchange) endAttempt() {
	r := &x.fastReq
	if r.onConnect {
		r.balancer.OnDisconnect(r.target)
		r.onConnect = false
	}
	if r.cbHeld {
		r.cb.Release()
		r.cbHeld = false
	}
	r.u = nil
}

// ---- responses to the client ----

// sendError answers the request with a status page (serveError).
func (c *fconn) sendError(code int) {
	r := &c.x.fastReq
	site := r.site
	if r.bodyLeft > 0 {
		// The request body is unread: the connection closes after this
		// response (stall.go).
		c.closeAfter = true
	}
	body := errorPageBody(site, code)
	b := c.fl.out[:0]
	b = append(b, statusLine(code)...)
	b = append(b, "Content-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"...)
	b = c.appendCommonHeaders(b)
	b = append(b, "Content-Length: "...)
	b = appendInt(b, int64(len(body)))
	b = append(b, "\r\n"...)
	if c.closeAfter {
		b = append(b, "Connection: close\r\n"...)
	}
	b = append(b, "Date: "...)
	b = append(b, c.fl.date.get(c.l.Wall())...)
	b = append(b, "\r\n\r\n"...)
	c.fl.out = b[:0]
	r.sentHead, r.status = true, code
	var ok bool
	if r.isHead {
		ok = c.write2(b, nil)
	} else {
		ok = c.write2(b, body)
	}
	if !ok {
		return // the write failed: the connection was aborted, request logged
	}
	r.bytes = int64(len(body))
	c.finish()
}

// The rest of downstream for an HTTP/1.1 connection.

func (c *fconn) serving() bool      { return c.state == csProxy }
func (c *fconn) backlog() bool      { return len(c.pending) > 0 }
func (c *fconn) errorPage(code int) { c.sendError(code) }
func (c *fconn) commonHead() []byte { return c.appendCommonHeaders(nil) }
func (c *fconn) proto() uint8       { return protoH1 }
func (c *fconn) broken()            { c.endBroken() }
func (c *fconn) mustClose()         { c.closeAfter = true }
func (c *fconn) stopBodyTimer()     { c.l.Stop(&c.timer) }

// appendCommonHeaders appends the headers ServeHTTP puts on every response
// besides X-Content-Type-Options: Alt-Svc and the echoed request id.
func (c *fconn) appendCommonHeaders(b []byte) []byte {
	r := &c.x.fastReq
	if r.site != nil && r.site.altSvcHeader != "" {
		b = append(b, "Alt-Svc: "...)
		b = append(b, r.site.altSvcHeader...)
		b = append(b, "\r\n"...)
	}
	if r.reqIDOn {
		b = append(b, "X-Request-Id: "...)
		b = append(b, r.reqID...)
		b = append(b, "\r\n"...)
	}
	return b
}

func appendInt(b []byte, n int64) []byte {
	var tmp [20]byte
	i := len(tmp)
	if n == 0 {
		return append(b, '0')
	}
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(b, tmp[i:]...)
}

// write2 writes a then b to the client, keeping what the socket does not
// take in c.pending. Returns false when the connection failed.
func (c *fconn) write2(a, b []byte) bool {
	if c.state == csClosed {
		return false
	}
	if c.tls != nil {
		return c.writeTLS(a, b, nil)
	}
	if len(c.pending) > 0 {
		appendBuf(&c.pending, a)
		appendBuf(&c.pending, b)
		return true
	}
	var n int
	var errno syscall.Errno
	if len(b) == 0 {
		n, errno = ngx.Write(c.fd, a)
	} else if len(a) == 0 {
		n, errno = ngx.Write(c.fd, b)
	} else {
		iov := c.l.Iov[:2]
		ngx.SetIov(&iov[0], a)
		ngx.SetIov(&iov[1], b)
		n, errno = ngx.Writev(c.fd, iov)
		iov[0].Base, iov[1].Base = nil, nil
	}
	if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR {
		c.writeFailed()
		return false
	}
	if n < len(a)+len(b) {
		if n < len(a) {
			appendBuf(&c.pending, a[n:])
			appendBuf(&c.pending, b)
		} else {
			appendBuf(&c.pending, b[n-len(a):])
		}
		c.writable = false
		c.outPending()
	}
	return true
}

// writeTimer is a connection's write limit: it runs while output waits
// for the client (c.pending), in every state, apart from the connection's
// other timer.
type writeTimer struct {
	ngx.Timer
	c *fconn
}

// OnTimer: the client stalled taking output past the write limit.
func (wt *writeTimer) OnTimer() {
	c := wt.c
	defer c.recoverPanic()
	switch c.state {
	case csProxy:
		c.abort(0)
	case csRead, csLinger:
		c.close()
	}
}

// outPending starts the write limit when output starts waiting for the
// client. Like net/http, which sets the write deadline per write of at most
// the response buffer (32 KiB), the limit restarts after every 32 KiB the
// client takes (writePending).
func (c *fconn) outPending() {
	if len(c.pending) == 0 || c.wt.Armed() || c.x.writeLimit <= 0 {
		return
	}
	c.wsince = 0
	c.l.Arm(&c.wt.Timer, c.x.writeLimit)
}

// writePending writes pending output while the socket takes it; false when
// the connection failed (it is then closed).
func (c *fconn) writePending() bool {
	for len(c.pending) > 0 {
		n, errno := ngx.Write(c.fd, c.pending)
		if errno == unix.EAGAIN {
			c.writable = false
			return true
		}
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			c.writeFailed()
			return false
		}
		rest := copy(c.pending, c.pending[n:])
		c.pending = c.pending[:rest]
		if c.wsince += n; c.wsince >= 32<<10 && c.wt.Armed() && len(c.pending) > 0 {
			c.wsince = 0
			if c.x.writeLimit > 0 {
				c.l.Arm(&c.wt.Timer, c.x.writeLimit)
			} else {
				c.l.Stop(&c.wt.Timer)
			}
		}
	}
	releaseBuf(&c.pending)
	c.l.Stop(&c.wt.Timer)
	return true
}

// flush writes pending output; when it is all out, a paused upstream
// resumes and a finished response completes.
func (c *fconn) flush() {
	if !c.writePending() || len(c.pending) > 0 {
		return
	}
	switch c.state {
	case csProxy:
		if u := c.x.u; u != nil {
			u.resume()
			// A request body waits for the client's output (pumpBody).
			if c.state == csProxy && c.x.u == u && c.x.bodyLeft > 0 && u.state == usSending && c.x.sent {
				if c.pumpBody(u) {
					u.bodySent()
				}
			}
		}
	case csRead:
		c.afterResponse()
	case csLinger:
		c.lingerStart()
	}
}

// writeFailed: the client stopped taking the response.
func (c *fconn) writeFailed() {
	c.abort(0)
}

// finish ends the current request: access log, accounting, and either the
// next request or the close.
func (c *fconn) finish() {
	if c.state == csClosed {
		return
	}
	c.l.Stop(&c.timer) // the body's read limit ends with the request
	r := &c.x.fastReq
	c.x.logRequest()
	if r.connLimiter != nil {
		r.connLimiter.Release()
		r.connLimiter = nil
	}
	c.served++
	if c.closeAfter {
		c.state = csLinger
		if len(c.pending) == 0 {
			c.lingerStart()
		}
		return
	}
	c.state = csRead
	if len(c.pending) == 0 {
		c.afterResponse()
	}
	// else: flush completes it
}

// afterResponse: the response is out; wait for (or serve) the next request.
func (c *fconn) afterResponse() {
	if c.state != csRead {
		return
	}
	c.firstByte = false
	if len(c.in) > 0 {
		c.gotBytes()
	} else {
		if c.fs.closing.Load() {
			c.close()
			return
		}
		if c.fs.idleTO > 0 {
			c.l.Arm(&c.timer, c.fs.idleTO)
		} else {
			c.l.Stop(&c.timer)
		}
	}
	if !c.reading && (len(c.in) > 0 || c.mayRead()) {
		c.readRequests()
	}
}

func (x *fastExchange) logRequest() {
	r := &x.fastReq
	status := r.status
	if !r.sentHead {
		status = http.StatusOK
		if r.logStatus != 0 {
			status = r.logStatus
		}
	}
	fl := x.fl
	dur := float64((x.l.Now()-r.start)/1000) / 1000.0
	// The loop's buffer takes the line when it is whole: a line cut short
	// (a panic while it is written) never joins the next request's.
	b := append(fl.logBuf, r.logHead...)
	b = logging.AppendAccessHTTPMid(b, status, r.bytes, dur, r.target)
	fl.logBuf = append(b, r.logTail...)
	fl.l.RequestIterationEnd(fl.logHook)
	if len(fl.logBuf) > 64<<10 {
		fl.flushLog()
	}
}

// watch handles readiness of the client while a request is answered: it
// detects the client going away (net/http cancels the request then) and
// buffers what it sends next.
func (c *fconn) watch() {
	for c.mayRead() && c.state == csProxy {
		if len(c.in) >= maxFastRequestHead {
			return // enough buffered; read on after the response
		}
		if c.in == nil {
			c.in = getBuf(1)
		}
		if cap(c.in)-len(c.in) == 0 {
			nb := getBuf(maxFastRequestHead + 1024)
			nb = append(nb, c.in...)
			putBuf(c.in)
			c.in = nb
		}
		n, eof, err := c.recv(c.in[len(c.in):cap(c.in)])
		if n > 0 {
			c.in = c.in[:len(c.in)+n]
			continue
		}
		if len(c.in) == 0 {
			releaseBuf(&c.in)
		}
		if eof || err != nil {
			c.eof = true
			c.abort(statusClientClosedRequest)
		}
		return
	}
}

// abort ends the connection now: the request in progress (if any) is
// cancelled, its backend connection closed, and the request logged with
// logStatus when nothing was sent (0: keep what was sent).
func (c *fconn) abort(logStatus int) {
	if c.state == csClosed {
		return
	}
	if c.state == csProxy {
		r := &c.x.fastReq
		if u := r.u; u != nil {
			u.x = nil
			u.close()
		}
		if r.onConnect || r.cbHeld {
			c.x.endAttempt()
		}
		if !r.sentHead && logStatus != 0 {
			r.logStatus = logStatus
		}
		c.x.logRequest()
		if r.connLimiter != nil {
			r.connLimiter.Release()
			r.connLimiter = nil
		}
	}
	c.close()
}

// beginShutdown: the server is stopping. An idle connection closes now; one
// answering a request closes after its response.
func (c *fconn) beginShutdown() {
	switch c.state {
	case csRead:
		if len(c.in) == 0 && len(c.pending) == 0 {
			c.close()
			return
		}
		c.closeAfter = true
	case csProxy:
		c.closeAfter = true
	}
}

// lingerStart half-closes the connection after its last response and waits
// briefly for the client's FIN, so that unread input does not turn the
// close into a reset that could destroy the response (net/http's
// closeWriteAndWait).
func (c *fconn) lingerStart() {
	if c.state == csClosed {
		return
	}
	c.state = csLinger
	if c.tls != nil {
		c.tlsCloseNotify()
	}
	_ = unix.Shutdown(c.fd, unix.SHUT_WR)
	c.l.Arm(&c.timer, 500*time.Millisecond)
	c.drainLinger()
}

func (c *fconn) drainLinger() {
	// Only once the response is out (lingerStart): before, a client that
	// already sent its FIN would have the end of its response cut.
	for c.state == csLinger && len(c.pending) == 0 && c.mayRead() {
		n, eof, err := c.recv(c.l.Scratch)
		if eof || err != nil {
			c.close()
			return
		}
		if n == 0 {
			return
		}
	}
}

// OnTimer: the header, idle, write or linger timer of the connection fired.
func (c *fconn) OnTimer() {
	defer c.recoverPanic()
	switch c.state {
	case csRead:
		if c.proxyWait && len(c.in) > 0 {
			// A relay that stalled in the middle of its PROXY header.
			c.fs.g.proxyRejected(&net.TCPAddr{IP: c.peerIP}, proxyRejectTimeout, nil)
		}
		// Header or idle timeout: net/http closes without a response.
		c.close()
	case csProxy:
		if c.x.bodyLeft > 0 && !c.x.sentHead {
			// The client stalled sending its body past the read limit:
			// 408, as stall.go answers.
			c.bodyFailed(http.StatusRequestTimeout)
			return
		}
		// The client stalled sending the rest of a body the response
		// already started for.
		c.abort(0)
	case csLinger:
		c.close()
	}
}

// close releases the connection.
func (c *fconn) close() {
	if c.state == csClosed {
		return
	}
	if c.tls != nil {
		c.tlsCloseNotify()
	}
	c.state = csClosed
	c.l.Stop(&c.timer)
	c.l.Stop(&c.wt.Timer)
	c.l.Unregister(c.fd, c.reg)
	unix.Close(c.fd)
	c.fd = -1
	panicProbe("close")
	c.release()
}

// release frees the connection's buffers and drops it from the server.
func (c *fconn) release() {
	c.own.closeAll()
	releaseBuf(&c.in)
	releaseBuf(&c.pending)
	if c.tls != nil {
		c.tls.release()
	}
	c.unlist()
}

// unlist takes the connection out of the server's list and count (once).
func (c *fconn) unlist() {
	if c.unlisted {
		return
	}
	c.unlisted = true
	c.fs.lists[c.l.ID()].remove(c)
	c.fs.active.Add(-1)
	c.fs.checkDrained()
}

// handoff gives the connection to the bind group's net/http server, with
// the bytes read and not yet answered: first, then c.in when withIn.
func (c *fconn) handoff(first []byte, withIn bool) {
	prefix := make([]byte, 0, len(first)+len(c.in))
	prefix = append(prefix, first...)
	if withIn {
		prefix = append(prefix, c.in...)
	}
	// Output not yet written (the end of the previous response) goes out
	// before anything net/http writes.
	unwritten := append([]byte(nil), c.pending...)
	fd := c.fd
	t := c.tls
	var unread []byte // TLS: ciphertext read from the socket, not decrypted yet
	if t != nil {
		unread = t.tt.unread()
	}
	c.state = csClosed
	c.l.Stop(&c.timer)
	c.l.Stop(&c.wt.Timer)
	c.l.Unregister(fd, c.reg)
	c.fd = -1
	c.release()
	f := os.NewFile(uintptr(fd), "")
	nc, err := net.FileConn(f)
	f.Close()
	if err != nil {
		logging.Error("[HTTP] fast path: handing a connection to net/http: %v", err)
		return
	}
	var hc net.Conn
	if t == nil {
		hc = &prefixConn{Conn: nc, prefix: prefix, remote: c.proxyClient}
	} else {
		t.tt.toBlocking(nc, unread)
		st := t.tc.ConnectionState()
		hc = &tlsHandoffConn{prefixConn: prefixConn{Conn: t.tc, prefix: prefix}, state: &st}
	}
	hl := c.fs.handoff
	if len(unwritten) == 0 {
		hl.push(hc)
		return
	}
	go func() {
		nc.SetWriteDeadline(time.Now().Add(defaultWriteTimeout))
		if _, err := nc.Write(unwritten); err != nil {
			hc.Close()
			return
		}
		nc.SetWriteDeadline(time.Time{})
		hl.push(hc)
	}()
}

// ---- upstream connections ----

const (
	usIdle      = iota
	usResolving // looking up a host name
	usDialTLS   // connecting and handshaking with a TLS backend, off the loop
	usConnecting
	usSending
	usWaitHead
	usBody
	usClosed
)

// poolKey scopes idle backend connections the way the net/http path's
// transports are scoped: per site and backend, then per server address. A
// connection is never reused across sites, even to the same address.
type poolKey struct {
	site    *HTTPServer
	backend string
	target  string
	// tls is the config a backend_tls backend's connections were made
	// with (the site's, so a reload's new settings never reuse them).
	tls *tls.Config
}

type upPool struct {
	key  poolKey
	head *uconn
	n    int // idle connections
	usePeak
}

// usePeak counts the connections that serve a request now (those being
// opened included), among a pool's or among the ones one client connection
// has to itself (ownConns), and remembers the most that did at the same
// time: in the current period and in the one before it (poolPeakPeriod).
type usePeak struct {
	inUse  int
	peak   int
	prev   int
	period int64
}

// How many idle connections a loop keeps to one backend server.
//
// A fixed number is wrong in both directions. Too small for the load, and
// every request above it closes its connection when it is done and the
// next one opens a new one: with 320 requests in flight on a loop and 64
// kept, that was 14,000 connects a second, local ports ran short and the
// proxy stalled. Too large, and a quiet backend is left holding
// connections nobody needs.
//
// So the number follows the load: a connection is kept while the pool
// holds fewer idle ones than the most that were in use at the same time
// in the last seconds. A steady load, however large, then reopens nothing;
// a burst leaves behind what it used at once, and those close when they
// have been idle for upIdleTimeout, or as later requests return them to a
// pool that needs fewer. How many connections are opened is not decided
// here but by how many requests run at once (a backend's max_connections
// bounds that).
//
// It never goes below the number net/http's path keeps: its 256 per
// backend server (MaxIdleConnsPerHost) divided among the loops, at least
// 16 per loop.

// minIdlePerTarget is that floor.
func (fl *fastLoop) minIdlePerTarget() int {
	return max(16, 256/len(fl.l.Group().Loops()))
}

// poolPeakPeriod is the length of a period over which a pool's peak of
// connections in use is taken. The current period and the one before count,
// so "the last seconds" are between one and two of them. A variable for the
// tests only.
var poolPeakPeriod = int64(5 * time.Second)

// roll moves the peaks on when a period has ended.
func (p *usePeak) roll(now int64) {
	per := now / poolPeakPeriod
	if per == p.period {
		return
	}
	if per == p.period+1 {
		p.prev = p.peak
	} else {
		p.prev = 0
	}
	p.peak, p.period = p.inUse, per // what is in use now is this period's start
}

// use counts u, which starts to serve a request, among the connections in
// use.
func (p *usePeak) use(u *uconn, now int64) {
	p.roll(now)
	p.inUse++
	p.peak = max(p.peak, p.inUse)
	u.up = p
}

// keep returns how many idle connections are kept now.
func (p *usePeak) keep(now int64, floor int) int {
	p.roll(now)
	return max(floor, p.peak, p.prev)
}

// poolOf returns the loop's pool for k.
func (fl *fastLoop) poolOf(k poolKey) *upPool {
	p := fl.pools[k]
	if p == nil {
		p = &upPool{key: k}
		fl.pools[k] = p
	}
	return p
}

// upstream idle timeout (the slow path's Transport.IdleConnTimeout).
const upIdleTimeout = 90 * time.Second

type uconn struct {
	fl       *fastLoop
	fd       int
	reg      ngx.Reg
	timer    ngx.Timer
	key      string  // the server address (target)
	pool     poolKey // its idle pool
	state    int
	reused   bool
	x        *fastExchange // the request it serves; nil: idle, or its request went away
	readable bool
	writable bool
	rdhup    bool // the backend's FIN (or an error) was reported
	paused   bool

	prev, next *uconn // idle list

	out      []byte // request head bytes not yet written (a slice of the request's upReq)
	pend     []byte // request body bytes the backend has not taken yet
	in       []byte // response bytes buffered (an incomplete head)
	framing  int
	remain   int64
	chunk    chunkReader
	rechunk  bool
	gotByte  bool   // any response byte arrived for the current request
	keep     bool   // reusable after this response
	head     []byte // the client's response head, sent with the first body bytes
	sniff    bool   // head lacks Content-Type: add one sniffed from the first body bytes
	isHeadRq bool
	connTO   time.Duration
	scanned  int // bytes at the front of u.in searched for the end of a head
	// job: a response head past the loop's limits is being parsed off the
	// loop. Nothing is read from the backend until bigDone.
	job *bigHead
	// respBy: the loop time by which the response head is due (the
	// backend's response_header limit), 0 when none runs.
	respBy int64
	// later: the connection gave way in the middle of a relay (relayRound)
	// and is queued to go on.
	queued  bool
	laterFn func()
	// tls is set on a connection to a backend_tls backend.
	tls *upTLS
	// up counts the connection among the ones in use (its pool's, or its
	// client connection's own), from the request it is taken or opened for
	// until it is idle again or closed; nil otherwise.
	up *usePeak
	// own is set on a connection that began with one client's PROXY header
	// (send_proxy_v2): it serves that client's connection only and waits,
	// idle, there and not in the loop's pools. hdr is what of the header
	// the socket has not taken yet (a plain backend; a backend_tls one gets
	// it from the goroutine that dials).
	own *ownConns
	hdr []byte
}

func (fl *fastLoop) takeIdle(k poolKey) *uconn {
	p := fl.pools[k]
	if p == nil || p.head == nil {
		return nil
	}
	u := p.head
	p.head = u.next
	if p.head != nil {
		p.head.prev = nil
	}
	u.next, u.prev = nil, nil
	p.n--
	u.reused = true
	fl.l.Stop(&u.timer)
	return u
}

func (fl *fastLoop) putIdle(u *uconn) {
	if u.up != nil {
		u.up.inUse-- // it served its request
		u.up = nil
	}
	if o := u.own; o != nil {
		o.put(u, fl.l.Now())
		return
	}
	p := fl.poolOf(u.pool)
	if p.n >= p.keep(fl.l.Now(), fl.minIdlePerTarget()) {
		u.close()
		return
	}
	u.state = usIdle
	u.x = nil
	u.paused = false
	u.prev = nil
	u.next = p.head
	if p.head != nil {
		p.head.prev = u
	}
	p.head = u
	p.n++
	fl.l.Arm(&u.timer, upIdleTimeout)
	if u.readable {
		u.OnEvent(ngx.EvIn) // something arrived meanwhile: check it
	}
}

func (fl *fastLoop) unlinkIdle(u *uconn) {
	if o := u.own; o != nil {
		o.remove(u)
		return
	}
	p := fl.pools[u.pool]
	if p == nil {
		return
	}
	if u.prev != nil {
		u.prev.next = u.next
	} else if p.head == u {
		p.head = u.next
	} else {
		return
	}
	if u.next != nil {
		u.next.prev = u.prev
	}
	u.prev, u.next = nil, nil
	p.n--
}

// dial opens a connection to target ("ip:port", or "host:port" whose name
// is looked up off the loop, as the transport's dialer does per dial). The
// connect timeout covers the lookup and the connect.
func (fl *fastLoop) dial(k poolKey, connectTO time.Duration) (*uconn, error) {
	target := k.target
	u := &uconn{fl: fl, fd: -1, key: target, pool: k, connTO: connectTO}
	u.timer.F = u
	sa, ok := fl.addrs[target]
	if !ok {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: err}
		}
		ip, ipErr := netip.ParseAddr(host)
		pn, perr := strconvPort(port)
		if ipErr != nil || perr != nil || ip.Zone() != "" {
			// A host name (or a named port): resolve in the background.
			u.state = usResolving
			if connectTO > 0 {
				fl.l.Arm(&u.timer, connectTO)
			}
			l := fl.l
			go func() {
				sa, err := resolveSockaddr(target)
				l.Post(func() { u.resolved(sa, err) })
			}()
			return u, nil
		}
		sa = sockaddrOf(ip, pn)
		if len(fl.addrs) > 4096 {
			clear(fl.addrs)
		}
		fl.addrs[target] = sa
	}
	if err := u.connectTo(sa); err != nil {
		return nil, err
	}
	return u, nil
}

// ---- TLS to a backend (backend_tls) ----

// upTLS is the TLS state of a connection to a backend_tls backend. As on
// the client side (fastTLS), crypto/tls keeps the record layer over an
// in-memory transport: the loop feeds it what it reads from the socket and
// writes out what it produces.
type upTLS struct {
	tc  *tls.Conn
	tt  *tlsTransport
	out []byte // ciphertext the socket has not taken yet
}

// backendTLSHandshakeTimeout is the net/http path's (its Transport's
// TLSHandshakeTimeout). A variable for the tests only.
var backendTLSHandshakeTimeout = 10 * time.Second

// errTLSHandshakeTimeout has the text of net/http's error.
var errTLSHandshakeTimeout = timeoutError("net/http: TLS handshake timeout")

// dialTLS opens a connection to a backend_tls server: the connect (under
// the connect timeout) and the TLS handshake (10 s) run on a goroutine, on
// the Go runtime's poller, as the client side's handshakes do; the socket
// then moves to the loop. A failure of either is a connect failure.
func (fl *fastLoop) dialTLS(k poolKey, connectTO time.Duration, proxyHdr []byte) *uconn {
	u := &uconn{fl: fl, fd: -1, key: k.target, pool: k, connTO: connectTO, state: usDialTLS}
	u.timer.F = u
	cfg := k.tls
	if cfg.ServerName == "" {
		// The name sent and checked is the server address's host, as
		// net/http's Transport takes it.
		host := k.target
		if h, _, err := net.SplitHostPort(k.target); err == nil {
			host = h
		}
		cfg = cfg.Clone()
		cfg.ServerName = host
	}
	l := fl.l
	target := k.target
	go func() {
		t, fd, err := tlsDial(target, connectTO, cfg, proxyHdr)
		l.Post(func() { u.tlsDialed(t, fd, err) })
	}()
	return u
}

// tlsDial connects to target and completes the TLS handshake (blocking: on
// a goroutine). It returns the TLS state in memory mode and the socket's
// descriptor, to be registered on a loop. proxyHdr, the PROXY header of a
// send_proxy_v2 backend's connection, goes out before the handshake.
func tlsDial(target string, connectTO time.Duration, cfg *tls.Config, proxyHdr []byte) (*upTLS, int, error) {
	d := net.Dialer{Timeout: connectTO}
	c, err := d.Dial("tcp", target)
	if err != nil {
		return nil, -1, err
	}
	tt := &tlsTransport{nc: c, local: c.LocalAddr(), remote: c.RemoteAddr()}
	tc := tls.Client(tt, cfg)
	c.SetDeadline(time.Now().Add(backendTLSHandshakeTimeout))
	if len(proxyHdr) > 0 {
		if _, err := c.Write(proxyHdr); err != nil {
			c.Close()
			return nil, -1, err
		}
	}
	if err := tc.HandshakeContext(context.Background()); err != nil {
		c.Close()
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			err = errTLSHandshakeTimeout
		}
		return nil, -1, err
	}
	c.SetDeadline(time.Time{})
	fd, err := dupConnFD(c)
	if err != nil {
		c.Close()
		return nil, -1, err
	}
	// The socket lives on as fd; the runtime's descriptor is closed (which
	// also takes it out of the runtime's poller).
	tt.nc = nil
	c.Close()
	return &upTLS{tc: tc, tt: tt}, fd, nil
}

// tlsDialed puts a connection dialTLS opened on the loop and sends the
// waiting request on it.
func (u *uconn) tlsDialed(t *upTLS, fd int, err error) {
	defer u.recoverPanic()
	if u.state != usDialTLS {
		if fd >= 0 {
			unix.Close(fd) // abandoned meanwhile (the client left)
		}
		return
	}
	x := u.x
	if err == nil {
		setSockOpts(fd, 30)
		reg, rerr := u.fl.l.Register(fd, u)
		if rerr != nil {
			unix.Close(fd)
			err = dialError(u.key, rerr)
		} else {
			u.fd, u.reg, u.tls = fd, reg, t
			t.tt.owner = u
		}
	}
	if err != nil || x == nil {
		u.x = nil
		u.close()
		if x != nil {
			x.attemptFailed(err, false, false)
		}
		return
	}
	u.state = usSending
	u.writable, u.readable = true, true // what the handshake read past its end is in the transport
	u.sendRequest()
}

// tlsOut takes ciphertext the tls.Conn writes (tlsTransport).
func (u *uconn) tlsOut(p []byte) {
	if u.tls != nil {
		appendBuf(&u.tls.out, p)
	}
}

// flushTLS writes the ciphertext waiting for the socket; EAGAIN when the
// socket does not take all of it.
func (u *uconn) flushTLS() syscall.Errno {
	t := u.tls
	for len(t.out) > 0 {
		n, errno := ngx.Write(u.fd, t.out)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			if errno != unix.EAGAIN {
				releaseBuf(&t.out)
			}
			return errno
		}
		rest := copy(t.out, t.out[n:])
		t.out = t.out[:rest]
	}
	releaseBuf(&t.out)
	return 0
}

// write writes p to the backend: all of it or, when the socket is not
// taking (EAGAIN), none. Over TLS, p is encrypted whole once the earlier
// ciphertext is out; what the socket then leaves waits in the connection
// (at most one write's worth), so the callers' back-pressure holds.
func (u *uconn) write(p []byte) (int, syscall.Errno) {
	t := u.tls
	if t == nil {
		return ngx.Write(u.fd, p)
	}
	if errno := u.flushTLS(); errno != 0 {
		return 0, errno
	}
	if _, err := t.tc.Write(p); err != nil {
		return 0, unix.EPIPE
	}
	if errno := u.flushTLS(); errno != 0 && errno != unix.EAGAIN {
		return 0, errno
	}
	return len(p), 0
}

// readTLS reads plaintext from a TLS backend into p: what the connection
// holds decrypted, then what it can decrypt from the socket.
func (u *uconn) readTLS(p []byte) (int, bool, error) {
	t := u.tls
	tt := t.tt
	for {
		n, err := t.tc.Read(p)
		if len(t.out) > 0 {
			// A post-handshake message was answered (KeyUpdate).
			if errno := u.flushTLS(); errno != 0 && errno != unix.EAGAIN {
				return 0, false, os.NewSyscallError("write", errno)
			}
		}
		if n > 0 {
			return n, false, nil
		}
		switch {
		case err == nil:
			continue
		case err == errWouldBlock:
		case errors.Is(err, io.EOF):
			return 0, true, nil
		default:
			return 0, false, err
		}
		// More ciphertext is needed.
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
		m, errno := ngx.Read(u.fd, free)
		switch {
		case errno == unix.EAGAIN:
			u.readable = false
			if len(tt.in) == 0 {
				releaseBuf(&tt.in)
			}
			return 0, false, nil
		case errno == unix.EINTR:
			continue
		case errno != 0:
			return 0, false, os.NewSyscallError("read", errno)
		case m == 0:
			tt.eof = true
			continue
		}
		tt.in = tt.in[:len(tt.in)+m]
	}
}

// isGRPC reports whether a request's Content-Type is gRPC's (not gRPC-Web,
// which is plain HTTP).
func isGRPC(ct string) bool {
	const p = "application/grpc"
	if len(ct) < len(p) || !strings.EqualFold(ct[:len(p)], p) {
		return false
	}
	rest := ct[len(p):]
	return !(len(rest) >= 4 && strings.EqualFold(rest[:4], "-web"))
}

func strconvPort(p string) (int, error) {
	n := 0
	if p == "" || len(p) > 5 {
		return 0, errors.New("bad port")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return 0, errors.New("bad port")
		}
		n = n*10 + int(p[i]-'0')
	}
	if n > 65535 {
		return 0, errors.New("bad port")
	}
	return n, nil
}

func sockaddrOf(a netip.Addr, port int) unix.Sockaddr {
	if a.Is4() || a.Is4In6() {
		return &unix.SockaddrInet4{Port: port, Addr: a.Unmap().As4()}
	}
	return &unix.SockaddrInet6{Port: port, Addr: a.As16()}
}

// upSendBuffer, when set, is the send buffer of the sockets to backends. A
// variable for the tests only: with the kernel's own size (megabytes on a
// tuned host) a test cannot make a backend's socket fill up.
var upSendBuffer int

// connectTo starts the non-blocking connect.
func (u *uconn) connectTo(sa unix.Sockaddr) error {
	family := unix.AF_INET
	if _, ok := sa.(*unix.SockaddrInet6); ok {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("socket", err)}
	}
	setSockOpts(fd, 30)
	if upSendBuffer > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, upSendBuffer)
	}
	err = unix.Connect(fd, sa)
	state := usSending
	switch err {
	case nil:
	case unix.EINPROGRESS:
		state = usConnecting
	default:
		unix.Close(fd)
		return dialError(u.key, err)
	}
	reg, rerr := u.fl.l.Register(fd, u)
	if rerr != nil {
		unix.Close(fd)
		return dialError(u.key, rerr)
	}
	u.fd, u.reg = fd, reg
	if state == usConnecting && u.connTO > 0 && u.state != usResolving {
		u.fl.l.Arm(&u.timer, u.connTO)
	}
	u.state = state
	return nil
}

// resolved continues a dial once its host name is looked up.
func (u *uconn) resolved(sa unix.Sockaddr, err error) {
	defer u.recoverPanic()
	if u.state != usResolving {
		return // timed out or abandoned meanwhile
	}
	x := u.x
	if err == nil {
		err = u.connectTo(sa)
	}
	if err != nil {
		u.x = nil
		u.close()
		if x != nil {
			x.attemptFailed(err, false, false)
		}
		return
	}
	if u.state == usSending {
		u.fl.l.Stop(&u.timer)
		if x != nil {
			u.sendRequest()
		}
	}
}

func dialError(target string, err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Addr: fakeAddr(target), Err: os.NewSyscallError("connect", err)}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// resolveSockaddr resolves target ("host:port") to a socket address.
func resolveSockaddr(target string) (unix.Sockaddr, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: err}
	}
	pn, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: err}
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return sockaddrOf(ip, pn), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errors.New("no addresses")
		}
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: err}
	}
	return sockaddrOf(ips[0], pn), nil
}

func (u *uconn) OnEvent(ev uint32) {
	if u.state == usClosed {
		return
	}
	defer u.recoverPanic()
	if ev&(ngx.EvErr|ngx.EvHup) != 0 {
		u.readable, u.writable, u.rdhup = true, true, true
	}
	if ev&ngx.EvRDHUP != 0 {
		u.rdhup = true
	}
	if ev&ngx.EvOut != 0 {
		u.writable = true
		if u.tls != nil && len(u.tls.out) > 0 && u.flushTLS() == unix.EAGAIN {
			u.writable = false
			return
		}
		switch u.state {
		case usConnecting:
			u.connected()
		case usSending:
			u.sendRequest()
		}
		if u.state == usClosed {
			return
		}
	}
	if ev&(ngx.EvIn|ngx.EvRDHUP) != 0 {
		u.readable = true
	}
	if u.readable {
		u.onReadable()
	}
}

func (u *uconn) connected() {
	errno, err := unix.GetsockoptInt(u.fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err == nil && errno != 0 {
		err = syscall.Errno(errno)
	}
	x := u.x
	if err != nil {
		u.close()
		if x != nil {
			x.attemptFailed(dialError(u.key, err), false, false)
		}
		return
	}
	u.fl.l.Stop(&u.timer)
	u.state = usSending
	if x != nil {
		u.sendRequest()
	}
}

// sendRequest writes the client's request (or the rest of it).
func (u *uconn) sendRequest() {
	x := u.x
	if x == nil {
		u.close()
		return
	}
	r := &x.fastReq
	if u.state != usSending {
		u.state = usSending
		u.out = r.sendBytes()
		u.gotByte = false
		u.in = u.in[:0]
		u.scanned = 0
		u.respBy = 0
		u.isHeadRq = r.isHead // an early response is framed by it
	}
	if len(u.out) == 0 && !r.sent {
		u.out = r.sendBytes()
	}
	// A new connection to a send_proxy_v2 backend: its PROXY header first.
	for len(u.hdr) > 0 {
		n, errno := ngx.Write(u.fd, u.hdr)
		if errno == unix.EAGAIN {
			u.writable = false
			return
		}
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			u.failBeforeHead(os.NewSyscallError("write", errno))
			return
		}
		u.hdr = u.hdr[n:]
	}
	for len(u.out) > 0 {
		n, errno := u.write(u.out)
		if errno == unix.EAGAIN {
			u.writable = false
			return
		}
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			u.failBeforeHead(os.NewSyscallError("write", errno))
			return
		}
		u.out = u.out[n:]
	}
	r.sent = true
	if r.bodyLeft > 0 || len(u.pend) > 0 {
		if !x.d.pumpBody(u) {
			return // waiting for the client or the backend, or failed
		}
	}
	u.state = usWaitHead
	u.isHeadRq = r.isHead
	if r.respHeader > 0 && u.job == nil { // a head that is here already waits for no backend
		u.respBy = u.fl.l.Now() + int64(r.respHeader)
		u.fl.l.Arm(&u.timer, r.respHeader)
	}
	if u.readable {
		u.onReadable()
	}
}

// pumpBody sends the request body: what the backend has not taken yet,
// what the client already sent, then what it sends next — never faster than
// the backend takes it. It returns true once all of it is out, false while
// it waits for the client or the backend (or after a failure, which it
// answers).
func (c *fconn) pumpBody(u *uconn) bool {
	r := &c.x.fastReq
	if u.job != nil {
		// The backend answered and its head is being parsed off the
		// loop: what becomes of the body is decided when it is back
		// (bigDone). Until then nothing is read from the client, and its
		// read limit does not run.
		c.l.Stop(&c.timer)
		return false
	}
	moved := 0
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
			rest := copy(u.pend, u.pend[n:])
			u.pend = u.pend[:rest]
		}
		releaseBuf(&u.pend)
		if r.bodyLeft == 0 {
			c.l.Stop(&c.timer) // the read limit
			return true
		}
		if len(c.pending) > 0 {
			// The client is not taking its output: like net/http, whose
			// handler is blocked in the write, read nothing more from it
			// (flush goes on with the body). The write limit times it.
			c.l.Stop(&c.timer)
			c.outPending()
			return false
		}
		var chunk []byte
		fromIn := len(c.in) > 0
		if fromIn {
			chunk = c.in[:min(int64(len(c.in)), r.bodyLeft)]
		} else {
			buf := c.l.Scratch
			if int64(len(buf)) > r.bodyLeft {
				buf = buf[:r.bodyLeft]
			}
			n, eof, err := c.recv(buf)
			if n == 0 {
				if eof || err != nil {
					// The client's body broke off: net/http's body read
					// fails, and the request is answered 400.
					c.bodyFailed(http.StatusBadRequest)
					return false
				}
				// Waiting for the client's next body bytes: the read limit
				// runs from the start of the wait (stall.go sets its
				// deadline around each body read).
				if r.readLimit > 0 && !c.timer.Armed() {
					c.l.Arm(&c.timer, r.readLimit)
				}
				return false
			}
			chunk = buf[:n]
		}
		// Body bytes are here: the client is not stalling. Waits on the
		// backend (u.pend) are not limited by the read limit.
		c.l.Stop(&c.timer)
		r.bodyTouched = true
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
		r.bodyLeft -= int64(len(chunk))
		if fromIn {
			rest := copy(c.in, c.in[len(chunk):])
			c.in = c.in[:rest]
			if rest == 0 {
				releaseBuf(&c.in)
			}
		}
		if moved += len(chunk); moved >= relayRound && r.bodyLeft > 0 && len(u.pend) == 0 {
			// A fast client with a fast backend: give way to the loop's
			// other connections, then go on.
			c.laterBody()
			return false
		}
	}
}

// laterBody goes on with the request body from the loop's task queue,
// after the events that are waiting.
func (c *fconn) laterBody() {
	if c.bodyQueued {
		return
	}
	c.bodyQueued = true
	if c.bodyFn == nil {
		c.bodyFn = func() {
			defer c.recoverPanic()
			c.bodyQueued = false
			if u := c.x.u; c.state == csProxy && u != nil && c.x.bodyLeft > 0 && u.state == usSending && c.x.sent {
				if c.pumpBody(u) {
					u.bodySent()
				}
			}
		}
	}
	c.l.Post(c.bodyFn)
}

// bodySent: the body is out (pumped from a client event); wait for the
// response.
func (u *uconn) bodySent() {
	x := u.x
	if x == nil || u.state != usSending {
		return
	}
	u.state = usWaitHead
	u.isHeadRq = x.isHead
	if x.respHeader > 0 && u.job == nil {
		u.respBy = u.fl.l.Now() + int64(x.respHeader)
		u.fl.l.Arm(&u.timer, x.respHeader)
	}
	if u.readable {
		u.onReadable()
	}
}

// failBody: writing the body to the backend failed. A response it sent
// meanwhile (a refusal of the body, say) is relayed; otherwise the attempt
// failed after the request was sent (502, not replayed).
func (u *uconn) failBody(err error) {
	x := u.x
	if x == nil {
		u.close()
		return
	}
	u.readable = true // read what the backend sent before it stopped
	releaseBuf(&u.pend)
	x.bodyLeft = 0
	x.d.mustClose()
	x.d.stopBodyTimer() // the body's read limit
	u.readHead()
	if u.state == usSending && u.x == x && u.job == nil {
		// No response came: the attempt failed.
		u.x = nil
		u.close()
		x.attemptFailed(err, false, false)
	}
}

// bodyFailed answers a request whose body could not be read from the client
// (it stalled, or broke off) with code, and ends the attempt without an
// outcome for the backend.
func (c *fconn) bodyFailed(code int) {
	r := &c.x.fastReq
	if u := r.u; u != nil {
		u.x = nil
		u.close()
	}
	c.x.endAttempt()
	c.closeAfter = true
	c.sendError(code)
}

// failBeforeHead: the attempt failed before any response head. A request
// on a reused connection that never got a byte back is retried on a fresh
// connection first, as Go's transport does.
func (u *uconn) failBeforeHead(err error) {
	x := u.x
	reused, gotByte := u.reused, u.gotByte
	u.x = nil
	u.close()
	if x == nil {
		return
	}
	r := &x.fastReq
	if reused && !gotByte && x.transportRetryable() && r.replays < 32 {
		r.replays++
		r.sent = false
		x.connectUpstream(r.replays > 4)
		return
	}
	x.attemptFailed(err, false, false)
}

// transportRetryable is Go's transport rule for retrying a request on a
// new connection after a reused one failed: nothing was written, or the
// request is replayable (bodiless here) with a method that allows it.
func (x *fastExchange) transportRetryable() bool {
	r := &x.fastReq
	if r.hasBody {
		return false // net/http cannot replay a server request's body
	}
	if !r.sent {
		return true
	}
	switch string(r.method) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return r.idempotencyKey
}

func (u *uconn) onReadable() {
	switch u.state {
	case usIdle:
		// An idle connection got data or its end: it cannot be reused.
		var b [64]byte
		if u.tls != nil {
			// What a TLS backend sends between requests (session tickets,
			// KeyUpdate) is its own business and is taken; anything for
			// us, or the end, closes the connection.
			if n, eof, err := u.readTLS(b[:]); n == 0 && !eof && err == nil {
				return
			}
			u.fl.unlinkIdle(u)
			u.close()
			return
		}
		n, errno := ngx.Read(u.fd, b[:])
		if errno == unix.EAGAIN {
			u.readable = false
			return
		}
		_ = n
		u.fl.unlinkIdle(u)
		u.close()
	case usWaitHead:
		u.readHead()
	case usBody:
		u.readBody()
	case usSending:
		// The backend answers while the body is still going out (it
		// refuses it, say): read its response.
		if x := u.x; x != nil && x.sent {
			u.readHead()
		}
	case usConnecting:
		// Data before the request was sent: wait (handled once sent).
	}
}

// read reads from the backend into p.
func (u *uconn) read(p []byte) (int, bool, error) {
	if u.tls != nil {
		return u.readTLS(p)
	}
	n, errno := ngx.Read(u.fd, p)
	switch {
	case errno == unix.EAGAIN:
		u.readable = false
		return 0, false, nil
	case errno == unix.EINTR:
		return 0, false, nil
	case errno != 0:
		return 0, false, os.NewSyscallError("read", errno)
	case n == 0:
		return 0, true, nil
	}
	if n < len(p) && !u.rdhup {
		u.readable = false
	}
	return n, false, nil
}

func (u *uconn) readHead() {
	got := 0
	for (u.state == usWaitHead || u.state == usSending && u.x != nil && u.x.sent) && u.readable && !u.paused && u.job == nil {
		x := u.x
		if x == nil {
			u.close()
			return
		}
		if got >= relayRound {
			u.later()
			return
		}
		var data []byte
		var n int
		var eof bool
		var err error
		if len(u.in) == 0 {
			n, eof, err = u.read(u.fl.l.Scratch)
			if n > 0 {
				data = u.fl.l.Scratch[:n]
			}
		} else {
			if cap(u.in)-len(u.in) < 4096 {
				nb := getBuf(min(max(2*cap(u.in), len(u.in)+64<<10), maxFastResponseHead+4096))
				nb = append(nb, u.in...)
				putBuf(u.in)
				u.in = nb
			}
			n, eof, err = u.read(u.in[len(u.in):cap(u.in)])
			if n > 0 {
				u.in = u.in[:len(u.in)+n]
				data = u.in
			}
		}
		if n == 0 {
			if eof {
				u.failBeforeHead(errors.New("EOF"))
			} else if err != nil {
				u.failBeforeHead(err)
			}
			return
		}
		u.gotByte = true
		got += n
		if !u.onHeadBytes(data) {
			return
		}
	}
	if u.state == usBody {
		// The rest of the body may already be in the socket: no new edge
		// announces it.
		u.paused = u.x != nil && u.x.d.backlog()
		u.readBody()
	}
}

// onHeadBytes parses a response head from data; false when the response
// moved on (or failed) and reading must stop here.
func (u *uconn) onHeadBytes(data []byte) bool {
	x := u.x
	h := &u.fl.resp
	for {
		scanned := 0
		if len(u.in) > 0 && &data[0] == &u.in[0] {
			scanned = u.scanned // this head's bytes already searched for its end
		}
		ok, err := parseResponseFrom(data, h, u.isHeadRq, scanned)
		if err == errRespBig {
			u.parseOffLoop(data) // bigDone goes on with it
			return false
		}
		if err != nil {
			u.x = nil
			u.close()
			x.attemptFailed(err, false, false)
			return false
		}
		if !ok {
			u.keepRest(data)
			u.scanned = len(u.in)
			if len(u.in) >= maxFastResponseHead {
				u.x = nil
				u.close()
				x.attemptFailed(respError("header too large"), false, false)
				return false
			}
			return true
		}
		rest, next, ret := u.headParsed(h, data, nil)
		if !next {
			return ret
		}
		data = rest
	}
}

// headParsed acts on the response head h, parsed from the front of data
// (on a goroutine, with its part of the client's head built, when pre is
// set). An informational response is passed on; next then says that the
// head after it is to be parsed from rest. Otherwise ret is what
// onHeadBytes returns: whether readHead goes on.
func (u *uconn) headParsed(h *respHead, data []byte, pre *bigHead) (rest []byte, next, ret bool) {
	panicProbe("response")
	x := u.x
	r := &x.fastReq
	if h.status >= 100 && h.status < 200 && h.status != http.StatusSwitchingProtocols {
		// An informational response (103 Early Hints): passed on.
		x.d.informational(h, pre)
		if u.x == nil || u.state == usClosed {
			return nil, false, false // the client went away
		}
		data = data[h.headLen:]
		if x.d.backlog() {
			// The client is not taking them: read on once it caught
			// up (net/http blocks writing the 1xx the same way).
			u.keepRest(data)
			u.paused = true
			return nil, false, false
		}
		if len(data) == 0 {
			u.in = u.in[:0]
			u.scanned = 0
			return nil, false, true
		}
		return data, true, false
	}
	u.fl.l.Stop(&u.timer)
	u.respBy = 0
	if h.status == http.StatusSwitchingProtocols {
		x.report(false)
		u.x = nil
		u.close()
		x.attemptFailed(errBadSwitch, true, false)
		return nil, false, false
	}
	canRetry := r.attempt+1 < r.policy.attempts
	if canRetry && r.policy.retriesStatus(h.status) && r.replayable(true) {
		x.report(false)
		retryStatus := h.status
		u.x = nil
		u.close()
		x.endAttempt()
		logging.Warn("[HTTP] Retry %d/%d for %s: %v", r.attempt+1, r.policy.attempts, logging.SanitizeLogField(bstr(r.path)), fmt.Errorf("status %d", retryStatus))
		r.excluded = append(r.excluded, r.target)
		r.attempt++
		x.attempt()
		return nil, false, false
	}
	x.report(true)
	u.keep = !h.connClose
	if u.state == usSending {
		// The request body is not all out: stop sending it. The backend
		// connection cannot carry another request, and the client's is
		// closed after the response (the rest of its body is unread).
		u.keep = false
		releaseBuf(&u.pend)
		r.bodyLeft = 0
		x.d.mustClose()
		x.d.stopBodyTimer() // the body's read limit: the body is not read any more
	}
	u.state = usBody
	body := data[h.headLen:]
	u.respond(h, body, pre)
	if len(u.in) > 0 && u.state != usBody {
		u.in = u.in[:0]
		u.scanned = 0
	}
	return nil, false, u.state == usBody // readHead goes on with the body
}

// ---- response heads past a loop's limits ----

// bigHead is a response head being parsed, and its part of the client's
// head built, on a goroutine: one past maxLoopResponseHead, or with more
// fields or Connection names than a loop's lists hold. net/http does this
// work on the request's goroutine; on a loop it would keep the loop's
// other connections waiting for as long as the backend's bytes make it
// last. The backend connection is parked meanwhile (uconn.job); bigDone
// goes on with the result, on the loop.
type bigHead struct {
	buf    []byte // its own: the head and what was read after it
	cfg    *fastSiteConfig
	parked int64 // loop time at which the connection was parked
	isHead bool
	rules  [2][]headerRule
	common []byte      // nvelox's own response fields (downstream.commonHead)
	proto  uint8       // the client's protocol: for HTTP/2 and HTTP/3 list is a header block
	gone   atomic.Bool // the connection was closed meanwhile: the result is not wanted

	// The result.
	h   respHead
	err error
	// list is, for an informational response, all of it as the client
	// gets it; otherwise the client's head up to its last header field
	// (startResponse ends it), with room to append that end.
	list                  []byte
	hasCT, hasCE, hasDate bool
}

// bigHeadSlots bounds the response heads parsed off the loops at a time:
// a 10 MiB head of very short fields takes hundreds of MiB while it is
// parsed. A site takes one slot at a time (fastSiteConfig.bigHeads), so
// another site's head waits for at most the head being parsed.
var bigHeadSlots = make(chan struct{}, max(1, min(2, runtime.GOMAXPROCS(0)/2)))

// parseOffLoop hands the response head at the front of data, which is past
// what the loop parses (errRespBig), to a goroutine.
func (u *uconn) parseOffLoop(data []byte) {
	x := u.x
	j := &bigHead{isHead: u.isHeadRq, rules: x.respRules, common: x.d.commonHead(), proto: x.d.proto()}
	if x.site != nil {
		j.cfg = x.site.fastConfig()
	}
	// The backend sent this whole head: the time it now spends here, in
	// nvelox's own work and its wait for a slot, is not counted against
	// the backend's response_header limit (504, passive health).
	j.parked = u.fl.l.Now()
	u.fl.l.Stop(&u.timer)
	if u.state == usSending {
		// The request body is still on its way: it rests until the head
		// is back (pumpBody), and the client's read limit with it.
		x.d.stopBodyTimer()
	}
	if len(u.in) > 0 && &data[0] == &u.in[0] {
		j.buf, u.in = u.in, nil // the buffered head itself
	} else {
		// The loop's scratch, or what followed an informational response.
		j.buf = append(getBuf(len(data)), data...)
		u.in = u.in[:0]
	}
	u.scanned = 0
	u.job = j
	l := u.fl.l
	go func() {
		if j.cfg != nil {
			j.cfg.bigHeads.Lock()
		}
		bigHeadSlots <- struct{}{}
		if !j.gone.Load() {
			j.run()
		}
		<-bigHeadSlots
		if j.cfg != nil {
			j.cfg.bigHeads.Unlock()
		}
		l.Post(func() { u.bigDone(j) })
	}()
}

// run parses the head and builds the client's from it (on a goroutine).
func (j *bigHead) run() {
	h := &j.h
	h.big = true
	ok, err := parseResponseFrom(j.buf, h, j.isHead, 0)
	if err == nil && !ok {
		err = respError("header too large") // not reached: the loop saw the head's end
	}
	if err != nil {
		j.err = err
		return
	}
	switch j.proto {
	case protoH3:
		j.buildH3()
		return
	case protoH2:
		j.buildH2()
		return
	}
	if h.status >= 100 && h.status < 200 && h.status != http.StatusSwitchingProtocols {
		j.list = appendInformational(make([]byte, 0, h.headLen+64), h)
		return
	}
	b := make([]byte, 0, h.headLen+h.headLen/2+len(j.common)+1024)
	b = append(b, statusLine(h.status)...)
	b = append(b, "X-Content-Type-Options: nosniff\r\n"...)
	b = append(b, j.common...)
	if len(j.rules[0]) == 0 && len(j.rules[1]) == 0 {
		// No header rules: the fields go out as they are listed, with
		// respFields' decisions, and without a second list of them (a
		// head of millions of fields would hold it twice).
		var fl respFlags
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
			b = append(b, hd.name...)
			b = append(b, ": "...)
			b = append(b, hd.value...)
			b = append(b, "\r\n"...)
		}
		j.hasCT, j.hasCE, j.hasDate = fl.hasCT, fl.hasCE, fl.hasDate
	} else {
		hs, hasCT, hasCE, hasDate := respFields(make([]outHeader, 0, len(h.headers)+8), h, j.isHead, &j.rules, false)
		j.hasCT, j.hasCE, j.hasDate = hasCT, hasCE, hasDate
		b = appendFields(b, hs)
	}
	if cap(b)-len(b) < 512 {
		// Room for the head's end (startResponse): no copy on the loop.
		b = append(make([]byte, 0, len(b)+512), b...)
	}
	j.list = b
}

// bigDone goes on, on the loop, with a response head parsed off it.
func (u *uconn) bigDone(j *bigHead) {
	defer u.recoverPanic()
	if u.job != j {
		return // the connection was closed meanwhile
	}
	u.job = nil
	x := u.x
	if x == nil {
		u.close() // not reached: a connection without a client has no job
		return
	}
	if j.err != nil {
		u.x = nil
		u.close()
		x.attemptFailed(j.err, false, false)
		return
	}
	// What follows the head in j.buf is used as bytes read into the loop's
	// scratch are: taken or copied before this returns.
	rest, next, ret := u.headParsed(&j.h, j.buf, j)
	if next {
		ret = u.onHeadBytes(rest)
	}
	putBuf(j.buf)
	if u.job == nil && u.state == usWaitHead && u.x == x && x.respHeader > 0 && !u.timer.Armed() {
		// Still waiting for a head (an informational response was passed
		// on): the response_header limit runs on, without the time the
		// head spent parked.
		now := u.fl.l.Now()
		if u.respBy == 0 {
			u.respBy = now + int64(x.respHeader)
		} else {
			u.respBy += now - j.parked
		}
		u.fl.l.ArmAt(&u.timer, u.respBy)
	}
	if u.job == nil && u.state == usSending && u.x == x && x.d.serving() && x.u == u && x.sent && (x.bodyLeft > 0 || len(u.pend) > 0) {
		// An informational response came while the request body was
		// still going out: the body goes on.
		if x.d.pumpBody(u) {
			u.bodySent()
		}
	}
	if ret {
		u.readHead()
	}
}

// keepRest leaves exactly data, the unparsed rest of what was read, in u.in
// (moved to its front: what came before was parsed and must not be parsed
// again). data is u.in's tail, or the loop's scratch when u.in is empty.
func (u *uconn) keepRest(data []byte) {
	if len(data) > 0 && len(u.in) > 0 && &data[0] == &u.in[0] {
		return // already at the front
	}
	u.scanned = 0
	if len(u.in) > 0 {
		u.in = u.in[:copy(u.in, data)]
	} else if len(data) > 0 {
		appendBuf(&u.in, data)
	}
}

// informational sends a 1xx response on to the client (downstream; pre:
// built off the loop).
func (c *fconn) informational(h *respHead, pre *bigHead) {
	if pre != nil {
		c.write2(pre.list, nil)
		return
	}
	b := appendInformational(c.fl.out[:0], h)
	c.fl.out = b[:0]
	c.write2(b, nil)
}

// appendInformational appends the 1xx response h as the client gets it.
func appendInformational(b []byte, h *respHead) []byte {
	b = append(b, statusLine(h.status)...)
	for i := range h.headers {
		hd := &h.headers[i]
		if hd.drop || hd.kind == hkContentLength {
			continue
		}
		b = append(b, hd.name...)
		b = append(b, ": "...)
		b = append(b, hd.value...)
		b = append(b, "\r\n"...)
	}
	return append(b, "\r\n"...)
}

// respFields lists the header fields of the client's response in hs (its
// scratch): the backend's, minus hop-by-hop (but the Trailer announcement
// of a chunked body, whose trailers are passed on), through the header
// rules.
func respFields(hs []outHeader, h *respHead, isHead bool, rules *[2][]headerRule, overH2 bool) (_ []outHeader, hasCT, hasCE, hasDate bool) {
	code := h.status
	bodyAllowed := !(code >= 100 && code < 200) && code != 204 && code != 304
	// net/http's ReverseProxy announces the trailers of a chunked response
	// also when the response has no body (HEAD, 204, 304).
	trailers := h.chunked
	for i := range h.headers {
		hd := &h.headers[i]
		if hd.drop && !(hd.kind == hkTrailer && trailers) {
			continue
		}
		hs = append(hs, outHeader{name: hd.name, value: hd.value})
	}
	hs = applyRules(hs, rules[0])
	hs = applyRules(hs, rules[1])
	fl := respFlags{h2: overH2}
	for i := range hs {
		if !hs[i].drop && !fl.out(headerKind(hs[i].name), hs[i].value, code, isHead, bodyAllowed) {
			hs[i].drop = true
		}
	}
	return hs, fl.hasCT, fl.hasCE, fl.hasDate
}

// respFlags is what the fields of the client's response say of it.
type respFlags struct {
	hasCT, hasCE, hasDate bool
	seenCE                bool
	// h2: the client speaks HTTP/2. Go's HTTP/2 server keeps two fields
	// its HTTP/1 server takes out: the Content-Type of a 304, and the
	// Content-Length of a response that has no body to frame with it.
	h2 bool
}

// out reports whether a field (of kind k) of the client's response is
// written, and notes what it says of the response.
func (f *respFlags) out(k uint8, value []byte, code int, isHead, bodyAllowed bool) bool {
	switch k {
	case hkContentType:
		if code == 304 && !f.h2 {
			return false
		}
		f.hasCT = true
	case hkContentEncoding:
		// net/http asks for the header's first value.
		if !f.seenCE {
			f.seenCE, f.hasCE = true, len(value) > 0
		}
	case hkDate:
		f.hasDate = true
	case hkContentLength:
		// The framing is the backend's real one, written by
		// startResponse; a HEAD response keeps its Content-Length as sent.
		if f.h2 {
			if !isHead && bodyAllowed {
				return false
			}
			_, ok := parseRespContentLength(value)
			return ok
		}
		return isHead && bodyAllowed && code != 304
	case hkTransferEncoding:
		return false
	}
	return true
}

// appendFields appends the header fields of hs that are not dropped.
func appendFields(b []byte, hs []outHeader) []byte {
	for i := range hs {
		if hs[i].drop {
			continue
		}
		b = append(b, hs[i].name...)
		b = append(b, ": "...)
		b = append(b, hs[i].value...)
		b = append(b, "\r\n"...)
	}
	return b
}

// respond starts the client's response to the request u serves: h is the
// backend's final head and body the bytes that came after it (pre: the head
// was parsed off the loop, and its part of the client's head is built).
func (u *uconn) respond(h *respHead, body []byte, pre *bigHead) {
	x := u.x
	code := h.status
	bodyAllowed := !(code >= 100 && code < 200) && code != 204 && code != 304
	noBody := h.framing == bodyNone || x.isHead || !bodyAllowed
	u.framing = h.framing
	u.remain = h.contentLength
	u.rechunk = !noBody && (h.framing == bodyChunked || h.framing == bodyClose)
	u.chunk.reset()
	if h.framing == bodyClose {
		u.keep = false
	}
	x.sentHead, x.status = true, code
	if noBody && len(body) > 0 {
		// A HEAD response's framing says nothing about what the backend
		// sends next: reuse the connection only when it sent nothing.
		u.keep = false
	}
	if !x.d.head(u, h, pre, noBody) {
		return
	}
	if noBody {
		u.endResponse()
		return
	}
	u.body(body)
}

// head builds the client's response head from the backend's (downstream):
// written at once when no body follows, else kept to go out with the first
// body bytes (data). pre: the head was parsed off the loop, and its part of
// the client's head is built. False when the connection failed.
func (c *fconn) head(u *uconn, h *respHead, pre *bigHead, noBody bool) bool {
	r := &c.x.fastReq
	code := h.status

	// The status line, nvelox's own fields, then the backend's through
	// the header rules: in the loop's scratch, or (pre) in a buffer of
	// the head's own, which never becomes the loop's scratch.
	var b []byte
	var hasCT, hasCE, hasDate bool
	if pre != nil {
		b, hasCT, hasCE, hasDate = pre.list, pre.hasCT, pre.hasCE, pre.hasDate
	} else {
		var hs []outHeader
		hs, hasCT, hasCE, hasDate = respFields(c.fl.hdrs[:0], h, r.isHead, &r.respRules, false)
		c.fl.hdrs = hs[:0]
		b = c.fl.out[:0]
		b = append(b, statusLine(code)...)
		b = append(b, "X-Content-Type-Options: nosniff\r\n"...)
		b = c.appendCommonHeaders(b)
		b = appendFields(b, hs)
	}
	if !noBody && h.framing == bodyLength {
		b = append(b, "Content-Length: "...)
		b = appendInt(b, h.contentLength)
		b = append(b, "\r\n"...)
	}
	if c.closeAfter {
		b = append(b, "Connection: close\r\n"...)
	}
	if u.rechunk {
		b = append(b, "Transfer-Encoding: chunked\r\n"...)
	}
	if !hasDate {
		b = append(b, "Date: "...)
		b = append(b, c.fl.date.get(c.l.Wall())...)
		b = append(b, "\r\n"...)
	}
	if noBody {
		b = append(b, "\r\n"...)
		if pre == nil {
			c.fl.out = b[:0]
		}
		return c.write2(b, nil)
	}
	// net/http sniffs a Content-Type from the first body bytes when the
	// response has none (and no Content-Encoding).
	u.sniff = !hasCT && !hasCE
	if u.sniff && h.framing != bodyLength {
		// A streamed body: net/http flushes the head before any body.
		u.sniff = false
	}
	if u.sniff && h.contentLength == 0 {
		u.sniff = false
	}
	switch {
	case pre != nil:
		// Its own buffer already: no copy of a large head on the loop.
		if !u.sniff {
			b = append(b, "\r\n"...)
		}
		u.head = b
	case u.sniff:
		u.head = append(getBuf(len(b)+64), b...)
		c.fl.out = b[:0]
	default:
		b = append(b, "\r\n"...)
		u.head = append(getBuf(len(b)), b...)
		c.fl.out = b[:0]
	}
	return true
}

// takeHead returns the response head to send with the body bytes p (nil
// once sent), completed with a sniffed Content-Type when needed.
func (u *uconn) takeHead(p []byte) []byte {
	if u.head == nil {
		return nil
	}
	if u.sniff {
		if len(p) == 0 {
			return nil // wait for the first body bytes
		}
		u.head = append(u.head, "Content-Type: "...)
		u.head = append(u.head, http.DetectContentType(p)...)
		u.head = append(u.head, "\r\n\r\n"...)
		u.sniff = false
	}
	h := u.head
	u.head = nil
	return h
}

// body relays body bytes of the response: it takes them out of the
// backend's framing and hands the data to the client's side.
func (u *uconn) body(p []byte) {
	x := u.x
	if x == nil {
		return
	}
	switch u.framing {
	case bodyLength:
		n := int64(len(p))
		if n > u.remain {
			n = u.remain
			u.keep = false // the backend sent more than its Content-Length
		}
		if !x.d.data(u, p[:n]) {
			return
		}
		x.bytes += n
		u.remain -= n
		if u.remain == 0 {
			u.endResponse()
		}
	case bodyClose:
		if !x.d.data(u, p) {
			return
		}
		x.bytes += int64(len(p))
	case bodyChunked:
		// The head goes out before the first chunk is looked at.
		if !x.d.data(u, nil) {
			return
		}
		// The data of this read goes out as one piece, however many
		// chunks the backend cut it into: one write per read, never one
		// per chunk (a backend sending a byte per chunk would otherwise
		// cost a system call per byte).
		var one []byte // the read's only run of data so far
		g := u.fl.gather[:0]
		runs := 0
		var bad error
		for len(p) > 0 {
			off, n, used, done, err := u.chunk.next(p)
			if err != nil {
				bad = err // what came before it still goes out, as net/http relays it
				break
			}
			if n > 0 {
				switch runs {
				case 0:
					one = p[off : off+n]
				case 1:
					g = append(append(g, one...), p[off:off+n]...)
				default:
					g = append(g, p[off:off+n]...)
				}
				runs++
			}
			p = p[used:]
			if done {
				break
			}
		}
		data := one
		if runs > 1 {
			data = g
		}
		if cap(g) <= 2*ngx.ScratchSize {
			u.fl.gather = g[:0] // the body bytes after a large head can be more: not kept
		}
		if len(data) > 0 {
			if !x.d.data(u, data) {
				return
			}
			x.bytes += int64(len(data))
		}
		if bad != nil {
			u.abortBody(bad)
			return
		}
		if u.chunk.state == ckDone {
			if len(p) > 0 {
				u.keep = false
			}
			u.endChunked()
		}
	}
}

// data writes body bytes of the response to the client, in the framing the
// client's head announced; with no bytes, a head that waits for nothing
// goes out (downstream). False when the connection failed.
func (c *fconn) data(u *uconn, p []byte) bool {
	switch u.framing {
	case bodyLength:
		head := u.takeHead(p)
		if len(head) == 0 && len(p) == 0 {
			return true
		}
		ok := c.write2(head, p)
		putBuf(head)
		return ok
	case bodyClose:
		// To the client a body without a length is chunked.
		head := u.takeHead(p)
		if len(p) == 0 {
			if len(head) == 0 {
				return true
			}
			ok := c.write2(head, nil)
			putBuf(head)
			return ok
		}
		b := u.fl.out[:0]
		if len(head) > maxLoopResponseHead {
			// A head built off the loop goes out by itself: the loop's
			// scratch never grows to the size of one.
			ok := c.write2(head, nil)
			putBuf(head)
			if !ok {
				return false
			}
		} else {
			b = append(b, head...)
			putBuf(head)
		}
		b = appendChunkHeader(b, len(p))
		u.fl.out = b[:0]
		return c.write3(b, p, crlf)
	default: // bodyChunked
		if head := u.takeHead(p); len(head) > 0 {
			ok := c.write2(head, nil)
			putBuf(head)
			if !ok {
				return false
			}
		}
		if len(p) == 0 {
			return true
		}
		hdr := appendChunkHeader(u.fl.out[:0], len(p))
		u.fl.out = hdr[:0]
		return c.write3(hdr, p, crlf)
	}
}

// end ends a body that had no length, with the trailer lines of a chunked
// one (downstream): the last chunk.
func (c *fconn) end(u *uconn, trailers []byte) bool {
	b := append(u.fl.out[:0], "0\r\n"...)
	b = append(b, trailers...)
	b = append(b, "\r\n"...)
	u.fl.out = b[:0]
	return c.write2(b, nil)
}

var crlf = []byte("\r\n")

// write3 writes a, b, then c to the client.
func (c *fconn) write3(a, b, d []byte) bool {
	if c.state == csClosed {
		return false
	}
	if c.tls != nil {
		return c.writeTLS(a, b, d)
	}
	if len(c.pending) > 0 {
		appendBuf(&c.pending, a)
		appendBuf(&c.pending, b)
		appendBuf(&c.pending, d)
		return true
	}
	iov := c.l.Iov[:3]
	ngx.SetIov(&iov[0], a)
	ngx.SetIov(&iov[1], b)
	ngx.SetIov(&iov[2], d)
	parts := iov
	if len(a) == 0 {
		parts = iov[1:]
	}
	n, errno := ngx.Writev(c.fd, parts)
	iov[0].Base, iov[1].Base, iov[2].Base = nil, nil, nil
	if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR {
		c.writeFailed()
		return false
	}
	total := len(a) + len(b) + len(d)
	if n < total {
		for _, part := range [][]byte{a, b, d} {
			if n >= len(part) {
				n -= len(part)
				continue
			}
			appendBuf(&c.pending, part[n:])
			n = 0
		}
		c.writable = false
		c.outPending()
	}
	return true
}

// endChunked ends a chunked response: its end and the trailers.
func (u *uconn) endChunked() {
	x := u.x
	var trailers []byte
	if t, ok := u.chunk.trailerLines(); ok {
		trailers = t
	}
	if !x.d.end(u, trailers) {
		return
	}
	u.endResponse()
}

// readBody reads the response body from the backend while the client keeps
// up.
func (u *uconn) readBody() {
	got := 0
	for u.state == usBody && u.readable && !u.paused {
		x := u.x
		if x == nil {
			u.close()
			return
		}
		if x.d.backlog() {
			u.paused = true
			return
		}
		if got >= relayRound {
			u.later()
			return
		}
		n, eof, err := u.read(u.fl.l.Scratch)
		got += n
		if n == 0 {
			switch {
			case eof && u.framing == bodyClose:
				u.keep = false
				if x.d.end(u, nil) {
					u.endResponse()
				}
			case eof:
				u.abortBody(errors.New("unexpected EOF"))
			case err != nil:
				u.abortBody(err)
			}
			return
		}
		u.body(u.fl.l.Scratch[:n])
		if u.state == usBody && u.x != nil && u.x.d.backlog() {
			u.paused = true
		}
	}
	if u.state == usBody && !u.paused && u.x != nil {
		if r := &u.x.fastReq; r.silence > 0 {
			u.fl.l.Arm(&u.timer, r.silence)
		}
	}
}

// relayRound is how much one connection reads in one go before it gives
// way to the loop's other connections. A backend that always has more to
// read (a fast one, or one that sends its body in very small chunks) would
// otherwise keep its loop for as long as it likes.
const relayRound = 256 << 10

// later goes on reading this connection from the loop's task queue, after
// the events that are waiting.
func (u *uconn) later() {
	if u.queued {
		return
	}
	u.queued = true
	if u.laterFn == nil {
		u.laterFn = func() {
			defer u.recoverPanic()
			u.queued = false
			if u.state != usClosed && u.readable {
				u.onReadable()
			}
		}
	}
	u.fl.l.Post(u.laterFn)
}

// resume continues reading the response after the client caught up.
func (u *uconn) resume() {
	if !u.paused || u.job != nil {
		return
	}
	u.paused = false
	switch u.state {
	case usBody:
		if u.readable {
			u.readBody()
		} else if x := u.x; x != nil && x.silence > 0 {
			u.fl.l.Arm(&u.timer, x.silence)
		}
	case usWaitHead, usSending:
		// Informational responses were waiting for the client: parse
		// what is buffered, then read on.
		if u.x == nil {
			return
		}
		if len(u.in) > 0 && !u.onHeadBytes(u.in) {
			return
		}
		if u.state == usBody {
			u.paused = u.x != nil && u.x.d.backlog()
			u.readBody()
			return
		}
		u.readHead()
	}
}

// abortBody: the backend failed mid-body. The client cannot be told; its
// connection is closed (net/http aborts the handler the same way).
func (u *uconn) abortBody(err error) {
	x := u.x
	u.x = nil
	u.close()
	if x == nil {
		return
	}
	// The line net/http's ReverseProxy writes (with Go's standard logger,
	// on stderr) when a response body breaks off.
	log.Printf("httputil: ReverseProxy read error during body copy: %v", err)
	x.endAttempt()
	x.d.abort(0)
}

// endResponse: the backend's response is complete.
func (u *uconn) endResponse() {
	x := u.x
	u.fl.l.Stop(&u.timer)
	u.x = nil
	if u.keep && u.state != usClosed && !u.rdhup {
		u.reused = false
		u.in = u.in[:0]
		u.scanned = 0
		releaseBuf(&u.in)
		u.fl.putIdle(u)
	} else {
		u.close()
	}
	if x != nil {
		x.endAttempt()
		x.d.finish()
	}
}

// OnTimer: connect, response-header, silence or idle timeout.
func (u *uconn) OnTimer() {
	defer u.recoverPanic()
	x := u.x
	switch u.state {
	case usIdle:
		u.fl.unlinkIdle(u)
		u.close()
	case usConnecting, usResolving:
		u.x = nil
		u.close()
		if x != nil {
			x.attemptFailed(&net.OpError{Op: "dial", Net: "tcp", Addr: fakeAddr(u.key), Err: errDialTimeout}, false, false)
		}
	case usWaitHead, usSending:
		u.x = nil
		u.close()
		if x != nil {
			x.attemptFailed(errTimeoutHeaders, false, true)
		}
	case usBody:
		if x != nil {
			u.abortBody(fmt.Errorf("backend server %s sent nothing for %v (its timeouts.read)", u.key, x.silence))
		}
	}
}

var (
	errDialTimeout    = timeoutError("i/o timeout")
	errTimeoutHeaders = timeoutError("net/http: timeout awaiting response headers")
)

type timeoutError string

func (e timeoutError) Error() string   { return string(e) }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

func (u *uconn) close() {
	if u.state == usClosed {
		return
	}
	u.state = usClosed
	if u.up != nil {
		u.up.inUse--
		u.up = nil
	}
	u.fl.l.Stop(&u.timer)
	if t := u.tls; t != nil {
		if u.fd >= 0 {
			// close_notify, if the socket takes it now (the net/http path
			// says goodbye to a TLS backend too).
			_ = t.tc.CloseWrite()
			if len(t.out) > 0 {
				ngx.Write(u.fd, t.out)
			}
		}
		t.tt.owner = nil
		releaseBuf(&t.tt.in)
		releaseBuf(&t.out)
	}
	if u.fd >= 0 {
		u.fl.l.Unregister(u.fd, u.reg)
		unix.Close(u.fd)
		u.fd = -1
	}
	if u.job != nil {
		u.job.gone.Store(true) // bigDone drops its result
		u.job = nil
	}
	releaseBuf(&u.in)
	releaseBuf(&u.head)
	releaseBuf(&u.pend)
}

// ---- handoff to net/http ----

// handoffListener is the net.Listener the bind group's http.Server serves:
// it yields the connections the fast path hands over.
type handoffListener struct {
	addr   net.Addr
	mu     sync.Mutex
	q      []net.Conn
	ready  chan struct{}
	done   chan struct{}
	closed bool
}

func newHandoffListener(addr net.Addr) *handoffListener {
	return &handoffListener{addr: addr, ready: make(chan struct{}, 1), done: make(chan struct{})}
}

func (l *handoffListener) push(c net.Conn) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		c.Close()
		return
	}
	l.q = append(l.q, c)
	l.mu.Unlock()
	select {
	case l.ready <- struct{}{}:
	default:
	}
}

func (l *handoffListener) Accept() (net.Conn, error) {
	for {
		l.mu.Lock()
		if len(l.q) > 0 {
			c := l.q[0]
			l.q[0] = nil
			l.q = l.q[1:]
			l.mu.Unlock()
			return c, nil
		}
		closed := l.closed
		l.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		select {
		case <-l.ready:
		case <-l.done:
		}
	}
}

func (l *handoffListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.done)
	for _, c := range l.q {
		c.Close()
	}
	l.q = nil
	return nil
}

func (l *handoffListener) Addr() net.Addr { return l.addr }

// prefixConn replays the bytes the fast path read before handing the
// connection over.
type prefixConn struct {
	net.Conn
	prefix []byte
	// remote is the client a trusted relay's PROXY header named (nil: the
	// connection's own peer).
	remote *net.TCPAddr
}

func (c *prefixConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// CloseWrite lets net/http half-close the connection before closing it.
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
