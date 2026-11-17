//go:build linux

package httpproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"

	"nvelox/core/logging"
	"nvelox/proxy"
)

// HTTPS on the fast path. The TLS handshake runs as net/http runs it: in a
// goroutine per connection, on the Go runtime's poller, with the same
// timeout and the same answer to a plaintext request. A connection that
// negotiates HTTP/2, or reaches a bind group with a client-certificate site,
// then goes to the group's net/http server as the *tls.Conn it is. An
// HTTP/1.1 connection moves to an event loop: crypto/tls keeps its record
// layer and state, over an in-memory transport the loop fills with what it
// reads from the socket and drains into the socket.

// fastTLS is the TLS state of a fast-path connection.
type fastTLS struct {
	tc   *tls.Conn
	tt   *tlsTransport
	more bool // tc may hold decrypted data not read yet
}

// tlsTransport is the net.Conn under a fast-path tls.Conn: blocking on nc
// during the handshake and after a handoff, in memory in between.
type tlsTransport struct {
	nc            net.Conn // the blocking transport, nil while on a loop
	owner         tlsOwner // the loop's connection (memory mode)
	in            []byte   // ciphertext read from the socket, from off on not consumed yet
	off           int
	eof           bool
	local, remote net.Addr
}

// tlsOwner is the loop's connection a transport in memory mode belongs to:
// a client's (fconn) or a backend's (uconn). It takes the ciphertext the
// tls.Conn writes.
type tlsOwner interface{ tlsOut(p []byte) }

// errWouldBlock: the in-memory transport has no ciphertext now. A temporary
// net.Error: crypto/tls keeps its state and the part of a record read so
// far, and the read is simply tried again later.
var errWouldBlock error = wouldBlock{}

type wouldBlock struct{}

func (wouldBlock) Error() string   { return "tls transport: no data yet" }
func (wouldBlock) Timeout() bool   { return false }
func (wouldBlock) Temporary() bool { return true }

func (t *tlsTransport) Read(p []byte) (int, error) {
	if t.off < len(t.in) {
		n := copy(p, t.in[t.off:])
		t.off += n
		if t.off == len(t.in) {
			t.in, t.off = t.in[:0], 0
		}
		return n, nil
	}
	if t.nc != nil {
		return t.nc.Read(p)
	}
	if t.eof {
		return 0, io.EOF
	}
	return 0, errWouldBlock
}

// Write: on a loop, ciphertext is appended to the connection's output;
// the loop writes it out.
func (t *tlsTransport) Write(p []byte) (int, error) {
	if t.nc != nil {
		return t.nc.Write(p)
	}
	if t.owner == nil {
		return 0, net.ErrClosed
	}
	t.owner.tlsOut(p)
	return len(p), nil
}

func (t *tlsTransport) Close() error {
	if t.nc != nil {
		return t.nc.Close()
	}
	return nil
}

func (t *tlsTransport) LocalAddr() net.Addr  { return t.local }
func (t *tlsTransport) RemoteAddr() net.Addr { return t.remote }

func (t *tlsTransport) SetDeadline(d time.Time) error {
	if t.nc != nil {
		return t.nc.SetDeadline(d)
	}
	return nil
}

func (t *tlsTransport) SetReadDeadline(d time.Time) error {
	if t.nc != nil {
		return t.nc.SetReadDeadline(d)
	}
	return nil
}

func (t *tlsTransport) SetWriteDeadline(d time.Time) error {
	if t.nc != nil {
		return t.nc.SetWriteDeadline(d)
	}
	return nil
}

// CloseWrite half-closes the blocking transport (after a handoff).
func (t *tlsTransport) CloseWrite() error {
	if cw, ok := t.nc.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// unread copies the ciphertext read from the socket and not consumed yet.
func (t *tlsTransport) unread() []byte {
	if t.off < len(t.in) {
		return append([]byte(nil), t.in[t.off:]...)
	}
	return nil
}

// toBlocking hands the transport to nc (a handoff, after the loop released
// its buffers): unread, the ciphertext already read from the socket but not
// consumed, is read first.
func (t *tlsTransport) toBlocking(nc net.Conn, unread []byte) {
	t.in, t.off = unread, 0
	t.owner = nil
	t.nc = nc
}

func (f *fastTLS) release() {
	if f.tt.nc == nil {
		releaseBuf(&f.tt.in)
		f.tt.off = 0
		f.tt.owner = nil
	}
}

// tlsOut takes ciphertext the tls.Conn writes: straight into the loop's
// output scratch while a write is being encrypted, else after what is
// already pending.
func (c *fconn) tlsOut(p []byte) {
	if c.fl.tlsDirect && len(c.pending) == 0 {
		c.fl.tlsBuf = append(c.fl.tlsBuf, p...)
		return
	}
	appendBuf(&c.pending, p)
	c.outPending()
}

// recvTLS reads plaintext into p: decrypting what the connection holds, and
// reading ciphertext from the socket when it needs more.
func (c *fconn) recvTLS(p []byte) (int, bool, error) {
	f := c.tls
	tt := f.tt
	for {
		c.fl.tlsDirect = false
		n, err := f.tc.Read(p)
		if c.state == csClosed {
			return 0, false, net.ErrClosed
		}
		if len(c.pending) > 0 && c.writable {
			// A post-handshake message (KeyUpdate) was answered.
			if !c.writePending() {
				return 0, false, net.ErrClosed
			}
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
		// Need more ciphertext. Not while output waits for the client:
		// net/http's blocking writes stop its reads the same way, so that
		// a peer sending KeyUpdates and reading nothing gets no further.
		if !c.readable || len(c.pending) > 0 {
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

// tlsBufKeep is the largest ciphertext scratch a loop keeps between
// writes: well above a response head of the loop's own size plus a read of
// body.
const tlsBufKeep = 512 << 10

// writeTLS encrypts a, b and d (in one record when they fit) and writes the
// ciphertext out.
func (c *fconn) writeTLS(a, b, d []byte) bool {
	f := c.tls
	fl := c.fl
	fl.tlsDirect = len(c.pending) == 0
	fl.tlsBuf = fl.tlsBuf[:0]
	var err error
	if n := len(a) + len(b) + len(d); n <= 16<<10 && (len(b) > 0 || len(d) > 0) {
		buf := append(fl.tlsPlain[:0], a...)
		buf = append(buf, b...)
		buf = append(buf, d...)
		fl.tlsPlain = buf[:0]
		_, err = f.tc.Write(buf)
	} else {
		for _, part := range [3][]byte{a, b, d} {
			if len(part) > 0 && err == nil {
				_, err = f.tc.Write(part)
			}
		}
	}
	fl.tlsDirect = false
	if err != nil {
		c.writeFailed()
		return false
	}
	if len(fl.tlsBuf) > 0 {
		out := fl.tlsBuf
		fl.tlsBuf = fl.tlsBuf[:0]
		if cap(out) > tlsBufKeep {
			fl.tlsBuf = nil // a very large write's (a head built off the loop): not kept
		}
		if len(c.pending) > 0 {
			appendBuf(&c.pending, out)
		} else {
			n, errno := ngx.Write(c.fd, out)
			if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR {
				c.writeFailed()
				return false
			}
			if n < len(out) {
				appendBuf(&c.pending, out[max(n, 0):])
			}
		}
	}
	if len(c.pending) > 0 {
		c.writable = false
		c.outPending()
	}
	return true
}

// tlsCloseNotify sends close_notify (best effort; the connection is
// closing).
func (c *fconn) tlsCloseNotify() {
	f := c.tls
	if f == nil || f.tt.owner == nil {
		return
	}
	c.fl.tlsDirect = false
	_ = f.tc.CloseWrite()
	for len(c.pending) > 0 {
		n, errno := ngx.Write(c.fd, c.pending)
		if errno != 0 || n <= 0 {
			break
		}
		rest := copy(c.pending, c.pending[n:])
		c.pending = c.pending[:rest]
	}
}

// tlsHandoffConn is a fast-path TLS connection handed to net/http in the
// middle of its life: plaintext, with the bytes already decrypted in front,
// and its TLS state for the requests (fastConnContext).
type tlsHandoffConn struct {
	prefixConn
	state *tls.ConnectionState
}

// CloseWrite: close_notify, then the TCP half-close.
func (c *tlsHandoffConn) CloseWrite() error {
	tc := c.prefixConn.Conn.(*tls.Conn)
	err := tc.CloseWrite()
	if cw, ok := tc.NetConn().(interface{ CloseWrite() error }); ok {
		if ferr := cw.CloseWrite(); err == nil {
			err = ferr
		}
	}
	return err
}

type fastTLSStateKey struct{}

// fastConnContext gives the requests of a handed-over TLS connection its
// TLS state (BindGroup.ServeHTTP sets r.TLS from it).
func fastConnContext(ctx context.Context, c net.Conn) context.Context {
	if hc, ok := c.(*tlsHandoffConn); ok {
		return context.WithValue(ctx, fastTLSStateKey{}, hc.state)
	}
	return ctx
}

// fastTLSState returns the TLS state fastConnContext attached, or nil.
func fastTLSState(r *http.Request) *tls.ConnectionState {
	st, _ := r.Context().Value(fastTLSStateKey{}).(*tls.ConnectionState)
	return st
}

// startFastTLS serves an HTTPS bind group: ln is its bound TCP socket,
// tlsCfg the group's server config.
func (g *BindGroup) startFastTLS(ln net.Listener, readHeader, idle time.Duration) {
	fs := newFastServer(g, -1, readHeader, idle, ln.Addr())
	fs.isTLS = true
	fs.tlsLn = ln
	fs.tlsCfg = g.httpServer.TLSConfig
	g.fast = fs
	g.httpServer.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return fastConnContext(g.connContext(ctx, c), c)
	}
	go func() {
		if !g.serveGate.Wait(g.gateDone) {
			fs.closing.Store(true)
			ln.Close()
			return
		}
		go fs.acceptTLS()
		if err := g.httpServer.Serve(fs.handoff); err != nil && err != http.ErrServerClosed {
			logging.Error("[HTTP] Server error: %v", err)
		}
	}()
}

// acceptTLS accepts TLS connections and handshakes each in its own
// goroutine (net/http's Serve does the same).
func (fs *fastServer) acceptTLS() {
	var backoff time.Duration
	for {
		c, err := fs.tlsLn.Accept()
		if err != nil {
			if fs.closing.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			backoff = max(5*time.Millisecond, 2*backoff)
			if backoff > time.Second {
				backoff = time.Second
			}
			fs.logf("http: Accept error: %v; retrying in %v", err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		fs.handshakes.Store(c, struct{}{})
		go fs.handshake(c)
	}
}

// logf logs like the group's http.Server.
func (fs *fastServer) logf(format string, args ...any) {
	if l := fs.g.httpServer.ErrorLog; l != nil {
		l.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// handshake runs the TLS handshake of c and sends the connection on.
func (fs *fastServer) handshake(c net.Conn) {
	defer fs.handshakes.Delete(c)
	// net/http bounds the handshake by the smallest of its read, write and
	// read-header timeouts; only read_header is set on a bind group.
	if d := fs.readHeaderTO; d > 0 {
		dl := time.Now().Add(d)
		c.SetReadDeadline(dl)
		c.SetWriteDeadline(dl)
	}
	// A trusted relay's PROXY header comes before the ClientHello: read
	// here, on the socket itself and not one byte further, under the same
	// deadline. The client it names is the connection's peer from here on
	// (for net/http too: it is the tls.Conn's RemoteAddr).
	remote := c.RemoteAddr()
	if tr := fs.g.proxyTrust(); tr.Trusts(remote) {
		hdr, err := proxy.ReadStreamHeader(c)
		client, reason, cause := proxyClient(tr, hdr, err)
		if reason != "" {
			fs.g.proxyRejected(remote, reason, cause)
			c.Close()
			return
		}
		if client != nil {
			remote = client
		}
	}
	tt := &tlsTransport{nc: c, local: c.LocalAddr(), remote: remote}
	tc := tls.Server(tt, fs.tlsCfg)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		var reason string
		if re, ok := err.(tls.RecordHeaderError); ok && re.Conn != nil && tlsRecordHeaderLooksLikeHTTP(re.RecordHeader) {
			io.WriteString(re.Conn, "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n")
			re.Conn.Close()
			reason = "client sent an HTTP request to an HTTPS server"
		} else {
			reason = err.Error()
		}
		fs.logf("http: TLS handshake error from %s: %v", remote, reason)
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	c.SetWriteDeadline(time.Time{})
	if fs.closing.Load() {
		tc.Close()
		return
	}
	st := tc.ConnectionState()
	isH2 := st.NegotiatedProtocol == "h2"
	if fs.g.anyClientAuth() || isH2 && !h2CipherOK(&st) {
		fs.handoff.push(tc)
		return
	}
	fd, err := dupConnFD(c)
	if err != nil {
		fs.handoff.push(tc)
		return
	}
	peer, ok := netip.AddrFromSlice(tcpIP(remote))
	if !ok {
		unix.Close(fd)
		fs.handoff.push(tc)
		return
	}
	// The socket lives on as fd; the runtime's descriptor is closed (which
	// also takes it out of the runtime's poller). From here on the loop
	// feeds the transport.
	tt.nc = nil
	c.Close()
	t := &fastTLS{tc: tc, tt: tt, more: true}
	l := fs.group.Next()
	l.Post(func() {
		if isH2 {
			fs.addH2Conn(l, fd, peer.Unmap(), t)
			return
		}
		if conn := fs.addConn(l, fd, peer.Unmap(), t); conn != nil {
			// The handshake may have read the first request already.
			defer conn.recoverPanic()
			conn.readRequests()
		}
	})
}

func tcpIP(a net.Addr) net.IP {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP
	}
	return nil
}

// dupConnFD duplicates c's socket descriptor (close-on-exec).
func dupConnFD(c net.Conn) (int, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return -1, errors.New("not a socket")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	var derr error
	if err := rc.Control(func(s uintptr) { fd, derr = unix.FcntlInt(s, unix.F_DUPFD_CLOEXEC, 0) }); err != nil {
		return -1, err
	}
	return fd, derr
}

// tlsRecordHeaderLooksLikeHTTP is net/http's check: does a TLS record
// header look like the start of a plaintext HTTP request?
func tlsRecordHeaderLooksLikeHTTP(hdr [5]byte) bool {
	switch string(hdr[:]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	}
	return false
}

// anyClientAuth reports whether a site of the group asks for client
// certificates: its connections stay with net/http, which checks them per
// request.
func (g *BindGroup) anyClientAuth() bool {
	ss := g.sites.Load()
	if ss == nil {
		return false
	}
	for _, s := range ss.all {
		if s.Listener.ClientAuth != nil || (s.Listener.TLS != nil && clientAuthConfigured(s.Listener.TLS.ClientAuth)) {
			return true
		}
	}
	return false
}

// closeHandshakes closes the connections still in their handshake.
func (fs *fastServer) closeHandshakes() {
	fs.handshakes.Range(func(k, _ any) bool {
		k.(net.Conn).Close()
		return true
	})
}
