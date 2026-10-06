package core

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
)

// L4 TCP relay with standard proxy half-close semantics.
//
// The previous L4 TCP data path ran the client side on nbio and, as soon as
// EITHER side ended, closed BOTH connections. nbio's Conn.Close discards its
// pending write queue, so when a backend wrote a response and closed first,
// every byte nvelox had already read from the backend but not yet flushed to
// a slower client was silently dropped (production: a 90,104-byte HTTP/1.1
// "Connection: close" response reached clients as 41-52 KB, cut mid TLS
// record). nbio also treats a peer's half-close (EPOLLRDHUP) as a full close,
// so a client that half-closed after sending its request never got an answer.
//
// relayL4 instead does what an L4 proxy must:
//
//  1. When one side reaches EOF, everything already read from it is written
//     to the other side first (blocking writes = real back-pressure; nothing
//     is queued in user space past a single buffer).
//  2. Then only the WRITE direction toward the other side is half-closed
//     (TCP shutdown(SHUT_WR); for TLS a close_notify plus the TCP FIN) — never
//     a full close, never SO_LINGER 0, no deadline poked into the other side.
//  3. The opposite direction keeps copying until it ends too, or until the
//     session has been idle (no bytes moved in EITHER direction) for the
//     listener's idle timeout.
//  4. Only a real error (RST, failed write, idle timeout) aborts the session,
//     and only then is the other side closed immediately.

// relayBufSize is the per-direction copy buffer. 16 KiB per direction matches
// the nginx stream / HAProxy defaults and keeps per-connection memory at the
// old data path's single 32 KiB read buffer.
const relayBufSize = 16 * 1024

var relayBufPool = sync.Pool{New: func() any {
	b := make([]byte, relayBufSize)
	return &b
}}

// defaultL4IdleTimeout applies to plain L4 TCP listeners when timeouts.idle is
// unset (unchanged from the previous data path). An explicit "0" disables it.
const defaultL4IdleTimeout = 5 * time.Minute

// l4IdleTimeout resolves a plain L4 TCP listener's idle timeout.
func l4IdleTimeout(l *ListenerConfig) time.Duration {
	if l.Timeouts.Idle == "" {
		return defaultL4IdleTimeout
	}
	return l.Timeouts.ParseIdle()
}

// relayResult summarises one finished L4 session.
type relayResult struct {
	ClientToBackend int64 // bytes written to the backend
	BackendToClient int64 // bytes written to the client
	// Err is the first real error that aborted the session (RST, write
	// failure, idle timeout). nil means both directions ended cleanly with a
	// half-close each.
	Err error
}

type l4Relay struct {
	client, backend net.Conn
	idle            time.Duration // 0 = no idle timeout
	start           time.Time
	lastActive      atomic.Int64 // time.Duration since start of the last progress in either direction

	abortOnce sync.Once
	err       error // set once by fail; read after both directions returned
}

// relayL4 copies client<->backend until both directions have ended (see the
// comment above for the exact semantics), then closes both conns. It blocks
// for the whole session. client/backend may be *net.TCPConn, *tls.Conn, or a
// *proxyproto.Conn wrapping either.
func relayL4(client, backend net.Conn, idle time.Duration) relayResult {
	r := &l4Relay{client: client, backend: backend, idle: idle, start: time.Now()}
	var res relayResult
	up := make(chan int64, 1)
	go func() { up <- r.pipe(backend, client, true) }()
	res.BackendToClient = r.pipe(client, backend, false)
	res.ClientToBackend = <-up
	res.Err = r.err
	// Both directions are finished (or the session was aborted): release the
	// sockets. Everything already written has been handed to the kernel, which
	// still delivers it after close.
	client.Close()
	backend.Close()
	return res
}

// pipe copies src -> dst until src ends. On a clean EOF every byte read from
// src has already been written to dst, so it half-closes dst's write side to
// propagate the end of stream and returns WITHOUT touching the opposite
// direction. Any real error aborts the whole session.
func (r *l4Relay) pipe(dst, src net.Conn, toBackend bool) int64 {
	n, writeFailed, err := r.copy(dst, src)
	switch {
	case err == nil:
		err = closeWrite(dst)
	case toBackend && writeFailed && peerClosed(err):
		// The backend stopped accepting data (it closed or reset its socket)
		// while the client is still sending. That alone must not cut the
		// response the backend may still be delivering: the backend->client
		// direction ends on its own (EOF after the backend's FIN, or the
		// backend's real error). Meanwhile keep reading — and dropping —
		// client input: closing the client socket with unread input makes the
		// kernel answer with an RST and throw away response bytes still queued
		// for the client (the classic lingering-close problem).
		_, _, err = r.copy(nil, src)
	}
	if err != nil {
		r.fail(err)
	}
	return n
}

// copy moves bytes src -> dst until src's clean EOF (nil error) or the first
// real error; writeFailed reports whether that error came from writing to
// dst. A nil dst reads and discards.
func (r *l4Relay) copy(dst, src net.Conn) (written int64, writeFailed bool, err error) {
	bp := relayBufPool.Get().(*[]byte)
	defer relayBufPool.Put(bp)
	buf := *bp
	for {
		if r.idle > 0 {
			src.SetReadDeadline(r.idleDeadline())
		}
		nr, rerr := src.Read(buf)
		if nr > 0 {
			r.touch()
			if dst != nil {
				nw, werr := r.write(dst, buf[:nr])
				written += int64(nw)
				if werr != nil {
					return written, true, werr
				}
			}
		}
		if rerr != nil {
			if isCleanEOF(rerr) {
				return written, false, nil
			}
			if isTimeout(rerr) && r.idleFor() < r.idle {
				// This direction was quiet but the other one moved bytes
				// recently: the session is not idle. Re-arm and keep reading.
				continue
			}
			return written, false, rerr
		}
	}
}

// write writes b fully to dst. With an idle timeout, a peer that accepts no
// data for a whole idle period is treated as dead — otherwise a zero-window
// peer could pin a half-closed session forever once the other direction is
// done. (A timed-out write is never retried: on a *tls.Conn it is fatal.)
func (r *l4Relay) write(dst net.Conn, b []byte) (int, error) {
	if r.idle > 0 {
		dst.SetWriteDeadline(time.Now().Add(r.idle))
	}
	n, err := dst.Write(b)
	if n > 0 {
		r.touch()
	}
	if err == nil && n < len(b) {
		err = io.ErrShortWrite
	}
	return n, err
}

// fail aborts the session on the first real error: both conns are closed at
// the transport level, which unblocks the other direction immediately. For
// TLS the transport is closed WITHOUT a close_notify so the client can tell
// an aborted stream from a complete one.
func (r *l4Relay) fail(err error) {
	r.abortOnce.Do(func() {
		r.err = err
		transportOf(r.client).Close()
		transportOf(r.backend).Close()
	})
}

func (r *l4Relay) touch() { r.lastActive.Store(int64(time.Since(r.start))) }

func (r *l4Relay) idleFor() time.Duration {
	return time.Since(r.start) - time.Duration(r.lastActive.Load())
}

func (r *l4Relay) idleDeadline() time.Time {
	return r.start.Add(time.Duration(r.lastActive.Load()) + r.idle)
}

// closeWrite half-closes c's write side: the peer reads EOF while c can still
// be read from. For TLS that is a close_notify alert followed by the TCP FIN
// (tls.Conn.CloseWrite alone only sends the alert).
func closeWrite(c net.Conn) error {
	var err error
	if tc := tlsConnOf(c); tc != nil {
		err = tc.CloseWrite()
	}
	if cw, ok := transportOf(c).(interface{ CloseWrite() error }); ok {
		if ferr := cw.CloseWrite(); err == nil {
			err = ferr
		}
	}
	return err
}

// tlsConnOf returns the *tls.Conn inside c (directly or under a
// proxyproto.Conn), or nil for a plain transport.
func tlsConnOf(c net.Conn) *tls.Conn {
	if pc, ok := c.(*proxyproto.Conn); ok {
		c = pc.Raw()
	}
	tc, _ := c.(*tls.Conn)
	return tc
}

// transportOf unwraps proxyproto.Conn / tls.Conn down to the transport
// connection (normally a *net.TCPConn).
func transportOf(c net.Conn) net.Conn {
	if pc, ok := c.(*proxyproto.Conn); ok {
		c = pc.Raw()
	}
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	return c
}

// isCleanEOF reports an orderly end of stream. io.ErrUnexpectedEOF is what a
// *tls.Conn returns when the peer's TCP FIN cuts a record short — still a
// FIN, not a reset, so the bytes read so far are forwarded and the end of
// stream is propagated like any other half-close.
func isCleanEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func isTimeout(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }

// peerClosed reports a write that failed because the peer already closed or
// reset its socket (as opposed to a timeout or a local error).
func peerClosed(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}
