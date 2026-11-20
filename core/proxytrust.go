package core

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/core/logging"
	"nvelox/proxy"
)

// proxyTrust is the accept_proxy_from trust of a listener: the shared
// proxy.Trust (the HTTP listeners use the same one) under the names this
// package's TCP and UDP paths call it by. A nil *proxyTrust trusts nobody.
type proxyTrust struct{ *proxy.Trust }

func newProxyTrust(cidrs []string, keys [][]byte, replayRequired bool) *proxyTrust {
	t := proxy.NewTrust(cidrs, keys)
	t.SetReplayWindow(replayRequired)
	return &proxyTrust{t}
}

// shared returns the proxy.Trust (nil for a nil receiver).
func (p *proxyTrust) shared() *proxy.Trust {
	if p == nil {
		return nil
	}
	return p.Trust
}

// setKeys replaces the signing keys (nil: headers need no signature).
func (p *proxyTrust) setKeys(keys [][]byte) { p.Trust.SetKeys(keys) }

// relayDatagram checks the header of a datagram from a trusted relay's
// socket at port relayPort (proxy.Trust.VerifyFrom): the counter it
// carries (counted false: none), for the window of that relay socket
// (relayWindows), or the reason the datagram is dropped.
func (p *proxyTrust) relayDatagram(h *proxyproto.Header, payload []byte, relayPort uint16) (counter uint64, counted bool, drop string) {
	counter, counted, err := p.shared().VerifyFrom(h, payload, true, relayPort)
	if err != nil {
		return 0, false, udpDropBadSignature
	}
	return counter, counted, ""
}

const (
	// relayWindowKeep is how long the window of a relay socket is kept
	// once no session uses it: a header taken in it passes its time check
	// until proxy.SignatureWindow after it was signed, which may be
	// proxy.SignatureWindow after it was taken.
	relayWindowKeep = 2 * proxy.SignatureWindow
	// relayWindowExpireMax bounds the windows one call removes, so that no
	// datagram waits for many: each session that ends adds at most one to
	// remove.
	relayWindowExpireMax = 64
)

// relayWindow is the replay window of one relay socket (a trusted peer's
// address and port; accept_proxy_replay_window): the counters of its
// headers that were taken. The sessions of that socket use it one after
// the other.
type relayWindow struct {
	proxy.ReplayWindow
	peer     netip.AddrPort
	sessions int   // the sessions that use it
	ended    int64 // when the last of them ended (unix nanoseconds)
	queued   bool  // it has an entry in relayWindows.idle
}

// relayWindows holds the windows of the relay sockets one event loop, or
// one listener socket, serves. A window outlives the sessions that used
// it: the session that took a header may end long before a copy of that
// header stops passing its time check (no answer from the server, a
// failure, a refusal), and the copy would begin a new session. A window is
// made for the first counted header of a relay socket, so only a relay
// that has the key adds one. Not safe for concurrent use.
type relayWindows struct {
	m map[netip.AddrPort]*relayWindow
	// idle: the windows whose sessions all ended, about in the order the
	// last one did. A window has one entry at most, however many sessions
	// end: the list grows with the relay sockets, not with the sessions
	// (a flood of sessions that are refused at once ends one each). A window
	// used again since its entry was made is put back, at its later end,
	// when the entry comes up.
	idle []idleWindow
}

type idleWindow struct {
	w     *relayWindow
	ended int64
}

// attach returns the window of the relay socket at peer for a session that
// takes its counters from now on (unix nanoseconds). A window no session
// has used for more than relayWindowKeep starts empty: what it held passes
// its time check no longer.
func (t *relayWindows) attach(peer netip.AddrPort, now int64) *relayWindow {
	if t.m == nil {
		t.m = make(map[netip.AddrPort]*relayWindow)
	}
	w := t.m[peer]
	switch {
	case w == nil:
		w = &relayWindow{peer: peer}
		t.m[peer] = w
	case w.sessions == 0 && now-w.ended > int64(relayWindowKeep):
		w.ReplayWindow = proxy.ReplayWindow{}
	}
	w.sessions++
	t.expire(now)
	return w
}

// detach: a session that used w is over (now: unix nanoseconds).
func (t *relayWindows) detach(w *relayWindow, now int64) {
	w.sessions--
	w.ended = now
	if w.sessions == 0 && !w.queued {
		w.queued = true
		t.idle = append(t.idle, idleWindow{w, now})
	}
	t.expire(now)
}

// expire removes, oldest first, windows no session has used since their
// last one ended more than relayWindowKeep ago: at most
// relayWindowExpireMax of them.
func (t *relayWindows) expire(now int64) {
	for i := 0; i < relayWindowExpireMax && len(t.idle) > 0; i++ {
		e := t.idle[0]
		if now-e.ended <= int64(relayWindowKeep) {
			return
		}
		t.idle[0] = idleWindow{}
		t.idle = t.idle[1:]
		w := e.w
		w.queued = false
		switch {
		case w.sessions > 0:
			// In use: queued again when its last session ends.
		case w.ended != e.ended:
			// Used again since, and idle again from a later end: put
			// back at that end (behind entries that may be older; a
			// window goes at most relayWindowKeep late, never early).
			w.queued = true
			t.idle = append(t.idle, idleWindow{w, w.ended})
		case t.m[w.peer] == w:
			delete(t.m, w.peer)
		}
	}
}

func (p *proxyTrust) enabled() bool { return p.shared().Enabled() }

// trusts reports whether addr (the immediate TCP/UDP peer) is an allowed
// inbound-PROXY sender. Safe on a nil receiver / empty list (returns false).
func (p *proxyTrust) trusts(addr net.Addr) bool { return p.shared().Trusts(addr) }

func ipOf(addr net.Addr) net.IP { return proxy.IPOf(addr) }

// relayClient reads the PROXY v2 header a trusted relay's TCP connection
// must start with, waiting at most wait, and returns the client it names:
// the relay's own address for a LOCAL header (the relay speaks for itself,
// as in its health checks). It reads the header's bytes and not one more:
// what follows belongs to the session (or to the TLS handshake).
//
// A reason is returned instead when the connection is to be closed: the
// stream starts with something else (proxy.RefusedMissing), the header does
// not parse or is cut short (RefusedMalformed), did not complete in time
// (RefusedTimeout) or, with accept_proxy_key_file, is not validly signed
// (RefusedSignature). Nothing is guessed: a relay is never taken for the
// client of bytes it relays. proxy.NothingSent (the relay closed or stayed
// silent without sending a byte) closes the connection too, but is no
// refusal.
//
// cause is the error behind a reason, for the log.
func (p *proxyTrust) relayClient(c net.Conn, wait time.Duration) (client net.Addr, reason string, cause error) {
	c.SetReadDeadline(time.Now().Add(wait))
	hdr, err := proxy.ReadStreamHeader(c)
	c.SetReadDeadline(time.Time{})
	named, reason, cause := p.shared().StreamClient(hdr, err, uint16(portOf(c.RemoteAddr())))
	if reason != "" {
		return nil, reason, cause
	}
	if named == nil {
		return c.RemoteAddr(), "", nil // LOCAL
	}
	return named, "", nil
}

// proxyRefusals counts the trusted relays' connections closed for their
// PROXY header (nvelox_proxy_header_rejected_total{listener,reason}, the
// counter of the HTTP listeners) and logs them, at most one line a second.
type proxyRefusals struct {
	lastLog atomic.Int64 // unix nanos
}

// proxyRefused records that relay's connection to listener l was closed for
// reason, with the error behind it (relayClient). proxy.NothingSent is no
// refusal and is not recorded.
func (e *Engine) proxyRefused(l *ListenerConfig, relay net.Addr, reason string, cause error) {
	if reason == proxy.NothingSent {
		return
	}
	if e.Metrics != nil {
		e.Metrics.GetCounter("nvelox_proxy_header_rejected_total", map[string]string{"listener": l.Name, "reason": reason}).Inc()
	}
	now := time.Now().UnixNano()
	if last := e.proxyRefusals.lastLog.Load(); now-last >= int64(time.Second) && e.proxyRefusals.lastLog.CompareAndSwap(last, now) {
		logging.Warn("[PROXY] listener %s: connection from relay %s refused (%s): %v", l.Name, ipStrOf(relay), reason, cause)
	}
}

// parseInboundProxyV2Datagram reads the PROXY v2 header of a datagram, for
// UDP listeners. A UDP datagram is atomic — the whole PROXY-v2 header is
// present in this one datagram or it isn't, so there is no cross-read
// reassembly (no "need more bytes" state).
//
// Returns:
//   - isProxy=false              => not a PROXY-v2 datagram (raw payload); forward
//     as-is, keep the peer addr (consumed=0, src=nil).
//   - isProxy=true, src!=nil, consumed=N => a valid PROXY (non-LOCAL) header: src
//     is the real client; drop the first N bytes before forwarding the payload.
//   - isProxy=true, src=nil, consumed=N  => malformed/LOCAL header: still strip N
//     bytes (don't leak them as payload) but fall back to the peer addr.
func parseInboundProxyV2Datagram(data []byte) (src net.Addr, consumed int, isProxy bool) {
	hdr, consumed, isProxy := parseInboundProxyV2DatagramHeader(data)
	if hdr != nil {
		src = hdr.SourceAddr
	}
	return src, consumed, isProxy
}

// parseInboundProxyV2DatagramHeader is parseInboundProxyV2Datagram returning
// the parsed header (nil when there is no usable one) for a signature check.
// A usable header names a datagram's client by an IP address
// (proxy.ParseDatagramStrict): a LOCAL header, one for a stream, and one
// with a source that is no IP address (AF_UNIX) name none, and such a
// client would pass every check that goes by address.
func parseInboundProxyV2DatagramHeader(data []byte) (hdr *proxyproto.Header, consumed int, isProxy bool) {
	hdr, consumed, err := proxy.ParseDatagramStrict(data)
	switch {
	case err == nil:
		return hdr, consumed, true
	case errors.Is(err, proxy.ErrNoHeader) || consumed == 0:
		return nil, 0, false // no header, or one cut short: nothing of it is taken off
	}
	return nil, consumed, true
}
