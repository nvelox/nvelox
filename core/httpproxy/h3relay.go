package httpproxy

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"nvelox/core/logging"
	"nvelox/proxy"
)

// HTTP/3 behind a UDP relay (accept_proxy_from on an https listener with
// http3).
//
// A UDP relay keeps one socket per client and puts a PROXY protocol v2
// header, naming that client, in front of every datagram it passes on.
// QUIC must not see the header, and its answers must go back the way the
// packets came. So the group's QUIC socket is wrapped:
//
//   - A datagram from an address that is not a trusted relay goes to QUIC
//     as it is: a direct client.
//   - A datagram from a trusted relay must start with a header that names
//     a datagram client and is signed over the datagram's payload
//     (accept_proxy_key_file: a UDP source address is forged with one
//     packet, so the address alone proves nothing). The header is taken
//     off, and the relay's own address stays the packet's source: QUIC
//     answers the relay, which answers the client.
//   - The relay's address (its socket for that client) is pinned to the
//     client the header named. A later datagram from it that names another
//     client is dropped: a relay's socket has one client. A header signed
//     with a counter (accept_proxy_replay_window) is bound to the relay
//     socket's port, and its counter is checked against that socket's
//     window, kept with its pin: a copy of a datagram is dropped.
//   - Requests of a QUIC connection whose peer is a relay are given the
//     pinned client as their remote address (BindGroup.ServeHTTP), so the
//     access policy, the limits, the log and X-Forwarded-For see the
//     client. A relay's connection with no pin is refused.
//
// Whatever does not pass is dropped and counted
// (nvelox_proxy_header_rejected_total), never passed to QUIC.

const (
	// h3RelayPinTTL: a pin unused for this long is forgotten. It is twice
	// the idle timeout of the quic-go server's connections (30 s), so the
	// connection a pin served there is gone by then. A connection on the
	// loops may live longer (the listener's idle timeout): it keeps the
	// client it began with itself (qconn.relayed). It is also twice
	// proxy.SignatureWindow: a pin's window of counters is kept that long,
	// as long as a header it took can pass its time check.
	h3RelayPinTTL = 60 * time.Second
	// h3RelayPinsMax bounds the pins of one socket. Datagrams of a relay
	// socket that would need one more are dropped.
	h3RelayPinsMax = 1 << 16
	// h3RelaySweepEvery is how often expired pins are removed.
	h3RelaySweepEvery = 15 * time.Second
	// h3RelayDatagramMax: the largest datagram read, with its header.
	h3RelayDatagramMax = 64 << 10
)

// Why a relay's datagram is dropped, beside the reasons shared with the
// stream listeners.
const (
	h3RelayClientChanged = "client_changed"
	h3RelayTableFull     = "table_full"
)

var errH3RelayClientChanged = errors.New("the relay's socket named another client before")

type h3Pin struct {
	client netip.AddrPort
	seen   int64              // unix nanoseconds
	replay proxy.ReplayWindow // the relay socket's counters
}

// h3Pins is the pin table of one socket: which client each relay socket
// that sends to it stands for. It is not safe for concurrent use: the
// quic-go path's socket guards its table (h3RelayConn.mu), a loop's socket
// is read by its loop alone (web.Relays.Datagram).
type h3Pins struct {
	pins  map[netip.AddrPort]h3Pin
	swept int64
}

// h3RelayConn is the QUIC socket of a bind group with trusted relays. Only
// the methods quic-go's plain socket path uses are offered, with
// SyscallConn and the buffer setters so that it still sets DF and sizes the
// buffers; ReadMsgUDP is not, on purpose: quic-go would then read past this
// type.
type h3RelayConn struct {
	uc *net.UDPConn
	g  *BindGroup

	// buf is ReadFrom's scratch. quic-go reads a socket from one goroutine.
	buf []byte

	mu sync.Mutex
	h3Pins
}

func newH3RelayConn(uc *net.UDPConn, g *BindGroup) *h3RelayConn {
	return &h3RelayConn{uc: uc, g: g, buf: make([]byte, h3RelayDatagramMax)}
}

func (c *h3RelayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.uc.ReadFromUDPAddrPort(c.buf)
		if err != nil {
			return 0, nil, err
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		tr := c.g.proxyTrust()
		if !trustsAddr(tr, from.Addr()) {
			return copy(p, c.buf[:n]), net.UDPAddrFromAddrPort(from), nil
		}
		payload, reason, cause := c.relayed(tr, from, c.buf[:n])
		if reason != "" {
			c.g.proxyRejected(net.UDPAddrFromAddrPort(from), reason, cause)
			continue
		}
		return copy(p, payload), net.UDPAddrFromAddrPort(from), nil
	}
}

// relayed checks a datagram from the trusted relay socket from and returns
// what follows its header, or why it is dropped.
func (c *h3RelayConn) relayed(tr *proxy.Trust, from netip.AddrPort, data []byte) (payload []byte, reason string, cause error) {
	payload, client, counter, counted, reason, cause := h3RelayHeader(tr, data, from.Port())
	if reason != "" {
		return nil, reason, cause
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if reason, cause = c.pin(from, client, time.Now().UnixNano(), counter, counted); reason != "" {
		return nil, reason, cause
	}
	return payload, "", nil
}

// h3RelayHeader checks the header of a datagram from a trusted relay's
// socket at port relayPort (it must name a datagram client and be signed
// over what follows it) and returns what follows it, the client it names
// and the counter it carries (counted false: none), or why the datagram is
// dropped.
func h3RelayHeader(tr *proxy.Trust, data []byte, relayPort uint16) (payload []byte, client netip.AddrPort, counter uint64, counted bool, reason string, cause error) {
	hdr, consumed, err := proxy.ParseDatagramStrict(data)
	switch {
	case errors.Is(err, proxy.ErrNoHeader):
		return nil, client, 0, false, proxy.RefusedMissing, err
	case err != nil:
		return nil, client, 0, false, proxy.RefusedMalformed, err
	}
	payload = data[consumed:]
	// Without keys nothing could tell a relay's datagram from one with a
	// forged source address (the configuration is refused at load; a
	// reload that drops the key file must not open this).
	if len(tr.Keys()) == 0 {
		return nil, client, 0, false, proxy.RefusedSignature, proxy.ErrSignatureMissing
	}
	counter, counted, err = tr.VerifyFrom(hdr, payload, true, relayPort)
	if err != nil {
		return nil, client, 0, false, proxy.RefusedSignature, err
	}
	ua := hdr.SourceAddr.(*net.UDPAddr)
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return nil, client, 0, false, proxy.RefusedMalformed, proxy.ErrBadHeader
	}
	return payload, netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port)), counter, counted, "", nil
}

// pin notes, at the time now, that the relay socket from stands for
// client, or says why its datagram is dropped: the socket named another
// client less than h3RelayPinTTL ago, the table is full, or the header's
// counter (counted) was taken from that relay socket before or is older
// than its window. A pin that has expired keeps its window until it is
// swept (h3Pins.sweep).
func (t *h3Pins) pin(from, client netip.AddrPort, now int64, counter uint64, counted bool) (reason string, cause error) {
	if t.pins == nil {
		t.pins = make(map[netip.AddrPort]h3Pin)
	}
	if now-t.swept >= int64(h3RelaySweepEvery) {
		t.sweep(now)
	}
	pin, ok := t.pins[from]
	switch {
	case ok && now-pin.seen < int64(h3RelayPinTTL) && pin.client != client:
		return h3RelayClientChanged, errH3RelayClientChanged
	case !ok && len(t.pins) >= h3RelayPinsMax:
		t.sweep(now)
		if len(t.pins) >= h3RelayPinsMax {
			return h3RelayTableFull, nil
		}
	}
	if counted && !pin.replay.Take(counter) {
		return proxy.RefusedReplayed, proxy.ErrReplayed
	}
	pin.client, pin.seen = client, now
	t.pins[from] = pin
	return "", nil
}

// trustsAddr is tr.TrustsIP for a netip address, without an allocation
// (it runs for every datagram).
func trustsAddr(tr *proxy.Trust, a netip.Addr) bool {
	if a.Is4() {
		b := a.As4()
		return tr.TrustsIP(b[:])
	}
	b := a.As16()
	return tr.TrustsIP(b[:])
}

// sweep removes the pins unused for more than h3RelayPinTTL, and their
// windows with them: by then a header a pin took passes its time check no
// longer (h3RelayPinTTL is at least twice proxy.SignatureWindow).
func (t *h3Pins) sweep(now int64) {
	t.swept = now
	for k, p := range t.pins {
		if now-p.seen > int64(h3RelayPinTTL) {
			delete(t.pins, k)
		}
	}
}

// client returns the client pinned to the relay socket at addr.
func (c *h3RelayConn) client(addr netip.AddrPort) (netip.AddrPort, bool) {
	now := time.Now().UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	pin, ok := c.pins[addr]
	if !ok || now-pin.seen >= int64(h3RelayPinTTL) {
		return netip.AddrPort{}, false
	}
	return pin.client, true
}

func (c *h3RelayConn) WriteTo(p []byte, addr net.Addr) (int, error) { return c.uc.WriteTo(p, addr) }
func (c *h3RelayConn) Close() error                                 { return c.uc.Close() }
func (c *h3RelayConn) LocalAddr() net.Addr                          { return c.uc.LocalAddr() }
func (c *h3RelayConn) SetDeadline(t time.Time) error                { return c.uc.SetDeadline(t) }
func (c *h3RelayConn) SetReadDeadline(t time.Time) error            { return c.uc.SetReadDeadline(t) }
func (c *h3RelayConn) SetWriteDeadline(t time.Time) error           { return c.uc.SetWriteDeadline(t) }
func (c *h3RelayConn) SyscallConn() (syscall.RawConn, error)        { return c.uc.SyscallConn() }
func (c *h3RelayConn) SetReadBuffer(n int) error                    { return c.uc.SetReadBuffer(n) }
func (c *h3RelayConn) SetWriteBuffer(n int) error                   { return c.uc.SetWriteBuffer(n) }

// h3Client resolves the remote address of an HTTP/3 connection or request:
// the address itself for a direct client, the pinned client for a trusted
// relay's socket. ok is false for a relay's socket that has no pin (its
// requests are refused), and for a relay when the group's QUIC socket was
// not started with relays in mind.
func (g *BindGroup) h3Client(remote netip.AddrPort) (client netip.AddrPort, ok bool) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if !trustsAddr(g.proxyTrust(), remote.Addr()) {
		return remote, true
	}
	if g.h3Relay == nil {
		return netip.AddrPort{}, false
	}
	return g.h3Relay.client(remote)
}

// h3ClientAddr is h3Client for a net.Addr (a QUIC connection's remote
// address): the address a PROXY header to a backend names. Nil when there
// is none.
func (g *BindGroup) h3ClientAddr(remote net.Addr) net.Addr {
	ua, ok := remote.(*net.UDPAddr)
	if !ok {
		return remote
	}
	client, ok := g.h3Client(ua.AddrPort())
	if !ok {
		return nil
	}
	return net.UDPAddrFromAddrPort(client)
}

// warnH3RelayNeedsRestart: a reload gave an HTTP/3 group relays to trust,
// but its QUIC socket was opened without the relay layer.
func (g *BindGroup) warnH3RelayNeedsRestart() {
	if g.http3Server != nil && g.h3Relay == nil && g.proxyTrust().Enabled() {
		logging.Warn("[HTTP3] %s: accept_proxy_from was added by a reload: HTTP/3 through relays starts with the next restart (HTTP/1.1 and HTTP/2 through relays work now); datagrams from the relays are not served as HTTP/3 until then", g.addr)
	}
}
