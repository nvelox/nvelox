package core

import (
	"bufio"
	"bytes"
	"net"
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

func newProxyTrust(cidrs []string, keys [][]byte) *proxyTrust {
	return &proxyTrust{proxy.NewTrust(cidrs, keys)}
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

// verify checks a trusted peer's header (proxy.Trust.Verify).
func (p *proxyTrust) verify(h *proxyproto.Header, payload []byte, datagram bool) error {
	return p.shared().Verify(h, payload, datagram)
}

func (p *proxyTrust) enabled() bool { return p.shared().Enabled() }

// trusts reports whether addr (the immediate TCP/UDP peer) is an allowed
// inbound-PROXY sender. Safe on a nil receiver / empty list (returns false).
func (p *proxyTrust) trusts(addr net.Addr) bool { return p.shared().Trusts(addr) }

func ipOf(addr net.Addr) net.IP { return proxy.IPOf(addr) }

// proxyV2Signature is the 12-byte PROXY-protocol-v2 magic prefix.
var proxyV2Signature = proxy.V2Signature

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
	named, reason, cause := p.shared().StreamClient(hdr, err)
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
func parseInboundProxyV2DatagramHeader(data []byte) (hdr *proxyproto.Header, consumed int, isProxy bool) {
	if len(data) < 16 || !bytes.Equal(data[:len(proxyV2Signature)], proxyV2Signature) {
		return nil, 0, false
	}
	total := 16 + (int(data[14])<<8 | int(data[15]))
	if len(data) < total {
		return nil, 0, false // truncated/garbled — treat as raw rather than block
	}
	hdr, err := proxyproto.Read(bufio.NewReader(bytes.NewReader(data[:total])))
	if err != nil || hdr == nil || hdr.Command == proxyproto.LOCAL || hdr.SourceAddr == nil {
		return nil, total, true
	}
	return hdr, total, true
}
