package core

import (
	"bufio"
	"bytes"
	"net"

	"nvelox/core/acl"

	"github.com/pires/go-proxyproto"
)

// proxyTrust decides, per inbound connection, whether nvelox should TRUST an
// inbound PROXY-protocol-v2 header and use its source as the real client. Only
// peers whose address falls in one of the configured `accept_proxy_from` CIDRs
// are trusted; everyone else (direct clients, attackers) has any inbound PROXY
// header IGNORED, so a forged header can never spoof a source IP. Empty list =>
// trust nobody => behaves exactly as before (no inbound PROXY acceptance).
//
// This is the receiving half of cross-region client-IP preservation: a peer
// region's relay prepends a PROXY-v2 header carrying the real client; the
// trusted accept here recovers it so the existing send_proxy_v2 forwards the
// real client to the backend (tunnel-server) instead of the relay pod.
type proxyTrust struct {
	nets []*net.IPNet // nil/empty => trust nobody
}

func newProxyTrust(cidrs []string) *proxyTrust {
	return &proxyTrust{nets: acl.ParseCIDRList(cidrs)} // reuse the shared CIDR parser
}

func (p *proxyTrust) enabled() bool { return p != nil && len(p.nets) > 0 }

// trusts reports whether addr (the immediate TCP/UDP peer) is an allowed
// inbound-PROXY sender. Safe on a nil receiver / empty list (returns false).
func (p *proxyTrust) trusts(addr net.Addr) bool {
	if !p.enabled() || addr == nil {
		return false
	}
	ip := ipOf(addr)
	if ip == nil {
		return false
	}
	for _, n := range p.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// policy builds the go-proxyproto PolicyFunc used to wrap a net.Listener (the
// TLS plane): USE the inbound header for trusted CIDRs, IGNORE it otherwise.
// Returns (nil, nil) when disabled so the caller can skip wrapping.
func (p *proxyTrust) policy() (proxyproto.PolicyFunc, error) {
	if !p.enabled() {
		return nil, nil
	}
	cidrs := make([]string, len(p.nets))
	for i, n := range p.nets {
		cidrs[i] = n.String()
	}
	// LaxWhiteListPolicy: USE for listed CIDRs, IGNORE for everyone else
	// (never REJECT/REQUIRE) — so non-PROXY clients (browsers) still pass.
	return proxyproto.LaxWhiteListPolicy(cidrs)
}

func ipOf(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return net.ParseIP(addr.String())
		}
		return net.ParseIP(host)
	}
}

// proxyV2Signature is the 12-byte PROXY-protocol-v2 magic prefix.
var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// tryParseInboundProxyV2 inspects a buffer accumulated from a TRUSTED peer on
// the nbio (raw-TCP) plane, where we cannot pre-wrap a net.Listener and must
// parse the header out of the byte stream ourselves.
//
// Returns:
//   - done=false               => need more bytes (header still arriving); wait.
//   - done=true, src=nil        => not a PROXY-v2 stream (raw payload); use the
//     real peer addr and keep buf intact (consumed=0).
//   - done=true, src!=nil, consumed=N => header parsed; src is the real client
//     and the first N bytes of buf must be dropped before forwarding payload.
func tryParseInboundProxyV2(buf []byte) (done bool, src net.Addr, consumed int) {
	// Match the signature incrementally so a short raw read (e.g. a TLS
	// ClientHello, or any non-PROXY payload) is detected as raw immediately.
	if len(buf) < len(proxyV2Signature) {
		if !bytes.Equal(buf, proxyV2Signature[:len(buf)]) {
			return true, nil, 0 // diverged from the v2 magic => raw
		}
		return false, nil, 0 // still a prefix of the magic => wait for more
	}
	if !bytes.Equal(buf[:len(proxyV2Signature)], proxyV2Signature) {
		return true, nil, 0 // not a v2 header => raw
	}
	if len(buf) < 16 {
		return false, nil, 0 // have the magic, need the 4-byte ver/cmd+fam+len
	}
	total := 16 + (int(buf[14])<<8 | int(buf[15]))
	if len(buf) < total {
		return false, nil, 0 // header not fully arrived yet
	}
	hdr, err := proxyproto.Read(bufio.NewReader(bytes.NewReader(buf[:total])))
	if err != nil || hdr == nil || hdr.Command == proxyproto.LOCAL || hdr.SourceAddr == nil {
		// Malformed or LOCAL (health-check) header: consume it but fall back to
		// the real peer addr. Consuming avoids leaking header bytes as payload.
		return true, nil, total
	}
	return true, hdr.SourceAddr, total
}
