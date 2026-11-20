package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/core/acl"
)

// Trust decides, per inbound connection, whether an inbound PROXY protocol
// v2 header is believed and its source used as the real client. Only peers
// whose address is in one of the configured accept_proxy_from CIDRs are
// trusted; everyone else (direct clients, attackers) has any inbound PROXY
// header ignored. Over TCP the handshake proves the peer address, so only a
// listed peer can name a client. Over UDP the source address of a datagram
// can be forged: a UDP relay may be listed only where the network drops
// packets that claim its address from anywhere else (see accept_proxy_from
// in nvelox.example.yaml). An empty list trusts nobody.
//
// One Trust serves every path: TCP and UDP listeners, and the HTTP
// listeners (plain, TLS, on the event loops and on net/http).
type Trust struct {
	nets []*net.IPNet // nil/empty => trust nobody
	// keys (accept_proxy_key_file): a trusted peer's header must carry a
	// valid signature made with one of them. Swapped by a reload (rotation).
	keys atomic.Pointer[[][]byte]
	// counted (accept_proxy_replay_window: required): the signature must
	// have a counter, which only version 2 has. Set by a reload.
	counted atomic.Bool
}

// NewTrust builds a Trust for the accept_proxy_from CIDRs and the signing
// keys (nil: headers need no signature).
func NewTrust(cidrs []string, keys [][]byte) *Trust {
	p := &Trust{nets: acl.ParseCIDRList(cidrs)}
	p.SetKeys(keys)
	return p
}

// SetKeys replaces the signing keys (nil: headers need no signature).
func (p *Trust) SetKeys(keys [][]byte) {
	if len(keys) == 0 {
		p.keys.Store(nil)
		return
	}
	p.keys.Store(&keys)
}

// SetReplayWindow sets whether a signed header must carry a counter
// (accept_proxy_replay_window: required) or passes without one too, a
// version 1 signature (when_present).
func (p *Trust) SetReplayWindow(required bool) { p.counted.Store(required) }

// ReplayWindowRequired reports whether a signed header must carry a counter.
func (p *Trust) ReplayWindowRequired() bool { return p != nil && p.counted.Load() }

// Keys returns the signing keys, nil when headers need no signature.
func (p *Trust) Keys() [][]byte {
	if p == nil {
		return nil
	}
	if k := p.keys.Load(); k != nil {
		return *k
	}
	return nil
}

// VerifyFrom checks a trusted peer's header h, which came in a datagram or
// on a stream with the ends ends: with keys configured it must name that
// transport (a signed stream header sent again as a datagram is refused)
// and carry a valid signature over payload (the datagram after the header;
// nil for a stream), made for those ends when it has a counter (version
// 2). It returns the counter, for the relay socket's ReplayWindow, with
// counted true; a version 1 signature has none (counted false) and passes
// only while the window is not required. Without keys every header passes,
// uncounted.
func (p *Trust) VerifyFrom(h *proxyproto.Header, payload []byte, datagram bool, ends Ends) (counter uint64, counted bool, err error) {
	if p == nil {
		return 0, false, nil
	}
	keys := p.keys.Load()
	if keys == nil {
		return 0, false, nil
	}
	if datagram && !h.TransportProtocol.IsDatagram() || !datagram && !h.TransportProtocol.IsStream() {
		return 0, false, fmt.Errorf("%w: its transport protocol is not the connection's", ErrSignatureMalformed)
	}
	counter, counted, err = VerifyFrom(h, *keys, payload, time.Now(), ends)
	if err == nil && !counted && p.counted.Load() {
		return 0, false, ErrSignatureUncounted
	}
	return counter, counted, err
}

// Enabled reports whether any peer is trusted.
func (p *Trust) Enabled() bool { return p != nil && len(p.nets) > 0 }

// Nets returns the trusted networks.
func (p *Trust) Nets() []*net.IPNet {
	if p == nil {
		return nil
	}
	return p.nets
}

// Trusts reports whether addr (the immediate TCP/UDP peer) is an allowed
// inbound-PROXY sender. Safe on a nil receiver / empty list (false).
func (p *Trust) Trusts(addr net.Addr) bool {
	if !p.Enabled() || addr == nil {
		return false
	}
	return p.TrustsIP(IPOf(addr))
}

// TrustsIP is Trusts for an address already taken apart.
func (p *Trust) TrustsIP(ip net.IP) bool {
	if !p.Enabled() || ip == nil {
		return false
	}
	for _, n := range p.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IPOf returns the IP of a TCP, UDP or "host:port" address.
func IPOf(addr net.Addr) net.IP {
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

// Why a trusted relay's connection is closed on a listener that requires
// its header (the reason label of nvelox_proxy_header_rejected_total).
const (
	RefusedMissing   = "missing"   // the stream starts with something else
	RefusedMalformed = "malformed" // a header that does not parse, is cut short, or names no stream client
	RefusedSignature = "signature" // keys are set and the signature is absent or wrong
	RefusedTimeout   = "timeout"   // the header did not complete in time
	RefusedReplayed  = "replayed"  // a datagram whose relay socket's counter was taken before, or is too old (ReplayWindow)
	// NothingSent is not a refusal: the relay closed its connection, or
	// stayed silent to the limit, without sending a byte (a TCP health
	// check, a spare connection). Such a connection is closed like any
	// client's that sends nothing: it is not counted and not logged.
	NothingSent = "nothing sent"
)

// ErrNotStream: the header names a datagram's client, or no address.
var ErrNotStream = errors.New("proxy protocol: the header names no stream client")

// StreamClient turns what a trusted relay sent at the start of a stream
// with the ends ends (the result of ReadStreamHeader or ParseStreamStrict)
// into the client's address. It returns nil and no
// reason for a LOCAL header (the relay speaks for itself: it is the
// client), and nil with a reason when the connection is to be closed; cause
// is then the error behind the reason, for the log (which signature check
// failed, what the read returned).
func (p *Trust) StreamClient(hdr *proxyproto.Header, err error, ends Ends) (client *net.TCPAddr, reason string, cause error) {
	var ne net.Error
	switch {
	case err == nil:
	case errors.Is(err, ErrNothingSent):
		return nil, NothingSent, err
	case errors.Is(err, ErrNoHeader):
		return nil, RefusedMissing, err
	case errors.As(err, &ne) && ne.Timeout():
		return nil, RefusedTimeout, err
	default:
		return nil, RefusedMalformed, err
	}
	if hdr == nil {
		return nil, "", nil // LOCAL
	}
	ta, ok := hdr.SourceAddr.(*net.TCPAddr)
	if !ok || ta.IP == nil {
		return nil, RefusedMalformed, ErrNotStream
	}
	if _, _, verr := p.VerifyFrom(hdr, nil, false, ends); verr != nil {
		return nil, RefusedSignature, verr
	}
	return ta, "", nil
}

// V2Signature is the 12-byte PROXY protocol v2 magic prefix.
var V2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// maxV2Header bounds a v2 header: 16 bytes and the 16-bit length they give.
const maxV2Header = 16 + 65535

// Errors of ReadStreamHeader and ParseStreamStrict: what a trusted relay
// sent is not a usable PROXY v2 header.
var (
	// ErrNoHeader: the stream does not start with a PROXY v2 header.
	ErrNoHeader = errors.New("proxy protocol: no v2 header from a trusted relay")
	// ErrBadHeader: the header is malformed.
	ErrBadHeader = errors.New("proxy protocol: malformed v2 header")
	// ErrNothingSent: the connection ended, or its read gave up at the
	// deadline, before the relay sent a single byte (a TCP health check,
	// a spare connection). Nothing was refused.
	ErrNothingSent = errors.New("proxy protocol: the relay sent nothing")
)

// ParseStreamStrict parses a PROXY v2 header at the start of buf, the bytes
// read so far from a trusted relay, for listeners that require one. It
// returns done=false while more bytes are needed. Once done: consumed is
// the header's length; hdr is nil for a LOCAL header (the relay speaks for
// itself: its own address is the client); err is ErrNoHeader when the
// stream starts with anything else and ErrBadHeader for a header that does
// not parse or names no source.
func ParseStreamStrict(buf []byte) (done bool, hdr *proxyproto.Header, consumed int, err error) {
	n := min(len(buf), len(V2Signature))
	if !bytes.Equal(buf[:n], V2Signature[:n]) {
		return true, nil, 0, ErrNoHeader
	}
	if len(buf) < 16 {
		return false, nil, 0, nil
	}
	total := 16 + (int(buf[14])<<8 | int(buf[15]))
	if len(buf) < total {
		return false, nil, 0, nil
	}
	h, perr := proxyproto.Read(bufio.NewReader(bytes.NewReader(buf[:total])))
	if perr != nil || h == nil {
		return true, nil, total, ErrBadHeader
	}
	if h.Command == proxyproto.LOCAL {
		return true, nil, total, nil
	}
	if h.SourceAddr == nil {
		return true, nil, total, ErrBadHeader
	}
	return true, h, total, nil
}

// ParseDatagramStrict parses the PROXY v2 header a trusted relay puts at the
// start of every datagram it relays. A datagram is whole: there is no
// "more bytes needed". It returns the header and its length, or
// ErrNoHeader when the datagram starts with anything else and ErrBadHeader
// for a header that is cut short, does not parse, or names no datagram
// client (a LOCAL header, a stream one): a relayed datagram without a
// client to attribute it to is not served.
func ParseDatagramStrict(data []byte) (hdr *proxyproto.Header, consumed int, err error) {
	if len(data) < len(V2Signature) || !bytes.Equal(data[:len(V2Signature)], V2Signature) {
		return nil, 0, ErrNoHeader
	}
	if len(data) < 16 {
		return nil, 0, ErrBadHeader
	}
	total := 16 + (int(data[14])<<8 | int(data[15]))
	if len(data) < total {
		return nil, 0, ErrBadHeader
	}
	h, perr := proxyproto.Read(bufio.NewReader(bytes.NewReader(data[:total])))
	if perr != nil || h == nil || h.Command != proxyproto.PROXY || !h.TransportProtocol.IsDatagram() {
		return nil, total, ErrBadHeader
	}
	if ua, ok := h.SourceAddr.(*net.UDPAddr); !ok || ua.IP == nil {
		return nil, total, ErrBadHeader
	}
	return h, total, nil
}

// ReadStreamHeader reads exactly one PROXY v2 header from r, a trusted
// relay's connection, and nothing after it (the bytes that follow belong
// to TLS or HTTP). Results as ParseStreamStrict; ErrNothingSent when the
// read ended before the first byte, and any other read error as it is.
func ReadStreamHeader(r io.Reader) (hdr *proxyproto.Header, err error) {
	var buf [16]byte
	// The magic, as it arrives: a stream that starts with anything else is
	// recognised at its first bytes, without waiting for twelve of them (a
	// peer that sent a short message and waits for the answer would wait
	// for the whole header limit).
	for got := 0; got < len(V2Signature); {
		n, err := r.Read(buf[got:len(V2Signature)])
		got += n
		if !bytes.Equal(buf[:got], V2Signature[:got]) {
			return nil, ErrNoHeader // whatever came, it is no header
		}
		if err != nil && got < len(V2Signature) {
			switch {
			case got == 0:
				return nil, ErrNothingSent
			case err == io.EOF:
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
	if _, err := io.ReadFull(r, buf[len(V2Signature):]); err != nil {
		return nil, err
	}
	total := 16 + (int(buf[14])<<8 | int(buf[15]))
	full := make([]byte, total)
	copy(full, buf[:])
	if _, err := io.ReadFull(r, full[16:]); err != nil {
		return nil, err
	}
	_, hdr, _, err = ParseStreamStrict(full)
	return hdr, err
}
