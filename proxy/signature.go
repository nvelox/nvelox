package proxy

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

// Signed PROXY v2 headers.
//
// A receiver that trusts a relay's PROXY header by the relay's source address
// alone can be fooled over UDP, where a datagram can claim any source. With a
// shared key, the sender adds a signature TLV and the receiver accepts the
// header only with a valid signature:
//
//	type   0xE4 (PP2 application-specific range)
//	value  version (1 byte, 1) | unix time in seconds (8 bytes, big-endian) |
//	       HMAC-SHA256 (32 bytes)
//
// The HMAC covers the string "nvelox PROXY v2 signature v1", the timestamp,
// the transport protocol byte, the source and destination address (16 bytes
// each, IPv4 in IPv4-mapped form) and ports (2 bytes each, big-endian), and
// for a datagram the payload that follows the header. Other TLVs are not
// covered. A signature is valid for SignatureWindow either side of the
// receiver's clock.
const (
	SignatureTLV    proxyproto.PP2Type = 0xE4
	SignatureWindow                    = 30 * time.Second

	signatureVersion = 1
	signatureLen     = 1 + 8 + sha256.Size
)

var signatureDomain = []byte("nvelox PROXY v2 signature v1")

// Version 2 (accept_proxy_replay_window) binds a header to the relay socket
// that sent it and numbers that socket's headers, so that a copy of one is
// refused:
//
//	type   0xE4, as version 1
//	value  version (1 byte, 2) | unix time in seconds (8 bytes) |
//	       counter (8 bytes) | HMAC-SHA256 (32 bytes)
//
// The HMAC covers the string "nvelox PROXY v2 signature v2", the time, the
// counter, the relay socket's port as the receiver sees it (2 bytes: the
// source port of the datagram, or of the connection, that carries the
// header), and then what version 1 covers. Numbers are big-endian. The
// counter is the relay socket's: it starts at the relay's clock in
// nanoseconds when the socket opens and goes up by one with every header,
// so that a relay that opens a socket on the same port again counts on above
// its last header. A receiver keeps a ReplayWindow per relay socket. A
// stream has one header, bound to its connection by the port: its counter
// is 0 and not looked at.
const (
	signatureV2    = 2
	signatureV2Len = 1 + 8 + 8 + sha256.Size
)

var signatureDomainV2 = []byte("nvelox PROXY v2 signature v2")

// Signature errors, distinguishable for logging.
var (
	ErrSignatureMissing   = errors.New("PROXY header has no signature")
	ErrSignatureMalformed = errors.New("PROXY header signature is malformed")
	ErrSignatureExpired   = errors.New("PROXY header signature is outside the time window")
	ErrSignatureInvalid   = errors.New("PROXY header signature does not match any key")
	// ErrSignatureUncounted: a version 1 signature, which has no counter,
	// where the listener requires one (accept_proxy_replay_window:
	// required).
	ErrSignatureUncounted = errors.New("PROXY header signature has no counter (version 1), and the listener requires one")
	// ErrReplayed: the relay socket's counter was taken before, or is older
	// than its window (ReplayWindow).
	ErrReplayed = errors.New("PROXY header counter was taken from this relay socket before, or is older than its window")
)

// Sign returns the signature TLV for header h (as the receiver will parse it)
// and payload (nil for a stream), made with key at now.
func Sign(key []byte, h *proxyproto.Header, payload []byte, now time.Time) (proxyproto.TLV, error) {
	ts := uint64(now.Unix())
	mac, err := signatureMAC(key, h, ts, payload)
	if err != nil {
		return proxyproto.TLV{}, err
	}
	v := make([]byte, signatureLen)
	v[0] = signatureVersion
	binary.BigEndian.PutUint64(v[1:9], ts)
	copy(v[9:], mac)
	return proxyproto.TLV{Type: SignatureTLV, Value: v}, nil
}

// SignFrom returns the version 2 signature TLV for header h (as the receiver
// will parse it) and payload (nil for a stream), made with key at now for
// the relay socket that sends from port relayPort, as its header number
// counter.
func SignFrom(key []byte, h *proxyproto.Header, payload []byte, now time.Time, relayPort uint16, counter uint64) (proxyproto.TLV, error) {
	ts := uint64(now.Unix())
	mac, err := signatureMACv2(key, h, ts, counter, relayPort, payload)
	if err != nil {
		return proxyproto.TLV{}, err
	}
	v := make([]byte, signatureV2Len)
	v[0] = signatureV2
	binary.BigEndian.PutUint64(v[1:9], ts)
	binary.BigEndian.PutUint64(v[9:17], counter)
	copy(v[17:], mac)
	return proxyproto.TLV{Type: SignatureTLV, Value: v}, nil
}

// Verify checks that h carries a version 1 signature made at most
// SignatureWindow from now with one of keys over h and payload (nil for a
// stream).
func Verify(h *proxyproto.Header, keys [][]byte, payload []byte, now time.Time) error {
	v, err := signatureValue(h)
	if err != nil {
		return err
	}
	if len(v) != signatureLen || v[0] != signatureVersion {
		return ErrSignatureMalformed
	}
	return verifyV1(h, keys, payload, now, v)
}

// VerifyFrom checks that h carries a signature made at most SignatureWindow
// from now with one of keys over h and payload (nil for a stream). A version
// 2 signature must have been made for the relay socket port relayPort, the
// port the header came from: its counter is returned, with counted true. A
// version 1 signature has no counter and is bound to no port: counted
// false.
func VerifyFrom(h *proxyproto.Header, keys [][]byte, payload []byte, now time.Time, relayPort uint16) (counter uint64, counted bool, err error) {
	v, err := signatureValue(h)
	if err != nil {
		return 0, false, err
	}
	switch {
	case len(v) == signatureLen && v[0] == signatureVersion:
		return 0, false, verifyV1(h, keys, payload, now, v)
	case len(v) == signatureV2Len && v[0] == signatureV2:
	default:
		return 0, false, ErrSignatureMalformed
	}
	ts, counter := binary.BigEndian.Uint64(v[1:9]), binary.BigEndian.Uint64(v[9:17])
	if expired(ts, now) {
		return 0, false, ErrSignatureExpired
	}
	for _, k := range keys {
		mac, err := signatureMACv2(k, h, ts, counter, relayPort, payload)
		if err != nil {
			return 0, false, fmt.Errorf("%w: %v", ErrSignatureMalformed, err)
		}
		if hmac.Equal(mac, v[17:]) {
			return counter, true, nil
		}
	}
	return 0, false, ErrSignatureInvalid
}

// signatureValue returns the value of h's (first) signature TLV.
func signatureValue(h *proxyproto.Header) ([]byte, error) {
	tlvs, err := h.TLVs()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureMalformed, err)
	}
	for _, t := range tlvs {
		if t.Type == SignatureTLV {
			return t.Value, nil
		}
	}
	return nil, ErrSignatureMissing
}

// verifyV1 checks the version 1 signature value v of h.
func verifyV1(h *proxyproto.Header, keys [][]byte, payload []byte, now time.Time, v []byte) error {
	ts := binary.BigEndian.Uint64(v[1:9])
	if expired(ts, now) {
		return ErrSignatureExpired
	}
	for _, k := range keys {
		mac, err := signatureMAC(k, h, ts, payload)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSignatureMalformed, err)
		}
		if hmac.Equal(mac, v[9:]) {
			return nil
		}
	}
	return ErrSignatureInvalid
}

// expired reports whether a signature made at the unix time ts is outside
// SignatureWindow either side of now.
func expired(ts uint64, now time.Time) bool {
	d := now.Sub(time.Unix(int64(ts), 0))
	return d > SignatureWindow || d < -SignatureWindow
}

// SignHeader adds a version 1 stream signature TLV to h, computed over h as
// the receiver will parse it.
func SignHeader(h *proxyproto.Header, key []byte, now time.Time) error {
	return signHeader(h, func(parsed *proxyproto.Header) (proxyproto.TLV, error) { return Sign(key, parsed, nil, now) })
}

// SignHeaderFrom adds a version 2 stream signature TLV to h, computed over h
// as the receiver will parse it, for the connection that leaves from port
// relayPort (its counter is 0: a stream has one header).
func SignHeaderFrom(h *proxyproto.Header, key []byte, now time.Time, relayPort uint16) error {
	return signHeader(h, func(parsed *proxyproto.Header) (proxyproto.TLV, error) {
		return SignFrom(key, parsed, nil, now, relayPort, 0)
	})
}

func signHeader(h *proxyproto.Header, sign func(parsed *proxyproto.Header) (proxyproto.TLV, error)) error {
	raw, err := h.Format()
	if err != nil {
		return err
	}
	parsed, err := proxyproto.Read(bufioReader(raw))
	if err != nil {
		return fmt.Errorf("parse own PROXY header: %w", err)
	}
	t, err := sign(parsed)
	if err != nil {
		return err
	}
	tlvs, err := h.TLVs()
	if err != nil {
		return err
	}
	return h.SetTLVs(append(tlvs, t))
}

// SignedHeaderBytes returns header (a complete PROXY v2 header as written)
// with a version 1 signature TLV for payload appended, its length field
// updated.
func SignedHeaderBytes(header []byte, key []byte, payload []byte, now time.Time) ([]byte, error) {
	h, err := proxyproto.Read(bufioReader(header))
	if err != nil {
		return nil, fmt.Errorf("parse own PROXY header: %w", err)
	}
	t, err := Sign(key, h, payload, now)
	if err != nil {
		return nil, err
	}
	return AppendTLV(header, t)
}

// SignedHeaderBytesFrom is SignedHeaderBytes with a version 2 signature, for
// the relay socket that sends from port relayPort, as its header number
// counter.
func SignedHeaderBytesFrom(header []byte, key []byte, payload []byte, now time.Time, relayPort uint16, counter uint64) ([]byte, error) {
	h, err := proxyproto.Read(bufioReader(header))
	if err != nil {
		return nil, fmt.Errorf("parse own PROXY header: %w", err)
	}
	t, err := SignFrom(key, h, payload, now, relayPort, counter)
	if err != nil {
		return nil, err
	}
	return AppendTLV(header, t)
}

// AppendTLV appends t to a complete PROXY v2 header and updates its length.
func AppendTLV(header []byte, t proxyproto.TLV) ([]byte, error) {
	if len(header) < 16 {
		return nil, errors.New("PROXY v2 header too short")
	}
	n := int(binary.BigEndian.Uint16(header[14:16])) + 3 + len(t.Value)
	if n > 0xFFFF || len(t.Value) > 0xFFFF {
		return nil, errors.New("PROXY v2 header too long")
	}
	out := make([]byte, 0, len(header)+3+len(t.Value))
	out = append(out, header...)
	out = append(out, byte(t.Type), byte(len(t.Value)>>8), byte(len(t.Value)))
	out = append(out, t.Value...)
	binary.BigEndian.PutUint16(out[14:16], uint16(n))
	return out, nil
}

func signatureMAC(key []byte, h *proxyproto.Header, ts uint64, payload []byte) ([]byte, error) {
	m := hmac.New(sha256.New, key)
	m.Write(signatureDomain)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], ts)
	m.Write(b[:])
	if err := writeHeaderParts(m, h); err != nil {
		return nil, err
	}
	m.Write(payload)
	return m.Sum(nil), nil
}

func signatureMACv2(key []byte, h *proxyproto.Header, ts, counter uint64, relayPort uint16, payload []byte) ([]byte, error) {
	m := hmac.New(sha256.New, key)
	m.Write(signatureDomainV2)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], ts)
	m.Write(b[:])
	binary.BigEndian.PutUint64(b[:], counter)
	m.Write(b[:])
	binary.BigEndian.PutUint16(b[:2], relayPort)
	m.Write(b[:2])
	if err := writeHeaderParts(m, h); err != nil {
		return nil, err
	}
	m.Write(payload)
	return m.Sum(nil), nil
}

// writeHeaderParts writes what a signature covers of h: the transport
// protocol byte, the source address and port, the destination address and
// port (16 bytes each address, IPv4 in IPv4-mapped form).
func writeHeaderParts(m io.Writer, h *proxyproto.Header) error {
	srcIP, srcPort, err := addrParts(h.SourceAddr)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	dstIP, dstPort, err := addrParts(h.DestinationAddr)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	var b [2]byte
	m.Write([]byte{byte(h.TransportProtocol)})
	m.Write(srcIP)
	binary.BigEndian.PutUint16(b[:], srcPort)
	m.Write(b[:])
	m.Write(dstIP)
	binary.BigEndian.PutUint16(b[:], dstPort)
	m.Write(b[:])
	return nil
}

// ReplayWindow is what a receiver keeps of one relay socket's counters
// (accept_proxy_replay_window): the highest it took, and which of the 63
// below that it took, as IPsec and WireGuard keep theirs. A datagram that
// arrives out of order within those 64 passes; a counter taken before, or
// older than that, does not. The zero value has taken none.
type ReplayWindow struct {
	top, seen uint64 // bit i of seen: counter top-i was taken
	started   bool
}

// Take reports whether counter c is new to the window, and notes it when it
// is.
func (w *ReplayWindow) Take(c uint64) bool {
	switch {
	case !w.started:
		w.top, w.seen, w.started = c, 1, true
		return true
	case c > w.top:
		if d := c - w.top; d < 64 {
			w.seen = w.seen<<d | 1
		} else {
			w.seen = 1
		}
		w.top = c
		return true
	}
	d := w.top - c
	if d >= 64 || w.seen&(1<<d) != 0 {
		return false
	}
	w.seen |= 1 << d
	return true
}

func addrParts(a net.Addr) (net.IP, uint16, error) {
	var ip net.IP
	var port int
	switch v := a.(type) {
	case *net.TCPAddr:
		ip, port = v.IP, v.Port
	case *net.UDPAddr:
		ip, port = v.IP, v.Port
	default:
		return nil, 0, fmt.Errorf("unsupported address %T", a)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, 0, errors.New("no IP address")
	}
	return ip16, uint16(port), nil
}

func bufioReader(b []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(b)) }
