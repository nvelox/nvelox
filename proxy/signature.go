package proxy

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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

// Signature errors, distinguishable for logging.
var (
	ErrSignatureMissing   = errors.New("PROXY header has no signature")
	ErrSignatureMalformed = errors.New("PROXY header signature is malformed")
	ErrSignatureExpired   = errors.New("PROXY header signature is outside the time window")
	ErrSignatureInvalid   = errors.New("PROXY header signature does not match any key")
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

// Verify checks that h carries a signature made at most SignatureWindow from
// now with one of keys over h and payload (nil for a stream).
func Verify(h *proxyproto.Header, keys [][]byte, payload []byte, now time.Time) error {
	tlvs, err := h.TLVs()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureMalformed, err)
	}
	var v []byte
	for _, t := range tlvs {
		if t.Type == SignatureTLV {
			v = t.Value
			break
		}
	}
	if v == nil {
		return ErrSignatureMissing
	}
	if len(v) != signatureLen || v[0] != signatureVersion {
		return ErrSignatureMalformed
	}
	ts := binary.BigEndian.Uint64(v[1:9])
	if d := now.Sub(time.Unix(int64(ts), 0)); d > SignatureWindow || d < -SignatureWindow {
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

// SignHeader adds a stream signature TLV to h, computed over h as the
// receiver will parse it.
func SignHeader(h *proxyproto.Header, key []byte, now time.Time) error {
	raw, err := h.Format()
	if err != nil {
		return err
	}
	parsed, err := proxyproto.Read(bufioReader(raw))
	if err != nil {
		return fmt.Errorf("parse own PROXY header: %w", err)
	}
	t, err := Sign(key, parsed, nil, now)
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
// with a signature TLV for payload appended, its length field updated.
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
	srcIP, srcPort, err := addrParts(h.SourceAddr)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	dstIP, dstPort, err := addrParts(h.DestinationAddr)
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	m := hmac.New(sha256.New, key)
	m.Write(signatureDomain)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], ts)
	m.Write(b[:])
	m.Write([]byte{byte(h.TransportProtocol)})
	m.Write(srcIP)
	binary.BigEndian.PutUint16(b[:2], srcPort)
	m.Write(b[:2])
	m.Write(dstIP)
	binary.BigEndian.PutUint16(b[:2], dstPort)
	m.Write(b[:2])
	m.Write(payload)
	return m.Sum(nil), nil
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
