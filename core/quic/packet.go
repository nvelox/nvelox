package quic

import (
	"encoding/binary"
	"errors"
)

// Long header packet types (RFC 9000, section 17.2).
const (
	PacketInitial   = 0
	Packet0RTT      = 1
	PacketHandshake = 2
	PacketRetry     = 3
	// PacketShort is a 1-RTT packet, which has a short header.
	PacketShort = 4
)

// MaxCIDLen is the longest connection ID of version 1.
const MaxCIDLen = 20

// MinInitialSize is the smallest datagram that may carry a client's
// Initial packet (RFC 9000, section 14.1): smaller ones are dropped.
const MinInitialSize = 1200

// Errors of ParseHeader. All of them mean: drop the packet.
var (
	// ErrHeader is a header that does not parse.
	ErrHeader = errors.New("quic: malformed packet header")
	// ErrVersion is a long header of a version this endpoint does not
	// speak; the header's connection IDs are parsed (a Version Negotiation
	// packet answers it).
	ErrVersion = errors.New("quic: unsupported version")
)

// Header is the part of a packet header that is not protected.
type Header struct {
	Type    uint8  // PacketInitial ... PacketShort
	Version uint32 // long headers
	DCID    []byte // slices of the packet
	SCID    []byte // long headers
	Token   []byte // Initial packets
	// PNOff is where the packet number starts; End where the packet ends
	// in its datagram (another packet may follow a long header one).
	PNOff int
	End   int
}

// varint reads a variable-length integer (RFC 9000, section 16); n is 0
// when b does not hold all of it.
func varint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

// appendVarint appends the shortest encoding of v.
func appendVarint(dst []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(dst, byte(v))
	case v < 1<<14:
		return append(dst, 0x40|byte(v>>8), byte(v))
	case v < 1<<30:
		return append(dst, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return append(dst, 0xc0|byte(v>>56)&0x3f, byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ParseHeader parses the unprotected part of the header of the packet at
// the start of b, the rest of a datagram. cidLen is the length of the
// connection IDs this endpoint issues: a short header does not say where
// its Destination Connection ID ends.
//
// For ErrVersion the header's Version, DCID and SCID are set. A Retry
// packet's token and tag, and the versions of a Version Negotiation packet
// (Version 0), are what follows PNOff.
func ParseHeader(b []byte, cidLen int) (h Header, err error) {
	if len(b) == 0 {
		return h, ErrHeader
	}
	if b[0]&0x80 == 0 {
		// Short header: flags, Destination Connection ID, packet number.
		if b[0]&0x40 == 0 || len(b) < 1+cidLen {
			return h, ErrHeader
		}
		h.Type = PacketShort
		h.DCID = b[1 : 1+cidLen]
		h.PNOff = 1 + cidLen
		h.End = len(b)
		return h, nil
	}
	if len(b) < 7 {
		return h, ErrHeader
	}
	h.Version = binary.BigEndian.Uint32(b[1:5])
	p := 5
	dl := int(b[p])
	p++
	if dl > len(b)-p {
		return h, ErrHeader
	}
	h.DCID = b[p : p+dl]
	p += dl
	if p >= len(b) {
		return h, ErrHeader
	}
	sl := int(b[p])
	p++
	if sl > len(b)-p {
		return h, ErrHeader
	}
	h.SCID = b[p : p+sl]
	p += sl
	h.PNOff, h.End = p, len(b)
	if h.Version == 0 {
		return h, nil // Version Negotiation: any lengths, no type
	}
	if h.Version != Version1 {
		return h, ErrVersion
	}
	// Version 1: the fixed bit, and connection IDs of at most 20 bytes.
	if b[0]&0x40 == 0 || dl > MaxCIDLen || sl > MaxCIDLen {
		return h, ErrHeader
	}
	h.Type = b[0] >> 4 & 0x03
	if h.Type == PacketRetry {
		return h, nil
	}
	if h.Type == PacketInitial {
		tl, n := varint(b[p:])
		if n == 0 || tl > uint64(len(b)-p-n) {
			return h, ErrHeader
		}
		p += n
		h.Token = b[p : p+int(tl)]
		p += int(tl)
	}
	length, n := varint(b[p:])
	if n == 0 || length > uint64(len(b)-p-n) {
		return h, ErrHeader
	}
	p += n
	h.PNOff = p
	h.End = p + int(length)
	return h, nil
}

// pnLenFor returns how many bytes carry packet number pn so that the peer,
// which has acknowledged up to largestAcked (-1: nothing), recovers it:
// twice the distance must fit (RFC 9000, section 17.1).
func pnLenFor(pn, largestAcked int64) int {
	d := uint64(pn-largestAcked) * 2
	switch {
	case d < 1<<8:
		return 1
	case d < 1<<16:
		return 2
	case d < 1<<24:
		return 3
	}
	return 4
}

// AppendLongHeader appends a version 1 long header of the given type up to
// and including the packet number, and returns the offsets of the Length
// field (always two bytes: set it with SetLength once the payload is known)
// and of the packet number. token is used by Initial packets only.
func AppendLongHeader(dst []byte, typ uint8, dcid, scid, token []byte, pn int64, pnLen int) (out []byte, lenOff, pnOff int) {
	dst = append(dst, 0xc0|typ<<4|byte(pnLen-1))
	dst = binary.BigEndian.AppendUint32(dst, Version1)
	dst = append(dst, byte(len(dcid)))
	dst = append(dst, dcid...)
	dst = append(dst, byte(len(scid)))
	dst = append(dst, scid...)
	if typ == PacketInitial {
		dst = appendVarint(dst, uint64(len(token)))
		dst = append(dst, token...)
	}
	lenOff = len(dst)
	dst = append(dst, 0x40, 0) // Length, as a two-byte variable-length integer
	pnOff = len(dst)
	return appendPN(dst, pn, pnLen), lenOff, pnOff
}

// SetLength writes the Length of a long header packet whose packet number
// starts at pnOff and whose payload ends at the end of b, counting the tag
// Seal will add: call it when the payload is complete and before Seal (the
// header, Length included, is authenticated).
func SetLength(b []byte, lenOff, pnOff int) {
	n := len(b) - pnOff + Overhead
	b[lenOff], b[lenOff+1] = 0x40|byte(n>>8), byte(n)
}

// AppendShortHeader appends a 1-RTT packet's header: the flags (with the
// key phase), the peer's connection ID and the packet number. It returns
// the offset of the packet number.
func AppendShortHeader(dst []byte, dcid []byte, keyPhase bool, pn int64, pnLen int) (out []byte, pnOff int) {
	first := byte(0x40 | (pnLen - 1))
	if keyPhase {
		first |= 0x04
	}
	dst = append(dst, first)
	dst = append(dst, dcid...)
	pnOff = len(dst)
	return appendPN(dst, pn, pnLen), pnOff
}

func appendPN(dst []byte, pn int64, pnLen int) []byte {
	for i := pnLen - 1; i >= 0; i-- {
		dst = append(dst, byte(pn>>(8*uint(i))))
	}
	return dst
}

// AppendRetry appends a Retry packet answering a client's Initial packet
// whose connection IDs were dcid and scid: the client is to send its
// Initial packets again, with token, to the connection ID newCID. first is
// a byte the client cannot predict (four bits of it are used).
func AppendRetry(dst []byte, first byte, dcid, scid, newCID, token []byte) []byte {
	start := len(dst)
	dst = append(dst, 0xc0|PacketRetry<<4|first&0x0f)
	dst = binary.BigEndian.AppendUint32(dst, Version1)
	dst = append(dst, byte(len(scid)))
	dst = append(dst, scid...)
	dst = append(dst, byte(len(newCID)))
	dst = append(dst, newCID...)
	dst = append(dst, token...)
	retry := append([]byte(nil), dst[start:]...)
	return append(dst[:start], AppendRetryTag(retry, dcid)...)
}

// AppendVersionNegotiation appends a Version Negotiation packet answering
// a packet whose connection IDs were dcid and scid: they come back swapped,
// with the one version this endpoint speaks. first is a byte the sender
// cannot predict (its top bit is set here; the rest is unused).
func AppendVersionNegotiation(dst []byte, first byte, dcid, scid []byte) []byte {
	dst = append(dst, 0x80|first, 0, 0, 0, 0)
	dst = append(dst, byte(len(scid)))
	dst = append(dst, scid...)
	dst = append(dst, byte(len(dcid)))
	dst = append(dst, dcid...)
	return binary.BigEndian.AppendUint32(dst, Version1)
}
