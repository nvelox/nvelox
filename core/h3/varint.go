// Package h3 is HTTP/3 (RFC 9114) and QPACK (RFC 9204) on the wire, for
// the event loops: QUIC's variable-length integers, the frames and
// settings of request and control streams, and field sections coded
// against QPACK's static table. It holds no connection state and does no
// I/O.
package h3

// MaxVarint is the largest value a variable-length integer holds.
const MaxVarint = 1<<62 - 1

// Varint reads a variable-length integer (RFC 9000, section 16) from the
// start of b. n is its length in bytes, 0 when b does not hold all of it.
func Varint(b []byte) (v uint64, n int) {
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

// VarintLen returns the length of the shortest encoding of v.
func VarintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	}
	return 8
}

// AppendVarint appends the shortest encoding of v, which must not exceed
// MaxVarint (its two top bits are not kept).
func AppendVarint(dst []byte, v uint64) []byte {
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
