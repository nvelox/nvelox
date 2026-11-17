package h3

import (
	"errors"
	"strconv"

	"nvelox/core/h2"
)

// QPACK (RFC 9204) with a dynamic table of capacity 0, which is what this
// server offers (SETTINGS_QPACK_MAX_TABLE_CAPACITY is not sent, so it is 0)
// and uses: a field section refers to the static table or carries literals,
// and can be decoded by itself, in any order. The encoder and decoder
// streams then carry nothing.

// ErrFieldSection is a field section that cannot be decoded: the
// connection error QPACK_DECOMPRESSION_FAILED.
var ErrFieldSection = errors.New("h3: field section cannot be decoded")

// ErrStringLength is a string literal longer than the limit given to
// DecodeFields. Nothing else is wrong with the section (there is no table
// to keep in step), so this fails the request, not the connection.
var ErrStringLength = errors.New("h3: field string too long")

// staticBytes is the static table as byte strings, and staticByName the
// entries of each name, for the encoder.
var (
	staticBytes  [len(staticTable)]struct{ name, value []byte }
	staticByName = map[string][]uint8{}
)

func init() {
	for i, e := range staticTable {
		staticBytes[i].name, staticBytes[i].value = []byte(e.name), []byte(e.value)
		staticByName[e.name] = append(staticByName[e.name], uint8(i))
	}
}

// prefixInt reads an integer with an n-bit prefix (RFC 7541, section 5.1,
// which QPACK uses) from the start of p. ok is false when p ends inside it
// or it does not fit in 62 bits.
func prefixInt(p []byte, n uint) (v uint64, rest []byte, ok bool) {
	if len(p) == 0 {
		return 0, nil, false
	}
	mask := uint64(1)<<n - 1
	v = uint64(p[0]) & mask
	p = p[1:]
	if v < mask {
		return v, p, true
	}
	for shift := uint(0); ; shift += 7 {
		if len(p) == 0 || shift > 56 {
			return 0, nil, false
		}
		b := p[0]
		p = p[1:]
		v += uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			if v > MaxVarint {
				return 0, nil, false
			}
			return v, p, true
		}
	}
}

// DecodeFields decodes the field section p and calls emit for each field
// line, in order. The slices emit gets are valid during the call only: they
// point into p, into the static table (which must not be written to) or
// into *scratch, which holds the Huffman-coded strings of the field being
// emitted and may be reused by the caller afterwards. maxString bounds one
// decoded name or value.
//
// It returns ErrFieldSection for a section that is malformed or refers to
// the dynamic table, ErrStringLength for a string over the limit, and
// whatever emit returns.
func DecodeFields(p []byte, scratch *[]byte, maxString int, emit func(name, value []byte) error) error {
	// The prefix: Required Insert Count and Base. With no dynamic table the
	// count is 0: anything else refers to entries that do not exist. The
	// Base matters to dynamic references only, and a section without them
	// may carry any (RFC 9204, section 4.5.1.2): it is read and dropped,
	// its sign with it.
	ric, p, ok := prefixInt(p, 8)
	if !ok || ric != 0 {
		return ErrFieldSection
	}
	if len(p) == 0 {
		return ErrFieldSection
	}
	if _, p, ok = prefixInt(p, 7); !ok {
		return ErrFieldSection
	}
	for len(p) > 0 {
		b := p[0]
		var name, value []byte
		var err error
		buf := (*scratch)[:0]
		switch {
		case b&0x80 != 0: // 1T: indexed field line
			if b&0x40 == 0 {
				return ErrFieldSection // the dynamic table
			}
			var idx uint64
			if idx, p, ok = prefixInt(p, 6); !ok || idx >= uint64(len(staticBytes)) {
				return ErrFieldSection
			}
			name, value = staticBytes[idx].name, staticBytes[idx].value
		case b&0x40 != 0: // 01NT: literal field line with name reference
			if b&0x10 == 0 {
				return ErrFieldSection // the dynamic table
			}
			var idx uint64
			if idx, p, ok = prefixInt(p, 4); !ok || idx >= uint64(len(staticBytes)) {
				return ErrFieldSection
			}
			name = staticBytes[idx].name
			if value, p, buf, err = readString(p, 7, buf, maxString); err != nil {
				return err
			}
		case b&0x20 != 0: // 001NH: literal field line with literal name
			if name, p, buf, err = readString(p, 3, buf, maxString); err != nil {
				return err
			}
			if value, p, buf, err = readString(p, 7, buf, maxString); err != nil {
				return err
			}
		default: // 0001, 0000: post-base references, the dynamic table
			return ErrFieldSection
		}
		*scratch = buf
		if err := emit(name, value); err != nil {
			return err
		}
	}
	return nil
}

// readString reads a string literal whose length has an n-bit prefix, the
// bit above it saying whether it is Huffman coded. A Huffman-coded string is
// decoded into buf, which it returns grown.
func readString(p []byte, n uint, buf []byte, max int) (s, rest, bufOut []byte, err error) {
	if len(p) == 0 {
		return nil, nil, buf, ErrFieldSection
	}
	huff := p[0]&(1<<n) != 0
	l, p, ok := prefixInt(p, n)
	if !ok || l > uint64(len(p)) {
		return nil, nil, buf, ErrFieldSection
	}
	raw := p[:l]
	p = p[l:]
	if !huff {
		if len(raw) > max {
			return nil, nil, buf, ErrStringLength
		}
		return raw, p, buf, nil
	}
	start := len(buf)
	out, ok := h2.HuffmanDecode(buf, raw, start+max)
	if !ok {
		if len(out)-start >= max {
			return nil, nil, out, ErrStringLength
		}
		return nil, nil, out, ErrFieldSection
	}
	return out[start:], p, out, nil
}

// ---- encoding ----

// AppendPrefix appends the prefix of a field section that refers to no
// dynamic table entry.
func AppendPrefix(dst []byte) []byte { return append(dst, 0, 0) }

// appendPrefixInt appends v with an n-bit prefix under the bits of first.
func appendPrefixInt(dst []byte, first byte, n uint, v uint64) []byte {
	mask := uint64(1)<<n - 1
	if v < mask {
		return append(dst, first|byte(v))
	}
	dst = append(dst, first|byte(mask))
	v -= mask
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// appendString appends s as a string literal with an n-bit length prefix
// under the bits of first, Huffman coded when that is shorter.
func appendString(dst []byte, first byte, n uint, s []byte) []byte {
	if hl := h2.HuffmanEncodedLen(s); hl < len(s) {
		dst = appendPrefixInt(dst, first|1<<n, n, uint64(hl))
		return h2.AppendHuffman(dst, s)
	}
	dst = appendPrefixInt(dst, first, n, uint64(len(s)))
	return append(dst, s...)
}

// AppendField appends a field line. name must be in lower case.
func AppendField(dst, name, value []byte) []byte {
	ids := staticByName[string(name)]
	if len(ids) == 0 {
		// Literal field line with literal name.
		dst = appendString(dst, 0x20, 3, name)
		return appendString(dst, 0, 7, value)
	}
	for _, id := range ids {
		if string(staticBytes[id].value) == string(value) {
			return appendPrefixInt(dst, 0xc0, 6, uint64(id)) // indexed field line, static
		}
	}
	// Literal field line with a static name reference.
	dst = appendPrefixInt(dst, 0x50, 4, uint64(ids[0]))
	return appendString(dst, 0, 7, value)
}

// AppendStatus appends the :status field of a response.
func AppendStatus(dst []byte, code int) []byte {
	var b [3]byte
	return AppendField(dst, staticBytes[24].name, strconv.AppendInt(b[:0], int64(code), 10))
}
