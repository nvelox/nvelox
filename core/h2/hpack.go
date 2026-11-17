package h2

import (
	"errors"
	"strconv"
)

// HPACK (RFC 7541): a decoder for request header blocks and a stateless
// encoder for response header blocks.

// MaxTableSize is the dynamic table size the decoder offers its peer
// (SETTINGS_HEADER_TABLE_SIZE): the protocol's default.
const MaxTableSize = 4096

// maxDynEntries is how many entries fit in a table of MaxTableSize: an
// entry counts 32 bytes besides its name and value.
const maxDynEntries = MaxTableSize / 32

// ErrCompression is a header block that cannot be decoded: the connection
// error COMPRESSION_ERROR.
var ErrCompression = errors.New("h2: header block cannot be decoded")

// ErrStringLength is a string literal longer than the decoder's limit. The
// table can no longer be kept in step with the peer's, so this ends the
// connection too.
var ErrStringLength = errors.New("h2: header string too long")

// Decoder decodes the header blocks of one connection, in order. It keeps
// the dynamic table in a fixed 4 KiB of its own; nothing it is given is
// kept.
type Decoder struct {
	// MaxString bounds the length of a decoded name or value.
	MaxString int

	maxSize uint32 // the table's size limit (set by the peer's size updates)
	size    uint32 // the table's size, as the RFC counts it
	ents    [maxDynEntries]dynEntry
	head    int // index in ents of the newest entry
	n       int // entries in the table
	buf     [MaxTableSize]byte
	end     int // buf[:end] holds the entries' bytes, oldest first (with gaps before the oldest)

	// saved is the start of a representation whose end has not arrived
	// (a header block comes in fragments).
	saved []byte
	// fields: a field was decoded in this block (a table size update is
	// allowed only before the first one).
	fields  bool
	scratch []byte // one field's decoded strings
}

type dynEntry struct {
	off        uint16
	nlen, vlen uint16
}

// NewDecoder returns a decoder with an empty table of MaxTableSize.
func NewDecoder(maxString int) *Decoder {
	return &Decoder{MaxString: maxString, maxSize: MaxTableSize}
}

// Reset empties the table and forgets an unfinished block (a new
// connection).
func (d *Decoder) Reset() {
	d.maxSize, d.size, d.head, d.n, d.end = MaxTableSize, 0, 0, 0, 0
	d.saved, d.fields = d.saved[:0], false
}

// Write decodes the next fragment of a header block and calls emit for
// every field it completes. name and value are valid only during the call.
// An error of emit stops the decoding and is returned; the decoder is then
// out of step with its peer, like after any other error, and the
// connection has to end.
func (d *Decoder) Write(p []byte, emit func(name, value []byte, sensitive bool) error) error {
	if len(d.saved) > 0 {
		// A representation straddles two fragments: decode from a copy
		// of both.
		d.saved = append(d.saved, p...)
		p = d.saved
	}
	for len(p) > 0 {
		n, err := d.one(p, emit)
		if err != nil {
			return err
		}
		if n == 0 {
			break // incomplete: wait for the next fragment
		}
		p = p[n:]
	}
	if len(p) > 0 && (len(d.saved) == 0 || &p[0] != &d.saved[0]) {
		d.saved = append(d.saved[:0], p...)
	} else if len(p) == 0 {
		d.saved = d.saved[:0]
	}
	return nil
}

// Close ends a header block. A block that stops in the middle of a
// representation is an error.
func (d *Decoder) Close() error {
	d.fields = false
	cut := len(d.saved) > 0
	// A block with a very long field does not leave its buffers behind.
	if cap(d.saved) > decoderKeep {
		d.saved = nil
	}
	if cap(d.scratch) > decoderKeep {
		d.scratch = nil
	}
	d.saved = d.saved[:0]
	if cut {
		return ErrCompression
	}
	return nil
}

// decoderKeep is how much buffer a decoder keeps between header blocks.
const decoderKeep = 16 << 10

// one decodes the representation at the start of p. It returns how many
// bytes it took: 0 when p ends before the representation does.
func (d *Decoder) one(p []byte, emit func(name, value []byte, sensitive bool) error) (int, error) {
	b := p[0]
	switch {
	case b&0x80 != 0:
		// Indexed header field. An index below 127 is this one byte.
		idx, n := uint64(b&0x7f), 1
		if idx == 0x7f {
			var err error
			if idx, n, err = readInt(p, 7); n == 0 || err != nil {
				return 0, err
			}
		}
		name, value, ok := d.at(idx)
		if !ok {
			return 0, ErrCompression
		}
		d.fields = true
		return n, emit(name, value, false)
	case b&0xc0 == 0x40:
		return d.literal(p, 6, true, false, emit)
	case b&0xe0 == 0x20:
		// Dynamic table size update: never above what this decoder
		// offered. It belongs before the block's first field (several may
		// come there: the smallest size since the last block, then the
		// final one). After a field it is refused, unless the table is
		// empty, where Go's decoder lets it pass and it changes nothing
		// that was decoded.
		size, n, err := readInt(p, 5)
		if n == 0 || err != nil {
			return 0, err
		}
		if d.fields && d.size > 0 || size > MaxTableSize {
			return 0, ErrCompression
		}
		d.maxSize = uint32(size)
		d.evict(0)
		return n, nil
	default:
		// Literal without indexing (0000) or never indexed (0001).
		return d.literal(p, 4, false, b&0x10 != 0, emit)
	}
}

// literal decodes a literal field whose name index has a prefix of the
// given bits.
func (d *Decoder) literal(p []byte, prefix uint, index, sensitive bool, emit func(name, value []byte, sensitive bool) error) (int, error) {
	idx, n, err := readInt(p, prefix)
	if n == 0 || err != nil {
		return 0, err
	}
	d.scratch = d.scratch[:0]
	var name []byte
	fromTable := false
	if idx == 0 {
		var used int
		if name, used, err = d.str(p[n:]); used == 0 || err != nil {
			return 0, err
		}
		n += used
	} else {
		var ok bool
		if name, _, ok = d.at(idx); !ok {
			return 0, ErrCompression
		}
		fromTable = idx > uint64(len(staticTable)-1)
	}
	value, used, err := d.str(p[n:])
	if used == 0 || err != nil {
		return 0, err
	}
	n += used
	d.fields = true
	if index {
		if fromTable {
			// The entry the name comes from may be evicted, or moved, by
			// the insertion: take the name out first. (A value decoded
			// into scratch stays where it is if this append moves scratch.)
			at := len(d.scratch)
			d.scratch = append(d.scratch, name...)
			name = d.scratch[at:]
		}
		d.insert(name, value)
	}
	return n, emit(name, value, sensitive)
}

// str decodes the string literal at the start of p. It returns the string
// and how many bytes it took: 0 when p ends before the string does. A
// Huffman-coded string is decoded into d.scratch.
func (d *Decoder) str(p []byte) ([]byte, int, error) {
	if len(p) == 0 {
		return nil, 0, nil
	}
	huff := p[0]&0x80 != 0
	l, n, err := readInt(p, 7)
	if n == 0 || err != nil {
		return nil, 0, err
	}
	// The length is checked before anything is buffered or decoded.
	if l > uint64(d.MaxString) {
		return nil, 0, ErrStringLength
	}
	if uint64(len(p)-n) < l {
		return nil, 0, nil
	}
	raw := p[n : n+int(l)]
	if !huff {
		return raw, n + int(l), nil
	}
	at := len(d.scratch)
	var ok bool
	d.scratch, ok = huffDecode(d.scratch, raw, at+d.MaxString)
	if !ok {
		if len(d.scratch)-at >= d.MaxString {
			return nil, 0, ErrStringLength
		}
		return nil, 0, ErrCompression
	}
	return d.scratch[at:], n + int(l), nil
}

// at returns the entry at an HPACK index: the static table first, then the
// dynamic table from its newest entry on.
func (d *Decoder) at(idx uint64) (name, value []byte, ok bool) {
	if idx == 0 {
		return nil, nil, false
	}
	if idx < uint64(len(staticTable)) {
		e := &staticBytes[idx]
		return e.name, e.value, true
	}
	i := idx - uint64(len(staticTable))
	if i >= uint64(d.n) {
		return nil, nil, false
	}
	e := &d.ents[(d.head-int(i)+maxDynEntries)%maxDynEntries]
	return d.buf[e.off : e.off+e.nlen], d.buf[int(e.off)+int(e.nlen) : int(e.off)+int(e.nlen)+int(e.vlen)], true
}

// evict drops the oldest entries until need more bytes fit under the size
// limit.
func (d *Decoder) evict(need uint32) {
	for d.n > 0 && d.size+need > d.maxSize {
		oldest := &d.ents[(d.head-d.n+1+maxDynEntries)%maxDynEntries]
		d.size -= uint32(oldest.nlen) + uint32(oldest.vlen) + 32
		d.n--
	}
	if d.n == 0 {
		d.end = 0
	}
}

// insert adds an entry as the newest. name and value must not point into
// the table.
func (d *Decoder) insert(name, value []byte) {
	need := uint32(len(name)) + uint32(len(value)) + 32
	if need > d.maxSize {
		// Larger than the whole table: the table is emptied.
		d.n, d.size, d.end = 0, 0, 0
		return
	}
	d.evict(need)
	l := len(name) + len(value)
	if d.end+l > len(d.buf) {
		// Close the gaps the evicted entries left at the start.
		w := 0
		for i := d.n - 1; i >= 0; i-- {
			e := &d.ents[(d.head-i+maxDynEntries)%maxDynEntries]
			n := int(e.nlen) + int(e.vlen)
			copy(d.buf[w:], d.buf[e.off:int(e.off)+n])
			e.off = uint16(w)
			w += n
		}
		d.end = w
	}
	d.head = (d.head + 1) % maxDynEntries
	e := &d.ents[d.head]
	e.off, e.nlen, e.vlen = uint16(d.end), uint16(len(name)), uint16(len(value))
	copy(d.buf[d.end:], name)
	copy(d.buf[d.end+len(name):], value)
	d.end += l
	d.size += need
	d.n++
}

// readInt decodes the integer at the start of p whose first byte holds
// prefix bits of it (RFC 7541, section 5.1). It returns the value and how
// many bytes it took: 0 when p ends before the integer does.
func readInt(p []byte, prefix uint) (uint64, int, error) {
	if len(p) == 0 {
		return 0, 0, nil
	}
	mask := uint64(1)<<prefix - 1
	v := uint64(p[0]) & mask
	if v < mask {
		return v, 1, nil
	}
	shift := uint(0)
	for i := 1; i < len(p); i++ {
		b := p[i]
		v += uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, i + 1, nil
		}
		shift += 7
		if shift >= 63 {
			// Go's limit: an integer may be padded with empty groups of
			// bits, up to ten bytes in all. What it then amounts to is
			// checked by its user (an index, a length, a table size).
			return 0, 0, ErrCompression
		}
	}
	return 0, 0, nil
}

// appendInt appends v as an integer with prefix bits in its first byte,
// whose other bits are high.
func appendInt(dst []byte, high byte, prefix uint, v uint64) []byte {
	mask := uint64(1)<<prefix - 1
	if v < mask {
		return append(dst, high|byte(v))
	}
	dst = append(dst, high|byte(mask))
	v -= mask
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// The encoder is stateless: it refers to the static table and sends
// everything else as a literal that is not added to the table, so a
// response head can be built from buffers that are reused at once, and one
// connection's output never depends on another's.

var (
	staticNames = map[string]uint8{} // the lowest index of each name
	// staticBytes is staticTable as byte slices, for the decoder.
	staticBytes [len(staticTable)]struct{ name, value []byte }
)

func init() {
	for i := len(staticTable) - 1; i >= 1; i-- {
		e := staticTable[i]
		staticNames[e.name] = uint8(i)
		staticBytes[i].name, staticBytes[i].value = []byte(e.name), []byte(e.value)
	}
}

// AppendTableSize appends a dynamic table size update. A header block may
// start with one; an encoder that keeps no table says so with size 0.
func AppendTableSize(dst []byte, size uint32) []byte {
	return appendInt(dst, 0x20, 5, uint64(size))
}

// AppendStatus appends the :status field of a response.
func AppendStatus(dst []byte, code int) []byte {
	switch code {
	case 200:
		return append(dst, 0x80|8)
	case 204:
		return append(dst, 0x80|9)
	case 206:
		return append(dst, 0x80|10)
	case 304:
		return append(dst, 0x80|11)
	case 400:
		return append(dst, 0x80|12)
	case 404:
		return append(dst, 0x80|13)
	case 500:
		return append(dst, 0x80|14)
	}
	dst = append(dst, 0x08) // literal without indexing, name = index 8 (:status)
	var b [3]byte
	return appendString(dst, strconv.AppendInt(b[:0], int64(code), 10))
}

// AppendField appends a field whose name is already in lower case.
func AppendField(dst, name, value []byte) []byte {
	if idx, ok := staticNames[string(name)]; ok {
		dst = appendInt(dst, 0x00, 4, uint64(idx))
	} else {
		dst = append(dst, 0x00)
		dst = appendString(dst, name)
	}
	return appendString(dst, value)
}

// appendString appends s as a string literal, Huffman coded when that is
// shorter.
func appendString(dst, s []byte) []byte {
	if hl := huffEncodedLen(s); hl < len(s) {
		dst = appendInt(dst, 0x80, 7, uint64(hl))
		return appendHuff(dst, s)
	}
	dst = appendInt(dst, 0x00, 7, uint64(len(s)))
	return append(dst, s...)
}
