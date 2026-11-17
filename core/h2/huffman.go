package h2

import "sync"

// The Huffman code of HPACK (RFC 7541, section 5.2 and Appendix B).

// huffEOS is the end-of-string symbol: thirty 1 bits. A string never holds
// it; its most significant bits are the padding of a string's last byte.
const (
	huffEOSCode = 0x3fffffff
	huffEOSLen  = 30
)

// The decoder walks the code tree four bits at a time. A state is an inner
// node of the tree (the root is state 0): the bits read since the last
// symbol. No code is shorter than five bits, so four bits end at most one
// symbol.
type huffStep struct {
	next uint8 // the state after these four bits
	sym  uint8 // the symbol they ended, when flags has huffEmit
	// huffEmit: a symbol ended. huffAccept: the string may end after these
	// bits (next is the root, or what follows the last symbol is at most
	// seven 1 bits). huffFail: the bits ran into the end-of-string symbol.
	flags uint8
}

const (
	huffEmit   = 1 << 0
	huffAccept = 1 << 1
	huffFail   = 1 << 2
)

var (
	huffOnce  sync.Once
	huffTable [256][16]huffStep
)

type huffNode struct {
	child [2]int16 // inner node index, or -1-symbol for a leaf (256 is EOS); 0 is unset
	set   [2]bool
}

// buildHuffTable derives the decoder's table from the code table.
func buildHuffTable() {
	// The code tree: 257 leaves, so 256 inner nodes.
	nodes := make([]huffNode, 1, 256)
	add := func(code uint32, length uint8, sym int) {
		n := 0
		for i := int(length) - 1; i >= 0; i-- {
			bit := (code >> uint(i)) & 1
			if i == 0 {
				nodes[n].child[bit], nodes[n].set[bit] = int16(-1-sym), true
				return
			}
			if !nodes[n].set[bit] {
				nodes = append(nodes, huffNode{})
				nodes[n].child[bit], nodes[n].set[bit] = int16(len(nodes)-1), true
			}
			n = int(nodes[n].child[bit])
		}
	}
	for sym := 0; sym < 256; sym++ {
		add(huffCodes[sym], huffLens[sym], sym)
	}
	add(huffEOSCode, huffEOSLen, 256)
	if len(nodes) != 256 {
		panic("h2: the Huffman code is not a full tree of 257 symbols")
	}
	// The states a string may end in: the root, and up to seven 1 bits
	// below it (the start of the end-of-string symbol).
	accept := make([]bool, len(nodes))
	for n, depth := 0, 0; depth <= 7; depth++ {
		accept[n] = true
		n = int(nodes[n].child[1])
	}
	for state := range nodes {
		for nibble := 0; nibble < 16; nibble++ {
			var st huffStep
			n := state
			for i := 3; i >= 0; i-- {
				c := nodes[n].child[(nibble>>uint(i))&1]
				if c > 0 {
					n = int(c)
					continue
				}
				sym := int(-1 - c)
				if sym == 256 {
					st.flags |= huffFail
					break
				}
				st.flags |= huffEmit
				st.sym = uint8(sym)
				n = 0
			}
			st.next = uint8(n)
			if st.flags&huffFail == 0 && accept[n] {
				// After a symbol the remaining bits of the nibble are the
				// start of the next code: they pad only when they are 1 bits,
				// which is what accept[n] says of the node they lead to.
				st.flags |= huffAccept
			}
			huffTable[state][nibble] = st
		}
	}
}

// huffDecode appends the string that src encodes to dst, which must have
// room for it within max bytes in all: more than that, the end-of-string
// symbol, or a padding that is longer than seven bits or holds a 0 bit,
// gives false.
func huffDecode(dst, src []byte, max int) ([]byte, bool) {
	huffOnce.Do(buildHuffTable)
	state := uint8(0)
	ok := true // an empty string is valid
	for _, b := range src {
		st := huffTable[state][b>>4]
		if st.flags&huffFail != 0 {
			return dst, false
		}
		if st.flags&huffEmit != 0 {
			if len(dst) >= max {
				return dst, false
			}
			dst = append(dst, st.sym)
		}
		st = huffTable[st.next][b&0xf]
		if st.flags&huffFail != 0 {
			return dst, false
		}
		if st.flags&huffEmit != 0 {
			if len(dst) >= max {
				return dst, false
			}
			dst = append(dst, st.sym)
		}
		state = st.next
		ok = st.flags&huffAccept != 0
	}
	return dst, ok
}

// huffEncodedLen returns how many bytes s takes when encoded.
func huffEncodedLen(s []byte) int {
	bits := 0
	for _, b := range s {
		bits += int(huffLens[b])
	}
	return (bits + 7) / 8
}

// appendHuff appends the encoding of s to dst, padded with 1 bits.
func appendHuff(dst, s []byte) []byte {
	var acc uint64 // the bits not written yet, in its low n bits
	n := uint(0)
	for _, b := range s {
		l := uint(huffLens[b])
		acc = acc<<l | uint64(huffCodes[b])
		n += l
		for n >= 8 {
			n -= 8
			dst = append(dst, byte(acc>>n))
		}
	}
	if n > 0 {
		dst = append(dst, byte(acc<<(8-n))|byte(0xff>>n))
	}
	return dst
}

// HuffmanDecode appends the string that src encodes (RFC 7541, Appendix B;
// QPACK uses the same code) to dst, which may grow to max bytes in all. It
// reports false for an invalid encoding and for a string longer than that.
func HuffmanDecode(dst, src []byte, max int) ([]byte, bool) { return huffDecode(dst, src, max) }

// HuffmanEncodedLen returns how many bytes s takes when Huffman coded.
func HuffmanEncodedLen(s []byte) int { return huffEncodedLen(s) }

// AppendHuffman appends the Huffman coding of s to dst.
func AppendHuffman(dst, s []byte) []byte { return appendHuff(dst, s) }
