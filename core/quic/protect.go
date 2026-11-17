// Package quic is QUIC version 1 (RFC 9000, 9001, 9002) for the event
// loops: the parts of the transport that hold no socket and start no
// goroutine. Packets are parsed, opened and sealed in place.
package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// Version1 is QUIC version 1.
const Version1 = 0x00000001

// initialSalt is the salt of version 1's Initial secrets (RFC 9001,
// section 5.2).
var initialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// ErrDecrypt is a packet that does not open with the keys: forged,
// corrupted, or protected with other keys. Such a packet is dropped.
var ErrDecrypt = errors.New("quic: packet cannot be opened")

// errShortPacket is a packet too short to hold the sample its header
// protection is made from.
var errShortPacket = errors.New("quic: packet too short")

// tagLen is the length of the authentication tag of every cipher suite
// QUIC uses.
const tagLen = 16

// sampleLen is the length of the header protection sample.
const sampleLen = 16

// Keys protects, or opens, the packets of one direction at one encryption
// level.
type Keys struct {
	aead   cipher.AEAD
	iv     [12]byte
	block  cipher.Block // header protection of the AES suites
	chacha []byte       // header protection key of ChaCha20-Poly1305
	suite  uint16
	secret []byte // the traffic secret (a key update derives the next from it)
}

// expandLabel is TLS 1.3's HKDF-Expand-Label with an empty context.
func expandLabel(h func() hash.Hash, secret []byte, label string, n int) []byte {
	info := make([]byte, 0, 4+6+len(label))
	info = append(info, byte(n>>8), byte(n), byte(6+len(label)))
	info = append(info, "tls13 "...)
	info = append(info, label...)
	info = append(info, 0)
	out, err := hkdf.Expand(h, secret, string(info), n)
	if err != nil {
		panic("quic: hkdf: " + err.Error()) // only for a length no suite asks for
	}
	return out
}

// suiteHash returns the hash of a TLS 1.3 cipher suite and its key length,
// ok false for a suite QUIC does not use.
func suiteHash(suite uint16) (h func() hash.Hash, keyLen int, ok bool) {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		return sha256.New, 16, true
	case tls.TLS_AES_256_GCM_SHA384:
		return sha512.New384, 32, true
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return sha256.New, 32, true
	}
	return nil, 0, false
}

// NewKeys derives the packet protection keys of a traffic secret that
// crypto/tls reported for a cipher suite (RFC 9001, section 5.1).
func NewKeys(suite uint16, secret []byte) (*Keys, error) {
	h, keyLen, ok := suiteHash(suite)
	if !ok {
		return nil, errors.New("quic: cipher suite not supported")
	}
	k := &Keys{suite: suite, secret: append([]byte(nil), secret...)}
	if err := k.setAEAD(h, keyLen); err != nil {
		return nil, err
	}
	hp := expandLabel(h, secret, "quic hp", keyLen)
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		k.chacha = hp
		return k, nil
	}
	var err error
	k.block, err = aes.NewCipher(hp)
	return k, err
}

// setAEAD derives the key and IV of the keys' secret.
func (k *Keys) setAEAD(h func() hash.Hash, keyLen int) error {
	key := expandLabel(h, k.secret, "quic key", keyLen)
	copy(k.iv[:], expandLabel(h, k.secret, "quic iv", 12))
	var err error
	if k.suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		k.aead, err = chacha20poly1305.New(key)
		return err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	k.aead, err = cipher.NewGCM(b)
	return err
}

// Next returns the keys of the next key phase (RFC 9001, section 6): a new
// secret with its key and IV. The header protection key is not changed by
// a key update.
func (k *Keys) Next() (*Keys, error) {
	h, keyLen, _ := suiteHash(k.suite)
	n := &Keys{suite: k.suite, block: k.block, chacha: k.chacha}
	n.secret = expandLabel(h, k.secret, "quic ku", h().Size())
	if err := n.setAEAD(h, keyLen); err != nil {
		return nil, err
	}
	return n, nil
}

// InitialKeys derives the keys of Initial packets from the Destination
// Connection ID of the client's first Initial packet (RFC 9001, section
// 5.2): what the client seals with, and what the server seals with.
func InitialKeys(dcid []byte) (client, server *Keys) {
	initial, err := hkdf.Extract(sha256.New, dcid, initialSalt)
	if err != nil {
		panic("quic: hkdf: " + err.Error())
	}
	h := func() hash.Hash { return sha256.New() }
	c, _ := NewKeys(tls.TLS_AES_128_GCM_SHA256, expandLabel(h, initial, "client in", 32))
	s, _ := NewKeys(tls.TLS_AES_128_GCM_SHA256, expandLabel(h, initial, "server in", 32))
	return c, s
}

// mask returns the header protection mask for a sample.
func (k *Keys) mask(sample []byte) (m [5]byte) {
	if k.block != nil {
		var out [16]byte
		k.block.Encrypt(out[:], sample)
		copy(m[:], out[:5])
		return m
	}
	// ChaCha20: the sample's first four bytes are the block counter, the
	// other twelve the nonce; the mask is the start of the key stream.
	c, err := chacha20.NewUnauthenticatedCipher(k.chacha, sample[4:16])
	if err != nil {
		panic("quic: chacha20: " + err.Error())
	}
	c.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
	c.XORKeyStream(m[:], m[:])
	return m
}

func (k *Keys) nonce(pn int64) (n [12]byte) {
	n = k.iv
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(pn))
	for i := range b {
		n[4+i] ^= b[i]
	}
	return n
}

// DecodePacketNumber recovers a packet number from the nbits low bits a
// header carries, given the largest one received so far in its space, -1
// when none (RFC 9000, appendix A.3).
func DecodePacketNumber(largest int64, truncated uint64, nbits uint) int64 {
	expected := largest + 1
	win := int64(1) << nbits
	hwin := win / 2
	candidate := expected&^(win-1) | int64(truncated)
	if candidate <= expected-hwin && candidate < 1<<62-win {
		return candidate + win
	}
	if candidate > expected+hwin && candidate >= win {
		return candidate - win
	}
	return candidate
}

// Open removes the protection of the packet b, in place: its header's
// first byte and packet number, then its payload. pnOff is where the packet
// number starts (the unprotected part of the header ends there) and largest
// the largest packet number received in the packet's space, -1 for none.
// It returns the payload (a part of b), the packet number and its length.
//
// A packet that does not open is ErrDecrypt. It was opened in place, so
// its bytes are then no longer the packet: it is dropped. Only its last 16
// bytes, the tag, are as they came (a stateless reset is told by them).
func (k *Keys) Open(b []byte, pnOff int, largest int64) (payload []byte, pn int64, pnLen int, err error) {
	pnLen, truncated, err := k.Unmask(b, pnOff)
	if err != nil {
		return nil, 0, 0, err
	}
	pn = DecodePacketNumber(largest, truncated, uint(8*pnLen))
	payload, err = k.OpenBody(b, pnOff, pnLen, pn)
	return payload, pn, pnLen, err
}

// Unmask removes the header protection of the packet b, in place, and
// returns the length of its packet number and the number as the header
// carries it. The first byte is then in the clear: a 1-RTT packet's key
// phase bit says which generation of keys opens the rest (OpenBody). The
// header protection key is the same for every generation.
func (k *Keys) Unmask(b []byte, pnOff int) (pnLen int, truncated uint64, err error) {
	if len(b) < pnOff+4+sampleLen {
		return 0, 0, errShortPacket
	}
	m := k.mask(b[pnOff+4 : pnOff+4+sampleLen])
	if b[0]&0x80 != 0 {
		b[0] ^= m[0] & 0x0f
	} else {
		b[0] ^= m[0] & 0x1f
	}
	pnLen = int(b[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		b[pnOff+i] ^= m[1+i]
		truncated = truncated<<8 | uint64(b[pnOff+i])
	}
	return pnLen, truncated, nil
}

// OpenBody opens, in place, the payload of a packet whose header
// protection is removed and whose packet number is pn.
func (k *Keys) OpenBody(b []byte, pnOff, pnLen int, pn int64) ([]byte, error) {
	nonce := k.nonce(pn)
	body := b[pnOff+pnLen:]
	payload, err := k.aead.Open(body[:0], nonce[:], body, b[:pnOff+pnLen])
	if err != nil {
		return nil, ErrDecrypt
	}
	return payload, nil
}

// Overhead is how much Seal adds to a packet's payload.
const Overhead = tagLen

// Seal protects the packet b, in place, and returns it with its tag
// appended (b needs room for Overhead more bytes). b holds the header,
// whose packet number of pnLen bytes at pnOff is already written and whose
// first byte carries pnLen-1 in its low bits, followed by the payload. The
// packet number field and the payload together must be at least 4 bytes
// long (pad the payload): the header protection samples that far in.
func (k *Keys) Seal(b []byte, pnOff, pnLen int, pn int64) []byte {
	hdrLen := pnOff + pnLen
	nonce := k.nonce(pn)
	b = k.aead.Seal(b[:hdrLen], nonce[:], b[hdrLen:], b[:hdrLen])
	m := k.mask(b[pnOff+4 : pnOff+4+sampleLen])
	if b[0]&0x80 != 0 {
		b[0] ^= m[0] & 0x0f
	} else {
		b[0] ^= m[0] & 0x1f
	}
	for i := 0; i < pnLen; i++ {
		b[pnOff+i] ^= m[1+i]
	}
	return b
}

// retryKey and retryNonce protect the integrity of version 1's Retry
// packets (RFC 9001, section 5.8).
var (
	retryKey   = []byte{0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e}
	retryNonce = []byte{0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb}
	retryAEAD  cipher.AEAD
)

func init() {
	b, err := aes.NewCipher(retryKey)
	if err != nil {
		panic(err)
	}
	if retryAEAD, err = cipher.NewGCM(b); err != nil {
		panic(err)
	}
}

// AppendRetryTag appends the integrity tag of the Retry packet retry
// (without its tag), sent in answer to a packet whose Destination
// Connection ID was odcid.
func AppendRetryTag(retry, odcid []byte) []byte {
	pseudo := make([]byte, 0, 1+len(odcid)+len(retry))
	pseudo = append(pseudo, byte(len(odcid)))
	pseudo = append(pseudo, odcid...)
	pseudo = append(pseudo, retry...)
	return retryAEAD.Seal(retry, retryNonce, nil, pseudo)
}
