package quic

import (
	"testing"
)

// FuzzPacket: whatever a datagram holds, reading the header of its first
// packet does not panic and reports nothing that lies outside the
// datagram. This is the first code a datagram from anywhere reaches. An
// Initial packet is then opened with the keys its connection ID gives
// (anybody can make one that opens), and what opens is read as frames.
func FuzzPacket(f *testing.F) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	scid := []byte{9, 10, 11, 12}
	initial := func(token, frames []byte) []byte {
		b, lenOff, pnOff := AppendLongHeader(make([]byte, 0, 1500), PacketInitial, dcid, scid, token, 7, 2)
		b = append(b, frames...)
		for len(b)+Overhead < MinInitialSize {
			b = append(b, FramePadding)
		}
		SetLength(b, lenOff, pnOff)
		client, _ := InitialKeys(dcid)
		return client.Seal(b, pnOff, 2, 7)
	}
	f.Add(initial(nil, AppendCrypto(nil, 0, []byte("a first flight that is none"))), uint8(8))
	f.Add(initial([]byte("a token from a Retry packet"), []byte{FramePing}), uint8(8))
	f.Add(append(initial(nil, []byte{FramePing}), initial(nil, AppendAck(nil, 0, [][2]uint64{{0, 3}}))...), uint8(8))
	// A short header; a long header of another version; Version Negotiation;
	// a Retry; headers that end early.
	f.Add(append([]byte{0x41, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0}, make([]byte, 40)...), uint8(8))
	f.Add([]byte{0xc0, 0xfa, 0xce, 0xb0, 0x0c, 8, 1, 2, 3, 4, 5, 6, 7, 8, 4, 9, 10, 11, 12, 0, 0, 0}, uint8(8))
	f.Add([]byte{0x80, 0, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 1, 0xfa, 0xce, 0xb0, 0x0c}, uint8(0))
	f.Add(append([]byte{0xf0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 4, 9, 10, 11, 12}, make([]byte, 24)...), uint8(8))
	f.Add([]byte{0xc0, 0, 0, 0, 1, 20}, uint8(20))
	f.Add([]byte{0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, uint8(8))

	f.Fuzz(func(t *testing.T, b []byte, cidLen uint8) {
		h, err := ParseHeader(b, int(cidLen)%(MaxCIDLen+1))
		if err != nil && err != ErrVersion {
			return
		}
		if len(h.DCID) > len(b) || len(h.SCID) > len(b) || len(h.Token) > len(b) {
			t.Fatalf("a header with connection IDs of %d and %d bytes and a token of %d in a datagram of %d", len(h.DCID), len(h.SCID), len(h.Token), len(b))
		}
		if err != nil {
			return
		}
		if h.PNOff < 0 || h.PNOff > h.End || h.End > len(b) {
			t.Fatalf("a packet whose number is at %d and which ends at %d, in a datagram of %d bytes", h.PNOff, h.End, len(b))
		}
		if h.Type != PacketInitial || h.Version != Version1 {
			return
		}
		client, _ := InitialKeys(h.DCID)
		pkt := append([]byte(nil), b[:h.End]...)
		payload, pn, pnLen, err := client.Open(pkt, h.PNOff, -1)
		if err != nil {
			return
		}
		if pn < 0 || pnLen < 1 || pnLen > 4 || len(payload) > len(pkt) {
			t.Fatalf("a packet that opened: number %d of %d bytes, %d bytes of payload in %d", pn, pnLen, len(payload), len(pkt))
		}
		var fr Frame
		for len(payload) > 0 {
			n, err := ParseFrame(payload, &fr)
			if err != nil {
				return
			}
			if n <= 0 || n > len(payload) {
				t.Fatalf("a frame of %d bytes out of %d", n, len(payload))
			}
			payload = payload[n:]
		}
	})
}
