package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The Initial keys of RFC 9001, appendix A.1.
func TestInitialKeys_RFCVector(t *testing.T) {
	client, server := InitialKeys(unhex(t, "8394c8f03e515708"))
	if got := hex.EncodeToString(client.secret); got != "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" {
		t.Errorf("client initial secret %s", got)
	}
	if got := hex.EncodeToString(client.iv[:]); got != "fa044b2f42a3fd3b46fb255c" {
		t.Errorf("client iv %s", got)
	}
	if got := hex.EncodeToString(server.secret); got != "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b" {
		t.Errorf("server initial secret %s", got)
	}
	if got := hex.EncodeToString(server.iv[:]); got != "0ac1493ca1905853b0bba03e" {
		t.Errorf("server iv %s", got)
	}
}

// The ChaCha20-Poly1305 short header packet of RFC 9001, appendix A.5: the
// whole protected packet, from the secret.
func TestSeal_RFCChaChaVector(t *testing.T) {
	k, err := NewKeys(tls.TLS_CHACHA20_POLY1305_SHA256, unhex(t, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"))
	if err != nil {
		t.Fatal(err)
	}
	const pn = 654360564
	b := make([]byte, 0, 64)
	b, pnOff := AppendShortHeader(b, nil, false, pn, 3)
	if hex.EncodeToString(b) != "4200bff4" {
		t.Fatalf("unprotected header %x, want 4200bff4", b)
	}
	b = append(b, 0x01) // a PING frame
	b = k.Seal(b, pnOff, 3, pn)
	if got := hex.EncodeToString(b); got != "4cfe4189655e5cd55c41f69080575d7999c25a5bfb" {
		t.Fatalf("protected packet %s, want 4cfe4189655e5cd55c41f69080575d7999c25a5bfb", got)
	}
	payload, gotPN, pnLen, err := k.Open(b, pnOff, pn-1)
	if err != nil || gotPN != pn || pnLen != 3 || !bytes.Equal(payload, []byte{0x01}) {
		t.Errorf("opening it: %x, pn %d (%d bytes), %v", payload, gotPN, pnLen, err)
	}
	// The same appendix gives the secret of the next key phase.
	next, err := k.Next()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(next.secret); got != "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9" {
		t.Errorf("the next phase's secret %s", got)
	}
}

// A key update: the next phase's keys open what the next phase's keys
// sealed and nothing of the phase before, in either direction; the header
// protection is the same in both phases.
func TestKeys_Next(t *testing.T) {
	for _, suite := range []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256} {
		n := 32
		if suite == tls.TLS_AES_256_GCM_SHA384 {
			n = 48
		}
		k0, err := NewKeys(suite, bytes.Repeat([]byte{0x77}, n))
		if err != nil {
			t.Fatal(err)
		}
		k1, err := k0.Next()
		if err != nil {
			t.Fatal(err)
		}
		k2, _ := k1.Next()
		seal := func(k *Keys, phase bool) ([]byte, int) {
			b, pnOff := AppendShortHeader(make([]byte, 0, 128), []byte{1, 2, 3, 4, 5, 6, 7, 8}, phase, 9, 1)
			b = append(b, "a payload of the phase"...)
			return k.Seal(b, pnOff, 1, 9), pnOff
		}
		p1, pnOff := seal(k1, true)
		// Unmasking works with any phase's keys and shows the phase bit.
		pnLen, trunc, err := k0.Unmask(p1, pnOff)
		if err != nil || pnLen != 1 || trunc != 9 || p1[0]&0x04 == 0 {
			t.Fatalf("suite %#x: unmask with the old keys: pnLen %d, pn %d, first byte %#x, %v", suite, pnLen, trunc, p1[0], err)
		}
		keep := append([]byte(nil), p1...)
		if _, err := k0.OpenBody(p1, pnOff, pnLen, 9); err != ErrDecrypt {
			t.Errorf("suite %#x: the old keys opened a packet of the next phase: %v", suite, err)
		}
		if _, err := k2.OpenBody(append([]byte(nil), keep...), pnOff, pnLen, 9); err != ErrDecrypt {
			t.Errorf("suite %#x: the keys after next opened it: %v", suite, err)
		}
		if got, err := k1.OpenBody(keep, pnOff, pnLen, 9); err != nil || string(got) != "a payload of the phase" {
			t.Errorf("suite %#x: the next keys: %q, %v", suite, got, err)
		}
	}
}

// The Retry packet of RFC 9001, appendix A.4.
func TestRetryTag_RFCVector(t *testing.T) {
	retry := unhex(t, "ff000000010008f067a5502a4262b5746f6b656e")
	got := AppendRetryTag(retry, unhex(t, "8394c8f03e515708"))
	if hex.EncodeToString(got) != "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba" {
		t.Errorf("Retry packet %x", got)
	}
}

func TestDecodePacketNumber(t *testing.T) {
	// RFC 9000, appendix A.3.
	if got := DecodePacketNumber(0xa82f30ea, 0x9b32, 16); got != 0xa82f9b32 {
		t.Errorf("%#x, want 0xa82f9b32", got)
	}
	for _, tc := range []struct {
		largest   int64
		truncated uint64
		nbits     uint
		want      int64
	}{
		{-1, 0, 8, 0}, {-1, 5, 8, 5}, {0, 1, 8, 1}, {255, 0, 8, 256}, {300, 0x2d, 8, 301}, {300, 0x2b, 8, 299},
		{1 << 20, 0, 16, 1 << 20}, {1<<20 + 40000, 0, 16, 1<<20 + 1<<16}, {65535, 0, 16, 65536},
	} {
		if got := DecodePacketNumber(tc.largest, tc.truncated, tc.nbits); got != tc.want {
			t.Errorf("largest %d, %#x in %d bits: %d, want %d", tc.largest, tc.truncated, tc.nbits, got, tc.want)
		}
	}
	// Whatever length pnLenFor picks, the receiver recovers the number.
	for _, acked := range []int64{-1, 0, 100, 1 << 20, 1 << 40} {
		for _, ahead := range []int64{1, 2, 127, 128, 255, 30000, 1 << 20, 1 << 22} {
			pn := acked + ahead
			n := pnLenFor(pn, acked)
			trunc := uint64(pn) & (1<<(8*uint(n)) - 1)
			// The receiver has seen anything from the acknowledged one up.
			for _, largest := range []int64{acked, pn - 1} {
				if got := DecodePacketNumber(largest, trunc, uint(8*n)); got != pn {
					t.Errorf("pn %d (acked %d, receiver at %d) in %d bytes: %d", pn, acked, largest, n, got)
				}
			}
		}
	}
}

// Every suite, both header forms, every packet number length: what Seal
// protects, Open opens; a packet changed anywhere does not open, and is
// left as it came.
func TestSealOpen(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5a}, 48)
	for _, suite := range []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256} {
		n := 32
		if suite == tls.TLS_AES_256_GCM_SHA384 {
			n = 48
		}
		k, err := NewKeys(suite, secret[:n])
		if err != nil {
			t.Fatal(err)
		}
		dcid, scid := []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 10, 11, 12}
		for pnLen := 1; pnLen <= 4; pnLen++ {
			for _, long := range []bool{true, false} {
				pn := int64(1)<<(8*uint(pnLen)-2) + 77
				payload := bytes.Repeat([]byte{0xab}, 40)
				b := make([]byte, 0, 256)
				var pnOff, lenOff int
				if long {
					b, lenOff, pnOff = AppendLongHeader(b, PacketHandshake, dcid, scid, nil, pn, pnLen)
				} else {
					b, pnOff = AppendShortHeader(b, dcid, true, pn, pnLen)
				}
				b = append(b, payload...)
				if long {
					SetLength(b, lenOff, pnOff)
				}
				b = k.Seal(b, pnOff, pnLen, pn)
				h, err := ParseHeader(b, len(dcid))
				if err != nil || h.PNOff != pnOff || h.End != len(b) || !bytes.Equal(h.DCID, dcid) {
					t.Fatalf("suite %#x long=%v pnLen=%d: header %+v, %v", suite, long, pnLen, h, err)
				}
				if long && (h.Type != PacketHandshake || !bytes.Equal(h.SCID, scid)) {
					t.Fatalf("long header: %+v", h)
				}
				sealed := append([]byte(nil), b...)
				for _, at := range []int{0, pnOff, pnOff + pnLen, len(b) - 1} {
					bad := append([]byte(nil), sealed...)
					bad[at] ^= 0x40
					tag := append([]byte(nil), bad[len(bad)-tagLen:]...)
					if _, _, _, err := k.Open(bad, pnOff, pn-1); err != ErrDecrypt {
						t.Errorf("suite %#x long=%v pnLen=%d: byte %d changed: %v", suite, long, pnLen, at, err)
					}
					if !bytes.Equal(bad[len(bad)-tagLen:], tag) {
						t.Errorf("suite %#x: the tag of a packet that did not open was changed", suite)
					}
				}
				got, gotPN, gotLen, err := k.Open(b, pnOff, pn-1)
				if err != nil || gotPN != pn || gotLen != pnLen || !bytes.Equal(got, payload) {
					t.Fatalf("suite %#x long=%v pnLen=%d: %x, pn %d (%d), %v", suite, long, pnLen, got, gotPN, gotLen, err)
				}
			}
		}
		if _, _, _, err := k.Open(make([]byte, 20), 9, -1); err != errShortPacket {
			t.Errorf("a packet too short for its sample: %v", err)
		}
	}
	if _, err := NewKeys(tls.TLS_RSA_WITH_AES_128_GCM_SHA256, secret[:32]); err == nil {
		t.Errorf("keys for a suite QUIC does not use")
	}
}

func TestParseHeader(t *testing.T) {
	dcid, scid := []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 9}
	b, lenOff, pnOff := AppendLongHeader(nil, PacketInitial, dcid, scid, []byte("token"), 3, 2)
	b = append(b, bytes.Repeat([]byte{0}, 30)...)
	SetLength(b, lenOff, pnOff)
	b = append(b, make([]byte, Overhead)...)                                           // where the tag goes
	coalesced := append(append([]byte(nil), b...), 0x40, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0) // a short header packet behind it
	h, err := ParseHeader(coalesced, 8)
	if err != nil || h.Type != PacketInitial || h.Version != Version1 || string(h.Token) != "token" || h.PNOff != pnOff || h.End != len(b) {
		t.Fatalf("Initial: %+v, %v", h, err)
	}
	h2, err := ParseHeader(coalesced[h.End:], 8)
	if err != nil || h2.Type != PacketShort || !bytes.Equal(h2.DCID, dcid) || h2.PNOff != 9 {
		t.Fatalf("the packet behind it: %+v, %v", h2, err)
	}
	v2 := append([]byte(nil), b...)
	v2[1], v2[2], v2[3], v2[4] = 0x6b, 0x33, 0x43, 0xcf
	if h, err := ParseHeader(v2, 8); err != ErrVersion || !bytes.Equal(h.DCID, dcid) || !bytes.Equal(h.SCID, scid) || h.Version != 0x6b3343cf {
		t.Errorf("another version: %+v, %v", h, err)
	}
	vn := AppendVersionNegotiation(nil, 0x55, dcid, scid)
	if h, err := ParseHeader(vn, 8); err != nil || h.Version != 0 || !bytes.Equal(h.DCID, scid) || !bytes.Equal(h.SCID, dcid) || !bytes.Equal(vn[h.PNOff:], []byte{0, 0, 0, 1}) {
		t.Errorf("version negotiation: %+v, %v", h, err)
	}
	for name, p := range map[string][]byte{
		"empty":                        nil,
		"short header, no fixed bit":   {0x00, 1, 2, 3, 4, 5, 6, 7, 8, 0},
		"short header, cut":            {0x40, 1, 2, 3},
		"long header, cut":             b[:6],
		"long header, no fixed bit":    append([]byte{b[0] &^ 0x40}, b[1:]...),
		"DCID longer than the packet":  {0xc0, 0, 0, 0, 1, 200, 1, 2},
		"a 21-byte connection ID":      append(append([]byte{0xc0, 0, 0, 0, 1, 21}, make([]byte, 21)...), 0, 0, 0x40, 0),
		"token longer than the packet": {0xc0, 0, 0, 0, 1, 0, 0, 0x40, 0x7f, 1},
		"length beyond the datagram":   b[:len(b)-1],
		"no length":                    b[:lenOff],
	} {
		if _, err := ParseHeader(p, 8); err != ErrHeader {
			t.Errorf("%s: %v, want %v", name, err, ErrHeader)
		}
	}
}

// A real client's first packet: quic-go's Initial opens with the keys made
// from its Destination Connection ID, and carries the start of a TLS
// ClientHello in a CRYPTO frame.
func TestOpen_RealClientInitial(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		// The dial never completes: nobody answers. It ends with ctx.
		c, err := quicgo.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"h3"}}, nil)
		if err == nil {
			c.CloseWithError(0, "")
		}
	}()
	buf := make([]byte, 2048)
	pc.SetReadDeadline(time.Now().Add(4 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	dgram := buf[:n]
	if n < MinInitialSize {
		t.Errorf("the client's first datagram is %d bytes, below %d", n, MinInitialSize)
	}
	h, err := ParseHeader(dgram, 8)
	if err != nil || h.Type != PacketInitial || h.Version != Version1 || len(h.DCID) < 8 {
		t.Fatalf("header %+v, %v", h, err)
	}
	client, _ := InitialKeys(h.DCID)
	payload, pn, _, err := client.Open(dgram[:h.End], h.PNOff, -1)
	if err != nil {
		t.Fatalf("the client's Initial does not open: %v", err)
	}
	if dgram[0]&0x0c != 0 {
		t.Errorf("reserved bits set after opening: %#x", dgram[0])
	}
	if pn != 0 {
		t.Errorf("packet number %d, want 0", pn)
	}
	// Find a CRYPTO frame (0x06) at offset 0: a ClientHello starts with
	// handshake type 1. (A ClientHello that does not fit one packet comes
	// in pieces, in any order: the piece at offset 0 may be in a later
	// packet, so only the frames' shape is checked then.)
	sawCrypto, sawHello := false, false
	for p := payload; len(p) > 0; {
		switch p[0] {
		case 0x00, 0x01: // PADDING, PING
			p = p[1:]
		case 0x06:
			off, n1 := varint(p[1:])
			l, n2 := varint(p[1+n1:])
			if n1 == 0 || n2 == 0 || uint64(len(p)-1-n1-n2) < l {
				t.Fatalf("CRYPTO frame cut short")
			}
			data := p[1+n1+n2 : 1+n1+n2+int(l)]
			sawCrypto = true
			if off == 0 && len(data) > 0 && data[0] == 0x01 {
				sawHello = true
			}
			p = p[1+n1+n2+int(l):]
		default:
			t.Fatalf("frame type %#x in a client's first Initial", p[0])
		}
	}
	if !sawCrypto {
		t.Errorf("no CRYPTO frame in the client's Initial")
	}
	t.Logf("client Initial: %d bytes, DCID %x, CRYPTO seen, ClientHello start seen: %v", n, h.DCID, sawHello)
}
