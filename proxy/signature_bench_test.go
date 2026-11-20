package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

// signatureMACv2PortOnly is what version 2 covered before it took both ends:
// the relay socket's port alone. For BenchmarkSignatureMACv2, which sets
// the two side by side.
func signatureMACv2PortOnly(key []byte, h *proxyproto.Header, ts, counter uint64, relayPort uint16, payload []byte) ([]byte, error) {
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

// BenchmarkSignatureMACv2: the signature of a relayed datagram (a QUIC
// packet of 1200 bytes, and a small one of 100) over both ends, and over
// the relay's port alone as before; each sender signs, and each receiver
// checks, one per datagram.
func BenchmarkSignatureMACv2(b *testing.B) {
	key := bytes.Repeat([]byte("k"), 32)
	h := &proxyproto.Header{Version: 2, Command: proxyproto.PROXY, TransportProtocol: proxyproto.UDPv4,
		SourceAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4321}, DestinationAddr: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}}
	ts := uint64(time.Now().Unix())
	for _, size := range []int{100, 1200} {
		payload := bytes.Repeat([]byte("p"), size)
		b.Run("ends/"+strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := signatureMACv2(key, h, ts, uint64(i), testEnds, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("port/"+strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := signatureMACv2PortOnly(key, h, ts, uint64(i), testEnds.Relay.Port(), payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
