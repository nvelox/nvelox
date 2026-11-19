package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"testing/iotest"
	"time"

	"github.com/pires/go-proxyproto"
)

// What the parsers say about a relay's bytes, compared as values.
type parsed struct {
	done     bool
	header   string // the header as formatted again; "" for none
	consumed int
	err      error
}

func headerText(t *testing.T, h *proxyproto.Header) string {
	t.Helper()
	if h == nil {
		return ""
	}
	b, err := h.Format()
	if err != nil {
		t.Fatalf("a header the parser accepted does not format again: %v", err)
	}
	return string(b)
}

func parseStream(t *testing.T, buf []byte) parsed {
	t.Helper()
	done, h, n, err := ParseStreamStrict(buf)
	return parsed{done, headerText(t, h), n, err}
}

func formatV2(cmd proxyproto.ProtocolVersionAndCommand, tp proxyproto.AddressFamilyAndProtocol, src, dst net.Addr) []byte {
	h := &proxyproto.Header{Version: 2, Command: cmd, TransportProtocol: tp, SourceAddr: src, DestinationAddr: dst}
	b, err := h.Format()
	if err != nil {
		panic(err)
	}
	return b
}

func streamSeeds() [][]byte {
	tcp4 := formatV2(proxyproto.PROXY, proxyproto.TCPv4, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443})
	tcp6 := formatV2(proxyproto.PROXY, proxyproto.TCPv6, &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5000}, &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443})
	local := formatV2(proxyproto.LOCAL, proxyproto.UNSPEC, nil, nil)
	udp4 := formatV2(proxyproto.PROXY, proxyproto.UDPv4, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53})
	signed, _ := SignedHeaderBytes(udp4, bytes.Repeat([]byte("k"), 32), []byte("payload"), time.Unix(1_800_000_000, 0))
	return [][]byte{
		tcp4, append(append([]byte{}, tcp4...), "GET / HTTP/1.1\r\n"...), tcp6, local, udp4, signed,
		tcp4[:11], tcp4[:12], tcp4[:15], tcp4[:16], tcp4[:len(tcp4)-1],
		[]byte("PROXY TCP4 192.0.2.1 198.51.100.1 5000 443\r\n"), []byte("GET / HTTP/1.1\r\n"), {}, {0x0D},
		append(append([]byte{}, V2Signature...), 0x21, 0x11, 0xFF, 0xFF),
	}
}

// FuzzParseStream: whatever a trusted relay sends at the start of a stream,
// the parser of a stream that requires a header gives one verdict, the same
// however the bytes are split as they arrive, and the reader of a
// connection agrees with it, reading the header and not a byte more.
func FuzzParseStream(f *testing.F) {
	for _, s := range streamSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, buf []byte) {
		full := parseStream(t, buf)
		if full.done {
			switch {
			case errors.Is(full.err, ErrNoHeader):
				if full.consumed != 0 || full.header != "" || bytes.HasPrefix(buf, V2Signature[:min(len(buf), len(V2Signature))]) {
					t.Fatalf("%x: no header, yet %+v", buf, full)
				}
			case full.err == nil || errors.Is(full.err, ErrBadHeader):
				if full.consumed < 16 || full.consumed > len(buf) || full.consumed != 16+(int(buf[14])<<8|int(buf[15])) {
					t.Fatalf("%x: consumed %d", buf, full.consumed)
				}
				if full.err != nil && full.header != "" {
					t.Fatalf("%x: a malformed header with a header", buf)
				}
			default:
				t.Fatalf("%x: an error of no kind the callers know: %v", buf, full.err)
			}
		} else if full.err != nil || full.header != "" || full.consumed != 0 {
			t.Fatalf("%x: more bytes needed, yet %+v", buf, full)
		}

		// The same verdict on every prefix that holds what it needs, none
		// on a prefix that does not.
		ks := []int{}
		if len(buf) <= 300 {
			for k := 0; k <= len(buf); k++ {
				ks = append(ks, k)
			}
		} else {
			ks = []int{0, 1, 11, 12, 15, 16, full.consumed - 1, full.consumed, full.consumed + 1, len(buf) - 1}
		}
		for _, k := range ks {
			if k < 0 || k > len(buf) {
				continue
			}
			p := parseStream(t, buf[:k])
			if p.done && (p.consumed != full.consumed || p.header != full.header || !errors.Is(p.err, full.err) && !(p.err == nil && full.err == nil)) {
				t.Fatalf("%x: the first %d bytes give %+v, all of them %+v", buf, k, p, full)
			}
			if full.done && full.err == nil || errors.Is(full.err, ErrBadHeader) {
				if (k >= full.consumed) != p.done {
					t.Fatalf("%x: the first %d bytes give done=%v; the header is %d bytes", buf, k, p.done, full.consumed)
				}
			}
		}

		// The reader of a connection, whole and one byte at a time.
		for _, oneByte := range []bool{false, true} {
			br := bytes.NewReader(buf)
			var r io.Reader = br
			if oneByte {
				r = iotest.OneByteReader(br)
			}
			h, err := ReadStreamHeader(r)
			got := headerText(t, h)
			switch {
			case !full.done:
				if err == nil || errors.Is(err, ErrNoHeader) || errors.Is(err, ErrBadHeader) {
					t.Fatalf("%x: a header cut short read as %q, %v", buf, got, err)
				}
			case !errors.Is(err, full.err) && !(err == nil && full.err == nil) || got != full.header:
				t.Fatalf("%x: the reader says %q, %v; the parser %+v", buf, got, err, full)
			case err == nil && br.Len() != len(buf)-full.consumed:
				t.Fatalf("%x: the reader took %d bytes for a header of %d", buf, len(buf)-br.Len(), full.consumed)
			}
		}
	})
}

// FuzzParseDatagram: whatever a datagram from a trusted relay starts with,
// what the parser accepts names a datagram client, and the signature check
// gives a verdict on it, whatever it holds.
func FuzzParseDatagram(f *testing.F) {
	for _, s := range streamSeeds() {
		f.Add(s)
	}
	trust := NewTrust([]string{"0.0.0.0/0"}, [][]byte{bytes.Repeat([]byte("k"), 32)})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, n, err := ParseDatagramStrict(data)
		if err != nil {
			if h != nil {
				t.Fatalf("%x: an error and a header", data)
			}
			if !errors.Is(err, ErrNoHeader) && !errors.Is(err, ErrBadHeader) {
				t.Fatalf("%x: an error of no kind the callers know: %v", data, err)
			}
			return
		}
		if n < 16 || n > len(data) || n != 16+(int(data[14])<<8|int(data[15])) {
			t.Fatalf("%x: consumed %d", data, n)
		}
		if ua, ok := h.SourceAddr.(*net.UDPAddr); !ok || ua.IP == nil || h.Command != proxyproto.PROXY || !h.TransportProtocol.IsDatagram() {
			t.Fatalf("%x: accepted %+v", data, h)
		}
		_, _, _ = trust.VerifyFrom(h, data[n:], true, 40001)
		_, _, _ = trust.VerifyFrom(h, data[n:], false, 40001)
	})
}

// FuzzSignature: a datagram header signed with a key passes with that key
// and only for its own payload, its own addresses and its own time.
func FuzzSignature(f *testing.F) {
	f.Add([]byte{192, 0, 2, 1}, uint16(5000), []byte{198, 51, 100, 1}, uint16(53), []byte("payload"), []byte("a key of thirty-two characters!!"), int64(0))
	f.Add([]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}, uint16(1), []byte{0x20, 0x01, 0x0d, 0xb8, 15: 2}, uint16(65535), []byte{}, []byte("k"), int64(29))
	f.Add([]byte{192, 0, 2, 1}, uint16(5000), []byte{198, 51, 100, 1}, uint16(53), []byte("late"), []byte("a key of thirty-two characters!!"), int64(45))
	f.Fuzz(func(t *testing.T, src []byte, sport uint16, dst []byte, dport uint16, payload, key []byte, skew int64) {
		ipOf := func(b []byte) net.IP {
			if len(b) >= 16 {
				return net.IP(b[:16])
			}
			ip := make(net.IP, 4)
			copy(ip, b)
			return ip
		}
		tp := proxyproto.UDPv4
		s, d := ipOf(src), ipOf(dst)
		if len(s) == 16 || len(d) == 16 {
			tp = proxyproto.UDPv6
			s, d = s.To16(), d.To16()
		}
		now := time.Unix(1_800_000_000, 0)
		hdr := formatV2(proxyproto.PROXY, tp, &net.UDPAddr{IP: s, Port: int(sport)}, &net.UDPAddr{IP: d, Port: int(dport)})
		signed, err := SignedHeaderBytes(hdr, key, payload, now)
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
		h, n, err := ParseDatagramStrict(append(signed, payload...))
		if err != nil || n != len(signed) {
			t.Fatalf("the signed header does not parse: %v (%d of %d)", err, n, len(signed))
		}
		keys := [][]byte{[]byte("another key, not the one used!!!"), key}
		at := now.Add(time.Duration(skew%60) * time.Second)
		err = Verify(h, keys, payload, at)
		inWindow := at.Sub(now) <= SignatureWindow && now.Sub(at) <= SignatureWindow
		switch {
		case inWindow && err != nil:
			t.Fatalf("a header signed with the key fails: %v", err)
		case !inWindow && !errors.Is(err, ErrSignatureExpired):
			t.Fatalf("a header signed %v away passes: %v", at.Sub(now), err)
		}
		if !inWindow {
			return
		}
		if err := Verify(h, keys[:1], payload, at); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("a header passes with a key it was not signed with: %v", err)
		}
		other := append(append([]byte{}, payload...), 0)
		if err := Verify(h, keys, other, at); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("a header passes for another payload: %v", err)
		}
		moved := *h
		moved.SourceAddr = &net.UDPAddr{IP: s, Port: int(sport) ^ 1}
		if err := Verify(&moved, keys, payload, at); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("a header passes for another source port: %v", err)
		}
	})
}
