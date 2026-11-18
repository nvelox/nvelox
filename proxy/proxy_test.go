package proxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestWriteProxyHeaderV2_IPv4_TCP(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 80}

	var buf bytes.Buffer
	err := WriteProxyHeaderV2(&buf, src, dst)
	if err != nil {
		t.Fatalf("WriteProxyHeaderV2 failed: %v", err)
	}

	data := buf.Bytes()

	// Check Signature
	if !bytes.Equal(data[:12], sigV2) {
		t.Errorf("Invalid signature")
	}

	// Check Ver/Cmd (0x21)
	if data[12] != 0x21 {
		t.Errorf("Expected Ver/Cmd 0x21, got 0x%X", data[12])
	}

	// Check Fam/Proto (IPv4=0x10 | TCP=0x1) = 0x11
	if data[13] != 0x11 {
		t.Errorf("Expected Fam/Proto 0x11, got 0x%X", data[13])
	}

	// Check Length (12 bytes)
	length := binary.BigEndian.Uint16(data[14:16])
	if length != 12 {
		t.Errorf("Expected length 12, got %d", length)
	}

	// Check Addresses
	// 192.168.1.1
	if !bytes.Equal(data[16:20], src.IP.To4()) {
		t.Errorf("Src IP mismatch")
	}
	// 10.0.0.1
	if !bytes.Equal(data[20:24], dst.IP.To4()) {
		t.Errorf("Dst IP mismatch")
	}

	// Check Ports
	srcPort := binary.BigEndian.Uint16(data[24:26])
	if srcPort != 12345 {
		t.Errorf("Expected src port 12345, got %d", srcPort)
	}
	dstPort := binary.BigEndian.Uint16(data[26:28])
	if dstPort != 80 {
		t.Errorf("Expected dst port 80, got %d", dstPort)
	}
}

func TestWriteProxyHeaderV2_IPv6_TCP(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 8443}

	var buf bytes.Buffer
	err := WriteProxyHeaderV2(&buf, src, dst)
	if err != nil {
		t.Fatalf("WriteProxyHeaderV2 failed: %v", err)
	}

	data := buf.Bytes()

	// Check Fam/Proto (IPv6=0x20 | TCP=0x1) = 0x21
	if data[13] != 0x21 {
		t.Errorf("Expected Fam/Proto 0x21, got 0x%X", data[13])
	}

	// Check Length (36 bytes: 16+16+4)
	length := binary.BigEndian.Uint16(data[14:16])
	if length != 36 {
		t.Errorf("Expected length 36, got %d", length)
	}

	// Simple check of full length
	if len(data) != 16+36 {
		t.Errorf("Expected total size %d, got %d", 16+36, len(data))
	}
}

func TestWriteProxyHeaderV2_IPv4_UDP(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 53}
	dst := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}

	var buf bytes.Buffer
	err := WriteProxyHeaderV2(&buf, src, dst)
	if err != nil {
		t.Fatalf("WriteProxyHeaderV2 failed: %v", err)
	}

	data := buf.Bytes()

	// Check Fam/Proto (IPv4=0x10 | UDP=0x2) = 0x12
	if data[13] != 0x12 {
		t.Errorf("Expected Fam/Proto 0x12, got 0x%X", data[13])
	}
}

// An IPv4 address and an IPv6 one have no family of their own in the header:
// both go as IPv6, the IPv4 one in its IPv4-mapped form, whichever side it
// is on, over UDP and TCP alike. An address of neither family is an error.
func TestWriteProxyHeaderV2_MixedFamiliesGoAsIPv6(t *testing.T) {
	mapped := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
	for _, c := range []struct {
		src, dst net.Addr
		famProto byte
		v4At     int // where the IPv4 address is in the header: 16 the source, 32 the destination
	}{
		{&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}, &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}, 0x22, 16},
		{&net.UDPAddr{IP: net.ParseIP("2001:db8::7"), Port: 4444}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2).To4(), Port: 443}, 0x22, 32},
		{&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}, &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}, 0x21, 16},
	} {
		var buf bytes.Buffer
		if err := WriteProxyHeaderV2(&buf, c.src, c.dst); err != nil {
			t.Fatalf("%v -> %v: %v", c.src, c.dst, err)
		}
		data := buf.Bytes()
		if len(data) != 16+36 || data[13] != c.famProto || binary.BigEndian.Uint16(data[14:]) != 36 {
			t.Fatalf("%v -> %v: %d bytes, family/protocol 0x%02x, length %d; want 52, 0x%02x, 36", c.src, c.dst, len(data), data[13], binary.BigEndian.Uint16(data[14:]), c.famProto)
		}
		if v4 := data[c.v4At : c.v4At+16]; !bytes.Equal(v4[:12], mapped) {
			t.Errorf("%v -> %v: the IPv4 address went as % x, want ::ffff: in front of it", c.src, c.dst, v4)
		}
		done, h, n, err := ParseStreamStrict(data)
		if !done || err != nil || h == nil || n != len(data) {
			t.Fatalf("%v -> %v: the header does not parse back: %v, %v", c.src, c.dst, done, err)
		}
		// To Go the mapped form is the same address.
		if h.SourceAddr.String() != c.src.String() || h.DestinationAddr.String() != c.dst.String() {
			t.Errorf("%v -> %v: parsed back as %v -> %v", c.src, c.dst, h.SourceAddr, h.DestinationAddr)
		}
	}
	var buf bytes.Buffer
	if err := WriteProxyHeaderV2(&buf, &net.UDPAddr{IP: net.IP{1, 2, 3}, Port: 1}, &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}); err == nil {
		t.Errorf("an address of 3 bytes: no error")
	}
}

// A UDP listener bound to all interfaces reports [::] as its own address while
// the client is IPv4: the header goes as IPv4 with dst 0.0.0.0 and the dst
// port kept. Before, the pair failed as a family mismatch and the datagram went
// to the backend with no header at all.
func TestWriteProxyHeaderV2_UnspecifiedListenerAddr(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src, dst net.Addr
		fam      byte
		dstIP    net.IP
	}{
		{"udp v4 client, [::] listener", &net.UDPAddr{IP: net.ParseIP("176.0.29.117"), Port: 54885}, &net.UDPAddr{IP: net.IPv6unspecified, Port: 17084}, 0x12, net.IPv4zero.To4()},
		{"udp v4 client, 0.0.0.0 listener", &net.UDPAddr{IP: net.ParseIP("176.0.29.117"), Port: 54885}, &net.UDPAddr{IP: net.IPv4zero, Port: 443}, 0x12, net.IPv4zero.To4()},
		{"udp v4 client, nil listener IP", &net.UDPAddr{IP: net.ParseIP("176.0.29.117"), Port: 54885}, &net.UDPAddr{Port: 443}, 0x12, net.IPv4zero.To4()},
		{"tcp v4 client, [::] listener", &net.TCPAddr{IP: net.ParseIP("176.0.29.117"), Port: 54885}, &net.TCPAddr{IP: net.IPv6unspecified, Port: 443}, 0x11, net.IPv4zero.To4()},
		{"udp v6 client, [::] listener", &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 54885}, &net.UDPAddr{IP: net.IPv6unspecified, Port: 443}, 0x22, net.IPv6unspecified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteProxyHeaderV2(&buf, tc.src, tc.dst); err != nil {
				t.Fatalf("WriteProxyHeaderV2: %v (no header means the backend gets the datagram raw)", err)
			}
			b := buf.Bytes()
			if b[13] != tc.fam {
				t.Fatalf("fam/proto 0x%X, want 0x%X", b[13], tc.fam)
			}
			n := 4
			if tc.fam>>4 == 2 {
				n = 16
			}
			dst := net.IP(b[16+n : 16+2*n])
			if !dst.Equal(tc.dstIP) {
				t.Fatalf("dst IP %v, want %v", dst, tc.dstIP)
			}
			dstPort := int(binary.BigEndian.Uint16(b[16+2*n+2:]))
			want := 0
			switch a := tc.dst.(type) {
			case *net.UDPAddr:
				want = a.Port
			case *net.TCPAddr:
				want = a.Port
			}
			if dstPort != want {
				t.Fatalf("dst port %d, want %d (the backend demuxes on it)", dstPort, want)
			}
		})
	}
}
