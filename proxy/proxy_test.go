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

func TestWriteProxyHeaderV2_Mismatch(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 80}

	var buf bytes.Buffer
	err := WriteProxyHeaderV2(&buf, src, dst)
	if err == nil {
		t.Fatal("Expected error for mismatched address families, got nil")
	}
}
