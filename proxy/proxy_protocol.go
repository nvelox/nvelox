package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

var (
	sigV2 = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

const (
	v2CmdProxy = 1
	v2Ver      = 2

	v2FamIPv4  = 0x10
	v2FamIPv6  = 0x20
	v2ProtoTCP = 1
	v2ProtoUDP = 2
)

// WriteProxyHeaderV2 writes the PROXY Protocol v2 header to the writer.
// It supports IPv4 and IPv6 over TCP and UDP.
func WriteProxyHeaderV2(w io.Writer, src, dst net.Addr) error {
	header := make([]byte, 16, 108) // Min 16 bytes for header + 0 addr
	copy(header, sigV2)

	// Version 2, Command PROXY
	header[12] = (v2Ver << 4) | v2CmdProxy

	var srcIP, dstIP net.IP
	var srcPort, dstPort int

	// Extract IP and Port
	if tcpAddr, ok := src.(*net.TCPAddr); ok {
		srcIP = tcpAddr.IP
		srcPort = tcpAddr.Port
	} else if udpAddr, ok := src.(*net.UDPAddr); ok {
		srcIP = udpAddr.IP
		srcPort = udpAddr.Port
	} else {
		return fmt.Errorf("unsupported address type: %T", src)
	}

	if tcpAddr, ok := dst.(*net.TCPAddr); ok {
		dstIP = tcpAddr.IP
		dstPort = tcpAddr.Port
	} else if udpAddr, ok := dst.(*net.UDPAddr); ok {
		dstIP = udpAddr.IP
		dstPort = udpAddr.Port
	} else {
		return fmt.Errorf("unsupported address type: %T", dst)
	}

	// A UDP listener bound to all interfaces (":443", ":17000-17100") reports
	// its own address as the dual-stack unspecified [::] while clients arrive
	// as IPv4: the pair failed as a family mismatch, so no header was written
	// and every UDP datagram went to the backend without one (HTTP/3 and UDP
	// tunnels behind send_proxy_v2 dropped all of them). An unspecified side
	// takes the other side's family; the backend reads only its port.
	srcIP, dstIP = matchUnspecified(srcIP, dstIP)

	// Family and Protocol
	sIP4 := srcIP.To4()
	dIP4 := dstIP.To4()

	if sIP4 != nil && dIP4 != nil {
		// IPv4
		header[13] = v2FamIPv4
		if _, ok := src.(*net.TCPAddr); ok {
			header[13] |= v2ProtoTCP
		} else {
			header[13] |= v2ProtoUDP
		}
		// Length (12 bytes for 2xIPv4 + 2xPort)
		binary.BigEndian.PutUint16(header[14:], 12)

		// Append Addrs
		header = append(header, sIP4...)
		header = append(header, dIP4...)

		portBuf := make([]byte, 4)
		binary.BigEndian.PutUint16(portBuf[0:], uint16(srcPort))
		binary.BigEndian.PutUint16(portBuf[2:], uint16(dstPort))
		header = append(header, portBuf...)

	} else if sIP4 == nil && dIP4 == nil {
		// IPv6
		header[13] = v2FamIPv6
		if _, ok := src.(*net.TCPAddr); ok {
			header[13] |= v2ProtoTCP
		} else {
			header[13] |= v2ProtoUDP
		}
		// Length (36 bytes for 2xIPv6 + 2xPort)
		binary.BigEndian.PutUint16(header[14:], 36)

		header = append(header, srcIP.To16()...)
		header = append(header, dstIP.To16()...)

		portBuf := make([]byte, 4)
		binary.BigEndian.PutUint16(portBuf[0:], uint16(srcPort))
		binary.BigEndian.PutUint16(portBuf[2:], uint16(dstPort))
		header = append(header, portBuf...)
	} else {
		return fmt.Errorf("IP family mismatch or unsupported")
	}

	_, err := w.Write(header)
	return err
}

// matchUnspecified gives an unspecified (or missing) address the other side's
// family, as that family's zero address: a UDP listener bound to all
// interfaces reports itself as [::] while its client is IPv4, and the pair then
// goes as IPv4 with dst 0.0.0.0 (dst port kept). Two concrete addresses of
// different families are left alone — still a mismatch.
func matchUnspecified(src, dst net.IP) (net.IP, net.IP) {
	unspec := func(ip net.IP) bool { return len(ip) == 0 || ip.IsUnspecified() }
	zeroLike := func(ip net.IP) net.IP {
		if ip.To4() != nil {
			return net.IPv4zero
		}
		return net.IPv6unspecified
	}
	switch {
	case unspec(dst) && !unspec(src):
		return src, zeroLike(src)
	case unspec(src) && !unspec(dst):
		return zeroLike(dst), dst
	}
	return src, dst
}
