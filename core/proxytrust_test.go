package core

import (
	"net"
	"testing"

	"github.com/pires/go-proxyproto"
)

func TestProxyTrust_Trusts(t *testing.T) {
	pt := newProxyTrust([]string{"10.20.0.0/16", "192.0.2.5/32"})
	if !pt.enabled() {
		t.Fatal("expected enabled")
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.20.1.1", true},
		{"10.21.0.1", false},
		{"192.0.2.5", true},
		{"192.0.2.6", false},
	}
	for _, c := range cases {
		got := pt.trusts(&net.TCPAddr{IP: net.ParseIP(c.ip), Port: 1234})
		if got != c.want {
			t.Errorf("trusts(%s) = %v, want %v", c.ip, got, c.want)
		}
	}

	// Empty = trust nobody; nil-safe.
	empty := newProxyTrust(nil)
	if empty.enabled() {
		t.Error("empty trust should be disabled")
	}
	if empty.trusts(&net.TCPAddr{IP: net.ParseIP("10.20.1.1"), Port: 1}) {
		t.Error("empty trust must trust nobody")
	}
	var nilPT *proxyTrust
	if nilPT.trusts(&net.TCPAddr{IP: net.ParseIP("10.20.1.1")}) {
		t.Error("nil trust must trust nobody")
	}

	// policy() only non-nil when enabled.
	if p, _ := empty.policy(); p != nil {
		t.Error("disabled trust must yield nil policy")
	}
	if p, err := pt.policy(); err != nil || p == nil {
		t.Errorf("enabled trust must yield a policy: p=%v err=%v", p, err)
	}
}

func TestTryParseInboundProxyV2(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 5555}
	dest := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}
	hdr := proxyproto.HeaderProxyFromAddrs(2, client, dest)
	full, err := hdr.Format()
	if err != nil {
		t.Fatalf("format header: %v", err)
	}

	// Full header parses, returns the real client + consumes exactly the header.
	done, src, consumed := tryParseInboundProxyV2(full)
	if !done || src == nil {
		t.Fatalf("full header: done=%v src=%v", done, src)
	}
	if consumed != len(full) {
		t.Errorf("consumed=%d want %d", consumed, len(full))
	}
	if got := src.(*net.TCPAddr).IP.String(); got != "203.0.113.7" {
		t.Errorf("src IP=%s want 203.0.113.7", got)
	}

	// Chunked: signature split across calls — must report not-done until complete.
	if done, _, _ := tryParseInboundProxyV2(full[:8]); done {
		t.Error("partial signature should not be done")
	}
	if done, _, _ := tryParseInboundProxyV2(full[:14]); done {
		t.Error("signature-only (no length yet) should not be done")
	}
	if done, _, _ := tryParseInboundProxyV2(full[:len(full)-1]); done {
		t.Error("header missing last byte should not be done")
	}

	// Header followed by payload: consumes only the header, leaving payload.
	withPayload := append(append([]byte{}, full...), []byte("hello-origin")...)
	done, src, consumed = tryParseInboundProxyV2(withPayload)
	if !done || src == nil || consumed != len(full) {
		t.Fatalf("header+payload: done=%v src=%v consumed=%d want consumed=%d", done, src, consumed, len(full))
	}
	if string(withPayload[consumed:]) != "hello-origin" {
		t.Errorf("payload remainder = %q", withPayload[consumed:])
	}

	// Raw (non-PROXY) traffic: done immediately, no source, nothing consumed.
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	done, src, consumed = tryParseInboundProxyV2(raw)
	if !done || src != nil || consumed != 0 {
		t.Errorf("raw: done=%v src=%v consumed=%d (want done,nil,0)", done, src, consumed)
	}

	// A short raw read that diverges from the signature is detected as raw.
	if done, src, _ := tryParseInboundProxyV2([]byte{0x16, 0x03, 0x01}); !done || src != nil {
		t.Errorf("short non-sig bytes should be raw: done=%v src=%v", done, src)
	}
}

// TestParseInboundProxyV2Datagram exercises the UDP (datagram) inbound parser
// used by the owner-region nvelox to recover the real client from a peer-region
// relay's per-datagram header (cross-region UDP #77 / N1). It round-trips against
// the SAME WriteProxyHeaderV2 the relay/send path uses, so writer↔parser stay
// symmetric.
func TestParseInboundProxyV2Datagram(t *testing.T) {
	// UDP DGRAM header (real client + the dedicated dst port), built exactly as
	// the tunnel-server relay / nvelox send path builds it.
	client := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 5555}
	dest := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 17042}
	hdr := proxyproto.HeaderProxyFromAddrs(2, client, dest)
	full, err := hdr.Format()
	if err != nil {
		t.Fatalf("format header: %v", err)
	}
	payload := []byte("wireguard-handshake")
	dgram := append(append([]byte{}, full...), payload...)

	src, consumed, isProxy := parseInboundProxyV2Datagram(dgram)
	if !isProxy || src == nil {
		t.Fatalf("isProxy=%v src=%v (want true, non-nil)", isProxy, src)
	}
	if consumed != len(full) {
		t.Errorf("consumed=%d want %d (header len)", consumed, len(full))
	}
	// go-proxyproto decodes a UDP/DGRAM header's source to a *net.UDPAddr;
	// ipOf handles both UDP and TCP addr types.
	if ip := ipOf(src); ip == nil || ip.String() != "203.0.113.7" {
		t.Errorf("src IP=%v want 203.0.113.7", src)
	}
	if string(dgram[consumed:]) != "wireguard-handshake" {
		t.Errorf("payload remainder = %q want %q", dgram[consumed:], payload)
	}

	// Raw datagram (no PROXY header): not a proxy datagram, nothing consumed.
	if src, consumed, isProxy := parseInboundProxyV2Datagram([]byte("\x00\x01\x02 raw dns query")); isProxy || src != nil || consumed != 0 {
		t.Errorf("raw datagram: isProxy=%v src=%v consumed=%d (want false,nil,0)", isProxy, src, consumed)
	}

	// Too-short datagram: treated as raw (no block).
	if _, _, isProxy := parseInboundProxyV2Datagram([]byte{0x0D, 0x0A}); isProxy {
		t.Error("short datagram should be treated as raw")
	}

	// Header truncated mid-address-block: treated as raw rather than blocking.
	if _, _, isProxy := parseInboundProxyV2Datagram(full[:len(full)-2]); isProxy {
		t.Error("truncated header datagram should be treated as raw")
	}
}
