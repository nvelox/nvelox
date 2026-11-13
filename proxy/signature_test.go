package proxy

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

var (
	keyA = []byte("0123456789abcdef0123456789abcdef-key-A")
	keyB = []byte("0123456789abcdef0123456789abcdef-key-B")
)

func parseHeader(t *testing.T, b []byte) (*proxyproto.Header, []byte) {
	t.Helper()
	r := bufioReader(b)
	h, err := proxyproto.Read(r)
	if err != nil {
		t.Fatal(err)
	}
	rest := make([]byte, r.Buffered())
	r.Read(rest)
	return h, rest
}

// TestSignature_Datagram: a UDP header signed over its payload verifies; a
// changed payload, address, key or time does not; a receiver holding several
// keys (rotation) accepts any of them.
func TestSignature_Datagram(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 5555}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 17042}
	var base bytes.Buffer
	if err := WriteProxyHeaderV2(&base, src, dst); err != nil {
		t.Fatal(err)
	}
	payload := []byte("datagram payload")
	signed, err := SignedHeaderBytes(base.Bytes(), keyA, payload, now)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := parseHeader(t, append(append([]byte{}, signed...), payload...))
	if h.SourceAddr.String() != src.String() {
		t.Fatalf("source %v, want %v", h.SourceAddr, src)
	}
	if err := Verify(h, [][]byte{keyA}, payload, now); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	if err := Verify(h, [][]byte{keyB, keyA}, payload, now.Add(20*time.Second)); err != nil {
		t.Fatalf("second key of a rotation, 20 s later: %v", err)
	}
	for name, c := range map[string]struct {
		keys    [][]byte
		payload []byte
		now     time.Time
		want    error
	}{
		"other payload": {[][]byte{keyA}, []byte("forged payload!!"), now, ErrSignatureInvalid},
		"wrong key":     {[][]byte{keyB}, payload, now, ErrSignatureInvalid},
		"too old":       {[][]byte{keyA}, payload, now.Add(31 * time.Second), ErrSignatureExpired},
		"from future":   {[][]byte{keyA}, payload, now.Add(-31 * time.Second), ErrSignatureExpired},
	} {
		if err := Verify(h, c.keys, c.payload, c.now); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// The same signature on a header naming another client.
	var other bytes.Buffer
	WriteProxyHeaderV2(&other, &net.UDPAddr{IP: net.ParseIP("192.0.2.66"), Port: 5555}, dst)
	tlvs, _ := h.TLVs()
	forged, err := AppendTLV(other.Bytes(), tlvs[0])
	if err != nil {
		t.Fatal(err)
	}
	fh, _ := parseHeader(t, forged)
	if err := Verify(fh, [][]byte{keyA}, payload, now); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("signature moved to another client: %v, want ErrSignatureInvalid", err)
	}
	// Unsigned and malformed.
	uh, _ := parseHeader(t, base.Bytes())
	if err := Verify(uh, [][]byte{keyA}, payload, now); !errors.Is(err, ErrSignatureMissing) {
		t.Errorf("unsigned: %v, want ErrSignatureMissing", err)
	}
	bad, _ := AppendTLV(base.Bytes(), proxyproto.TLV{Type: SignatureTLV, Value: []byte{1, 2, 3}})
	bh, _ := parseHeader(t, bad)
	if err := Verify(bh, [][]byte{keyA}, payload, now); !errors.Is(err, ErrSignatureMalformed) {
		t.Errorf("short signature: %v, want ErrSignatureMalformed", err)
	}
}

// TestSignature_Stream: a TCP header built with go-proxyproto and signed with
// Sign round-trips through Format/Read.
func TestSignature_Stream(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 40000},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443})
	tlv, err := Sign(keyA, h, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetTLVs([]proxyproto.TLV{tlv}); err != nil {
		t.Fatal(err)
	}
	raw, err := h.Format()
	if err != nil {
		t.Fatal(err)
	}
	ph, _ := parseHeader(t, raw)
	if err := Verify(ph, [][]byte{keyA}, nil, now); err != nil {
		t.Fatalf("stream signature: %v", err)
	}
	if err := Verify(ph, [][]byte{keyA}, []byte("x"), now); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("stream signature checked with a payload: %v", err)
	}
}
