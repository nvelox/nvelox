package proxy

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

// relayed builds a UDP header naming client for dst, signed in version 2
// for payload by the relay socket at port relayPort as its header counter,
// and returns it as the receiver parses it.
func relayed(t testing.TB, key, payload []byte, now time.Time, relayPort uint16, counter uint64) *proxyproto.Header {
	t.Helper()
	hdr := formatV2(proxyproto.PROXY, proxyproto.UDPv4, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53})
	signed, err := SignedHeaderBytesFrom(hdr, key, payload, now, relayPort, counter)
	if err != nil {
		t.Fatal(err)
	}
	h, n, err := ParseDatagramStrict(append(signed, payload...))
	if err != nil || n != len(signed) {
		t.Fatalf("a signed header does not parse: %v", err)
	}
	return h
}

// A version 2 signature holds for the relay socket's port it was made for
// and gives back its counter; a copy from another port, or with another
// counter, another payload or another time, does not pass. A version 1
// signature passes uncounted, from any port; a version 1 receiver (Verify)
// refuses version 2.
func TestSignatureV2_BoundToPortAndCounter(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	payload := []byte("a datagram")
	now := time.Unix(1_800_000_000, 0)
	h := relayed(t, key, payload, now, 40001, 812)
	keys := [][]byte{[]byte("another key, not the one used!!!"), key}

	if c, counted, err := VerifyFrom(h, keys, payload, now, 40001); err != nil || !counted || c != 812 {
		t.Fatalf("from its own port: counter %d counted %v, %v; want 812, true, nil", c, counted, err)
	}
	if _, _, err := VerifyFrom(h, keys, payload, now, 50123); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("a copy from another port: %v, want ErrSignatureInvalid", err)
	}
	if _, _, err := VerifyFrom(h, keys, []byte("another one"), now, 40001); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("another payload: %v, want ErrSignatureInvalid", err)
	}
	if _, _, err := VerifyFrom(h, keys, payload, now.Add(SignatureWindow+time.Second), 40001); !errors.Is(err, ErrSignatureExpired) {
		t.Errorf("31 s later: %v, want ErrSignatureExpired", err)
	}
	if err := Verify(h, keys, payload, now); !errors.Is(err, ErrSignatureMalformed) {
		t.Errorf("a version 1 receiver given version 2: %v, want ErrSignatureMalformed", err)
	}

	// The counter is covered: one changed in the TLV does not pass.
	raw, _ := h.Format()
	i := bytes.Index(raw, []byte{byte(SignatureTLV), 0, signatureV2Len, signatureV2})
	if i < 0 {
		t.Fatal("no version 2 signature TLV in the header")
	}
	raw[i+3+1+8+7] ^= 1 // the counter's last byte
	th, _, err := ParseDatagramStrict(append(raw, payload...))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyFrom(th, keys, payload, now, 40001); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("another counter in the header: %v, want ErrSignatureInvalid", err)
	}

	// Version 1: no counter, no port.
	hdr := formatV2(proxyproto.PROXY, proxyproto.UDPv4, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53})
	signed, _ := SignedHeaderBytes(hdr, key, payload, now)
	h1, _, _ := ParseDatagramStrict(append(signed, payload...))
	for _, port := range []uint16{40001, 50123} {
		if c, counted, err := VerifyFrom(h1, keys, payload, now, port); err != nil || counted || c != 0 {
			t.Errorf("version 1 from port %d: %d %v %v, want 0, false, nil", port, c, counted, err)
		}
	}

	// A stream header is bound to its connection's port; its counter is 0.
	sh := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443})
	if err := SignHeaderFrom(sh, key, now, 40002); err != nil {
		t.Fatal(err)
	}
	sraw, _ := sh.Format()
	ph, err := ReadStreamHeader(bytes.NewReader(sraw))
	if err != nil {
		t.Fatal(err)
	}
	if c, counted, err := VerifyFrom(ph, keys, nil, now, 40002); err != nil || !counted || c != 0 {
		t.Errorf("a stream header on its connection: %d %v %v, want 0, true, nil", c, counted, err)
	}
	if _, _, err := VerifyFrom(ph, keys, nil, now, 40003); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("a stream header on another connection: %v, want ErrSignatureInvalid", err)
	}
}

// A relay socket's window takes a counter once, out of order within the 64
// below the highest, and refuses what it took and what is older.
func TestReplayWindow(t *testing.T) {
	var w ReplayWindow
	for i, c := range []struct {
		n    uint64
		take bool
	}{
		{100, true}, {100, false}, {101, true}, {99, true}, {99, false},
		{164, true}, {101, false}, {102, true}, {100, false}, {164, false},
		{1000, true}, {937, true}, {936, false}, {1001, true}, {1000, false},
		{1 << 62, true}, {1<<62 - 63, true}, {1<<62 - 64, false},
	} {
		if got := w.Take(c.n); got != c.take {
			t.Fatalf("step %d: Take(%d) = %v, want %v", i, c.n, got, c.take)
		}
	}
	var zero ReplayWindow
	if !zero.Take(0) || zero.Take(0) {
		t.Error("counter 0: taken once, then refused")
	}
}

// FuzzReplayWindow: the window decides as a plain record of every counter
// taken does: a counter passes when it was not taken and is above the
// highest taken less 64.
func FuzzReplayWindow(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0, 65, 0, 1, 0, 2})
	f.Add([]byte{255, 254, 200, 3, 3, 130, 129, 2})
	f.Fuzz(func(t *testing.T, steps []byte) {
		var w ReplayWindow
		taken := map[uint64]bool{}
		var top uint64
		base := uint64(1 << 40)
		for i, s := range steps {
			c := base + uint64(s)*3 // jumps of up to 765, steps back and forth
			if i%5 == 4 {
				base += 70 // and now and then the whole range moves past the window
			}
			want := len(taken) == 0 || c > top || (top-c < 64 && !taken[c])
			if got := w.Take(c); got != want {
				t.Fatalf("step %d: Take(%d) = %v, the record says %v (highest %d)", i, c, got, want, top)
			}
			if want {
				taken[c] = true
				if c > top {
					top = c
				}
			}
		}
	})
}

// A Trust with accept_proxy_replay_window required refuses a version 1
// signature; when_present takes both, version 2 counted.
func TestTrust_ReplayWindowRequired(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	payload := []byte("a datagram")
	now := time.Now()
	v2 := relayed(t, key, payload, now, 40001, 7)
	hdr := formatV2(proxyproto.PROXY, proxyproto.UDPv4, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53})
	signed, _ := SignedHeaderBytes(hdr, key, payload, now)
	v1, _, _ := ParseDatagramStrict(append(signed, payload...))

	tr := NewTrust([]string{"0.0.0.0/0"}, [][]byte{key})
	if c, counted, err := tr.VerifyFrom(v2, payload, true, 40001); err != nil || !counted || c != 7 {
		t.Errorf("when_present, version 2: %d %v %v", c, counted, err)
	}
	if _, counted, err := tr.VerifyFrom(v1, payload, true, 40001); err != nil || counted {
		t.Errorf("when_present, version 1: counted %v, %v; want it taken uncounted", counted, err)
	}
	tr.SetReplayWindow(true)
	if !tr.ReplayWindowRequired() {
		t.Error("required is not reported")
	}
	if _, _, err := tr.VerifyFrom(v1, payload, true, 40001); !errors.Is(err, ErrSignatureUncounted) {
		t.Errorf("required, version 1: %v, want ErrSignatureUncounted", err)
	}
	if c, counted, err := tr.VerifyFrom(v2, payload, true, 40001); err != nil || !counted || c != 7 {
		t.Errorf("required, version 2: %d %v %v", c, counted, err)
	}
	if _, _, err := tr.VerifyFrom(v2, payload, false, 40001); !errors.Is(err, ErrSignatureMalformed) {
		t.Errorf("a datagram header on a stream: %v, want ErrSignatureMalformed", err)
	}
	if _, counted, err := NewTrust([]string{"0.0.0.0/0"}, nil).VerifyFrom(v1, payload, true, 1); err != nil || counted {
		t.Errorf("without keys: counted %v, %v; want every header taken", counted, err)
	}
}
