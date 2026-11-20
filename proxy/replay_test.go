package proxy

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

// testEnds are the ends of a relay's datagram, or connection, in the tests:
// the relay's socket and the receiver's.
var testEnds = Ends{Relay: netip.MustParseAddrPort("192.0.2.50:40001"), Receiver: netip.MustParseAddrPort("198.51.100.10:9000")}

// relayed builds a UDP header naming client for dst, signed in version 2
// for payload, for a datagram with the ends ends, as its relay socket's
// header counter, and returns it as the receiver parses it.
func relayed(t testing.TB, key, payload []byte, now time.Time, ends Ends, counter uint64) *proxyproto.Header {
	t.Helper()
	hdr := formatV2(proxyproto.PROXY, proxyproto.UDPv4, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53})
	signed, err := SignedHeaderBytesFrom(hdr, key, payload, now, ends, counter)
	if err != nil {
		t.Fatal(err)
	}
	h, n, err := ParseDatagramStrict(append(signed, payload...))
	if err != nil || n != len(signed) {
		t.Fatalf("a signed header does not parse: %v", err)
	}
	return h
}

// A version 2 signature holds for the two ends it was made for and gives
// back its counter, whichever form an IPv4 end comes in; a copy from
// another address or port of a relay, or to another address or port of the
// receiver, or with another counter, another payload or another time, does
// not pass, and ends that are not known pass nothing. A version 1 signature
// passes uncounted, whatever the ends; a version 1 receiver (Verify)
// refuses version 2.
func TestSignatureV2_BoundToBothEndsAndCounter(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	payload := []byte("a datagram")
	now := time.Unix(1_800_000_000, 0)
	h := relayed(t, key, payload, now, testEnds, 812)
	keys := [][]byte{[]byte("another key, not the one used!!!"), key}

	if c, counted, err := VerifyFrom(h, keys, payload, now, testEnds); err != nil || !counted || c != 812 {
		t.Fatalf("with its own ends: counter %d counted %v, %v; want 812, true, nil", c, counted, err)
	}
	mapped := Ends{Relay: netip.MustParseAddrPort("[::ffff:192.0.2.50]:40001"), Receiver: netip.MustParseAddrPort("[::ffff:198.51.100.10]:9000")}
	if c, _, err := VerifyFrom(h, keys, payload, now, mapped); err != nil || c != 812 {
		t.Errorf("its ends in their IPv4-mapped form: %d, %v; want 812, nil", c, err)
	}
	for what, e := range map[string]Ends{
		"from another port of the relay":        {Relay: netip.MustParseAddrPort("192.0.2.50:50123"), Receiver: testEnds.Receiver},
		"from another trusted address":          {Relay: netip.MustParseAddrPort("192.0.2.51:40001"), Receiver: testEnds.Receiver},
		"to another port of the receiver":       {Relay: testEnds.Relay, Receiver: netip.MustParseAddrPort("198.51.100.10:9001")},
		"to another address of the receiver":    {Relay: testEnds.Relay, Receiver: netip.MustParseAddrPort("198.51.100.11:9000")},
		"with the two ends the other way round": {Relay: testEnds.Receiver, Receiver: testEnds.Relay},
	} {
		if _, _, err := VerifyFrom(h, keys, payload, now, e); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("a copy %s: %v, want ErrSignatureInvalid", what, err)
		}
	}
	if _, _, err := VerifyFrom(h, keys, payload, now, Ends{Relay: testEnds.Relay}); !errors.Is(err, ErrEndsUnknown) {
		t.Errorf("the receiver's end not known: %v, want ErrEndsUnknown", err)
	}
	if _, err := SignFrom(key, h, payload, now, Ends{Receiver: testEnds.Receiver}, 1); !errors.Is(err, ErrEndsUnknown) {
		t.Errorf("signed without the relay's end: %v, want ErrEndsUnknown", err)
	}
	if _, _, err := VerifyFrom(h, keys, []byte("another one"), now, testEnds); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("another payload: %v, want ErrSignatureInvalid", err)
	}
	if _, _, err := VerifyFrom(h, keys, payload, now.Add(SignatureWindow+time.Second), testEnds); !errors.Is(err, ErrSignatureExpired) {
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
	if _, _, err := VerifyFrom(th, keys, payload, now, testEnds); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("another counter in the header: %v, want ErrSignatureInvalid", err)
	}

	// Version 1: no counter, no ends.
	hdr := formatV2(proxyproto.PROXY, proxyproto.UDPv4, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53})
	signed, _ := SignedHeaderBytes(hdr, key, payload, now)
	h1, _, _ := ParseDatagramStrict(append(signed, payload...))
	for _, e := range []Ends{testEnds, {Relay: netip.MustParseAddrPort("192.0.2.51:50123"), Receiver: testEnds.Receiver}, {}} {
		if c, counted, err := VerifyFrom(h1, keys, payload, now, e); err != nil || counted || c != 0 {
			t.Errorf("version 1 with the ends %v: %d %v %v, want 0, false, nil", e, c, counted, err)
		}
	}

	// A stream header is bound to its connection's ends; its counter is 0.
	sh := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443})
	if err := SignHeaderFrom(sh, key, now, testEnds); err != nil {
		t.Fatal(err)
	}
	sraw, _ := sh.Format()
	ph, err := ReadStreamHeader(bytes.NewReader(sraw))
	if err != nil {
		t.Fatal(err)
	}
	if c, counted, err := VerifyFrom(ph, keys, nil, now, testEnds); err != nil || !counted || c != 0 {
		t.Errorf("a stream header on its connection: %d %v %v, want 0, true, nil", c, counted, err)
	}
	for what, e := range map[string]Ends{
		"another connection of the relay's": {Relay: netip.MustParseAddrPort("192.0.2.50:40002"), Receiver: testEnds.Receiver},
		"a connection of another relay's":   {Relay: netip.MustParseAddrPort("192.0.2.51:40001"), Receiver: testEnds.Receiver},
		"a connection to another listener":  {Relay: testEnds.Relay, Receiver: netip.MustParseAddrPort("198.51.100.10:9443")},
		"a connection to another address":   {Relay: testEnds.Relay, Receiver: netip.MustParseAddrPort("198.51.100.12:9000")},
	} {
		if _, _, err := VerifyFrom(ph, keys, nil, now, e); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("a stream header on %s: %v, want ErrSignatureInvalid", what, err)
		}
	}
}

// A version 2 counter may not be ahead of its header's time by more than
// SignatureWindow: a relay's counter starts at its clock in nanoseconds
// and goes up by one a header. One that is would hold its relay socket's
// window above every counter that socket sends next.
func TestSignatureV2_CounterFitsItsTime(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	keys := [][]byte{key}
	payload := []byte("a datagram")
	now := time.Unix(1_800_000_000, 0)
	limit := uint64(now.Add(SignatureWindow).UnixNano())
	for _, c := range []struct {
		counter uint64
		ok      bool
	}{{1, true}, {uint64(now.UnixNano()), true}, {limit, true}, {limit + 1, false}, {1<<64 - 1, false}} {
		h := relayed(t, key, payload, now, testEnds, c.counter)
		got, _, err := VerifyFrom(h, keys, payload, now, testEnds)
		switch {
		case c.ok && (err != nil || got != c.counter):
			t.Errorf("counter %d: %d, %v; want it taken", c.counter, got, err)
		case !c.ok && !errors.Is(err, ErrCounterAhead):
			t.Errorf("counter %d, %d ns after the header's time: %v, want ErrCounterAhead", c.counter, c.counter-uint64(now.UnixNano()), err)
		}
	}
}

// NextCounter: a socket's first counter is the clock in nanoseconds, then
// one more for each, also from several goroutines at once.
func TestNextCounter(t *testing.T) {
	var c atomic.Uint64
	now := time.Unix(1_800_000_000, 123)
	first := uint64(now.UnixNano())
	if got := NextCounter(&c, now); got != first {
		t.Fatalf("first counter %d, want the clock in nanoseconds %d", got, first)
	}
	if got := NextCounter(&c, now.Add(time.Hour)); got != first+1 {
		t.Fatalf("second counter %d, want %d", got, first+1)
	}
	var wg sync.WaitGroup
	got := make([]uint64, 8*100)
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 100 {
				got[g*100+i] = NextCounter(&c, now)
			}
		}()
	}
	wg.Wait()
	slices.Sort(got)
	for i, n := range got {
		if want := first + 2 + uint64(i); n != want {
			t.Fatalf("from several goroutines: %d in place %d, want %d: each counter once, none left out", n, i, want)
		}
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
	v2 := relayed(t, key, payload, now, testEnds, 7)
	hdr := formatV2(proxyproto.PROXY, proxyproto.UDPv4, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53})
	signed, _ := SignedHeaderBytes(hdr, key, payload, now)
	v1, _, _ := ParseDatagramStrict(append(signed, payload...))

	tr := NewTrust([]string{"0.0.0.0/0"}, [][]byte{key})
	if c, counted, err := tr.VerifyFrom(v2, payload, true, testEnds); err != nil || !counted || c != 7 {
		t.Errorf("when_present, version 2: %d %v %v", c, counted, err)
	}
	if _, counted, err := tr.VerifyFrom(v1, payload, true, testEnds); err != nil || counted {
		t.Errorf("when_present, version 1: counted %v, %v; want it taken uncounted", counted, err)
	}
	tr.SetReplayWindow(true)
	if !tr.ReplayWindowRequired() {
		t.Error("required is not reported")
	}
	if _, _, err := tr.VerifyFrom(v1, payload, true, testEnds); !errors.Is(err, ErrSignatureUncounted) {
		t.Errorf("required, version 1: %v, want ErrSignatureUncounted", err)
	}
	if c, counted, err := tr.VerifyFrom(v2, payload, true, testEnds); err != nil || !counted || c != 7 {
		t.Errorf("required, version 2: %d %v %v", c, counted, err)
	}
	if _, _, err := tr.VerifyFrom(v2, payload, false, testEnds); !errors.Is(err, ErrSignatureMalformed) {
		t.Errorf("a datagram header on a stream: %v, want ErrSignatureMalformed", err)
	}
	if _, counted, err := NewTrust([]string{"0.0.0.0/0"}, nil).VerifyFrom(v1, payload, true, Ends{}); err != nil || counted {
		t.Errorf("without keys: counted %v, %v; want every header taken", counted, err)
	}
}
