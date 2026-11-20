package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"testing/iotest"
	"time"

	"github.com/pires/go-proxyproto"
)

func v2Header(t *testing.T, h *proxyproto.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := h.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func tcpHeader(t *testing.T) []byte {
	return v2Header(t, proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}))
}

// ParseStreamStrict waits for the whole header, names the client, and
// tells a missing header from a broken one.
func TestParseStreamStrict(t *testing.T) {
	hdr := tcpHeader(t)
	for n := 0; n < len(hdr); n++ {
		if done, _, _, err := ParseStreamStrict(hdr[:n]); done || err != nil {
			t.Fatalf("%d of %d bytes: done=%v err=%v, want to wait", n, len(hdr), done, err)
		}
	}
	stream := append(append([]byte{}, hdr...), "GET / HTTP/1.1\r\n"...)
	done, h, consumed, err := ParseStreamStrict(stream)
	if !done || err != nil || h == nil || consumed != len(hdr) {
		t.Fatalf("a header and a request: done=%v h=%v consumed=%d err=%v, want the header's %d bytes", done, h, consumed, err, len(hdr))
	}
	if got := h.SourceAddr.String(); got != "203.0.113.7:4444" {
		t.Fatalf("client %s, want 203.0.113.7:4444", got)
	}

	local := v2Header(t, &proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC})
	if done, h, consumed, err := ParseStreamStrict(local); !done || h != nil || err != nil || consumed != len(local) {
		t.Fatalf("LOCAL: done=%v h=%v consumed=%d err=%v, want no client and no error", done, h, consumed, err)
	}

	// Anything else at the start is no header, from its first byte on.
	for _, s := range []string{"G", "GET / HTTP/1.1\r\n\r\n", "PROXY TCP4 203.0.113.7 192.0.2.1 4444 443\r\n", "\r\n\r\n\x00\r\nQUIX\n", "\x16\x03\x01"} {
		if done, _, _, err := ParseStreamStrict([]byte(s)); !done || !errors.Is(err, ErrNoHeader) {
			t.Errorf("%q: done=%v err=%v, want ErrNoHeader", s, done, err)
		}
	}

	bad := map[string][]byte{
		"addresses cut short":     append(append([]byte{}, V2Signature...), 0x21, 0x11, 0x00, 0x04, 1, 2, 3, 4),
		"version 1 in the byte":   append(append([]byte{}, V2Signature...), 0x11, 0x11, 0x00, 0x0c, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
		"a command that is none":  append(append([]byte{}, V2Signature...), 0x2f, 0x11, 0x00, 0x0c, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
		"PROXY without addresses": append(append([]byte{}, V2Signature...), 0x21, 0x00, 0x00, 0x00),
	}
	for name, b := range bad {
		done, h, consumed, err := ParseStreamStrict(b)
		if !done || h != nil || !errors.Is(err, ErrBadHeader) || consumed != len(b) {
			t.Errorf("%s: done=%v h=%v consumed=%d err=%v, want ErrBadHeader over %d bytes", name, done, h, consumed, err, len(b))
		}
	}
}

// ReadStreamHeader takes the header and not one byte more, and says what
// ended a read that brought none.
func TestReadStreamHeader(t *testing.T) {
	hdr := tcpHeader(t)
	rest := "GET / HTTP/1.1\r\n\r\n"
	r := bytes.NewReader(append(append([]byte{}, hdr...), rest...))
	h, err := ReadStreamHeader(r)
	if err != nil || h == nil || h.SourceAddr.String() != "203.0.113.7:4444" {
		t.Fatalf("header %v, err %v", h, err)
	}
	if left, _ := io.ReadAll(r); string(left) != rest {
		t.Fatalf("after the header %q is left, want %q", left, rest)
	}

	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"nothing":                  {nil, ErrNothingSent},
		"a request":                {[]byte(rest), ErrNoHeader},
		"three bytes of a request": {[]byte("GET"), ErrNoHeader},
		"five bytes of a header":   {hdr[:5], io.ErrUnexpectedEOF},
		"the magic alone":          {hdr[:12], io.EOF},
		"all but the last byte":    {hdr[:len(hdr)-1], io.ErrUnexpectedEOF},
		"addresses cut short":      {append(append([]byte{}, V2Signature...), 0x21, 0x11, 0x00, 0x04, 1, 2, 3, 4), ErrBadHeader},
	} {
		h, err := ReadStreamHeader(bytes.NewReader(tc.in))
		if h != nil || !errors.Is(err, tc.want) {
			t.Errorf("%s: header %v, err %v; want %v", name, h, err, tc.want)
		}
		if tc.want != ErrNothingSent && errors.Is(err, ErrNothingSent) {
			t.Errorf("%s: reported as nothing sent", name)
		}
	}

	// The two readers agree on every header they are given whole.
	for name, b := range map[string][]byte{
		"tcp":   hdr,
		"local": v2Header(t, &proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}),
		"udp": v2Header(t, proxyproto.HeaderProxyFromAddrs(2,
			&net.UDPAddr{IP: net.ParseIP("2001:db8::7"), Port: 4444}, &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443})),
		"bad": append(append([]byte{}, V2Signature...), 0x21, 0x00, 0x00, 0x00),
	} {
		_, ph, _, perr := ParseStreamStrict(b)
		rh, rerr := ReadStreamHeader(bytes.NewReader(b))
		if (ph == nil) != (rh == nil) || !errors.Is(rerr, perr) && perr != rerr {
			t.Errorf("%s: parsed (%v, %v), read (%v, %v)", name, ph, perr, rh, rerr)
		}
	}
}

// A stream that starts with anything else is recognised at its first
// bytes: the reader does not wait for the rest of a header that is not
// coming. A header that arrives a byte at a time is read whole.
func TestReadStreamHeader_AsItArrives(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go a.Write([]byte("hel")) // and then the peer waits for an answer
	done := make(chan error, 1)
	go func() {
		_, err := ReadStreamHeader(b)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNoHeader) {
			t.Fatalf("three bytes of something else: %v, want ErrNoHeader", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("three bytes of something else: the reader waits for more")
	}

	hdr := tcpHeader(t)
	rest := "payload"
	r := bytes.NewReader(append(append([]byte{}, hdr...), rest...))
	h, err := ReadStreamHeader(iotest.OneByteReader(r))
	if err != nil || h == nil || h.SourceAddr.String() != "203.0.113.7:4444" {
		t.Fatalf("a byte at a time: header %v, err %v", h, err)
	}
	if left, _ := io.ReadAll(r); string(left) != rest {
		t.Fatalf("after the header %q is left, want %q", left, rest)
	}
}

// A Trust with no relays, or none at all, trusts nobody.
func TestTrustNobodyByDefault(t *testing.T) {
	peer := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}
	var none *Trust
	for name, tr := range map[string]*Trust{"nil": none, "empty": NewTrust(nil, nil)} {
		if tr.Enabled() || tr.Trusts(peer) || tr.TrustsIP(peer.IP) || tr.Keys() != nil || len(tr.Nets()) != 0 {
			t.Errorf("%s trust trusts someone", name)
		}
	}
	tr := NewTrust([]string{"10.0.0.0/24", "2001:db8::/32"}, nil)
	for ip, want := range map[string]bool{"10.0.0.1": true, "10.0.1.1": false, "2001:db8::1": true, "2001:db9::1": false, "::ffff:10.0.0.1": true} {
		if got := tr.TrustsIP(net.ParseIP(ip)); got != want {
			t.Errorf("%s trusted = %v, want %v", ip, got, want)
		}
	}
	if tr.Trusts(nil) || tr.TrustsIP(nil) {
		t.Error("no address is trusted")
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// StreamClient names the client, or says why a relay's connection is closed.
func TestStreamClient(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef-test-key")
	open, keyed := NewTrust([]string{"10.0.0.0/8"}, nil), NewTrust([]string{"10.0.0.0/8"}, [][]byte{key})
	parse := func(b []byte) (*proxyproto.Header, error) {
		t.Helper()
		done, h, _, err := ParseStreamStrict(b)
		if !done {
			t.Fatal("header not complete")
		}
		return h, err
	}
	tcp := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443})
	signed := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443})
	if err := SignHeader(signed, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	other := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443})
	if err := SignHeader(other, []byte("another-key-0123456789abcdef0123456789"), time.Now()); err != nil {
		t.Fatal(err)
	}
	udp := proxyproto.HeaderProxyFromAddrs(2, &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443})
	local := &proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
	// Version 2, made for the relay's connection with the ends testEnds.
	signedV2 := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443})
	if err := SignHeaderFrom(signedV2, key, time.Now(), testEnds); err != nil {
		t.Fatal(err)
	}
	required := NewTrust([]string{"10.0.0.0/8"}, [][]byte{key})
	required.SetReplayWindow(true)

	for name, tc := range map[string]struct {
		trust  *Trust
		hdr    []byte // parsed when set
		err    error  // else what the read returned
		client string
		reason string
	}{
		"a client":                  {open, v2Header(t, tcp), nil, "203.0.113.7:4444", ""},
		"LOCAL":                     {open, v2Header(t, local), nil, "", ""},
		"LOCAL with keys":           {keyed, v2Header(t, local), nil, "", ""},
		"a datagram's header":       {open, v2Header(t, udp), nil, "", RefusedMalformed},
		"signed, keys set":          {keyed, v2Header(t, signed), nil, "203.0.113.7:4444", ""},
		"signed, no keys":           {open, v2Header(t, signed), nil, "203.0.113.7:4444", ""},
		"unsigned, keys set":        {keyed, v2Header(t, tcp), nil, "", RefusedSignature},
		"another key":               {keyed, v2Header(t, other), nil, "", RefusedSignature},
		"no header":                 {open, nil, ErrNoHeader, "", RefusedMissing},
		"a broken header":           {open, nil, ErrBadHeader, "", RefusedMalformed},
		"cut short":                 {open, nil, io.ErrUnexpectedEOF, "", RefusedMalformed},
		"stalled":                   {open, nil, timeoutErr{}, "", RefusedTimeout},
		"nothing sent":              {open, nil, ErrNothingSent, "", NothingSent},
		"nothing sent, keys set":    {keyed, nil, ErrNothingSent, "", NothingSent},
		"a broken header, keys set": {keyed, nil, ErrBadHeader, "", RefusedMalformed},
		"version 2, its connection": {keyed, v2Header(t, signedV2), nil, "203.0.113.7:4444", ""},
		"version 2, required":       {required, v2Header(t, signedV2), nil, "203.0.113.7:4444", ""},
		"version 1, required":       {required, v2Header(t, signed), nil, "", RefusedSignature},
	} {
		var h *proxyproto.Header
		err := tc.err
		if tc.hdr != nil {
			h, err = parse(tc.hdr)
		}
		client, reason, cause := tc.trust.StreamClient(h, err, testEnds)
		got := ""
		if client != nil {
			got = client.String()
		}
		if got != tc.client || reason != tc.reason {
			t.Errorf("%s: client %q, reason %q; want %q, %q", name, got, reason, tc.client, tc.reason)
		}
		// A reason always comes with the error behind it, for the log.
		if (reason != "") != (cause != nil) {
			t.Errorf("%s: reason %q with cause %v", name, reason, cause)
		}
	}
	// A version 2 header copied onto another connection of the relay's.
	h, err := parse(v2Header(t, signedV2))
	another := Ends{Relay: netip.MustParseAddrPort("192.0.2.50:40002"), Receiver: testEnds.Receiver}
	if client, reason, _ := keyed.StreamClient(h, err, another); client != nil || reason != RefusedSignature {
		t.Errorf("version 2 on another connection: client %v, reason %q; want refused for its signature", client, reason)
	}
}

// ParseDatagramStrict takes a datagram that starts with a complete v2
// header naming a datagram client, and nothing else.
func TestParseDatagramStrict(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4321}
	dst := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	var b bytes.Buffer
	if err := WriteProxyHeaderV2(&b, src, dst); err != nil {
		t.Fatal(err)
	}
	good := append(b.Bytes(), "payload"...)
	hdr, n, err := ParseDatagramStrict(good)
	if err != nil || string(good[n:]) != "payload" {
		t.Fatalf("a good datagram: n=%d, %v", n, err)
	}
	if ua := hdr.SourceAddr.(*net.UDPAddr); !ua.IP.Equal(src.IP) || ua.Port != src.Port {
		t.Errorf("source %v, want %v", ua, src)
	}

	var sb bytes.Buffer
	if err := WriteProxyHeaderV2(&sb, &net.TCPAddr{IP: src.IP, Port: src.Port}, &net.TCPAddr{IP: dst.IP, Port: dst.Port}); err != nil {
		t.Fatal(err)
	}
	local := append(append([]byte{}, V2Signature...), 0x20, 0x00, 0x00, 0x00)
	for name, tc := range map[string]struct {
		data []byte
		want error
	}{
		"no header":           {[]byte("a QUIC packet, long enough to hold a header"), ErrNoHeader},
		"empty":               {nil, ErrNoHeader},
		"the magic only":      {append([]byte{}, V2Signature...), ErrBadHeader},
		"cut short":           {good[:20], ErrBadHeader},
		"a LOCAL header":      {local, ErrBadHeader},
		"a stream header":     {sb.Bytes(), ErrBadHeader},
		"an unknown protocol": {append(append([]byte{}, V2Signature...), 0x21, 0x00, 0x00, 0x00), ErrBadHeader},
	} {
		if _, _, err := ParseDatagramStrict(tc.data); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}
