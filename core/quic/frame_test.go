package quic

import (
	"bytes"
	"testing"
)

func mustParse(t *testing.T, p []byte) Frame {
	t.Helper()
	var f Frame
	n, err := ParseFrame(p, &f)
	if err != nil || n != len(p) {
		t.Fatalf("frame %x: n=%d of %d, %v", p, n, len(p), err)
	}
	return f
}

// Every frame the writers produce parses back to what went in.
func TestFrames_RoundTrip(t *testing.T) {
	// ACK: ranges from the highest down.
	ranges := [][2]uint64{{1000, 1010}, {900, 950}, {898, 898}, {0, 3}}
	f := mustParse(t, AppendAck(nil, 25, ranges))
	if f.Type != FrameAck || f.Largest != 1010 || f.Delay != 25 || f.FirstRange != 10 {
		t.Fatalf("ACK: %+v", f)
	}
	var got [][2]uint64
	f.AckRanges(func(s, l uint64) bool { got = append(got, [2]uint64{s, l}); return true })
	if len(got) != len(ranges) {
		t.Fatalf("ACK ranges %v, want %v", got, ranges)
	}
	for i := range ranges {
		if got[i] != ranges[i] {
			t.Fatalf("ACK ranges %v, want %v", got, ranges)
		}
	}
	n := 0
	f.AckRanges(func(_, _ uint64) bool { n++; return n < 2 })
	if n != 2 {
		t.Errorf("AckRanges went on after its callback said stop: %d ranges", n)
	}
	// ACK with ECN counts.
	ecn := append(AppendAck(nil, 0, [][2]uint64{{5, 9}}), 1, 2, 3)
	ecn[0] = FrameAck + 1
	if f := mustParse(t, ecn); f.ECN != [3]uint64{1, 2, 3} || f.Largest != 9 || f.FirstRange != 4 {
		t.Errorf("ACK with ECN: %+v", f)
	}

	if f := mustParse(t, AppendCrypto(nil, 1200, []byte("hello"))); f.Type != FrameCrypto || f.Offset != 1200 || string(f.Data) != "hello" {
		t.Errorf("CRYPTO: %+v", f)
	}
	for _, tc := range []struct {
		id, off uint64
		data    string
		fin     bool
	}{{0, 0, "abc", false}, {4, 70000, "", true}, {1 << 40, 1 << 50, "xyz", true}, {8, 0, "", false}} {
		b := AppendStreamHeader(nil, tc.id, tc.off, len(tc.data), tc.fin)
		if len(b) != StreamHeaderLen(tc.id, tc.off, len(tc.data)) {
			t.Errorf("STREAM header for %+v: %d bytes, StreamHeaderLen says %d", tc, len(b), StreamHeaderLen(tc.id, tc.off, len(tc.data)))
		}
		f := mustParse(t, append(b, tc.data...))
		if f.StreamID != tc.id || f.Offset != tc.off || string(f.Data) != tc.data || f.Fin != tc.fin {
			t.Errorf("STREAM %+v: %+v", tc, f)
		}
	}
	// A STREAM frame without a length runs to the end of the packet.
	if f := mustParse(t, []byte{FrameStream | 0x01, 4, 'a', 'b'}); f.StreamID != 4 || string(f.Data) != "ab" || !f.Fin || f.Offset != 0 {
		t.Errorf("STREAM without a length: %+v", f)
	}
	if f := mustParse(t, AppendFrame1(nil, FrameMaxData, 1<<40)); f.Max != 1<<40 {
		t.Errorf("MAX_DATA: %+v", f)
	}
	if f := mustParse(t, AppendFrame1(nil, FrameMaxStreams+1, 100)); f.Type != FrameMaxStreams+1 || f.Max != 100 {
		t.Errorf("MAX_STREAMS: %+v", f)
	}
	if f := mustParse(t, AppendFrame1(nil, FrameRetireConnectionID, 7)); f.Seq != 7 {
		t.Errorf("RETIRE_CONNECTION_ID: %+v", f)
	}
	if f := mustParse(t, AppendFrame2(nil, FrameMaxStreamData, 12, 65536)); f.StreamID != 12 || f.Max != 65536 {
		t.Errorf("MAX_STREAM_DATA: %+v", f)
	}
	if f := mustParse(t, AppendFrame2(nil, FrameStopSending, 12, 0x10c)); f.StreamID != 12 || f.ErrorCode != 0x10c {
		t.Errorf("STOP_SENDING: %+v", f)
	}
	if f := mustParse(t, AppendResetStream(nil, 8, 0x10c, 4096)); f.StreamID != 8 || f.ErrorCode != 0x10c || f.FinalSize != 4096 {
		t.Errorf("RESET_STREAM: %+v", f)
	}
	cid, token := []byte{1, 2, 3, 4, 5, 6, 7, 8}, bytes.Repeat([]byte{0xee}, 16)
	if f := mustParse(t, AppendNewConnectionID(nil, 3, 1, cid, token)); f.Seq != 3 || f.RetirePriorTo != 1 || !bytes.Equal(f.CID, cid) || !bytes.Equal(f.ResetToken, token) {
		t.Errorf("NEW_CONNECTION_ID: %+v", f)
	}
	pd := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if f := mustParse(t, AppendPath(nil, FramePathResponse, pd)); f.Type != FramePathResponse || f.PathData != pd {
		t.Errorf("PATH_RESPONSE: %+v", f)
	}
	if f := mustParse(t, AppendNewToken(nil, []byte("tok"))); string(f.Data) != "tok" {
		t.Errorf("NEW_TOKEN: %+v", f)
	}
	if f := mustParse(t, AppendConnectionClose(nil, false, uint64(ProtocolViolation), FrameStream, "why")); f.Type != FrameConnectionClose || f.ErrorCode != 0x0a || f.FrameType != FrameStream || string(f.Reason) != "why" {
		t.Errorf("CONNECTION_CLOSE: %+v", f)
	}
	if f := mustParse(t, AppendConnectionClose(nil, true, 0x100, 0, "")); f.Type != FrameConnectionClose+1 || f.ErrorCode != 0x100 || len(f.Reason) != 0 {
		t.Errorf("CONNECTION_CLOSE of the application: %+v", f)
	}
	// A run of PADDING is one frame; PING and HANDSHAKE_DONE are one byte.
	var pf Frame
	if n, err := ParseFrame([]byte{0, 0, 0, 0, FramePing}, &pf); err != nil || n != 4 || pf.Type != FramePadding {
		t.Errorf("PADDING run: n=%d, %v", n, err)
	}
	if f := mustParse(t, []byte{FrameHandshakeDone}); f.Type != FrameHandshakeDone {
		t.Errorf("HANDSHAKE_DONE: %+v", f)
	}
}

func TestFrames_Malformed(t *testing.T) {
	big := appendVarint(nil, 1<<61)
	for name, tc := range map[string]struct {
		p    []byte
		want error
	}{
		"empty":                                  {nil, FrameEncodingError},
		"an undefined type":                      {[]byte{0x1f}, FrameEncodingError},
		"an undefined two-byte type":             {[]byte{0x40, 0xaf}, FrameEncodingError},
		"PING written in two bytes":              {[]byte{0x40, 0x01}, ProtocolViolation},
		"ACK cut short":                          {[]byte{FrameAck, 10, 0}, FrameEncodingError},
		"ACK first range below 0":                {[]byte{FrameAck, 5, 0, 0, 6}, FrameEncodingError},
		"ACK gap below 0":                        {[]byte{FrameAck, 10, 0, 1, 2, 7, 0}, FrameEncodingError},
		"ACK range below 0":                      {[]byte{FrameAck, 10, 0, 1, 2, 2, 5}, FrameEncodingError},
		"ACK with more ranges than bytes":        {[]byte{FrameAck, 10, 0, 0x7f, 0xff, 0}, FrameEncodingError},
		"ACK with ECN cut short":                 {[]byte{FrameAck + 1, 10, 0, 0, 0, 1, 2}, FrameEncodingError},
		"CRYPTO longer than the packet":          {[]byte{FrameCrypto, 0, 5, 'a'}, FrameEncodingError},
		"CRYPTO past the largest offset":         {append(append([]byte{FrameCrypto}, appendVarint(nil, maxVarint)...), 1, 'a'), FrameEncodingError},
		"STREAM longer than the packet":          {[]byte{FrameStream | 0x02, 0, 9, 'a'}, FrameEncodingError},
		"STREAM past the largest offset":         {append(append([]byte{FrameStream | 0x04}, 0), append(appendVarint(nil, maxVarint), 'a')...), FrameEncodingError},
		"STREAM without its stream":              {[]byte{FrameStream}, FrameEncodingError},
		"NEW_TOKEN without a token":              {[]byte{FrameNewToken, 0}, FrameEncodingError},
		"MAX_STREAMS above 2^60":                 {append([]byte{FrameMaxStreams}, big...), FrameEncodingError},
		"STREAMS_BLOCKED above 2^60":             {append([]byte{FrameStreamsBlocked + 1}, big...), FrameEncodingError},
		"NEW_CONNECTION_ID of length 0":          {append([]byte{FrameNewConnectionID, 1, 0, 0}, make([]byte, 16)...), FrameEncodingError},
		"NEW_CONNECTION_ID of length 21":         {append([]byte{FrameNewConnectionID, 1, 0, 21}, make([]byte, 37)...), FrameEncodingError},
		"NEW_CONNECTION_ID retiring past itself": {append([]byte{FrameNewConnectionID, 1, 2, 4, 1, 2, 3, 4}, make([]byte, 16)...), FrameEncodingError},
		"NEW_CONNECTION_ID without its token":    {[]byte{FrameNewConnectionID, 1, 0, 4, 1, 2, 3, 4, 9, 9}, FrameEncodingError},
		"PATH_CHALLENGE cut short":               {[]byte{FramePathChallenge, 1, 2, 3}, FrameEncodingError},
		"CONNECTION_CLOSE reason cut short":      {[]byte{FrameConnectionClose, 1, 0, 5, 'a'}, FrameEncodingError},
		"RESET_STREAM cut short":                 {[]byte{FrameResetStream, 4, 1}, FrameEncodingError},
	} {
		var f Frame
		if _, err := ParseFrame(tc.p, &f); err != tc.want {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if FrameEncodingError.Error() != "quic: FRAME_ENCODING_ERROR" || (CryptoError+40).Error() != "quic: CRYPTO_ERROR (TLS alert 40)" || TransportError(0x999).Error() != "quic: error 0x999" {
		t.Errorf("error texts: %q %q %q", FrameEncodingError.Error(), (CryptoError + 40).Error(), TransportError(0x999).Error())
	}
}

func TestFrames_Rules(t *testing.T) {
	early := map[uint64]bool{FramePadding: true, FramePing: true, FrameAck: true, FrameAck + 1: true, FrameCrypto: true, FrameConnectionClose: true}
	for typ := uint64(0); typ <= FrameHandshakeDone; typ++ {
		f := Frame{Type: typ}
		fromClient := typ != FrameNewToken && typ != FrameHandshakeDone
		for _, l := range []Level{LevelInitial, LevelHandshake} {
			if got := f.AllowedAt(l); got != (early[typ] && fromClient) {
				t.Errorf("frame %#x at level %d: allowed=%v", typ, l, got)
			}
		}
		if got := f.AllowedAt(LevelApplication); got != fromClient {
			t.Errorf("frame %#x in a 1-RTT packet: allowed=%v", typ, got)
		}
		quiet := typ == FramePadding || typ == FrameAck || typ == FrameAck+1 || typ == FrameConnectionClose || typ == FrameConnectionClose+1
		if f.AckEliciting() == quiet {
			t.Errorf("frame %#x: ack-eliciting=%v", typ, f.AckEliciting())
		}
	}
}

// Parsing a packet's frames allocates nothing.
func TestFrames_ParseAllocations(t *testing.T) {
	var p []byte
	p = AppendAck(p, 3, [][2]uint64{{90, 100}, {50, 60}, {1, 9}})
	p = AppendStreamHeader(p, 4, 1000, 5, false)
	p = append(p, "hello"...)
	p = AppendFrame2(p, FrameMaxStreamData, 4, 1<<20)
	p = append(p, FramePing, 0, 0, 0)
	var f Frame
	sum := uint64(0)
	if a := testing.AllocsPerRun(200, func() {
		for b := p; len(b) > 0; {
			n, err := ParseFrame(b, &f)
			if err != nil {
				t.Fatal(err)
			}
			if f.Type == FrameAck {
				f.AckRanges(func(s, l uint64) bool { sum += l - s; return true })
			}
			b = b[n:]
		}
	}); a != 0 {
		t.Errorf("%v allocations per packet", a)
	}
}

// FuzzParseFrame: whatever the bytes, the parser does not panic, takes no
// more than it was given, and an ACK frame it accepts has ranges that go
// down without touching.
func FuzzParseFrame(f *testing.F) {
	f.Add(AppendAck(nil, 3, [][2]uint64{{90, 100}, {50, 60}, {1, 9}}))
	f.Add(append(AppendStreamHeader(nil, 4, 1000, 5, true), "hello"...))
	f.Add(AppendNewConnectionID(nil, 3, 1, []byte{1, 2, 3, 4}, make([]byte, 16)))
	f.Add(AppendConnectionClose(nil, false, 10, 8, "reason"))
	f.Add([]byte{FrameAck + 1, 10, 0, 1, 2, 2, 1, 1, 2, 3})
	f.Fuzz(func(t *testing.T, p []byte) {
		var fr Frame
		for len(p) > 0 {
			n, err := ParseFrame(p, &fr)
			if err != nil {
				return
			}
			if n <= 0 || n > len(p) {
				t.Fatalf("a frame of %d bytes out of %d", n, len(p))
			}
			if fr.Type == FrameAck || fr.Type == FrameAck+1 {
				prev := uint64(0)
				first := true
				fr.AckRanges(func(s, l uint64) bool {
					if s > l || !first && l+2 > prev {
						t.Fatalf("ACK ranges out of order: [%d, %d] after one starting at %d", s, l, prev)
					}
					prev, first = s, false
					return true
				})
			}
			p = p[n:]
		}
	})
}
