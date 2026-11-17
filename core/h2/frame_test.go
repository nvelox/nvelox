package h2

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2"
)

// The frames this package writes are read back by golang.org/x/net/http2's
// Framer, and the ones the Framer writes are read here.

func TestFramesReadByReference(t *testing.T) {
	var out []byte
	out = AppendSettings(out, Setting{SettingMaxConcurrentStreams, 250}, Setting{SettingInitialWindowSize, 1 << 20}, Setting{SettingMaxHeaderListSize, 1<<20 + 320})
	out = AppendSettingsAck(out)
	out = AppendPing(out, false, []byte("12345678"))
	out = AppendPing(out, true, []byte("abcdefgh"))
	out = AppendWindowUpdate(out, 0, 983041)
	out = AppendWindowUpdate(out, 7, 1)
	out = AppendRSTStream(out, 5, ErrCancel)
	out = AppendDataHeader(out, 3, 5, true)
	out = append(out, "hello"...)
	out = AppendGoAway(out, 2147483647, ErrEnhanceYourCalm, []byte("too many resets"))

	fr := http2.NewFramer(nil, bytes.NewReader(out))
	next := func() http2.Frame {
		t.Helper()
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	sf := next().(*http2.SettingsFrame)
	if sf.IsAck() || sf.NumSettings() != 3 {
		t.Fatalf("settings: %v", sf)
	}
	for i, want := range []http2.Setting{{ID: http2.SettingMaxConcurrentStreams, Val: 250}, {ID: http2.SettingInitialWindowSize, Val: 1 << 20}, {ID: http2.SettingMaxHeaderListSize, Val: 1<<20 + 320}} {
		if got := sf.Setting(i); got != want {
			t.Fatalf("setting %d: %v, want %v", i, got, want)
		}
	}
	if sf := next().(*http2.SettingsFrame); !sf.IsAck() || sf.NumSettings() != 0 {
		t.Fatalf("settings ack: %v", sf)
	}
	if pf := next().(*http2.PingFrame); pf.IsAck() || string(pf.Data[:]) != "12345678" {
		t.Fatalf("ping: %v", pf)
	}
	if pf := next().(*http2.PingFrame); !pf.IsAck() || string(pf.Data[:]) != "abcdefgh" {
		t.Fatalf("ping ack: %v", pf)
	}
	if wf := next().(*http2.WindowUpdateFrame); wf.StreamID != 0 || wf.Increment != 983041 {
		t.Fatalf("window update: %v", wf)
	}
	if wf := next().(*http2.WindowUpdateFrame); wf.StreamID != 7 || wf.Increment != 1 {
		t.Fatalf("window update: %v", wf)
	}
	if rf := next().(*http2.RSTStreamFrame); rf.StreamID != 5 || rf.ErrCode != http2.ErrCodeCancel {
		t.Fatalf("rst_stream: %v", rf)
	}
	if df := next().(*http2.DataFrame); df.StreamID != 3 || !df.StreamEnded() || string(df.Data()) != "hello" {
		t.Fatalf("data: %v", df)
	}
	if gf := next().(*http2.GoAwayFrame); gf.LastStreamID != 2147483647 || gf.ErrCode != http2.ErrCodeEnhanceYourCalm || string(gf.DebugData()) != "too many resets" {
		t.Fatalf("goaway: %v", gf)
	}
}

// A header block larger than a frame goes out as HEADERS and
// CONTINUATION frames that the reference puts together again.
func TestAppendHeadersSplits(t *testing.T) {
	for _, tc := range []struct {
		size, maxFrame, frames int
		endStream              bool
	}{
		{0, 16384, 1, true}, {100, 16384, 1, false}, {16384, 16384, 1, true}, {16385, 16384, 2, false}, {40000, 16384, 3, true}, {50, 20, 3, false},
	} {
		block := bytes.Repeat([]byte{0x82}, tc.size) // ":method: GET", again and again
		out := AppendHeaders(nil, 9, block, tc.endStream, tc.maxFrame)
		fr := http2.NewFramer(nil, bytes.NewReader(out))
		fr.SetMaxReadFrameSize(1 << 20)
		var got []byte
		for i := 0; i < tc.frames; i++ {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatalf("size %d, frame %d: %v", tc.size, i, err)
			}
			last := i == tc.frames-1
			switch f := f.(type) {
			case *http2.HeadersFrame:
				if i != 0 || f.StreamID != 9 || f.StreamEnded() != tc.endStream || f.HeadersEnded() != last {
					t.Fatalf("size %d, frame %d: %v", tc.size, i, f)
				}
				got = append(got, f.HeaderBlockFragment()...)
			case *http2.ContinuationFrame:
				if i == 0 || f.StreamID != 9 || f.HeadersEnded() != last {
					t.Fatalf("size %d, frame %d: %v", tc.size, i, f)
				}
				got = append(got, f.HeaderBlockFragment()...)
			default:
				t.Fatalf("size %d, frame %d is a %T", tc.size, i, f)
			}
		}
		if _, err := fr.ReadFrame(); err == nil {
			t.Fatalf("size %d: more than %d frames", tc.size, tc.frames)
		}
		if !bytes.Equal(got, block) {
			t.Fatalf("size %d: the fragments do not add up to the block", tc.size)
		}
	}
}

// What the reference writes is read here.
func TestReferenceFramesRead(t *testing.T) {
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)
	fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535}, http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384})
	fr.WriteWindowUpdate(3, 4096)
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 5, BlockFragment: []byte{0x82, 0x84}, EndStream: true, EndHeaders: true,
		Priority: http2.PriorityParam{StreamDep: 3, Weight: 15}, PadLength: 4})
	fr.WriteData(5, false, []byte("body"))
	fr.WriteRSTStream(5, http2.ErrCodeCancel)
	b := buf.Bytes()
	read := func() (FrameHeader, []byte) {
		t.Helper()
		if len(b) < FrameHeaderLen {
			t.Fatal("no frame left")
		}
		h := ReadFrameHeader(b)
		p := b[FrameHeaderLen : FrameHeaderLen+int(h.Length)]
		b = b[FrameHeaderLen+int(h.Length):]
		if code, _ := h.Check(DefaultMaxFrameSize); code != ErrNo {
			t.Fatalf("%+v: error %#x", h, code)
		}
		return h, p
	}
	h, p := read()
	if h.Type != FrameSettings || h.StreamID != 0 || h.Flags != 0 || len(p) != 12 ||
		ReadSetting(p) != (Setting{SettingInitialWindowSize, 65535}) || ReadSetting(p[6:]) != (Setting{SettingMaxFrameSize, 16384}) {
		t.Fatalf("settings: %+v %x", h, p)
	}
	if h, p = read(); h.Type != FrameWindowUpdate || h.StreamID != 3 || len(p) != 4 || p[3] != 0 || p[2] != 0x10 {
		t.Fatalf("window update: %+v %x", h, p)
	}
	if h, p = read(); h.Type != FrameHeaders || h.StreamID != 5 || h.Flags != FlagEndStream|FlagEndHeaders|FlagPadded|FlagPriority || len(p) != 1+5+2+4 {
		t.Fatalf("headers: %+v %x", h, p)
	}
	if h, p = read(); h.Type != FrameData || h.StreamID != 5 || h.Flags != 0 || string(p) != "body" {
		t.Fatalf("data: %+v %x", h, p)
	}
	if h, p = read(); h.Type != FrameRSTStream || h.StreamID != 5 || len(p) != 4 || p[3] != byte(ErrCancel) {
		t.Fatalf("rst_stream: %+v %x", h, p)
	}
}

// The rules a frame header can break on its own (RFC 9113, section 6).
func TestFrameHeaderCheck(t *testing.T) {
	const max = DefaultMaxFrameSize
	for name, tc := range map[string]struct {
		h    FrameHeader
		code ErrCode
		conn bool
	}{
		"data":                            {FrameHeader{Length: 10, Type: FrameData, StreamID: 1}, ErrNo, false},
		"data on stream 0":                {FrameHeader{Length: 10, Type: FrameData}, ErrProtocol, true},
		"a frame over the announced size": {FrameHeader{Length: max + 1, Type: FrameData, StreamID: 1}, ErrFrameSize, true},
		"a frame of the announced size":   {FrameHeader{Length: max, Type: FrameData, StreamID: 1}, ErrNo, false},
		"headers on stream 0":             {FrameHeader{Type: FrameHeaders}, ErrProtocol, true},
		"continuation on stream 0":        {FrameHeader{Type: FrameContinuation}, ErrProtocol, true},
		"priority":                        {FrameHeader{Length: 5, Type: FramePriority, StreamID: 3}, ErrNo, false},
		"priority of 4 bytes":             {FrameHeader{Length: 4, Type: FramePriority, StreamID: 3}, ErrFrameSize, true},
		"priority on stream 0":            {FrameHeader{Length: 5, Type: FramePriority}, ErrProtocol, true},
		"rst_stream":                      {FrameHeader{Length: 4, Type: FrameRSTStream, StreamID: 3}, ErrNo, false},
		"rst_stream of 5 bytes":           {FrameHeader{Length: 5, Type: FrameRSTStream, StreamID: 3}, ErrFrameSize, true},
		"rst_stream on stream 0":          {FrameHeader{Length: 4, Type: FrameRSTStream}, ErrProtocol, true},
		"settings":                        {FrameHeader{Length: 12, Type: FrameSettings}, ErrNo, false},
		"settings of 7 bytes":             {FrameHeader{Length: 7, Type: FrameSettings}, ErrFrameSize, true},
		"settings ack with a payload":     {FrameHeader{Length: 6, Type: FrameSettings, Flags: FlagAck}, ErrFrameSize, true},
		"settings on a stream":            {FrameHeader{Type: FrameSettings, StreamID: 1}, ErrProtocol, true},
		"push_promise":                    {FrameHeader{Length: 4, Type: FramePushPromise, StreamID: 1}, ErrProtocol, true},
		"ping":                            {FrameHeader{Length: 8, Type: FramePing}, ErrNo, false},
		"ping of 7 bytes":                 {FrameHeader{Length: 7, Type: FramePing}, ErrFrameSize, true},
		"ping on a stream":                {FrameHeader{Length: 8, Type: FramePing, StreamID: 1}, ErrProtocol, true},
		"goaway":                          {FrameHeader{Length: 8, Type: FrameGoAway}, ErrNo, false},
		"goaway of 7 bytes":               {FrameHeader{Length: 7, Type: FrameGoAway}, ErrFrameSize, true},
		"goaway on a stream":              {FrameHeader{Length: 8, Type: FrameGoAway, StreamID: 1}, ErrProtocol, true},
		"window_update":                   {FrameHeader{Length: 4, Type: FrameWindowUpdate, StreamID: 1}, ErrNo, false},
		"window_update of 5 bytes":        {FrameHeader{Length: 5, Type: FrameWindowUpdate}, ErrFrameSize, true},
		"an unknown type":                 {FrameHeader{Length: 100, Type: 0x77, StreamID: 9}, ErrNo, false},
	} {
		if code, conn := tc.h.Check(max); code != tc.code || conn != tc.conn {
			t.Errorf("%s: error %#x (connection=%v), want %#x (%v)", name, code, conn, tc.code, tc.conn)
		}
	}
}

func TestCheckSetting(t *testing.T) {
	for name, tc := range map[string]struct {
		s    Setting
		want ErrCode
	}{
		"push 0":               {Setting{SettingEnablePush, 0}, ErrNo},
		"push 2":               {Setting{SettingEnablePush, 2}, ErrProtocol},
		"window max":           {Setting{SettingInitialWindowSize, MaxWindow}, ErrNo},
		"window over max":      {Setting{SettingInitialWindowSize, MaxWindow + 1}, ErrFlowControl},
		"frame size min":       {Setting{SettingMaxFrameSize, 16384}, ErrNo},
		"frame size under min": {Setting{SettingMaxFrameSize, 16383}, ErrProtocol},
		"frame size max":       {Setting{SettingMaxFrameSize, 1<<24 - 1}, ErrNo},
		"frame size over max":  {Setting{SettingMaxFrameSize, 1 << 24}, ErrProtocol},
		"connect protocol 2":   {Setting{SettingEnableConnectProto, 2}, ErrProtocol},
		"table size":           {Setting{SettingHeaderTableSize, 1 << 30}, ErrNo},
		"an unknown parameter": {Setting{0x99, 12345}, ErrNo},
	} {
		if got := CheckSetting(tc.s); got != tc.want {
			t.Errorf("%s: error %#x, want %#x", name, got, tc.want)
		}
	}
}

func TestAddWindow(t *testing.T) {
	w := int64(DefaultWindow)
	if !AddWindow(&w, 100) || w != DefaultWindow+100 {
		t.Fatalf("window %d", w)
	}
	if AddWindow(&w, 0) {
		t.Fatal("an increment of 0 was taken")
	}
	if AddWindow(&w, MaxWindow) || w != DefaultWindow+100 {
		t.Fatalf("a window past the maximum: %d", w)
	}
	w = -5000 // a window a SETTINGS change made negative
	if !AddWindow(&w, MaxWindow) || w != MaxWindow-5000 {
		t.Fatalf("window %d", w)
	}
}

func FuzzFrameHeader(f *testing.F) {
	f.Add([]byte{0, 0, 8, 6, 1, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 9, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < FrameHeaderLen {
			return
		}
		h := ReadFrameHeader(b)
		out := AppendFrameHeader(nil, int(h.Length), h.Type, h.Flags, h.StreamID)
		want := append([]byte(nil), b[:FrameHeaderLen]...)
		want[5] &= 0x7f // the reserved bit is ignored
		if !bytes.Equal(out, want) {
			t.Fatalf("%x read as %+v and written as %x", b[:FrameHeaderLen], h, out)
		}
		h.Check(DefaultMaxFrameSize)
	})
}
