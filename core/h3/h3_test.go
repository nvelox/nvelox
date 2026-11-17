package h3

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/quic-go/qpack"
)

func TestVarint(t *testing.T) {
	// RFC 9000, appendix A.1.
	for _, tc := range []struct {
		in []byte
		v  uint64
	}{
		{[]byte{0x25}, 37},
		{[]byte{0x40, 0x25}, 37},
		{[]byte{0x7b, 0xbd}, 15293},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333},
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652},
	} {
		v, n := Varint(append(tc.in, 0xaa))
		if v != tc.v || n != len(tc.in) {
			t.Errorf("Varint(%x) = %d, %d; want %d, %d", tc.in, v, n, tc.v, len(tc.in))
		}
		for cut := 0; cut < len(tc.in); cut++ {
			if _, n := Varint(tc.in[:cut]); n != 0 {
				t.Errorf("Varint(%x) of a %d-byte encoding: n=%d, want 0", tc.in[:cut], len(tc.in), n)
			}
		}
	}
	for _, v := range []uint64{0, 1, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, MaxVarint} {
		b := AppendVarint(nil, v)
		got, n := Varint(b)
		if got != v || n != len(b) || n != VarintLen(v) {
			t.Errorf("round trip of %d: %x -> %d, n=%d, VarintLen=%d", v, b, got, n, VarintLen(v))
		}
	}
}

func TestFrameRules(t *testing.T) {
	typ, length, n := FrameHeader(AppendFrameHeader(nil, FrameHeaders, 70000))
	if typ != FrameHeaders || length != 70000 || n != 5 {
		t.Errorf("frame header: %d %d %d", typ, length, n)
	}
	if _, _, n := FrameHeader([]byte{0x01}); n != 0 {
		t.Errorf("a frame header without its length: n=%d", n)
	}
	for _, tc := range []struct {
		typ   uint64
		known bool
		err   error
	}{
		{FrameData, true, nil}, {FrameHeaders, true, nil},
		{FrameSettings, false, ErrFrameUnexpected}, {FrameGoAway, false, ErrFrameUnexpected},
		{FrameCancelPush, false, ErrFrameUnexpected}, {FrameMaxPushID, false, ErrFrameUnexpected},
		{FramePushPromise, false, ErrFrameUnexpected},
		{0x2, false, ErrFrameUnexpected}, {0x6, false, ErrFrameUnexpected}, {0x8, false, ErrFrameUnexpected}, {0x9, false, ErrFrameUnexpected},
		{0x21, false, nil}, {0xf0700, false, nil}, {0x1f*7 + 0x21, false, nil},
	} {
		if known, err := RequestFrame(tc.typ); known != tc.known || err != tc.err {
			t.Errorf("request stream, frame %#x: %v, %v; want %v, %v", tc.typ, known, err, tc.known, tc.err)
		}
	}
	for _, tc := range []struct {
		typ   uint64
		first bool
		known bool
		err   error
	}{
		{FrameSettings, true, true, nil}, {FrameSettings, false, false, ErrFrameUnexpected},
		{FrameGoAway, true, false, ErrMissingSettings}, {0x21, true, false, ErrMissingSettings},
		{FrameGoAway, false, true, nil}, {FrameMaxPushID, false, true, nil}, {FrameCancelPush, false, true, nil},
		{FrameData, false, false, ErrFrameUnexpected}, {FrameHeaders, false, false, ErrFrameUnexpected},
		{FramePushPromise, false, false, ErrFrameUnexpected}, {0x6, false, false, ErrFrameUnexpected},
		{0xf0700, false, false, nil}, {0x21, false, false, nil},
	} {
		if known, err := ControlFrame(tc.typ, tc.first); known != tc.known || err != tc.err {
			t.Errorf("control stream, frame %#x (first=%v): %v, %v; want %v, %v", tc.typ, tc.first, known, err, tc.known, tc.err)
		}
	}
	if ErrFrameUnexpected.Error() != "h3: H3_FRAME_UNEXPECTED" || Error(0x999).Error() != "h3: error 0x999" {
		t.Errorf("error texts: %q, %q", ErrFrameUnexpected.Error(), Error(0x999).Error())
	}
}

func TestSettings(t *testing.T) {
	var p []byte
	p = AppendSetting(p, SettingMaxFieldSectionSize, 65536)
	p = AppendSetting(p, SettingQPACKMaxTableCapacity, 0)
	p = AppendSetting(p, 0x1f*3+0x21, 7) // a reserved identifier: passed on like any unknown one
	got := map[uint64]uint64{}
	if err := Settings(p, func(id, v uint64) { got[id] = v }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[SettingMaxFieldSectionSize] != 65536 || got[SettingQPACKMaxTableCapacity] != 0 {
		t.Errorf("settings %v", got)
	}
	none := func(uint64, uint64) {}
	for name, tc := range map[string]struct {
		p    []byte
		want error
	}{
		"twice":              {AppendSetting(AppendSetting(nil, 6, 1), 6, 2), ErrSettings},
		"HTTP/2's 0x2":       {AppendSetting(nil, 0x2, 0), ErrSettings},
		"HTTP/2's 0x4":       {AppendSetting(nil, 0x4, 65535), ErrSettings},
		"HTTP/2's 0x5":       {AppendSetting(nil, 0x5, 16384), ErrSettings},
		"0x0":                {AppendSetting(nil, 0x0, 1), ErrSettings},
		"ends in a value":    {p[:len(p)-1], ErrFrame},
		"ends in an id":      {[]byte{0x40}, ErrFrame},
		"an id and no value": {[]byte{0x06}, ErrFrame},
	} {
		if err := Settings(tc.p, none); err != tc.want {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	var many []byte
	for i := 0; i < maxSettings+1; i++ {
		many = AppendSetting(many, uint64(0x100+i), 1)
	}
	if err := Settings(many, none); err != ErrSettings {
		t.Errorf("%d settings: %v, want %v", maxSettings+1, err, ErrSettings)
	}
	if err := Settings(nil, none); err != nil {
		t.Errorf("an empty SETTINGS frame: %v", err)
	}
}

type field struct{ name, value string }

// decodeAll decodes p with this package.
func decodeAll(p []byte, maxString int) ([]field, error) {
	var out []field
	var scratch []byte
	err := DecodeFields(p, &scratch, maxString, func(name, value []byte) error {
		out = append(out, field{string(name), string(value)})
		return nil
	})
	return out, err
}

// referenceDecode decodes p with quic-go's qpack package, which the
// deployed HTTP/3 server uses.
func referenceDecode(p []byte) ([]field, error) {
	var out []field
	next := qpack.NewDecoder().Decode(p)
	for {
		hf, err := next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, field{hf.Name, hf.Value})
	}
}

func referenceEncode(fields []field) []byte {
	var b bytes.Buffer
	e := qpack.NewEncoder(&b)
	for _, f := range fields {
		e.WriteField(qpack.HeaderField{Name: f.name, Value: f.value})
	}
	if len(fields) == 0 {
		return []byte{0, 0}
	}
	return b.Bytes()
}

func encodeAll(fields []field) []byte {
	b := AppendPrefix(nil)
	for _, f := range fields {
		b = AppendField(b, []byte(f.name), []byte(f.value))
	}
	return b
}

func sameFields(a, b []field) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Both directions against the reference: what it encodes this package
// decodes to the same fields, and what this package encodes it decodes to
// the same fields. Every static table entry, by itself and by name only,
// and requests and responses with literals of every kind.
func TestQPACK_AgainstReference(t *testing.T) {
	var sets [][]field
	for _, e := range staticTable {
		sets = append(sets, []field{{e.name, e.value}}, []field{{e.name, "another value, not in the table"}}, []field{{e.name, ""}})
	}
	sets = append(sets,
		nil,
		[]field{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "/index.html?q=1"}, {"user-agent", "curl/8.5.0"}, {"accept", "*/*"}},
		[]field{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.com:8443"}, {":path", "/upload"}, {"content-length", "12345"}, {"content-type", "application/octet-stream"}, {"x-custom-header", "some value"}, {"cookie", "a=b; c=d"}},
		[]field{{":status", "200"}, {"content-type", "text/html; charset=utf-8"}, {"server", "nvelox"}, {"date", "Sat, 14 Nov 2026 22:00:00 GMT"}, {"x-request-id", "0123456789abcdef"}},
		[]field{{":status", "418"}, {"x", ""}, {"", "empty name"}, {"binary", "\x00\x01\xff\xfe"}},
		[]field{{"long", string(bytes.Repeat([]byte("abcdefgh"), 4096))}, {string(bytes.Repeat([]byte("n"), 300)), "long name"}},
	)
	for i, fs := range sets {
		got, err := decodeAll(referenceEncode(fs), 1<<20)
		if err != nil || !sameFields(got, fs) {
			t.Errorf("set %d: decoding the reference's encoding: %v, %v; want %v", i, got, err, fs)
		}
		ref, err := referenceDecode(encodeAll(fs))
		if err != nil || !sameFields(ref, fs) {
			t.Errorf("set %d: the reference decoding ours: %v, %v; want %v", i, ref, err, fs)
		}
	}
	// :status takes the table's entry where there is one (one byte for an
	// index below 63, two above), else a reference to the name.
	for code, want := range map[int]int{200: 1, 404: 1, 503: 1, 204: 2, 500: 2, 418: 6, 599: 6} {
		b := AppendStatus(nil, code)
		if len(b) != want {
			t.Errorf(":status %d: %d bytes (%x), want %d", code, len(b), b, want)
		}
	}
}

func TestQPACK_Invalid(t *testing.T) {
	for name, tc := range map[string]struct {
		p    []byte
		want error
	}{
		"empty":                            {nil, ErrFieldSection},
		"the count only":                   {[]byte{0}, ErrFieldSection},
		"a required insert count":          {[]byte{1, 0}, ErrFieldSection},
		"indexed, dynamic":                 {[]byte{0, 0, 0x80}, ErrFieldSection},
		"indexed, past the table":          {[]byte{0, 0, 0xff, 0x24}, ErrFieldSection},
		"indexed, cut short":               {[]byte{0, 0, 0xff}, ErrFieldSection},
		"name reference, dynamic":          {[]byte{0, 0, 0x40, 0x00}, ErrFieldSection},
		"name reference, no value":         {[]byte{0, 0, 0x51}, ErrFieldSection},
		"name reference, value cut short":  {[]byte{0, 0, 0x51, 0x05, 'a', 'b'}, ErrFieldSection},
		"literal name cut short":           {[]byte{0, 0, 0x23, 'a', 'b'}, ErrFieldSection},
		"literal name without a value":     {[]byte{0, 0, 0x21, 'a'}, ErrFieldSection},
		"post-base index":                  {[]byte{0, 0, 0x10}, ErrFieldSection},
		"post-base name reference":         {[]byte{0, 0, 0x00, 0x00}, ErrFieldSection},
		"Huffman value with a bad padding": {[]byte{0, 0, 0x51, 0x81, 0x00}, ErrFieldSection},
		"a length that does not fit":       {[]byte{0, 0, 0x51, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, ErrFieldSection},
		"a value over the limit":           {append([]byte{0, 0, 0x51, 0x11}, bytes.Repeat([]byte("v"), 17)...), ErrStringLength},
		"a Huffman value over the limit":   {append([]byte{0, 0, 0x51}, appendString(nil, 0, 7, bytes.Repeat([]byte("e"), 40))...), ErrStringLength},
		"a literal name over the limit":    {append(append([]byte{0, 0}, appendString(nil, 0x20, 3, bytes.Repeat([]byte("q"), 17))...), 0x00), ErrStringLength},
	} {
		if _, err := decodeAll(tc.p, 16); err != tc.want {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// Any Base is taken when the count is 0: it matters to dynamic
	// references only. The reference refuses a delta other than 0: the one
	// input where this decoder takes more.
	for _, base := range []byte{0x05, 0x80, 0x85} {
		if got, err := decodeAll([]byte{0, base, 0xc0 | 17}, 16); err != nil || !sameFields(got, []field{{":method", "GET"}}) {
			t.Errorf("base byte %#x: %v, %v", base, got, err)
		}
	}
	// What emit returns ends the decoding and is returned.
	stop := errors.New("stop")
	n := 0
	var scratch []byte
	err := DecodeFields(encodeAll([]field{{"a", "1"}, {"b", "2"}, {"c", "3"}}), &scratch, 16, func(_, _ []byte) error {
		n++
		if n == 2 {
			return stop
		}
		return nil
	})
	if err != stop || n != 2 {
		t.Errorf("emit's error: %v after %d fields", err, n)
	}
}

// Decoding allocates nothing once the scratch buffer has grown.
func TestQPACK_DecodeAllocations(t *testing.T) {
	p := encodeAll([]field{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "/a/long/path/with/some/segments?and=a&query=string"}, {"user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}, {"accept-encoding", "gzip, deflate, br"}, {"x-custom", "custom value"}})
	scratch := make([]byte, 0, 4096)
	n := 0
	emit := func(name, value []byte) error { n += len(name) + len(value); return nil }
	if a := testing.AllocsPerRun(200, func() {
		if err := DecodeFields(p, &scratch, 1<<16, emit); err != nil {
			t.Fatal(err)
		}
	}); a != 0 {
		t.Errorf("%v allocations per field section", a)
	}
	dst := make([]byte, 0, 4096)
	name, value := []byte("content-type"), []byte("text/html; charset=utf-8")
	other, ov := []byte("x-request-id"), []byte("0123456789abcdef")
	if a := testing.AllocsPerRun(200, func() {
		b := AppendPrefix(dst[:0])
		b = AppendStatus(b, 200)
		b = AppendField(b, name, value)
		b = AppendField(b, other, ov)
		_ = b
	}); a != 0 {
		t.Errorf("%v allocations per encoded section", a)
	}
}

// FuzzDecodeFields: the decoder never panics, and agrees with the
// reference: the same fields, or both refuse. The one known difference (a
// Base delta other than 0 with no dynamic references, which RFC 9204 allows
// and the reference refuses) is left out.
func FuzzDecodeFields(f *testing.F) {
	f.Add(encodeAll([]field{{":method", "GET"}, {":path", "/"}, {"x-a", "b"}}))
	f.Add(referenceEncode([]field{{":status", "200"}, {"content-type", "text/plain"}, {"set-cookie", "a=b"}}))
	f.Add([]byte{0, 0, 0x51, 0x81, 0x00})
	f.Add([]byte{0, 0, 0x23, 'a', 'b', 'c', 0x83, 0x1c, 0x64, 0x3f})
	f.Add([]byte{0, 0, 0xff, 0x24})
	f.Fuzz(func(t *testing.T, p []byte) {
		got, err := decodeAll(p, 1<<30)
		if len(p) >= 2 && p[0] == 0 && p[1]&0x7f != 0 {
			return
		}
		ref, rerr := referenceDecode(p)
		if (err != nil) != (rerr != nil) {
			t.Fatalf("%x: ours %v (%v), reference %v (%v)", p, err, got, rerr, ref)
		}
		if err == nil && !sameFields(got, ref) {
			t.Fatalf("%x: ours %v, reference %v", p, got, ref)
		}
	})
}

// FuzzEncodeFields: what the encoder writes, the reference and this
// package decode to the fields that went in.
func FuzzEncodeFields(f *testing.F) {
	f.Add("content-type", "text/html", "x-custom", "v")
	f.Add(":status", "200", "", "")
	f.Add("accept-encoding", "gzip, deflate, br", "vary", "accept-encoding")
	f.Fuzz(func(t *testing.T, n1, v1, n2, v2 string) {
		fs := []field{{n1, v1}, {n2, v2}}
		p := encodeAll(fs)
		got, err := decodeAll(p, 1<<30)
		if err != nil || !sameFields(got, fs) {
			t.Fatalf("%q: ours decodes %x to %q, %v", fs, p, got, err)
		}
		ref, err := referenceDecode(p)
		if err != nil || !sameFields(ref, fs) {
			t.Fatalf("%q: the reference decodes %x to %q, %v", fs, p, ref, err)
		}
	})
}
