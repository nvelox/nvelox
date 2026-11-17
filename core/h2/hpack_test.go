package h2

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// The reference for these tests is golang.org/x/net/http2/hpack: the
// tables, the Huffman code, and what a decoder makes of a header block,
// well formed or not.

type field struct {
	name, value string
	sensitive   bool
}

func (f field) String() string {
	return fmt.Sprintf("%q: %q (sensitive=%v)", f.name, f.value, f.sensitive)
}

// decodeOurs feeds block to d in the given fragment sizes and returns the
// fields, and the error of Write or Close.
func decodeOurs(d *Decoder, block []byte, frags []int) ([]field, error) {
	var out []field
	emit := func(name, value []byte, sensitive bool) error {
		out = append(out, field{string(name), string(value), sensitive})
		return nil
	}
	for len(block) > 0 {
		n := len(block)
		if len(frags) > 0 {
			if frags[0] < n {
				n = frags[0]
			}
			frags = frags[1:]
		}
		if n == 0 {
			n = 1
		}
		if err := d.Write(block[:n], emit); err != nil {
			return out, err
		}
		block = block[n:]
	}
	return out, d.Close()
}

func decodeRef(d *hpack.Decoder, block []byte) ([]field, error) {
	var out []field
	d.SetEmitFunc(func(f hpack.HeaderField) { out = append(out, field{f.Name, f.Value, f.Sensitive}) })
	if _, err := d.Write(block); err != nil {
		return out, err
	}
	return out, d.Close()
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

// The static table is RFC 7541's: the reference decodes every index to the
// same entry.
func TestStaticTableAgrees(t *testing.T) {
	ref := hpack.NewDecoder(4096, nil)
	d := NewDecoder(1 << 20)
	for i := 1; i <= 61; i++ {
		block := []byte{0x80 | byte(i)}
		want, err := decodeRef(ref, block)
		if err != nil || len(want) != 1 {
			t.Fatalf("reference, index %d: %v, %v", i, want, err)
		}
		got, err := decodeOurs(d, block, nil)
		if err != nil || !sameFields(got, want) {
			t.Fatalf("index %d: %v, %v; want %v", i, got, err, want)
		}
		if staticTable[i].name != want[0].name || staticTable[i].value != want[0].value {
			t.Fatalf("static table entry %d is %v, want %v", i, staticTable[i], want[0])
		}
	}
	for _, block := range [][]byte{{0x80}, {0x80 | 62}} {
		if _, err := decodeOurs(NewDecoder(1<<20), block, nil); !errors.Is(err, ErrCompression) {
			t.Errorf("block %x: err %v, want ErrCompression", block, err)
		}
	}
}

// The Huffman code is RFC 7541's: every byte value encodes as the
// reference encodes it, and strings round-trip.
func TestHuffmanAgrees(t *testing.T) {
	for b := 0; b < 256; b++ {
		s := []byte{byte(b)}
		want := hpack.AppendHuffmanString(nil, string(s))
		if got := appendHuff(nil, s); !bytes.Equal(got, want) {
			t.Fatalf("byte %#x encodes as %x, want %x", b, got, want)
		}
		if n := huffEncodedLen(s); n != len(want) {
			t.Fatalf("byte %#x: encoded length %d, want %d", b, n, len(want))
		}
	}
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		s := make([]byte, rnd.Intn(64))
		for j := range s {
			if i%2 == 0 {
				s[j] = byte(rnd.Intn(256))
			} else {
				s[j] = "abcdefghijklmnopqrstuvwxyz0123456789-_/.=; "[rnd.Intn(43)]
			}
		}
		enc := appendHuff(nil, s)
		if want := hpack.AppendHuffmanString(nil, string(s)); !bytes.Equal(enc, want) {
			t.Fatalf("%q encodes as %x, want %x", s, enc, want)
		}
		if len(enc) != huffEncodedLen(s) {
			t.Fatalf("%q: length %d, huffEncodedLen %d", s, len(enc), huffEncodedLen(s))
		}
		dec, ok := huffDecode(nil, enc, 1<<20)
		if !ok || !bytes.Equal(dec, s) {
			t.Fatalf("%q decodes back as %q (ok=%v)", s, dec, ok)
		}
	}
}

// Any bytes at all decode as the reference decodes them: the same string,
// or an error in both (the end-of-string symbol, a padding that is too
// long or not all 1 bits).
func TestHuffmanDecodeAgreesOnAnyBytes(t *testing.T) {
	rnd := rand.New(rand.NewSource(2))
	check := func(src []byte) {
		t.Helper()
		want, werr := hpack.HuffmanDecodeToString(src)
		got, ok := huffDecode(nil, src, 1<<20)
		if ok != (werr == nil) || (ok && string(got) != want) {
			t.Fatalf("%x: decoded %q (ok=%v), reference %q (%v)", src, got, ok, want, werr)
		}
	}
	for i := 0; i < 300000; i++ {
		src := make([]byte, rnd.Intn(12))
		rnd.Read(src)
		if i%3 == 0 && len(src) > 0 {
			src[len(src)-1] |= byte(0xff >> uint(rnd.Intn(8))) // a likelier valid padding
		}
		check(src)
	}
	check(nil)
	check([]byte{0xff})                   // 8 bits of padding
	check([]byte{0xff, 0xff, 0xff, 0xff}) // the end-of-string symbol
	check([]byte{0x00})                   // '0' and three 0 bits
	// The output limit: one byte more than fits.
	enc := appendHuff(nil, []byte("abcdef"))
	if _, ok := huffDecode(nil, enc, 5); ok {
		t.Fatal("6 bytes decoded into a limit of 5")
	}
	if got, ok := huffDecode(nil, enc, 6); !ok || string(got) != "abcdef" {
		t.Fatalf("limit 6: %q, %v", got, ok)
	}
}

func randomFields(rnd *rand.Rand) []hpack.HeaderField {
	names := []string{":method", ":path", ":scheme", ":authority", "accept", "accept-encoding", "cookie", "user-agent",
		"x-request-id", "content-type", "content-length", "authorization", "x-" + strings.Repeat("n", rnd.Intn(40)), "te", "referer"}
	values := []string{"GET", "POST", "/", "/index.html", "https", "example.test", "gzip, deflate", "", "a=b; c=d",
		strings.Repeat("v", rnd.Intn(300)), "Mozilla/5.0 (X11; Linux x86_64)", "\x00\xff binary \x80", "trailers", "0", "12345"}
	fs := make([]hpack.HeaderField, rnd.Intn(24))
	for i := range fs {
		fs[i] = hpack.HeaderField{Name: names[rnd.Intn(len(names))], Value: values[rnd.Intn(len(values))], Sensitive: rnd.Intn(9) == 0}
	}
	return fs
}

// Header blocks from the reference encoder (its dynamic table, Huffman
// strings, table size updates) decode to the same fields, block after
// block on one connection and however the blocks are cut into fragments.
func TestDecoderAgreesOnEncodedBlocks(t *testing.T) {
	rnd := rand.New(rand.NewSource(3))
	for conn := 0; conn < 300; conn++ {
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		ref := hpack.NewDecoder(4096, nil)
		d := NewDecoder(1 << 20)
		for block := 0; block < 30; block++ {
			buf.Reset()
			fields := randomFields(rnd)
			// One size change per block that has a field to carry it: two
			// changes in a row make the reference's encoder send two
			// updates, which its own decoder refuses (see agree).
			if len(fields) > 0 && rnd.Intn(8) == 0 {
				enc.SetMaxDynamicTableSize(uint32(rnd.Intn(4097)))
			}
			for _, f := range fields {
				if err := enc.WriteField(f); err != nil {
					t.Fatal(err)
				}
			}
			b := append([]byte(nil), buf.Bytes()...)
			want, werr := decodeRef(ref, b)
			if werr != nil {
				t.Fatalf("reference failed on its own encoder's block: %v", werr)
			}
			frags := make([]int, rnd.Intn(6))
			for i := range frags {
				frags[i] = 1 + rnd.Intn(40)
			}
			got, err := decodeOurs(d, b, frags)
			if err != nil || !sameFields(got, want) {
				t.Fatalf("connection %d, block %d (%x), fragments %v:\n got  %v (%v)\n want %v", conn, block, b, frags, got, err, want)
			}
		}
	}
}

// mutate returns block with a few random changes.
func mutate(rnd *rand.Rand, block []byte) []byte {
	b := append([]byte(nil), block...)
	for n := 1 + rnd.Intn(3); n > 0 && len(b) > 0; n-- {
		switch rnd.Intn(4) {
		case 0:
			b[rnd.Intn(len(b))] = byte(rnd.Intn(256))
		case 1:
			b = b[:rnd.Intn(len(b)+1)]
		case 2:
			i := rnd.Intn(len(b) + 1)
			b = append(b[:i], append([]byte{byte(rnd.Intn(256))}, b[i:]...)...)
		case 3:
			b[rnd.Intn(len(b))] ^= 1 << uint(rnd.Intn(8))
		}
	}
	return b
}

// agree decodes block with both decoders, which must be in the same state,
// and reports a difference: the same fields and both in order, or both
// failing. After a failure neither decoder can be used again.
func agree(d *Decoder, ref *hpack.Decoder, block []byte, frags []int) (failed bool, diff string) {
	want, werr := decodeRef(ref, block)
	got, err := decodeOurs(d, block, frags)
	if err == nil && werr != nil && strings.Contains(werr.Error(), "dynamic table size update MUST occur at the beginning") {
		// The one stated difference: a second table size update at the
		// start of a block (the smallest size, then the final one: RFC
		// 7541, section 4.2) is refused by the reference when the first
		// left entries in the table. It is a valid block.
		return true, ""
	}
	if (err == nil) != (werr == nil) {
		return true, fmt.Sprintf("block %x: err %v, reference %v\n got  %v\n want %v", block, err, werr, got, want)
	}
	if err != nil {
		// Both refuse the block. The fields before the error are the
		// same ones, up to where the shorter list ends: the two may stop
		// emitting at different points of a broken block.
		n := len(got)
		if len(want) < n {
			n = len(want)
		}
		if !sameFields(got[:n], want[:n]) {
			return true, fmt.Sprintf("block %x: fields before the error differ\n got  %v\n want %v", block, got, want)
		}
		return true, ""
	}
	if !sameFields(got, want) {
		return false, fmt.Sprintf("block %x:\n got  %v\n want %v", block, got, want)
	}
	return false, ""
}

// Damaged blocks: both decoders accept or both refuse, and after a block
// both accept, the tables are still the same (the following blocks agree).
func TestDecoderAgreesOnDamagedBlocks(t *testing.T) {
	rnd := rand.New(rand.NewSource(4))
	cases := 0
	for conn := 0; conn < 6000; conn++ {
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		ref := hpack.NewDecoder(4096, nil)
		ref.SetMaxStringLength(1 << 20)
		d := NewDecoder(1 << 20)
		for block := 0; block < 12; block++ {
			buf.Reset()
			for _, f := range randomFields(rnd) {
				enc.WriteField(f)
			}
			b := buf.Bytes()
			if rnd.Intn(3) != 0 {
				b = mutate(rnd, b)
			}
			frags := []int{1 + rnd.Intn(30), 1 + rnd.Intn(30)}
			failed, diff := agree(d, ref, b, frags)
			cases++
			if diff != "" {
				t.Fatalf("connection %d, block %d: %s", conn, block, diff)
			}
			if failed {
				break // the connection would end here
			}
		}
	}
	t.Logf("%d blocks compared", cases)
}

// The limits the decoder sets itself.
func TestDecoderLimits(t *testing.T) {
	emit := func(name, value []byte, sensitive bool) error { return nil }
	// A string longer than MaxString is refused when its length is read,
	// before its bytes arrive.
	d := NewDecoder(100)
	block := appendInt([]byte{0x00}, 0x00, 7, 101) // literal, new name of 101 bytes
	if err := d.Write(block, emit); !errors.Is(err, ErrStringLength) {
		t.Fatalf("a name of 101 bytes with a limit of 100: %v", err)
	}
	// A Huffman string that decodes to more than MaxString.
	d = NewDecoder(100)
	long := appendHuff(nil, bytes.Repeat([]byte("a"), 150)) // 94 bytes encoded
	block = append([]byte{0x00}, appendInt(nil, 0x80, 7, uint64(len(long)))...)
	block = append(block, long...)
	if err := d.Write(block, emit); !errors.Is(err, ErrStringLength) {
		t.Fatalf("150 decoded bytes with a limit of 100: %v", err)
	}
	// A table size update above what the decoder offered, and one after a
	// field.
	if err := NewDecoder(100).Write(appendInt(nil, 0x20, 5, MaxTableSize+1), emit); !errors.Is(err, ErrCompression) {
		t.Fatalf("a table size update above the offer: %v", err)
	}
	d = NewDecoder(100)
	if err := d.Write([]byte{0x40, 0x01, 'a', 0x01, 'b', 0x82, 0x20}, emit); !errors.Is(err, ErrCompression) {
		t.Fatalf("a table size update after a field, with an entry in the table: %v", err)
	}
	// Two updates at the start of a block are in order (the smallest size
	// since the last block, then the final one), also with entries in the
	// table.
	d = NewDecoder(100)
	if err := d.Write([]byte{0x40, 0x01, 'a', 0x01, 'b'}, emit); err != nil || d.Close() != nil {
		t.Fatal(err)
	}
	if err := d.Write(append(appendInt(nil, 0x20, 5, 100), appendInt(nil, 0x20, 5, 4096)...), emit); err != nil || d.Close() != nil {
		t.Fatalf("two table size updates at the start of a block: %v", err)
	}
	if d.n != 1 || d.maxSize != 4096 {
		t.Fatalf("after them: %d entries, limit %d", d.n, d.maxSize)
	}
	// An integer that goes on past ten bytes.
	if err := NewDecoder(100).Write([]byte{0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, emit); !errors.Is(err, ErrCompression) {
		t.Fatalf("an integer that never ends: %v", err)
	}
	// An integer padded with empty groups is what it amounts to, as Go's
	// decoder reads it (found by the fuzzer: a table size update of 31
	// written in seven bytes, then one of 16).
	d = NewDecoder(100)
	if err := d.Write([]byte{0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x30}, emit); err != nil || d.Close() != nil {
		t.Fatalf("a padded integer: %v", err)
	}
	if d.maxSize != 16 {
		t.Fatalf("table size limit %d after updates to 31 and 16", d.maxSize)
	}
	// A length that large is still checked against the limit.
	if err := NewDecoder(100).Write([]byte{0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}, emit); !errors.Is(err, ErrStringLength) {
		t.Fatalf("a name length of 2^56: %v", err)
	}
	// A block cut in the middle of a field.
	d = NewDecoder(100)
	if err := d.Write([]byte{0x00, 0x05, 'a', 'b'}, emit); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); !errors.Is(err, ErrCompression) {
		t.Fatalf("a block that stops inside a name: %v", err)
	}
	// An error of emit comes back.
	stop := errors.New("stop")
	if err := NewDecoder(100).Write([]byte{0x82}, func(_, _ []byte, _ bool) error { return stop }); err != stop {
		t.Fatalf("emit's error: %v", err)
	}
}

// The table stays inside its 4 KiB whatever is inserted, and an entry that
// names itself as it is evicted keeps its name.
func TestDecoderTable(t *testing.T) {
	rnd := rand.New(rand.NewSource(5))
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	ref := hpack.NewDecoder(4096, nil)
	d := NewDecoder(1 << 20)
	for i := 0; i < 20000; i++ {
		buf.Reset()
		name := fmt.Sprintf("x-%d", rnd.Intn(40))
		value := strings.Repeat("v", rnd.Intn(1500)) + fmt.Sprint(i)
		enc.WriteField(hpack.HeaderField{Name: name, Value: value})
		if _, diff := agree(d, ref, buf.Bytes(), []int{7}); diff != "" {
			t.Fatalf("insertion %d: %s", i, diff)
		}
		if d.size > d.maxSize || d.end > len(d.buf) || d.n > maxDynEntries {
			t.Fatalf("insertion %d: table size %d of %d, %d bytes, %d entries", i, d.size, d.maxSize, d.end, d.n)
		}
	}
	// "Literal with incremental indexing, indexed name", where the name's
	// entry is the one the insertion evicts (RFC 7541, section 4.4).
	d = NewDecoder(1 << 20)
	ref = hpack.NewDecoder(4096, nil)
	first := append([]byte{0x40}, appendString(nil, []byte("the-name"))...)
	first = append(first, appendString(nil, bytes.Repeat([]byte("a"), 2000))...)
	second := appendInt(nil, 0x40, 6, 62) // name = dynamic entry 62
	second = append(second, appendString(nil, bytes.Repeat([]byte("b"), 2100))...)
	for i, b := range [][]byte{first, second, {0x80 | 62}} {
		if _, diff := agree(d, ref, b, nil); diff != "" {
			t.Fatalf("block %d: %s", i, diff)
		}
	}
}

// What the encoder writes, the reference reads back as the same fields;
// nothing is added to its table.
func TestEncoderRoundTrip(t *testing.T) {
	rnd := rand.New(rand.NewSource(6))
	ref := hpack.NewDecoder(4096, nil)
	for i := 0; i < 20000; i++ {
		var want []field
		var block []byte
		code := []int{200, 204, 206, 304, 400, 404, 500, 100, 201, 301, 302, 403, 502, 503, 999}[rnd.Intn(15)]
		block = AppendStatus(block, code)
		want = append(want, field{":status", fmt.Sprint(code), false})
		for _, f := range randomFields(rnd) {
			if strings.HasPrefix(f.Name, ":") {
				continue
			}
			block = AppendField(block, []byte(f.Name), []byte(f.Value))
			want = append(want, field{f.Name, f.Value, false})
		}
		got, err := decodeRef(ref, block)
		if err != nil || !sameFields(got, want) {
			t.Fatalf("block %x:\n reference read %v (%v)\n want %v", block, got, err, want)
		}
	}
	// The reference's table is still empty: index 62 does not exist.
	if _, err := decodeRef(ref, []byte{0x80 | 62}); err == nil {
		t.Fatal("the encoder's output added an entry to the peer's table")
	}
}

func FuzzDecoder(f *testing.F) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	rnd := rand.New(rand.NewSource(7))
	for i := 0; i < 8; i++ {
		buf.Reset()
		for _, hf := range randomFields(rnd) {
			enc.WriteField(hf)
		}
		f.Add(append([]byte(nil), buf.Bytes()...), uint8(i), uint8(3*i+1))
	}
	f.Add([]byte{0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff}, uint8(2), uint8(5))
	f.Add([]byte{0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x30}, uint8(0), uint8(0)) // a padded integer
	f.Fuzz(func(t *testing.T, data []byte, a, b uint8) {
		// Three blocks on one connection: the input cut in three.
		ref := hpack.NewDecoder(4096, nil)
		ref.SetMaxStringLength(1 << 16)
		d := NewDecoder(1 << 16)
		for i := 0; i < 3 && len(data) > 0; i++ {
			n := len(data)
			if i < 2 {
				n = int(a) % (len(data) + 1)
			}
			failed, diff := agree(d, ref, data[:n], []int{1 + int(b)%17, 1 + int(a)%9})
			if diff != "" {
				t.Fatal(diff)
			}
			if failed {
				return
			}
			if d.size > d.maxSize || d.end > len(d.buf) || d.n > maxDynEntries {
				t.Fatalf("table size %d of %d, %d bytes, %d entries", d.size, d.maxSize, d.end, d.n)
			}
			data = data[n:]
		}
	})
}

func FuzzHuffman(f *testing.F) {
	f.Add([]byte("www.example.com"))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		want, werr := hpack.HuffmanDecodeToString(data)
		got, ok := huffDecode(nil, data, 1<<20)
		if ok != (werr == nil) || (ok && string(got) != want) {
			t.Fatalf("%x: decoded %q (ok=%v), reference %q (%v)", data, got, ok, want, werr)
		}
		enc := appendHuff(nil, data)
		if back, ok := huffDecode(nil, enc, 1<<20); !ok || !bytes.Equal(back, data) {
			t.Fatalf("%x does not round-trip: %x (ok=%v)", data, back, ok)
		}
	})
}

// A browser's request head, as its encoder sends it once its table is warm
// (every field indexed), and as it sends the first request (literals).
func benchRequest(warm bool) [][]byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "www.example.test"},
		{Name: ":path", Value: "/assets/app.3f9a1c.js"},
		{Name: "user-agent", Value: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
		{Name: "accept", Value: "*/*"}, {Name: "accept-encoding", Value: "gzip, deflate, br, zstd"},
		{Name: "accept-language", Value: "en-US,en;q=0.9"}, {Name: "referer", Value: "https://www.example.test/"},
		{Name: "sec-fetch-dest", Value: "script"}, {Name: "sec-fetch-mode", Value: "no-cors"}, {Name: "sec-fetch-site", Value: "same-origin"},
	}
	var blocks [][]byte
	for i := 0; i < 2; i++ {
		buf.Reset()
		for _, f := range fields {
			enc.WriteField(f)
		}
		blocks = append(blocks, append([]byte(nil), buf.Bytes()...))
	}
	if warm {
		return blocks // the first fills the table, the second is all indexes
	}
	return blocks[:1]
}

func BenchmarkDecodeIndexedRequest(b *testing.B) {
	blocks := benchRequest(true)
	d := NewDecoder(1 << 20)
	n := 0
	emit := func(name, value []byte, _ bool) error { n += len(name) + len(value); return nil }
	if err := d.Write(blocks[0], emit); err != nil || d.Close() != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := d.Write(blocks[1], emit); err != nil {
			b.Fatal(err)
		}
		d.Close()
	}
}

func BenchmarkDecodeFirstRequest(b *testing.B) {
	block := benchRequest(false)[0]
	d := NewDecoder(1 << 20)
	n := 0
	emit := func(name, value []byte, _ bool) error { n += len(name) + len(value); return nil }
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Reset()
		if err := d.Write(block, emit); err != nil {
			b.Fatal(err)
		}
		d.Close()
	}
}

func BenchmarkEncodeResponseHead(b *testing.B) {
	type kv struct{ k, v []byte }
	fields := []kv{
		{[]byte("content-type"), []byte("application/javascript; charset=utf-8")},
		{[]byte("content-length"), []byte("48211")},
		{[]byte("date"), []byte("Sat, 14 Nov 2026 18:22:05 GMT")},
		{[]byte("etag"), []byte(`"3f9a1c-bc53"`)},
		{[]byte("cache-control"), []byte("public, max-age=31536000, immutable")},
		{[]byte("x-request-id"), []byte("0af7651916cd43dd8448eb211c80319c")},
		{[]byte("vary"), []byte("Accept-Encoding")},
		{[]byte("server"), []byte("origin/1.0")},
	}
	dst := make([]byte, 0, 512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = AppendStatus(dst[:0], 200)
		for _, f := range fields {
			dst = AppendField(dst, f.k, f.v)
		}
	}
}
