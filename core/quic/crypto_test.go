package quic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	mrand "math/rand"
	"net"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// Frames in order, out of order, repeated and overlapping: the stream
// comes out whole and in order, once.
func TestCryptoRecv(t *testing.T) {
	stream := make([]byte, 20000)
	rand.Read(stream)
	for seed := int64(1); seed <= 200; seed++ {
		rng := mrand.New(mrand.NewSource(seed))
		// Cut the stream in pieces, then send them shuffled, some twice and
		// some widened over their neighbours.
		type piece struct{ off, end int }
		var pieces []piece
		for off := 0; off < len(stream); {
			n := 1 + rng.Intn(1500)
			end := min(off+n, len(stream))
			pieces = append(pieces, piece{off, end})
			off = end
		}
		if seed%4 != 0 { // a quarter of the runs stay in order
			rng.Shuffle(len(pieces), func(i, j int) { pieces[i], pieces[j] = pieces[j], pieces[i] })
		}
		var c CryptoRecv
		var got []byte
		deliver := func(p []byte) error { got = append(got, p...); return nil }
		for _, p := range pieces {
			off, end := p.off, p.end
			if rng.Intn(3) == 0 {
				off, end = max(0, off-rng.Intn(300)), min(len(stream), end+rng.Intn(300))
			}
			if err := c.Push(uint64(off), stream[off:end], deliver); err != nil {
				t.Fatalf("seed %d: %v", seed, err)
			}
			if rng.Intn(4) == 0 {
				if err := c.Push(uint64(p.off), stream[p.off:p.end], deliver); err != nil {
					t.Fatalf("seed %d, a repeated frame: %v", seed, err)
				}
			}
		}
		if !bytes.Equal(got, stream) {
			t.Fatalf("seed %d: %d bytes delivered, want the stream's %d in order", seed, len(got), len(stream))
		}
		if c.Pending() {
			t.Fatalf("seed %d: data still held", seed)
		}
	}
	// Too far ahead, and too many pieces.
	var c CryptoRecv
	none := func([]byte) error { return nil }
	if err := c.Push(CryptoWindow, []byte{1}, none); err != CryptoBufferExceeded {
		t.Errorf("data past the window: %v", err)
	}
	if err := c.Push(CryptoWindow-1, []byte{1}, none); err != nil {
		t.Errorf("data at the end of the window: %v", err)
	}
	c = CryptoRecv{}
	var err error
	for i := 0; i <= cryptoMaxRanges && err == nil; i++ {
		err = c.Push(uint64(10+3*i), []byte{1}, none)
	}
	if err != CryptoBufferExceeded {
		t.Errorf("%d separate pieces: %v", cryptoMaxRanges+1, err)
	}
}

// holedStream cuts stream into pieces of pieceLen bytes with one byte left
// out between them, and before the first: the pieces, and the offsets of
// the bytes left out.
func holedStream(stream []byte, pieceLen int) (pieces [][2]int, holes []int) {
	for off := 0; off < len(stream); off += pieceLen + 1 {
		holes = append(holes, off)
		if off+1 < len(stream) {
			pieces = append(pieces, [2]int{off + 1, min(off+1+pieceLen, len(stream))})
		}
	}
	return pieces, holes
}

// A stream's window filled with as many separate pieces as are kept, and
// the holes between them filled from the front, one piece delivered at a
// time: all of it comes out whole and in order, nothing stays held, and
// the buffer is no larger than twice what waited.
func TestReassembly_HolesFilledFromTheFront(t *testing.T) {
	stream := make([]byte, 1<<20)
	rand.Read(stream)
	pieces, holes := holedStream(stream, len(stream)/(streamMaxRanges-2))
	if len(pieces) > streamMaxRanges || len(pieces) < streamMaxRanges-8 {
		t.Fatalf("the test cut the stream in %d pieces, want about %d", len(pieces), streamMaxRanges)
	}
	var r reassembly
	largest := 0
	// Four windows of it, one after the other on the same stream: the
	// buffer is the same size for the fourth as for the first.
	for window := 0; window < 4; window++ {
		base := uint64(window * len(stream))
		var got []byte
		deliver := func(p []byte) { got = append(got, p...) }
		for _, p := range pieces {
			if !r.push(base+uint64(p[0]), stream[p[0]:p[1]], streamMaxRanges, deliver) {
				t.Fatalf("window %d: the piece at %d was not taken", window, p[0])
			}
		}
		if len(got) != 0 || len(r.ranges) != len(pieces) {
			t.Fatalf("window %d: %d bytes delivered and %d pieces held before the first byte arrived", window, len(got), len(r.ranges))
		}
		for i, off := range holes {
			if !r.push(base+uint64(off), stream[off:off+1], streamMaxRanges, deliver) {
				t.Fatalf("window %d: the byte at %d was not taken", window, off)
			}
			want := len(stream)
			if i+1 < len(holes) {
				want = holes[i+1]
			}
			if len(got) != want {
				t.Fatalf("window %d: after the byte at %d: %d bytes delivered, want %d", window, off, len(got), want)
			}
			largest = max(largest, cap(r.buf))
		}
		if !bytes.Equal(got, stream) {
			t.Fatalf("window %d: the stream came out changed", window)
		}
		if len(r.ranges) != 0 || len(r.buf) != 0 || r.at != 0 {
			t.Errorf("window %d: at the end %d pieces and %d bytes are held (from %d)", window, len(r.ranges), len(r.buf), r.at)
		}
	}
	if largest > 2*len(stream) {
		t.Errorf("the buffer grew to %d bytes for windows of %d", largest, len(stream))
	}
	// A stream that goes on behind a hole which is filled late: what was
	// delivered in front does not stay in the buffer for good.
	r = reassembly{}
	deliver := func([]byte) {}
	const piece = 1000
	r.push(1, stream[1:piece], streamMaxRanges, deliver) // the hole is byte 0
	off := piece
	step := func() {
		r.push(uint64(off+1), stream[off+1:off+piece], streamMaxRanges, deliver) // a hole at off as well
		r.push(uint64(off-piece), stream[off-piece:off-piece+1], streamMaxRanges, deliver)
		off += piece
	}
	for i := 0; i < 20; i++ {
		step()
	}
	// From here on the buffer is what it will be: no step allocates, and it
	// stays small. (Ten steps a run: AllocsPerRun reports whole numbers.)
	if a := testing.AllocsPerRun(50, func() {
		for i := 0; i < 10; i++ {
			step()
		}
	}); a != 0 {
		t.Errorf("%v allocations for ten pieces delivered behind a late hole, want none: what was delivered is dropped in place", a)
	}
	if cap(r.buf) > 64<<10 {
		t.Errorf("the buffer has grown to %d bytes for two pieces of %d that wait", cap(r.buf), piece)
	}
	if r.next != uint64(off-piece) {
		t.Errorf("%d bytes were delivered, want %d", r.next, off-piece)
	}
}

// BenchmarkReassembly: a megabyte in pieces with holes between them that
// are filled from the front, as above: what it costs per megabyte.
func BenchmarkReassembly(b *testing.B) {
	stream := make([]byte, 1<<20)
	pieces, holes := holedStream(stream, len(stream)/(streamMaxRanges-2))
	deliver := func([]byte) {}
	b.SetBytes(int64(len(stream)))
	var r reassembly
	for i := 0; i < b.N; i++ {
		base := r.next
		for _, p := range pieces {
			r.push(base+uint64(p[0]), stream[p[0]:p[1]], streamMaxRanges, deliver)
		}
		for _, off := range holes {
			r.push(base+uint64(off), stream[off:off+1], streamMaxRanges, deliver)
		}
		if r.next != base+uint64(len(stream)) {
			b.Fatalf("%d bytes delivered of %d", r.next-base, len(stream))
		}
	}
}

// testCert is a self-signed certificate for "example.test".
func testCert(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A real client's first flight, through this package and into crypto/tls:
// quic-go's Initial packets are opened, their CRYPTO frames put in order
// and given to tls.QUICServer, which then reports the client's transport
// parameters (they parse, and name the connection ID the packets came
// from), the Handshake keys, and the server's own flight to send.
func TestHandshake_RealClientFirstFlight(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	go func() {
		c, err := quicgo.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"h3"}}, nil)
		if err == nil {
			c.CloseWithError(0, "")
		}
	}()

	srv := tls.QUICServer(&tls.QUICConfig{TLSConfig: &tls.Config{Certificates: []tls.Certificate{testCert(t)}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}})
	defer srv.Close()
	var odcid, scid []byte
	var recv CryptoRecv
	var clientParams Params
	var gotParams, gotHandshakeRead, gotHandshakeWrite bool
	var initialOut, handshakeOut int
	started := false
	// drain reads the events crypto/tls has for us.
	drain := func() {
		for {
			ev := srv.NextEvent()
			switch ev.Kind {
			case tls.QUICNoEvent:
				return
			case tls.QUICTransportParameters:
				if err := ParseClientParams(ev.Data, &clientParams); err != nil {
					t.Fatalf("the client's transport parameters: %v (%x)", err, ev.Data)
				}
				clientParams.InitialSCID = append([]byte(nil), clientParams.InitialSCID...)
				gotParams = true
			case tls.QUICSetReadSecret:
				if ev.Level == tls.QUICEncryptionLevelHandshake {
					if _, err := NewKeys(ev.Suite, ev.Data); err != nil {
						t.Fatalf("Handshake read keys: %v", err)
					}
					gotHandshakeRead = true
				}
			case tls.QUICSetWriteSecret:
				if ev.Level == tls.QUICEncryptionLevelHandshake {
					if _, err := NewKeys(ev.Suite, ev.Data); err != nil {
						t.Fatalf("Handshake write keys: %v", err)
					}
					gotHandshakeWrite = true
				}
			case tls.QUICWriteData:
				switch ev.Level {
				case tls.QUICEncryptionLevelInitial:
					initialOut += len(ev.Data)
				case tls.QUICEncryptionLevelHandshake:
					handshakeOut += len(ev.Data)
				}
			case tls.QUICErrorEvent:
				t.Fatalf("crypto/tls: %v", ev.Err)
			}
		}
	}
	buf := make([]byte, 2048)
	var f Frame
	for deadline := time.Now().Add(5 * time.Second); !gotHandshakeWrite && time.Now().Before(deadline); {
		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		for dgram := buf[:n]; len(dgram) > 0; {
			h, err := ParseHeader(dgram, 8)
			if err != nil || h.Type != PacketInitial {
				break // padding after the packet, or another type
			}
			if odcid == nil {
				odcid = append([]byte(nil), h.DCID...)
				scid = append([]byte(nil), h.SCID...)
			}
			client, _ := InitialKeys(odcid)
			payload, _, _, err := client.Open(dgram[:h.End], h.PNOff, -1)
			if err != nil {
				t.Fatalf("an Initial packet does not open: %v", err)
			}
			for p := payload; len(p) > 0; {
				fn, err := ParseFrame(p, &f)
				if err != nil {
					t.Fatalf("frame: %v", err)
				}
				if !f.AllowedAt(LevelInitial) {
					t.Fatalf("frame %#x in an Initial packet", f.Type)
				}
				if f.Type == FrameCrypto {
					if !started {
						// Our parameters go in before the handshake starts.
						sp := Params{OriginalDCID: odcid, InitialSCID: []byte{1, 2, 3, 4, 5, 6, 7, 8}, MaxIdleTimeout: 30 * time.Second,
							InitialMaxData: 1 << 20, InitialMaxStreamDataBidiRemote: 1 << 18, InitialMaxStreamDataUni: 1 << 18,
							InitialMaxStreamsBidi: 100, InitialMaxStreamsUni: 3, AckDelayExponent: defaultAckDelayExponent, MaxAckDelay: defaultMaxAckDelay}
						srv.SetTransportParameters(sp.Append(nil))
						if err := srv.Start(context.Background()); err != nil {
							t.Fatal(err)
						}
						started = true
					}
					if err := recv.Push(f.Offset, f.Data, func(d []byte) error {
						return srv.HandleData(tls.QUICEncryptionLevelInitial, d)
					}); err != nil {
						t.Fatalf("CRYPTO data: %v", err)
					}
					drain()
				}
				p = p[fn:]
			}
			dgram = dgram[h.End:]
		}
	}
	cancel()
	if !gotParams || !gotHandshakeRead || !gotHandshakeWrite {
		t.Fatalf("after the client's first flight: parameters %v, Handshake read keys %v, write keys %v", gotParams, gotHandshakeRead, gotHandshakeWrite)
	}
	if !bytes.Equal(clientParams.InitialSCID, scid) {
		t.Errorf("initial_source_connection_id %x, the packets came from %x", clientParams.InitialSCID, scid)
	}
	if clientParams.InitialMaxData == 0 || clientParams.InitialMaxStreamsUni < 3 || clientParams.MaxUDPPayloadSize < 1200 {
		t.Errorf("a client that offers no room: %+v", clientParams)
	}
	if initialOut == 0 || handshakeOut == 0 {
		t.Errorf("the server's flight: %d bytes at the Initial level, %d at the Handshake level", initialOut, handshakeOut)
	}
	t.Logf("client: %d-byte ODCID, max_data %d, streams bidi/uni %d/%d, idle %v; server flight: %d + %d bytes", len(odcid), clientParams.InitialMaxData, clientParams.InitialMaxStreamsBidi, clientParams.InitialMaxStreamsUni, clientParams.MaxIdleTimeout, initialOut, handshakeOut)
}
