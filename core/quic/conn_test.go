package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// testServer runs connections of this package on a UDP socket, one
// goroutine for all of them, the way a loop will: datagrams in, datagrams
// out, timers.
type testServer struct {
	t   *testing.T
	pc  *net.UDPConn
	cfg *Config

	mu    sync.Mutex
	conns map[string]*Conn // by client address
	all   []*Conn
	// drop, when set, says whether an outgoing datagram (the n-th, from 0)
	// is lost on its way; dropIn the same for the incoming ones.
	drop   func(n int) bool
	dropIn func(n int) bool
	sent   int
	recvd  int
	// established, when set, is called once for each connection whose
	// handshake completes.
	established func(c *Conn)
	told        map[*Conn]bool
	// inHandshake: RecvHandshake is running; afterHandshake counts the
	// datagrams it left a part of for Recv.
	inHandshake    bool
	afterHandshake int
	// coalesce joins a client's datagram that ends with a Handshake packet
	// with the datagram that follows it within a moment, as a client may
	// send them itself: the handshake's last packet then shares a
	// datagram with the first packets after it.
	coalesce bool
}

// endsWithHandshake reports whether every packet of the datagram has a
// long header and the last one is a Handshake packet: another datagram may
// be appended to such a one.
func endsWithHandshake(d []byte) bool {
	last := -1
	for len(d) > 0 {
		h, err := ParseHeader(d, CIDLen)
		if err != nil || h.Type == PacketShort {
			return false
		}
		last = int(h.Type)
		d = d[h.End:]
	}
	return last == PacketHandshake
}

// handshakeGuard is a server's handler, checked: nothing may reach it
// from RecvHandshake.
type handshakeGuard struct {
	Handler
	s *testServer
}

func (g *handshakeGuard) StreamData(c *Conn, id uint64, data []byte, fin bool) {
	if g.s.inHandshake {
		g.s.t.Errorf("RecvHandshake told the handler of data on stream %d", id)
	}
	g.Handler.StreamData(c, id, data, fin)
}

// newTestServer starts a server; setup, when given, changes it before its
// goroutine runs.
func newTestServer(t *testing.T, setup func(*testServer)) *testServer {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{t: t, pc: pc, conns: map[string]*Conn{}}
	s.cfg = &Config{
		TLS: &tls.Config{Certificates: []tls.Certificate{testCert(t)}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		Params: Params{MaxIdleTimeout: 30 * time.Second, InitialMaxData: 1 << 20, InitialMaxStreamDataBidiRemote: 1 << 18,
			InitialMaxStreamDataUni: 1 << 18, InitialMaxStreamsBidi: 100, InitialMaxStreamsUni: 100,
			AckDelayExponent: defaultAckDelayExponent, MaxAckDelay: defaultMaxAckDelay},
	}
	s.told = map[*Conn]bool{}
	if setup != nil {
		setup(s)
	}
	if h := s.cfg.Handler; h != nil {
		s.cfg.Handler = &handshakeGuard{Handler: h, s: s}
	}
	done := make(chan struct{})
	t.Cleanup(func() { pc.Close(); <-done })
	go func() {
		defer close(done)
		s.serve()
	}()
	return s
}

func (s *testServer) addr() string { return s.pc.LocalAddr().String() }

func (s *testServer) serve() {
	in := make([]byte, 4096) // room for two datagrams joined (coalesce)
	out := make([]byte, 2048)
	for {
		s.pc.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		n, from, err := s.pc.ReadFromUDP(in)
		if err == nil && s.coalesce && n+1300 <= len(in) && endsWithHandshake(in[:n]) {
			s.pc.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			if m, from2, err2 := s.pc.ReadFromUDP(in[n:]); err2 == nil && from2.String() == from.String() {
				n += m
			}
		}
		now := time.Now().UnixNano()
		s.mu.Lock()
		if err == nil && s.dropIn != nil && s.dropIn(s.recvd) {
			s.recvd++
			err = errDropped
		} else if err == nil {
			s.recvd++
		}
		if err == nil {
			key := from.String()
			c := s.conns[key]
			if c == nil {
				h, herr := ParseHeader(in[:n], CIDLen)
				if herr == nil && h.Type == PacketInitial && n >= MinInitialSize {
					cid, token := make([]byte, CIDLen), make([]byte, 16)
					rand.Read(cid)
					rand.Read(token)
					if c, err = Accept(s.cfg, now, h.DCID, h.SCID, cid, token); err == nil {
						s.conns[key] = c
						s.all = append(s.all, c)
					}
				}
			}
			if c != nil {
				// As a server feeds a connection whose handshake runs away
				// from its streams: RecvHandshake until it is complete,
				// Recv for what follows in that datagram and from then on.
				if c.Established() {
					c.Recv(now, in[:n])
				} else {
					s.inHandshake = true
					rest := c.RecvHandshake(now, in[:n])
					s.inHandshake = false
					if len(rest) > 0 {
						if !c.Established() {
							s.t.Errorf("RecvHandshake left %d bytes of a datagram although the handshake is not complete", len(rest))
						}
						s.afterHandshake++
						c.Recv(now, rest)
					}
				}
				if s.established != nil && c.Established() && !s.told[c] {
					s.told[c] = true
					s.established(c)
				}
			}
		} else if ne, ok := err.(net.Error); err != errDropped && (!ok || !ne.Timeout()) {
			s.mu.Unlock()
			return // the socket was closed
		}
		for key, c := range s.conns {
			if d := c.Deadline(); d != 0 && now >= d {
				c.OnTimer(now)
			}
			addr, _ := net.ResolveUDPAddr("udp", key)
			for {
				m := c.Send(now, out[:maxDatagram])
				if m == 0 {
					break
				}
				lost := s.drop != nil && s.drop(s.sent)
				s.sent++
				if !lost {
					s.pc.WriteToUDP(out[:m], addr)
				}
			}
			if c.Closed() {
				delete(s.conns, key)
			}
		}
		s.mu.Unlock()
	}
}

var errDropped = errors.New("dropped by the test")

// conn returns the i-th connection the server accepted, waiting for it.
func (s *testServer) conn(i int) *Conn {
	s.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		if len(s.all) > i {
			c := s.all[i]
			s.mu.Unlock()
			return c
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			s.t.Fatalf("the server accepted no connection %d", i)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// state reads something of a connection under the server's lock.
func (s *testServer) state(c *Conn) (established, closed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return c.Established(), c.Closed(), c.Err()
}

func (s *testServer) waitFor(what string, cond func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

var clientTLS = &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"h3"}}

// A real client completes its handshake with this server: quic-go's dial
// returns, with the ALPN protocol agreed and TLS 1.3, and the server has
// the connection established. The client's close then ends it with the
// client's code.
func TestConn_HandshakeWithRealClient(t *testing.T) {
	s := newTestServer(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cc, err := quicgo.DialAddr(ctx, s.addr(), clientTLS, &quicgo.Config{})
	if err != nil {
		t.Fatalf("the client's handshake: %v", err)
	}
	st := cc.ConnectionState()
	if st.TLS.NegotiatedProtocol != "h3" || st.TLS.Version != tls.VersionTLS13 || !st.TLS.HandshakeComplete {
		t.Errorf("client TLS state: protocol %q, version %#x, complete %v", st.TLS.NegotiatedProtocol, st.TLS.Version, st.TLS.HandshakeComplete)
	}
	c := s.conn(0)
	s.waitFor("the server's connection to be established", func() bool { e, _, _ := s.state(c); return e })
	s.mu.Lock()
	proto := c.ConnectionState().NegotiatedProtocol
	s.mu.Unlock()
	if proto != "h3" {
		t.Errorf("server TLS state: protocol %q", proto)
	}
	// The connection stays up while nothing happens (the client is told
	// the handshake is done and does not send it again and again).
	time.Sleep(300 * time.Millisecond)
	if e, closed, err := s.state(c); !e || closed || err != nil {
		t.Fatalf("300 ms after the handshake: established %v, closed %v, %v", e, closed, err)
	}
	if cerr := context.Cause(cc.Context()); cerr != nil {
		t.Fatalf("the client's connection ended: %v", cerr)
	}
	cc.CloseWithError(0x10c, "bye")
	s.waitFor("the server to see the client's close", func() bool { _, _, err := s.state(c); return err != nil })
	_, _, cerr := s.state(c)
	var pcErr *PeerClosed
	if !errors.As(cerr, &pcErr) || !pcErr.App || pcErr.Code != 0x10c || pcErr.Reason != "bye" {
		t.Errorf("the connection's error: %v, want the client's close with code 0x10c", cerr)
	}
}

// The server's flight is lost on its way: the first datagrams it sends
// never arrive. The handshake still completes, through the probe timeout.
func TestConn_HandshakeWithLoss(t *testing.T) {
	for _, lost := range []int{1, 2, 3} {
		s := newTestServer(t, func(s *testServer) { s.drop = func(n int) bool { return n < lost } })
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cc, err := quicgo.DialAddr(ctx, s.addr(), clientTLS, &quicgo.Config{})
		cancel()
		if err != nil {
			t.Fatalf("first %d datagrams lost: the client's handshake: %v", lost, err)
		}
		c := s.conn(0)
		s.waitFor("the server's connection to be established", func() bool { e, _, _ := s.state(c); return e })
		cc.CloseWithError(0, "")
	}
}

// A client that offers another ALPN protocol is refused in the handshake:
// its dial fails with a TLS alert, and the server's connection ends with
// the matching CRYPTO_ERROR.
func TestConn_HandshakeRefused(t *testing.T) {
	s := newTestServer(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conf := clientTLS.Clone()
	conf.NextProtos = []string{"something-else"}
	if cc, err := quicgo.DialAddr(ctx, s.addr(), conf, &quicgo.Config{}); err == nil {
		cc.CloseWithError(0, "")
		t.Fatalf("a client without a common protocol was let in")
	} else {
		var te *quicgo.TransportError
		if !errors.As(err, &te) || te.ErrorCode != quicgo.TransportErrorCode(CryptoError+120) {
			t.Errorf("the client's error: %v, want CRYPTO_ERROR with alert 120 (no_application_protocol)", err)
		}
	}
	c := s.conn(0)
	_, _, cerr := s.state(c)
	if cerr == nil {
		t.Errorf("the server's connection has no error")
	}
}

// Nothing arrives for the idle timeout: the connection ends, silently.
func TestConn_IdleTimeout(t *testing.T) {
	s := newTestServer(t, func(s *testServer) { s.cfg.Params.MaxIdleTimeout = 400 * time.Millisecond })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The client keeps its own idle timeout long and sends no keep-alives.
	cc, err := quicgo.DialAddr(ctx, s.addr(), clientTLS, &quicgo.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.CloseWithError(0, "")
	c := s.conn(0)
	s.waitFor("the idle timeout", func() bool { _, closed, _ := s.state(c); return closed })
	if _, _, cerr := s.state(c); cerr != ErrIdle {
		t.Errorf("the connection's error: %v, want %v", cerr, ErrIdle)
	}
}
