package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// ticketCache is a client's session cache that also hands out every
// session stored in it.
type ticketCache struct {
	tls.ClientSessionCache
	stored chan *tls.ClientSessionState
}

func newTicketCache() *ticketCache {
	return &ticketCache{ClientSessionCache: tls.NewLRUClientSessionCache(1), stored: make(chan *tls.ClientSessionState, 4)}
}

func (c *ticketCache) Put(key string, cs *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, cs)
	if cs == nil {
		return
	}
	select {
	case c.stored <- cs:
	default:
	}
}

// ticket waits for the session ticket of a connection, at most for d.
func (c *ticketCache) ticket(d time.Duration) *tls.ClientSessionState {
	select {
	case cs := <-c.stored:
		return cs
	case <-time.After(d):
		return nil
	}
}

// resumed reports whether the server's i-th connection resumed a session.
func (s *testServer) resumed(i int) bool {
	c := s.conn(i)
	s.waitFor("the server's connection to be established", func() bool { e, _, _ := s.state(c); return e })
	s.mu.Lock()
	defer s.mu.Unlock()
	return c.ConnectionState().DidResume
}

// Once the handshake is done the server sends a session ticket, and a
// client that comes back with it resumes the session. The ticket offers no
// early data: a client that sends as soon as it may, as a 0-RTT client
// does, is answered once, on a connection that did not use 0-RTT.
func TestConn_SessionResumed(t *testing.T) {
	s, h := newEchoServer(t, nil)
	cache := newTicketCache()
	conf := clientTLS.Clone()
	conf.ClientSessionCache = cache
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	first, err := quicgo.DialAddr(ctx, s.addr(), conf, &quicgo.Config{})
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	defer first.CloseWithError(0, "")
	ticket := cache.ticket(5 * time.Second)
	if ticket == nil {
		t.Fatal("the server sent no session ticket")
	}
	_, session, err := ticket.ResumptionState()
	if err != nil || session == nil {
		t.Fatalf("session ticket: state %v, err %v", session, err)
	}
	if session.EarlyData {
		t.Error("the session ticket offers early data")
	}
	if first.ConnectionState().TLS.DidResume || s.resumed(0) {
		t.Error("the first connection resumed a session")
	}
	first.CloseWithError(0, "")

	second, err := quicgo.DialAddrEarly(ctx, s.addr(), conf, &quicgo.Config{})
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	defer second.CloseWithError(0, "")
	body := []byte("sent as soon as the client may send")
	got, err := echo(second, body)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("echo on the second connection: %q, %v", got, err)
	}
	select {
	case <-second.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("the handshake of the second connection did not complete")
	}
	st := second.ConnectionState()
	if !st.TLS.DidResume {
		t.Error("the client did not resume the session: the ticket went unused")
	}
	if st.Used0RTT {
		t.Error("the second connection used 0-RTT")
	}
	if !s.resumed(1) {
		t.Error("the server did not resume the session")
	}
	s.mu.Lock()
	n := len(h.streams[s.all[1]])
	s.mu.Unlock()
	if n != 1 {
		t.Errorf("the server saw %d streams on the second connection, want the one", n)
	}
	// A resumed connection is given a ticket of its own.
	if cache.ticket(5*time.Second) == nil {
		t.Error("the resumed connection got no session ticket")
	}
}

// The datagram that carries the session ticket is lost: the ticket is sent
// again, like any data of the handshake, and the client's next connection
// resumes the session.
func TestConn_SessionTicketSentAgain(t *testing.T) {
	var armed bool
	var after, lost int
	s := newTestServer(t, func(s *testServer) {
		// The first datagram the server sends once a handshake is complete.
		s.established = func(*Conn) {
			if !armed {
				armed, after = true, s.sent
			}
		}
		s.drop = func(n int) bool {
			if armed && n == after {
				lost++
				return true
			}
			return false
		}
	})
	cache := newTicketCache()
	conf := clientTLS.Clone()
	conf.ClientSessionCache = cache
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	first, err := quicgo.DialAddr(ctx, s.addr(), conf, &quicgo.Config{})
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	defer first.CloseWithError(0, "")
	if cache.ticket(10*time.Second) == nil {
		t.Fatal("the session ticket never arrived after its datagram was lost")
	}
	s.mu.Lock()
	n := lost
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d datagrams were lost, want the one that follows the handshake", n)
	}
	first.CloseWithError(0, "")

	second, err := quicgo.DialAddr(ctx, s.addr(), conf, &quicgo.Config{})
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	defer second.CloseWithError(0, "")
	if !second.ConnectionState().TLS.DidResume || !s.resumed(1) {
		t.Error("the second connection did not resume the session")
	}
}

// Without a ticket a connection is none the worse. Tickets turned off in
// the TLS configuration: none is sent. Turned off in the configuration the
// server was given but not in the one chosen for the client: there is no
// key to make a ticket with, which is no reason to end the connection. In
// both cases the connection serves, and the next one is a full handshake.
func TestConn_NoSessionTicket(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *tls.Config)
	}{
		{"tickets off", func(c *tls.Config) { c.SessionTicketsDisabled = true }},
		{"no ticket keys", func(c *tls.Config) {
			sub := c.Clone()
			c.SessionTicketsDisabled = true
			c.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return sub, nil }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newEchoServer(t, func(s *testServer) { tc.setup(s.cfg.TLS) })
			cache := newTicketCache()
			conf := clientTLS.Clone()
			conf.ClientSessionCache = cache
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			for i := range 2 {
				cc, err := quicgo.DialAddr(ctx, s.addr(), conf, &quicgo.Config{})
				if err != nil {
					t.Fatalf("connection %d: %v", i, err)
				}
				body := []byte("served without a ticket")
				got, err := echo(cc, body)
				if err != nil || !bytes.Equal(got, body) {
					t.Fatalf("connection %d: echo %q, %v", i, got, err)
				}
				if cache.ticket(300*time.Millisecond) != nil {
					t.Errorf("connection %d: the server sent a session ticket", i)
				}
				if cc.ConnectionState().TLS.DidResume || s.resumed(i) {
					t.Errorf("connection %d resumed a session", i)
				}
				if cerr := context.Cause(cc.Context()); cerr != nil {
					t.Errorf("connection %d ended: %v", i, cerr)
				}
				cc.CloseWithError(0, "")
			}
		})
	}
}
