//go:build linux

package httpproxy

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"

	nvquic "github.com/nvelox/ngx/quic"

	"github.com/quic-go/quic-go"
)

// rovingConn is a client's UDP socket whose datagrams can leave from
// another one: they then come from another port, as when a NAT maps the
// client's flow anew. What the server sends to the socket in use reaches
// the client; what it sends to one the client has left is lost, as it
// would be, and so is what it sends to a spy's.
type rovingConn struct {
	net.PacketConn // where the client is at first

	mu    sync.Mutex
	now   net.PacketConn   // where its datagrams leave from
	spies []net.PacketConn // when set: each datagram leaves from one of them first, a copy, in turn
	turn  int
	named []byte                 // the connection ID of the server's that the client's 1-RTT packets name
	first []byte                 // the one its first 1-RTT packet named
	sent  map[net.PacketConn]int // datagrams sent from each socket
	bytes map[net.PacketConn]int // their bytes
	got   map[net.PacketConn][]int
	// lost, when set, says whether a datagram of n bytes that the server
	// sent to pc is lost on its way.
	lost     func(pc net.PacketConn, n int) bool
	socks    []net.PacketConn
	deadline time.Time
	kick     chan struct{}
	in       chan rovingDatagram
	// holding: so many of the next datagrams are kept back instead of
	// sent (held), for the test to send later; everywhere: what the server
	// sends to any of the sockets reaches the client.
	holding    int
	held       [][]byte
	everywhere bool
}

type rovingDatagram struct {
	b    []byte
	from net.Addr
}

func newRovingConn(t *testing.T) *rovingConn {
	t.Helper()
	c := &rovingConn{sent: map[net.PacketConn]int{}, bytes: map[net.PacketConn]int{}, got: map[net.PacketConn][]int{},
		kick: make(chan struct{}, 1), in: make(chan rovingDatagram, 4096)}
	c.PacketConn = c.open(t, "127.0.0.1")
	c.now = c.PacketConn
	t.Cleanup(func() { c.Close() })
	return c
}

// open opens a socket at ip and has what arrives on it recorded, and
// passed to the client while it is the socket in use.
func (c *rovingConn) open(t *testing.T, ip string) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.socks = append(c.socks, pc)
	c.mu.Unlock()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			c.mu.Lock()
			c.got[pc] = append(c.got[pc], n)
			live := (c.now == pc || c.everywhere) && (c.lost == nil || !c.lost(pc, n))
			c.mu.Unlock()
			if live {
				select {
				case c.in <- rovingDatagram{append([]byte(nil), buf[:n]...), from}:
				default:
				}
			}
		}
	}()
	return pc
}

// moveTo takes the client to a new address at ip, which it returns.
func (c *rovingConn) moveTo(t *testing.T, ip string) net.PacketConn {
	pc := c.open(t, ip)
	c.mu.Lock()
	c.now = pc
	c.mu.Unlock()
	return pc
}

func (c *rovingConn) WriteTo(p []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	if c.holding > 0 {
		c.holding--
		c.held = append(c.held, append([]byte(nil), p...))
		c.mu.Unlock()
		return len(p), nil
	}
	now := c.now
	var spy net.PacketConn
	if len(c.spies) > 0 {
		spy = c.spies[c.turn%len(c.spies)]
		c.turn++
		c.sent[spy]++
		c.bytes[spy] += len(p)
	}
	c.sent[now]++
	c.bytes[now] += len(p)
	// The first 1-RTT packet often shares its datagram with a packet of
	// the handshake, which it then follows.
	for d := p; len(d) > 0; {
		h, err := nvquic.ParseHeader(d, nvquic.CIDLen)
		if err != nil {
			break
		}
		if h.Type == nvquic.PacketShort {
			c.named = append(c.named[:0], h.DCID...)
			if c.first == nil {
				c.first = append([]byte(nil), h.DCID...)
			}
			break
		}
		d = d[h.End:]
	}
	c.mu.Unlock()
	if spy != nil {
		// The copy is well ahead, whichever of the server's sockets the
		// two reach.
		spy.WriteTo(p, a)
		time.Sleep(time.Millisecond)
	}
	return now.WriteTo(p, a)
}

func (c *rovingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		by := c.deadline
		c.mu.Unlock()
		var timeout <-chan time.Time
		if !by.IsZero() {
			t := time.NewTimer(time.Until(by))
			defer t.Stop()
			timeout = t.C
		}
		select {
		case d := <-c.in:
			return copy(p, d.b), d.from, nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.kick:
		}
	}
}

func (c *rovingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return nil
}

func (c *rovingConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *rovingConn) Close() error {
	c.mu.Lock()
	socks := c.socks
	c.socks = nil
	c.mu.Unlock()
	for _, pc := range socks {
		pc.Close()
	}
	return c.SetReadDeadline(time.Now())
}

func asAppError(err error, target **quic.ApplicationError) bool {
	for err != nil {
		if e, ok := err.(*quic.ApplicationError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
