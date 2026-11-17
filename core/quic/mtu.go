package quic

// The size of the datagrams a connection sends (RFC 9000, section 14.3;
// RFC 8899). Every path carries maxDatagram bytes, and nearly every path
// carries more: Ethernet 1,472 of UDP payload over IPv4, a tunnel some
// tens fewer. A download in larger datagrams is fewer packets, for this
// server, for the client and for everything between them that works per
// packet.
//
// A connection finds out what its path carries by trying: once it has
// sent enough to be a download (mtuAfter), it sends a datagram of the
// first of mtuSizes that the client accepts, with nothing in it that would
// be missed (PING and PADDING). When that is acknowledged, the path carries
// the size, and the connection uses it from then on. When it is lost, the
// size is tried once more, then the next smaller one. A probe that is lost
// says nothing about congestion.
//
// A path may stop carrying what it carried (a route changes): the large
// datagrams then vanish, all of them, while smaller ones may still arrive.
// That is told from congestion, which may also take many datagrams at
// once, by two things: no large datagram sent after the lost ones arrives,
// and what is sent once the loss is known is lost as well. mtuBlackHole
// large datagrams lost like that, or two probe timeouts in a row, take the
// connection back to maxDatagram, for good on that path. A client that
// moves starts over at maxDatagram on its new path.

// mtuSizes are the datagram sizes tried, the largest first: what Ethernet
// carries over IPv6 (and over PPPoE with either IP), a WireGuard tunnel
// over it, and steps below for paths with more around their packets.
var mtuSizes = [...]int{MaxDatagramSize, 1392, 1350, 1300, 1252}

const (
	// mtuAfter is how many bytes of its streams a connection must have
	// sent on a path before it tries larger datagrams there: one that
	// answers small requests has nothing to gain.
	mtuAfter = 64 << 10
	// mtuTries is how often a size is tried before the next smaller one.
	mtuTries = 2
	// mtuBlackHole is how many datagrams larger than maxDatagram, lost
	// while none sent after them is acknowledged, say that the path no
	// longer carries them, when the last of them was sent after the first
	// was known to be lost. Loss that is congestion does not look like
	// this, however many datagrams it takes at once: large datagrams sent
	// after the lost ones arrive (their acknowledgement is usually what
	// tells of the loss), and so does what is sent again.
	mtuBlackHole = 8
)

// mtuState is what a connection knows of its path's datagram size.
type mtuState struct {
	mtu    int    // the size of the datagrams sent
	next   int    // which of mtuSizes is tried next
	tried  int    // how often it was lost
	flying bool   // a probe waits for its acknowledgement
	done   bool   // nothing more is tried on this path
	from   uint64 // sentData when the path became the connection's
	// lostLarge counts the datagrams larger than maxDatagram that were
	// given up as lost and were sent after every one of them that was
	// acknowledged: largeNext is one above the highest packet number of
	// those. lostFrom is the first packet number sent after the first of
	// the counted ones was given up.
	lostLarge int
	largeNext int64
	lostFrom  int64
}

// mtuReset: the connection has a (new) path, about which nothing is known.
func (c *Conn) mtuReset() {
	c.mtuState = mtuState{mtu: maxDatagram, from: c.sentData}
	c.cc.mds = maxDatagram
}

// mtuProbe returns the size of the datagram to try now, 0 for none.
func (c *Conn) mtuProbe() int {
	if c.done || c.flying || !c.handshakeDone || c.sentData-c.from < mtuAfter {
		return 0
	}
	// No size the client does not take (its max_udp_payload_size).
	for c.next < len(mtuSizes) && uint64(mtuSizes[c.next]) > c.peer.MaxUDPPayloadSize {
		c.next, c.tried = c.next+1, 0
	}
	if c.next >= len(mtuSizes) {
		c.done = true
		return 0
	}
	return mtuSizes[c.next]
}

// sendMTUProbe writes a datagram of size bytes into buf: one 1-RTT packet
// with a PING and padding. It waits for its acknowledgement like any other
// packet and counts in flight; what becomes of it is told to mtuArrived or
// mtuLost.
func (c *Conn) sendMTUProbe(now int64, buf []byte, size int) int {
	sp := &c.spaces[LevelApplication]
	c.maybeUpdateKeys()
	pn := sp.nextPN
	pnLen := pnLenFor(pn, sp.largestAcked)
	b, pnOff := AppendShortHeader(buf[:0], c.dcid, c.sendPhase, pn, pnLen)
	b = append(b, FramePing)
	for len(b)+Overhead < size {
		b = append(b, FramePadding)
	}
	sp.nextPN++
	b = sp.wk.Seal(b, pnOff, pnLen, pn)
	sp.push(sentPacket{pn: pn, at: now, mtu: true, size: uint16(len(b))})
	c.flying = true
	c.cc.onSent(int64(len(b)))
	c.cc.paced(int64(len(b)))
	c.setPTO(now)
	return len(b)
}

// mtuArrived: the probe, of size bytes, was acknowledged: the path
// carries the size. (There is one probe at a time, and none is left
// waiting when the path changes: Migrated gives up what was sent before
// it starts over.)
func (c *Conn) mtuArrived(size int) {
	c.flying = false
	c.mtu, c.done = size, true
	c.cc.mds = int64(size)
}

// mtuLost: the probe was given up as lost.
func (c *Conn) mtuLost() {
	c.flying = false
	if c.tried++; c.tried >= mtuTries {
		c.next, c.tried = c.next+1, 0
	}
}

// mtuTimeout: a probe timeout fired. The second in a row, with datagrams
// larger than every path carries, takes the connection back to that size.
func (c *Conn) mtuTimeout() {
	if c.ptoCount >= 2 {
		c.mtuFallBack()
	}
}

// mtuSettled: packet pn, which was not a probe, was acknowledged (lost
// false) or given up as lost; size is its datagram's. The order in which
// packets are settled is not the order in which they were sent: an
// acknowledgement settles what it acknowledges first and what it shows to
// be lost after. So a lost datagram counts only when it was sent after
// the last large one known to have arrived; and the path is given up only
// with one that was sent when the loss was known, which a burst of
// congestion does not reach: what is sent again after it arrives.
func (c *Conn) mtuSettled(pn int64, size int, lost bool) {
	switch {
	case size <= maxDatagram || c.mtu == maxDatagram:
	case !lost:
		if pn >= c.largeNext {
			c.largeNext, c.lostLarge = pn+1, 0
		}
	case pn >= c.largeNext:
		if c.lostLarge == 0 {
			c.lostFrom = c.spaces[LevelApplication].nextPN
		}
		if c.lostLarge++; c.lostLarge >= mtuBlackHole && pn >= c.lostFrom {
			c.mtuFallBack()
		}
	}
}

// mtuFallBack: the path does not carry (any more) what it was found to
// carry. The connection sends what every path carries, and tries nothing
// more on this one.
func (c *Conn) mtuFallBack() {
	if c.mtu > maxDatagram {
		c.mtu, c.done = maxDatagram, true
		c.cc.mds = maxDatagram
	}
}

// DatagramSize returns the size of the datagrams the connection sends now.
func (c *Conn) DatagramSize() int { return c.mtu }
