package quic

// Connection IDs after the handshake (RFC 9000, section 5.1).
//
// Each side gives the other connection IDs to send to. The handshake
// settles one for each direction; more follow in NEW_CONNECTION_ID frames,
// and RETIRE_CONNECTION_ID gives one back. A client needs spare ones of
// this side to move on purpose (a packet from its new address then names a
// connection ID it has not used before, so that nobody on the way can tell
// the old path's packets and the new one's are the same connection's), and
// this side answers in kind: what it sends to that address names a
// connection ID of the client's that it has not used before either
// (section 9.5).
//
// This side's connection IDs are chosen by the owner of the sockets, which
// finds a connection by them: it is asked for some once the handshake is
// complete (WantCIDs, AddCID) and told when the client gives one back
// (RetiredCID).

const (
	// maxLocalCIDs is how many connection IDs of this side a client holds
	// at a time, the handshake's included, when its own limit allows.
	maxLocalCIDs = 4
	// maxRetiring bounds the connection IDs of the client's that this side
	// has given up and whose RETIRE_CONNECTION_ID is not acknowledged yet.
	maxRetiring = 16
)

// localCID is a connection ID of this side that the client may send to.
type localCID struct {
	seq  uint64
	cid  [CIDLen]byte
	tok  [16]byte
	used bool
	send bool // its NEW_CONNECTION_ID is to be sent
}

// peerCID is a connection ID of the client's.
type peerCID struct {
	seq uint64
	n   uint8
	cid [MaxCIDLen]byte
}

func (p *peerCID) bytes() []byte { return p.cid[:p.n] }

// retiring is a RETIRE_CONNECTION_ID that was sent and is not acknowledged.
type retiring struct {
	seq uint64
	pn  int64
}

// peerLimit is how many connection IDs of the client's this side holds at
// a time: what its transport parameters said.
func (c *Conn) peerLimit() int {
	if n := c.cfg.Params.ActiveConnectionIDLimit; n != 0 {
		return int(min(n, 16))
	}
	return defaultActiveCIDLimit
}

// WantCIDs returns how many more connection IDs the client may be given
// now (AddCID): none before the handshake is complete.
func (c *Conn) WantCIDs() int {
	if c.state != stateEstablished {
		return 0
	}
	n := int(min(c.peer.ActiveConnectionIDLimit, maxLocalCIDs))
	for i := range c.local {
		if c.local[i].used {
			n--
		}
	}
	return max(n, 0)
}

// AddCID gives the client another connection ID of this side: cid
// (CIDLen bytes), with its stateless reset token (16 bytes). It reports
// whether there was room for it (WantCIDs).
func (c *Conn) AddCID(cid, token []byte) bool {
	if c.WantCIDs() == 0 {
		return false
	}
	for i := range c.local {
		l := &c.local[i]
		if l.used {
			continue
		}
		*l = localCID{seq: c.localNext, used: true, send: true}
		copy(l.cid[:], cid)
		copy(l.tok[:], token)
		c.localNext++
		c.localSend = true
		return true
	}
	return false
}

// CIDsChanged reports whether the client gave back a connection ID since
// RetiredCID was last asked to the end: there is one to take off the
// books, and room for a new one.
func (c *Conn) CIDsChanged() bool { return len(c.localGone) > 0 }

// RetiredCID returns a connection ID of this side that the client gave
// back: packets no longer come for it.
func (c *Conn) RetiredCID() (cid [CIDLen]byte, ok bool) {
	if len(c.localGone) == 0 {
		return cid, false
	}
	cid = c.localGone[len(c.localGone)-1]
	c.localGone = c.localGone[:len(c.localGone)-1]
	return cid, true
}

// onRetireConnectionID takes the client's RETIRE_CONNECTION_ID; on is the
// connection ID its packet came for. False: the connection was closed
// over it.
func (c *Conn) onRetireConnectionID(now int64, f *Frame, on []byte) bool {
	if f.Seq >= c.localNext {
		c.closeWith(now, ProtocolViolation, f.Type, "a connection ID that was never given is given back")
		return false
	}
	for i := range c.local {
		l := &c.local[i]
		if !l.used || l.seq != f.Seq {
			continue
		}
		if string(l.cid[:]) == string(on) {
			c.closeWith(now, ProtocolViolation, f.Type, "the connection ID of the packet itself is given back")
			return false
		}
		l.used, l.send = false, false
		c.localGone = append(c.localGone, l.cid)
		return true
	}
	return true // given back before
}

// onNewConnectionID takes the client's NEW_CONNECTION_ID. False: the
// connection was closed over it.
func (c *Conn) onNewConnectionID(now int64, f *Frame) bool {
	if len(c.dcid) == 0 {
		c.closeWith(now, ProtocolViolation, f.Type, "a connection ID from a client that uses none")
		return false
	}
	if c.givenBack(f.Seq) {
		return true // a frame sent twice: this side is done with that one
	}
	// One that is known already: the same again is a frame sent twice,
	// another under the same number is not allowed.
	known := func(p *peerCID) bool { return p.seq == f.Seq }
	same := func(cid []byte) bool { return string(cid) == string(f.CID) }
	switch {
	case f.Seq == c.dcidSeq:
		if !same(c.dcid) {
			c.closeWith(now, ProtocolViolation, f.Type, "two connection IDs with one sequence number")
			return false
		}
		return true
	}
	for _, list := range [...][]peerCID{c.spare, c.pathCIDs} {
		for i := range list {
			if known(&list[i]) {
				if !same(list[i].bytes()) {
					c.closeWith(now, ProtocolViolation, f.Type, "two connection IDs with one sequence number")
					return false
				}
				return true
			}
		}
	}
	if f.RetirePriorTo > c.retirePrior {
		// The client takes its older ones out of use: they are given back,
		// and the one in use is replaced when it is among them.
		c.retirePrior = f.RetirePriorTo
		keep := c.spare[:0]
		for i := range c.spare {
			if c.spare[i].seq < c.retirePrior {
				c.giveBack(c.spare[i].seq)
			} else {
				keep = append(keep, c.spare[i])
			}
		}
		c.spare = keep
		keep = c.pathCIDs[:0]
		for i := range c.pathCIDs {
			if c.pathCIDs[i].seq < c.retirePrior {
				c.giveBack(c.pathCIDs[i].seq)
			} else {
				keep = append(keep, c.pathCIDs[i])
			}
		}
		c.pathCIDs = keep
	}
	if f.Seq < c.retirePrior {
		// Out of use before it arrived (frames that overtook each other):
		// given back at once.
		c.giveBack(f.Seq)
	} else {
		var p peerCID
		p.seq, p.n = f.Seq, uint8(copy(p.cid[:], f.CID))
		c.spare = append(c.spare, p)
	}
	if c.dcidSeq < c.retirePrior && len(c.spare) > 0 {
		// The lowest of the spare ones takes over.
		best := 0
		for i := range c.spare {
			if c.spare[i].seq < c.spare[best].seq {
				best = i
			}
		}
		c.giveBack(c.dcidSeq)
		c.useCID(&c.spare[best])
		c.spare = append(c.spare[:best], c.spare[best+1:]...)
	}
	if 1+len(c.spare)+len(c.pathCIDs) > c.peerLimit() {
		c.closeWith(now, ConnectionIDLimitError, f.Type, "")
		return false
	}
	if len(c.retire)+len(c.retiring) > maxRetiring {
		c.closeWith(now, ConnectionIDLimitError, f.Type, "too many connection IDs given up at once")
		return false
	}
	return true
}

// useCID makes p the connection ID packets to the client name.
func (c *Conn) useCID(p *peerCID) {
	c.dcid = append(c.dcid[:0], p.bytes()...)
	c.dcidSeq = p.seq
}

// giveBack has the client told that its connection ID with the sequence
// number seq is done with (RETIRE_CONNECTION_ID), and remembers that it
// is: a NEW_CONNECTION_ID frame for it that arrives again must not bring
// it back. What is remembered is every number below goneBelow and the ones
// in goneExtra; connection IDs are taken into use lowest first, so the
// second list stays short.
func (c *Conn) giveBack(seq uint64) {
	if c.givenBack(seq) {
		return
	}
	c.retire = append(c.retire, seq)
	c.goneExtra = append(c.goneExtra, seq)
	for again := true; again; {
		again = false
		for i, s := range c.goneExtra {
			if s == c.goneBelow {
				c.goneExtra = append(c.goneExtra[:i], c.goneExtra[i+1:]...)
				c.goneBelow++
				again = true
				break
			}
		}
	}
}

// givenBack reports whether this side has given back the client's
// connection ID with the sequence number seq.
func (c *Conn) givenBack(seq uint64) bool {
	if seq < c.goneBelow {
		return true
	}
	for _, s := range c.goneExtra {
		if s == seq {
			return true
		}
	}
	return false
}

// appendCIDFrames appends, as far as room goes, the NEW_CONNECTION_ID and
// RETIRE_CONNECTION_ID frames that are to be sent, and notes them in sent,
// the record of the packet pn they go into.
func (c *Conn) appendCIDFrames(b []byte, room int, sent *sentPacket, pn int64) []byte {
	if c.localSend {
		c.localSend = false
		for i := range c.local {
			l := &c.local[i]
			if !l.used || !l.send {
				continue
			}
			if room-len(b) < 48 {
				c.localSend = true // the next packet takes it
				break
			}
			b = AppendNewConnectionID(b, l.seq, 0, l.cid[:], l.tok[:])
			l.send = false
			sent.cids |= 1 << i
		}
	}
	for len(c.retire) > 0 && room-len(b) > 16 {
		seq := c.retire[0]
		c.retire = c.retire[1:]
		b = AppendFrame1(b, FrameRetireConnectionID, seq)
		c.retiring = append(c.retiring, retiring{seq: seq, pn: pn})
		sent.ctl |= pktRetire
	}
	return b
}

// cidFramesAcked and cidFramesLost settle the connection ID frames of a
// packet that was acknowledged, or given up as lost: those are sent again.
func (c *Conn) cidFramesAcked(p *sentPacket) {
	if p.ctl&pktRetire == 0 {
		return
	}
	keep := c.retiring[:0]
	for _, r := range c.retiring {
		if r.pn != p.pn {
			keep = append(keep, r)
		}
	}
	c.retiring = keep
}

func (c *Conn) cidFramesLost(p *sentPacket) {
	for i := range c.local {
		if p.cids&(1<<i) != 0 && c.local[i].used {
			c.local[i].send, c.localSend = true, true
		}
	}
	if p.ctl&pktRetire == 0 {
		return
	}
	keep := c.retiring[:0]
	for _, r := range c.retiring {
		if r.pn != p.pn {
			keep = append(keep, r)
		} else {
			c.retire = append(c.retire, r.seq) // sent again
		}
	}
	c.retiring = keep
}

// PeerCIDs returns how many connection IDs of the client's are to spare
// and how many are chosen for other addresses of the client (PathCID),
// beside the one in use.
func (c *Conn) PeerCIDs() (spare, chosen int) { return len(c.spare), len(c.pathCIDs) }

// PathCID chooses the connection ID of the client's that a probe to
// another of its addresses names (AppendProbe). other says that the
// client's packets from there name a connection ID of this side which it
// did not use on the connection's path: it moved on purpose, and is
// answered with one of its own that was not used before. Otherwise its
// address changed under it, and the one in use stays in use. seq is -1 for
// the one in use; ok is false when the client has none to spare (or went
// through too many without ever moving), and that address cannot be
// answered.
func (c *Conn) PathCID(other bool) (seq int64, ok bool) {
	if !other || len(c.dcid) == 0 {
		return -1, true
	}
	if len(c.spare) == 0 || len(c.goneExtra) >= maxRetiring {
		return 0, false
	}
	best := 0
	for i := range c.spare {
		if c.spare[i].seq < c.spare[best].seq {
			best = i
		}
	}
	p := c.spare[best]
	c.spare = append(c.spare[:best], c.spare[best+1:]...)
	c.pathCIDs = append(c.pathCIDs, p)
	return int64(p.seq), true
}

// DropPathCID gives up a connection ID that PathCID chose: its address is
// no longer looked at. It was seen on the way, so it is not used again: the
// client is told that it is done with.
func (c *Conn) DropPathCID(seq int64) {
	for i := range c.pathCIDs {
		if int64(c.pathCIDs[i].seq) == seq {
			c.pathCIDs = append(c.pathCIDs[:i], c.pathCIDs[i+1:]...)
			c.giveBack(uint64(seq))
			return
		}
	}
}

// pathCID returns the client's connection ID that PathCID chose as seq:
// the one in use for -1, nil for one that is gone since (the client took
// it out of use).
func (c *Conn) pathCID(seq int64) ([]byte, bool) {
	if seq < 0 {
		return c.dcid, true
	}
	for i := range c.pathCIDs {
		if int64(c.pathCIDs[i].seq) == seq {
			return c.pathCIDs[i].bytes(), true
		}
	}
	return nil, false
}
