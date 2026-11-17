package quic

// A client's address can change while its connection lives: a NAT forgets
// the flow and maps it anew, and the client, which notices nothing, goes on
// sending. Its packets then come from an address the connection does not
// send to. They are served like any others (a packet proves itself by its
// keys, not by where it came from), but answers follow the client only once
// it has shown that it receives at the new address (RFC 9000, sections 8.2
// and 9.3): a PATH_CHALLENGE is sent there, and the PATH_RESPONSE with its
// data is the proof.
//
// A connection knows no addresses. What is here is what the owner of the
// sockets builds that on: RecvFrom for a datagram from another address,
// AppendProbe for the datagram that challenges it (and answers the client's
// own challenge on that path), PathResponse for the answers that arrive,
// and Migrated when the owner starts sending to the new address.

// PathInfo is what a datagram from another address held (RecvFrom).
type PathInfo struct {
	// Packets: it held packets of the connection, which opened with the
	// connection's keys and were not seen before. Only then is the address
	// worth a look.
	Packets bool
	// Newest: one of them has the highest packet number received so far
	// (packets that were overtaken say nothing about where the client is
	// now).
	Newest bool
	// NonProbing: one of them held more than the frames that probe a path
	// (RFC 9000, section 9.1): the client uses the path, it does not only
	// try it.
	NonProbing bool
	// Challenge is the data of a PATH_CHALLENGE in it, when HasChallenge:
	// to be answered on that path.
	Challenge    [8]byte
	HasChallenge bool
	// OtherCID: one of them named another connection ID of this side than
	// the client's packets by the connection's path do: the client is
	// there on purpose (PathCID).
	OtherCID bool
}

// probingFrame reports whether a frame of type t only probes a path: a
// packet with nothing else moves no connection.
func probingFrame(t uint64) bool {
	return t == FramePadding || t == FramePathChallenge || t == FramePathResponse || t == FrameNewConnectionID
}

// RecvFrom is Recv for a datagram that came from another address than the
// one the connection sends to. It is for a connection whose handshake is
// complete; the datagram of any other is dropped. A PATH_CHALLENGE in it is
// not answered by Send, which sends on the connection's path: the answer
// belongs on the one the challenge came by.
func (c *Conn) RecvFrom(now int64, dgram []byte) PathInfo {
	c.clock = now
	if c.state != stateEstablished {
		return PathInfo{}
	}
	c.offPath, c.pathInfo = true, PathInfo{}
	c.Recv(now, dgram)
	c.offPath = false
	return c.pathInfo
}

// PathResponse returns the data of a PATH_RESPONSE that arrived since it
// was last asked for: the client's answer to a challenge of AppendProbe,
// by whichever path it came (an answer on any path proves the one the
// challenge was sent on).
func (c *Conn) PathResponse() (data [8]byte, ok bool) {
	data, ok = c.pathAnswer, c.pathAnswered
	c.pathAnswered = false
	return data, ok
}

// AppendProbe writes into buf, which must hold 1200 bytes, a
// datagram for another address of the client than the one the connection
// sends to, and returns its length (0: the connection sends nothing). The
// datagram is one 1-RTT packet with a PATH_CHALLENGE (challenge not nil:
// its data, which must be unpredictable), the answer to a challenge of the
// client's that came from that address (response not nil), or both, padded
// to the size every path must carry. It names the client's connection ID
// that PathCID chose for that address as cid. Nothing waits for its
// acknowledgement: a challenge that goes unanswered is sent anew by
// whoever asked.
func (c *Conn) AppendProbe(buf []byte, challenge, response *[8]byte, cid int64) int {
	sp := &c.spaces[LevelApplication]
	if c.state != stateEstablished || sp.wk == nil || challenge == nil && response == nil {
		return 0
	}
	dcid, ok := c.pathCID(cid)
	if !ok {
		return 0
	}
	c.maybeUpdateKeys()
	pn := sp.nextPN
	pnLen := pnLenFor(pn, sp.largestAcked)
	b, pnOff := AppendShortHeader(buf[:0], dcid, c.sendPhase, pn, pnLen)
	if challenge != nil {
		b = AppendPath(b, FramePathChallenge, *challenge)
		c.challenged = true
	}
	if response != nil {
		b = AppendPath(b, FramePathResponse, *response)
	}
	for len(b)+Overhead < maxDatagram {
		b = append(b, FramePadding)
	}
	sp.nextPN++
	return len(sp.wk.Seal(b, pnOff, pnLen, pn))
}

// ProbeTimeout returns how long the answer to a packet may take as the
// connection sees its path now: its probe timeout, without backoff.
func (c *Conn) ProbeTimeout() int64 {
	return c.pto() + int64(c.peer.MaxAckDelay)
}

// Migrated tells the connection that its datagrams go to another address
// of the client from now on, and name the client's connection ID that
// PathCID chose for it as cid (the one that was in use is then done
// with). What was sent and is not acknowledged went to the address before,
// which the client has left: it is sent again now. The round-trip estimate
// and the congestion window were that path's and start over (RFC 9000,
// section 9.4).
func (c *Conn) Migrated(now int64, cid int64) {
	if c.state != stateEstablished {
		return
	}
	for i := range c.pathCIDs {
		if int64(c.pathCIDs[i].seq) == cid {
			old := c.dcidSeq
			c.useCID(&c.pathCIDs[i])
			c.pathCIDs = append(c.pathCIDs[:i], c.pathCIDs[i+1:]...)
			c.giveBack(old)
			break
		}
	}
	sp := &c.spaces[LevelApplication]
	sent := sp.sent
	sp.sent, sp.sentBuf, sp.lossAt = nil, nil, 0
	for i := range sent {
		c.packetLost(LevelApplication, &sent[i])
	}
	c.cc = congestion{}
	c.cc.init(maxDatagram)
	c.mtuReset() // the new path may carry less
	c.rttSampled, c.rttSmoothed, c.rttVar, c.rttMin, c.rttLatest = false, 0, 0, 0, 0
	c.ptoCount, c.probes, c.paceAt = 0, 0, 0
	c.setPTO(now)
}
