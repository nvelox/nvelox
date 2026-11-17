package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"time"
)

// Conn is the server's side of one QUIC connection: what it has received
// and sent, its keys and its timers. It reads no socket and no clock: its
// owner gives it the datagrams that arrive (Recv), asks it for the ones to
// send (Send), and calls OnTimer at the time Deadline names. Time is in
// nanoseconds on a clock that never goes back.
//
// A Conn is used from one goroutine at a time.
type Conn struct {
	// Data is the caller's: what it keeps with the connection. The
	// connection never looks at it.
	Data any

	cfg   *Config
	tls   *tls.QUICConn
	odcid []byte // the Destination Connection ID of the client's first Initial packet
	scid  []byte // this server's connection ID: what the client sends to
	dcid  []byte // the client's connection ID: what this server sends to

	state         connState
	spaces        [3]space
	peer          Params
	gotPeerParams bool

	// The handshake.
	handshakeDone bool // crypto/tls reported it complete
	sendDone      bool // HANDSHAKE_DONE is to be (re)sent
	addrValidated bool // the client proved it receives at its address
	recvBytes     int  // datagram bytes received before validation
	sentBytes     int  // and sent: at most three times recvBytes until then

	// Round-trip time (RFC 9002, section 5).
	rttSmoothed, rttVar, rttMin, rttLatest int64
	rttSampled                             bool

	// Timers: the probe timeout with its backoff, the idle timeout, and the
	// end of the closing or draining period.
	ptoAt       int64
	ptoCount    int
	probes      int // ack-eliciting packets owed for a probe timeout
	idleAt      int64
	idleTimeout int64
	closeAt     int64

	// Why the connection ended, and what the peer is told while closing.
	err        error
	closeFrame []byte // the CONNECTION_CLOSE frame, written once
	closeSend  bool   // send it (again): a packet arrived while closing

	frame Frame // scratch for parsing

	// Streams (stream.go). sendq: the ones with something to send, in
	// turn.
	streams map[uint64]*stream
	free    []*stream
	sendq   []*stream
	// clientBidi: the client's bidirectional streams that are not over.
	clientBidi int
	// Client-opened streams: how many were opened so far, how many the
	// client may open in all (extended as they finish), and whether that
	// is to be told (MAX_STREAMS).
	openedBidi, openedUni     uint64
	maxBidi, maxUni           uint64
	maxBidiDirty, maxUniDirty bool
	// Our unidirectional streams: how many were opened, how many the
	// client allows.
	nextUni, peerMaxUni uint64
	// The connection's flow control. Receiving: the limit given to the
	// peer, how far it has sent in all, what the application consumed.
	// Sending: the peer's limit, how far we have sent, and how much the
	// streams have taken to send (what was sent, and what waits in their
	// buffers to be sent for the first time).
	recvMaxData, recvData, consumedData uint64
	maxDataDirty                        bool
	sendMaxData, sentData, sendTaken    uint64
	// The connection's receive window as it is now, the round its growth
	// is judged by (when it began, and what was consumed by then), and how
	// much of its growth the process's count knows.
	rwin, rwinFrom uint64
	rwinAt         int64
	rwinCounted    int64
	// clock is the time of the last call that was told one (Recv,
	// RecvFrom, OnTimer, Send): what the application calls in between has
	// none of its own.
	clock int64
	// Key updates (RFC 9001, section 6). recvPhase and sendPhase are the
	// key phase bits of the 1-RTT keys in use in each direction (they
	// differ only between one side's update and the other's following
	// it); phaseFirst is the lowest packet number received in the current
	// phase, phaseSendFirst the first sent in it; nextRK the read keys of
	// the next phase, made ahead; prevRK those of the phase before, kept
	// until prevUntil for packets that were overtaken.
	recvPhase, sendPhase bool
	phaseFirst           int64
	phaseSendFirst       int64
	nextRK               *Keys
	prevRK               *Keys
	prevUntil            int64
	// A PATH_CHALLENGE to answer.
	pathResp     [8]byte
	pathRespSend bool
	// Another address of the client (path.go). offPath: the datagram being
	// read came from one, and pathInfo collects what it holds. challenged:
	// a PATH_CHALLENGE was sent; pathAnswer is the data of a PATH_RESPONSE
	// that arrived and was not asked for yet.
	offPath      bool
	challenged   bool
	pathAnswered bool
	pathAnswer   [8]byte
	pathInfo     PathInfo
	// Connection IDs (cid.go). This side's: the ones the client holds,
	// the next sequence number, whether a NEW_CONNECTION_ID is to be sent,
	// the ones the client gave back (for the owner of the sockets), and
	// the one on the newest packet that came by the connection's path.
	local     [maxLocalCIDs]localCID
	localNext uint64
	localSend bool
	localGone [][CIDLen]byte
	arrivedOn [CIDLen]byte
	// The client's: the sequence number of the one in use (dcid), the
	// spare ones, the ones chosen for other addresses of the client, the
	// highest Retire Prior To it sent, the ones to give back, the ones
	// whose RETIRE_CONNECTION_ID waits for its acknowledgement, and which
	// were given back in all (giveBack).
	dcidSeq     uint64
	spare       []peerCID
	pathCIDs    []peerCID
	retirePrior uint64
	retire      []uint64
	retiring    []retiring
	goneBelow   uint64
	goneExtra   []uint64
	// The send buffer (stream.go): what the streams hold together to
	// send, what of it the process's count knows, the streams that wait
	// for room to write (the one that waits longest first), and whether
	// room was made since they were last looked at.
	sendHeld    int
	sendCounted int64
	waiting     []*stream
	wakeDue     bool
	// When a delayed acknowledgement is due (0: none).
	ackAt int64

	// Congestion control (cubic.go), and when the pacer lets the next
	// datagram out (0: now).
	cc congestion
	// The size of the datagrams sent, and what is being found out about
	// the path's (mtu.go).
	mtuState
	paceAt int64
}

type connState uint8

const (
	stateHandshake connState = iota
	stateEstablished
	stateClosing  // we closed: answer packets with CONNECTION_CLOSE for a while
	stateDraining // the peer closed: send nothing, wait
	stateClosed
)

// Config is what the connections of one listener share.
type Config struct {
	// TLS is the server's TLS configuration (TLS 1.3; NextProtos is the
	// ALPN offered).
	TLS *tls.Config
	// Params are the transport parameters sent to clients; the connection
	// IDs are filled in per connection. Its stream and data limits are the
	// ones the connections enforce.
	Params Params
	// Handler is told what happens on the connections' streams. Without
	// one, clients may open no streams.
	Handler Handler
	// MaxSendBuffer is the most the streams of a connection hold together
	// to send (stream.go, "The send buffer"). 0: sendBufferMax.
	MaxSendBuffer int64
	// MaxStreamWindow and MaxConnWindow are how far the receive windows
	// may grow: the one of a stream its client opened in both directions,
	// and the one of all streams together. 0: that window stays as Params
	// give it. (stream.go, "The receive windows".)
	MaxStreamWindow, MaxConnWindow uint64
}

// Config returns the configuration the connection was accepted with.
func (c *Conn) Config() *Config { return c.cfg }

// CIDLen is the length of the connection IDs this server issues.
const CIDLen = 8

// maxDatagram is the size of datagram every QUIC path must carry (RFC 9000,
// section 14): what a connection sends until its path has shown that it
// carries more (mtu.go).
const maxDatagram = 1200

// MaxDatagramSize is the largest datagram a connection ever sends, on a
// path that carries it: what Ethernet carries of IPv6 and UDP. A caller of
// Send has room for it.
const MaxDatagramSize = 1452

// Timing constants of RFC 9002.
const (
	initialRTT       = 333 * int64(time.Millisecond)
	timerGranularity = int64(time.Millisecond)
	maxPTOBackoff    = 6 // the probe timeout doubles this many times at most
)

// ErrIdle is the error of a connection that ended because nothing arrived
// for its idle timeout.
var ErrIdle = errors.New("quic: idle timeout")

// PeerClosed is the error of a connection the peer closed: the code of its
// CONNECTION_CLOSE frame, and whether the application sent it.
type PeerClosed struct {
	Code   uint64
	App    bool
	Reason string
}

func (e *PeerClosed) Error() string {
	if e.App {
		return "quic: closed by the peer's application"
	}
	return "quic: closed by the peer: " + TransportError(e.Code).Error()
}

// space is one packet number space with the keys of its encryption level.
type space struct {
	rk, wk       *Keys // nil: not there yet, or discarded
	recv         recvSet
	ackNeeded    bool // an ack-eliciting packet arrived and is not acknowledged yet
	nextPN       int64
	largestAcked int64 // the largest of our packet numbers the peer acknowledged, -1: none

	crypto CryptoRecv
	// out is the CRYPTO stream to send at this level, whole; outSent how
	// much of it has been sent since the last retransmission started; acked
	// which parts the peer has acknowledged.
	out     []byte
	outSent uint64
	acked   byteRanges

	// sent is the ack-eliciting packets not yet acknowledged, by packet
	// number. Packets leave it at its front (acknowledgements come in
	// order, give or take) and join at its back: it is a window that moves
	// along sentBuf, which has room for it twice over (push), so that
	// neither end costs more than the packets it is about.
	sent    []sentPacket
	sentBuf []sentPacket
	// unacked counts the ack-eliciting packets received since the last
	// acknowledgement was sent; largestAt is when the packet with the
	// largest number arrived (for the ACK Delay field).
	unacked   int
	largestAt int64
	// lossAt is when the oldest packet that is not acknowledged, and was
	// sent before one that is, is given up as lost (0: none such).
	lossAt int64
}

// push adds a packet that waits for its acknowledgement.
func (sp *space) push(p sentPacket) {
	if len(sp.sent) == cap(sp.sent) {
		// No room behind the last one. When at least half of the buffer is
		// free in front of the first (packets that were acknowledged), the
		// window moves back to the buffer's start; else the buffer doubles.
		n := len(sp.sent)
		if 2*n > cap(sp.sentBuf) || n == cap(sp.sentBuf) {
			sp.sentBuf = make([]sentPacket, 0, max(2*cap(sp.sentBuf), 64))
		}
		sp.sent = sp.sentBuf[:copy(sp.sentBuf[:n], sp.sent)]
	}
	sp.sent = append(sp.sent, p)
}

// settle takes out of the first end packets of sent all but the first keep
// of them (the caller has moved those that stay to the front, in order):
// they move up against the packets behind them, which stay where they are.
func (sp *space) settle(keep, end int) {
	copy(sp.sent[end-keep:end], sp.sent[:keep])
	sp.sent = sp.sent[end-keep:]
	if len(sp.sent) == 0 && cap(sp.sentBuf) > sentKeep {
		// Nothing waits, and the buffer is one a large window left behind:
		// a connection that is idle does not keep it.
		sp.sent, sp.sentBuf = nil, nil
	}
}

// sentKeep is the largest buffer for the packets that wait for their
// acknowledgement, in packets, that a connection keeps while none does.
const sentKeep = 256

// sentPacket is what must be known about a packet until it is acknowledged
// or given up as lost.
type sentPacket struct {
	pn        int64
	at        int64
	cryptoOff uint64 // the CRYPTO bytes it carried
	cryptoLen uint64
	done      bool // it carried HANDSHAKE_DONE
	mtu       bool // it was sent to find out whether the path carries its size (mtu.go)
	// What it carried for streams, and which of the connection's limits
	// (pktMaxData ...).
	nrec uint8
	ctl  uint8
	cids uint8  // the connection IDs of this side whose NEW_CONNECTION_ID it carried, by their place in Conn.local
	size uint16 // its length, counted in flight
	recs [maxStreamRecs]streamRec
}

// Connection-level frames a packet carried that are sent again when it is
// lost (with the value of then).
const (
	pktMaxData = 1 << iota
	pktMaxStreamsBidi
	pktMaxStreamsUni
	pktRetire // RETIRE_CONNECTION_ID frames (Conn.retiring names them)
)

// byteRanges is a set of byte ranges [start, end) of a stream, ascending
// and not touching.
type byteRanges [][2]uint64

func (r *byteRanges) add(start, end uint64) {
	if start >= end {
		return
	}
	out := (*r)[:0:0]
	placed := false
	for _, x := range *r {
		switch {
		case x[1] < start:
			out = append(out, x)
		case x[0] > end:
			if !placed {
				out = append(out, [2]uint64{start, end})
				placed = true
			}
			out = append(out, x)
		default:
			start, end = min(start, x[0]), max(end, x[1])
		}
	}
	if !placed {
		out = append(out, [2]uint64{start, end})
	}
	*r = out
}

// from returns the first offset at or after off that is not in the set.
func (r byteRanges) from(off uint64) uint64 {
	for _, x := range r {
		if off >= x[0] && off < x[1] {
			return x[1]
		}
	}
	return off
}

// Accept returns the connection for a client whose first Initial packet had
// the Destination Connection ID odcid and the Source Connection ID
// clientCID; cid is the connection ID chosen for it (CIDLen bytes) and
// resetToken that connection ID's stateless reset token.
func Accept(cfg *Config, now int64, odcid, clientCID, cid, resetToken []byte) (*Conn, error) {
	return accept(cfg, now, odcid, nil, clientCID, cid, resetToken)
}

// AcceptRetried is Accept for a client that came back with the token of a
// Retry packet, which proves its address. retryCID is the Source
// Connection ID that Retry packet carried: the client's Initial packets
// are sent to it since, and it stays the connection's ID. odcid is the
// Destination Connection ID of the client's very first Initial packet,
// which the token remembered.
func AcceptRetried(cfg *Config, now int64, odcid, retryCID, clientCID, resetToken []byte) (*Conn, error) {
	return accept(cfg, now, odcid, retryCID, clientCID, retryCID, resetToken)
}

func accept(cfg *Config, now int64, odcid, retryCID, clientCID, cid, resetToken []byte) (*Conn, error) {
	c := &Conn{cfg: cfg}
	c.odcid = append([]byte(nil), odcid...)
	c.dcid = append([]byte(nil), clientCID...)
	c.scid = append([]byte(nil), cid...)
	c.local[0].used, c.localNext = true, 1
	copy(c.local[0].cid[:], cid)
	copy(c.local[0].tok[:], resetToken)
	c.arrivedOn = c.local[0].cid
	for i := range c.spaces {
		c.spaces[i].largestAcked = -1
	}
	// The Initial keys come from the connection ID the client's Initial
	// packets are sent to: after a Retry that is the Retry's.
	keyCID := odcid
	p := cfg.Params
	if retryCID != nil {
		keyCID = retryCID
		p.RetrySCID = c.scid
		c.addrValidated = true
	}
	c.spaces[LevelInitial].rk, c.spaces[LevelInitial].wk = InitialKeys(keyCID)
	p.OriginalDCID, p.InitialSCID, p.StatelessResetToken = c.odcid, c.scid, resetToken
	c.idleTimeout = int64(p.MaxIdleTimeout)
	c.cc.init(maxDatagram)
	c.mtuReset()
	c.initStreams()
	c.tls = tls.QUICServer(&tls.QUICConfig{TLSConfig: cfg.TLS})
	c.tls.SetTransportParameters(p.Append(nil))
	if err := c.tls.Start(context.Background()); err != nil {
		return nil, err
	}
	c.touch(now)
	return c, nil
}

// AddressValidated reports whether the client has proven that it receives
// at its address: by a Handshake packet, or by the token of a Retry.
func (c *Conn) AddressValidated() bool { return c.addrValidated }

// Established reports whether the handshake is complete and the
// connection open.
func (c *Conn) Established() bool { return c.state == stateEstablished }

// Closed reports whether the connection is over: nothing more is to be
// received, sent or timed for it.
func (c *Conn) Closed() bool { return c.state == stateClosed }

// Err returns why the connection ended or is ending, nil while it is open.
func (c *Conn) Err() error { return c.err }

// ConnectionState returns the TLS state of the connection.
func (c *Conn) ConnectionState() tls.ConnectionState { return c.tls.ConnectionState() }

// touch restarts the idle timeout.
func (c *Conn) touch(now int64) {
	if c.idleTimeout > 0 {
		c.idleAt = now + c.idleTimeout
	}
}

// ---- receiving ----

// RecvHandshake is Recv for a connection whose handshake runs on another
// goroutine than the one that serves its streams. It takes the packets of
// dgram until the handshake is complete and returns what follows the
// packet that completed it: that is for Recv, on the streams' goroutine.
// The handler is told nothing during it, since a client's streams begin
// after the handshake.
func (c *Conn) RecvHandshake(now int64, dgram []byte) (rest []byte) {
	if c.state == stateClosed {
		return nil
	}
	if !c.addrValidated {
		c.recvBytes += len(dgram)
	}
	for len(dgram) > 0 {
		if c.state == stateEstablished {
			return dgram
		}
		h, err := ParseHeader(dgram, CIDLen)
		if err != nil {
			return nil
		}
		c.recvPacket(now, &h, dgram[:h.End])
		if c.state == stateClosed {
			return nil
		}
		dgram = dgram[h.End:]
	}
	return nil
}

// Recv takes a datagram that arrived for the connection: every packet in
// it.
func (c *Conn) Recv(now int64, dgram []byte) {
	c.clock = now
	if c.state == stateClosed {
		return
	}
	if !c.addrValidated {
		c.recvBytes += len(dgram)
	}
	for len(dgram) > 0 {
		h, err := ParseHeader(dgram, CIDLen)
		if err != nil {
			return // the rest of the datagram cannot be told apart
		}
		c.recvPacket(now, &h, dgram[:h.End])
		if c.state == stateClosed {
			return
		}
		dgram = dgram[h.End:]
	}
	if c.wakeDue {
		c.wakeWriters()
	}
}

func (c *Conn) recvPacket(now int64, h *Header, pkt []byte) {
	var lvl Level
	switch h.Type {
	case PacketInitial:
		lvl = LevelInitial
	case PacketHandshake:
		lvl = LevelHandshake
	case PacketShort:
		lvl = LevelApplication
	default:
		return // 0-RTT is not accepted; a server gets no Retry
	}
	sp := &c.spaces[lvl]
	if sp.rk == nil {
		return // keys not there yet (the client sends again) or discarded
	}
	prevLargest := sp.recv.largest()
	var payload []byte
	var pn int64
	var err error
	if lvl == LevelApplication {
		payload, pn, err = c.openShort(now, pkt, h.PNOff, prevLargest)
	} else {
		payload, pn, _, err = sp.rk.Open(pkt, h.PNOff, prevLargest)
	}
	if err != nil {
		return
	}
	// The reserved bits, now that the header is in the clear.
	if pkt[0]&0x80 != 0 && pkt[0]&0x0c != 0 || pkt[0]&0x80 == 0 && pkt[0]&0x18 != 0 {
		c.closeWith(now, ProtocolViolation, 0, "reserved header bits")
		return
	}
	if c.state == stateDraining {
		return
	}
	if c.state == stateClosing {
		c.closeSend = true // tell the peer again
		return
	}
	if sp.recv.add(uint64(pn)) {
		return // a duplicate
	}
	if c.offPath {
		// A packet of the connection's, from another address (path.go).
		c.pathInfo.Packets = true
		c.pathInfo.Newest = c.pathInfo.Newest || pn > prevLargest
		c.pathInfo.OtherCID = c.pathInfo.OtherCID || string(h.DCID) != string(c.arrivedOn[:])
	}
	if pn > prevLargest {
		sp.largestAt = now
		if lvl == LevelApplication && !c.offPath {
			copy(c.arrivedOn[:], h.DCID)
		}
	}
	if lvl == LevelHandshake && c.spaces[LevelInitial].rk != nil {
		// A Handshake packet proves the client receives at its address
		// (when a Retry's token has not proven it already), and the Initial
		// keys are done with (RFC 9001, section 4.9.1).
		c.addrValidated = true
		c.dropSpace(LevelInitial)
	}
	c.touch(now)
	if len(payload) == 0 {
		c.closeWith(now, ProtocolViolation, 0, "packet without frames")
		return
	}
	f := &c.frame
	eliciting := false
	for len(payload) > 0 {
		n, err := ParseFrame(payload, f)
		if err != nil {
			code := FrameEncodingError
			if te, ok := err.(TransportError); ok {
				code = te
			}
			c.closeWith(now, code, 0, "")
			return
		}
		payload = payload[n:]
		if !f.AllowedAt(lvl) {
			c.closeWith(now, ProtocolViolation, f.Type, "frame not allowed in this packet")
			return
		}
		eliciting = eliciting || f.AckEliciting()
		if c.offPath && !probingFrame(f.Type) {
			c.pathInfo.NonProbing = true
		}
		switch f.Type {
		case FramePadding, FramePing:
		case FrameAck, FrameAck + 1:
			if !c.onAck(now, lvl, f) {
				return
			}
		case FrameCrypto:
			if err := sp.crypto.Push(f.Offset, f.Data, func(d []byte) error {
				return c.tls.HandleData(tlsLevel(lvl), d)
			}); err != nil {
				c.tlsFailed(now, err)
				return
			}
			if !c.tlsEvents(now) {
				return
			}
		case FrameConnectionClose, FrameConnectionClose + 1:
			c.err = &PeerClosed{Code: f.ErrorCode, App: f.Type == FrameConnectionClose+1, Reason: string(f.Reason)}
			c.state = stateDraining
			c.closeAt = now + 3*c.pto()
			return
		case FrameStream, FrameStream + 1, FrameStream + 2, FrameStream + 3, FrameStream + 4, FrameStream + 5, FrameStream + 6, FrameStream + 7:
			if !c.onStream(now, f) {
				return
			}
		case FrameResetStream:
			if !c.onResetStream(now, f) {
				return
			}
		case FrameStopSending:
			if !c.onStopSending(now, f) {
				return
			}
		case FrameMaxStreamData:
			if !c.onMaxStreamData(now, f) {
				return
			}
		case FrameMaxData:
			if f.Max > c.sendMaxData {
				c.sendMaxData = f.Max
				for _, st := range c.streams {
					if st.pending() {
						c.queue(st)
					}
				}
				if len(c.waiting) > 0 {
					c.wakeDue = true
				}
			}
		case FrameMaxStreams + 1:
			c.peerMaxUni = max(c.peerMaxUni, f.Max)
		case FrameMaxStreams, FrameDataBlocked, FrameStreamsBlocked, FrameStreamsBlocked + 1:
			// The server opens no bidirectional streams; that the client
			// is held back by a limit changes nothing here (limits follow
			// what the application consumes).
		case FrameStreamDataBlocked:
			if _, ok := c.recvSide(now, f.StreamID, f.Type); !ok {
				return
			}
		case FramePathChallenge:
			if c.offPath {
				// Answered on the path it came by (AppendProbe).
				c.pathInfo.Challenge, c.pathInfo.HasChallenge = f.PathData, true
			} else {
				c.pathResp, c.pathRespSend = f.PathData, true
			}
		case FramePathResponse:
			if !c.challenged {
				c.closeWith(now, ProtocolViolation, f.Type, "PATH_RESPONSE to a challenge never sent")
				return
			}
			c.pathAnswer, c.pathAnswered = f.PathData, true
		case FrameNewConnectionID:
			if !c.onNewConnectionID(now, f) {
				return
			}
		case FrameRetireConnectionID:
			if !c.onRetireConnectionID(now, f, h.DCID) {
				return
			}
		default:
			c.closeWith(now, ProtocolViolation, f.Type, "")
			return
		}
	}
	if eliciting {
		// Handshake packets are acknowledged at once. Of 1-RTT packets,
		// every second one is, and one that came out of order; a single one
		// waits for max_ack_delay, in case a packet of ours can carry the
		// acknowledgement (RFC 9000, section 13.2).
		sp.unacked++
		switch {
		case lvl != LevelApplication || sp.unacked >= 2 || pn != prevLargest+1:
			sp.ackNeeded = true
		case c.ackAt == 0:
			c.ackAt = now + int64(c.cfg.Params.MaxAckDelay)
		}
	}
}

// openShort opens a 1-RTT packet with the keys of its key phase: the
// current ones, the next ones when the client has updated its keys (which
// this side then does too, for both directions), or the ones before for a
// packet that was overtaken by the update.
func (c *Conn) openShort(now int64, pkt []byte, pnOff int, largest int64) ([]byte, int64, error) {
	sp := &c.spaces[LevelApplication]
	pnLen, truncated, err := sp.rk.Unmask(pkt, pnOff)
	if err != nil {
		return nil, 0, err
	}
	pn := DecodePacketNumber(largest, truncated, uint(8*pnLen))
	if phase := pkt[0]&0x04 != 0; phase == c.recvPhase {
		payload, err := sp.rk.OpenBody(pkt, pnOff, pnLen, pn)
		if err == nil && pn < c.phaseFirst {
			c.phaseFirst = pn
		}
		return payload, pn, err
	}
	if pn < c.phaseFirst {
		// Sent before the update, arrived after it.
		if c.prevRK == nil || now >= c.prevUntil {
			c.prevRK = nil
			return nil, 0, ErrDecrypt
		}
		payload, err := c.prevRK.OpenBody(pkt, pnOff, pnLen, pn)
		return payload, pn, err
	}
	// The next phase. The keys are made ahead, so that a packet which
	// merely claims an update costs no more than any other that fails.
	if c.nextRK == nil {
		if c.nextRK, err = sp.rk.Next(); err != nil {
			return nil, 0, ErrDecrypt
		}
	}
	payload, err := c.nextRK.OpenBody(pkt, pnOff, pnLen, pn)
	if err != nil {
		return nil, 0, err
	}
	// It opened: the client is in the next phase. Its old keys stay for a
	// while for what is still on its way.
	c.prevRK, c.prevUntil = sp.rk, now+3*c.pto()
	sp.rk = c.nextRK
	c.nextRK, _ = sp.rk.Next()
	c.recvPhase, c.phaseFirst = !c.recvPhase, pn
	if c.sendPhase == c.recvPhase {
		return payload, pn, nil // it followed an update of ours
	}
	// The client started this update. It may do so only after it has
	// acknowledged a packet of the phase it leaves (RFC 9001, section
	// 6.2): one update after another without that could go on for ever.
	if sp.largestAcked < c.phaseSendFirst {
		c.closeWith(now, KeyUpdateError, 0, "key update before the last one was acknowledged")
		return nil, 0, ErrDecrypt
	}
	// Ours follow before anything else is sent, the acknowledgement of
	// this packet included.
	if !c.updateSendKeys() {
		return nil, 0, ErrDecrypt
	}
	return payload, pn, nil
}

// keyUpdateInterval is how many packets are sent with one generation of
// keys before this side starts a key update. Every suite's limit is far
// above it (2^23 packets for AES-GCM: RFC 9001, section 6.6). A variable
// for the tests only.
var keyUpdateInterval int64 = 1 << 20

// updateSendKeys moves the packets sent from here on to the next key
// phase.
func (c *Conn) updateSendKeys() bool {
	sp := &c.spaces[LevelApplication]
	wk, err := sp.wk.Next()
	if err != nil {
		return false
	}
	sp.wk = wk
	c.sendPhase = !c.sendPhase
	c.phaseSendFirst = sp.nextPN
	return true
}

// maybeUpdateKeys starts a key update when the current keys have protected
// keyUpdateInterval packets: once the handshake is confirmed, no update is
// under way, and the client has acknowledged a packet of this phase.
func (c *Conn) maybeUpdateKeys() {
	sp := &c.spaces[LevelApplication]
	if sp.nextPN-c.phaseSendFirst >= keyUpdateInterval && c.handshakeDone && c.sendPhase == c.recvPhase && sp.largestAcked >= c.phaseSendFirst {
		c.updateSendKeys()
	}
}

func tlsLevel(l Level) tls.QUICEncryptionLevel {
	switch l {
	case LevelInitial:
		return tls.QUICEncryptionLevelInitial
	case LevelHandshake:
		return tls.QUICEncryptionLevelHandshake
	}
	return tls.QUICEncryptionLevelApplication
}

func levelOf(l tls.QUICEncryptionLevel) (Level, bool) {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return LevelInitial, true
	case tls.QUICEncryptionLevelHandshake:
		return LevelHandshake, true
	case tls.QUICEncryptionLevelApplication:
		return LevelApplication, true
	}
	return 0, false // early data: not used
}

// tlsEvents takes what crypto/tls has to say after it was given data. It
// reports false when the connection was closed over it.
func (c *Conn) tlsEvents(now int64) bool {
	for {
		ev := c.tls.NextEvent()
		switch ev.Kind {
		case tls.QUICNoEvent:
			return true
		case tls.QUICTransportParameters:
			if err := ParseClientParams(ev.Data, &c.peer); err != nil {
				c.closeWith(now, TransportParameterError, 0, "")
				return false
			}
			// The client's parameters must name the connection ID its
			// packets come from (RFC 9000, section 7.3).
			if string(c.peer.InitialSCID) != string(c.dcid) {
				c.closeWith(now, TransportParameterError, 0, "initial_source_connection_id")
				return false
			}
			c.peer.InitialSCID = c.dcid // not the handshake's buffer
			c.gotPeerParams = true
			c.sendMaxData, c.peerMaxUni = c.peer.InitialMaxData, c.peer.InitialMaxStreamsUni
			if t := int64(c.peer.MaxIdleTimeout); t > 0 && (c.idleTimeout == 0 || t < c.idleTimeout) {
				c.idleTimeout = t
				c.touch(now)
			}
		case tls.QUICSetReadSecret, tls.QUICSetWriteSecret:
			lvl, ok := levelOf(ev.Level)
			if !ok {
				continue
			}
			k, err := NewKeys(ev.Suite, ev.Data)
			if err != nil {
				c.closeWith(now, InternalError, 0, "")
				return false
			}
			if ev.Kind == tls.QUICSetReadSecret {
				c.spaces[lvl].rk = k
			} else {
				c.spaces[lvl].wk = k
			}
		case tls.QUICWriteData:
			if lvl, ok := levelOf(ev.Level); ok {
				sp := &c.spaces[lvl]
				sp.out = append(sp.out, ev.Data...)
			}
		case tls.QUICHandshakeDone:
			// The handshake is confirmed for a server when it completes:
			// the client is told (HANDSHAKE_DONE) and the Handshake keys
			// are done with (RFC 9001, sections 4.1.2 and 4.9.2).
			c.handshakeDone = true
			c.sendDone = true
			c.state = stateEstablished
			c.dropSpace(LevelHandshake)
			// The client is given a session ticket: its next connection can
			// resume the session, a handshake without the certificate and
			// its signature. The ticket offers no early data: a request
			// sent as 0-RTT can be replayed, and none is read here. It
			// leaves like the rest of the handshake, as CRYPTO data, in
			// 1-RTT packets. An error means there is no ticket (tickets
			// turned off, or no key to make one with), and a connection
			// does without.
			_ = c.tls.SendSessionTicket(tls.QUICSessionTicketOptions{})
		case tls.QUICErrorEvent:
			c.tlsFailed(now, ev.Err)
			return false
		}
	}
}

// tlsFailed closes the connection for an error of the handshake: a TLS
// alert goes out as a CRYPTO_ERROR, anything else as it is.
func (c *Conn) tlsFailed(now int64, err error) {
	var te TransportError
	var alert tls.AlertError
	switch {
	case errors.As(err, &te):
		c.closeWith(now, te, FrameCrypto, "")
	case errors.As(err, &alert):
		c.closeWith(now, CryptoError+TransportError(alert), FrameCrypto, "")
	default:
		c.closeWith(now, CryptoError+80, FrameCrypto, "") // internal_error
	}
	if c.err == nil || errors.Is(c.err, CryptoError+80) {
		c.err = err
	}
}

// dropSpace discards the keys and the state of an encryption level that is
// done with.
func (c *Conn) dropSpace(l Level) {
	sp := &c.spaces[l]
	sp.rk, sp.wk = nil, nil
	for i := range sp.sent {
		c.cc.forget(int64(sp.sent[i].size)) // no longer waited for
	}
	sp.sent, sp.sentBuf, sp.out, sp.ackNeeded, sp.lossAt = nil, nil, nil, false, 0
	sp.crypto = CryptoRecv{}
	c.ptoCount = 0
}

// ---- acknowledgements, loss and the probe timeout ----

// Loss detection constants of RFC 9002, section 6.1.
const (
	packetThreshold = 3 // a packet is lost when one sent this many later is acknowledged
	maxAckRanges    = 64
)

// onAck takes an ACK frame for our packets at level lvl. False: the
// connection was closed over it.
func (c *Conn) onAck(now int64, lvl Level, f *Frame) bool {
	sp := &c.spaces[lvl]
	if int64(f.Largest) >= sp.nextPN {
		c.closeWith(now, ProtocolViolation, f.Type, "acknowledgement of a packet not sent")
		return false
	}
	// The frame's ranges, highest first; the packets waiting are in the
	// order they were sent, so one pass over both settles the frame.
	var rs [maxAckRanges][2]uint64
	n := 0
	f.AckRanges(func(lo, hi uint64) bool {
		rs[n] = [2]uint64{lo, hi}
		n++
		return n < len(rs)
	})
	// The frame can name only packets up to its largest, and those are at
	// the front of the ones that wait. What was sent after it, in a download
	// nearly all of them, is neither looked at nor moved: an
	// acknowledgement costs what it acknowledges, not what is in flight.
	end := 0
	for end < len(sp.sent) && sp.sent[end].pn <= int64(f.Largest) {
		end++
	}
	newly := false
	var largestAt int64 = -1
	j := n - 1
	kept := 0
	c.cc.acking()
	for i := 0; i < end; i++ {
		p := &sp.sent[i]
		for j >= 0 && rs[j][1] < uint64(p.pn) {
			j--
		}
		if j < 0 || rs[j][0] > uint64(p.pn) {
			if kept != i {
				sp.sent[kept] = *p
			}
			kept++
			continue
		}
		newly = true
		if uint64(p.pn) == f.Largest {
			largestAt = p.at
		}
		c.cc.onAck(int64(p.size), p.at, now, c.rttSmoothed)
		c.packetAcked(lvl, p)
		if c.state >= stateClosing {
			return false // a handler closed the connection
		}
	}
	sp.settle(kept, end)
	if int64(f.Largest) > sp.largestAcked {
		sp.largestAcked = int64(f.Largest)
	}
	if !newly {
		return true
	}
	if largestAt >= 0 {
		c.rttSample(now-largestAt, lvl, f.Delay)
	}
	c.detectLoss(now, lvl)
	// Progress: the probe timeout starts over (while the client's address
	// is not validated it keeps its backoff: RFC 9002, section 6.2.1).
	if c.addrValidated {
		c.ptoCount = 0
	}
	c.setPTO(now)
	return true
}

// packetAcked settles what an acknowledged packet carried.
func (c *Conn) packetAcked(lvl Level, p *sentPacket) {
	sp := &c.spaces[lvl]
	sp.acked.add(p.cryptoOff, p.cryptoOff+p.cryptoLen)
	if p.done {
		c.sendDone = false
	}
	if p.mtu {
		c.mtuArrived(int(p.size))
	} else {
		c.mtuSettled(p.pn, int(p.size), false)
	}
	if p.ctl&pktRetire != 0 {
		c.cidFramesAcked(p)
	}
	for i := 0; i < int(p.nrec); i++ {
		c.ackStream(&p.recs[i])
	}
}

// packetLost queues again what a packet given up as lost carried: never
// the packet, always what it was for, as it stands now.
func (c *Conn) packetLost(lvl Level, p *sentPacket) {
	sp := &c.spaces[lvl]
	if p.mtu {
		c.mtuLost()
	} else {
		c.mtuSettled(p.pn, int(p.size), true)
	}
	if p.cryptoLen > 0 {
		sp.outSent = min(sp.outSent, p.cryptoOff)
	}
	// HANDSHAKE_DONE goes out again by itself: sendDone is still set and
	// no packet with it is waiting any more.
	if p.ctl&pktMaxData != 0 {
		c.maxDataDirty = true
	}
	if p.ctl&pktMaxStreamsBidi != 0 {
		c.maxBidiDirty = true
	}
	if p.ctl&pktMaxStreamsUni != 0 {
		c.maxUniDirty = true
	}
	if p.cids != 0 || p.ctl&pktRetire != 0 {
		c.cidFramesLost(p)
	}
	for i := 0; i < int(p.nrec); i++ {
		c.lostStream(&p.recs[i])
	}
}

// lossDelay is how long after it was sent a packet is given up when a
// later one is acknowledged (RFC 9002, section 6.1.2).
func (c *Conn) lossDelay() int64 {
	if !c.rttSampled {
		return 9 * initialRTT / 8
	}
	return max(9*max(c.rttSmoothed, c.rttLatest)/8, timerGranularity)
}

// detectLoss gives up the packets of a space that were sent before an
// acknowledged one and are either three packets behind it or older than
// the loss delay, and notes when the next one will be.
func (c *Conn) detectLoss(now int64, lvl Level) {
	sp := &c.spaces[lvl]
	sp.lossAt = 0
	if sp.largestAcked < 0 {
		return
	}
	delay := c.lossDelay()
	// Only packets sent before the largest acknowledged one can be given
	// up, and they are at the front of the ones that wait.
	end := 0
	for end < len(sp.sent) && sp.sent[end].pn < sp.largestAcked {
		end++
	}
	kept := 0
	for i := 0; i < end; i++ {
		p := &sp.sent[i]
		if sp.largestAcked-p.pn >= packetThreshold || p.at <= now-delay {
			if p.mtu {
				// It was too large for the path, which says nothing about
				// how much the path carries (RFC 9000, section 14.4).
				c.cc.forget(int64(p.size))
			} else {
				c.cc.onLost(int64(p.size), p.at, now)
			}
			c.packetLost(lvl, p)
			continue
		}
		if t := p.at + delay; sp.lossAt == 0 || t < sp.lossAt {
			sp.lossAt = t
		}
		if kept != i {
			sp.sent[kept] = *p
		}
		kept++
	}
	sp.settle(kept, end)
}

// rttSample updates the round-trip estimate with a sample (RFC 9002,
// section 5.3).
func (c *Conn) rttSample(latest int64, lvl Level, ackDelay uint64) {
	if latest <= 0 {
		latest = 1
	}
	c.rttLatest = latest
	if !c.rttSampled {
		c.rttSampled = true
		c.rttMin, c.rttSmoothed, c.rttVar = latest, latest, latest/2
		return
	}
	c.rttMin = min(c.rttMin, latest)
	adj := latest
	if lvl == LevelApplication {
		d := int64(ackDelay) << c.peer.AckDelayExponent * int64(time.Microsecond)
		if c.handshakeDone {
			d = min(d, int64(c.peer.MaxAckDelay))
		}
		if latest-d >= c.rttMin {
			adj = latest - d
		}
	}
	dev := c.rttSmoothed - adj
	if dev < 0 {
		dev = -dev
	}
	c.rttVar = (3*c.rttVar + dev) / 4
	c.rttSmoothed = (7*c.rttSmoothed + adj) / 8
}

// pto is the probe timeout without its backoff.
func (c *Conn) pto() int64 {
	if !c.rttSampled {
		return initialRTT + max(4*(initialRTT/2), timerGranularity)
	}
	return c.rttSmoothed + max(4*c.rttVar, timerGranularity)
}

// setPTO arms the probe timeout for the packets that wait for an
// acknowledgement, or disarms it when none does.
func (c *Conn) setPTO(now int64) {
	// Per space, the timeout runs from its last packet that waits for an
	// acknowledgement; the earliest of them counts (RFC 9002, appendix
	// A.8).
	var earliest int64 = -1
	for i := range c.spaces {
		if s := c.spaces[i].sent; len(s) > 0 {
			if at := s[len(s)-1].at; earliest < 0 || at < earliest {
				earliest = at
			}
		}
	}
	if earliest < 0 {
		c.ptoAt = 0
		return
	}
	d := c.pto()
	if c.handshakeDone {
		d += int64(c.peer.MaxAckDelay)
	}
	c.ptoAt = earliest + d<<min(c.ptoCount, maxPTOBackoff)
}

// Deadline returns when OnTimer is to be called, 0 for never.
func (c *Conn) Deadline() int64 {
	if c.state == stateClosed {
		return 0
	}
	if c.state == stateClosing || c.state == stateDraining {
		return c.closeAt
	}
	if c.wakeDue {
		// At once: the application made room (it reset a stream), and
		// streams that wait to write are told from OnTimer, not from
		// within its call.
		return 1
	}
	d := c.idleAt
	for _, t := range [...]int64{c.ptoAt, c.ackAt, c.paceAt, c.spaces[0].lossAt, c.spaces[1].lossAt, c.spaces[2].lossAt} {
		if t != 0 && (d == 0 || t < d) {
			d = t
		}
	}
	return d
}

// OnTimer is called at, or after, the time Deadline named.
func (c *Conn) OnTimer(now int64) {
	c.clock = now
	switch c.state {
	case stateClosed:
		return
	case stateClosing, stateDraining:
		if now >= c.closeAt {
			c.end()
		}
		return
	}
	if c.idleAt != 0 && now >= c.idleAt {
		// Idle: the connection ends without a word (RFC 9000, section 10.1).
		c.err = ErrIdle
		c.end()
		return
	}
	if c.wakeDue {
		c.wakeWriters()
		if c.state != stateEstablished {
			return // a handler closed the connection
		}
	}
	if c.ackAt != 0 && now >= c.ackAt {
		c.ackAt = 0
		c.spaces[LevelApplication].ackNeeded = true
	}
	if c.paceAt != 0 && now >= c.paceAt {
		c.paceAt = 0 // Send asks the pacer again
	}
	for lvl := LevelInitial; lvl <= LevelApplication; lvl++ {
		if t := c.spaces[lvl].lossAt; t != 0 && now >= t {
			c.detectLoss(now, lvl)
			if c.state >= stateClosing {
				return
			}
		}
	}
	if c.ptoAt != 0 && now >= c.ptoAt {
		// A probe timeout: up to two packets go out that the peer must
		// acknowledge, carrying what waits longest (the handshake's data
		// from its first unacknowledged byte, the oldest 1-RTT packet's
		// content), and the timeout doubles.
		c.ptoCount++
		c.probes = 2
		c.mtuTimeout()
		for lvl := LevelInitial; lvl <= LevelApplication; lvl++ {
			sp := &c.spaces[lvl]
			if len(sp.sent) == 0 {
				continue
			}
			if lvl != LevelApplication {
				sp.outSent = sp.acked.from(0)
				continue
			}
			// Its content goes out again; the packet is no longer waited
			// for, which says nothing about the path.
			p := sp.sent[0]
			sp.sent = sp.sent[1:]
			c.cc.forget(int64(p.size))
			c.packetLost(lvl, &p)
		}
		// Until the probes are sent (Send arms the timeout again from
		// them), do not fire again.
		c.ptoAt = now + c.pto()<<min(c.ptoCount, maxPTOBackoff)
	}
}

// ---- closing ----

// Close closes the connection with an application error code.
func (c *Conn) Close(now int64, code uint64, reason string) {
	if c.state >= stateClosing {
		return
	}
	c.startClosing(now, AppendConnectionClose(nil, true, code, 0, reason))
}

// closeWith closes the connection for a transport error.
func (c *Conn) closeWith(now int64, code TransportError, frameType uint64, reason string) {
	if c.state >= stateClosing {
		return
	}
	c.err = code
	c.startClosing(now, AppendConnectionClose(nil, false, uint64(code), frameType, reason))
}

// Abandon ends the connection at once, without a word to the peer: for a
// connection its owner gives up on (a handshake that takes too long, a
// failure in the code that serves it).
func (c *Conn) Abandon() {
	if c.state != stateClosed {
		c.end()
	}
}

func (c *Conn) startClosing(now int64, frame []byte) {
	c.closeFrame = frame
	c.closeSend = true
	c.state = stateClosing
	c.closeAt = now + 3*c.pto()
	c.ptoAt, c.idleAt, c.ackAt, c.paceAt = 0, 0, 0, 0
}

func (c *Conn) end() {
	c.state = stateClosed
	c.tls.Close()
	for i := range c.spaces {
		c.spaces[i] = space{}
	}
	c.releaseStreams()
}

// ---- sending ----

// appWants reports whether there is something to send in a 1-RTT packet
// beside acknowledgements and the handshake's own frames.
func (c *Conn) appWants() bool {
	return c.pathRespSend || c.maxDataDirty || c.maxBidiDirty || c.maxUniDirty || c.localSend || len(c.retire) > 0 || len(c.sendq) > 0
}

// levelWants reports whether level l has a packet to send now. data says
// whether more than an acknowledgement may go out (the congestion window
// and the pacer allow it, or a probe is owed).
func (c *Conn) levelWants(l Level, data bool) bool {
	sp := &c.spaces[l]
	if sp.wk == nil {
		return false
	}
	if sp.ackNeeded {
		return true
	}
	if !data {
		return false
	}
	if sp.acked.from(sp.outSent) < uint64(len(sp.out)) || c.probes > 0 && len(sp.sent) > 0 {
		return true
	}
	return l == LevelApplication && (c.sendDone && !c.doneInFlight() || c.appWants())
}

// Send writes the next datagram the connection has to send into buf and
// returns its length: 0 when there is nothing to send now. It is called
// until it returns 0. buf holds MaxDatagramSize bytes; with room for less
// (maxDatagram at the least) the connection sends no datagram larger than
// the room, and does not find out whether its path carries more.
func (c *Conn) Send(now int64, buf []byte) int {
	c.clock = now
	if c.state == stateClosed || c.state == stateDraining {
		return 0
	}
	b := buf[:0]
	limit := min(c.mtu, len(buf))
	if !c.addrValidated {
		// Before the client's address is validated at most three times
		// what it sent goes back (RFC 9000, section 8.1).
		limit = min(limit, 3*c.recvBytes-c.sentBytes)
	}
	padTo := 0
	// The datagram's last packet, not sealed yet: where it starts and
	// where its Length and packet number are.
	lastStart, lastPNOff, lastLenOff, lastPNLen := 0, -1, -1, 0
	var lastLevel Level
	var lastPN int64
	closing := c.state == stateClosing
	// More than acknowledgements goes out when the congestion window has
	// room and the pacer agrees, or as a probe, which neither holds back.
	data := c.probes > 0
	if !data && !closing && c.cc.canSend() {
		ok, at := c.cc.ready(now, c.rttSmoothed)
		data = ok
		if !ok {
			c.paceAt = at
		} else if size := c.mtuProbe(); size > 0 && size <= len(buf) {
			// Where a datagram of data may go, one that tries a larger
			// size may: it is held back by what holds data back.
			return c.sendMTUProbe(now, buf, size)
		}
	}
	// The packets of this datagram that count as in flight, to be given
	// their size once they are sealed.
	var flying [3]struct {
		lvl Level
		idx int
		at  int
	}
	nflying := 0
	for lvl := LevelInitial; lvl <= LevelApplication; lvl++ {
		sp := &c.spaces[lvl]
		if sp.wk == nil {
			continue
		}
		// A packet needs its header, a frame and the tag.
		if limit-len(b)-64 <= 0 {
			break
		}
		if closing {
			if !c.closeSend || lvl != c.closeLevel() {
				continue
			}
		} else if !c.levelWants(lvl, data) {
			continue
		}
		if lvl == LevelApplication && !closing {
			c.maybeUpdateKeys()
		}
		start := len(b)
		pn := sp.nextPN
		pnLen := pnLenFor(pn, sp.largestAcked)
		var pnOff, lenOff int
		if lvl == LevelApplication {
			b, pnOff = AppendShortHeader(b, c.dcid, c.sendPhase, pn, pnLen)
		} else {
			typ := uint8(PacketInitial)
			if lvl == LevelHandshake {
				typ = PacketHandshake
			}
			b, lenOff, pnOff = AppendLongHeader(b, typ, c.dcid, c.scid, nil, pn, pnLen)
		}
		payloadStart := len(b)
		// Frames may fill the datagram up to its tag.
		room := limit - Overhead
		eliciting := false
		sent := sentPacket{pn: pn, at: now}
		if closing {
			b = append(b, c.closeFrame...)
		} else {
			// An acknowledgement rides along whenever there is something
			// to acknowledge.
			if r := sp.recv.ranges(); len(r) > 0 && (sp.ackNeeded || sp.unacked > 0) {
				delay := uint64(0)
				if lvl == LevelApplication && now > sp.largestAt {
					delay = uint64(now-sp.largestAt) / uint64(time.Microsecond) >> c.cfg.Params.AckDelayExponent
				}
				// The highest ranges that fit (each takes at most 16 bytes).
				r = r[:min(len(r), max(1, (room-len(b)-24)/16))]
				b = AppendAck(b, delay, r)
				sp.ackNeeded, sp.unacked = false, 0
				if lvl == LevelApplication {
					c.ackAt = 0
				}
			}
			if off := sp.acked.from(sp.outSent); data && off < uint64(len(sp.out)) && room-len(b) > 24 {
				n := min(uint64(len(sp.out))-off, uint64(room-len(b)-16))
				// Up to the next part the peer already has.
				for _, r := range sp.acked {
					if r[0] > off {
						n = min(n, r[0]-off)
						break
					}
				}
				b = AppendCrypto(b, off, sp.out[off:off+n])
				sent.cryptoOff, sent.cryptoLen = off, n
				sp.outSent = off + n
				eliciting = true
			}
			if lvl == LevelApplication && data {
				if c.sendDone && !c.doneInFlight() {
					b = append(b, FrameHandshakeDone)
					sent.done = true
					eliciting = true
				}
				if c.pathRespSend && room-len(b) > 16 {
					// The answer to a path challenge goes in a full-size
					// datagram (RFC 9000, section 8.2.2).
					b = AppendPath(b, FramePathResponse, c.pathResp)
					c.pathRespSend = false
					padTo = maxDatagram
					eliciting = true
				}
				if c.maxDataDirty && room-len(b) > 16 {
					b = AppendFrame1(b, FrameMaxData, c.recvMaxData)
					c.maxDataDirty = false
					sent.ctl |= pktMaxData
					eliciting = true
				}
				if c.maxBidiDirty && room-len(b) > 16 {
					b = AppendFrame1(b, FrameMaxStreams, c.maxBidi)
					c.maxBidiDirty = false
					sent.ctl |= pktMaxStreamsBidi
					eliciting = true
				}
				if c.maxUniDirty && room-len(b) > 16 {
					b = AppendFrame1(b, FrameMaxStreams+1, c.maxUni)
					c.maxUniDirty = false
					sent.ctl |= pktMaxStreamsUni
					eliciting = true
				}
				if c.localSend || len(c.retire) > 0 {
					before := len(b)
					b = c.appendCIDFrames(b, room, &sent, pn)
					eliciting = eliciting || len(b) > before
				}
				if len(c.sendq) > 0 {
					before := len(b)
					b = c.appendStreams(b, room, &sent)
					eliciting = eliciting || len(b) > before
				}
			}
			if c.probes > 0 && !eliciting && len(sp.sent) > 0 {
				b = append(b, FramePing)
				eliciting = true
			}
			if len(b) == payloadStart {
				// Nothing to say after all (streams that wait for the
				// peer's credit).
				b = b[:start]
				continue
			}
		}
		// The header protection samples 4 bytes past the start of the
		// packet number.
		for len(b)-payloadStart+pnLen < 4 {
			b = append(b, FramePadding)
		}
		if lvl == LevelInitial && eliciting {
			padTo = maxDatagram // a datagram with an ack-eliciting Initial packet is a full one
		}
		lastStart, lastPNOff, lastLenOff, lastPNLen, lastLevel, lastPN = start, pnOff, lenOff, pnLen, lvl, pn
		sp.nextPN++
		if eliciting {
			sp.push(sent)
			flying[nflying].lvl, flying[nflying].idx, flying[nflying].at = lvl, len(sp.sent)-1, start
			nflying++
			if c.probes > 0 {
				c.probes--
			}
		}
		// A packet that another follows is sealed now. The datagram's last
		// one is sealed after the padding, which goes into it: it is the
		// last when no higher level has anything to send, or when what is
		// left of the datagram does not take another packet.
		if lvl == LevelApplication || closing || !c.laterLevelSends(lvl, data) || limit-len(b)-Overhead-64 <= 0 {
			break
		}
		SetLength(b, lenOff, pnOff)
		b = b[:start+len(sp.wk.Seal(b[start:], pnOff-start, pnLen, pn))]
		lastPNOff = -1
	}
	if len(b) == 0 {
		return 0
	}
	if lastPNOff >= 0 {
		// Pad the last packet so that the datagram is as long as it must
		// be, then seal it. (When a higher level, expected to add a packet,
		// had nothing to say after all, the packets before it are sealed
		// already and go as they are.)
		for padTo > 0 && len(b)+Overhead < min(padTo, limit) {
			b = append(b, FramePadding)
		}
		sp := &c.spaces[lastLevel]
		if lastLevel != LevelApplication {
			SetLength(b, lastLenOff, lastPNOff)
		}
		b = b[:lastStart+len(sp.wk.Seal(b[lastStart:], lastPNOff-lastStart, lastPNLen, lastPN))]
	}
	if closing {
		c.closeSend = false
	}
	if !c.addrValidated {
		c.sentBytes += len(b)
	}
	// Each packet that waits for an acknowledgement is in flight with its
	// size: from where it starts to where the next one does.
	for i := 0; i < nflying; i++ {
		end := len(b)
		if i+1 < nflying {
			end = flying[i+1].at
		}
		size := end - flying[i].at
		c.spaces[flying[i].lvl].sent[flying[i].idx].size = uint16(size)
		c.cc.onSent(int64(size))
	}
	if nflying > 0 {
		c.cc.paced(int64(len(b)))
	}
	c.setPTO(now)
	return len(b)
}

// closeLevel is the level CONNECTION_CLOSE is sent at: one the client is
// sure to have the keys of. After the handshake that is 1-RTT; before it,
// Handshake once the client has sent a Handshake packet, else Initial.
func (c *Conn) closeLevel() Level {
	switch {
	case c.handshakeDone:
		return LevelApplication
	case c.addrValidated && c.spaces[LevelHandshake].wk != nil:
		return LevelHandshake
	case c.spaces[LevelInitial].wk != nil:
		return LevelInitial
	}
	return LevelHandshake
}

// laterLevelSends reports whether a level above lvl will put a packet in
// the datagram being built: the packet of lvl is then not the last.
func (c *Conn) laterLevelSends(lvl Level, data bool) bool {
	for l := lvl + 1; l <= LevelApplication; l++ {
		if c.levelWants(l, data) {
			return true
		}
	}
	return false
}

// doneInFlight reports whether a packet with HANDSHAKE_DONE waits for its
// acknowledgement.
func (c *Conn) doneInFlight() bool {
	for i := range c.spaces[LevelApplication].sent {
		if c.spaces[LevelApplication].sent[i].done {
			return true
		}
	}
	return false
}
