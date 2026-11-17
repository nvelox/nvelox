package quic

import "strconv"

// Frame types (RFC 9000, section 19). Types with variants name the first.
const (
	FramePadding            = 0x00
	FramePing               = 0x01
	FrameAck                = 0x02 // 0x03: with ECN counts
	FrameResetStream        = 0x04
	FrameStopSending        = 0x05
	FrameCrypto             = 0x06
	FrameNewToken           = 0x07
	FrameStream             = 0x08 // to 0x0f: OFF 0x04, LEN 0x02, FIN 0x01
	FrameMaxData            = 0x10
	FrameMaxStreamData      = 0x11
	FrameMaxStreams         = 0x12 // 0x13: unidirectional
	FrameDataBlocked        = 0x14
	FrameStreamDataBlocked  = 0x15
	FrameStreamsBlocked     = 0x16 // 0x17: unidirectional
	FrameNewConnectionID    = 0x18
	FrameRetireConnectionID = 0x19
	FramePathChallenge      = 0x1a
	FramePathResponse       = 0x1b
	FrameConnectionClose    = 0x1c // 0x1d: by the application
	FrameHandshakeDone      = 0x1e
)

// TransportError is a QUIC transport error code (RFC 9000, section 20.1):
// what a connection is closed with.
type TransportError uint64

const (
	NoError                 TransportError = 0x00
	InternalError           TransportError = 0x01
	ConnectionRefused       TransportError = 0x02
	FlowControlError        TransportError = 0x03
	StreamLimitError        TransportError = 0x04
	StreamStateError        TransportError = 0x05
	FinalSizeError          TransportError = 0x06
	FrameEncodingError      TransportError = 0x07
	TransportParameterError TransportError = 0x08
	ConnectionIDLimitError  TransportError = 0x09
	ProtocolViolation       TransportError = 0x0a
	InvalidToken            TransportError = 0x0b
	ApplicationError        TransportError = 0x0c
	CryptoBufferExceeded    TransportError = 0x0d
	KeyUpdateError          TransportError = 0x0e
	AEADLimitReached        TransportError = 0x0f
	NoViablePath            TransportError = 0x10
	// CryptoError is the first of the 256 codes that carry a TLS alert.
	CryptoError TransportError = 0x0100
)

var transportErrorNames = [...]string{
	"NO_ERROR", "INTERNAL_ERROR", "CONNECTION_REFUSED", "FLOW_CONTROL_ERROR", "STREAM_LIMIT_ERROR",
	"STREAM_STATE_ERROR", "FINAL_SIZE_ERROR", "FRAME_ENCODING_ERROR", "TRANSPORT_PARAMETER_ERROR",
	"CONNECTION_ID_LIMIT_ERROR", "PROTOCOL_VIOLATION", "INVALID_TOKEN", "APPLICATION_ERROR",
	"CRYPTO_BUFFER_EXCEEDED", "KEY_UPDATE_ERROR", "AEAD_LIMIT_REACHED", "NO_VIABLE_PATH",
}

func (e TransportError) Error() string {
	switch {
	case int(e) < len(transportErrorNames):
		return "quic: " + transportErrorNames[e]
	case e >= CryptoError && e < CryptoError+256:
		return "quic: CRYPTO_ERROR (TLS alert " + strconv.Itoa(int(e-CryptoError)) + ")"
	}
	return "quic: error 0x" + strconv.FormatUint(uint64(e), 16)
}

// maxVarint is the largest value of a variable-length integer.
const maxVarint = 1<<62 - 1

// Frame is one parsed frame. Type says which fields are set; the slices
// point into the packet it was parsed from.
type Frame struct {
	Type uint64

	// ACK: the largest packet number acknowledged, the delay field as sent
	// (to be scaled by the peer's ack_delay_exponent), the length of the
	// first range, the ranges after it (Ranges, for NextRange) and, for
	// type 0x03, the ECN counts (ECT(0), ECT(1), CE).
	Largest    uint64
	Delay      uint64
	FirstRange uint64
	Ranges     []byte
	rangeCount uint64
	ECN        [3]uint64

	// STREAM, CRYPTO, RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA,
	// STREAM_DATA_BLOCKED: the stream; Offset and Data (STREAM, CRYPTO);
	// Fin (STREAM); FinalSize (RESET_STREAM).
	StreamID  uint64
	Offset    uint64
	Data      []byte // also NEW_TOKEN's token
	Fin       bool
	FinalSize uint64

	// MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS and the three BLOCKED frames:
	// the limit.
	Max uint64

	// RESET_STREAM, STOP_SENDING, CONNECTION_CLOSE: the error code;
	// CONNECTION_CLOSE 0x1c: the type of the frame that caused it, and for
	// both forms the reason phrase.
	ErrorCode uint64
	FrameType uint64
	Reason    []byte

	// NEW_CONNECTION_ID: its sequence number, Retire Prior To, the
	// connection ID and its stateless reset token (16 bytes).
	// RETIRE_CONNECTION_ID: Seq.
	Seq           uint64
	RetirePriorTo uint64
	CID           []byte
	ResetToken    []byte

	// PATH_CHALLENGE, PATH_RESPONSE.
	PathData [8]byte
}

// frameErr is what every malformed frame gives: FRAME_ENCODING_ERROR.
const frameErr = FrameEncodingError

// ParseFrame parses the frame at the start of p into f and returns its
// length. A frame that is cut short, has a field out of its range or a
// type that is not defined is FrameEncodingError; a type written longer
// than needed is ProtocolViolation.
func ParseFrame(p []byte, f *Frame) (n int, err error) {
	typ, tn := varint(p)
	if tn == 0 {
		return 0, frameErr
	}
	if tn != 1 {
		// Every type defined fits one byte, and a type is written in its
		// shortest form (RFC 9000, section 12.4).
		if typ > FrameHandshakeDone {
			return 0, frameErr
		}
		return 0, ProtocolViolation
	}
	f.Type = typ
	b := p[1:]
	// next reads a variable-length integer field.
	ok := true
	next := func() uint64 {
		v, l := varint(b)
		if l == 0 {
			ok = false
			return 0
		}
		b = b[l:]
		return v
	}
	// bytesN takes the next l bytes.
	bytesN := func(l uint64) []byte {
		if !ok || l > uint64(len(b)) {
			ok = false
			return nil
		}
		out := b[:l]
		b = b[l:]
		return out
	}
	switch {
	case typ == FramePadding:
		// A run of PADDING frames is taken as one.
		for len(b) > 0 && b[0] == 0 {
			b = b[1:]
		}
	case typ == FramePing, typ == FrameHandshakeDone:
	case typ == FrameAck, typ == FrameAck+1:
		f.Largest = next()
		f.Delay = next()
		f.rangeCount = next()
		f.FirstRange = next()
		if !ok || f.FirstRange > f.Largest {
			return 0, frameErr
		}
		// The further ranges: each a gap and a length, going down. They
		// are walked here once, so that NextRange cannot fail later.
		start := b
		smallest := f.Largest - f.FirstRange
		for i := uint64(0); i < f.rangeCount; i++ {
			gap, length := next(), next()
			if !ok || gap+2 > smallest {
				return 0, frameErr
			}
			largest := smallest - gap - 2
			if length > largest {
				return 0, frameErr
			}
			smallest = largest - length
		}
		f.Ranges = start[:len(start)-len(b)]
		if typ == FrameAck+1 {
			f.ECN = [3]uint64{next(), next(), next()}
		}
	case typ == FrameResetStream:
		f.StreamID, f.ErrorCode, f.FinalSize = next(), next(), next()
	case typ == FrameStopSending:
		f.StreamID, f.ErrorCode = next(), next()
	case typ == FrameCrypto:
		f.Offset = next()
		f.Data = bytesN(next())
		if ok && f.Offset+uint64(len(f.Data)) > maxVarint {
			return 0, frameErr
		}
	case typ == FrameNewToken:
		f.Data = bytesN(next())
		if ok && len(f.Data) == 0 {
			return 0, frameErr
		}
	case typ >= FrameStream && typ <= FrameStream+7:
		f.StreamID = next()
		f.Offset = 0
		if typ&0x04 != 0 {
			f.Offset = next()
		}
		if typ&0x02 != 0 {
			f.Data = bytesN(next())
		} else if ok {
			f.Data, b = b, nil // to the end of the packet
		}
		f.Fin = typ&0x01 != 0
		if ok && f.Offset+uint64(len(f.Data)) > maxVarint {
			return 0, frameErr
		}
	case typ == FrameMaxData, typ == FrameDataBlocked:
		f.Max = next()
	case typ == FrameMaxStreamData, typ == FrameStreamDataBlocked:
		f.StreamID, f.Max = next(), next()
	case typ == FrameMaxStreams, typ == FrameMaxStreams+1, typ == FrameStreamsBlocked, typ == FrameStreamsBlocked+1:
		// A stream count above 2^60 cannot be expressed as a stream ID.
		if f.Max = next(); f.Max > 1<<60 {
			return 0, frameErr
		}
	case typ == FrameNewConnectionID:
		f.Seq, f.RetirePriorTo = next(), next()
		if !ok || len(b) == 0 {
			return 0, frameErr
		}
		l := uint64(b[0])
		b = b[1:]
		f.CID = bytesN(l)
		f.ResetToken = bytesN(16)
		if !ok || l < 1 || l > MaxCIDLen || f.RetirePriorTo > f.Seq {
			return 0, frameErr
		}
	case typ == FrameRetireConnectionID:
		f.Seq = next()
	case typ == FramePathChallenge, typ == FramePathResponse:
		d := bytesN(8)
		if ok {
			copy(f.PathData[:], d)
		}
	case typ == FrameConnectionClose:
		f.ErrorCode, f.FrameType = next(), next()
		f.Reason = bytesN(next())
	case typ == FrameConnectionClose+1:
		f.ErrorCode, f.FrameType = next(), 0
		f.Reason = bytesN(next())
	default:
		return 0, frameErr
	}
	if !ok {
		return 0, frameErr
	}
	return len(p) - len(b), nil
}

// AckRanges walks the packet number ranges an ACK frame acknowledges, from
// the highest down: each as its smallest and largest number.
func (f *Frame) AckRanges(yield func(smallest, largest uint64) bool) {
	largest := f.Largest
	smallest := largest - f.FirstRange
	if !yield(smallest, largest) {
		return
	}
	b := f.Ranges
	for i := uint64(0); i < f.rangeCount; i++ {
		gap, n := varint(b)
		b = b[n:]
		length, n := varint(b)
		b = b[n:]
		largest = smallest - gap - 2
		smallest = largest - length
		if !yield(smallest, largest) {
			return
		}
	}
}

// Level is an encryption level: the packet number space and keys a packet
// belongs to.
type Level uint8

const (
	LevelInitial Level = iota
	LevelHandshake
	LevelApplication // 1-RTT
)

// AllowedAt reports whether a frame of this type may come in a packet of
// the given level from a client (RFC 9000, section 12.4): Initial and
// Handshake packets carry only PADDING, PING, ACK, CRYPTO and a transport
// CONNECTION_CLOSE; a client never sends NEW_TOKEN or HANDSHAKE_DONE.
func (f *Frame) AllowedAt(l Level) bool {
	t := f.Type
	if t == FrameNewToken || t == FrameHandshakeDone {
		return false
	}
	if l == LevelApplication {
		return true
	}
	return t == FramePadding || t == FramePing || t == FrameAck || t == FrameAck+1 || t == FrameCrypto || t == FrameConnectionClose
}

// AckEliciting reports whether a packet with this frame must be
// acknowledged: every frame but ACK, PADDING and CONNECTION_CLOSE.
func (f *Frame) AckEliciting() bool {
	t := f.Type
	return t != FramePadding && t != FrameAck && t != FrameAck+1 && t != FrameConnectionClose && t != FrameConnectionClose+1
}

// ---- writing ----

// AppendAck appends an ACK frame for the ranges given from the highest
// down, each as its smallest and largest packet number (ranges must not
// touch or overlap); delay is the ACK Delay field, already scaled.
func AppendAck(dst []byte, delay uint64, ranges [][2]uint64) []byte {
	dst = append(dst, FrameAck)
	dst = appendVarint(dst, ranges[0][1])
	dst = appendVarint(dst, delay)
	dst = appendVarint(dst, uint64(len(ranges)-1))
	dst = appendVarint(dst, ranges[0][1]-ranges[0][0])
	for i := 1; i < len(ranges); i++ {
		dst = appendVarint(dst, ranges[i-1][0]-ranges[i][1]-2)
		dst = appendVarint(dst, ranges[i][1]-ranges[i][0])
	}
	return dst
}

// AppendCrypto appends a CRYPTO frame.
func AppendCrypto(dst []byte, offset uint64, data []byte) []byte {
	dst = append(dst, FrameCrypto)
	dst = appendVarint(dst, offset)
	dst = appendVarint(dst, uint64(len(data)))
	return append(dst, data...)
}

// AppendStreamHeader appends a STREAM frame's header for n bytes of data
// that the caller appends after it. The frame always carries its length
// and, unless it is 0, its offset.
func AppendStreamHeader(dst []byte, id, offset uint64, n int, fin bool) []byte {
	typ := byte(FrameStream | 0x02)
	if offset != 0 {
		typ |= 0x04
	}
	if fin {
		typ |= 0x01
	}
	dst = append(dst, typ)
	dst = appendVarint(dst, id)
	if offset != 0 {
		dst = appendVarint(dst, offset)
	}
	return appendVarint(dst, uint64(n))
}

// StreamHeaderLen is the length of the header AppendStreamHeader writes.
func StreamHeaderLen(id, offset uint64, n int) int {
	l := 1 + varintLen(id) + varintLen(uint64(n))
	if offset != 0 {
		l += varintLen(offset)
	}
	return l
}

func varintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	}
	return 8
}

// AppendFrame1 appends a frame that is a type and one integer: MAX_DATA,
// MAX_STREAMS, DATA_BLOCKED, STREAMS_BLOCKED, RETIRE_CONNECTION_ID.
func AppendFrame1(dst []byte, typ byte, v uint64) []byte {
	return appendVarint(append(dst, typ), v)
}

// AppendFrame2 appends a frame that is a type and two integers:
// MAX_STREAM_DATA and STREAM_DATA_BLOCKED (stream, limit), STOP_SENDING
// (stream, error code).
func AppendFrame2(dst []byte, typ byte, a, b uint64) []byte {
	return appendVarint(appendVarint(append(dst, typ), a), b)
}

// AppendResetStream appends a RESET_STREAM frame.
func AppendResetStream(dst []byte, id, code, finalSize uint64) []byte {
	return appendVarint(appendVarint(appendVarint(append(dst, FrameResetStream), id), code), finalSize)
}

// AppendNewConnectionID appends a NEW_CONNECTION_ID frame; token is the
// connection ID's 16-byte stateless reset token.
func AppendNewConnectionID(dst []byte, seq, retirePriorTo uint64, cid, token []byte) []byte {
	dst = appendVarint(appendVarint(append(dst, FrameNewConnectionID), seq), retirePriorTo)
	dst = append(dst, byte(len(cid)))
	dst = append(dst, cid...)
	return append(dst, token[:16]...)
}

// AppendPath appends a PATH_CHALLENGE or PATH_RESPONSE frame.
func AppendPath(dst []byte, typ byte, data [8]byte) []byte {
	return append(append(dst, typ), data[:]...)
}

// AppendNewToken appends a NEW_TOKEN frame.
func AppendNewToken(dst, token []byte) []byte {
	return append(appendVarint(append(dst, FrameNewToken), uint64(len(token))), token...)
}

// AppendConnectionClose appends a CONNECTION_CLOSE frame: of the transport
// (app false; frameType is the type of the frame at fault, 0 when none) or
// of the application.
func AppendConnectionClose(dst []byte, app bool, code, frameType uint64, reason string) []byte {
	if app {
		dst = appendVarint(append(dst, FrameConnectionClose+1), code)
	} else {
		dst = appendVarint(appendVarint(append(dst, FrameConnectionClose), code), frameType)
	}
	dst = appendVarint(dst, uint64(len(reason)))
	return append(dst, reason...)
}
