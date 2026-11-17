// Package h2 is the wire format of HTTP/2 (RFC 9113) and HPACK (RFC 7541)
// as nvelox's event loops use it: frame headers and the fixed-size frames,
// the header-block decoder and a stateless encoder. It does no I/O and
// keeps nothing it is given; the connection logic lives with the loops.
package h2

import "encoding/binary"

// FrameType is a frame's type.
type FrameType uint8

const (
	FrameData         FrameType = 0x0
	FrameHeaders      FrameType = 0x1
	FramePriority     FrameType = 0x2
	FrameRSTStream    FrameType = 0x3
	FrameSettings     FrameType = 0x4
	FramePushPromise  FrameType = 0x5
	FramePing         FrameType = 0x6
	FrameGoAway       FrameType = 0x7
	FrameWindowUpdate FrameType = 0x8
	FrameContinuation FrameType = 0x9
)

// Frame flags.
const (
	FlagEndStream  = 0x1 // DATA, HEADERS
	FlagAck        = 0x1 // SETTINGS, PING
	FlagEndHeaders = 0x4 // HEADERS, CONTINUATION
	FlagPadded     = 0x8 // DATA, HEADERS
	FlagPriority   = 0x20
)

// ErrCode is an HTTP/2 error code.
type ErrCode uint32

const (
	ErrNo                 ErrCode = 0x0
	ErrProtocol           ErrCode = 0x1
	ErrInternal           ErrCode = 0x2
	ErrFlowControl        ErrCode = 0x3
	ErrSettingsTimeout    ErrCode = 0x4
	ErrStreamClosed       ErrCode = 0x5
	ErrFrameSize          ErrCode = 0x6
	ErrRefusedStream      ErrCode = 0x7
	ErrCancel             ErrCode = 0x8
	ErrCompressionCode    ErrCode = 0x9
	ErrConnect            ErrCode = 0xa
	ErrEnhanceYourCalm    ErrCode = 0xb
	ErrInadequateSecurity ErrCode = 0xc
	ErrHTTP11Required     ErrCode = 0xd
)

// SettingID is a SETTINGS parameter.
type SettingID uint16

const (
	SettingHeaderTableSize      SettingID = 0x1
	SettingEnablePush           SettingID = 0x2
	SettingMaxConcurrentStreams SettingID = 0x3
	SettingInitialWindowSize    SettingID = 0x4
	SettingMaxFrameSize         SettingID = 0x5
	SettingMaxHeaderListSize    SettingID = 0x6
	SettingEnableConnectProto   SettingID = 0x8
	SettingNoRFC7540Priorities  SettingID = 0x9
)

// Setting is one SETTINGS parameter and its value.
type Setting struct {
	ID  SettingID
	Val uint32
}

const (
	// FrameHeaderLen is the size of a frame header.
	FrameHeaderLen = 9
	// DefaultMaxFrameSize is the largest frame payload a peer may send
	// unless SETTINGS_MAX_FRAME_SIZE raised it; it is also the smallest
	// value of that setting.
	DefaultMaxFrameSize = 16384
	// MaxFrameSizeLimit is the largest value of SETTINGS_MAX_FRAME_SIZE.
	MaxFrameSizeLimit = 1<<24 - 1
	// DefaultWindow is a flow-control window before any SETTINGS or
	// WINDOW_UPDATE.
	DefaultWindow = 65535
	// MaxWindow is the largest flow-control window.
	MaxWindow = 1<<31 - 1
)

// ClientPreface is what a client sends first.
const ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// FrameHeader is the 9 bytes every frame starts with.
type FrameHeader struct {
	Length   uint32 // of the payload
	Type     FrameType
	Flags    uint8
	StreamID uint32
}

// ReadFrameHeader decodes the frame header in b[:9].
func ReadFrameHeader(b []byte) FrameHeader {
	_ = b[8]
	return FrameHeader{
		Length:   uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]),
		Type:     FrameType(b[3]),
		Flags:    b[4],
		StreamID: binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff,
	}
}

// AppendFrameHeader appends a frame header.
func AppendFrameHeader(dst []byte, length int, t FrameType, flags uint8, stream uint32) []byte {
	return append(dst, byte(length>>16), byte(length>>8), byte(length), byte(t), flags,
		byte(stream>>24)&0x7f, byte(stream>>16), byte(stream>>8), byte(stream))
}

// Check applies the rules a frame header can break by itself (RFC 9113,
// section 6): the payload size against maxFrame (what this end announced)
// and against the frame type's fixed size, and whether the type belongs on
// stream 0 or on a stream. It returns the error code and whether the error
// ends the connection; ErrNo when the header is in order. Every error it
// finds ends the connection, as in Go's server. Frames of unknown types
// pass: they are ignored.
func (h FrameHeader) Check(maxFrame uint32) (code ErrCode, conn bool) {
	if h.Length > maxFrame {
		return ErrFrameSize, true
	}
	switch h.Type {
	case FrameData, FrameHeaders, FrameContinuation:
		if h.StreamID == 0 {
			return ErrProtocol, true
		}
	case FramePriority:
		if h.StreamID == 0 {
			return ErrProtocol, true
		}
		if h.Length != 5 {
			// A stream error in RFC 9113; Go's server ends the connection,
			// and so do we.
			return ErrFrameSize, true
		}
	case FrameRSTStream:
		if h.StreamID == 0 {
			return ErrProtocol, true
		}
		if h.Length != 4 {
			return ErrFrameSize, true
		}
	case FrameSettings:
		if h.StreamID != 0 {
			return ErrProtocol, true
		}
		if h.Flags&FlagAck != 0 && h.Length != 0 || h.Length%6 != 0 {
			return ErrFrameSize, true
		}
	case FramePushPromise:
		return ErrProtocol, true // a client never pushes
	case FramePing:
		if h.StreamID != 0 {
			return ErrProtocol, true
		}
		if h.Length != 8 {
			return ErrFrameSize, true
		}
	case FrameGoAway:
		if h.StreamID != 0 {
			return ErrProtocol, true
		}
		if h.Length < 8 {
			return ErrFrameSize, true
		}
	case FrameWindowUpdate:
		if h.Length != 4 {
			return ErrFrameSize, true
		}
	}
	return ErrNo, false
}

// CheckSetting applies the limits of a peer's SETTINGS parameter. Unknown
// parameters pass: they are ignored.
func CheckSetting(s Setting) ErrCode {
	switch s.ID {
	case SettingEnablePush:
		if s.Val > 1 {
			return ErrProtocol
		}
	case SettingInitialWindowSize:
		if s.Val > MaxWindow {
			return ErrFlowControl
		}
	case SettingMaxFrameSize:
		if s.Val < DefaultMaxFrameSize || s.Val > MaxFrameSizeLimit {
			return ErrProtocol
		}
	case SettingEnableConnectProto:
		if s.Val > 1 {
			return ErrProtocol
		}
	}
	return ErrNo
}

// ReadSetting decodes the parameter in b[:6] of a SETTINGS payload.
func ReadSetting(b []byte) Setting {
	_ = b[5]
	return Setting{ID: SettingID(binary.BigEndian.Uint16(b)), Val: binary.BigEndian.Uint32(b[2:])}
}

// AppendSettings appends a SETTINGS frame.
func AppendSettings(dst []byte, settings ...Setting) []byte {
	dst = AppendFrameHeader(dst, 6*len(settings), FrameSettings, 0, 0)
	for _, s := range settings {
		dst = append(dst, byte(s.ID>>8), byte(s.ID), byte(s.Val>>24), byte(s.Val>>16), byte(s.Val>>8), byte(s.Val))
	}
	return dst
}

// AppendSettingsAck appends the acknowledgement of a SETTINGS frame.
func AppendSettingsAck(dst []byte) []byte {
	return AppendFrameHeader(dst, 0, FrameSettings, FlagAck, 0)
}

// AppendPing appends a PING frame with the 8 bytes of data.
func AppendPing(dst []byte, ack bool, data []byte) []byte {
	var flags uint8
	if ack {
		flags = FlagAck
	}
	dst = AppendFrameHeader(dst, 8, FramePing, flags, 0)
	return append(dst, data[:8]...)
}

// AppendGoAway appends a GOAWAY frame.
func AppendGoAway(dst []byte, lastStream uint32, code ErrCode, debug []byte) []byte {
	dst = AppendFrameHeader(dst, 8+len(debug), FrameGoAway, 0, 0)
	dst = append(dst, byte(lastStream>>24)&0x7f, byte(lastStream>>16), byte(lastStream>>8), byte(lastStream),
		byte(code>>24), byte(code>>16), byte(code>>8), byte(code))
	return append(dst, debug...)
}

// AppendRSTStream appends a RST_STREAM frame.
func AppendRSTStream(dst []byte, stream uint32, code ErrCode) []byte {
	dst = AppendFrameHeader(dst, 4, FrameRSTStream, 0, stream)
	return append(dst, byte(code>>24), byte(code>>16), byte(code>>8), byte(code))
}

// AppendWindowUpdate appends a WINDOW_UPDATE frame (stream 0: the
// connection's window).
func AppendWindowUpdate(dst []byte, stream, incr uint32) []byte {
	dst = AppendFrameHeader(dst, 4, FrameWindowUpdate, 0, stream)
	return append(dst, byte(incr>>24)&0x7f, byte(incr>>16), byte(incr>>8), byte(incr))
}

// AppendDataHeader appends the header of a DATA frame of length bytes; the
// payload follows.
func AppendDataHeader(dst []byte, stream uint32, length int, endStream bool) []byte {
	var flags uint8
	if endStream {
		flags = FlagEndStream
	}
	return AppendFrameHeader(dst, length, FrameData, flags, stream)
}

// AppendHeaders appends a header block as a HEADERS frame and, when the
// block is larger than maxFrame, the CONTINUATION frames that carry on.
func AppendHeaders(dst []byte, stream uint32, block []byte, endStream bool, maxFrame int) []byte {
	var flags uint8
	if endStream {
		flags = FlagEndStream
	}
	t := FrameHeaders
	for {
		n := len(block)
		if n > maxFrame {
			n = maxFrame
		} else {
			flags |= FlagEndHeaders
		}
		dst = AppendFrameHeader(dst, n, t, flags, stream)
		dst = append(dst, block[:n]...)
		block = block[n:]
		if flags&FlagEndHeaders != 0 {
			return dst
		}
		t, flags = FrameContinuation, 0
	}
}

// AddWindow adds a WINDOW_UPDATE's increment to a flow-control window. It
// reports false when the window would pass MaxWindow (a flow-control
// error) or the increment is zero (a protocol error).
func AddWindow(w *int64, incr uint32) bool {
	if incr == 0 || *w+int64(incr) > MaxWindow {
		return false
	}
	*w += int64(incr)
	return true
}
