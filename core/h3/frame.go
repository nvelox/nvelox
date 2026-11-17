package h3

import "strconv"

// Frame types (RFC 9114, section 7.2).
const (
	FrameData        = 0x0
	FrameHeaders     = 0x1
	FrameCancelPush  = 0x3
	FrameSettings    = 0x4
	FramePushPromise = 0x5
	FrameGoAway      = 0x7
	FrameMaxPushID   = 0xd
)

// Unidirectional stream types (RFC 9114, section 6.2; RFC 9204, section
// 4.2).
const (
	StreamControl      = 0x0
	StreamPush         = 0x1
	StreamQPACKEncoder = 0x2
	StreamQPACKDecoder = 0x3
)

// Settings (RFC 9114, section 7.2.4.1; RFC 9204, section 5; RFC 9220; RFC
// 9297).
const (
	SettingQPACKMaxTableCapacity = 0x1
	SettingMaxFieldSectionSize   = 0x6
	SettingQPACKBlockedStreams   = 0x7
	SettingEnableConnectProtocol = 0x8
	SettingH3Datagram            = 0x33
)

// Error is an HTTP/3 or QPACK error code (RFC 9114, section 8.1; RFC 9204,
// section 6): what a stream is reset or a connection closed with.
type Error uint64

const (
	ErrNoError              Error = 0x100
	ErrGeneralProtocol      Error = 0x101
	ErrInternal             Error = 0x102
	ErrStreamCreation       Error = 0x103
	ErrClosedCriticalStream Error = 0x104
	ErrFrameUnexpected      Error = 0x105
	ErrFrame                Error = 0x106
	ErrExcessiveLoad        Error = 0x107
	ErrID                   Error = 0x108
	ErrSettings             Error = 0x109
	ErrMissingSettings      Error = 0x10a
	ErrRequestRejected      Error = 0x10b
	ErrRequestCancelled     Error = 0x10c
	ErrRequestIncomplete    Error = 0x10d
	ErrMessage              Error = 0x10e
	ErrConnect              Error = 0x10f
	ErrVersionFallback      Error = 0x110
	ErrQPACKDecompression   Error = 0x200
	ErrQPACKEncoderStream   Error = 0x201
	ErrQPACKDecoderStream   Error = 0x202
)

var errorNames = map[Error]string{
	ErrNoError: "H3_NO_ERROR", ErrGeneralProtocol: "H3_GENERAL_PROTOCOL_ERROR", ErrInternal: "H3_INTERNAL_ERROR",
	ErrStreamCreation: "H3_STREAM_CREATION_ERROR", ErrClosedCriticalStream: "H3_CLOSED_CRITICAL_STREAM",
	ErrFrameUnexpected: "H3_FRAME_UNEXPECTED", ErrFrame: "H3_FRAME_ERROR", ErrExcessiveLoad: "H3_EXCESSIVE_LOAD",
	ErrID: "H3_ID_ERROR", ErrSettings: "H3_SETTINGS_ERROR", ErrMissingSettings: "H3_MISSING_SETTINGS",
	ErrRequestRejected: "H3_REQUEST_REJECTED", ErrRequestCancelled: "H3_REQUEST_CANCELLED",
	ErrRequestIncomplete: "H3_REQUEST_INCOMPLETE", ErrMessage: "H3_MESSAGE_ERROR", ErrConnect: "H3_CONNECT_ERROR",
	ErrVersionFallback: "H3_VERSION_FALLBACK", ErrQPACKDecompression: "QPACK_DECOMPRESSION_FAILED",
	ErrQPACKEncoderStream: "QPACK_ENCODER_STREAM_ERROR", ErrQPACKDecoderStream: "QPACK_DECODER_STREAM_ERROR",
}

func (e Error) Error() string {
	if n, ok := errorNames[e]; ok {
		return "h3: " + n
	}
	return "h3: error 0x" + strconv.FormatUint(uint64(e), 16)
}

// FrameHeader reads the type and the payload length of the frame at the
// start of b. n is the header's length, 0 when b does not hold all of it.
func FrameHeader(b []byte) (typ, length uint64, n int) {
	typ, n1 := Varint(b)
	if n1 == 0 {
		return 0, 0, 0
	}
	length, n2 := Varint(b[n1:])
	if n2 == 0 {
		return 0, 0, 0
	}
	return typ, length, n1 + n2
}

// AppendFrameHeader appends the header of a frame of the given type and
// payload length.
func AppendFrameHeader(dst []byte, typ, length uint64) []byte {
	return AppendVarint(AppendVarint(dst, typ), length)
}

// http2Only reports a frame type HTTP/2 defined and HTTP/3 does not
// (PRIORITY, PING, WINDOW_UPDATE, CONTINUATION): receiving one is a
// connection error, not an unknown frame to skip (RFC 9114, section 7.2.8).
func http2Only(typ uint64) bool {
	return typ == 0x2 || typ == 0x6 || typ == 0x8 || typ == 0x9
}

// RequestFrame says what a server does with a frame of type typ on a
// request stream: handle it (DATA and HEADERS: known is true), skip its
// payload (an unknown type: known false, err nil), or close the connection
// with err (a frame that belongs elsewhere, or to HTTP/2 only; a client
// never sends PUSH_PROMISE).
func RequestFrame(typ uint64) (known bool, err error) {
	switch typ {
	case FrameData, FrameHeaders:
		return true, nil
	case FrameCancelPush, FrameSettings, FramePushPromise, FrameGoAway, FrameMaxPushID:
		return false, ErrFrameUnexpected
	}
	if http2Only(typ) {
		return false, ErrFrameUnexpected
	}
	return false, nil
}

// ControlFrame is RequestFrame for the client's control stream. first says
// that this is the stream's first frame, which must be SETTINGS; SETTINGS
// may not come again.
func ControlFrame(typ uint64, first bool) (known bool, err error) {
	if first && typ != FrameSettings {
		return false, ErrMissingSettings
	}
	switch typ {
	case FrameSettings:
		if !first {
			return false, ErrFrameUnexpected
		}
		return true, nil
	case FrameGoAway, FrameMaxPushID, FrameCancelPush:
		return true, nil
	case FrameData, FrameHeaders, FramePushPromise:
		return false, ErrFrameUnexpected
	}
	if http2Only(typ) {
		return false, ErrFrameUnexpected
	}
	return false, nil
}

// maxSettings bounds the settings of one SETTINGS frame that are looked at
// (their identifiers must be distinct, which is checked against the ones
// before).
const maxSettings = 32

// Settings reads the payload of a SETTINGS frame and calls set for each
// setting, in order. A setting that comes twice, one whose identifier
// HTTP/2 defined and HTTP/3 does not, or more than 32 of them is
// ErrSettings; a payload that ends inside a setting is ErrFrame.
func Settings(p []byte, set func(id, value uint64)) error {
	var seen [maxSettings]uint64
	n := 0
	for len(p) > 0 {
		id, l := Varint(p)
		if l == 0 {
			return ErrFrame
		}
		p = p[l:]
		v, l := Varint(p)
		if l == 0 {
			return ErrFrame
		}
		p = p[l:]
		// 0x0 and 0x2 to 0x5 are HTTP/2's settings without a meaning here.
		if id == 0x0 || id >= 0x2 && id <= 0x5 {
			return ErrSettings
		}
		for _, s := range seen[:n] {
			if s == id {
				return ErrSettings
			}
		}
		if n == maxSettings {
			return ErrSettings
		}
		seen[n] = id
		n++
		set(id, v)
	}
	return nil
}

// AppendSetting appends one setting to the payload of a SETTINGS frame.
func AppendSetting(dst []byte, id, value uint64) []byte {
	return AppendVarint(AppendVarint(dst, id), value)
}
