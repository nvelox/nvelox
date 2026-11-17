package quic

import "time"

// Transport parameters (RFC 9000, section 18): what each endpoint tells the
// other, inside the TLS handshake, about its limits and connection IDs.

// Transport parameter identifiers.
const (
	paramOriginalDCID          = 0x00
	paramMaxIdleTimeout        = 0x01
	paramStatelessResetToken   = 0x02
	paramMaxUDPPayloadSize     = 0x03
	paramInitialMaxData        = 0x04
	paramMaxStreamDataBidiLoc  = 0x05
	paramMaxStreamDataBidiRem  = 0x06
	paramMaxStreamDataUni      = 0x07
	paramInitialMaxStreamsBidi = 0x08
	paramInitialMaxStreamsUni  = 0x09
	paramAckDelayExponent      = 0x0a
	paramMaxAckDelay           = 0x0b
	paramDisableMigration      = 0x0c
	paramPreferredAddress      = 0x0d
	paramActiveCIDLimit        = 0x0e
	paramInitialSCID           = 0x0f
	paramRetrySCID             = 0x10
)

// Defaults of the parameters a peer leaves out.
const (
	defaultMaxUDPPayload    = 65527
	defaultAckDelayExponent = 3
	defaultMaxAckDelay      = 25 * time.Millisecond
	defaultActiveCIDLimit   = 2
)

// Params is one endpoint's transport parameters.
type Params struct {
	// Connection IDs, for the checks of RFC 9000, section 7.3. A server
	// sends OriginalDCID (the Destination Connection ID of the client's
	// first Initial packet), InitialSCID (its own) and, after a Retry,
	// RetrySCID; a client sends InitialSCID only.
	OriginalDCID []byte
	InitialSCID  []byte
	RetrySCID    []byte
	// StatelessResetToken (16 bytes) of the server's first connection ID.
	StatelessResetToken []byte

	MaxIdleTimeout    time.Duration // 0: none
	MaxUDPPayloadSize uint64

	InitialMaxData                 uint64
	InitialMaxStreamDataBidiLocal  uint64
	InitialMaxStreamDataBidiRemote uint64
	InitialMaxStreamDataUni        uint64
	InitialMaxStreamsBidi          uint64
	InitialMaxStreamsUni           uint64

	AckDelayExponent        uint8
	MaxAckDelay             time.Duration
	DisableActiveMigration  bool
	ActiveConnectionIDLimit uint64
}

func appendParam(dst []byte, id uint64, v uint64) []byte {
	dst = appendVarint(dst, id)
	dst = appendVarint(dst, uint64(varintLen(v)))
	return appendVarint(dst, v)
}

func appendParamBytes(dst []byte, id uint64, v []byte) []byte {
	dst = appendVarint(dst, id)
	dst = appendVarint(dst, uint64(len(v)))
	return append(dst, v...)
}

// Append appends a server's transport parameters: every one of p that is
// not at its default.
func (p *Params) Append(dst []byte) []byte {
	dst = appendParamBytes(dst, paramOriginalDCID, p.OriginalDCID)
	dst = appendParamBytes(dst, paramInitialSCID, p.InitialSCID)
	if p.RetrySCID != nil {
		dst = appendParamBytes(dst, paramRetrySCID, p.RetrySCID)
	}
	if len(p.StatelessResetToken) == 16 {
		dst = appendParamBytes(dst, paramStatelessResetToken, p.StatelessResetToken)
	}
	if p.MaxIdleTimeout > 0 {
		dst = appendParam(dst, paramMaxIdleTimeout, uint64(p.MaxIdleTimeout/time.Millisecond))
	}
	if p.MaxUDPPayloadSize != 0 && p.MaxUDPPayloadSize != defaultMaxUDPPayload {
		dst = appendParam(dst, paramMaxUDPPayloadSize, p.MaxUDPPayloadSize)
	}
	for _, e := range [...]struct{ id, v uint64 }{
		{paramInitialMaxData, p.InitialMaxData},
		{paramMaxStreamDataBidiLoc, p.InitialMaxStreamDataBidiLocal},
		{paramMaxStreamDataBidiRem, p.InitialMaxStreamDataBidiRemote},
		{paramMaxStreamDataUni, p.InitialMaxStreamDataUni},
		{paramInitialMaxStreamsBidi, p.InitialMaxStreamsBidi},
		{paramInitialMaxStreamsUni, p.InitialMaxStreamsUni},
	} {
		if e.v != 0 {
			dst = appendParam(dst, e.id, e.v)
		}
	}
	if p.AckDelayExponent != defaultAckDelayExponent {
		dst = appendParam(dst, paramAckDelayExponent, uint64(p.AckDelayExponent))
	}
	if p.MaxAckDelay != defaultMaxAckDelay {
		dst = appendParam(dst, paramMaxAckDelay, uint64(p.MaxAckDelay/time.Millisecond))
	}
	if p.DisableActiveMigration {
		dst = appendParamBytes(dst, paramDisableMigration, nil)
	}
	if p.ActiveConnectionIDLimit != 0 && p.ActiveConnectionIDLimit != defaultActiveCIDLimit {
		dst = appendParam(dst, paramActiveCIDLimit, p.ActiveConnectionIDLimit)
	}
	return dst
}

// ParseClientParams parses the transport parameters a client sent into p,
// with the defaults for the ones it left out. Anything a client must not
// send or a value outside its range is TransportParameterError: a
// parameter twice, one of the four only a server sends, a missing
// initial_source_connection_id, max_udp_payload_size below 1200,
// ack_delay_exponent above 20, max_ack_delay of 2^14 ms or more,
// active_connection_id_limit below 2, a stream count above 2^60, or a
// parameter whose value is not the one integer its length says.
func ParseClientParams(b []byte, p *Params) error {
	*p = Params{
		MaxUDPPayloadSize:       defaultMaxUDPPayload,
		AckDelayExponent:        defaultAckDelayExponent,
		MaxAckDelay:             defaultMaxAckDelay,
		ActiveConnectionIDLimit: defaultActiveCIDLimit,
	}
	var seen uint32 // the parameters 0x00 to 0x10 that came
	for len(b) > 0 {
		id, n := varint(b)
		if n == 0 {
			return TransportParameterError
		}
		b = b[n:]
		l, n := varint(b)
		if n == 0 || l > uint64(len(b)-n) {
			return TransportParameterError
		}
		v := b[n : n+int(l)]
		b = b[n+int(l):]
		if id > paramRetrySCID {
			continue // an unknown or reserved parameter: ignored
		}
		if seen&(1<<id) != 0 {
			return TransportParameterError
		}
		seen |= 1 << id
		// num reads the value as the one integer it must be.
		num := func() (uint64, bool) {
			x, n := varint(v)
			return x, n != 0 && n == len(v)
		}
		var x uint64
		ok := true
		switch id {
		case paramOriginalDCID, paramStatelessResetToken, paramPreferredAddress, paramRetrySCID:
			return TransportParameterError // a server's
		case paramInitialSCID:
			if len(v) > MaxCIDLen {
				return TransportParameterError
			}
			p.InitialSCID = v
		case paramDisableMigration:
			ok = len(v) == 0
			p.DisableActiveMigration = true
		case paramMaxIdleTimeout:
			x, ok = num()
			// A value too large for a Duration means no timeout worth
			// keeping time for.
			if x < uint64(1<<62)/uint64(time.Millisecond) {
				p.MaxIdleTimeout = time.Duration(x) * time.Millisecond
			}
		case paramMaxUDPPayloadSize:
			x, ok = num()
			ok = ok && x >= 1200
			p.MaxUDPPayloadSize = x
		case paramInitialMaxData:
			p.InitialMaxData, ok = num()
		case paramMaxStreamDataBidiLoc:
			p.InitialMaxStreamDataBidiLocal, ok = num()
		case paramMaxStreamDataBidiRem:
			p.InitialMaxStreamDataBidiRemote, ok = num()
		case paramMaxStreamDataUni:
			p.InitialMaxStreamDataUni, ok = num()
		case paramInitialMaxStreamsBidi:
			p.InitialMaxStreamsBidi, ok = num()
			ok = ok && p.InitialMaxStreamsBidi <= 1<<60
		case paramInitialMaxStreamsUni:
			p.InitialMaxStreamsUni, ok = num()
			ok = ok && p.InitialMaxStreamsUni <= 1<<60
		case paramAckDelayExponent:
			x, ok = num()
			ok = ok && x <= 20
			p.AckDelayExponent = uint8(x)
		case paramMaxAckDelay:
			x, ok = num()
			ok = ok && x < 1<<14
			p.MaxAckDelay = time.Duration(x) * time.Millisecond
		case paramActiveCIDLimit:
			x, ok = num()
			ok = ok && x >= 2
			p.ActiveConnectionIDLimit = x
		}
		if !ok {
			return TransportParameterError
		}
	}
	if seen&(1<<paramInitialSCID) == 0 {
		return TransportParameterError
	}
	return nil
}
