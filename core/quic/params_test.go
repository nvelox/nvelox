package quic

import (
	"bytes"
	"testing"
	"time"
)

// A server's parameters, as written: the generic reader below finds each
// with the value that was set, and nothing for the ones at their default.
func TestParams_Append(t *testing.T) {
	p := Params{
		OriginalDCID: []byte{1, 2, 3, 4, 5, 6, 7, 8}, InitialSCID: []byte{9, 9, 9, 9}, RetrySCID: []byte{7, 7},
		StatelessResetToken: bytes.Repeat([]byte{0xaa}, 16),
		MaxIdleTimeout:      30 * time.Second, MaxUDPPayloadSize: 1452,
		InitialMaxData: 1 << 20, InitialMaxStreamDataBidiLocal: 1 << 18, InitialMaxStreamDataBidiRemote: 1 << 17, InitialMaxStreamDataUni: 1 << 16,
		InitialMaxStreamsBidi: 100, InitialMaxStreamsUni: 3,
		AckDelayExponent: defaultAckDelayExponent, MaxAckDelay: defaultMaxAckDelay,
		DisableActiveMigration: true, ActiveConnectionIDLimit: 4,
	}
	got := map[uint64][]byte{}
	for b := p.Append(nil); len(b) > 0; {
		id, n := varint(b)
		l, n2 := varint(b[n:])
		if n == 0 || n2 == 0 || int(l) > len(b)-n-n2 {
			t.Fatalf("parameters cut short at %x", b)
		}
		if _, dup := got[id]; dup {
			t.Fatalf("parameter %#x twice", id)
		}
		got[id] = b[n+n2 : n+n2+int(l)]
		b = b[n+n2+int(l):]
	}
	num := func(id uint64) uint64 { v, _ := varint(got[id]); return v }
	if !bytes.Equal(got[paramOriginalDCID], p.OriginalDCID) || !bytes.Equal(got[paramInitialSCID], p.InitialSCID) || !bytes.Equal(got[paramRetrySCID], p.RetrySCID) || !bytes.Equal(got[paramStatelessResetToken], p.StatelessResetToken) {
		t.Errorf("connection IDs: %v", got)
	}
	if num(paramMaxIdleTimeout) != 30000 || num(paramMaxUDPPayloadSize) != 1452 || num(paramInitialMaxData) != 1<<20 || num(paramMaxStreamDataBidiLoc) != 1<<18 || num(paramMaxStreamDataBidiRem) != 1<<17 || num(paramMaxStreamDataUni) != 1<<16 || num(paramInitialMaxStreamsBidi) != 100 || num(paramInitialMaxStreamsUni) != 3 || num(paramActiveCIDLimit) != 4 {
		t.Errorf("limits: %v", got)
	}
	if v, ok := got[paramDisableMigration]; !ok || len(v) != 0 {
		t.Errorf("disable_active_migration: %v, %v", v, ok)
	}
	for _, id := range []uint64{paramAckDelayExponent, paramMaxAckDelay, paramPreferredAddress} {
		if _, ok := got[id]; ok {
			t.Errorf("parameter %#x was written at its default", id)
		}
	}
}

func TestParseClientParams(t *testing.T) {
	scid := []byte{1, 2, 3, 4}
	base := appendParamBytes(nil, paramInitialSCID, scid)
	var p Params
	if err := ParseClientParams(base, &p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.InitialSCID, scid) || p.MaxUDPPayloadSize != 65527 || p.AckDelayExponent != 3 || p.MaxAckDelay != 25*time.Millisecond || p.ActiveConnectionIDLimit != 2 || p.MaxIdleTimeout != 0 || p.InitialMaxData != 0 {
		t.Errorf("defaults: %+v", p)
	}
	full := append([]byte(nil), base...)
	full = appendParam(full, paramMaxIdleTimeout, 30000)
	full = appendParam(full, paramMaxUDPPayloadSize, 1472)
	full = appendParam(full, paramInitialMaxData, 15<<20)
	full = appendParam(full, paramMaxStreamDataBidiLoc, 6<<20)
	full = appendParam(full, paramMaxStreamDataBidiRem, 5<<20)
	full = appendParam(full, paramMaxStreamDataUni, 4<<20)
	full = appendParam(full, paramInitialMaxStreamsBidi, 100)
	full = appendParam(full, paramInitialMaxStreamsUni, 103)
	full = appendParam(full, paramAckDelayExponent, 10)
	full = appendParam(full, paramMaxAckDelay, 20)
	full = appendParamBytes(full, paramDisableMigration, nil)
	full = appendParam(full, paramActiveCIDLimit, 8)
	full = appendParamBytes(full, 31*7+27, []byte("grease")) // a reserved parameter: ignored
	full = appendParamBytes(full, 0x2ab2, nil)               // an unknown one: ignored
	if err := ParseClientParams(full, &p); err != nil {
		t.Fatal(err)
	}
	want := Params{InitialSCID: scid, MaxIdleTimeout: 30 * time.Second, MaxUDPPayloadSize: 1472, InitialMaxData: 15 << 20,
		InitialMaxStreamDataBidiLocal: 6 << 20, InitialMaxStreamDataBidiRemote: 5 << 20, InitialMaxStreamDataUni: 4 << 20,
		InitialMaxStreamsBidi: 100, InitialMaxStreamsUni: 103, AckDelayExponent: 10, MaxAckDelay: 20 * time.Millisecond,
		DisableActiveMigration: true, ActiveConnectionIDLimit: 8}
	if !bytes.Equal(p.InitialSCID, want.InitialSCID) {
		t.Errorf("initial_source_connection_id %x", p.InitialSCID)
	}
	p.InitialSCID, want.InitialSCID = nil, nil
	if !paramsEqual(&p, &want) {
		t.Errorf("parsed %+v\nwant   %+v", p, want)
	}

	with := func(extra []byte) []byte { return append(append([]byte(nil), base...), extra...) }
	for name, b := range map[string][]byte{
		"no initial_source_connection_id":    appendParam(nil, paramInitialMaxData, 1),
		"a parameter twice":                  with(append(appendParam(nil, paramInitialMaxData, 1), appendParam(nil, paramInitialMaxData, 2)...)),
		"original_destination_connection_id": with(appendParamBytes(nil, paramOriginalDCID, []byte{1})),
		"stateless_reset_token":              with(appendParamBytes(nil, paramStatelessResetToken, make([]byte, 16))),
		"preferred_address":                  with(appendParamBytes(nil, paramPreferredAddress, make([]byte, 41))),
		"retry_source_connection_id":         with(appendParamBytes(nil, paramRetrySCID, []byte{1})),
		"max_udp_payload_size 1199":          with(appendParam(nil, paramMaxUDPPayloadSize, 1199)),
		"ack_delay_exponent 21":              with(appendParam(nil, paramAckDelayExponent, 21)),
		"max_ack_delay 2^14":                 with(appendParam(nil, paramMaxAckDelay, 1<<14)),
		"active_connection_id_limit 1":       with(appendParam(nil, paramActiveCIDLimit, 1)),
		"initial_max_streams_bidi 2^60+1":    with(appendParam(nil, paramInitialMaxStreamsBidi, 1<<60+1)),
		"a 21-byte connection ID":            appendParamBytes(nil, paramInitialSCID, make([]byte, 21)),
		"disable_active_migration, a value":  with(appendParamBytes(nil, paramDisableMigration, []byte{1})),
		"an integer with bytes after it":     with(appendParamBytes(nil, paramInitialMaxData, []byte{1, 2})),
		"an integer cut short":               with(appendParamBytes(nil, paramInitialMaxData, []byte{0x40})),
		"a length past the end":              with([]byte{paramInitialMaxData, 5, 1}),
		"an identifier and nothing":          with([]byte{paramInitialMaxData}),
	} {
		if err := ParseClientParams(b, &p); err != TransportParameterError {
			t.Errorf("%s: %v, want %v", name, err, TransportParameterError)
		}
	}
}

func paramsEqual(a, b *Params) bool {
	return a.MaxIdleTimeout == b.MaxIdleTimeout && a.MaxUDPPayloadSize == b.MaxUDPPayloadSize && a.InitialMaxData == b.InitialMaxData &&
		a.InitialMaxStreamDataBidiLocal == b.InitialMaxStreamDataBidiLocal && a.InitialMaxStreamDataBidiRemote == b.InitialMaxStreamDataBidiRemote &&
		a.InitialMaxStreamDataUni == b.InitialMaxStreamDataUni && a.InitialMaxStreamsBidi == b.InitialMaxStreamsBidi && a.InitialMaxStreamsUni == b.InitialMaxStreamsUni &&
		a.AckDelayExponent == b.AckDelayExponent && a.MaxAckDelay == b.MaxAckDelay && a.DisableActiveMigration == b.DisableActiveMigration &&
		a.ActiveConnectionIDLimit == b.ActiveConnectionIDLimit
}

// FuzzParseClientParams: no input makes the parser panic.
func FuzzParseClientParams(f *testing.F) {
	f.Add(appendParam(appendParamBytes(nil, paramInitialSCID, []byte{1, 2}), paramInitialMaxData, 1<<20))
	f.Add([]byte{0x0f, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Params
		if err := ParseClientParams(b, &p); err == nil && len(p.InitialSCID) > MaxCIDLen {
			t.Fatalf("a connection ID of %d bytes", len(p.InitialSCID))
		}
	})
}
