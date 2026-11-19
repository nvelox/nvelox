package core

import (
	"net"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core/metrics"
)

// Every UDP drop reason is counted: a datagram with a bad signature used to
// vanish without a count or a log line.
func TestUDPDrops_EveryReasonCounted(t *testing.T) {
	for _, r := range []string{udpDropSessionLimit, udpDropSourceLimit, udpDropNoProxyHeader, udpDropClientChanged, udpDropBadSignature, udpDropReplayed} {
		if udpDropText[r] == "" {
			t.Errorf("%s has no log text", r)
		}
	}
	reg := &metrics.Registry{}
	d := newUDPDrops(reg)
	who := &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 4000}
	for r := range udpDropText {
		d.note(r, "l", who)
		d.note(r, "l", who)
		if got := reg.GetCounter("nvelox_udp_dropped_total", map[string]string{"reason": r}).Get(); got != 2 {
			t.Errorf("%s: counted %d drops, want 2", r, got)
		}
	}
}

// A relay's datagram whose header is unsigned or signed with another key is
// dropped and counted under bad_signature, on a running listener.
func TestUDPDrops_BadSignatureCounted(t *testing.T) {
	stUDPEngines(t, udpTestUDPDrops_BadSignatureCounted)
}

func udpTestUDPDrops_BadSignatureCounted(t *testing.T) {
	be, got := stUDPBackend(t, nil)
	addr := stFreeUDPAddr(t)
	e := stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "drops-udp", Bind: addr, Protocol: "udp", Backend: "be",
			AcceptProxyFrom: []string{"127.0.0.0/8"}, AcceptProxyKeys: [][]byte{sigKeyA}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{be}}},
	}, nil)
	badSig := e.Metrics.GetCounter("nvelox_udp_dropped_total", map[string]string{"reason": udpDropBadSignature})
	for name, d := range map[string][]byte{
		"unsigned header": stUDPDatagramWithProxy(t, "198.51.100.70:4000", addr, []byte("forged")),
		"another key":     signedUDPDatagram(t, sigKeyB, "198.51.100.71:4000", addr, []byte("forged")),
	} {
		before := badSig.Get()
		stUDPExchange("127.0.0.1", addr, d, 30*time.Millisecond)
		if b, ok := stWaitGot(got, 300*time.Millisecond); ok {
			t.Fatalf("%s: forwarded %q", name, b)
		}
		if n := badSig.Get() - before; n != 1 {
			t.Fatalf("%s: %d drops counted under bad_signature, want 1", name, n)
		}
	}
}
