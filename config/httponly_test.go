package config

import (
	"testing"
)

// The settings only http and https listeners read are refused on a tcp or
// udp listener, which would ignore them, each by its name; on an http
// listener they load. Timeouts are refused on a udp listener only.
func TestValidation_HTTPOnlyKeysRefusedOnTCPAndUDP(t *testing.T) {
	keys := []struct {
		name string
		set  func(*Listener)
	}{
		{"routes", func(l *Listener) { l.Routes = []RouteConfig{{Match: RouteMatch{PathPrefix: "/"}, Backend: "be"}} }},
		{"headers", func(l *Listener) { l.Headers.ResponseRemove = []string{"Server"} }},
		{"compression", func(l *Listener) { l.Compression.Enabled = true }},
		{"cache", func(l *Listener) { l.Cache.DefaultTTL = "5m" }},
		{"error_pages", func(l *Listener) { l.ErrorPages = map[int]string{404: "/var/www/404.html"} }},
		{"buffering", func(l *Listener) { l.Buffering.ResponseBuffer = "64KB" }},
		{"max_body_size", func(l *Listener) { l.MaxBodySize = "10MB" }},
		{"ip_rate_limit", func(l *Listener) { l.IPRateLimit.RequestsPerSecond = 10 }},
		{"request_id", func(l *Listener) { l.RequestID.Enabled = true }},
		{"trusted_proxies", func(l *Listener) { l.TrustedProxies = []string{"10.0.0.0/8"} }},
	}
	for _, proto := range []string{"tcp", "udp"} {
		for _, k := range keys {
			l := Listener{Name: "l", Bind: ":7000", Protocol: proto, Backend: "be"}
			k.set(&l)
			wantErr(t, validate(baseCfg(l)), "listener l", k.name, "only http and https listeners read")
		}
	}
	// Two at once: both named.
	l := Listener{Name: "l", Bind: ":7000", Protocol: "tcp", Backend: "be", MaxBodySize: "1MB", TrustedProxies: []string{"10.0.0.0/8"}}
	wantErr(t, validate(baseCfg(l)), "max_body_size, trusted_proxies")

	// On an http listener every one of them loads.
	h := Listener{Name: "h", Bind: ":8080", Protocol: "http", Backend: "be"}
	for _, k := range keys {
		k.set(&h)
	}
	if err := validate(baseCfg(h)); err != nil {
		t.Fatalf("an http listener with every key: %v", err)
	}

	// Timeouts: refused on udp, read on tcp.
	u := Listener{Name: "u", Bind: ":5353", Protocol: "udp", Backend: "be", Timeouts: TimeoutConfig{Idle: "30s"}}
	wantErr(t, validate(baseCfg(u)), "listener u", "timeouts do nothing on a udp listener")
	tcp := Listener{Name: "t", Bind: ":7001", Protocol: "tcp", Backend: "be", Timeouts: TimeoutConfig{Idle: "30s", Connect: "2s"}}
	if err := validate(baseCfg(tcp)); err != nil {
		t.Fatalf("a tcp listener with timeouts: %v", err)
	}
	// An empty value of each is no setting.
	quiet := Listener{Name: "q", Bind: ":5354", Protocol: "udp", Backend: "be",
		Headers: HeadersConfig{RequestAdd: map[string]string{}}, Compression: CompressionConfig{Types: []string{}}}
	if err := validate(baseCfg(quiet)); err != nil {
		t.Fatalf("empty values on a udp listener: %v", err)
	}
}
