package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writePEMPair writes a self-signed CA certificate and its key to dir and
// returns their paths.
func writePEMPair(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func baseCfg(ls ...Listener) *Config {
	return &Config{
		Version:   "2",
		Backends:  []Backend{{Name: "be", Servers: []string{"10.0.0.1:80"}}},
		Listeners: ls,
	}
}

func wantErr(t *testing.T, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", parts)
	}
	for _, p := range parts {
		if !strings.Contains(err.Error(), p) {
			t.Fatalf("error %q does not contain %q", err.Error(), p)
		}
	}
}

// Keys that are parsed but have no implementation are refused at load, with
// an error naming the key, instead of silently doing nothing.
func TestValidation_UnimplementedKeysRejected(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePEMPair(t, dir, "srv")

	cases := []struct {
		name string
		l    Listener
		key  string
	}{
		{"sni_routes", Listener{Name: "l", Bind: ":443", Protocol: "tcp", Backend: "be",
			SNIRoutes: []SNIRoute{{ServerName: "a.example.com", Backend: "be"}}}, "sni_routes"},
		{"throttle read_rate", Listener{Name: "l", Bind: ":80", Protocol: "tcp", Backend: "be",
			Throttle: ThrottleConfig{ReadRate: "1MB/s"}}, "throttle"},
		{"throttle write_rate", Listener{Name: "l", Bind: ":80", Protocol: "http", Backend: "be",
			Throttle: ThrottleConfig{WriteRate: "1MB/s"}}, "throttle"},
		{"ocsp_stapling", Listener{Name: "l", Bind: ":443", Protocol: "https", Backend: "be",
			TLS: TLSConfig{Cert: cert, Key: key, OCSPStapling: true}}, "tls.ocsp_stapling"},
		{"route scripts", Listener{Name: "l", Bind: ":80", Protocol: "http", Backend: "be",
			Routes: []RouteConfig{{Match: RouteMatch{PathPrefix: "/"}, Backend: "be",
				Scripts: ScriptsConfig{RequestScript: "/etc/nvelox/auth.lua"}}}}, "scripts"},
		// Accepted and never read until 2.0.0: each was a setting that
		// promised something and did nothing.
		{"zero_copy", Listener{Name: "l", Bind: ":80", Protocol: "tcp", Backend: "be", ZeroCopy: true}, "zero_copy"},
		{"grpc", Listener{Name: "l", Bind: ":80", Protocol: "http", Backend: "be", GRPC: true}, "grpc"},
		{"auto_cert", Listener{Name: "l", Bind: ":443", Protocol: "https", Backend: "be",
			TLS: TLSConfig{Cert: cert, Key: key, AutoCert: true}}, "tls.auto_cert"},
		{"request_body_buffer", Listener{Name: "l", Bind: ":80", Protocol: "http", Backend: "be",
			Buffering: BufferingConfig{RequestBodyBuffer: "64KB"}}, "buffering.request_body_buffer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantErr(t, validate(baseCfg(c.l)), "listener l", c.key, "not implemented")
		})
	}

	// Explicitly-off values are fine, and so is the buffer that is read.
	ok := Listener{Name: "l", Bind: ":443", Protocol: "https", Backend: "be", ZeroCopy: false, GRPC: false,
		TLS: TLSConfig{Cert: cert, Key: key, OCSPStapling: false, AutoCert: false}, Buffering: BufferingConfig{ResponseBuffer: "256KB"}}
	if err := validate(baseCfg(ok)); err != nil {
		t.Fatalf("the keys set to off must load: %v", err)
	}
}

// The top-level and server.* keys nothing implements are refused too.
func TestValidation_UnimplementedServerKeysRejected(t *testing.T) {
	l := Listener{Name: "l", Bind: ":80", Protocol: "http", Backend: "be"}
	for name, set := range map[string]func(*Config){
		"tracing.enabled":  func(c *Config) { c.Tracing.Enabled = true },
		"tracing.endpoint": func(c *Config) { c.Tracing.Endpoint = "otel:4317" },
		"tracing.service":  func(c *Config) { c.Tracing.Service = "edge" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := baseCfg(l)
			set(cfg)
			wantErr(t, validate(cfg), "tracing is not implemented")
		})
	}
	// server.workers is the number of event loops: 0 (one per core) to
	// MaxWorkers; anything else is not a number of loops.
	for _, n := range []int{0, 1, 4, MaxWorkers} {
		cfg := baseCfg(l)
		cfg.Server.Workers = n
		if err := validate(cfg); err != nil {
			t.Fatalf("server.workers %d must load: %v", n, err)
		}
	}
	for _, n := range []int{-1, MaxWorkers + 1} {
		cfg := baseCfg(l)
		cfg.Server.Workers = n
		wantErr(t, validate(cfg), "server.workers", "not a number of event loops")
	}
	cfg := baseCfg(l)

	// server.pid_file is implemented: it loads, and without a warning.
	cfg = baseCfg(l)
	cfg.Server.PidFile = "/run/nvelox.pid"
	if err := validate(cfg); err != nil {
		t.Fatalf("server.pid_file must load: %v", err)
	}
	if w := ServerWarnings(cfg.Server); len(w) != 0 {
		t.Fatalf("server.pid_file: no warning, got %q", w)
	}
}

// The same keys through YAML, as an operator would write them.
func TestLoad_UnimplementedKeysRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nvelox.yaml")
	os.WriteFile(p, []byte(`
version: "2"
listeners:
  - name: passthrough
    bind: ":8443"
    protocol: tcp
    backend: be
    sni_routes:
      - server_name: "api.example.com"
        backend: be
backends:
  - name: be
    servers: ["10.0.0.1:443"]
`), 0o600)
	_, err := Load(p)
	wantErr(t, err, "listener passthrough", "sni_routes", "not implemented")
}

func TestValidation_L4ListenerRequiresBackend(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", ""} {
		err := validate(baseCfg(Listener{Name: "l", Bind: ":9000", Protocol: proto}))
		wantErr(t, err, "requires 'backend'")
	}
	if err := validate(baseCfg(Listener{Name: "l", Bind: ":9000", Protocol: "udp", Backend: "be"})); err != nil {
		t.Fatalf("udp listener with backend must load: %v", err)
	}
}

func TestValidation_L4ACLOnlySourceIP(t *testing.T) {
	httpOnly := []struct {
		name  string
		match ACLMatch
	}{
		{"path_prefix", ACLMatch{PathPrefix: "/admin"}},
		{"path_regex", ACLMatch{PathRegex: "^/admin"}},
		{"method", ACLMatch{Method: []string{"POST"}}},
		{"headers", ACLMatch{Headers: map[string]string{"X-A": "b"}}},
	}
	for _, proto := range []string{"tcp", "udp"} {
		for _, c := range httpOnly {
			t.Run(proto+"/"+c.name, func(t *testing.T) {
				l := Listener{Name: "l", Bind: ":9000", Protocol: proto, Backend: "be",
					ACL: []ACLRule{{Match: c.match, Action: "deny"}}}
				wantErr(t, validate(baseCfg(l)), c.name, "only source_ip")
			})
		}
		l := Listener{Name: "l", Bind: ":9000", Protocol: proto, Backend: "be", ACL: []ACLRule{
			{Match: ACLMatch{SourceIP: []string{"10.0.0.0/8", "192.0.2.1"}}, Action: "allow"},
			{Action: "deny"},
		}}
		if err := validate(baseCfg(l)); err != nil {
			t.Fatalf("%s: source_ip-only ACL must load: %v", proto, err)
		}
		l.ACL = []ACLRule{{Match: ACLMatch{SourceIP: []string{"10.0.0.0/8"}}, Action: "block"}}
		wantErr(t, validate(baseCfg(l)), "action must be")
	}
	// HTTP listeners keep their request matchers.
	l := Listener{Name: "l", Bind: ":80", Protocol: "http", Backend: "be",
		ACL: []ACLRule{{Match: ACLMatch{PathPrefix: "/admin", Method: []string{"POST"}}, Action: "deny"}}}
	if err := validate(baseCfg(l)); err != nil {
		t.Fatalf("http ACL with path/method must load: %v", err)
	}
}

// A malformed entry must fail the load on every protocol: dropping it could
// empty an allowlist (allow everyone) or turn an ACL rule into a match-all.
func TestValidation_IPListsMustParse(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", "http"} {
		bad := []Listener{
			{Name: "l", Bind: ":9000", Protocol: proto, Backend: "be", IPAllowlist: []string{"10.0.0.0/33"}},
			{Name: "l", Bind: ":9000", Protocol: proto, Backend: "be", IPDenylist: []string{"not-an-ip"}},
			{Name: "l", Bind: ":9000", Protocol: proto, Backend: "be",
				ACL: []ACLRule{{Match: ACLMatch{SourceIP: []string{"10.0.0.256"}}, Action: "allow"}}},
		}
		for i, l := range bad {
			if err := validate(baseCfg(l)); err == nil {
				t.Errorf("%s case %d: malformed IP/CIDR must be rejected", proto, i)
			}
		}
		good := Listener{Name: "l", Bind: ":9000", Protocol: proto, Backend: "be",
			IPAllowlist: []string{"10.0.0.0/8", "2001:db8::/32", "192.0.2.7"},
			IPDenylist:  []string{"10.9.9.9", "::1"}}
		if err := validate(baseCfg(good)); err != nil {
			t.Errorf("%s: valid lists must load: %v", proto, err)
		}
	}
}

func TestValidation_UDPWithTLSRejected(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePEMPair(t, dir, "srv")
	l := Listener{Name: "u", Bind: ":443", Protocol: "udp", Backend: "be", TLS: TLSConfig{Cert: cert, Key: key}}
	wantErr(t, validate(baseCfg(l)), "not supported on udp")
}

// TestValidation_UDPListenersCannotSharePort: a datagram is matched to its
// udp listener by port, so two udp listeners on one port — also on different
// addresses or through overlapping ranges — are refused; a tcp listener on
// the same port and udp listeners on other ports are not.
func TestValidation_UDPListenersCannotSharePort(t *testing.T) {
	udp := func(name, bind string) Listener {
		return Listener{Name: name, Bind: bind, Protocol: "udp", Backend: "be"}
	}
	refused := map[string][]Listener{
		"same address":       {udp("a", ":7000"), udp("b", ":7000")},
		"different address":  {udp("a", "10.0.0.1:7000"), udp("b", "192.0.2.1:7000")},
		"range and port":     {udp("a", ":17000-17100"), udp("b", "10.0.0.1:17050")},
		"overlapping ranges": {udp("a", ":17000-17100"), udp("b", ":17100-17200")},
	}
	for name, ls := range refused {
		t.Run(name, func(t *testing.T) {
			wantErr(t, validate(baseCfg(ls...)), "two udp listeners cannot share port", "listeners a and b")
		})
	}
	allowed := map[string][]Listener{
		"other ports":     {udp("a", ":7000"), udp("b", ":7001")},
		"adjacent ranges": {udp("a", ":17000-17100"), udp("b", ":17101-17200")},
		"tcp on the same port": {udp("a", ":7000"),
			{Name: "b", Bind: ":7000", Protocol: "tcp", Backend: "be"}},
	}
	for name, ls := range allowed {
		if err := validate(baseCfg(ls...)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidation_ClientAuth(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePEMPair(t, dir, "srv")
	ca, _ := writePEMPair(t, dir, "ca")
	notPEM := filepath.Join(dir, "garbage.pem")
	os.WriteFile(notPEM, []byte("not a certificate"), 0o600)

	cases := []struct {
		name    string
		tls     TLSConfig
		wantErr string
	}{
		{"require with CA", TLSConfig{Cert: cert, Key: key, ClientAuth: "require", ClientCA: ca}, ""},
		{"Require (case)", TLSConfig{Cert: cert, Key: key, ClientAuth: "Require", ClientCA: ca}, ""},
		{"request without CA", TLSConfig{Cert: cert, Key: key, ClientAuth: "request"}, ""},
		{"request with CA", TLSConfig{Cert: cert, Key: key, ClientAuth: "request", ClientCA: ca}, ""},
		{"none", TLSConfig{Cert: cert, Key: key, ClientAuth: "none"}, ""},
		{"unknown value", TLSConfig{Cert: cert, Key: key, ClientAuth: "required"}, "invalid"},
		{"require without CA", TLSConfig{Cert: cert, Key: key, ClientAuth: "require"}, "needs tls.client_ca"},
		{"CA file missing", TLSConfig{Cert: cert, Key: key, ClientAuth: "require", ClientCA: filepath.Join(dir, "nope.pem")}, "client_ca"},
		{"CA not PEM", TLSConfig{Cert: cert, Key: key, ClientAuth: "require", ClientCA: notPEM}, "no PEM certificate"},
		{"CA without client_auth", TLSConfig{Cert: cert, Key: key, ClientCA: ca}, "client_auth"},
		{"client_auth without TLS", TLSConfig{ClientAuth: "require", ClientCA: ca}, "TLS-terminating"},
	}
	for _, c := range cases {
		for _, proto := range []string{"tcp", "https"} {
			t.Run(c.name+"/"+proto, func(t *testing.T) {
				err := validate(baseCfg(Listener{Name: "l", Bind: ":443", Protocol: proto, Backend: "be", TLS: c.tls}))
				if c.wantErr == "" {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					return
				}
				wantErr(t, err, c.wantErr)
			})
		}
	}
}

func TestValidation_BackendTLS(t *testing.T) {
	dir := t.TempDir()
	ca, _ := writePEMPair(t, dir, "ca")
	clientCert, clientKey := writePEMPair(t, dir, "client")
	_, otherKey := writePEMPair(t, dir, "other")
	notPEM := filepath.Join(dir, "garbage.pem")
	os.WriteFile(notPEM, []byte("garbage"), 0o600)

	cases := []struct {
		name    string
		btls    BackendTLSConfig
		wantErr string
	}{
		{"system roots", BackendTLSConfig{Enabled: true}, ""},
		{"insecure", BackendTLSConfig{Enabled: true, Insecure: true}, ""},
		{"ca + mTLS", BackendTLSConfig{Enabled: true, CACert: ca, ClientCert: clientCert, ClientKey: clientKey}, ""},
		{"disabled with junk paths", BackendTLSConfig{Enabled: false, CACert: "/nonexistent"}, ""},
		{"ca missing", BackendTLSConfig{Enabled: true, CACert: filepath.Join(dir, "nope.pem")}, "ca_cert"},
		{"ca not PEM", BackendTLSConfig{Enabled: true, CACert: notPEM}, "no PEM certificate"},
		{"cert without key", BackendTLSConfig{Enabled: true, ClientCert: clientCert}, "both be set"},
		{"key without cert", BackendTLSConfig{Enabled: true, ClientKey: clientKey}, "both be set"},
		{"mismatched pair", BackendTLSConfig{Enabled: true, ClientCert: clientCert, ClientKey: otherKey}, "client_cert/client_key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &Config{
				Version:   "2",
				Backends:  []Backend{{Name: "be", Servers: []string{"10.0.0.1:443"}, BackendTLS: c.btls}},
				Listeners: []Listener{{Name: "web", Bind: ":80", Protocol: "http", Backend: "be"}},
			}
			err := validate(cfg)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			wantErr(t, err, "backend be", c.wantErr)
		})
	}
}

// backend_tls is implemented on the HTTP path only: a tcp/udp listener on a
// backend_tls backend would forward plaintext, so the pairing is refused.
func TestValidation_BackendTLSOnL4ListenerRejected(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		cfg := &Config{
			Version: "2",
			Backends: []Backend{
				{Name: "tlsbe", Servers: []string{"10.0.0.1:443"}, BackendTLS: BackendTLSConfig{Enabled: true}},
			},
			Listeners: []Listener{{Name: "l4", Bind: ":9000", Protocol: proto, Backend: "tlsbe"}},
		}
		wantErr(t, validate(cfg), "listener l4", "backend_tls", "not implemented for "+proto)
	}
}

// A server.* key that does nothing is refused at load
// (TestValidation_UnimplementedServerKeysRejected), so none of them is left
// to warn about: what remains are the server.http3 keys that change nothing
// on a platform (http3_test.go).
func TestServerWarnings(t *testing.T) {
	if w := ServerWarnings(ServerConfig{}); len(w) != 0 {
		t.Fatalf("no server keys set: want no warning, got %q", w)
	}
	if w := ServerWarnings(ServerConfig{PidFile: "/var/run/nvelox.pid", User: "nvelox", Group: "nvelox", GatewayID: "gw-1", ShutdownTimeout: "5s", Workers: 1}); len(w) != 0 {
		t.Fatalf("keys that are all implemented: want no warning, got %q", w)
	}
	// More loops than cores is allowed and said: it gains nothing.
	w := serverWarnings(ServerConfig{Workers: 16}, "linux", 8)
	if len(w) != 1 || !strings.Contains(w[0], "server.workers (16)") || !strings.Contains(w[0], "8 CPU cores") {
		t.Fatalf("16 workers on 8 cores: got %q", w)
	}
	if w := serverWarnings(ServerConfig{Workers: 8}, "linux", 8); len(w) != 0 {
		t.Fatalf("8 workers on 8 cores: no warning, got %q", w)
	}
}

// TestStartupWarnings_MetricsEveryAddress: metrics bound to every address
// starts, with a warning; loopback, a specific address and the empty default
// do not warn.
func TestStartupWarnings_MetricsEveryAddress(t *testing.T) {
	for bind, want := range map[string]bool{
		":9090": true, "0.0.0.0:9090": true, "[::]:9090": true,
		"": false, "127.0.0.1:9090": false, "[::1]:9090": false, "10.20.0.10:9090": false,
	} {
		cfg := &Config{Metrics: MetricsConfig{Enabled: true, Bind: bind}}
		got := strings.Contains(strings.Join(StartupWarnings(cfg), "\n"), "every address")
		if got != want {
			t.Errorf("metrics.bind %q: warning=%v, want %v", bind, got, want)
		}
	}
	cfg := &Config{Metrics: MetricsConfig{Enabled: false, Bind: ":9090"}}
	if w := StartupWarnings(cfg); len(w) != 0 {
		t.Errorf("metrics disabled: want no warning, got %q", w)
	}
}

// TestProxyKeysAndInterfaces: key files load (several keys, comments),
// short, empty or missing files fail the load, and the settings need their
// counterparts: a key needs accept_proxy_from, a send key needs
// send_proxy_v2, interfaces need a udp listener and accept_proxy_from.
func TestProxyKeysAndInterfaces(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.keys", "# rotation: new key first\n  "+strings.Repeat("n", 40)+"  \n\n"+strings.Repeat("o", 32)+"\n")
	short := write("short.keys", "too-short\n")
	empty := write("empty.keys", "# nothing\n\n")
	load := func(extra string) (*Config, error) {
		p := filepath.Join(dir, "c.yaml")
		cfg := "version: \"2\"\n" + extra
		if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
		return Load(p)
	}
	udp := func(fields string) string {
		return "listeners:\n  - name: relay\n    bind: \":7000\"\n    protocol: udp\n    backend: b\n" + fields +
			"backends:\n  - name: b\n    servers: [\"127.0.0.1:1\"]\n"
	}
	cfg, err := load(udp("    accept_proxy_from: [\"10.0.0.0/8\"]\n    accept_proxy_key_file: \"" + good + "\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if k := cfg.Listeners[0].AcceptProxyKeys; len(k) != 2 || string(k[0]) != strings.Repeat("n", 40) {
		t.Fatalf("keys %q", k)
	}
	if cfg.Listeners[0].ReplayWindowRequired() {
		t.Error("accept_proxy_replay_window unset: required")
	}
	for value, required := range map[string]bool{"when_present": false, "required": true} {
		cfg, err := load(udp("    accept_proxy_from: [\"10.0.0.0/8\"]\n    accept_proxy_key_file: \"" + good + "\"\n    accept_proxy_replay_window: " + value + "\n"))
		if err != nil {
			t.Fatalf("accept_proxy_replay_window %s: %v", value, err)
		}
		if got := cfg.Listeners[0].ReplayWindowRequired(); got != required {
			t.Errorf("accept_proxy_replay_window %s: required %v", value, got)
		}
	}
	cfg, err = load("listeners:\n  - name: l\n    bind: \":7001\"\n    protocol: tcp\n    backend: b\n" +
		"backends:\n  - name: b\n    servers: [\"127.0.0.1:1\"]\n    send_proxy_v2: true\n    send_proxy_key_file: \"" + good + "\"\n")
	if err != nil || string(cfg.Backends[0].SendProxyKey) != strings.Repeat("n", 40) {
		t.Fatalf("send key: %v %q", err, cfg.Backends[0].SendProxyKey)
	}
	for name, c := range map[string]struct{ extra, want string }{
		"short key":         {udp("    accept_proxy_from: [\"10.0.0.0/8\"]\n    accept_proxy_key_file: \"" + short + "\"\n"), "shorter than 32"},
		"no key":            {udp("    accept_proxy_from: [\"10.0.0.0/8\"]\n    accept_proxy_key_file: \"" + empty + "\"\n"), "no key"},
		"missing file":      {udp("    accept_proxy_from: [\"10.0.0.0/8\"]\n    accept_proxy_key_file: \"" + dir + "/nope\"\n"), "no such file"},
		"key without trust": {udp("    accept_proxy_key_file: \"" + good + "\"\n"), "needs accept_proxy_from"},
		"replay window, another value": {udp("    accept_proxy_from: [\"10.0.0.0/8\"]\n    accept_proxy_key_file: \"" + good + "\"\n    accept_proxy_replay_window: always\n"),
			`accept_proxy_replay_window "always": want when_present or required`},
		"replay window without a key file": {udp("    accept_proxy_from: [\"10.0.0.0/8\"]\n    accept_proxy_replay_window: required\n"), "accept_proxy_replay_window needs accept_proxy_key_file"},
		"interfaces on tcp": {"listeners:\n  - name: l\n    bind: \":7002\"\n    protocol: tcp\n    backend: b\n    accept_proxy_from: [\"10.0.0.0/8\"]\n    accept_proxy_interfaces: [\"eth1\"]\n" +
			"backends:\n  - name: b\n    servers: [\"127.0.0.1:1\"]\n", "applies to udp listeners"},
		"interfaces without trust": {udp("    accept_proxy_interfaces: [\"eth1\"]\n"), "needs accept_proxy_from"},
		"send key without send_proxy_v2": {"listeners:\n  - name: l\n    bind: \":7003\"\n    protocol: tcp\n    backend: b\n" +
			"backends:\n  - name: b\n    servers: [\"127.0.0.1:1\"]\n    send_proxy_key_file: \"" + good + "\"\n", "needs send_proxy_v2"},
		// HTTP/3 through relays: a UDP source address proves nothing, so the
		// relays' headers must be signed.
		"http3 relays without a key file": {"listeners:\n  - name: l\n    bind: \":7004\"\n    protocol: https\n    http3: true\n    backend: b\n" +
			"    tls:\n      cert: \"" + good + "\"\n      key: \"" + good + "\"\n    accept_proxy_from: [\"10.0.0.0/8\"]\n" +
			"backends:\n  - name: b\n    servers: [\"127.0.0.1:1\"]\n", "http3 with accept_proxy_from needs accept_proxy_key_file"},
	} {
		if _, err := load(c.extra); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

// TestStartupWarnings_UDPAddressOnlyTrust: a udp listener that trusts
// PROXY headers by source address alone warns; a key or interfaces, or a tcp
// listener, do not.
func TestStartupWarnings_UDPAddressOnlyTrust(t *testing.T) {
	warn := func(l Listener) bool {
		return strings.Contains(strings.Join(StartupWarnings(&Config{Listeners: []Listener{l}}), "\n"), "trusts the source address alone")
	}
	trust := []string{"10.0.0.0/8"}
	if !warn(Listener{Name: "u", Protocol: "udp", AcceptProxyFrom: trust}) {
		t.Error("udp, address only: no warning")
	}
	for name, l := range map[string]Listener{
		"udp with key":        {Name: "u", Protocol: "udp", AcceptProxyFrom: trust, AcceptProxyKeyFile: "/k"},
		"udp with interfaces": {Name: "u", Protocol: "udp", AcceptProxyFrom: trust, AcceptProxyInterfaces: []string{"eth1"}},
		"tcp":                 {Name: "t", Protocol: "tcp", AcceptProxyFrom: trust},
		"udp without trust":   {Name: "u", Protocol: "udp"},
	} {
		if warn(l) {
			t.Errorf("%s: unexpected warning", name)
		}
	}
}

// TestStartupWarnings_RelayInTrustedProxies: on an http or https listener
// trusted_proxies is matched against the client a relay names, so a relay
// listed there too is reported.
func TestStartupWarnings_RelayInTrustedProxies(t *testing.T) {
	warn := func(l Listener) bool {
		return strings.Contains(strings.Join(StartupWarnings(&Config{Listeners: []Listener{l}}), "\n"), "overlaps accept_proxy_from")
	}
	for name, l := range map[string]Listener{
		"same range":              {Name: "h", Protocol: "http", AcceptProxyFrom: []string{"10.0.0.0/24"}, TrustedProxies: []string{"10.0.0.0/24"}},
		"relay inside the list":   {Name: "h", Protocol: "https", AcceptProxyFrom: []string{"10.0.0.0/24"}, TrustedProxies: []string{"192.0.2.1", " 10.0.0.0/8 "}},
		"proxy inside the relays": {Name: "h", Protocol: "http", AcceptProxyFrom: []string{"10.0.0.0/8"}, TrustedProxies: []string{"10.1.2.3"}},
		"ipv6":                    {Name: "h", Protocol: "http", AcceptProxyFrom: []string{"2001:db8::/32"}, TrustedProxies: []string{"2001:db8:1::1"}},
	} {
		if !warn(l) {
			t.Errorf("%s: no warning", name)
		}
	}
	for name, l := range map[string]Listener{
		"apart":          {Name: "h", Protocol: "http", AcceptProxyFrom: []string{"10.0.0.0/24"}, TrustedProxies: []string{"10.0.1.0/24", "192.0.2.0/24"}},
		"no relays":      {Name: "h", Protocol: "http", TrustedProxies: []string{"10.0.0.0/8"}},
		"no proxies":     {Name: "h", Protocol: "https", AcceptProxyFrom: []string{"10.0.0.0/8"}},
		"tcp listener":   {Name: "t", Protocol: "tcp", AcceptProxyFrom: []string{"10.0.0.0/8"}, TrustedProxies: []string{"10.0.0.0/8"}},
		"other families": {Name: "h", Protocol: "http", AcceptProxyFrom: []string{"10.0.0.0/8"}, TrustedProxies: []string{"2001:db8::/32"}},
	} {
		if warn(l) {
			t.Errorf("%s: unexpected warning", name)
		}
	}
}
