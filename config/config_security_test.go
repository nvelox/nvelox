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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantErr(t, validate(baseCfg(c.l)), c.key, "not implemented")
		})
	}

	// Explicitly-off values are fine.
	ok := Listener{Name: "l", Bind: ":443", Protocol: "https", Backend: "be",
		TLS: TLSConfig{Cert: cert, Key: key, OCSPStapling: false}}
	if err := validate(baseCfg(ok)); err != nil {
		t.Fatalf("ocsp_stapling: false must load: %v", err)
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

func TestServerWarnings(t *testing.T) {
	if w := ServerWarnings(ServerConfig{}); len(w) != 0 {
		t.Fatalf("no server keys set: want no warning, got %q", w)
	}
	w := ServerWarnings(ServerConfig{PidFile: "/var/run/nvelox.pid", Workers: 4})
	joined := strings.Join(w, "\n")
	if len(w) != 2 || !strings.Contains(joined, "server.pid_file") || !strings.Contains(joined, "server.workers") {
		t.Fatalf("pid_file + workers: got %q", w)
	}
	if !strings.Contains(joined, "not implemented") {
		t.Errorf("warnings must say the keys are not implemented: %q", w)
	}
}

// TestStartupWarnings_MetricsEveryAddress (D3): metrics bound to every address
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
