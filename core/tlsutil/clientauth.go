package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"nvelox/config"
)

// ClientAuth is a listener's parsed client-certificate (mTLS) policy.
type ClientAuth struct {
	Mode tls.ClientAuthType
	CAs  *x509.CertPool // nil when no client_ca is configured
}

// Apply sets the policy on a server tls.Config.
func (c *ClientAuth) Apply(t *tls.Config) {
	if c == nil {
		return
	}
	t.ClientAuth = c.Mode
	t.ClientCAs = c.CAs
}

// Requires reports whether the handshake demands a verified client certificate.
func (c *ClientAuth) Requires() bool {
	return c != nil && c.Mode == tls.RequireAndVerifyClientCert
}

// LoadClientAuth parses client_auth / client_ca and reads the CA bundle. It
// returns (nil, nil) when client authentication is off ("" or "none") and an
// error for an unknown mode, "require" without client_ca, or a client_ca that
// cannot be read or holds no PEM certificate. Callers must fail startup /
// the reload on error: serving without the configured client check would be
// fail-open.
func LoadClientAuth(cfg config.TLSConfig) (*ClientAuth, error) {
	var ca ClientAuth
	switch strings.ToLower(strings.TrimSpace(cfg.ClientAuth)) {
	case "", "none":
		if cfg.ClientCA != "" {
			return nil, fmt.Errorf("client_ca is set but client_auth is %q", cfg.ClientAuth)
		}
		return nil, nil
	case "require":
		if cfg.ClientCA == "" {
			return nil, fmt.Errorf("client_auth 'require' needs client_ca to verify certificates")
		}
		ca.Mode = tls.RequireAndVerifyClientCert
	case "request":
		ca.Mode = tls.RequestClientCert
	default:
		return nil, fmt.Errorf("invalid client_auth value: %q (must be require, request, or none)", cfg.ClientAuth)
	}
	if cfg.ClientCA != "" {
		pool, err := config.LoadCertPool(cfg.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("client CA: %v", err)
		}
		ca.CAs = pool
	}
	return &ca, nil
}

// ConfigureClientAuth sets up client certificate authentication on a tls.Config.
func ConfigureClientAuth(tlsCfg *tls.Config, cfg config.TLSConfig) error {
	ca, err := LoadClientAuth(cfg)
	if err != nil {
		return err
	}
	ca.Apply(tlsCfg)
	return nil
}

// ClientAuthMode returns the tls.ClientAuthType for the given config string.
func ClientAuthMode(mode string) tls.ClientAuthType {
	switch strings.ToLower(mode) {
	case "require":
		return tls.RequireAndVerifyClientCert
	case "request":
		return tls.RequestClientCert
	default:
		return tls.NoClientCert
	}
}

// ParseTLSVersion turns a "1.2" / "1.3" config string into the tls.Version
// constant. Empty/unknown returns 0 so the caller can apply a default.
func ParseTLSVersion(s string) uint16 {
	switch strings.TrimSpace(s) {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	}
	return 0
}

// ResolveCipherSuites maps config cipher-suite names to their tls.CipherSuite
// constants. Unknown names return an error so operators don't silently get
// a mistyped cipher dropped. Only suites in Go's tls.CipherSuites() (i.e.
// the ones Go considers safe) are accepted.
func ResolveCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}
	byName := make(map[string]uint16, 32)
	for _, cs := range tls.CipherSuites() {
		byName[cs.Name] = cs.ID
	}
	out := make([]uint16, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		id, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("unknown or disallowed cipher suite %q", n)
		}
		out = append(out, id)
	}
	return out, nil
}

// ApplyTLSVersionAndCiphers sets MinVersion/MaxVersion/CipherSuites on the
// given tls.Config from the user-supplied config. Defaults: MinVersion
// TLS 1.2, MaxVersion TLS 1.3, Go's default cipher list. Returns an error
// if MinVersion > MaxVersion or a cipher name is unknown.
func ApplyTLSVersionAndCiphers(tlsCfg *tls.Config, cfg config.TLSConfig) error {
	minV := ParseTLSVersion(cfg.MinVersion)
	if minV == 0 {
		minV = tls.VersionTLS12
	}
	maxV := ParseTLSVersion(cfg.MaxVersion)
	if maxV == 0 {
		maxV = tls.VersionTLS13
	}
	if minV > maxV {
		return fmt.Errorf("tls min_version (%q) is higher than max_version (%q)", cfg.MinVersion, cfg.MaxVersion)
	}
	tlsCfg.MinVersion = minV
	tlsCfg.MaxVersion = maxV

	ids, err := ResolveCipherSuites(cfg.CipherSuites)
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		tlsCfg.CipherSuites = ids
	}
	return nil
}
