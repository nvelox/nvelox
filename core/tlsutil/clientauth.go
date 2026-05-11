package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"nvelox/config"
)

// ConfigureClientAuth sets up client certificate authentication on a tls.Config.
func ConfigureClientAuth(tlsCfg *tls.Config, cfg config.TLSConfig) error {
	if cfg.ClientAuth == "" || strings.ToLower(cfg.ClientAuth) == "none" {
		return nil
	}

	switch strings.ToLower(cfg.ClientAuth) {
	case "require":
		if cfg.ClientCA == "" {
			return fmt.Errorf("client_auth 'require' needs client_ca to verify certificates")
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	case "request":
		tlsCfg.ClientAuth = tls.RequestClientCert
	default:
		return fmt.Errorf("invalid client_auth value: %q (must be require, request, or none)", cfg.ClientAuth)
	}

	if cfg.ClientCA != "" {
		caCert, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return fmt.Errorf("failed to read client CA cert: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse client CA cert")
		}
		tlsCfg.ClientCAs = pool
	}

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
