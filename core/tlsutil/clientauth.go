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
