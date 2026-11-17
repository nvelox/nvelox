package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// validateControlPlane checks the admin API and metrics endpoint settings.
// The admin API changes the running proxy (drains and disables backends,
// blocks client IPs), so it never runs without an API key. An empty bind is
// allowed for both: they then listen on loopback only (admin 127.0.0.1:9091,
// metrics 127.0.0.1:9090).
func validateControlPlane(cfg *Config) error {
	if cfg.Admin.Enabled {
		if strings.TrimSpace(cfg.Admin.APIKey) == "" {
			return fmt.Errorf("admin.api_key is required when admin.enabled is true (use a long random value, e.g. the output of `openssl rand -hex 32`)")
		}
		if cfg.Admin.Bind != "" {
			if err := validateControlBind(cfg.Admin.Bind); err != nil {
				return fmt.Errorf("admin.bind %q: %v", cfg.Admin.Bind, err)
			}
		}
	}
	if cfg.Metrics.Enabled && cfg.Metrics.Bind != "" {
		if err := validateControlBind(cfg.Metrics.Bind); err != nil {
			return fmt.Errorf("metrics.bind %q: %v", cfg.Metrics.Bind, err)
		}
	}
	return nil
}

// validateControlBind accepts host:port with a numeric port, where host is
// an IP, a hostname, or empty (every address).
func validateControlBind(bind string) error {
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return fmt.Errorf("must be host:port, e.g. 127.0.0.1:9091 (%v)", err)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("port must be a number from 1 to 65535")
	}
	if strings.ContainsAny(host, " /\t") {
		return fmt.Errorf("invalid host %q", host)
	}
	return nil
}
