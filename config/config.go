package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration for the proxy server.
type Config struct {
	Listeners []Listener `yaml:"listeners"`
	Backends  []Backend  `yaml:"backends"`
}

// Listener defines a frontend listener.
type Listener struct {
	Name           string `yaml:"name"`
	Bind           string `yaml:"bind"`            // e.g., ":80" or "*:1024-2048"
	Protocol       string `yaml:"protocol"`        // "tcp" or "udp"
	ZeroCopy       bool   `yaml:"zero_copy"`       // Use splice for TCP
	DefaultBackend string `yaml:"default_backend"` // Name of the backend pool
}

// Backend defines a server pool.
type Backend struct {
	Name        string   `yaml:"name"`
	Balance     string   `yaml:"balance"`       // "roundrobin", "leastconn", "random"
	SendProxyV2 bool     `yaml:"send_proxy_v2"` // Send PROXY Protocol v2 header to backend
	Servers     []string `yaml:"servers"`       // List of server addresses
}

// Load reads the configuration from a file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	backendNames := make(map[string]bool)
	for _, b := range cfg.Backends {
		if b.Name == "" {
			return fmt.Errorf("backend must have a name")
		}
		if backendNames[b.Name] {
			return fmt.Errorf("duplicate backend name: %s", b.Name)
		}
		backendNames[b.Name] = true
	}

	for _, l := range cfg.Listeners {
		if l.Name == "" {
			return fmt.Errorf("listener must have a name")
		}
		if l.Bind == "" {
			return fmt.Errorf("listener %s must have a bind address", l.Name)
		}
		if l.DefaultBackend != "" && !backendNames[l.DefaultBackend] {
			return fmt.Errorf("listener %s references unknown backend: %s", l.Name, l.DefaultBackend)
		}
	}

	return nil
}
