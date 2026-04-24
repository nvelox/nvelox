package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration for the proxy server.
type Config struct {
	Version string        `yaml:"version"`
	Server  ServerConfig  `yaml:"server"`
	Logging LoggingConfig `yaml:"logging"`
	Metrics MetricsConfig `yaml:"metrics,omitempty"`
	Admin   AdminConfig   `yaml:"admin,omitempty"`
	Tracing TracingConfig `yaml:"tracing,omitempty"`
	Include string        `yaml:"include"`

	Listeners []Listener `yaml:"listeners"`
	Backends  []Backend  `yaml:"backends"`
}

// MetricsConfig defines the Prometheus metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Bind    string `yaml:"bind"`
	Path    string `yaml:"path"`
}

// AdminConfig defines the admin REST API endpoint.
type AdminConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Bind     string `yaml:"bind"`      // e.g., "127.0.0.1:9091"
	APIKey   string `yaml:"api_key"`   // Required for all requests (via X-API-Key header)
}

// TracingConfig defines OpenTelemetry tracing settings.
type TracingConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"` // OTLP endpoint
	Service  string `yaml:"service"`  // service name
}

// ThrottleConfig defines bandwidth throttling settings.
type ThrottleConfig struct {
	ReadRate  string `yaml:"read_rate,omitempty"`  // e.g., "10MB/s"
	WriteRate string `yaml:"write_rate,omitempty"` // e.g., "10MB/s"
}

type ServerConfig struct {
	User    string `yaml:"user"`
	Group   string `yaml:"group"`
	PidFile string `yaml:"pid_file"`
	Workers int    `yaml:"workers,omitempty"` // SO_REUSEPORT workers (0 = single process)
}

type LoggingConfig struct {
	Level     string `yaml:"level"`      // debug, info, warning, error
	AccessLog string `yaml:"access_log"` // path to access log
	ErrorLog  string `yaml:"error_log"`  // path to error log
}

// Listener defines a frontend listener.
type Listener struct {
	Name           string `yaml:"name"`
	Bind           string `yaml:"bind"`            // e.g., ":80" or "*:1024-2048"
	Protocol       string `yaml:"protocol"`        // "tcp", "udp", "http", "https"
	ZeroCopy       bool   `yaml:"zero_copy"`       // Use splice for TCP
	DefaultBackend string `yaml:"default_backend"` // Name of the backend pool

	// Rate limiting
	RateLimit RateLimitConfig `yaml:"rate_limit,omitempty"`

	// Timeouts
	Timeouts TimeoutConfig `yaml:"timeouts,omitempty"`

	// TLS
	TLS TLSConfig `yaml:"tls,omitempty"`

	// SNI routing (TLS passthrough without termination)
	SNIRoutes []SNIRoute `yaml:"sni_routes,omitempty"`

	// Security
	IPAllowlist []string          `yaml:"ip_allowlist,omitempty"` // CIDR allow list
	IPDenylist  []string          `yaml:"ip_denylist,omitempty"`  // CIDR deny list
	MaxBodySize string            `yaml:"max_body_size,omitempty"` // e.g., "10MB"
	IPRateLimit IPRateLimitConfig `yaml:"ip_rate_limit,omitempty"`
	ACL         []ACLRule         `yaml:"acl,omitempty"`

	// TrustedProxies: CIDRs whose X-Forwarded-For / X-Real-IP / X-Forwarded-Proto
	// headers are trusted and extended. Requests from any other source have
	// these headers *replaced* (not appended) so a direct client can't spoof
	// their source IP by presenting a forged XFF chain.
	// If empty, no peer is trusted → XFF is always replaced with the peer IP.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`

	// L7 fields
	HTTP3       bool              `yaml:"http3,omitempty"`
	Routes      []RouteConfig     `yaml:"routes,omitempty"`
	Headers     HeadersConfig     `yaml:"headers,omitempty"`
	Compression CompressionConfig `yaml:"compression,omitempty"`
	ErrorPages  map[int]string    `yaml:"error_pages,omitempty"` // status code -> file path
	Root        string            `yaml:"root,omitempty"`        // Document root for static files
	Buffering   BufferingConfig   `yaml:"buffering,omitempty"`
	Cache       CacheConfig       `yaml:"cache,omitempty"`
	GRPC        bool              `yaml:"grpc,omitempty"`        // Enable gRPC-aware proxying
	Throttle    ThrottleConfig    `yaml:"throttle,omitempty"`    // Bandwidth throttling
}

// BufferingConfig defines request/response buffer sizes.
type BufferingConfig struct {
	RequestBodyBuffer string `yaml:"request_body_buffer,omitempty"` // e.g., "64KB"
	ResponseBuffer    string `yaml:"response_buffer,omitempty"`     // e.g., "256KB"
}

// CacheConfig defines response caching settings.
type CacheConfig struct {
	Enabled    bool     `yaml:"enabled"`
	MaxSize    string   `yaml:"max_size,omitempty"`    // e.g., "256MB"
	DefaultTTL string   `yaml:"default_ttl,omitempty"` // e.g., "5m"
	Methods    []string `yaml:"methods,omitempty"`     // default ["GET"]
}

// CompressionConfig defines response compression settings.
type CompressionConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Types     []string `yaml:"types,omitempty"`      // content types to compress
	MinLength int      `yaml:"min_length,omitempty"` // minimum response size in bytes
}

// IPRateLimitConfig defines per-IP rate limiting.
type IPRateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

// ACLRule defines an access control rule.
type ACLRule struct {
	Match  ACLMatch `yaml:"match"`
	Action string   `yaml:"action"` // "allow" or "deny"
}

// ACLMatch defines conditions for an ACL rule.
type ACLMatch struct {
	SourceIP []string          `yaml:"source_ip,omitempty"` // CIDR notation
	Method   []string          `yaml:"method,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
}

// RateLimitConfig defines per-listener connection rate limiting.
type RateLimitConfig struct {
	ConnectionsPerSecond float64 `yaml:"connections_per_second"`
	Burst                int     `yaml:"burst"`
}

// TLSConfig defines TLS certificate configuration.
type TLSConfig struct {
	Cert          string `yaml:"cert"`
	Key           string `yaml:"key"`
	AutoCert      bool   `yaml:"auto_cert"`
	OCSPStapling  bool   `yaml:"ocsp_stapling,omitempty"`  // Enable OCSP stapling
	ClientAuth    string `yaml:"client_auth,omitempty"`     // "require", "request", "none"
	ClientCA      string `yaml:"client_ca,omitempty"`       // CA cert for client verification
}

// RouteConfig defines an L7 route matching rule.
type RouteConfig struct {
	Match    RouteMatch     `yaml:"match"`
	Backend  string         `yaml:"backend,omitempty"`
	Headers  HeadersConfig  `yaml:"headers,omitempty"`
	Rewrite  RewriteConfig  `yaml:"rewrite,omitempty"`
	Redirect RedirectConfig `yaml:"redirect,omitempty"`
	Scripts  ScriptsConfig  `yaml:"scripts,omitempty"`
	Static   StaticConfig   `yaml:"static,omitempty"`   // Serve static files
	TryFiles TryFilesConfig `yaml:"try_files,omitempty"` // try_files logic
	Expires  string         `yaml:"expires,omitempty"`   // Cache-Control: "1y", "30d", "1h", "-1" (no cache)
	FastCGI  FastCGIConfig  `yaml:"fastcgi,omitempty"`   // Forward to FastCGI (PHP-FPM)
}

// FastCGIConfig defines FastCGI upstream (e.g., PHP-FPM) settings.
type FastCGIConfig struct {
	Pass         string            `yaml:"pass"`                    // FastCGI address (e.g., "127.0.0.1:9000" or "unix:/var/run/php-fpm.sock")
	DocumentRoot string            `yaml:"document_root,omitempty"` // DOCUMENT_ROOT for SCRIPT_FILENAME
	ScriptName   string            `yaml:"script_name,omitempty"`   // Override SCRIPT_NAME (default: from URL path)
	SplitPathInfo string           `yaml:"split_path_info,omitempty"` // Regex to split PATH_INFO (like fastcgi_split_path_info)
	Params       map[string]string `yaml:"params,omitempty"`        // Extra FastCGI params
	Index        string            `yaml:"index,omitempty"`         // Default script (e.g., "index.php")
}

// StaticConfig defines static file serving.
type StaticConfig struct {
	Root      string   `yaml:"root"`                  // Document root directory
	Index     []string `yaml:"index,omitempty"`        // Index files (default: ["index.html"])
	Autoindex bool     `yaml:"autoindex,omitempty"`    // Directory listing
}

// TryFilesConfig defines try_files behavior.
type TryFilesConfig struct {
	Files    []string `yaml:"files"`     // e.g., ["$uri", "$uri/", "/index.php$is_args$args"]
	Fallback string   `yaml:"fallback"`  // Fallback path or =status (e.g., "=404", "/fallback.html")
}

// ScriptsConfig defines Lua script hooks for a route.
type ScriptsConfig struct {
	RequestScript  string `yaml:"request_script,omitempty"`  // path to Lua file
	ResponseScript string `yaml:"response_script,omitempty"` // path to Lua file
}

// RouteMatch defines the conditions for matching an HTTP request.
type RouteMatch struct {
	Host       string `yaml:"host,omitempty"`        // Exact host match (case-insensitive)
	PathPrefix string `yaml:"path_prefix,omitempty"` // URL path prefix match
	PathRegex  string `yaml:"path_regex,omitempty"`  // Regex path match (captures available for rewrite)
}

// RewriteConfig defines URL rewriting.
type RewriteConfig struct {
	Path string `yaml:"path,omitempty"` // Replace path (supports $1 captures from regex)
}

// RedirectConfig defines HTTP redirect responses.
type RedirectConfig struct {
	URL  string `yaml:"url,omitempty"`
	Code int    `yaml:"code,omitempty"` // 301 or 302 (default 302)
}

// SNIRoute defines TLS passthrough routing based on server name.
type SNIRoute struct {
	ServerName string `yaml:"server_name"` // hostname or *.example.com pattern
	Backend    string `yaml:"backend"`
}

// TimeoutConfig defines configurable timeouts for listeners and backends.
type TimeoutConfig struct {
	Connect string `yaml:"connect,omitempty"` // dial timeout (default "10s")
	Read    string `yaml:"read,omitempty"`    // read timeout
	Write   string `yaml:"write,omitempty"`   // write timeout
	Idle    string `yaml:"idle,omitempty"`    // idle connection timeout
}

// ParseConnect returns the connect timeout duration, defaulting to 10s.
func (t TimeoutConfig) ParseConnect() time.Duration {
	if t.Connect == "" {
		return 10 * time.Second
	}
	d, err := time.ParseDuration(t.Connect)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

// ParseRead returns the read timeout duration, or 0 (no timeout) if not set.
func (t TimeoutConfig) ParseRead() time.Duration {
	if t.Read == "" {
		return 0
	}
	d, _ := time.ParseDuration(t.Read)
	return d
}

// ParseWrite returns the write timeout duration, or 0 (no timeout) if not set.
func (t TimeoutConfig) ParseWrite() time.Duration {
	if t.Write == "" {
		return 0
	}
	d, _ := time.ParseDuration(t.Write)
	return d
}

// ParseIdle returns the idle timeout duration, or 0 (no timeout) if not set.
func (t TimeoutConfig) ParseIdle() time.Duration {
	if t.Idle == "" {
		return 0
	}
	d, _ := time.ParseDuration(t.Idle)
	return d
}

// HeadersConfig defines request/response header manipulation.
type HeadersConfig struct {
	RequestAdd     map[string]string `yaml:"request_add,omitempty"`
	RequestSet     map[string]string `yaml:"request_set,omitempty"`
	RequestRemove  []string          `yaml:"request_remove,omitempty"`
	ResponseAdd    map[string]string `yaml:"response_add,omitempty"`
	ResponseSet    map[string]string `yaml:"response_set,omitempty"`
	ResponseRemove []string          `yaml:"response_remove,omitempty"`
}

// Backend defines a server pool.
type Backend struct {
	Name           string   `yaml:"name"`
	Balance        string   `yaml:"balance"`          // "roundrobin", "leastconn", "random"
	SendProxyV2    bool     `yaml:"send_proxy_v2"`    // Send PROXY Protocol v2 header to backend
	Servers        []string `yaml:"servers"`          // List of server addresses
	MaxConnections int      `yaml:"max_connections"`  // Max concurrent connections (0 = unlimited)

	Timeouts      TimeoutConfig     `yaml:"timeouts,omitempty"`
	Retry         RetryConfig       `yaml:"retry,omitempty"`
	StickySession StickyConfig      `yaml:"sticky_session,omitempty"`
	ResolveInterval string           `yaml:"resolve_interval,omitempty"` // DNS re-resolve interval
	// AllowPrivateIPs: if true, backend hostnames may resolve to RFC1918,
	// loopback, link-local or CGNAT addresses. Default (false) blocks these
	// to prevent DNS-rebinding / SSRF when a hostname is attacker-controlled.
	// Set to true only when backends legitimately live on a private network.
	AllowPrivateIPs bool              `yaml:"allow_private_ips,omitempty"`
	BackendTLS     BackendTLSConfig  `yaml:"backend_tls,omitempty"`
	CircuitBreaker CBConfig         `yaml:"circuit_breaker,omitempty"`
	HealthCheck    HealthCheckConfig `yaml:"health_check,omitempty"`
}

// CBConfig defines circuit breaker settings per backend.
type CBConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Threshold   int    `yaml:"threshold"`       // failures to open
	Timeout     string `yaml:"timeout"`          // time in open state before half-open
	HalfOpenMax int    `yaml:"half_open_max"`    // max requests in half-open
}

// BackendTLSConfig defines TLS settings for connecting to backend servers.
type BackendTLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CACert     string `yaml:"ca_cert,omitempty"`
	ClientCert string `yaml:"client_cert,omitempty"`
	ClientKey  string `yaml:"client_key,omitempty"`
	Insecure   bool   `yaml:"insecure,omitempty"` // skip certificate verification
}

// RetryConfig defines retry behavior on backend failure.
type RetryConfig struct {
	Attempts int    `yaml:"attempts"` // max attempts (default 1 = no retry)
	On       string `yaml:"on"`       // comma-separated: "connect_failure,502,503"
}

// StickyConfig defines session persistence.
type StickyConfig struct {
	Type       string `yaml:"type"`        // "cookie", "header", "ip_hash"
	CookieName string `yaml:"cookie_name"` // for cookie type (default "NVELOX_SRV")
	HeaderName string `yaml:"header_name"` // for header type
	TTL        string `yaml:"ttl"`         // session TTL (default "1h")
}

type HealthCheckConfig struct {
	Active  ActiveHealthCheck  `yaml:"active,omitempty"`
	Passive PassiveHealthCheck `yaml:"passive,omitempty"`
}

type ActiveHealthCheck struct {
	Type     string `yaml:"type"`     // tcp, http
	Path     string `yaml:"path"`     // for http
	Interval string `yaml:"interval"` // duration string
	Timeout  string `yaml:"timeout"`  // duration string
}

type PassiveHealthCheck struct {
	MaxFails int `yaml:"max_fails"`
}

// Load reads the configuration from a file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Load main config
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Process Include
	if cfg.Include != "" {
		matches, err := filepath.Glob(cfg.Include)
		if err != nil {
			return nil, fmt.Errorf("bad include glob pattern: %w", err)
		}

		for _, match := range matches {
			subData, err := os.ReadFile(match)
			if err != nil {
				// Warn but continue? Or fail? Nginx fails usually.
				return nil, fmt.Errorf("failed to read included config %s: %w", match, err)
			}
			var subCfg Config
			if err := yaml.Unmarshal(subData, &subCfg); err != nil {
				return nil, fmt.Errorf("failed to parse included config %s: %w", match, err)
			}

			// Append lists
			cfg.Listeners = append(cfg.Listeners, subCfg.Listeners...)
			cfg.Backends = append(cfg.Backends, subCfg.Backends...)
		}
	}

	// Apply Defaults
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	for i := range cfg.Listeners {
		if cfg.Listeners[i].Protocol == "" {
			cfg.Listeners[i].Protocol = "tcp"
		}
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	if cfg.Version != "2" {
		return fmt.Errorf("unsupported version: %s (expected '2')", cfg.Version)
	}

	backendNames := make(map[string]bool)
	validAlgorithms := map[string]bool{"": true, "roundrobin": true, "leastconn": true, "random": true}

	for _, b := range cfg.Backends {
		if b.Name == "" {
			return fmt.Errorf("backend must have a name")
		}
		if backendNames[b.Name] {
			return fmt.Errorf("duplicate backend name: %s", b.Name)
		}
		backendNames[b.Name] = true

		if len(b.Servers) == 0 {
			return fmt.Errorf("backend %s must have at least one server", b.Name)
		}

		if !validAlgorithms[b.Balance] {
			return fmt.Errorf("backend %s has invalid balance algorithm: %q (must be roundrobin, leastconn, or random)", b.Name, b.Balance)
		}

		for _, s := range b.Servers {
			if s == "" {
				return fmt.Errorf("backend %s has empty server address", b.Name)
			}
			if _, _, err := net.SplitHostPort(s); err != nil {
				// Allow bare IP/hostname without port (1:1 port mapping for port ranges)
				if net.ParseIP(s) != nil {
					continue // valid bare IP
				}
				// Not a bare IP — reject if it has invalid chars, allow hostnames
				if strings.ContainsAny(s, ":/ ") {
					return fmt.Errorf("backend %s has invalid server address %q: %v", b.Name, s, err)
				}
			}
		}

		if b.HealthCheck.Active.Interval != "" {
			if _, err := time.ParseDuration(b.HealthCheck.Active.Interval); err != nil {
				return fmt.Errorf("backend %s has invalid health check interval %q: %v", b.Name, b.HealthCheck.Active.Interval, err)
			}
		}
		if b.HealthCheck.Active.Timeout != "" {
			if _, err := time.ParseDuration(b.HealthCheck.Active.Timeout); err != nil {
				return fmt.Errorf("backend %s has invalid health check timeout %q: %v", b.Name, b.HealthCheck.Active.Timeout, err)
			}
		}

		// Validate backend timeouts
		if b.Timeouts.Connect != "" {
			if _, err := time.ParseDuration(b.Timeouts.Connect); err != nil {
				return fmt.Errorf("backend %s has invalid connect timeout %q: %v", b.Name, b.Timeouts.Connect, err)
			}
		}
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

		// Validate bind address format
		if err := validateBindAddress(l.Bind); err != nil {
			return fmt.Errorf("listener %s has invalid bind address %q: %v", l.Name, l.Bind, err)
		}

		// Validate TLS config
		if l.TLS.Cert != "" || l.TLS.Key != "" {
			if l.TLS.Cert == "" {
				return fmt.Errorf("listener %s: TLS key is set but cert is missing", l.Name)
			}
			if l.TLS.Key == "" {
				return fmt.Errorf("listener %s: TLS cert is set but key is missing", l.Name)
			}
			if _, err := os.Stat(l.TLS.Cert); err != nil {
				return fmt.Errorf("listener %s: TLS cert file not found: %v", l.Name, err)
			}
			if _, err := os.Stat(l.TLS.Key); err != nil {
				return fmt.Errorf("listener %s: TLS key file not found: %v", l.Name, err)
			}
		}

		// Validate listener timeouts
		for _, field := range []struct{ name, val string }{
			{"connect", l.Timeouts.Connect}, {"read", l.Timeouts.Read},
			{"write", l.Timeouts.Write}, {"idle", l.Timeouts.Idle},
		} {
			if field.val != "" {
				if _, err := time.ParseDuration(field.val); err != nil {
					return fmt.Errorf("listener %s has invalid %s timeout %q: %v", l.Name, field.name, field.val, err)
				}
			}
		}

		// Validate HTTP/HTTPS listener requirements
		if l.Protocol == "http" || l.Protocol == "https" {
			if l.DefaultBackend == "" && len(l.Routes) == 0 {
				return fmt.Errorf("listener %s: HTTP listener requires default_backend or routes", l.Name)
			}
			if l.Protocol == "https" && l.TLS.Cert == "" {
				return fmt.Errorf("listener %s: HTTPS listener requires TLS cert/key", l.Name)
			}
			for i, r := range l.Routes {
				hasRedirect := r.Redirect.URL != ""
				hasFastCGI := r.FastCGI.Pass != ""
				hasStatic := r.Static.Root != ""
				// Backend is required unless the route is a redirect, fastcgi, or static-only
				if r.Backend == "" && !hasRedirect && !hasFastCGI && !hasStatic {
					return fmt.Errorf("listener %s: route %d must have a backend", l.Name, i)
				}
				if r.Backend != "" && !backendNames[r.Backend] {
					return fmt.Errorf("listener %s: route %d references unknown backend: %s", l.Name, i, r.Backend)
				}
				if r.Match.Host == "" && r.Match.PathPrefix == "" && r.Match.PathRegex == "" {
					return fmt.Errorf("listener %s: route %d must have at least host, path_prefix, or path_regex", l.Name, i)
				}
			}
		}

		// Validate HTTP3 requires HTTPS
		if l.HTTP3 && l.Protocol != "https" {
			return fmt.Errorf("listener %s: http3 requires protocol 'https'", l.Name)
		}
	}

	return nil
}

func validateBindAddress(addr string) error {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return fmt.Errorf("missing port")
	}
	portStr := addr[lastColon+1:]

	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) != 2 {
			return fmt.Errorf("invalid port range format")
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("invalid range start port: %v", err)
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid range end port: %v", err)
		}
		if start < 1 || start > 65535 || end < 1 || end > 65535 {
			return fmt.Errorf("port out of range (1-65535)")
		}
		if start > end {
			return fmt.Errorf("port range start (%d) is greater than end (%d)", start, end)
		}
		return nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %v", err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", port)
	}
	return nil
}
