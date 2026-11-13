package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
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
	Bind    string `yaml:"bind"` // empty = 127.0.0.1:9090 (loopback only)
	Path    string `yaml:"path"`
}

// AdminConfig defines the admin REST API endpoint.
type AdminConfig struct {
	Enabled bool   `yaml:"enabled"`
	Bind    string `yaml:"bind"`    // e.g., "127.0.0.1:9091"; empty = 127.0.0.1:9091
	APIKey  string `yaml:"api_key"` // Required when enabled (startup error without it); sent as X-API-Key
}

// TracingConfig defines OpenTelemetry tracing settings.
type TracingConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"` // OTLP endpoint
	Service  string `yaml:"service"`  // service name
}

// ThrottleConfig defines bandwidth throttling settings. NOT IMPLEMENTED: a
// listener that sets read_rate or write_rate is rejected at load (no code
// path throttles traffic).
type ThrottleConfig struct {
	ReadRate  string `yaml:"read_rate,omitempty"`  // e.g., "10MB/s"
	WriteRate string `yaml:"write_rate,omitempty"` // e.g., "10MB/s"
}

// RequestIDConfig controls edge correlation-id (X-Request-ID) handling for an
// HTTP/HTTPS listener. When Enabled, nvelox reads an inbound X-Request-ID and,
// if absent — or present but not trusted (see TrustInbound) — generates a fresh
// 32-hex-char id, injects it on the upstream request, echoes it on the response,
// and records it (with the gateway identity) in the access log. This makes the
// gateway the origin of truth for the trace: one id follows the request from the
// gateway that first received it through every downstream service. The header
// name is fixed to X-Request-ID to stay consistent with the rest of the stack.
type RequestIDConfig struct {
	Enabled bool `yaml:"enabled,omitempty"`
	// TrustInbound: honor a well-formed inbound X-Request-ID from ANY peer.
	// Set this on INTERNAL listeners, where the caller is a trusted service
	// that already carries an id and we want the whole chain to share it.
	// Default false = at the true public edge an inbound id is honored only
	// when the immediate peer is a configured trusted_proxy, otherwise it is
	// overwritten with a fresh id so a client cannot forge or poison the trace.
	TrustInbound bool `yaml:"trust_inbound,omitempty"`
}

type ServerConfig struct {
	// User, Group, PidFile and Workers are accepted for config compatibility
	// but NOT IMPLEMENTED: nvelox never drops privileges, writes no pid file
	// and always runs one process. ServerWarnings reports them at startup.
	User    string `yaml:"user"`
	Group   string `yaml:"group"`
	PidFile string `yaml:"pid_file"`
	Workers int    `yaml:"workers,omitempty"`
	// GatewayID identifies THIS gateway on every HTTP access-log line as
	// gw=<id>, so a request can be attributed to the gateway that first
	// received it. Empty (default) → os.Hostname() is used at startup.
	GatewayID string `yaml:"gateway_id,omitempty"`
}

type LoggingConfig struct {
	Level     string `yaml:"level"`      // debug, info, warning, error
	AccessLog string `yaml:"access_log"` // path to access log
	ErrorLog  string `yaml:"error_log"`  // path to error log
}

// Listener defines a frontend listener.
//
// Multiple listeners may share the same `bind:` address (nginx-style
// multi-server-per-port). When they do, ServerNames + DefaultServer
// determine which one handles a given request:
//   - SNI / Host header is matched against ServerNames (exact, then
//     leftmost-wildcard "*.foo.com").
//   - Unmatched requests fall through to the listener with
//     DefaultServer: true. If no default exists, the connection is
//     closed (or 421 returned, depending on strict_sni).
type Listener struct {
	Name     string `yaml:"name"`
	Bind     string `yaml:"bind"`     // e.g., ":80" or "*:1024-2048"
	Protocol string `yaml:"protocol"` // "tcp", "udp", "http", "https"
	// ZeroCopy is accepted for config compatibility but currently has no
	// effect: L4 TCP sessions are relayed with a 16 KiB buffered copy per
	// direction (core/relay.go). Kernel splice is not implemented.
	ZeroCopy bool `yaml:"zero_copy"`

	// Backend names the upstream pool. For TCP/UDP listeners it's the
	// pool every connection is forwarded to. For HTTP/HTTPS listeners
	// with `routes:` it's the fallback when no route matches; without
	// `routes:` it's the single destination.
	Backend string `yaml:"backend,omitempty"`

	// DefaultBackend is the legacy YAML key (HAProxy-style). New configs
	// should use `backend:` instead. Setting both is a config error;
	// setting only this field still works and logs a deprecation warning
	// at load time. Will be removed in a future release.
	DefaultBackend string `yaml:"default_backend,omitempty"`

	// Multi-server-per-port (nginx-style).
	// ServerNames are SNI / Host names this listener answers to. Wildcards
	// allowed in the leftmost label only ("*.foo.com"). Empty + single
	// listener on the bind = match-everything (back-compat).
	ServerNames []string `yaml:"server_names,omitempty"`
	// DefaultServer marks this listener as the catch-all for its bind
	// group when SNI / Host doesn't match any other site's ServerNames.
	// At most one DefaultServer per bind group.
	DefaultServer bool `yaml:"default_server,omitempty"`

	// Rate limiting
	RateLimit RateLimitConfig `yaml:"rate_limit,omitempty"`

	// Timeouts
	Timeouts TimeoutConfig `yaml:"timeouts,omitempty"`

	// TLS
	TLS TLSConfig `yaml:"tls,omitempty"`

	// SNI routing (TLS passthrough without termination). NOT IMPLEMENTED: a
	// listener with sni_routes is rejected at load.
	SNIRoutes []SNIRoute `yaml:"sni_routes,omitempty"`

	// Security. ip_allowlist, ip_denylist and acl apply to every protocol:
	// on http/https per request (real client behind trusted_proxies), on
	// tcp/udp per connection / UDP session (the PROXY-v2 client behind a
	// trusted accept_proxy_from relay). On tcp/udp an acl rule may match
	// source_ip only. Entries must be valid IPs or CIDRs.
	IPAllowlist []string          `yaml:"ip_allowlist,omitempty"`  // CIDR allow list
	IPDenylist  []string          `yaml:"ip_denylist,omitempty"`   // CIDR deny list
	MaxBodySize string            `yaml:"max_body_size,omitempty"` // e.g., "10MB"
	IPRateLimit IPRateLimitConfig `yaml:"ip_rate_limit,omitempty"`
	ACL         []ACLRule         `yaml:"acl,omitempty"`

	// TrustedProxies: CIDRs whose X-Forwarded-For / X-Real-IP / X-Forwarded-Proto
	// headers are trusted and extended. Requests from any other source have
	// these headers *replaced* (not appended) so a direct client can't spoof
	// their source IP by presenting a forged XFF chain.
	// If empty, no peer is trusted → XFF is always replaced with the peer IP.
	//
	// SECURITY: this list also governs nvelox's OWN client-IP decisions — the
	// access log, ip_allowlist, ip_denylist, ip_rate_limit and acl all resolve
	// the real client from X-Forwarded-For / X-Real-IP when the connection peer
	// is trusted (see HTTPServer.realClientIP). Scope it to the ACTUAL upstream
	// proxy IPs/CIDR, never a broad range. In particular, behind a Kubernetes
	// Service with externalTrafficPolicy:Cluster, kube-proxy SNATs every inbound
	// packet to a node IP — so a broad CIDR like 10.0.0.0/8 marks ALL inbound
	// traffic (including anyone who can reach the NodePort directly) as trusted,
	// making the forwarding headers — and therefore every IP-based control above
	// — forgeable. Use externalTrafficPolicy:Local (or an LB that preserves the
	// source) and/or firewall the listener so only the real proxy can reach it.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`

	// AcceptProxyFrom: CIDRs whose INBOUND PROXY-protocol-v2 header is trusted
	// and used as the real client address at L4 (tcp / https-passthrough
	// listeners). Connections from peers OUTSIDE this list have any inbound
	// PROXY header IGNORED — the real TCP/UDP peer is used — so a direct client
	// can never spoof its source. Empty (default) = trust nobody = inbound PROXY
	// headers are never honored (behaviour unchanged). Distinct from
	// trusted_proxies (L7 XFF/X-Real-IP trust). Used behind a relay (another
	// nvelox, HAProxy, ...) that prepends a PROXY-v2 header with the real
	// client: this list lets nvelox accept it and forward it to the backend.
	AcceptProxyFrom []string `yaml:"accept_proxy_from,omitempty"`

	// L7 fields
	HTTP3       bool              `yaml:"http3,omitempty"`
	Routes      []RouteConfig     `yaml:"routes,omitempty"`
	Headers     HeadersConfig     `yaml:"headers,omitempty"`
	Compression CompressionConfig `yaml:"compression,omitempty"`
	ErrorPages  map[int]string    `yaml:"error_pages,omitempty"` // status code -> file path
	Root        string            `yaml:"root,omitempty"`        // Document root for static files
	Buffering   BufferingConfig   `yaml:"buffering,omitempty"`
	Cache       CacheConfig       `yaml:"cache,omitempty"`
	GRPC        bool              `yaml:"grpc,omitempty"`       // Enable gRPC-aware proxying
	Throttle    ThrottleConfig    `yaml:"throttle,omitempty"`   // NOT IMPLEMENTED: rejected at load when set
	RequestID   RequestIDConfig   `yaml:"request_id,omitempty"` // Edge correlation-id (X-Request-ID)
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
	// Status is the HTTP status returned when a "deny" rule matches. Optional;
	// defaults to 403 Forbidden. Set it to 404 to hide the existence of a path
	// (e.g. an admin surface) from unauthorized clients rather than advertising
	// it with a Forbidden. Ignored for "allow" rules.
	Status int `yaml:"status,omitempty"`
}

// ACLMatch defines conditions for an ACL rule. All specified conditions must
// match (AND); an empty field is a wildcard for that dimension.
type ACLMatch struct {
	SourceIP []string          `yaml:"source_ip,omitempty"` // CIDR notation
	Method   []string          `yaml:"method,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	// PathPrefix matches when the request path starts with this string.
	PathPrefix string `yaml:"path_prefix,omitempty"`
	// PathRegex matches when the request path matches this RE2 regular
	// expression. Prefer this over PathPrefix for boundary-safe matches, e.g.
	// "^/admin(/|$)" so "/administrator" is not caught.
	PathRegex string `yaml:"path_regex,omitempty"`
}

// RateLimitConfig defines per-listener connection rate limiting.
type RateLimitConfig struct {
	ConnectionsPerSecond float64 `yaml:"connections_per_second"`
	Burst                int     `yaml:"burst"`
}

// TLSConfig defines TLS certificate configuration.
//
// ClientAuth is the client-certificate (mTLS) policy of a TLS-terminating
// listener (tcp with tls, https and its HTTP/3): "require" fails the handshake
// unless the client presents a certificate that verifies against client_ca,
// "request" asks for a certificate without requiring it, "none" / empty asks
// for none. On a bind shared by several https sites the policy is per site
// (chosen by SNI), and a request whose Host names a client_auth site on a
// connection whose SNI selected another site is answered 421. ClientCA is a
// PEM CA bundle: required by "require", only valid with client_auth set.
// OCSPStapling is NOT IMPLEMENTED: true is rejected at load.
type TLSConfig struct {
	Cert         string `yaml:"cert"`
	Key          string `yaml:"key"`
	AutoCert     bool   `yaml:"auto_cert"`
	OCSPStapling bool   `yaml:"ocsp_stapling,omitempty"` // NOT IMPLEMENTED: rejected at load when true
	ClientAuth   string `yaml:"client_auth,omitempty"`   // "require", "request", "none"
	ClientCA     string `yaml:"client_ca,omitempty"`     // CA cert for client verification

	// MinVersion is the lowest TLS protocol version this listener accepts.
	// Values: "1.2", "1.3". Empty defaults to "1.2".
	MinVersion string `yaml:"min_version,omitempty"`
	// MaxVersion is the highest TLS protocol version this listener accepts.
	// Values: "1.2", "1.3". Empty defaults to "1.3".
	MaxVersion string `yaml:"max_version,omitempty"`
	// CipherSuites is an allowlist of cipher-suite names (TLS 1.2 only;
	// TLS 1.3 suites are mandatory and not configurable per RFC 8446).
	// Names must match Go's tls.CipherSuites(). Empty keeps Go's safe
	// default list. Example: ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"].
	CipherSuites []string `yaml:"cipher_suites,omitempty"`
}

// RouteConfig defines an L7 route matching rule.
type RouteConfig struct {
	Match    RouteMatch     `yaml:"match"`
	Backend  string         `yaml:"backend,omitempty"`
	Headers  HeadersConfig  `yaml:"headers,omitempty"`
	Rewrite  RewriteConfig  `yaml:"rewrite,omitempty"`
	Redirect RedirectConfig `yaml:"redirect,omitempty"`
	Scripts  ScriptsConfig  `yaml:"scripts,omitempty"`   // NOT IMPLEMENTED (Lua hooks): rejected at load when set
	Static   StaticConfig   `yaml:"static,omitempty"`    // Serve static files
	TryFiles TryFilesConfig `yaml:"try_files,omitempty"` // try_files logic
	Expires  string         `yaml:"expires,omitempty"`   // Cache-Control: "1y", "30d", "1h", "-1" (no cache)
	FastCGI  FastCGIConfig  `yaml:"fastcgi,omitempty"`   // Forward to FastCGI (PHP-FPM)
}

// FastCGIConfig defines FastCGI upstream (e.g., PHP-FPM) settings.
type FastCGIConfig struct {
	Pass          string            `yaml:"pass"`                      // FastCGI address (e.g., "127.0.0.1:9000" or "unix:/var/run/php-fpm.sock")
	DocumentRoot  string            `yaml:"document_root,omitempty"`   // DOCUMENT_ROOT for SCRIPT_FILENAME; required — only existing .php files inside it are run
	ScriptName    string            `yaml:"script_name,omitempty"`     // Override SCRIPT_NAME (default: from URL path)
	SplitPathInfo string            `yaml:"split_path_info,omitempty"` // Regex to split PATH_INFO (like fastcgi_split_path_info)
	Params        map[string]string `yaml:"params,omitempty"`          // Extra FastCGI params
	Index         string            `yaml:"index,omitempty"`           // Default script (e.g., "index.php")
}

// StaticConfig defines static file serving.
type StaticConfig struct {
	Root      string   `yaml:"root"`                // Document root directory
	Index     []string `yaml:"index,omitempty"`     // Index files (default: ["index.html"])
	Autoindex bool     `yaml:"autoindex,omitempty"` // Directory listing
}

// TryFilesConfig defines try_files behavior.
type TryFilesConfig struct {
	Files    []string `yaml:"files"`    // e.g., ["$uri", "$uri/", "/index.php$is_args$args"]
	Fallback string   `yaml:"fallback"` // Fallback path or =status (e.g., "=404", "/fallback.html")
}

// ScriptsConfig defines Lua script hooks for a route. NOT IMPLEMENTED: no
// code path runs them, so a route that sets either script is rejected at load.
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

// SNIRoute defines TLS passthrough routing based on server name. NOT
// IMPLEMENTED: listeners[].sni_routes is rejected at load.
type SNIRoute struct {
	ServerName string `yaml:"server_name"` // hostname or *.example.com pattern
	Backend    string `yaml:"backend"`
}

// TimeoutConfig defines configurable timeouts for listeners and backends.
//
// On HTTP listeners, ReadHeader bounds the time spent parsing request headers
// (slowloris guard) and is enforced at the http.Server level. Read and Write
// are applied per-request via http.ResponseController.SetReadDeadline /
// SetWriteDeadline once the routing site is known, so two sites sharing the
// same bind port can have different Read/Write budgets. ReadHeader is shared
// across sites on the same bind port (one http.Server) — the engine uses the
// max configured value across sites, falling back to a sensible default.
type TimeoutConfig struct {
	Connect    string `yaml:"connect,omitempty"`     // dial timeout (default "10s")
	ReadHeader string `yaml:"read_header,omitempty"` // request header read timeout (HTTP listeners)
	Read       string `yaml:"read,omitempty"`        // read timeout (whole request incl. body)
	Write      string `yaml:"write,omitempty"`       // write timeout (whole response)
	Idle       string `yaml:"idle,omitempty"`        // idle connection timeout
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

// ParseReadHeader returns the read-header timeout duration, or 0 (no timeout)
// if not set. An explicit "0" disables the timeout.
func (t TimeoutConfig) ParseReadHeader() time.Duration {
	if t.ReadHeader == "" {
		return 0
	}
	d, _ := time.ParseDuration(t.ReadHeader)
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

// ResolveRead returns the configured read timeout, or the supplied default
// when the field is unset. An explicit "0" yields 0 (unlimited), letting
// operators opt out of any per-request read deadline.
func (t TimeoutConfig) ResolveRead(def time.Duration) time.Duration {
	if t.Read == "" {
		return def
	}
	return t.ParseRead()
}

// ResolveWrite mirrors ResolveRead for the write timeout.
func (t TimeoutConfig) ResolveWrite(def time.Duration) time.Duration {
	if t.Write == "" {
		return def
	}
	return t.ParseWrite()
}

// ResolveReadHeader mirrors ResolveRead for the read-header timeout.
func (t TimeoutConfig) ResolveReadHeader(def time.Duration) time.Duration {
	if t.ReadHeader == "" {
		return def
	}
	return t.ParseReadHeader()
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
	Balance        string   `yaml:"balance"`         // "roundrobin", "leastconn", "random"
	SendProxyV2    bool     `yaml:"send_proxy_v2"`   // Send PROXY Protocol v2 header to backend
	Servers        []string `yaml:"servers"`         // List of server addresses
	MaxConnections int      `yaml:"max_connections"` // Max concurrent HTTP requests / TCP connections / UDP sessions (0 = unlimited)

	Timeouts        TimeoutConfig `yaml:"timeouts,omitempty"`
	Retry           RetryConfig   `yaml:"retry,omitempty"`
	StickySession   StickyConfig  `yaml:"sticky_session,omitempty"`
	ResolveInterval string        `yaml:"resolve_interval,omitempty"` // DNS re-resolve interval
	// AllowPrivateIPs: if true, backend hostnames may resolve to RFC1918,
	// loopback, link-local or CGNAT addresses. Default (false) blocks these
	// to prevent DNS-rebinding / SSRF when a hostname is attacker-controlled.
	// Set to true only when backends legitimately live on a private network.
	AllowPrivateIPs bool              `yaml:"allow_private_ips,omitempty"`
	BackendTLS      BackendTLSConfig  `yaml:"backend_tls,omitempty"`
	CircuitBreaker  CBConfig          `yaml:"circuit_breaker,omitempty"`
	HealthCheck     HealthCheckConfig `yaml:"health_check,omitempty"`
}

// CBConfig defines circuit breaker settings per backend.
type CBConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Threshold   int    `yaml:"threshold"`     // failures to open
	Timeout     string `yaml:"timeout"`       // time in open state before half-open
	HalfOpenMax int    `yaml:"half_open_max"` // max requests in half-open
}

// BackendTLSConfig defines TLS settings for connecting to backend servers.
// Implemented for http/https listeners only: a backend with backend_tls
// enabled cannot serve a tcp or udp listener (rejected at load). The CA and
// client key pair are checked at load, and a backend whose TLS config cannot
// be built fails startup / the reload — nvelox never falls back to plaintext.
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

	// Process Include.
	//
	// Security: resolve the glob relative to the main config file's
	// directory and require every match to stay under it. Without this,
	// a config loaded from an untrusted source (or generated by a template)
	// could include a pattern like "/etc/*/passwd" and pull in arbitrary
	// filesystem contents at parse time.
	if cfg.Include != "" {
		matches, err := resolveIncludeGlob(cfg.Include, path)
		if err != nil {
			return nil, err
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
		l := &cfg.Listeners[i]
		if l.Protocol == "" {
			l.Protocol = "tcp"
		}
		// Migrate the deprecated `default_backend:` key into `backend:`.
		// Setting both is a load error — it's almost always a typo or a
		// half-finished migration and we shouldn't silently pick one.
		if l.DefaultBackend != "" {
			if l.Backend != "" {
				return nil, fmt.Errorf("listener %s: both 'backend' and 'default_backend' are set — use 'backend' only", l.Name)
			}
			fmt.Fprintf(os.Stderr, "[CONFIG] listener %s: 'default_backend' is deprecated; use 'backend' instead\n", l.Name)
			l.Backend = l.DefaultBackend
			l.DefaultBackend = ""
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
	backendTLS := make(map[string]bool) // backend name -> backend_tls enabled
	validAlgorithms := map[string]bool{"": true, "roundrobin": true, "leastconn": true, "random": true}

	for _, b := range cfg.Backends {
		if b.Name == "" {
			return fmt.Errorf("backend must have a name")
		}
		if backendNames[b.Name] {
			return fmt.Errorf("duplicate backend name: %s", b.Name)
		}
		backendNames[b.Name] = true
		backendTLS[b.Name] = b.BackendTLS.Enabled

		if err := validateBackendTLS(b.BackendTLS); err != nil {
			return fmt.Errorf("backend %s: backend_tls: %v", b.Name, err)
		}

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
		if l.Backend != "" && !backendNames[l.Backend] {
			return fmt.Errorf("listener %s references unknown backend: %s", l.Name, l.Backend)
		}
		// Load defaults an empty protocol to tcp; validate() is also called
		// on hand-built configs, so normalise here too.
		proto := l.Protocol
		if proto == "" {
			proto = "tcp"
		}
		l4 := proto == "tcp" || proto == "udp"

		// Validate bind address format
		if err := validateBindAddress(l.Bind); err != nil {
			return fmt.Errorf("listener %s has invalid bind address %q: %v", l.Name, l.Bind, err)
		}

		// Validate accept_proxy_from CIDRs up front so a typo is caught at
		// startup rather than silently dropped (which would mean an intended
		// trusted peer is never trusted).
		for _, c := range l.AcceptProxyFrom {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
				return fmt.Errorf("listener %s: invalid accept_proxy_from CIDR %q: %v", l.Name, c, err)
			}
		}

		// Keys that are parsed but have no implementation behind them. A
		// security control that silently does nothing is worse than a startup
		// error, so they are refused instead of ignored.
		if err := rejectUnimplementedListenerKeys(l); err != nil {
			return err
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
			if proto == "udp" {
				return fmt.Errorf("listener %s: tls is not supported on udp listeners", l.Name)
			}
		}
		if err := validateClientAuth(l.TLS); err != nil {
			return fmt.Errorf("listener %s: %v", l.Name, err)
		}

		// IP list and ACL source_ip entries are checked for every protocol
		// by validateAddrLists below.
		if err := validateACL(l.ACL, l4); err != nil {
			return fmt.Errorf("listener %s: %v", l.Name, err)
		}

		// L4 (tcp/udp) listeners forward every connection to one pool, and
		// only plaintext: backend_tls is implemented on the HTTP path alone.
		if l4 {
			if l.Backend == "" {
				return fmt.Errorf("listener %s: %s listener requires 'backend'", l.Name, proto)
			}
			if backendTLS[l.Backend] {
				return fmt.Errorf("listener %s: backend %s has backend_tls enabled, which is not implemented for %s listeners (only http/https listeners connect to backends over TLS)",
					l.Name, l.Backend, proto)
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
			if l.Backend == "" && len(l.Routes) == 0 {
				return fmt.Errorf("listener %s: HTTP listener requires 'backend' or 'routes'", l.Name)
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
				// A route path_regex that doesn't compile must fail startup:
				// the router would otherwise drop the route.
				if r.Match.PathRegex != "" {
					if err := validatePathRegex(r.Match.PathRegex); err != nil {
						return fmt.Errorf("listener %s: route %d: path_regex: %v", l.Name, i, err)
					}
				}
				if hasFastCGI {
					if err := validateFastCGI(r.FastCGI); err != nil {
						return fmt.Errorf("listener %s: route %d: fastcgi: %v", l.Name, i, err)
					}
				}
			}
		}

		// Validate HTTP3 requires HTTPS
		if l.HTTP3 && l.Protocol != "https" {
			return fmt.Errorf("listener %s: http3 requires protocol 'https'", l.Name)
		}

		// Validate server_names format (early per-listener check; cross-
		// listener uniqueness is checked in the bind-group pass below).
		for _, sn := range l.ServerNames {
			if err := validateServerName(sn); err != nil {
				return fmt.Errorf("listener %s: server_names %q: %v", l.Name, sn, err)
			}
		}
	}

	// Every IP / CIDR list entry must parse (it used to be dropped silently).
	if err := validateAddrLists(cfg.Listeners); err != nil {
		return err
	}

	// Cross-listener bind-group rules (nginx-style multi-server-per-port).
	if err := validateBindGroups(cfg.Listeners); err != nil {
		return err
	}

	// Admin API and metrics endpoint (config/controlplane.go).
	if err := validateControlPlane(cfg); err != nil {
		return err
	}

	return nil
}

// rejectUnimplementedListenerKeys refuses listener keys that are parsed but
// have no implementation (sni_routes, throttle, tls.ocsp_stapling,
// routes[].scripts). Each would otherwise be a control that silently does
// nothing.
func rejectUnimplementedListenerKeys(l Listener) error {
	if len(l.SNIRoutes) > 0 {
		return fmt.Errorf("listener %s: sni_routes is not implemented (no TLS passthrough routing by SNI would happen); remove it", l.Name)
	}
	if l.Throttle.ReadRate != "" || l.Throttle.WriteRate != "" {
		return fmt.Errorf("listener %s: throttle is not implemented (no bandwidth limit would be applied); remove it", l.Name)
	}
	if l.TLS.OCSPStapling {
		return fmt.Errorf("listener %s: tls.ocsp_stapling is not implemented (no OCSP response would be stapled); remove it", l.Name)
	}
	for i, r := range l.Routes {
		if r.Scripts.RequestScript != "" || r.Scripts.ResponseScript != "" {
			return fmt.Errorf("listener %s: route %d: scripts (Lua request/response hooks) are not implemented (no script would run); remove them", l.Name, i)
		}
	}
	return nil
}

// validateClientAuth checks a listener's client-certificate (mTLS) settings:
// a known client_auth value, a TLS-terminating listener to apply it to, a
// client_ca for "require", and a client_ca file that holds at least one PEM
// certificate. A client_ca without client_auth is refused too: it reads like
// mTLS but would not ask for a certificate.
func validateClientAuth(t TLSConfig) error {
	mode := strings.ToLower(strings.TrimSpace(t.ClientAuth))
	switch mode {
	case "", "none":
		if t.ClientCA != "" {
			return fmt.Errorf("tls.client_ca is set but tls.client_auth is %q: set client_auth to \"require\" or \"request\", or remove client_ca", t.ClientAuth)
		}
		return nil
	case "require", "request":
	default:
		return fmt.Errorf("tls.client_auth %q is invalid (must be require, request or none)", t.ClientAuth)
	}
	if t.Cert == "" {
		return fmt.Errorf("tls.client_auth needs a TLS-terminating listener (tls.cert and tls.key)")
	}
	if mode == "require" && t.ClientCA == "" {
		return fmt.Errorf("tls.client_auth \"require\" needs tls.client_ca to verify client certificates")
	}
	if t.ClientCA != "" {
		if _, err := LoadCertPool(t.ClientCA); err != nil {
			return fmt.Errorf("tls.client_ca: %v", err)
		}
	}
	return nil
}

// validateBackendTLS checks an enabled backend_tls block at load: the CA file
// parses and the client certificate / key form a usable pair. Startup and
// reload build the same config again and fail instead of falling back to
// plaintext.
func validateBackendTLS(b BackendTLSConfig) error {
	if !b.Enabled {
		return nil
	}
	if (b.ClientCert != "") != (b.ClientKey != "") {
		return fmt.Errorf("client_cert and client_key must both be set (mTLS to the backend) or both be empty")
	}
	if b.ClientCert != "" {
		if _, err := tls.LoadX509KeyPair(b.ClientCert, b.ClientKey); err != nil {
			return fmt.Errorf("client_cert/client_key: %v", err)
		}
	}
	if b.CACert != "" {
		if _, err := LoadCertPool(b.CACert); err != nil {
			return fmt.Errorf("ca_cert: %v", err)
		}
	}
	return nil
}

// LoadCertPool reads a PEM file and returns a pool of its certificates. It
// fails when the file cannot be read or holds no PEM certificate.
func LoadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s: no PEM certificate found", path)
	}
	return pool, nil
}

// validateACL checks ACL rules: known action, sane deny status, compilable
// path_regex (validateAddrLists checks source_ip). A bad rule must fail
// startup rather than silently never match (or match everyone). On tcp/udp
// listeners (l4) a rule can only match the client IP: path, method and header
// matchers need an HTTP request and are refused.
func validateACL(rules []ACLRule, l4 bool) error {
	for i, a := range rules {
		if a.Action != "allow" && a.Action != "deny" {
			return fmt.Errorf("acl %d: action must be 'allow' or 'deny', got %q", i, a.Action)
		}
		if a.Status != 0 && (a.Status < 100 || a.Status > 599) {
			return fmt.Errorf("acl %d: status %d out of range (100-599)", i, a.Status)
		}
		if a.Match.PathRegex != "" {
			if len(a.Match.PathRegex) > 1024 {
				return fmt.Errorf("acl %d: path_regex too long", i)
			}
			if _, err := regexp.Compile(a.Match.PathRegex); err != nil {
				return fmt.Errorf("acl %d: invalid path_regex: %v", i, err)
			}
		}
		if l4 {
			var httpOnly []string
			if a.Match.PathPrefix != "" {
				httpOnly = append(httpOnly, "path_prefix")
			}
			if a.Match.PathRegex != "" {
				httpOnly = append(httpOnly, "path_regex")
			}
			if len(a.Match.Method) > 0 {
				httpOnly = append(httpOnly, "method")
			}
			if len(a.Match.Headers) > 0 {
				httpOnly = append(httpOnly, "headers")
			}
			if len(httpOnly) > 0 {
				return fmt.Errorf("acl %d: %s match HTTP requests and cannot be used on a tcp/udp listener (only source_ip)", i, strings.Join(httpOnly, ", "))
			}
		}
	}
	return nil
}

// ServerWarnings returns one warning per server.* key that is set but not
// implemented. user / group are reported only when the process does not
// already run as them (nvelox never drops privileges itself); pid_file and
// workers whenever they are set. main prints these at startup. They are
// warnings, not errors, because deployed configs carry these keys.
func ServerWarnings(s ServerConfig) []string {
	var out []string
	if msg := privilegeDropWarning(s.User, s.Group, os.Getuid(), os.Getgid()); msg != "" {
		out = append(out, msg)
	}
	if s.PidFile != "" {
		out = append(out, fmt.Sprintf("server.pid_file (%q) is set but not implemented: nvelox does not write a pid file", s.PidFile))
	}
	if s.Workers > 0 {
		out = append(out, fmt.Sprintf("server.workers (%d) is set but not implemented: nvelox always runs as one process", s.Workers))
	}
	return out
}

// privilegeDropWarning reports server.user / server.group values the process
// (uid, gid) is not running as. A name that does not resolve counts as
// different.
func privilegeDropWarning(userName, groupName string, uid, gid int) string {
	var set []string
	if userName != "" {
		if id, ok := lookupUID(userName); !ok || id != uid {
			set = append(set, fmt.Sprintf("server.user=%q", userName))
		}
	}
	if groupName != "" {
		if id, ok := lookupGID(groupName); !ok || id != gid {
			set = append(set, fmt.Sprintf("server.group=%q", groupName))
		}
	}
	if len(set) == 0 {
		return ""
	}
	return fmt.Sprintf("%s set but privilege drop is not implemented: nvelox is running as uid %d gid %d. Run nvelox under systemd User=/Group= with CAP_NET_BIND_SERVICE (AmbientCapabilities) instead",
		strings.Join(set, " and "), uid, gid)
}

func lookupUID(name string) (int, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		if u, err = user.LookupId(name); err != nil {
			return 0, false
		}
	}
	id, err := strconv.Atoi(u.Uid)
	return id, err == nil
}

func lookupGID(name string) (int, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		if g, err = user.LookupGroupId(name); err != nil {
			return 0, false
		}
	}
	id, err := strconv.Atoi(g.Gid)
	return id, err == nil
}

// validateServerName checks a server_names entry. Allows exact hostnames and
// leftmost-wildcard "*.foo.com" only — matches nginx semantics and avoids
// surprises with right-prefix wildcards that few certificate authorities
// support.
func validateServerName(s string) error {
	if s == "" {
		return fmt.Errorf("empty server name")
	}
	if strings.Contains(s, "*") {
		// Only "*.something" is allowed, and only one wildcard.
		if !strings.HasPrefix(s, "*.") || strings.Count(s, "*") > 1 {
			return fmt.Errorf("wildcard must be leftmost label only (e.g. \"*.foo.com\")")
		}
		// "*." alone is not a valid hostname.
		if len(s) <= 2 {
			return fmt.Errorf("wildcard must be followed by a hostname")
		}
	}
	// Reject path-like or scheme-prefixed entries.
	if strings.ContainsAny(s, "/:?# ") {
		return fmt.Errorf("server name must be a bare hostname")
	}
	return nil
}

// validateBindGroups enforces the nginx-style multi-server-per-port rules
// across the full set of listeners.
//
// "Bind group" here means listeners that actually share an OS socket. TCP
// and UDP on the same port number do NOT share a socket (HTTP/3 + HTTPS
// is the canonical example), so we group by (protocol-family, bind) pair.
// Within HTTP and HTTPS, however, we treat them as one family because
// they share an HTTP listener at the engine level — http+https on the
// same port is still rejected.
func validateBindGroups(listeners []Listener) error {
	// protocolFamily collapses protocols by underlying transport so we
	// only flag genuine same-socket conflicts:
	//   tcp, http, https → "tcp"  (all TCP-based — share a TCP socket)
	//   udp              → "udp"  (independent UDP socket)
	// HTTP+HTTPS on the same port still conflict (same TCP socket).
	// TCP+UDP on the same port number do NOT conflict (different sockets,
	// the canonical HTTP/3 + HTTPS pattern).
	protocolFamily := func(p string) string {
		switch p {
		case "udp":
			return "udp"
		default:
			return "tcp"
		}
	}

	// Group by (family, bind).
	type groupKey struct{ family, bind string }
	groups := make(map[groupKey][]*Listener)
	for i := range listeners {
		l := &listeners[i]
		k := groupKey{family: protocolFamily(l.Protocol), bind: l.Bind}
		groups[k] = append(groups[k], l)
	}

	for key, sites := range groups {
		bind := key.bind
		if len(sites) < 2 {
			// Single-listener groups behave exactly as today; no extra rules.
			continue
		}

		// Rule: same protocol within a bind group. With the (family, bind)
		// keying above this only fires for genuine same-socket conflicts
		// (e.g. http+https-on-the-same-port if someone ever wrote that).
		proto := sites[0].Protocol
		for _, s := range sites[1:] {
			if s.Protocol != proto {
				return fmt.Errorf("bind %s: listeners %s (%s) and %s (%s) share a port but use different protocols",
					bind, sites[0].Name, proto, s.Name, s.Protocol)
			}
		}

		// Rule: at most one default_server per bind group.
		defaults := 0
		for _, s := range sites {
			if s.DefaultServer {
				defaults++
			}
		}
		if defaults > 1 {
			return fmt.Errorf("bind %s: more than one listener marked default_server", bind)
		}

		// Rule: every non-default site in a multi-site group must declare
		// at least one server_name. Without it, host-based dispatch can't
		// route to it — silent unreachable config is worse than a startup
		// error.
		for _, s := range sites {
			if s.DefaultServer {
				continue
			}
			if len(s.ServerNames) == 0 {
				return fmt.Errorf("bind %s: listener %s shares a port but has no server_names and is not default_server",
					bind, s.Name)
			}
		}

		// Rule: each server_name appears in at most one site per bind group.
		seen := make(map[string]string) // name → owning listener
		for _, s := range sites {
			for _, sn := range s.ServerNames {
				lname := strings.ToLower(sn)
				if owner, dup := seen[lname]; dup {
					return fmt.Errorf("bind %s: server_name %q claimed by both %s and %s",
						bind, sn, owner, s.Name)
				}
				seen[lname] = s.Name
			}
		}

		// Rule: SNI passthrough (sni_routes) and TLS termination (https)
		// can't share a port — they're handled by entirely different paths.
		hasSNI, hasHTTPS := false, false
		for _, s := range sites {
			if len(s.SNIRoutes) > 0 {
				hasSNI = true
			}
			if s.Protocol == "https" {
				hasHTTPS = true
			}
		}
		if hasSNI && hasHTTPS {
			return fmt.Errorf("bind %s: cannot mix sni_routes (passthrough) and https (termination) on the same port", bind)
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

// resolveIncludeGlob expands an `include:` pattern and enforces that every
// match stays under the main config file's directory. Patterns may be
// relative (resolved against the main-config dir) or absolute, but any
// match that doesn't live under the main-config dir — or any pattern
// containing ".." traversal — is rejected.
//
// This prevents a templated / externally-authored config from pulling in
// arbitrary filesystem contents ("/etc/*/passwd", "../../../secrets/*")
// at parse time.
func resolveIncludeGlob(pattern, mainConfigPath string) ([]string, error) {
	if pattern == "" {
		return nil, nil
	}
	baseDir, err := filepath.Abs(filepath.Dir(mainConfigPath))
	if err != nil {
		return nil, fmt.Errorf("resolve include base dir: %w", err)
	}

	// Refuse ".." traversal in the pattern. This catches both explicit
	// upward traversal and any attempt to use it as a cross-dir bypass.
	for _, seg := range strings.Split(filepath.ToSlash(pattern), "/") {
		if seg == ".." {
			return nil, fmt.Errorf("include pattern %q must not contain '..' path segments", pattern)
		}
	}

	// Resolve to absolute. Relative patterns are rooted at baseDir; absolute
	// patterns must still land under baseDir to be accepted.
	full := pattern
	if !filepath.IsAbs(pattern) {
		full = filepath.Join(baseDir, pattern)
	}

	matches, err := filepath.Glob(full)
	if err != nil {
		return nil, fmt.Errorf("bad include glob pattern: %w", err)
	}

	// Verify each resolved match actually lives under baseDir.
	clean := make([]string, 0, len(matches))
	for _, m := range matches {
		abs, err := filepath.Abs(m)
		if err != nil {
			continue
		}
		if abs != baseDir && !strings.HasPrefix(abs, baseDir+string(filepath.Separator)) {
			return nil, fmt.Errorf("include match %q escapes config dir %q", abs, baseDir)
		}
		clean = append(clean, abs)
	}
	return clean, nil
}

// MaxPathRegexLen bounds a route path_regex and a fastcgi split_path_info
// (the ACL path_regex check uses the same 1024).
const MaxPathRegexLen = 1024

// validatePathRegex checks a path regex: bounded length, compiles as RE2.
func validatePathRegex(re string) error {
	if len(re) > MaxPathRegexLen {
		return fmt.Errorf("too long (%d bytes, max %d)", len(re), MaxPathRegexLen)
	}
	if _, err := regexp.Compile(re); err != nil {
		return fmt.Errorf("invalid: %v", err)
	}
	return nil
}

// validateFastCGI checks a route's fastcgi block. document_root is required:
// without it the script path was joined onto the process working directory
// ("/" in the container image). script_name must not climb out of it.
// fastCGIReservedParams are the FastCGI params that choose the script PHP-FPM
// runs. nvelox sets them from the script it confined to document_root; a
// route's params may not override them (an override such as
// SCRIPT_FILENAME: $request_uri would hand PHP-FPM an unchecked file).
var fastCGIReservedParams = map[string]bool{
	"SCRIPT_FILENAME": true,
	"SCRIPT_NAME":     true,
	"DOCUMENT_ROOT":   true,
	"PATH_INFO":       true,
	"PATH_TRANSLATED": true,
}

func validateFastCGI(f FastCGIConfig) error {
	if f.DocumentRoot == "" {
		return fmt.Errorf("document_root is required")
	}
	if f.SplitPathInfo != "" {
		if err := validatePathRegex(f.SplitPathInfo); err != nil {
			return fmt.Errorf("split_path_info: %v", err)
		}
	}
	for k := range f.Params {
		if fastCGIReservedParams[strings.ToUpper(strings.TrimSpace(k))] {
			return fmt.Errorf("params: %s is set by nvelox (the script it checked under document_root) and cannot be overridden", k)
		}
	}
	if f.ScriptName != "" {
		if strings.ContainsAny(f.ScriptName, "\\\x00") {
			return fmt.Errorf("script_name %q: backslash or NUL", f.ScriptName)
		}
		for _, seg := range strings.Split(f.ScriptName, "/") {
			if seg == "." || seg == ".." {
				return fmt.Errorf("script_name %q: '.' or '..' segment", f.ScriptName)
			}
		}
	}
	return nil
}
