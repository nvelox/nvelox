package config

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration for the proxy server.
type Config struct {
	// The version of the configuration format: "2". Any other value is
	// refused.
	Version string `yaml:"version"`
	// Settings of the process: the user it runs as, its event loops, how
	// it stops, the limits of HTTP/3.
	Server ServerConfig `yaml:"server"`
	// Where the access log and the error log go, and how much the error
	// log says.
	Logging LoggingConfig `yaml:"logging"`
	// The Prometheus metrics endpoint.
	Metrics MetricsConfig `yaml:"metrics,omitempty"`
	// The admin API: statistics, the backends and their servers, and the
	// denylist, changed at run time.
	Admin AdminConfig `yaml:"admin,omitempty"`
	// Tracing is not built yet: a configuration that sets any of its keys
	// is refused at load.
	Tracing TracingConfig `yaml:"tracing,omitempty"`
	// More configuration files whose listeners and backends are added to
	// this file's, as a file pattern such as "conf.d/*.yaml". The pattern is
	// read from this file's directory, and every file it matches must lie
	// under that directory: a pattern with ".." is refused. An included
	// file holds listeners, backends and version only (the same version as
	// this file's); any other key in it is refused.
	Include string `yaml:"include"`

	// The ports nvelox listens on, and what it does with what comes in.
	Listeners []Listener `yaml:"listeners"`
	// The servers nvelox passes traffic to, in named groups that listeners
	// and routes refer to.
	Backends []Backend `yaml:"backends"`
}

// MetricsConfig defines the Prometheus metrics endpoint.
type MetricsConfig struct {
	// Turns the metrics endpoint on.
	Enabled bool `yaml:"enabled"`
	// The address the metrics endpoint listens on. Default 127.0.0.1:9090:
	// the loopback interface only.
	Bind string `yaml:"bind"`
	// The path the metrics are served at. Default /metrics.
	Path string `yaml:"path"`
}

// AdminConfig defines the admin REST API endpoint.
type AdminConfig struct {
	// Turns the admin API on. It needs api_key: without one nvelox does not
	// start.
	Enabled bool `yaml:"enabled"`
	// The address the admin API listens on. Default 127.0.0.1:9091: the
	// loopback interface only.
	Bind string `yaml:"bind"`
	// The key every request to the admin API sends in its X-API-Key header.
	// Required when the admin API is on.
	APIKey string `yaml:"api_key"`
}

// TracingConfig defines OpenTelemetry tracing settings. NOT IMPLEMENTED: a
// config that sets any of them is rejected at load (no trace would be sent).
type TracingConfig struct {
	// Not built yet: a configuration that sets it is refused at load.
	Enabled bool `yaml:"enabled"`
	// Not built yet: a configuration that sets it is refused at load.
	Endpoint string `yaml:"endpoint"`
	// Not built yet: a configuration that sets it is refused at load.
	Service string `yaml:"service"`
}

// ThrottleConfig defines bandwidth throttling settings. NOT IMPLEMENTED: a
// listener that sets read_rate or write_rate is rejected at load (no code
// path throttles traffic).
type ThrottleConfig struct {
	// Not built yet: a listener that sets it is refused at load.
	ReadRate string `yaml:"read_rate,omitempty"`
	// Not built yet: a listener that sets it is refused at load.
	WriteRate string `yaml:"write_rate,omitempty"`
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
	// Turns request IDs on.
	Enabled bool `yaml:"enabled,omitempty"`
	// Keeps the X-Request-ID a request arrives with from any client, when
	// it is well formed. Off (the default), it is kept only from
	// trusted_proxies and replaced otherwise, so that a client cannot
	// choose its ID. For internal listeners whose callers carry an ID.
	//
	// TrustInbound: honor a well-formed inbound X-Request-ID from ANY peer.
	// Set this on INTERNAL listeners, where the caller is a trusted service
	// that already carries an id and we want the whole chain to share it.
	// Default false = at the true public edge an inbound id is honored only
	// when the immediate peer is a configured trusted_proxy, otherwise it is
	// overwritten with a fresh id so a client cannot forge or poison the trace.
	TrustInbound bool `yaml:"trust_inbound,omitempty"`
}

type ServerConfig struct {
	// The user nvelox runs as once it has bound its ports, when it is
	// started as root. Empty: it keeps the user it was started as. Started
	// as another user, nvelox cannot switch, and says so at start.
	//
	// (core/privdrop.)
	User string `yaml:"user"`
	// The group nvelox runs as once it has bound its ports, when it is
	// started as root. Empty: the group of user.
	Group string `yaml:"group"`
	// Where nvelox writes its process ID, once every port is bound and
	// before it switches to user, so that the file can lie in a directory
	// only root writes to; a clean stop removes it. Empty (the default): no
	// file. Read at start: a reload does not move it.
	//
	// (core/pidfile.)
	PidFile string `yaml:"pid_file"`
	// How many event loops nvelox runs, and so how many CPU cores it uses
	// for traffic: 1 to 1024. 0 (the default): one for each CPU core the
	// process may use. Read at start: a reload does not change it.
	//
	// MaxWorkers is the upper bound; main.go applies the value before the
	// first loop exists.
	Workers int `yaml:"workers,omitempty"`
	// A name for this nvelox, written on every line of the HTTP access log
	// as gw=<name>, so that a request can be traced to the gateway that
	// first received it. Empty (the default): the machine's host name.
	GatewayID string `yaml:"gateway_id,omitempty"`
	// How long a stop (SIGINT or SIGTERM) lets the HTTP requests in flight
	// finish before what is left is closed: a duration greater than 0, such
	// as 30s. Default 10s. A reload applies it.
	//
	// Empty: DefaultShutdownTimeout.
	ShutdownTimeout string `yaml:"shutdown_timeout,omitempty"`
	// The limits of HTTP/3 connections, for every listener that serves
	// HTTP/3.
	//
	// (http3.go.)
	HTTP3 HTTP3Config `yaml:"http3,omitempty"`
}

// DefaultShutdownTimeout is server.shutdown_timeout when it is not set.
const DefaultShutdownTimeout = 10 * time.Second

// ResolveShutdownTimeout returns server.shutdown_timeout, and
// DefaultShutdownTimeout when it is not set (or, in a config that was not
// loaded through Load, not a duration greater than 0).
func (s ServerConfig) ResolveShutdownTimeout() time.Duration {
	if d, err := time.ParseDuration(s.ShutdownTimeout); err == nil && d > 0 {
		return d
	}
	return DefaultShutdownTimeout
}

// validateShutdownTimeout checks server.shutdown_timeout: unset, or a
// duration greater than 0. Zero is refused rather than given a meaning:
// elsewhere in this file "0" lifts a limit, and a stop without a limit
// would wait for ever on a request that never ends.
func validateShutdownTimeout(val string) error {
	if val == "" {
		return nil
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return err
	}
	if d <= 0 {
		return fmt.Errorf("must be greater than 0 (it is how long a stop waits for the requests in flight; a small value such as \"1s\" makes a stop quick)")
	}
	return nil
}

type LoggingConfig struct {
	// How much the error log says: debug, info, warning or error. Default
	// info.
	Level string `yaml:"level"`
	// The file the access log is written to. Empty (the default): standard
	// output. nvelox opens the file again on SIGUSR1 or SIGHUP, after log
	// rotation has moved it away.
	AccessLog string `yaml:"access_log"`
	// The file the error log is written to. Empty (the default): standard
	// error. nvelox opens the file again on SIGUSR1 or SIGHUP.
	ErrorLog string `yaml:"error_log"`
	// Turns the access log on or off for every listener; on when not set.
	// A listener's own access_log wins over it.
	Access *bool `yaml:"access,omitempty"`
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
	// The listener's name, in log lines and in metrics. Required, and one
	// to a listener.
	Name string `yaml:"name"`
	// The address and port to listen on, such as ":80", "10.0.0.1:443" or
	// "[::]:443", or a range of ports, such as ":17000-17100", served
	// from one socket each. Required.
	Bind string `yaml:"bind"`
	// What the listener speaks: tcp (the default) and udp relay
	// connections and datagrams to a backend as they are; http and https
	// serve HTTP, https behind TLS.
	Protocol string `yaml:"protocol"`
	// Not built yet: a listener that sets it to true is refused at load.
	//
	// L4 TCP sessions are relayed with a buffered copy per direction;
	// kernel splice does not exist.
	ZeroCopy bool `yaml:"zero_copy"`

	// The backend to pass traffic to, by its name. A tcp or udp listener
	// passes every connection or session to it, and needs one. An http or
	// https listener with routes passes it the requests no route takes;
	// without routes, every request.
	Backend string `yaml:"backend,omitempty"`

	// The former name of backend. A listener that uses it loads, with a
	// warning that names the new key; one that sets both is refused.
	//
	// Will be removed in a future release.
	DefaultBackend string `yaml:"default_backend,omitempty"`

	// The host names this listener answers for when several http or https
	// listeners share one bind address: matched against the TLS server
	// name and the Host header, an exact name first, then one with a
	// wildcard in its leftmost label ("*.example.com"). A listener alone on
	// its address answers for every name. Refused on tcp and udp.
	ServerNames []string `yaml:"server_names,omitempty"`
	// Makes this listener the one that answers a request whose name no
	// listener on its bind address lists. At most one to a bind address.
	// Refused on tcp and udp.
	DefaultServer bool `yaml:"default_server,omitempty"`

	// A limit for the whole listener: new connections a second on tcp, new
	// sessions on udp, requests on http and https.
	RateLimit RateLimitConfig `yaml:"rate_limit,omitempty"`

	// How long the listener waits for its clients, and how long it gives
	// a backend to accept a connection. Refused on a udp listener: a udp
	// session ends after 60 seconds without a datagram from its client, or
	// 10 seconds without a reply from its backend.
	Timeouts TimeoutConfig `yaml:"timeouts,omitempty"`

	// The certificate an https listener, or a tcp listener that ends TLS,
	// presents, and how it treats client certificates.
	TLS TLSConfig `yaml:"tls,omitempty"`

	// Not built yet: a listener that sets it is refused at load.
	//
	// SNI routing (TLS passthrough without termination).
	SNIRoutes []SNIRoute `yaml:"sni_routes,omitempty"`

	// Addresses and ranges ("10.0.0.0/8") allowed in: any other client is
	// refused. Empty: every client. On http and https it is the client of
	// each request (behind trusted_proxies, the client they name); on tcp
	// and udp, of each connection or session (behind a relay of
	// accept_proxy_from, the client its header names).
	//
	// Security. ip_allowlist, ip_denylist and acl apply to every protocol.
	IPAllowlist []string `yaml:"ip_allowlist,omitempty"`
	// Addresses and ranges refused, with the same client as ip_allowlist.
	IPDenylist []string `yaml:"ip_denylist,omitempty"`
	// The largest request body an http or https listener takes, such as
	// "10MB"; a larger one is answered 413. Empty: no limit. Refused on tcp
	// and udp listeners.
	MaxBodySize string `yaml:"max_body_size,omitempty"`
	// A limit of requests a second for each client address, on http and
	// https listeners: past it a request is answered 429. Refused on tcp
	// and udp listeners.
	IPRateLimit IPRateLimitConfig `yaml:"ip_rate_limit,omitempty"`
	// Rules that allow or refuse requests by their client, method, path
	// and headers, checked in order: the first that matches decides, and
	// a request no rule matches is allowed. On tcp and udp a rule matches
	// the client address only.
	ACL []ACLRule `yaml:"acl,omitempty"`

	// Addresses and ranges of the proxies in front of an http or https
	// listener whose X-Forwarded-For, X-Real-IP and X-Forwarded-Proto are
	// believed: for a request from one of them, the client those headers
	// name is the client for the access log, ip_allowlist, ip_denylist,
	// ip_rate_limit and acl, and nvelox adds to the headers. From any other
	// address the headers are replaced, so a client cannot claim another
	// address. Empty: nobody is trusted. List only the proxies themselves:
	// behind a Kubernetes Service with externalTrafficPolicy: Cluster, every
	// packet comes from a node's address, so a range of node addresses
	// would trust every client. Refused on tcp and udp listeners, which
	// learn the client from a relay's header (accept_proxy_from).
	//
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

	// Addresses and ranges of the relays (another nvelox, HAProxy) whose
	// PROXY protocol version 2 header names the client: the client it
	// names is the client for every address-based control. A listed relay
	// must send the header, on every connection and in every datagram: a
	// connection without a valid one is closed, a datagram dropped (the
	// relay's own traffic, such as health checks, sends a LOCAL header).
	// Anyone else is the client itself, header or not. Empty (the
	// default): nobody. A datagram's source address can be forged, so a
	// udp listener should also set accept_proxy_key_file or
	// accept_proxy_interfaces; one that trusts by address alone starts
	// with a warning. Listeners on one bind address set the same.
	//
	// AcceptProxyFrom: CIDRs whose INBOUND PROXY-protocol-v2 header is trusted
	// and used as the real client address: on tcp and udp listeners, and on
	// http and https listeners for HTTP/1.1 and HTTP/2. Peers OUTSIDE this
	// list have any inbound PROXY header IGNORED and are the client
	// themselves. Empty (default) = trust nobody. Used behind a relay
	// (another nvelox, HAProxy, ...) that prepends a PROXY-v2 header with the
	// real client. A listed peer must send it: a tcp, http or https
	// connection from one that does not start with a valid header (LOCAL
	// for the relay's own traffic) is closed, a udp datagram without one is
	// dropped. A TCP handshake proves the peer address; a UDP datagram's
	// source can be forged, so a udp listener should also set
	// AcceptProxyKeyFile or AcceptProxyInterfaces (startup warning otherwise).
	//
	// On an http or https listener the header comes first on the connection
	// (before TLS). The client it names is the peer for every IP-based control
	// and for trusted_proxies, which is a different thing (whose
	// X-Forwarded-For is believed) and is matched against that client, not
	// the relay. Listeners that share a bind address must set the same
	// accept_proxy_from and accept_proxy_key_file.
	AcceptProxyFrom []string `yaml:"accept_proxy_from,omitempty"`
	// A file of keys, one to a line (32 characters at least; "#" begins a
	// comment), that a relay's PROXY header must be signed with: a header
	// without a valid signature closes its connection or drops its
	// datagram. A sending nvelox signs with send_proxy_key_file. Every key
	// in the file is accepted, so a key is rotated without a gap: add the
	// new one here, sign with it on the relays, then remove the old one.
	//
	// (proxy/signature.go.)
	AcceptProxyKeyFile string `yaml:"accept_proxy_key_file,omitempty"`
	// AcceptProxyReplayWindow is what a signed header must carry. A header
	// signed with a counter (signature version 2) is bound to both ends of
	// its connection or datagram (the relay's address and port, and the
	// address and port it was sent to) and refused when its counter was
	// taken before, is older than that relay socket's last 64, or is ahead
	// of the header's time: a copy of it, sent again, from another address
	// or port, or to another, does not pass. Both sides must see the same
	// addresses: no address translation between a relay and nvelox.
	// "when_present" (the default) also takes a header signed without one
	// (version 1, from a relay not updated yet); "required" takes only
	// headers with a counter, once every relay sends them. Needs
	// accept_proxy_key_file.
	AcceptProxyReplayWindow string `yaml:"accept_proxy_replay_window,omitempty"`
	// AcceptProxyKeys is loaded from AcceptProxyKeyFile by Load.
	AcceptProxyKeys [][]byte `yaml:"-"`
	// On a udp listener (Linux): network interfaces, such as a second
	// network card, a VLAN or a tunnel only the relays reach, on which a
	// relay's header counts. A datagram from a listed relay that arrived on
	// another interface is an ordinary client's. For relays that cannot
	// sign their headers. The interfaces and their addresses are read at
	// start.
	//
	// The listener gets one socket per address of each interface (a
	// listener bound to one address: its own socket, on the interface that
	// has the address), sharing its port (core/udpdevice.go).
	AcceptProxyInterfaces []string `yaml:"accept_proxy_interfaces,omitempty"`

	// Serves HTTP/3 too, on an https listener: over UDP, on the listener's
	// port, with its certificate.
	HTTP3 bool `yaml:"http3,omitempty"`
	// Rules that pick, for each request of an http or https listener, the
	// backend, the files or the FastCGI server that answers it, checked in
	// order: the first route that matches takes the request. Refused on tcp
	// and udp listeners.
	Routes []RouteConfig `yaml:"routes,omitempty"`
	// Request and response headers added, set or removed for every request
	// of an http or https listener. Refused on tcp and udp listeners.
	Headers HeadersConfig `yaml:"headers,omitempty"`
	// Compresses responses with gzip, for the clients that accept it, on
	// http and https listeners. Refused on tcp and udp listeners.
	Compression CompressionConfig `yaml:"compression,omitempty"`
	// Pages of your own for error answers, by status code, such as
	// 404: "/etc/nvelox/404.html": a file read at start and at each reload
	// (one that cannot be read is logged, and the built-in page is used).
	// Refused on tcp and udp listeners.
	ErrorPages map[int]string `yaml:"error_pages,omitempty"`
	// Not built for a listener: a listener that sets it is refused at load.
	// A route's static.root serves files.
	Root string `yaml:"root,omitempty"`
	// The size of the buffer response bodies are copied through. Refused
	// on tcp and udp listeners.
	Buffering BufferingConfig `yaml:"buffering,omitempty"`
	// A cache of responses in memory, on http and https listeners. Refused
	// on tcp and udp listeners.
	Cache CacheConfig `yaml:"cache,omitempty"`
	// Not built yet: a listener that sets it to true is refused at load.
	// gRPC is proxied to backends with backend_tls without it.
	GRPC bool `yaml:"grpc,omitempty"`
	// Not built yet: a listener that sets it is refused at load.
	Throttle ThrottleConfig `yaml:"throttle,omitempty"`
	// A request ID (X-Request-ID) for every request: kept from the client
	// when it is trusted, else made, passed to the backend, returned to the
	// client and written in the access log. Refused on tcp and udp
	// listeners.
	RequestID RequestIDConfig `yaml:"request_id,omitempty"`

	// Turns this listener's access-log lines on or off, whatever
	// logging.access says.
	//
	// Load sets it from logging.access when the listener does not.
	AccessLog *bool `yaml:"access_log,omitempty"`
}

// AccessLogOn reports whether the listener writes access-log lines: its
// own access_log, else on (Load fills that in from logging.access).
func (l *Listener) AccessLogOn() bool { return l.AccessLog == nil || *l.AccessLog }

// BufferingConfig defines request/response buffer sizes. RequestBodyBuffer
// is NOT IMPLEMENTED: a listener that sets it is rejected at load.
type BufferingConfig struct {
	// Not built yet: a listener that sets it is refused at load.
	RequestBodyBuffer string `yaml:"request_body_buffer,omitempty"`
	// The size of the buffer each response body is copied through, such as
	// "256KB", for the sites the event loops hand to the Go HTTP server:
	// those that compress, cache, or ask for client certificates. Default
	// 32KB. The event loops relay with buffers of their own.
	ResponseBuffer string `yaml:"response_buffer,omitempty"`
}

// CacheConfig defines response caching settings.
type CacheConfig struct {
	// Turns the cache on for the listener's responses.
	Enabled bool `yaml:"enabled"`
	// The most memory the cache holds, such as "256MB". Default 64MB. One
	// response is kept only up to 8MB, or up to max_size when that is
	// smaller.
	MaxSize string `yaml:"max_size,omitempty"`
	// How long a response stays in the cache, such as "5m". Default 5m.
	// Responses marked no-cache, no-store or private, and those that set a
	// cookie, are not kept.
	DefaultTTL string `yaml:"default_ttl,omitempty"`
	// The request methods whose responses are kept. Default GET.
	Methods []string `yaml:"methods,omitempty"`
}

// CompressionConfig defines response compression settings.
type CompressionConfig struct {
	// Turns gzip compression on, for the clients that accept it.
	Enabled bool `yaml:"enabled"`
	// The content types compressed. Default text/html, text/css,
	// text/plain, text/xml, application/json, application/javascript and
	// application/xml.
	Types []string `yaml:"types,omitempty"`
	// The smallest response compressed, in bytes, read from its
	// Content-Length; a response without one is compressed. 0 (the
	// default): every size.
	MinLength int `yaml:"min_length,omitempty"`
}

// IPRateLimitConfig defines per-IP rate limiting.
type IPRateLimitConfig struct {
	// The requests a second each client address may make over time; past
	// it a request is answered 429. 0 (the default): no limit.
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	// How many requests a client address may make at once before the rate
	// counts. Default 1.
	Burst int `yaml:"burst"`
}

// ACLRule defines an access control rule.
type ACLRule struct {
	// What a request must be for the rule to apply: every condition set
	// must hold.
	Match ACLMatch `yaml:"match"`
	// What the rule does to a request it matches: allow or deny.
	Action string `yaml:"action"`
	// The status a deny rule answers with. Default 403; 404 hides that the
	// path exists. Not used by an allow rule.
	Status int `yaml:"status,omitempty"`
}

// ACLMatch defines conditions for an ACL rule. All specified conditions must
// match (AND); an empty field is a wildcard for that dimension.
type ACLMatch struct {
	// Client addresses and ranges ("10.0.0.0/8"); the client as
	// ip_allowlist sees it.
	SourceIP []string `yaml:"source_ip,omitempty"`
	// Request methods, such as GET or POST. Not on tcp and udp listeners.
	Method []string `yaml:"method,omitempty"`
	// Request headers and the values they must have. Not on tcp and udp
	// listeners.
	Headers map[string]string `yaml:"headers,omitempty"`
	// The start of the request path, such as "/admin". The path is read as
	// the backend reads it ("//admin" and "/x/../admin" are "/admin"), and
	// case matters. Not on tcp and udp listeners.
	PathPrefix string `yaml:"path_prefix,omitempty"`
	// A regular expression (RE2) the request path must match, such as
	// "^/admin(/|$)", which leaves "/administrator" alone. Not on tcp and
	// udp listeners.
	PathRegex string `yaml:"path_regex,omitempty"`
}

// RateLimitConfig defines per-listener connection rate limiting.
type RateLimitConfig struct {
	// What the listener takes a second over time: new connections (tcp),
	// new sessions (udp) or requests (http, https). Past it a connection
	// is closed, a session's datagrams dropped, a request answered 429.
	// 0 (the default): no limit.
	ConnectionsPerSecond float64 `yaml:"connections_per_second"`
	// How many the listener takes at once before the rate counts. Default
	// 1.
	Burst int `yaml:"burst"`
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
// OCSPStapling and AutoCert are NOT IMPLEMENTED: true is rejected at load.
type TLSConfig struct {
	// The certificate file (PEM), with its chain. Read again on a reload,
	// so a renewed certificate is taken without a restart.
	Cert string `yaml:"cert"`
	// The private key file (PEM) of the certificate.
	Key string `yaml:"key"`
	// Not built yet: a listener that sets it to true is refused at load.
	AutoCert bool `yaml:"auto_cert"`
	// Not built yet: a listener that sets it to true is refused at load.
	OCSPStapling bool `yaml:"ocsp_stapling,omitempty"`
	// Client certificates: require (the handshake fails without one that
	// client_ca verifies), request (asked for, not required) or none (the
	// default). On a bind address shared by several https listeners, each
	// listener has its own, chosen by the server name; a request whose
	// Host names a listener that requires one, on a connection that began
	// with another's name, is answered 421.
	ClientAuth string `yaml:"client_auth,omitempty"`
	// The file (PEM) of the certificate authorities that client
	// certificates are verified with. Required by client_auth: require;
	// refused without client_auth.
	ClientCA string `yaml:"client_ca,omitempty"`

	// The lowest TLS version accepted: 1.2 (the default) or 1.3.
	MinVersion string `yaml:"min_version,omitempty"`
	// The highest TLS version accepted: 1.2 or 1.3 (the default).
	MaxVersion string `yaml:"max_version,omitempty"`
	// The cipher suites allowed for TLS 1.2, by their standard names, such
	// as TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256. Empty: a safe default list.
	// TLS 1.3 has fixed suites.
	CipherSuites []string `yaml:"cipher_suites,omitempty"`
}

// RouteConfig defines an L7 route matching rule.
type RouteConfig struct {
	// The requests the route takes: every condition set must hold.
	Match RouteMatch `yaml:"match"`
	// The backend the route's requests go to, by its name. Required unless
	// the route redirects, serves files or passes to FastCGI.
	Backend string `yaml:"backend,omitempty"`
	// Request and response headers added, set or removed for the route's
	// requests, after the listener's.
	Headers HeadersConfig `yaml:"headers,omitempty"`
	// A new path for the request on its way to the backend.
	Rewrite RewriteConfig `yaml:"rewrite,omitempty"`
	// Answers the route's requests with a redirect.
	Redirect RedirectConfig `yaml:"redirect,omitempty"`
	// Not built yet: a route that sets it is refused at load.
	Scripts ScriptsConfig `yaml:"scripts,omitempty"`
	// Serves the route's requests from files.
	Static StaticConfig `yaml:"static,omitempty"`
	// Files tried in turn for a request, as nginx's try_files does.
	TryFiles TryFilesConfig `yaml:"try_files,omitempty"`
	// Cache-Control and Expires of the route's answers: a time such as
	// "1y", "30d", "1h" or "10m"; "-1" for never kept; "epoch" for already
	// expired; "off" or empty to leave the headers as they are.
	Expires string `yaml:"expires,omitempty"`
	// Passes the route's requests to a FastCGI server, such as PHP-FPM.
	FastCGI FastCGIConfig `yaml:"fastcgi,omitempty"`
}

// FastCGIConfig defines FastCGI upstream (e.g., PHP-FPM) settings.
type FastCGIConfig struct {
	// The FastCGI server's address: "127.0.0.1:9000", or a socket file as
	// "unix:/run/php/php-fpm.sock".
	Pass string `yaml:"pass"`
	// The directory the scripts lie in, as the FastCGI server sees it, and
	// nvelox at the same path. Required: only a .php file that exists in it
	// is run.
	DocumentRoot string `yaml:"document_root,omitempty"`
	// SCRIPT_NAME as the script is told it. Default: from the request path.
	ScriptName string `yaml:"script_name,omitempty"`
	// A regular expression that splits the path into the script and
	// PATH_INFO, as nginx's fastcgi_split_path_info does, such as
	// "^(.+\.php)(/.+)$".
	SplitPathInfo string `yaml:"split_path_info,omitempty"`
	// More FastCGI parameters, by name.
	Params map[string]string `yaml:"params,omitempty"`
	// Not built yet: a route that sets it is refused at load. try_files
	// names the script a request falls back to.
	Index string `yaml:"index,omitempty"`
	// Three timeouts apply to a FastCGI server: connect (how long the
	// connection to it may take: default the listener's, else 10s; 502 when
	// it fails), send (how long it may pause in taking the request body:
	// default 60s, then 504) and response_header (how long it may take to
	// start answering once it has the request: default 60s, then 504). The
	// others are refused here.
	Timeouts TimeoutConfig `yaml:"timeouts,omitempty"`
}

// StaticConfig defines static file serving.
type StaticConfig struct {
	// The directory files are served from: a request's path names a file
	// under it, and never one outside it.
	Root string `yaml:"root"`
	// The files served for a directory, in order. Default index.html.
	Index []string `yaml:"index,omitempty"`
	// Lists a directory that has no index file.
	//
	// (core/httpproxy/autoindex.go.)
	Autoindex bool `yaml:"autoindex,omitempty"`
}

// TryFilesConfig defines try_files behavior.
type TryFilesConfig struct {
	// The files tried in order under static.root, the first that exists
	// served: $uri is the request path, $uri/ the directory with its index,
	// $args the query, $is_args "?" when there is one. Such as
	// ["$uri", "$uri/", "/index.php$is_args$args"].
	Files []string `yaml:"files"`
	// What answers when no file exists: "=404" (a status), or a path, such
	// as "/index.php", served by the same route.
	Fallback string `yaml:"fallback"`
}

// ScriptsConfig defines Lua script hooks for a route. NOT IMPLEMENTED: no
// code path runs them, so a route that sets either script is rejected at load.
type ScriptsConfig struct {
	// Not built yet: a route that sets it is refused at load.
	RequestScript string `yaml:"request_script,omitempty"`
	// Not built yet: a route that sets it is refused at load.
	ResponseScript string `yaml:"response_script,omitempty"`
}

// RouteMatch defines the conditions for matching an HTTP request.
type RouteMatch struct {
	// The request's host name, exactly, in any case.
	Host string `yaml:"host,omitempty"`
	// The start of the request path, such as "/api/".
	PathPrefix string `yaml:"path_prefix,omitempty"`
	// A regular expression (RE2) the request path must match; its groups
	// can be used as $1, $2 in rewrite.path and redirect.url.
	PathRegex string `yaml:"path_regex,omitempty"`
}

// RewriteConfig defines URL rewriting.
type RewriteConfig struct {
	// The path the backend is asked for instead of the request's, with $1,
	// $2 for the groups of match.path_regex, such as "/v2/$1".
	Path string `yaml:"path,omitempty"`
}

// RedirectConfig defines HTTP redirect responses.
type RedirectConfig struct {
	// Where the redirect points, with ${scheme}, ${host}, ${port},
	// ${path}, ${query} and ${uri} of the request, and $1, $2 for the
	// groups of match.path_regex: "https://${host}${uri}", say.
	URL string `yaml:"url,omitempty"`
	// The redirect's status code. Default 302.
	Code int `yaml:"code,omitempty"`
}

// SNIRoute defines TLS passthrough routing based on server name. NOT
// IMPLEMENTED: listeners[].sni_routes is rejected at load.
type SNIRoute struct {
	// Not built yet: a listener with sni_routes is refused at load.
	ServerName string `yaml:"server_name"`
	// Not built yet: a listener with sni_routes is refused at load.
	Backend string `yaml:"backend"`
}

// TimeoutConfig defines configurable timeouts for listeners and backends.
// Every value is a duration; "0" means no limit.
//
// On HTTP listeners, ReadHeader bounds the time spent parsing request headers
// (slowloris guard) and is enforced at the http.Server level; it is shared
// across sites on the same bind port (one http.Server) — the engine uses the
// max configured value across sites, falling back to a sensible default.
// Read and Write limit how long a transfer with the client may be stuck, not
// how long it may take: Read is how long nvelox waits for the next piece of a
// request body, Write how long it waits for the client to take the next piece
// of the response. A quiet event stream, or an upload or download that keeps
// moving, is never cut. Both are applied per request once the routing site is
// known, so two sites sharing a bind port can have different values.
//
// On backends (HTTP): Connect is the dial timeout (else the listener's, else
// 10s), ResponseHeader the time the backend gets to start answering once the
// request was sent, and Read the longest the backend may stay silent once it
// has started answering (no limit unless set). Write, Idle and ReadHeader are
// listener settings and are refused on a backend.
type TimeoutConfig struct {
	// How long opening a connection to a server may take, such as "5s": a
	// backend's own, else its listener's, else 10s. When it fails a
	// request is answered 502, a tcp client's connection closed. "0": no
	// limit.
	Connect string `yaml:"connect,omitempty"`
	// On an http or https listener: how long a client may take to send a
	// request's head. Default 10s. The listeners on one bind address share
	// one value, the largest they set. "0": no limit. Refused on a tcp
	// listener, on a backend and on a fastcgi route.
	ReadHeader string `yaml:"read_header,omitempty"`
	// On an http or https listener: how long a client may pause while it
	// sends a request body (default 60s). On a backend: how long a server
	// may stay silent once it has started to answer (no limit unless set).
	// A transfer that keeps moving is never cut. "0": no limit. Refused on
	// a tcp listener and on a fastcgi route.
	Read string `yaml:"read,omitempty"`
	// On an http or https listener: how long a client may pause while it
	// takes a response. Default 60s. A download that keeps moving is never
	// cut. "0": no limit. Refused on a tcp listener, on a backend and on a
	// fastcgi route.
	Write string `yaml:"write,omitempty"`
	// How long a connection may stay idle on a listener: on http and https
	// a kept-alive connection between requests (default 120s; the
	// listeners on one bind address share the largest they set); on tcp, with
	// tls or without, a connection with no traffic either way (default 5m).
	// "0": no limit. Refused on a backend and on a fastcgi route.
	Idle string `yaml:"idle,omitempty"`
	// On a backend, or a fastcgi route: how long a server may take to
	// start answering once it has the request. Default 60s, then 504.
	// Refused on a listener. "0": no limit.
	ResponseHeader string `yaml:"response_header,omitempty"`
	// On a fastcgi route: how long a FastCGI server may pause in taking the
	// request body. Default 60s; past it the exchange ends, with a 504 if
	// the server had not begun to answer. An upload it keeps taking is
	// never cut. "0": no limit. Refused on a listener and on a backend.
	Send string `yaml:"send,omitempty"`
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

// ResolveResponseHeader mirrors ResolveRead for a backend's response-header
// timeout.
func (t TimeoutConfig) ResolveResponseHeader(def time.Duration) time.Duration {
	if t.ResponseHeader == "" {
		return def
	}
	d, _ := time.ParseDuration(t.ResponseHeader)
	return d
}

// ResolveSend returns a fastcgi route's send timeout: def when unset, 0 (no
// limit) for "0".
func (t TimeoutConfig) ResolveSend(def time.Duration) time.Duration {
	if t.Send == "" {
		return def
	}
	d, _ := time.ParseDuration(t.Send)
	return d
}

// validateTimeout checks one timeout value: empty (unset) or a duration that
// is not negative ("0" = no limit). A negative value used to pass and act as
// no limit at all.
func validateTimeout(val string) error {
	if val == "" {
		return nil
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return err
	}
	if d < 0 {
		return fmt.Errorf("must not be negative")
	}
	return nil
}

// validateBackendTimeouts checks a backend's timeouts: connect,
// response_header and read must be valid durations; write, idle and
// read_header are listener settings, refused here because on a backend they
// would do nothing.
func validateBackendTimeouts(b Backend) error {
	t := b.Timeouts
	if t.Send != "" {
		return fmt.Errorf("backend %s: timeouts.send is a fastcgi route setting; a backend takes connect, response_header and read", b.Name)
	}
	for _, f := range []struct{ name, val string }{
		{"write", t.Write}, {"idle", t.Idle}, {"read_header", t.ReadHeader},
	} {
		if f.val != "" {
			return fmt.Errorf("backend %s: timeouts.%s is a listener setting; a backend takes connect, response_header and read", b.Name, f.name)
		}
	}
	for _, f := range []struct{ name, val string }{
		{"connect", t.Connect}, {"response_header", t.ResponseHeader}, {"read", t.Read},
	} {
		if err := validateTimeout(f.val); err != nil {
			return fmt.Errorf("backend %s has invalid %s timeout %q: %v", b.Name, f.name, f.val, err)
		}
	}
	return nil
}

// ReplayWindowRequired reports whether a signed header must carry a counter
// (accept_proxy_replay_window: required).
func (l Listener) ReplayWindowRequired() bool { return l.AcceptProxyReplayWindow == "required" }

// validateFastCGITimeouts checks a fastcgi route's timeouts: connect and
// response_header, as on an HTTP backend, and send; the others would do
// nothing on a fastcgi route and are refused.
func validateFastCGITimeouts(t TimeoutConfig) error {
	for _, f := range []struct{ name, val string }{
		{"read", t.Read}, {"write", t.Write}, {"idle", t.Idle}, {"read_header", t.ReadHeader},
	} {
		if f.val != "" {
			return fmt.Errorf("timeouts.%s does nothing on a fastcgi route; it takes connect, response_header and send", f.name)
		}
	}
	for _, f := range []struct{ name, val string }{
		{"connect", t.Connect}, {"response_header", t.ResponseHeader}, {"send", t.Send},
	} {
		if err := validateTimeout(f.val); err != nil {
			return fmt.Errorf("timeouts.%s %q: %v", f.name, f.val, err)
		}
	}
	return nil
}

// httpOnlyBackendTimeout names a timeouts field of b that only the HTTP path
// uses (response_header, read), or "" when it sets none.
func httpOnlyBackendTimeout(b Backend) string {
	switch {
	case b.Timeouts.ResponseHeader != "":
		return "response_header"
	case b.Timeouts.Read != "":
		return "read"
	}
	return ""
}

// HeadersConfig defines request/response header manipulation.
type HeadersConfig struct {
	// Headers added to the request on its way to the backend, next to
	// those of the same name it has.
	RequestAdd map[string]string `yaml:"request_add,omitempty"`
	// Headers set on the request on its way to the backend, in place of
	// those of the same name.
	RequestSet map[string]string `yaml:"request_set,omitempty"`
	// Headers removed from the request on its way to the backend.
	RequestRemove []string `yaml:"request_remove,omitempty"`
	// Headers added to the response on its way to the client.
	ResponseAdd map[string]string `yaml:"response_add,omitempty"`
	// Headers set on the response on its way to the client, in place of
	// those of the same name.
	ResponseSet map[string]string `yaml:"response_set,omitempty"`
	// Headers removed from the response on its way to the client.
	ResponseRemove []string `yaml:"response_remove,omitempty"`
}

// Backend defines a server pool.
type Backend struct {
	// The backend's name, which listeners and routes refer to. Required,
	// and one to a backend.
	Name string `yaml:"name"`
	// How a server is picked for each connection or request: roundrobin
	// (the default) in turn, leastconn the one with the fewest open,
	// random at random.
	Balance string `yaml:"balance"`
	// Begins every connection to the servers, and every datagram, with a
	// PROXY protocol version 2 header that names the client. The server
	// must expect it on every connection.
	SendProxyV2 bool `yaml:"send_proxy_v2"`
	// Signs that header with the first key of this file (as a listener's
	// accept_proxy_key_file holds them), for a receiver that checks it.
	// Signed in version 2, bound to both ends of the connection or
	// datagram: the receiver must see the addresses nvelox sends from and
	// to, with no address translation between them. nvelox 1.3.0 and
	// older, and 2.0.0-rc.3 and older, refuse it, so upgrade the receivers
	// first. Needs send_proxy_v2.
	SendProxyKeyFile string `yaml:"send_proxy_key_file,omitempty"`
	// SendProxyKey is loaded from SendProxyKeyFile by Load.
	SendProxyKey []byte `yaml:"-"`
	// The servers' addresses, such as "10.0.0.5:8080" or
	// "app.internal:8080"; a server without a port takes the listener's.
	Servers []string `yaml:"servers"`
	// The most HTTP requests, TCP connections or UDP sessions the backend
	// serves at once: past it a request is answered 503, a connection or
	// session refused. 0 (the default): no limit.
	MaxConnections int `yaml:"max_connections"`

	// How long a server gets to accept a connection, to start answering
	// and to stay silent once it has started.
	Timeouts TimeoutConfig `yaml:"timeouts,omitempty"`
	// Trying another server when the first fails.
	Retry RetryConfig `yaml:"retry,omitempty"`
	// Keeping a client on the server it began with.
	StickySession StickyConfig `yaml:"sticky_session,omitempty"`
	// Makes nvelox look the servers' names up itself, at this interval,
	// such as "30s", and spread the traffic over every address a name has.
	// Empty: a name is looked up as each connection to it is opened.
	ResolveInterval string `yaml:"resolve_interval,omitempty"`
	// With resolve_interval: lets the servers, by address or by name, be
	// private addresses (10.0.0.0/8 and the other private ranges,
	// loopback, link-local, carrier-grade NAT). Off (the default), such an
	// address is left out and logged, so that a name someone else controls
	// cannot point nvelox into your network. Turn it on when the servers
	// are on a private network.
	AllowPrivateIPs bool `yaml:"allow_private_ips,omitempty"`
	// TLS to the servers, for http and https listeners.
	BackendTLS BackendTLSConfig `yaml:"backend_tls,omitempty"`
	// Stops sending to the backend for a while after failures in a row.
	CircuitBreaker CBConfig `yaml:"circuit_breaker,omitempty"`
	// Checks that take a failing server out of the rotation, and bring it
	// back.
	HealthCheck HealthCheckConfig `yaml:"health_check,omitempty"`
}

// CBConfig defines circuit breaker settings per backend.
type CBConfig struct {
	// Turns the circuit breaker on.
	Enabled bool `yaml:"enabled"`
	// How many failed requests in a row open the breaker: the backend's
	// requests are then answered 503 at once.
	Threshold int `yaml:"threshold"`
	// How long the breaker stays open before it lets requests try again,
	// such as "30s". Default 30s.
	Timeout string `yaml:"timeout"`
	// How many requests may try at once when the breaker lets them;
	// success closes it, failure opens it again. Default 1.
	HalfOpenMax int `yaml:"half_open_max"`
}

// BackendTLSConfig defines TLS settings for connecting to backend servers.
// Implemented for http/https listeners only: a backend with backend_tls
// enabled cannot serve a tcp or udp listener (rejected at load). The CA and
// client key pair are checked at load, and a backend whose TLS config cannot
// be built fails startup / the reload — nvelox never falls back to plaintext.
type BackendTLSConfig struct {
	// Connects to the servers over TLS. A backend that cannot build its
	// TLS settings stops the start or the reload: nvelox never falls back
	// to plain text. For http and https listeners only.
	Enabled bool `yaml:"enabled"`
	// The file (PEM) of the certificate authorities the servers'
	// certificates are verified with. Empty: the system's.
	CACert string `yaml:"ca_cert,omitempty"`
	// The certificate file (PEM) nvelox presents to servers that ask for
	// one.
	ClientCert string `yaml:"client_cert,omitempty"`
	// The private key file (PEM) of client_cert.
	ClientKey string `yaml:"client_key,omitempty"`
	// Accepts any certificate from the servers, without verifying it: for
	// tests, never across a network you do not control. A warning says so
	// at start.
	Insecure bool `yaml:"insecure,omitempty"`
	// The name sent to the servers (SNI) and checked on their certificates.
	// Empty: the host of each server's address.
	ServerName string `yaml:"server_name,omitempty"`
}

// RetryConfig defines retry behavior on backend failure.
type RetryConfig struct {
	// How many servers a request tries, the first included. Default 1: no
	// retry.
	Attempts int `yaml:"attempts"`
	// When a request tries the next server, separated by commas:
	// connect_failure (the server could not be reached), 502, 503. Default
	// connect_failure.
	On string `yaml:"on"`
}

// StickyConfig defines session persistence.
type StickyConfig struct {
	// What keeps a client on its server: cookie (one nvelox sets), header
	// (one the client sends) or ip_hash (its address). Empty: none.
	Type string `yaml:"type"`
	// The cookie's name for type cookie. Default NVELOX_SRV.
	CookieName string `yaml:"cookie_name"`
	// The header's name for type header.
	HeaderName string `yaml:"header_name"`
	// How long a client stays on its server without a request, such as
	// "1h". Default 1h.
	TTL string `yaml:"ttl"`
}

// HealthCheckConfig holds the backend's health checks: active checks nvelox
// makes itself, and passive ones that watch the requests.
type HealthCheckConfig struct {
	// Checks nvelox makes of every server at an interval: a server that
	// fails one is out of the rotation until it passes one.
	Active ActiveHealthCheck `yaml:"active,omitempty"`
	// Takes a server out of the rotation after failed requests in a row.
	Passive PassiveHealthCheck `yaml:"passive,omitempty"`
}

type ActiveHealthCheck struct {
	// What a check is: tcp (the default) opens a connection; http asks for
	// path and wants a status from 200 to 399.
	Type string `yaml:"type"`
	// The path an http check asks for, such as "/healthz".
	Path string `yaml:"path"`
	// How often each server is checked, such as "10s". Active checks run
	// only when it is set.
	Interval string `yaml:"interval"`
	// How long a check may take, such as "2s". Default 1s.
	Timeout string `yaml:"timeout"`
}

type PassiveHealthCheck struct {
	// How many failed requests in a row take a server out of the rotation,
	// for 30 seconds; it then takes traffic again, and its next failure
	// takes it out again. When every server is out, they are all used.
	// 0 (the default): off.
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
	// A key no setting reads (a misspelled one, or one written a level off)
	// is refused: it would be a setting that silently changes nothing
	// (strict.go).
	if err := checkKeys(data, path, reflect.TypeOf(cfg)); err != nil {
		return nil, err
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
			subData, err := ReadNamedFile(match)
			if err != nil {
				// Warn but continue? Or fail? Nginx fails usually.
				return nil, fmt.Errorf("failed to read included config %s: %w", match, err)
			}
			var subCfg Config
			if err := yaml.Unmarshal(subData, &subCfg); err != nil {
				return nil, fmt.Errorf("failed to parse included config %s: %w", match, err)
			}
			// An included file adds listeners and backends, nothing else:
			// any other setting in it, and any unknown key, is refused
			// rather than dropped without a word.
			if err := checkIncludeKeys(subData, match); err != nil {
				return nil, err
			}
			if err := checkKeys(subData, match, reflect.TypeOf(subCfg)); err != nil {
				return nil, err
			}
			if subCfg.Version != "" && subCfg.Version != cfg.Version {
				return nil, fmt.Errorf("%s: version %q differs from the main config file's %q", match, subCfg.Version, cfg.Version)
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
		// The access log: the listener's own access_log, else
		// logging.access, else on.
		if l.AccessLog == nil && cfg.Logging.Access != nil {
			on := *cfg.Logging.Access
			l.AccessLog = &on
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
	if err := loadProxyKeys(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// minProxyKeyLen is the shortest PROXY signing key accepted (characters).
const minProxyKeyLen = 32

// loadProxyKeys reads the accept_proxy_key_file and send_proxy_key_file of
// every listener and backend.
func loadProxyKeys(cfg *Config) error {
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		if l.AcceptProxyKeyFile == "" {
			continue
		}
		keys, err := readProxyKeyFile(l.AcceptProxyKeyFile)
		if err != nil {
			return fmt.Errorf("listener %s: accept_proxy_key_file: %v", l.Name, err)
		}
		l.AcceptProxyKeys = keys
	}
	for i := range cfg.Backends {
		b := &cfg.Backends[i]
		if b.SendProxyKeyFile == "" {
			continue
		}
		if !b.SendProxyV2 {
			return fmt.Errorf("backend %s: send_proxy_key_file needs send_proxy_v2: true", b.Name)
		}
		keys, err := readProxyKeyFile(b.SendProxyKeyFile)
		if err != nil {
			return fmt.Errorf("backend %s: send_proxy_key_file: %v", b.Name, err)
		}
		b.SendProxyKey = keys[0]
	}
	return nil
}

// readProxyKeyFile returns the keys of a key file: one per line, surrounding
// spaces trimmed, blank lines and "#" comments skipped, each at least
// minProxyKeyLen characters. A file other users can read is reported.
func readProxyKeyFile(path string) ([][]byte, error) {
	data, err := ReadNamedFile(path)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "[CONFIG] WARNING: key file %s has mode %#o; other users should not read it (chmod 600)\n", path, fi.Mode().Perm())
	}
	var keys [][]byte
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) < minProxyKeyLen {
			return nil, fmt.Errorf("%s line %d: key shorter than %d characters", path, n+1, minProxyKeyLen)
		}
		keys = append(keys, []byte(line))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no key", path)
	}
	return keys, nil
}

func validate(cfg *Config) error {
	if cfg.Version != "2" {
		return fmt.Errorf("unsupported version: %s (expected '2')", cfg.Version)
	}
	if err := validateShutdownTimeout(cfg.Server.ShutdownTimeout); err != nil {
		return fmt.Errorf("server.shutdown_timeout: %v", err)
	}
	if err := validateHTTP3(cfg.Server.HTTP3); err != nil {
		return err
	}
	if err := rejectUnimplementedServerKeys(cfg); err != nil {
		return err
	}

	backendNames := make(map[string]bool)
	backendTLS := make(map[string]bool)        // backend name -> backend_tls enabled
	backendHTTPOnly := make(map[string]string) // backend name -> an HTTP-only timeouts field it sets
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

		if err := validateBackendTimeouts(b); err != nil {
			return err
		}
		backendHTTPOnly[b.Name] = httpOnlyBackendTimeout(b)
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
		if l.AcceptProxyKeyFile != "" && len(l.AcceptProxyFrom) == 0 {
			return fmt.Errorf("listener %s: accept_proxy_key_file needs accept_proxy_from (the peers whose signed headers are trusted)", l.Name)
		}
		switch l.AcceptProxyReplayWindow {
		case "", "when_present", "required":
		default:
			return fmt.Errorf("listener %s: accept_proxy_replay_window %q: want when_present or required", l.Name, l.AcceptProxyReplayWindow)
		}
		if l.AcceptProxyReplayWindow != "" && l.AcceptProxyKeyFile == "" {
			return fmt.Errorf("listener %s: accept_proxy_replay_window needs accept_proxy_key_file: only a signed header carries a counter", l.Name)
		}
		if len(l.AcceptProxyInterfaces) > 0 {
			if l.Protocol != "udp" {
				return fmt.Errorf("listener %s: accept_proxy_interfaces applies to udp listeners (a TCP handshake already proves the peer address)", l.Name)
			}
			if len(l.AcceptProxyFrom) == 0 {
				return fmt.Errorf("listener %s: accept_proxy_interfaces needs accept_proxy_from", l.Name)
			}
			for _, name := range l.AcceptProxyInterfaces {
				if strings.TrimSpace(name) == "" {
					return fmt.Errorf("listener %s: accept_proxy_interfaces has an empty name", l.Name)
				}
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
			if f := backendHTTPOnly[l.Backend]; f != "" {
				return fmt.Errorf("listener %s: backend %s sets timeouts.%s, which only http/https listeners use; give this %s listener a backend without it",
					l.Name, l.Backend, f, proto)
			}
			if err := rejectHTTPOnlyKeys(l, proto); err != nil {
				return err
			}
		}

		// Validate listener timeouts. response_header is a backend setting.
		if l.Timeouts.ResponseHeader != "" {
			return fmt.Errorf("listener %s: timeouts.response_header is a backend setting (the time a backend gets to start answering)", l.Name)
		}
		if l.Timeouts.Send != "" {
			return fmt.Errorf("listener %s: timeouts.send is a fastcgi route setting (how long a FastCGI server may pause in taking a request body)", l.Name)
		}
		for _, field := range []struct{ name, val string }{
			{"connect", l.Timeouts.Connect}, {"read_header", l.Timeouts.ReadHeader},
			{"read", l.Timeouts.Read}, {"write", l.Timeouts.Write}, {"idle", l.Timeouts.Idle},
		} {
			if err := validateTimeout(field.val); err != nil {
				return fmt.Errorf("listener %s has invalid %s timeout %q: %v", l.Name, field.name, field.val, err)
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
		// HTTP/3 through relays needs signed headers. A UDP source address
		// is forged with one packet: with accept_proxy_from alone, anyone
		// who can send a datagram that claims a relay's address could name
		// any client.
		if l.HTTP3 && len(l.AcceptProxyFrom) > 0 && l.AcceptProxyKeyFile == "" {
			return fmt.Errorf("listener %s: http3 with accept_proxy_from needs accept_proxy_key_file: a relay's datagrams are told from forged ones by their signature only", l.Name)
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

	// One udp listener per port (before the bind-group rules, whose
	// server_name rules are about HTTP sites).
	if err := validateUDPPorts(cfg.Listeners); err != nil {
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

// MaxWorkers is the most event loops server.workers may ask for.
const MaxWorkers = 1024

// rejectUnimplementedServerKeys refuses the top-level keys that are parsed
// but have no implementation (tracing), and checks server.workers.
func rejectUnimplementedServerKeys(cfg *Config) error {
	if t := cfg.Tracing; t.Enabled || t.Endpoint != "" || t.Service != "" {
		return fmt.Errorf("tracing is not implemented (no trace would be sent); remove it")
	}
	if w := cfg.Server.Workers; w < 0 || w > MaxWorkers {
		return fmt.Errorf("server.workers: %d is not a number of event loops (1 to %d; leave it out for one per CPU core)", w, MaxWorkers)
	}
	return nil
}

// rejectHTTPOnlyKeys refuses, on a tcp or udp listener (proto), the
// settings that only http and https listeners read, and on a udp listener
// its timeouts, which no udp session reads (a session ends after
// udpIdleTimeout without a datagram, or udpNoReplyTimeout without a reply,
// in core). Each would otherwise be a control that silently does nothing
// there: ip_rate_limit on a tcp listener reads like a limit and is none.
func rejectHTTPOnlyKeys(l Listener, proto string) error {
	h := l.Headers
	var set []string
	for _, k := range []struct {
		name string
		on   bool
	}{
		{"routes", len(l.Routes) > 0},
		{"headers", len(h.RequestAdd)+len(h.RequestSet)+len(h.RequestRemove)+len(h.ResponseAdd)+len(h.ResponseSet)+len(h.ResponseRemove) > 0},
		{"compression", l.Compression.Enabled || len(l.Compression.Types) > 0 || l.Compression.MinLength != 0},
		{"cache", l.Cache.Enabled || l.Cache.MaxSize != "" || l.Cache.DefaultTTL != "" || len(l.Cache.Methods) > 0},
		{"error_pages", len(l.ErrorPages) > 0},
		{"buffering", l.Buffering.ResponseBuffer != ""},
		{"max_body_size", l.MaxBodySize != ""},
		{"ip_rate_limit", l.IPRateLimit != (IPRateLimitConfig{})},
		{"request_id", l.RequestID != (RequestIDConfig{})},
		{"trusted_proxies", len(l.TrustedProxies) > 0},
		{"server_names", len(l.ServerNames) > 0},
		{"default_server", l.DefaultServer},
	} {
		if k.on {
			set = append(set, k.name)
		}
	}
	if len(set) > 0 {
		return fmt.Errorf("listener %s: %s: only http and https listeners read these, a %s listener would ignore them; remove them", l.Name, strings.Join(set, ", "), proto)
	}
	if proto == "udp" && l.Timeouts != (TimeoutConfig{}) {
		return fmt.Errorf("listener %s: timeouts do nothing on a udp listener (a session ends after 60s without a datagram from its client, or 10s without a reply from its backend); remove them", l.Name)
	}
	if proto == "tcp" {
		var set []string
		for _, f := range []struct{ name, val string }{
			{"read_header", l.Timeouts.ReadHeader}, {"read", l.Timeouts.Read}, {"write", l.Timeouts.Write},
		} {
			if f.val != "" {
				set = append(set, "timeouts."+f.name)
			}
		}
		if len(set) > 0 {
			return fmt.Errorf("listener %s: %s: a tcp listener reads timeouts.connect and timeouts.idle only, and would ignore these; remove them", l.Name, strings.Join(set, ", "))
		}
	}
	return nil
}

// rejectUnimplementedListenerKeys refuses listener keys that are parsed but
// have no implementation (sni_routes, throttle, tls.ocsp_stapling,
// tls.auto_cert, zero_copy, grpc, buffering.request_body_buffer,
// routes[].scripts, routes[].fastcgi.index, root). Each would otherwise be
// a control that silently does nothing.
func rejectUnimplementedListenerKeys(l Listener) error {
	if l.Root != "" {
		return fmt.Errorf("listener %s: root is not implemented for a listener (nothing reads it); remove it, and serve files from a route with static.root", l.Name)
	}
	if l.ZeroCopy {
		return fmt.Errorf("listener %s: zero_copy is not implemented (connections are relayed through a buffer per direction; no kernel splice would happen); remove it", l.Name)
	}
	if l.GRPC {
		return fmt.Errorf("listener %s: grpc is not implemented (it changes nothing: gRPC is proxied to backend_tls backends with or without it); remove it", l.Name)
	}
	if l.TLS.AutoCert {
		return fmt.Errorf("listener %s: tls.auto_cert is not implemented (no certificate would be requested or renewed); remove it and set tls.cert and tls.key", l.Name)
	}
	if l.Buffering.RequestBodyBuffer != "" {
		return fmt.Errorf("listener %s: buffering.request_body_buffer is not implemented (nothing reads it); remove it", l.Name)
	}
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
		if r.FastCGI.Index != "" {
			return fmt.Errorf("listener %s: route %d: fastcgi.index is not implemented (nothing reads it); remove it, and name the script with try_files", l.Name, i)
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
		if _, err := LoadKeyPair(b.ClientCert, b.ClientKey); err != nil {
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
	data, err := ReadNamedFile(path)
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

// StartupWarnings returns what main prints on stderr at startup, whatever the
// log level: server.* keys that do nothing, and settings that are accepted but
// expose something.
func StartupWarnings(cfg *Config) []string {
	out := ServerWarnings(cfg.Server)
	for _, l := range cfg.Listeners {
		if l.Protocol == "udp" && len(l.AcceptProxyFrom) > 0 && l.AcceptProxyKeyFile == "" && len(l.AcceptProxyInterfaces) == 0 {
			out = append(out, fmt.Sprintf("listener %s: accept_proxy_from on a udp listener trusts the source address alone, which a datagram can forge: set accept_proxy_key_file or accept_proxy_interfaces, or make sure the network drops packets that claim those addresses", l.Name))
		}
		if l.Protocol == "http" || l.Protocol == "https" {
			if tp, relay, ok := firstOverlap(l.TrustedProxies, l.AcceptProxyFrom); ok {
				out = append(out, fmt.Sprintf("listener %s: trusted_proxies %s overlaps accept_proxy_from %s: a relay's PROXY header names the client, and trusted_proxies is matched against that client, so a relay does not belong in trusted_proxies (there it only covers the relay's own requests, such as health checks)", l.Name, tp, relay))
			}
		}
	}
	if cfg.Metrics.Enabled && everyAddress(cfg.Metrics.Bind) {
		out = append(out, fmt.Sprintf("metrics.bind %q listens on every address, and the metrics endpoint has no authentication: bind a specific address or restrict the port with a firewall", cfg.Metrics.Bind))
	}
	return out
}

// everyAddress reports whether bind (host:port) leaves the host empty or names
// the IPv4 or IPv6 unspecified address. An empty bind is not one of them: it
// means each server's loopback default.
func everyAddress(bind string) bool {
	if bind == "" {
		return false
	}
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return false // validation reports a malformed bind
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// ServerWarnings returns one warning per key of server.http3 that changes
// nothing on this platform, and one when server.workers asks for more
// event loops than the machine has CPU cores. main prints these at
// startup. (A key that changes nothing on every platform is refused at
// load instead: rejectUnimplementedServerKeys.)
func ServerWarnings(s ServerConfig) []string {
	return serverWarnings(s, runtime.GOOS, runtime.NumCPU())
}

// serverWarnings is ServerWarnings on the platform goos with cpus CPU cores.
func serverWarnings(s ServerConfig, goos string, cpus int) []string {
	var out []string
	if s.Workers > cpus {
		out = append(out, fmt.Sprintf("server.workers (%d) is more than this machine's %d CPU cores: the loops beyond them only take turns on the same cores", s.Workers, cpus))
	}
	return append(out, http3Warnings(s.HTTP3, goos)...)
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

// sameStrings reports whether a and b hold the same strings, in any order.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		if seen[x] == 0 {
			return false
		}
		seen[x]--
	}
	return true
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

		// Rule: one relay list and key file per bind address. A relay's
		// PROXY header arrives before the SNI or Host that selects the
		// site, so every site on the port answers for the same relays.
		if proto == "http" || proto == "https" {
			for _, s := range sites[1:] {
				if !sameStrings(s.AcceptProxyFrom, sites[0].AcceptProxyFrom) || s.AcceptProxyKeyFile != sites[0].AcceptProxyKeyFile ||
					s.ReplayWindowRequired() != sites[0].ReplayWindowRequired() {
					return fmt.Errorf("bind %s: listeners %s and %s share a port but differ in accept_proxy_from, accept_proxy_key_file or accept_proxy_replay_window",
						bind, sites[0].Name, s.Name)
				}
			}
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

// validateUDPPorts refuses two udp listeners on one port, also on different
// addresses or through overlapping ranges: a datagram is matched to its udp
// listener by the port it arrived on, so one listener's settings (backend,
// IP lists, ACL, PROXY trust) would silently apply to the other's traffic.
func validateUDPPorts(listeners []Listener) error {
	owner := make(map[int]string) // port -> udp listener
	for _, l := range listeners {
		if l.Protocol != "udp" {
			continue
		}
		first, last, err := bindPortRange(l.Bind)
		if err != nil {
			continue // reported by validateBindAddress
		}
		for p := first; p <= last; p++ {
			if other, taken := owner[p]; taken {
				return fmt.Errorf("listeners %s and %s: two udp listeners cannot share port %d, also not on different addresses",
					other, l.Name, p)
			}
			owner[p] = l.Name
		}
	}
	return nil
}

func validateBindAddress(addr string) error {
	_, _, err := bindPortRange(addr)
	return err
}

// bindPortRange returns the port of a bind address, or the first and last
// port of a range ("10.0.0.1:7000", ":17000-17100").
func bindPortRange(addr string) (first, last int, err error) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return 0, 0, fmt.Errorf("missing port")
	}
	portStr := addr[lastColon+1:]

	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) != 2 {
			return 0, 0, fmt.Errorf("invalid port range format")
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid range start port: %v", err)
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid range end port: %v", err)
		}
		if start < 1 || start > 65535 || end < 1 || end > 65535 {
			return 0, 0, fmt.Errorf("port out of range (1-65535)")
		}
		if start > end {
			return 0, 0, fmt.Errorf("port range start (%d) is greater than end (%d)", start, end)
		}
		return start, end, nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port: %v", err)
	}
	if port < 1 || port > 65535 {
		return 0, 0, fmt.Errorf("port %d out of range (1-65535)", port)
	}
	return port, port, nil
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
	if err := validateFastCGITimeouts(f.Timeouts); err != nil {
		return err
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
