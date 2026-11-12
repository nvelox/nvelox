![License](https://img.shields.io/github/license/nvelox/nvelox)
![Go Version](https://img.shields.io/github/go-mod/go-version/nvelox/nvelox)
![Latest Release](https://img.shields.io/github/v/release/nvelox/nvelox?include_prereleases&label=latest%20release&color=blue)
![Build Status](https://github.com/nvelox/nvelox/actions/workflows/release.yml/badge.svg)

# Nvelox

![logo](image.png)

**High-Performance L4/L7 Load Balancer, Reverse Proxy & Web Server (Go + nbio)**

Nvelox is a lightweight, high-performance load balancer and reverse proxy written in Go. It handles TCP/UDP (L4) and HTTP/HTTPS (L7) traffic with features comparable to nginx and HAProxy — in a single static binary with simple YAML configuration.

## Why Nvelox?

* **L4 + L7 in one binary** — TCP/UDP proxy, HTTP reverse proxy, static file server, FastCGI (PHP-FPM)
* **Massive Scale** — Bind 10,000+ ports with a single config line (port ranges)
* **HTTP/1.1 + HTTP/2 + HTTP/3** — Full protocol support including QUIC
* **nginx-compatible features** — try_files, expires, FastCGI, regex routes, URL rewrite
* **Simple YAML config** — No complex directive syntax

## Features

### Core Proxy
- **L4 TCP/UDP Proxy** — TCP relay with standard half-close semantics (back-pressured; when either side closes first, everything already read is delivered before the FIN is passed on), UDP via the nbio event loop with bounded sessions (at most 16,384, and 512 per client IP; a session its backend never answers ends after 10 s)
- **L7 HTTP Reverse Proxy** — `httputil.ReverseProxy` with shared connection pool
- **HTTP/1.1 + HTTP/2** — automatic HTTP/2 via ALPN on HTTPS listeners
- **HTTP/3 (QUIC)** — via quic-go with Alt-Svc header advertisement
- **WebSocket Proxying** — transparent upgrade detection and bidirectional relay
- **Port Ranges** — bind `:10000-20000` with 1:1 port mapping for gaming/VoIP

### Load Balancing
- **Round Robin** — cycle through backends
- **Least Connections** — accurate per-connection tracking via OnConnect/OnDisconnect
- **Random** — random server selection
- **Sticky Sessions** — cookie, header, or IP-hash based session persistence
- **Connection Draining** — mark servers as draining (no new connections, existing continue)
- **Max Connections** — per-backend concurrency limit: 503 on HTTP when full, new TCP connections / UDP sessions refused

### Routing (L7)
- **Multi-server-per-port** — multiple HTTPS sites share one bind address (nginx-style); each picks its own TLS cert via SNI and dispatches by Host header. `server_names` + `default_server` control matching, leftmost wildcards (`*.foo.com`) supported.
- **Host-based routing** — route by `Host` header (first-match-wins)
- **Path prefix routing** — route by URL path prefix
- **Regex routing** — regex path matching with capture groups
- **URL Rewriting** — `$1`-style substitution from regex captures
- **Redirect Rules** — 301/302 with variable substitution (`${host}`, `${path}`, `${uri}`, `${scheme}`, `${query}`, `${port}`)

### Static Files & PHP
- **Static File Serving** — serve from document root with directory index support
- **try_files** — nginx-style `$uri`, `$uri/`, `/fallback$is_args$args`
- **expires** — `1y`, `30d`, `1h`, `-1` (no-cache), sets Cache-Control/Expires headers
- **FastCGI (PHP-FPM)** — forward to PHP-FPM via TCP or Unix socket with `split_path_info`, custom params

### Security
- **TLS Termination** — on any TCP or HTTPS listener
- **Client Certificate Auth (mTLS)** — `client_auth: require` / `request` with `client_ca` verification on TLS-terminating TCP, HTTPS and HTTP/3 listeners; per site (by SNI) when sites share a port
- **ACLs** — match by source IP/CIDR, HTTP method, path, headers; allow/deny actions (TCP/UDP listeners: source IP only)
- **IP Allowlist/Denylist** — CIDR-based per-listener filtering on HTTP, TCP and UDP listeners (behind a trusted PROXY v2 relay, on the client it names)
- **Per-IP Rate Limiting** — token bucket per client IP with LRU cleanup
- **Per-Listener Rate Limiting** — global connection rate limit
- **Request Body Size Limit** — reject oversized request bodies
- **SSL to Backend** — TLS when connecting to upstream servers from HTTP/HTTPS listeners (mTLS supported); a broken `backend_tls` config fails startup / the reload, never falls back to plaintext

### Resilience
- **Active Health Checks** — TCP connect or HTTP GET with configurable interval/timeout
- **Passive Health Checks** — mark down after N consecutive failures
- **Retries / Failover** — retry on connect failure, 502, 503; skip failed servers
- **Circuit Breaker** — closed/open/half-open state machine per backend
- **Configurable Timeouts** — connect/read_header/read/write/idle per listener and backend; read/write are applied per-request after Host-based routing, so sites sharing a bind port can have different budgets
- **Graceful Drain** — finish in-flight connections on shutdown with configurable deadline

### Response Processing
- **Header Manipulation** — add/set/remove on request and response (per-listener and per-route)
- **X-Forwarded-For/X-Real-IP** — automatic proxy header injection
- **Gzip Compression** — configurable content types and minimum size
- **Response Caching** — in-memory cache with TTL, LRU eviction, Cache-Control support
- **Request/Response Buffering** — sync.Pool-based buffer pool for reverse proxy
- **Custom Error Pages** — styled HTML error pages (403, 404, 429, 502, 503, etc.)

### Observability & Management
- **Per-Request Access Logging** — method, path, status, bytes, latency, backend in CLF format
- **Prometheus Metrics** — `/metrics` endpoint with counters, gauges, histograms
- **Admin REST API** — runtime stats, drain/enable/disable servers
- **Hot Reload** — SIGHUP reloads the whole config without dropping in-flight connections: backends (with sticky / CB / LeastConn state preserved on rename), per-listener routes / ACL / headers / error pages, TLS certs (Let's Encrypt rotation), and bind addresses (added or removed with 10s graceful drain). Pre-flight port-availability check ensures all-or-nothing apply.

### Extensibility
- **PROXY Protocol v2** — pass client IP to backends in HAProxy format; accept it from trusted relays (`accept_proxy_from`)
- **DNS Service Discovery** — periodic hostname resolution with auto-update
- **Modular Config** — split configs via `include` glob patterns
- **Config Validation** — comprehensive validation at load time; keys that are parsed but not implemented (`sni_routes`, `throttle`, `tls.ocsp_stapling`, `routes[].scripts`) are rejected with an error naming the key, and `server.user` / `group` / `pid_file` / `workers` print a startup warning (nvelox does not drop privileges: run it under systemd `User=` with `CAP_NET_BIND_SERVICE`)

## Architecture

```mermaid
graph TD
    Client -->|TCP/UDP/HTTP| Listeners
    subgraph Nvelox
        Listeners -->|IP Filter| ACL{ACL + Rate Limit}
        ACL -->|L4 TCP| L4Relay[TCP relay, half-close]
        ACL -->|L4 UDP| NBIOEngine[nbio UDP Event Loop]
        ACL -->|L7| HTTPServer[net/http Server]
        ACL -->|FastCGI| FCGIClient[FastCGI Client]
        HTTPServer -->|Route Match| Router
        Router -->|Static| FileServer[Static Files]
        Router -->|Proxy| ReverseProxy[httputil.ReverseProxy]
        Router -->|Redirect| RedirectHandler
        L4Relay -->|Dial| BackendPool
        NBIOEngine -->|DialAsync| BackendPool
        ReverseProxy -->|Shared Transport| BackendPool[Backend Pool]
        FCGIClient --> PHPFPM[PHP-FPM]
    end
    BackendPool -->|Connection Pool| Backends(Backend Servers)
```

## Nvelox vs. nginx vs. HAProxy

| Feature | Nvelox | HAProxy | Nginx |
| :--- | :--- | :--- | :--- |
| **L4 + L7** | Both | Both | Both |
| **HTTP/3** | Yes (quic-go) | Yes (quictls) | Yes (quic) |
| **FastCGI (PHP)** | Yes | No | Yes |
| **Static Files** | Yes | No | Yes |
| **try_files** | Yes | No | Yes |
| **Lua Scripting** | No | Yes (SPOE) | Yes |
| **Port Ranges** | `:10000-20000` | Individual | Individual |
| **Config Format** | YAML | Custom | Directives |
| **Binary** | Static (Go) | Dynamic (C) | Dynamic (C) |
| **Hot Reload** | SIGHUP | Hitless | SIGHUP |
| **Memory (10k)** | ~40MB | ~150MB | ~100MB |

## Quick Start

```bash
# Build
go build -o nvelox main.go

# Run with example config
./nvelox -config examples/01-basic-tcp-proxy.yaml

# See all 30 examples
cat examples/README.md
```

## Configuration

### Basic HTTP Proxy
```yaml
version: "2"
listeners:
  - name: "web"
    bind: ":80"
    protocol: "http"
    backend: "servers"
backends:
  - name: "servers"
    balance: "roundrobin"
    servers:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
```

### HTTPS + HTTP/2 + Routing + Compression
```yaml
listeners:
  - name: "secure"
    bind: ":443"
    protocol: "https"
    tls:
      cert: "/etc/ssl/cert.pem"
      key: "/etc/ssl/key.pem"
    backend: "web"
    compression:
      enabled: true
    headers:
      response_add:
        Strict-Transport-Security: "max-age=31536000"
    routes:
      - match:
          host: "api.example.com"
        backend: "api"
      - match:
          path_prefix: "/static"
        static:
          root: "/var/www/html"
        expires: "1y"
```

### PHP-FPM with Static Files (nginx-equivalent)
```yaml
listeners:
  - name: "php-app"
    bind: ":80"
    protocol: "http"
    routes:
      - match:
          path_regex: "\\.(css|js|png|jpg|gif|ico)$"
        static:
          root: "/var/www/html"
        try_files:
          files: ["$uri"]
          fallback: "=404"
        expires: "1y"

      - match:
          path_regex: "\\.php(/|$)"
        fastcgi:
          pass: "127.0.0.1:9000"
          document_root: "/var/www/html"
          split_path_info: "^(.+\\.php)(/.*)$"

      - match:
          path_prefix: "/"
        static:
          root: "/var/www/html"
        try_files:
          files: ["$uri", "$uri/"]
          fallback: "/index.php$is_args$args"
```

As in nginx, the `try_files` fallback is an internal redirect: `/index.php`
(with the query string as `QUERY_STRING`) goes through the ACL and the routes
again and lands on the PHP route. Static routes never serve `.php`, `.phtml`
or `.phar` files as files. A `fastcgi` route needs `document_root`, and
nvelox hands PHP-FPM only an existing `.php` file inside it — nvelox must see
the document root at the same path as PHP-FPM.

### Full Production (all features)
```yaml
version: "2"
metrics:
  enabled: true
  bind: "127.0.0.1:9090"   # no auth: bind a private IP + firewall it to scrape remotely
admin:
  enabled: true
  bind: "127.0.0.1:9091"
  api_key: "<output of: openssl rand -hex 32>"   # required
logging:
  level: "info"
  access_log: "/var/log/nvelox/access.log"
  error_log: "/var/log/nvelox/error.log"

listeners:
  - name: "https"
    bind: ":443"
    protocol: "https"
    http3: true
    tls:
      cert: "/etc/ssl/cert.pem"
      key: "/etc/ssl/key.pem"
    backend: "web"
    compression: { enabled: true }
    ip_rate_limit: { requests_per_second: 100, burst: 50 }
    routes:
      - match: { host: "api.example.com" }
        backend: "api"

  - name: "http-redirect"
    bind: ":80"
    protocol: "http"
    routes:
      - match: { path_prefix: "/" }
        redirect: { url: "https://${host}${uri}", code: 301 }

backends:
  - name: "web"
    balance: "roundrobin"
    max_connections: 200
    retry: { attempts: 2, on: "connect_failure,502" }
    sticky_session: { type: "cookie", cookie_name: "SRV", ttl: "1h" }
    health_check:
      active: { type: "http", path: "/health", interval: "5s", timeout: "2s" }
      passive: { max_fails: 3 }
    circuit_breaker: { enabled: true, threshold: 5, timeout: "30s" }
    servers:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"

  - name: "api"
    balance: "leastconn"
    timeouts: { connect: "2s", read: "10s" }
    servers:
      - "10.0.1.1:8080"
```

## Admin API, Metrics and Log Files

### Admin API
- `admin.api_key` is **required** when `admin.enabled` is true: nvelox refuses to start without it. Clients send it as the `X-API-Key` header; it is compared in constant time. Use a long random key (`openssl rand -hex 32`).
- An empty `admin.bind` means `127.0.0.1:9091`. On a loopback bind only loopback clients are served. On any other bind, firewall the port to the hosts that manage nvelox.
- Call the API by its bind address: a request whose `Host` header is not the bind IP (or hostname) is refused with 403, so a DNS-rebinding web page cannot reach it. `localhost` also works on a loopback bind; a wildcard bind (`:9091`) accepts any IP literal.
- `POST` requests need `Content-Type: application/json` (the body-less backend actions too), and browser cross-site requests (`Sec-Fetch-Site` / `Origin`) are refused with 403.
- A valid key is always served. After 10 failed attempts from one IP within 10 minutes, that IP's further *failures* get `429` (with `Retry-After`) for 15 minutes.
- The denylist refuses ranges wider than an IPv4 `/8` or an IPv6 `/16` (`0.0.0.0/0`, `::/0`, `::ffff:0:0/96`, …). `ttl_seconds` ≤ 0 keeps an entry until restart.

```bash
KEY=...   # admin.api_key
curl -H "X-API-Key: $KEY" http://127.0.0.1:9091/api/v1/stats
curl -X POST -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  "http://127.0.0.1:9091/api/v1/backends/web/drain?server=10.0.0.1:8080"
curl -X POST -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"ip":"203.0.113.7","ttl_seconds":3600}' http://127.0.0.1:9091/api/v1/denylist
curl -X DELETE -H "X-API-Key: $KEY" "http://127.0.0.1:9091/api/v1/denylist?cidr=203.0.113.7"
```

### Metrics
The `/metrics` endpoint has no authentication. An empty `metrics.bind` means `127.0.0.1:9090`. To scrape from another host, bind a private interface IP and firewall the port to your Prometheus servers; never bind it to a public address. Inside a container loopback is unreachable from outside, so bind `0.0.0.0:9090` there and publish the port to trusted networks only. Slow or oversized requests are cut off (5 s header / 10 s read and write timeouts, 8 KiB of headers).

### Signals and log rotation

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Reopen the log files, then reload the config and TLS certificates |
| `SIGUSR1` | Reopen the log files |
| `SIGINT`, `SIGTERM` | Graceful shutdown |

Log files are created with mode `0640` (directories `0750`); an existing file is tightened to `0640` when nvelox opens it. After logrotate renames the files, signal nvelox so it writes to the new ones:

```
/var/log/nvelox/*.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    create 0640
    sharedscripts
    postrotate
        systemctl kill -s USR1 nvelox.service 2>/dev/null || true
        # without systemd: kill -USR1 $(pidof nvelox)
    endscript
}
```

Only the files nvelox opens itself are reopened. If a service manager appends nvelox's stdout/stderr to the same files, send that output to the journal instead.

## Examples

See [`examples/`](examples/) for 30 ready-to-run configs with test commands:

| # | Feature | Config |
|---|---------|--------|
| 01 | Basic TCP proxy | `01-basic-tcp-proxy.yaml` |
| 02 | Load balancing | `02-load-balancing.yaml` |
| 03 | Health checks | `03-health-checks.yaml` |
| 04 | Rate limiting | `04-rate-limiting.yaml` |
| 05 | TLS termination | `05-tls-termination.yaml` |
| 06 | HTTPS + HTTP/2 | `06-https-http2.yaml` |
| 07 | HTTP/3 QUIC | `07-http3-quic.yaml` |
| 08 | Host routing | `08-host-routing.yaml` |
| 09 | Path routing | `09-path-routing.yaml` |
| 10 | Regex + rewrite | `10-regex-rewrite.yaml` |
| 11 | Redirects | `11-redirects.yaml` |
| 12 | Header manipulation | `12-header-manipulation.yaml` |
| 13 | Compression | `13-compression.yaml` |
| 14 | Retries / failover | `14-retries-failover.yaml` |
| 15 | Sticky sessions | `15-sticky-sessions.yaml` |
| 16 | Max connections | `16-max-connections.yaml` |
| 17 | ACL access control | `17-acl-access-control.yaml` |
| 18 | IP allowlist/denylist | `18-ip-allowlist-denylist.yaml` |
| 19 | Body size limit | `19-body-size-limit.yaml` |
| 20 | Circuit breaker | `20-circuit-breaker.yaml` |
| 21 | Prometheus metrics | `21-metrics-prometheus.yaml` |
| 22 | Admin API | `22-admin-api.yaml` |
| 23 | Timeouts | `23-timeouts.yaml` |
| 24 | Caching | `24-caching.yaml` |
| 25 | Port range | `25-port-range.yaml` |
| 26 | PROXY protocol | `26-proxy-protocol.yaml` |
| 27 | UDP proxy | `27-udp-proxy.yaml` |
| 28 | Full production | `28-full-production.yaml` |
| 29 | Static files + try_files | `29-static-files.yaml` |
| 30 | PHP-FPM FastCGI | `30-php-fpm-fastcgi.yaml` |

## Testing

```bash
go test ./...                    # All tests (22 packages)
go test -race ./...              # Race detector
go test -v ./integration/...     # Integration tests
go test -coverprofile=c.out ./... && go tool cover -html=c.out  # Coverage
```

See [`examples/README.md`](examples/README.md) for manual real-world testing with curl.

## Project Structure

```
core/
  engine.go          — Engine orchestration, lifecycle
  handler.go         — L4 accept gating + UDP proxy (nbio)
  l4tcp.go           — L4 TCP accept loop + per-connection proxying
  relay.go           — L4 TCP relay (half-close semantics, idle timeout)
  httpproxy/
    server.go        — L7 HTTP reverse proxy
    router.go        — Route matching (host/path/regex)
    static.go        — Static files, try_files, expires
    fastcgi.go       — FastCGI client (PHP-FPM)
    compress.go      — Gzip compression
    cache.go         — Response caching
    errorhtml/       — Styled error pages
  acl/               — Access control lists
  admin/             — Admin REST API
  circuitbreaker/    — Circuit breaker state machine
  discovery/         — DNS service discovery
  health/            — Active health checks
  metrics/           — Prometheus metrics
  middleware/        — Per-IP rate limiting
  scripting/         — Lua VM pool (not wired into the engine)
  sni/               — SNI-based TLS routing (not wired into the engine)
  sticky/            — Sticky session store
  throttle/          — Bandwidth throttling (not wired into the engine)
  tlsutil/           — TLS versions/ciphers, client cert auth, SNI matching
config/              — YAML config parsing + validation
lb/                  — Load balancing algorithms
proxy/               — PROXY Protocol v2
```

## License

MIT License.
