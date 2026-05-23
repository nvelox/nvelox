# Nvelox Examples

Each YAML file demonstrates a specific feature. Run nvelox with any config and test with the commands shown below.

## Prerequisites

```bash
# Build nvelox
go build -o nvelox main.go

# Generate TLS certs (required for examples 05-07, 28)
./examples/generate-certs.sh
```

## Running Examples

The general pattern:

```bash
# Terminal 1 — Start backend(s)
go run examples/http_backend.go :8081 "backend-1"

# Terminal 2 — Start nvelox
./nvelox -config examples/<config>.yaml

# Terminal 3 — Test
curl http://127.0.0.1:9000/
```

---

## 01 — Basic TCP Proxy

```bash
# Backend (TCP echo)
go run tools/mock_backend/main.go :8081

# Nvelox
./nvelox -config examples/01-basic-tcp-proxy.yaml

# Test
echo "hello" | nc 127.0.0.1 9000
# Expected: "hello" echoed back
```

## 02 — Load Balancing

```bash
# 3 backends
go run examples/http_backend.go :8081 "backend-1" &
go run examples/http_backend.go :8082 "backend-2" &
go run examples/http_backend.go :8083 "backend-3" &

# Nvelox
./nvelox -config examples/02-load-balancing.yaml

# Test — responses should rotate across backends
for i in $(seq 1 6); do curl -s http://127.0.0.1:9000/ | head -1; done
# Expected: alternating "Hello from backend-1/2/3"
```

## 03 — Health Checks

```bash
# Start 2 backends (kill one to see health check in action)
go run examples/http_backend.go :8081 "healthy" &
go run examples/http_backend.go :8082 "will-die" &

# Nvelox
./nvelox -config examples/03-health-checks.yaml

# Test — kill backend-2, traffic should auto-route to backend-1
kill %2
curl http://127.0.0.1:9000/
# Expected: only "Hello from healthy"
```

## 04 — Rate Limiting

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/04-rate-limiting.yaml

# Test — rapid requests should hit 429
for i in $(seq 1 10); do curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9000/; done
# Expected: first few 200, then 429
```

## 05 — TLS Termination (TCP)

```bash
./examples/generate-certs.sh
go run tools/mock_backend/main.go :8081

./nvelox -config examples/05-tls-termination.yaml

# Test
echo "hello-tls" | openssl s_client -connect 127.0.0.1:9443 -quiet 2>/dev/null
# Expected: "hello-tls" echoed back
```

## 06 — HTTPS with HTTP/2

```bash
./examples/generate-certs.sh
go run examples/http_backend.go :8081 "backend"

./nvelox -config examples/06-https-http2.yaml

# Test HTTP/2
curl -k --http2 https://127.0.0.1:9443/
# Expected: "Hello from backend" + headers showing HTTP/2

# Verify protocol
curl -k -v https://127.0.0.1:9443/ 2>&1 | grep "< HTTP/"
# Expected: "< HTTP/2 200"
```

## 07 — HTTP/3 (QUIC)

```bash
./examples/generate-certs.sh
go run examples/http_backend.go :8081 "backend"

./nvelox -config examples/07-http3-quic.yaml

# Test HTTP/2 (and check Alt-Svc header)
curl -k -v https://127.0.0.1:9443/ 2>&1 | grep "alt-svc"
# Expected: alt-svc: h3=":9443"; ma=86400

# Test HTTP/3 (requires curl with HTTP/3 support or a quic-go client)
# curl --http3 -k https://127.0.0.1:9443/
```

## 08 — Host-Based Routing

```bash
go run examples/http_backend.go :8081 "web" &
go run examples/http_backend.go :8082 "api" &
go run examples/http_backend.go :8083 "admin" &

./nvelox -config examples/08-host-routing.yaml

# Test
curl -H "Host: api.localhost" http://127.0.0.1:9000/
# Expected: "Hello from api"

curl -H "Host: admin.localhost" http://127.0.0.1:9000/
# Expected: "Hello from admin"

curl http://127.0.0.1:9000/
# Expected: "Hello from web" (default backend)
```

## 09 — Path-Based Routing

```bash
go run examples/http_backend.go :8081 "web" &
go run examples/http_backend.go :8082 "api" &
go run examples/http_backend.go :8083 "cdn" &

./nvelox -config examples/09-path-routing.yaml

curl http://127.0.0.1:9000/api/users
# Expected: "Hello from api" + Path: /api/users

curl http://127.0.0.1:9000/static/img.png
# Expected: "Hello from cdn"

curl http://127.0.0.1:9000/
# Expected: "Hello from web"
```

## 10 — Regex Routing with URL Rewrite

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/10-regex-rewrite.yaml

curl http://127.0.0.1:9000/api/v2/users
# Expected: backend sees Path: /v2/users (rewritten from /api/v2/users)
```

## 11 — Redirect Rules

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/11-redirects.yaml

curl -v http://127.0.0.1:9000/old/page 2>&1 | grep "Location"
# Expected: Location: /new (301 redirect)

curl http://127.0.0.1:9000/test
# Expected: "Hello from backend" (no redirect, proxied normally)
```

## 12 — Header Manipulation

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/12-header-manipulation.yaml

curl -v http://127.0.0.1:9000/ 2>&1
# Expected in response: X-Powered-By: nvelox, Strict-Transport-Security
# Expected at backend: X-Proxy: nvelox header received
```

## 13 — Compression

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/13-compression.yaml

curl -H "Accept-Encoding: gzip" -v http://127.0.0.1:9000/ 2>&1 | grep "Content-Encoding"
# Expected: Content-Encoding: gzip

# Without gzip
curl http://127.0.0.1:9000/
# Expected: plain text (no compression)
```

## 14 — Retries and Failover

```bash
# Start only 1 of 2 configured backends
go run examples/http_backend.go :8082 "good-backend"

./nvelox -config examples/14-retries-failover.yaml

curl http://127.0.0.1:9000/
# Expected: "Hello from good-backend" (retried after failing :8081)
```

## 15 — Sticky Sessions

```bash
go run examples/http_backend.go :8081 "backend-1" &
go run examples/http_backend.go :8082 "backend-2" &

./nvelox -config examples/15-sticky-sessions.yaml

# First request
curl -c /tmp/cookies.txt http://127.0.0.1:9000/

# Subsequent requests with same cookie go to same backend
curl -b /tmp/cookies.txt http://127.0.0.1:9000/
curl -b /tmp/cookies.txt http://127.0.0.1:9000/
# Expected: all responses from same backend
```

## 16 — Max Connections

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/16-max-connections.yaml

# Normal request
curl http://127.0.0.1:9000/
# Expected: 200

# Flood with concurrent requests (ab or hey)
# hey -n 100 -c 20 http://127.0.0.1:9000/
# Expected: some 503 responses when over 5 concurrent
```

## 17 — ACL Access Control

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/17-acl-access-control.yaml

curl http://127.0.0.1:9000/
# Expected: 200 (GET allowed)

curl -X DELETE http://127.0.0.1:9000/resource
# Expected: 403 Forbidden

curl -X PUT http://127.0.0.1:9000/resource
# Expected: 403 Forbidden
```

## 18 — IP Allowlist/Denylist

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/18-ip-allowlist-denylist.yaml

curl http://127.0.0.1:9000/
# Expected: 200 (localhost is allowed)

# From another IP (if available): expected 403
```

## 19 — Body Size Limit

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/19-body-size-limit.yaml

# Small body — OK
curl -X POST -d "small" http://127.0.0.1:9000/
# Expected: 200

# Large body — rejected
curl -X POST -d "$(head -c 2048 /dev/urandom | base64)" http://127.0.0.1:9000/
# Expected: error (body too large)
```

## 20 — Circuit Breaker

```bash
# Don't start backend — let it fail
./nvelox -config examples/20-circuit-breaker.yaml

# Send requests — after 3 failures, circuit opens
for i in $(seq 1 5); do
  curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9000/
done
# Expected: first 3 return 502 (connect failure), then 503 (circuit open)
```

## 21 — Prometheus Metrics

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/21-metrics-prometheus.yaml

# Generate traffic
curl http://127.0.0.1:9000/

# Check metrics
curl http://127.0.0.1:9090/metrics
# Expected: Prometheus text format with counters/gauges
```

## 22 — Admin API

```bash
go run examples/http_backend.go :8081 "backend-1" &
go run examples/http_backend.go :8082 "backend-2" &

./nvelox -config examples/22-admin-api.yaml

# Stats
curl http://127.0.0.1:9091/api/v1/stats
# Expected: {"uptime":"...","backends":1}

# List backends
curl http://127.0.0.1:9091/api/v1/backends
# Expected: [{"name":"pool"}]

# Drain a server
curl -X POST "http://127.0.0.1:9091/api/v1/backends/pool/drain?server=127.0.0.1:8081"
# Expected: server marked as draining

# Verify traffic goes only to backend-2
curl http://127.0.0.1:9000/

# Re-enable
curl -X POST "http://127.0.0.1:9091/api/v1/backends/pool/enable?server=127.0.0.1:8081"
```

## 23 — Configurable Timeouts

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/23-timeouts.yaml

# :9000 — defaults (10s read_header / 60s read / 60s write / 120s idle)
curl http://127.0.0.1:9000/

# :9001 — tight budgets, ideal for normal HTTP traffic
curl http://127.0.0.1:9001/

# :9002 — long-upload listener with read/write: 30m, suited for things
# like Docker registry blob PUT/PATCH that stream large bodies.
curl -X POST --data-binary @big.tgz http://127.0.0.1:9002/
```

Per-listener `read` and `write` are applied after the matched site is
known, so two sites on the same bind port can have different budgets.
`read_header` and `idle` live on the shared `http.Server` per bind, so
the engine uses the max configured value across sites. An explicit `"0"`
disables a timeout (unlimited).

## 24 — Response Caching

```bash
go run examples/http_backend.go :8081 "backend"
./nvelox -config examples/24-caching.yaml

# First request — cache MISS
curl -v http://127.0.0.1:9000/ 2>&1 | grep "X-Cache"
# Expected: no X-Cache header (or MISS)

# Second request — cache HIT
curl -v http://127.0.0.1:9000/ 2>&1 | grep "X-Cache"
# Expected: X-Cache: HIT

# Bypass cache
curl -H "Cache-Control: no-cache" http://127.0.0.1:9000/
# Expected: fresh response from backend
```

## 25 — Port Range

```bash
go run tools/mock_backend/main.go :9050

./nvelox -config examples/25-port-range.yaml

echo "test" | nc 127.0.0.1 9050
# Expected: "test" echoed back (1:1 port mapping)
```

## 26 — PROXY Protocol v2

```bash
# Use a backend that understands PROXY protocol, or capture with tcpdump
go run tools/mock_backend/main.go :8081

./nvelox -config examples/26-proxy-protocol.yaml

echo "hello" | nc 127.0.0.1 9000
# Backend receives PROXY v2 header before "hello"
```

## 27 — UDP Proxy

```bash
# Start a UDP echo backend
socat -v UDP-LISTEN:8081,fork EXEC:'/bin/cat' &

./nvelox -config examples/27-udp-proxy.yaml

echo "udp-test" | nc -u 127.0.0.1 9000
# Expected: "udp-test" echoed back
```

## 28 — Full Production Config

```bash
./examples/generate-certs.sh

# Start all backends
go run examples/http_backend.go :8081 "web-1" &
go run examples/http_backend.go :8082 "web-2" &
go run examples/http_backend.go :8083 "api" &
go run tools/mock_backend/main.go :8084 &

./nvelox -config examples/28-full-production.yaml

# Test HTTP redirect
curl -v http://127.0.0.1:9080/ 2>&1 | grep "Location"
# Expected: 301 → https://localhost:9443

# Test HTTPS
curl -k https://127.0.0.1:9443/
# Expected: "Hello from web-1" or "web-2"

# Test API routing
curl -k https://127.0.0.1:9443/api/users
# Expected: "Hello from api"

# Test metrics
curl http://127.0.0.1:9090/metrics

# Test admin API
curl http://127.0.0.1:9091/api/v1/stats

# Test TCP port range
echo "game-data" | nc 127.0.0.1 9100

# Logs
tail -f /tmp/nvelox-access.log
```

## 29 — Static Files with try_files

```bash
# Create test files
mkdir -p public
echo "<h1>Hello</h1>" > public/index.html
echo "body{}" > public/style.css

./nvelox -config examples/29-static-files.yaml

# Static file served directly
curl http://127.0.0.1:9000/style.css
# Expected: "body{}" with Cache-Control: max-age=31536000

# HTML served with index
curl http://127.0.0.1:9000/
# Expected: "<h1>Hello</h1>"

# Missing file falls back to backend
curl http://127.0.0.1:9000/missing-page
# Expected: proxied to backend (or 502 if no backend running)

# Check cache headers
curl -v http://127.0.0.1:9000/style.css 2>&1 | grep "Cache-Control"
# Expected: Cache-Control: public, max-age=31536000
```

## 30 — PHP-FPM via FastCGI

```bash
# Prerequisites: PHP-FPM running on port 9000
# On Ubuntu: sudo apt install php-fpm
# Start php-fpm: sudo php-fpm -F

# Create test PHP file
sudo mkdir -p /var/www/html
echo '<?php echo "Hello from PHP " . phpversion(); ?>' | sudo tee /var/www/html/index.php

./nvelox -config examples/30-php-fpm-fastcgi.yaml

# Test PHP execution
curl http://127.0.0.1:9080/
# Expected: "Hello from PHP 8.x"

# Test static file (create one first)
echo "body{}" | sudo tee /var/www/html/style.css
curl -v http://127.0.0.1:9080/style.css 2>&1 | grep "Cache-Control"
# Expected: static file served with 1y cache

# Test PATH_INFO
curl http://127.0.0.1:9080/index.php/some/path
# Expected: PHP receives PATH_INFO=/some/path
```

### Nvelox vs Nginx — PHP-FPM Config Comparison

**Nginx:**
```nginx
server {
    listen 80;
    root /var/www/html;

    location ~ \.(css|js|png|jpg)$ {
        expires 1y;
        try_files $uri =404;
    }

    location ~ \.php(/|$) {
        fastcgi_pass 127.0.0.1:9000;
        fastcgi_split_path_info ^(.+\.php)(/.*)$;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param DOCUMENT_ROOT $document_root;
        include fastcgi_params;
    }

    location / {
        try_files $uri $uri/ /index.php$is_args$args;
    }
}
```

**Nvelox:**
```yaml
listeners:
  - name: "php-app"
    bind: ":80"
    protocol: "http"
    routes:
      - match:
          path_regex: "\\.(css|js|png|jpg)$"
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
        fastcgi:
          pass: "127.0.0.1:9000"
          document_root: "/var/www/html"
```

---

## 31 — Multi-Server-Per-Port (nginx-style)

Multiple HTTPS sites can share one bind address (e.g. `:443`), each with
its own TLS certificate, server_names, routes and policies. The right
cert is selected by SNI; the request is then dispatched to the matching
site by Host header.

```bash
# Build
go build -o nvelox .

# Validate the multi-site config (uses placeholder cert paths — adjust
# to real certs to actually run it).
./nvelox -config examples/31-multisite-per-port.yaml -test
```

Match precedence (both for cert selection and Host dispatch):

1. **Exact** — `api.example.com` beats `*.example.com`.
2. **Wildcard** — `*.foo.com` matches one extra leftmost label
   (`api.foo.com` matches; `foo.com` and `x.y.foo.com` do not).
3. **default_server** — catch-all when nothing matches. Optional; at
   most one per bind group.

Validation runs at config load — duplicate server_names, mixed
protocols on the same port, missing server_names on a non-default site,
and other footguns are caught before the listener starts.

### Nvelox vs Nginx — multi-server config comparison

**Nginx:**
```nginx
server {
    listen 443 ssl;
    server_name api.example.com;
    ssl_certificate     /etc/ssl/api.pem;
    ssl_certificate_key /etc/ssl/api.key;
    location / { proxy_pass http://api-backend; }
}
server {
    listen 443 ssl default_server;
    ssl_certificate     /etc/ssl/wildcard.pem;
    ssl_certificate_key /etc/ssl/wildcard.key;
    location / { proxy_pass http://web-backend; }
}
```

**Nvelox:**
```yaml
listeners:
  - name: api-site
    bind: ":443"
    protocol: https
    server_names: ["api.example.com"]
    tls: { cert: /etc/ssl/api.pem, key: /etc/ssl/api.key }
    backend: api-backend
  - name: web-default
    bind: ":443"
    protocol: https
    default_server: true
    tls: { cert: /etc/ssl/wildcard.pem, key: /etc/ssl/wildcard.key }
    backend: web-backend
```

---

## 32 — SIGHUP Hot Reload

Apply config edits to a running nvelox without dropping connections.

```bash
# Start with the example config (real cert paths required for the :443
# listener; tweak the file or use generated test certs).
sudo ./nvelox -config examples/32-hot-reload.yaml &

# Generate steady traffic so you can observe reload doesn't drop it.
while true; do curl -s -o /dev/null -w "%{http_code} " http://localhost/; sleep 0.2; done &

# Edit examples/32-hot-reload.yaml (add a backend server, change a
# header, rotate cert paths, add a new listener…), then:
sudo kill -HUP $(pidof nvelox)

# Watch what changed:
tail -F /var/log/nvelox/error.log | grep RELOAD
# Expected: "Reload complete: backends +N/-M/~K, bind groups +N/-M,
#           K sites swapped, K TLS certs rotated"

# Verify with Prometheus metrics:
curl -s 127.0.0.1:9100/metrics | grep nvelox_reload
# nvelox_reload_total{result="ok"} 3
# nvelox_reload_duration_seconds_sum 0.012
```

What's covered:

| Change | Behaviour on reload |
|---|---|
| Add / remove backend | Reconciled by name. Kept backends preserve balancer + sticky + circuit-breaker state. |
| Edit backend server list | `balancer.UpdateServers` — no balancer replacement, LeastConn counts preserved. |
| Edit route / ACL / headers / error pages | Per-site `siteSet` swapped atomically. In-flight requests use old config; new ones use new. |
| Rotate TLS cert files on disk | Re-loaded via `GetCertificate`. Active TLS connections keep their existing cert. |
| Add a new `bind:` address | New BindGroup started. Existing groups untouched. |
| Remove a `bind:` address | Graceful Stop, 10s drain in background. Port becomes free once drained. |
| Add a new HTTP/3 listener | `Alt-Svc` advertisement turns on for the affected site. |
| Port conflict on a new bind | Reload aborts pre-flight; existing config keeps running. |
| Invalid YAML / config | `config.Load` rejects; existing config keeps running. |

Reload is serialized — concurrent SIGHUPs queue rather than racing.

### Cert rotation flow (Let's Encrypt)

```bash
# 30-day cron, or post-renewal hook:
certbot renew --post-hook "kill -HUP $(pidof nvelox)"
```

`certbot renew` writes new files to the same paths in `tls.cert` / `tls.key`. nvelox re-reads them on SIGHUP and serves the new cert on the next TLS handshake. Existing TLS sessions complete on the old cert; clients with cached session tickets resume cleanly.

---

## Cleanup

```bash
# Kill all background processes
jobs -p | xargs kill 2>/dev/null
rm -f /tmp/cookies.txt /tmp/nvelox-access.log /tmp/nvelox-error.log
```
