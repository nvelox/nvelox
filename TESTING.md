# Nvelox Testing Guide

## Prerequisites

- **Go** 1.25+
- **PHP-FPM** (optional, for FastCGI tests)
- **openssl** (optional, for TLS cert generation)

## Quick Start

```bash
go test ./...              # Run all tests (22+ packages)
go test -race ./...        # With race detector
go test -v ./integration/  # Integration tests only
```

## Test Packages

| Package | Tests | What's Tested |
|---------|-------|---------------|
| `config/` | Config validation | Version, addresses, ports, TLS, health check durations, balance algorithms, HTTP listener rules, routes, FastCGI |
| `core/` | Rate limiter, conn limiter, UDP pool, passive health, engine reload, drain, timeouts | Token bucket, semaphore, session affinity, failure tracking, graceful shutdown |
| `core/acl/` | ACL engine | Source IP/CIDR, method, header matching, allow/deny |
| `core/admin/` | Admin API | Stats, backends, drain/enable/disable endpoints |
| `core/circuitbreaker/` | Circuit breaker | Closed/open/half-open states, threshold, timeout, success reset |
| `core/discovery/` | DNS resolver | IP passthrough, hostname resolution, change detection |
| `core/health/` | Health checker | TCP connect, HTTP GET, lifecycle |
| `core/httpproxy/` | Router, handler, cache, static | Host/path/regex matching, redirect vars, headers, WebSocket detection, caching, buffer pool, try_files, expires, static files |
| `core/httpproxy/errorhtml/` | Error pages | All status codes, icons, colors, HTML structure |
| `core/logging/` | Logger | Init, file logging, level filtering |
| `core/metrics/` | Prometheus metrics | Counter, gauge, histogram, text output, label handling |
| `core/middleware/` | Per-IP rate limiter | Burst, replenish, different IPs, same IP different ports |
| `core/scripting/` | Lua VM | Get/set headers, path, deny, set_backend, logging, invalid scripts |
| `core/sni/` | SNI router | Exact match, wildcard, case insensitive, SNI extraction |
| `core/sticky/` | Sticky sessions | Set/get, expiry, refresh, cookie/IP-hash extraction |
| `core/throttle/` | Bandwidth throttle | Rate parsing, throttled reader/writer |
| `core/tlsutil/` | TLS helpers | Client auth modes, CA loading, missing files |
| `integration/` | End-to-end | TCP/UDP/HTTP/HTTPS proxy, TLS, HTTP/2, HTTP/3, routing, headers, rate limiting, retries, access logging, metrics, WebSocket, security |
| `lb/` | Load balancers | RoundRobin, LeastConn, Random, NextExcluding, MarkDraining, IsHealthy, UpdateServers, concurrent access |

## Running Specific Tests

```bash
# By package
go test -v ./core/acl/...
go test -v ./core/httpproxy/...
go test -v ./lb/...

# By test name
go test -v ./integration/ -run TestHTTP_HostRouting
go test -v ./core/circuitbreaker/ -run TestBreaker_OpensOnThreshold

# With race detector (recommended for concurrency tests)
go test -race ./core/... ./lb/...
```

## Coverage Report

```bash
# Generate coverage profile
go test -coverpkg=./... -coverprofile=coverage.out ./...

# View in terminal
go tool cover -func=coverage.out | tail -1

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html
open coverage.html
```

## Real-World Testing

The `examples/` directory contains 30 config files with test commands for manual testing against real backends. See [`examples/README.md`](examples/README.md) for:

- Backend startup commands
- nvelox launch with each config
- curl/nc test commands with expected output
- PHP-FPM integration testing
- TLS certificate generation

```bash
# Generate test certs
./examples/generate-certs.sh

# Start a test backend
go run examples/http_backend.go :8081 "backend-1"

# Run nvelox with any example
./nvelox -config examples/28-full-production.yaml
```

## CI/CD

Tests run on every push and PR via GitHub Actions (`.github/workflows/test.yml`).
