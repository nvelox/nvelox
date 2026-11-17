# Performance

## How nvelox moves traffic

On Linux, nvelox runs one event loop per CPU it may use (`GOMAXPROCS`). Each loop is a goroutine that drives its own epoll instance over non-blocking sockets. HTTP/1.1 (with or without TLS), HTTP/2, HTTP/3, and plain TCP and UDP listeners run on these loops:
- a strict parser handles requests without allocating;
- each loop keeps its own keep-alive connections to the backends, shared by the three HTTP versions;
- HTTP/2 output is encrypted and written once per pass of a loop, and HTTP/3 and UDP datagrams are read and sent in batches;
- HTTP/3 runs on nvelox's own QUIC transport, one UDP socket per loop;
- the access log is written once per loop iteration.

WebSocket and the site features that need Go's `net/http` (response cache, compression, client certificates, static files, FastCGI and a few more) run through `net/http`, as on other platforms: an HTTP/1.1 connection is handed over, an HTTP/2 or HTTP/3 request is passed to a handler while its connection stays on its loop. [ARCHITECTURE.md](ARCHITECTURE.md#http11-on-the-event-loops-linux) lists exactly what runs where.

## Benchmark

nvelox, nginx, HAProxy, Envoy, Traefik and Caddy as reverse proxies in front of the same origin, one proxy at a time.

| Setting | Value |
|---|---|
| Machine | 20 vCPU VM, Intel Xeon Gold 6242R 3.1 GHz (VMware), Linux 6.8 |
| Proxy | 4 vCPUs (cpuset). nginx `worker_processes 4`, HAProxy `nbthread 4`, Envoy `--concurrency 4`, Go proxies `GOMAXPROCS` 4 |
| Origin | nginx 1.31.8 on 4 other vCPUs, serving static 1 KiB and 64 KiB files; for UDP, an echo server on the same 4 vCPUs |
| Load | On the remaining 8 vCPUs, 8 threads. wrk 4.1.0 with 128 keep-alive connections for HTTP/1.1 and TCP; h2load (nghttp2 1.71.0 with ngtcp2) with 128 connections for HTTP/2 and HTTP/3; for UDP, 128 flows that each keep one datagram in flight |
| Runs | 3 s warm-up, then 10 s measured, 5 rounds. Within a scenario the proxies take turns, and the one that goes first changes every time, so all proxies of a scenario are measured within about two minutes of each other. The tables show the median |
| Packaging | Every proxy in a Docker container with host networking; nvelox from a static binary in `ubuntu:24.04` |
| TLS | TLS 1.3, AES-128-GCM, ECDSA P-256 certificate, on every proxy |
| Versions | nginx 1.31.8, HAProxy 3.4.7, Envoy 1.40.2, Traefik 3.7.18, Caddy 2.11.9 |

Scenarios:
- **HTTP 1 KiB, HTTP 64 KiB:** GET of a static file through the proxy.
- **HTTPS 1 KiB:** the same over TLS, with keep-alive.
- **L4 TCP:** HTTP 1 KiB through a TCP (layer 4) listener. Caddy's stock image has no TCP proxy.
- **HTTP 1 KiB, access log on:** every proxy formats and writes one access-log line per request, to a sink that discards it (`/dev/null`; for HAProxy, a log ring nobody reads). nvelox has its access log on in every HTTP scenario; the other proxies log only in this one.
- **HTTP/2, HTTP/3:** GET of the 1 KiB file over TLS, with one request at a time on each connection, and with ten.
- **UDP:** datagrams of 1,024 and of 64 bytes through a UDP listener to an origin that sends each one back; replies per second. HAProxy and Caddy's stock image have no UDP proxy.

Every proxy keeps a keep-alive pool to the origin, which it speaks HTTP/1.1 to in every HTTP scenario. For nginx this means `upstream keepalive 256` with high `keepalive_requests`, plus `reuseport`.

### Results

HTTP/1.1, HTTPS and TCP. Requests per second, median of 5 rounds:

| proxy | HTTP 1 KiB | HTTP 64 KiB | HTTPS 1 KiB | L4 TCP | HTTP 1 KiB, log on | memory |
|---|---|---|---|---|---|---|
| **nvelox** | **132,423** | **59,509** | **122,952** | **180,160** | **139,604** | **4-17 MiB** |
| nginx 1.31.8 | 124,675 | 35,366 | 99,060 | 171,143 | 120,823 | 40-47 MiB |
| HAProxy 3.4.7 | 104,059 | 40,022 | 81,429 | 156,108 | 93,290 | 26-41 MiB |
| Traefik 3.7.18 | 38,907 | 17,993 | 28,238 | 121,927 | 20,756 | 22-74 MiB |
| Envoy 1.40.2 | 35,349 | 21,822 | 32,254 | 126,238 | 32,501 | 20-37 MiB |
| Caddy 2.11.9 | 21,349 | 14,346 | 18,519 | n/a | 18,284 | 30-40 MiB |
| nvelox 1.3.0 | 15,326 | 10,382 | 15,196 | 109,196 | 15,538 | 8-24 MiB |

nvelox was ahead of nginx in 24 of the 25 rounds (five columns, 5 rounds each).

HTTP/2 and HTTP/3. Requests per second, median of 5 rounds:

| proxy | HTTP/2, one request at a time | HTTP/2, ten at a time | HTTP/3, one request at a time | HTTP/3, ten at a time |
|---|---|---|---|---|
| **nvelox** | **119,432** | **176,984** | **110,893** | **156,893** |
| nginx 1.31.8 | 87,615 | 97,554 | 81,459 | 103,965 |
| HAProxy 3.4.7 | 77,699 | 74,779 | 60,862 | 67,653 |
| Envoy 1.40.2 | 27,103 | 30,027 | 14,484 | 15,088 |
| Traefik 3.7.18 | 18,104 | 13,623 | 15,815 | 12,204 |
| Caddy 2.11.9 | 13,596 | 12,651 | 12,142 | 12,011 |
| nvelox 1.3.0 | 12,028 | 11,537 | 10,354 | 10,552 |

nvelox's slowest round beat nginx's fastest round in every column.

UDP. Replies per second, median of 5 rounds:

| proxy | 1,024-byte datagrams | 64-byte datagrams |
|---|---|---|
| **nvelox** | **289,871** | **317,954** |
| nginx 1.31.8 | 225,485 | 239,508 |
| Envoy 1.40.2 | 174,960 | 173,027 |
| nginx 1.31.8, `proxy_responses 1` | 111,823 | 116,437 |
| Traefik 3.7.18 | 79,058 (0.37% lost) | 81,024 |
| nvelox 1.3.0 | 74,691 (0.72% lost) | 78,489 |

nginx keeps a session per client address and port by default; with `proxy_responses 1` it ends the session after every reply. 

Against nvelox 1.3.0, this engine serves 8.6x the HTTP 1 KiB rate, 8.1x the HTTPS rate, 1.6x the L4 rate, 9.9x the HTTP/2 rate, 10.7x the HTTP/3 rate and 3.9x the UDP rate.

### On a smaller machine

The HTTP/1.1, HTTPS and TCP scenarios on a 6 vCPU VM (KVM, Intel Broadwell, Linux 5.4), with 2 vCPUs each for the proxy (2 workers / `GOMAXPROCS` 2), the origin and wrk (2 threads, 128 connections), measured with an earlier build of the event-loop engine. Requests per second, median of 3 rounds:

| proxy | HTTP 1 KiB | HTTP 64 KiB | HTTPS 1 KiB | L4 TCP | HTTP 1 KiB, log on |
|---|---|---|---|---|---|
| **nvelox (event-loop engine)** | **51,235** | **22,841** | **46,095** | **77,079** | **52,460** |
| nginx 1.31.8 | 43,607 | 12,770 | 28,508 | 71,378 | 41,649 |
| HAProxy 3.4.7 | 39,607 | 15,222 | 30,324 | 58,573 | 36,088 |
| Envoy 1.40.2 | 13,535 | 9,561 | 12,129 | 48,134 | 12,896 |
| Traefik 3.7.18 | 12,014 | 7,658 | 11,307 | 55,275 | 8,570 |
| Caddy 2.11.9 | 8,819 | 6,336 | 8,206 | n/a | 8,348 |
| nvelox 1.3.0 | 8,146 | 5,337 | 7,782 | 49,090 | 8,342 |

## Measuring it yourself

- Give the proxy, the origin and the load generator their own cores (cpusets or `taskset`). Otherwise they compete, and the result measures the scheduler.
- Check that the proxy is the bottleneck: its CPU should be near its core count, and the origin and wrk should have headroom. A proxy that is not saturated only shows the origin's or wrk's limit.
- Use keep-alive on both sides, warm up, and run several rounds in rotated order. Compare medians.
- Run the same TLS version and cipher everywhere. One proxy on AES-GCM and another on ChaCha20 compare ciphers, not proxies.

## Tuning

- **Cores.** nvelox starts one event loop per `GOMAXPROCS` as it finds it at start. Go sets it from the CPUs the process may run on (its affinity mask and, since Go 1.25, a cgroup CPU limit). Set `GOMAXPROCS` only to use fewer cores than that. Each loop runs on its own OS thread, and nvelox then raises `GOMAXPROCS` by the number of loops for the goroutines beside them, so a running nvelox reports twice the value it started with.
- **Open files.** Every client connection and every backend connection is a file descriptor; raise `ulimit -n` (for example to 65535 or more) for many concurrent connections. When the limit is reached, nvelox pauses accepting and retries, and connections that are already open keep working.
- **Features and speed.** A site with a response cache, compression or client certificates, and a route that serves static files, FastCGI, redirects, `try_files` or `expires`, run on `net/http`, as do backends with sticky sessions and gRPC requests to `backend_tls` backends. They behave the same; they are served at `net/http` speed.
- **Access log.** The access log is formatted without allocating and written once per loop iteration, so it costs little; the numbers above include it for nvelox in every HTTP scenario.
