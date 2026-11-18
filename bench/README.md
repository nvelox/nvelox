# The nvelox benchmark kit

This directory holds everything behind the numbers in [docs/PERFORMANCE.md](../docs/PERFORMANCE.md): the scripts, the
configuration of every proxy, the load tools, and the raw results of the published run. With Docker on a Linux machine
you can run the same tests yourself.

nvelox is measured against nginx, HAProxy, Envoy, Traefik and Caddy, and against the earlier nvelox release. Each is a
reverse proxy in front of the same origin, and only one proxy is under load at a time.

## The published run

[`results/v2.0.0-rc.3/`](results/v2.0.0-rc.3/) is the run the documentation quotes:

| File | What it holds |
|---|---|
| `REPORT.md` | every table and chart, the checks on the test setup, and every round |
| `results.jsonl` | one line per measurement: rate, latency, errors, CPU of the proxy, the origin and the load generator, memory, threads |
| `large.jsonl` | the same for the large downloads and uploads: gigabytes per second, CPU per gigabyte, memory, kernel socket buffers |
| `slow.jsonl` | the slow downloads, one line per second: what the origin had sent, what the client had taken, the proxy's memory and temp files |
| `tools.log` | what wrk, h2load, udptool and bigtool printed, measurement by measurement |
| `env.txt` | the machine, the image digests, and the checksums of the binaries, configs and scripts used |
| `idle.jsonl` | CPU and memory of every proxy with no traffic |
| `summary.json` | the medians of the report, for other programs |

## Run it

You need Linux with cgroup v2, Docker, `python3`, `curl`, `ss` (iproute2), and enough CPUs to give the origin, the
proxy and the load generator their own. The defaults expect 20 CPUs; on a smaller machine set the three CPU lists.
The large-object tests keep their files and nginx's temp files in memory: about 6 GiB of free RAM (`LARGE_ROUNDS=0
SLOW=0` leaves them out).

```sh
./bench.sh setup        # builds the load tools, fetches the nvelox release binaries, creates the containers
./bench.sh run          # measures; about 3 hours with the defaults
./bench.sh report results/<name>
./bench.sh down         # removes the containers
```

| Setting | Default | Meaning |
|---|---|---|
| `NVELOX_VERSION` | `v2.0.0-rc.3` | the release under test, downloaded from GitHub and checked against its checksum |
| `NVELOX_BIN` | | a binary of your own to test instead of the release |
| `PREV_VERSION` | `v1.3.0` | the earlier release, as a reference |
| `ORIGIN_CPUS`, `PROXY_CPUS`, `LOAD_CPUS` | `4-7`, `8-11`, `12-19` | the CPUs of the origin, of the proxy under test and of the load generator |
| `ROUNDS` | `12` | rounds of nvelox and nginx |
| `FIELD_ROUNDS` | `5` | the first rounds also measure the other proxies |
| `DUR`, `WARM` | `10`, `3` | seconds measured, and seconds of warm-up before them |
| `BURNIN` | `180` | seconds of load before round 1 that are not measured |
| `CONNS` | `128` | connections (UDP: flows) |
| `LARGE_ROUNDS` | `3` | rounds of the large-object tests, every proxy in each; `0` leaves them out |
| `LARGE_DUR` | `12` | seconds measured in a large-object test |
| `SLOW` | `1` | `1`: also one slow download through every proxy |
| `LOCK` | | a lock file to hold during a run, on a machine that others use too |

Every proxy gets as many workers as `PROXY_CPUS` has CPUs: nginx `worker_processes`, HAProxy `nbthread`, Envoy
`--concurrency`; the Go proxies take the count from the CPUs they may run on.

## What is measured

Everything runs on `127.0.0.1` with host networking, one Docker container per process:

```
load generator  ->  proxy under test  ->  origin
(LOAD_CPUS)         (PROXY_CPUS)          (ORIGIN_CPUS)
```

The origin is nginx serving a 1 KiB and a 64 KiB file, and files of 1 MiB, 16 MiB and 1 GiB that it holds in memory;
for UDP it is an echo server, and for uploads a sink that reads every body to its end. Every proxy keeps a pool of
keep-alive connections to the origin and speaks HTTP/1.1 to it.

| Test | Load | What goes through the proxy |
|---|---|---|
| HTTP, 1 KiB and 64 KiB | wrk, 128 keep-alive connections | `GET` of the file |
| HTTPS, 1 KiB | wrk | the same over TLS 1.3 |
| TCP relay, 1 KiB | wrk | the HTTP request through a TCP (layer 4) listener |
| HTTP, 1 KiB, access log written | wrk | every proxy formats and writes one access-log line per request, to a sink that discards it |
| HTTP/2, one and ten requests at a time | h2load, 128 connections | `GET` of the 1 KiB file over TLS |
| HTTP/3, one and ten requests at a time | h2load, 128 connections | the same over QUIC |
| UDP, 1,024 and 64 bytes | udptool, 128 flows with one datagram in flight each | datagrams to an origin that sends each one back |
| Large downloads | bigtool: 1 MiB on 64 connections, 16 MiB on 16, 1 GiB on 4 | `GET` of the file over plain HTTP/1.1, read and discarded |
| Large uploads | bigtool: 16 MiB on 16 connections, 1 GiB on 2 | `POST` with a `Content-Length`, to the sink |
| A slow download | curl, one connection, 20 MiB/s | `GET` of the 1 GiB file through a freshly started proxy |

TLS is version 1.3 with AES-128-GCM and an ECDSA P-256 certificate for every proxy; the load tools are forced to it, so
that no test compares ciphers.

A run is a number of rounds. Each round first measures the origin alone, then every test. Within a test nvelox and
nginx are measured back to back, and which of the two goes first alternates; that pair and the other proxies take
turns, and who goes first changes with the round and the test. A measurement is 3 seconds of warm-up and 10 seconds
measured. All proxies stay up for the whole run; `idle.jsonl` shows what they cost while they wait.

A machine that has been idle is faster during its first minutes under load, so a run starts with 3 minutes of load
that are not measured.

The kit also records, for exactly the measured seconds, the CPU time of the proxy, of the origin and of the load
generator (from their cgroups), the proxy's peak memory, and its threads.

The large-object tests run after the rounds, on freshly started proxies: every proxy in each of 3 rounds, the origin
(or the sink) alone first,
3 seconds of warm-up and 12 seconds measured, counting only the bytes moved inside the measured seconds. The kernel's
socket buffers of the proxy are recorded too (`peak_sock_mib`). The slow download comes last: the other proxies are
stopped, the proxy under test is started fresh, and one client reads the 1 GiB file at 20 MiB/s while, every second,
the kit notes what the origin has sent and what the client has taken. A proxy that reads from the origin only as fast
as its client takes the data holds a few megabytes; one that buffers holds the file.

## The proxies' configuration

The files are in [`conf/`](conf/). Each proxy runs its stable release from its official image, with what a careful
operator would set for this job:

- **nginx:** a keep-alive pool to the origin (`upstream keepalive 256`), a high `keepalive_requests`, `reuseport`, and
  `quic_gso on` for HTTP/3. None of these is nginx's default, and each makes nginx faster here. For large objects
  nginx is measured twice in each direction: with its defaults, which buffer a response in temp files and a whole
  request body before it goes upstream (only `client_max_body_size 0` is set, to let the uploads in), and set up for
  large bodies (`proxy_max_temp_file_size 0` with 16 buffers of 64k; `proxy_request_buffering off`). Its temp files
  are in memory, so they cost no disk writes.
- **HAProxy:** its defaults, which already reuse connections. HAProxy has no UDP proxy.
- **Envoy:** circuit-breaker thresholds raised so that they never trip, and no time limit for a whole request on the
  HTTP listener (the default of 15 seconds would cut the slow download).
- **Traefik and Caddy:** the idle pool to the origin raised to 256 connections per host. Caddy's stock image has no
  TCP or UDP proxy.
- **nvelox:** its defaults. nvelox writes its access log in every HTTP test, so it carries that work in all of them;
  the other proxies write one only in the access-log test.

## How to read the results

- **nvelox against nginx.** The two are measured back to back in every round, so every round gives one ratio. The
  report shows the median of the ratios and the number of rounds in which nvelox was the faster. The speed of a
  virtual machine moves from minute to minute, often by more than the difference between two proxies; comparing
  within a round takes that out. A ratio close to 1 with the rounds split between the two is a tie.
- **All proxies.** The medians of the rounds in which all of them were measured.
- **Is the proxy what is being measured?** The report lists how busy the origin and the load generator were. A proxy
  that does not use its cores, or an origin close to its own ceiling, is named there.

## What these numbers do not show

One machine and the loopback interface: no network card, no real latency, no packet loss. At most 128 connections and
a static origin. WebSocket and the site features that run through Go's `net/http` are not measured.
Throughput at full load is one property of a proxy among several; run the kit on your own hardware, with your own
traffic in mind, before you decide anything by it.

## Files

| Path | |
|---|---|
| `bench.sh` | setup, run, report, down |
| `measure.py` | one measurement, with the CPU and memory accounting |
| `report.py` | the tables and charts of a results directory |
| `conf/` | the configuration of the origin and of every proxy |
| `loadgen/` | the image with wrk and an h2load that speaks HTTP/3, and the wrk script that prints its result as JSON |
| `udptool/` | the UDP echo origin and load generator, written with Go's standard library only |
| `bigtool/` | the client and the sink of the large downloads and uploads, also standard library only |
