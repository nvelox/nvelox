# Performance Testing Guide

To verify the performance of the `proxy-server` and compare it against benchmarks (like standard Go `net` or HAProxy), you can use the following tools and methodologies.

## 1. TCP Throughput (iperf3)
**Best for:** Measuring raw TCP/UDP bandwidth and packet loss.

### Setup
1. **Start Backend (Server Mode)**:
   ```bash
   iperf3 -s -p 8081
   ```
2. **Configure Proxy**:
   Frontend: `9000` -> Backend: `8081`
3. **Run Client**:
   ```bash
   iperf3 -c 127.0.0.1 -p 9000 -t 30
   ```
   *   `-c`: Client mode
   *   `-p`: Port
   *   `-t`: Duration (seconds)

## 2. HTTP Requests Per Second (wrk / k6)
**Best for:** Measuring requests/sec and latency for HTTP traffic (L7 load on L4 proxy).

### Setup
1. **Start HTTP Backend**:
   Use a lightweight backend like `nginx` or a simple Go echo server.
   ```bash
   # Simple Go HTTP server
   go run -e 'package main; import ("net/http";"fmt"); func main() { http.ListenAndServe(":8081", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "ok") })) }'
   ```
2. **Configure Proxy**:
   Frontend: `9000` -> Backend: `8081`
3. **Run wrk**:
   ```bash
   wrk -t12 -c400 -d30s http://127.0.0.1:9000/
   ```
   *   `-t`: Threads
   *   `-c`: Connections
   *   `-d`: Duration

## 3. Connection Rate (hping3 / custom go tool)
**Best for:** Stress testing the accept loop and connection establishment rate.

### Setup
Use a tool that opens and closes connections rapidly.

## Expected Metrics
- **Memory**: Should remain stable. `gnet` uses object pooling.
- **CPU**: Should scale with traffic. 
- **Latency**: Should add minimal overhead (< 1ms).
- **Throughput**: Should approach line rate (limited by loopback in local usage).

## Tuning
- **GOMAXPROCS**: Ensure it matches your CPU count (default in Go > 1.5).
- **ULIMIT**: Ensure `ulimit -n` is high (e.g., 65535) for max connections.
