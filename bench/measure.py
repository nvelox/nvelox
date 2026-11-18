#!/usr/bin/env python3
"""One measured run of the benchmark kit, and what the containers in it used.

  measure.py --tool wrk|h2load|udp|big --warm S --dur S --proxy CT|- --origin CT --lg CT
             [--sink-stats URL] [--label k=v ...] [--log FILE] -- command ...
  measure.py slow --proxy CT --origin-port N --port N [--temp DIR] [--label k=v ...] -- command ...
  measure.py idle SECONDS CT...      CPU, memory and threads of containers that do nothing
  measure.py line                    one result line (stdin) as a line of text

Runs the command (the load tool). After --warm seconds it reads the CPU counters of every
container (cgroup v2 cpu.stat), and again after --dur more seconds: the CPU figures cover exactly
the measured window. The proxy's memory (memory.stat, memory.current) is sampled every 0.25 s for
the whole run; its threads are counted in the middle of the window. With --sink-stats, the bytes
the upload sink received in the window are read from its counter. Prints one JSON line.

slow: runs the command (one slow download) and, every second until it ends, prints one JSON line:
what the origin has sent (bytes acknowledged on its sockets), what the client has received, the
proxy's memory, and what DIR inside the proxy's container holds (temp files). A last line has the
proxy's CPU time for the whole download.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request


def cgroup(ct):
    cid = subprocess.run(["docker", "inspect", "-f", "{{.Id}}", ct], capture_output=True, text=True, check=True).stdout.strip()
    for path in ("/sys/fs/cgroup/system.slice/docker-%s.scope" % cid, "/sys/fs/cgroup/docker/%s" % cid):
        if os.path.isdir(path):
            return path
    sys.exit("measure.py: no cgroup v2 directory of container %s (is it running?)" % ct)


def cpu(cg):
    v = {}
    for line in open(cg + "/cpu.stat"):
        k, n = line.split()
        v[k] = int(n)
    return v


def memstat(cg):
    v = {}
    for line in open(cg + "/memory.stat"):
        k, n = line.split()
        if k in ("anon", "file", "shmem", "sock", "kernel"):
            v[k] = int(n)
    v["current"] = int(open(cg + "/memory.current").read())
    return v


def ms(s):
    """h2load's durations: 112us, 13.97ms, 1.20s."""
    return float(s[:-2]) / 1000 if s.endswith("us") else float(s[:-2]) if s.endswith("ms") else float(s[:-1]) * 1000


def sink(url):
    """The upload sink's counter: bytes received so far."""
    return int(urllib.request.urlopen(url, timeout=5).read())


def parse(tool, out):
    r = {}
    if tool == "wrk":
        m = re.search(r"^WRKJSON (.*)$", out, re.M)
        if m:
            d = json.loads(m.group(1))
            r["rps"] = d["requests"] / (d["duration_us"] / 1e6)
            r["p50_ms"], r["p99_ms"] = d["p50_us"] / 1000, d["p99_us"] / 1000
            r["errors"] = sum(d[k] for k in ("err_connect", "err_read", "err_write", "err_status", "err_timeout"))
    elif tool == "h2load":
        m = re.search(r"finished in [\d.]+\w+, ([\d.]+) req/s", out)
        if m:
            r["rps"] = float(m.group(1))
        m = re.search(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, (\d+) errored, (\d+) timeout", out)
        if m:
            r["errors"] = int(m.group(5)) + int(m.group(6)) + int(m.group(7))
        m = re.search(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx", out)
        if m:
            r["non2xx"] = int(m.group(2)) + int(m.group(3)) + int(m.group(4))
        # "request : min max median p95 p99 mean sd +/- sd"
        m = re.search(r"^request\s*:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", out, re.M)
        if m:
            r["p50_ms"], r["p99_ms"], r["max_ms"], r["mean_ms"] = ms(m.group(3)), ms(m.group(5)), ms(m.group(2)), ms(m.group(6))
        m = re.search(r"Application protocol: (\S+)", out)
        r["alpn"] = m.group(1) if m else None
    elif tool == "udp":
        m = re.search(r"^UDPJSON (.*)$", out, re.M)
        if m:
            d = json.loads(m.group(1))
            r["rps"] = d["replies_per_s"]
            r["p50_ms"], r["p99_ms"] = d["p50_us"] / 1000, d["p99_us"] / 1000
            r["lost_pct"], r["errors"] = d["lost_pct"], d["send_errors"]
    elif tool == "big":
        m = re.search(r"^BIGJSON (.*)$", out, re.M)
        if m:
            d = json.loads(m.group(1))
            r["client_gbps"], r["completed"], r["errors"] = d["gbps"], d["completed"], d["errors"]
            r["last_error"] = d.get("last_error") or None
    return r


def ss_sum(flt, field):
    """The sum of one counter over the established TCP sockets a filter selects (iproute2's ss)."""
    out = subprocess.run(["ss", "-Htin", "state", "established", flt], capture_output=True, text=True).stdout
    return sum(int(x) for x in re.findall(field + r":(\d+)", out))


def slow(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", required=True)
    ap.add_argument("--origin-port", type=int, required=True)
    ap.add_argument("--port", type=int, required=True, help="the proxy's listener the client downloads from")
    ap.add_argument("--temp", default="", help="a directory inside the proxy's container: its use is reported")
    ap.add_argument("--label", action="append", default=[])
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    lab = dict(kv.split("=", 1) for kv in a.label)
    cg = cgroup(a.proxy)
    sent = lambda: ss_sum("( sport = :%d )" % a.origin_port, "bytes_acked")
    base, c0, t0 = sent(), cpu(cg), time.monotonic()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    while p.poll() is None:
        time.sleep(1)
        m, temp = memstat(cg), 0
        if a.temp:
            f = subprocess.run(["docker", "exec", a.proxy, "df", "-B1", "--output=used", a.temp], capture_output=True, text=True).stdout.split()
            temp = int(f[-1]) if f and f[-1].isdigit() else 0
        print(json.dumps(dict(lab, ms=int((time.monotonic() - t0) * 1000), origin_sent=sent() - base,
                              client_got=ss_sum("( dport = :%d )" % a.port, "bytes_received"),
                              anon=m["anon"], shmem=m.get("shmem", 0), sock=m.get("sock", 0), temp_used=temp)), flush=True)
    out = p.stdout.read().strip()
    print(json.dumps(dict(lab, summary=True, cpu_s=(cpu(cg)["usage_usec"] - c0["usage_usec"]) / 1e6,
                          ms=int((time.monotonic() - t0) * 1000), client=out)), flush=True)


def idle(args):
    seconds, cts = float(args[0]), args[1:]
    cgs = {ct: cgroup(ct) for ct in cts}
    c0, t0 = {ct: cpu(c) for ct, c in cgs.items()}, time.monotonic()
    time.sleep(seconds)
    c1, dt = {ct: cpu(c) for ct, c in cgs.items()}, time.monotonic() - t0
    for ct, c in cgs.items():
        m = memstat(c)
        print(json.dumps({"container": ct, "idle_cpu_pct": 100 * (c1[ct]["usage_usec"] - c0[ct]["usage_usec"]) / 1e6 / dt,
                          "anon_mib": m["anon"] / 2**20, "current_mib": m["current"] / 2**20,
                          "threads": len(open(c + "/cgroup.threads").read().split())}))


def line():
    r = json.loads(sys.stdin.read())
    if r.get("dir"):  # a large-object measurement
        gb = r.get("delivered_gbps") if r["dir"] == "up" else r.get("client_gbps")
        use = ""
        if r.get("proxy_cpu_pct") is not None:
            use = "cpu %3.0f%% %.2f s/GB  %5.1f MiB, sockets %.0f MiB" % (r["proxy_cpu_pct"], r.get("proxy_cpu_s_per_gb") or 0,
                                                                        r.get("peak_anon_mib", 0), r.get("peak_sock_mib", 0))
        print("%s round %-2s %-14s %-4s %-4s x%-3s %s  %s %s" % (r["ts"], r["round"], r["proxy"], r["dir"], r["size"], r["conns"],
              "%6.2f GB/s" % gb if gb else "   FAILED", use, "errors=%s %s" % (r["errors"], r.get("last_error") or "") if r.get("errors") else ""))
        return
    rate = "%9.0f/s" % r["rps"] if r.get("rps") else "   FAILED"
    lat = "p50 %.2f p99 %.2f ms" % (r["p50_ms"], r["p99_ms"]) if r.get("p99_ms") is not None else ""
    use = ""
    if r.get("proxy_cpu_pct") is not None:
        use = "cpu %3.0f%% (origin %3.0f%%, load %3.0f%%)  %5.1f MiB" % (
            r["proxy_cpu_pct"], r["origin_cpu_pct"], r["lg_cpu_pct"], r.get("peak_anon_mib", 0))
    bad = []
    if r.get("errors"):
        bad.append("errors=%s" % r["errors"])
    if r.get("non2xx"):
        bad.append("non-2xx=%s" % r["non2xx"])
    if r.get("lost_pct"):
        bad.append("lost=%.2f%%" % r["lost_pct"])
    print("%s round %-2s %-11s %-12s %s  %-24s %s %s" % (r["ts"], r["round"], r["proxy"], r["test"], rate, lat, use, " ".join(bad)))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "idle":
        return idle(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "line":
        return line()
    if len(sys.argv) > 1 and sys.argv[1] == "slow":
        return slow(sys.argv[2:])
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True)
    ap.add_argument("--warm", type=float, required=True)
    ap.add_argument("--dur", type=float, required=True)
    ap.add_argument("--proxy", default="-")
    ap.add_argument("--origin", required=True)
    ap.add_argument("--lg", required=True)
    ap.add_argument("--sink-stats", help="the upload sink's counter: what it received in the window is reported")
    ap.add_argument("--label", action="append", default=[])
    ap.add_argument("--log", help="append the tool's raw output here")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    cgs = {"origin": cgroup(a.origin), "lg": cgroup(a.lg)}
    if a.proxy != "-":
        cgs["proxy"] = cgroup(a.proxy)

    peaks, threads, stop = {}, [], threading.Event()

    def sampler():
        while not stop.is_set():
            if "proxy" in cgs:
                try:
                    for k, v in memstat(cgs["proxy"]).items():
                        peaks[k] = max(peaks.get(k, 0), v)
                except OSError:
                    pass
            time.sleep(0.25)

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = []
    reader = threading.Thread(target=lambda: out.append(p.stdout.read()))
    reader.start()
    th = threading.Thread(target=sampler)
    th.start()
    time.sleep(a.warm)
    s0 = sink(a.sink_stats) if a.sink_stats else 0
    t0, c0 = time.monotonic(), {k: cpu(v) for k, v in cgs.items()}
    time.sleep(a.dur / 2)
    if "proxy" in cgs:
        threads.append(len(open(cgs["proxy"] + "/cgroup.threads").read().split()))
    time.sleep(max(0.0, t0 + a.dur - time.monotonic()))
    t1, c1 = time.monotonic(), {k: cpu(v) for k, v in cgs.items()}
    s1 = sink(a.sink_stats) if a.sink_stats else 0
    p.wait()
    reader.join()
    stop.set()
    th.join()
    text = out[0] if out else ""
    if a.log:
        with open(a.log, "a") as f:
            f.write("### %s\n%s\n" % (" ".join(a.label), text))
    dt = t1 - t0
    r = dict(kv.split("=", 1) for kv in a.label)
    r["ts"] = time.strftime("%H:%M:%S", time.gmtime())
    r["load"] = open("/proc/loadavg").read().split()[:3]
    r.update(parse(a.tool, text))
    r["window_s"] = dt
    for k in cgs:
        d = {x: c1[k][x] - c0[k][x] for x in ("usage_usec", "user_usec", "system_usec")}
        r[k + "_cpu_pct"] = 100 * d["usage_usec"] / 1e6 / dt
        if k == "proxy":
            r["proxy_user_pct"] = 100 * d["user_usec"] / 1e6 / dt
            r["proxy_sys_pct"] = 100 * d["system_usec"] / 1e6 / dt
            r["proxy_cpu_s"] = d["usage_usec"] / 1e6
    if "proxy" in cgs:
        if r.get("rps"):
            r["proxy_us_per_req"] = r["proxy_cpu_s"] * 1e6 / (r["rps"] * dt)
        r.update({"peak_" + k + "_mib": v / 2**20 for k, v in peaks.items()})
        r["threads"] = threads[0] if threads else None
    if a.sink_stats:
        r["delivered_gbps"] = (s1 - s0) / dt / 1e9
    gb = r.get("delivered_gbps") if a.sink_stats else r.get("client_gbps")
    if gb and "proxy" in cgs:
        r["proxy_cpu_s_per_gb"] = r["proxy_cpu_s"] / (gb * dt)
    if not r.get("rps") and not gb:
        r["raw_tail"] = text[-400:]
    print(json.dumps(r))


if __name__ == "__main__":
    main()
