#!/usr/bin/env python3
"""Tables and charts of one run of the benchmark kit.

  report.py <results dir> [--docs FILE]

Reads results.jsonl, idle.jsonl and env.txt of the directory (and large.jsonl and slow.jsonl, the
large-object tests, when the run has them) and writes REPORT.md, summary.json and charts/*.svg into it. With --docs, the block between the lines <!-- bench:begin --> and
<!-- bench:end --> of FILE is replaced by the summary (tables and charts), so that a page of the
documentation shows exactly what the results directory holds.

How the numbers are read:
- nvelox against nginx: both are measured back to back in every round, so each round gives one
  ratio. The table shows the median of those ratios and in how many rounds nvelox was the faster.
- All proxies: the medians of the rounds in which all of them were measured.
- Large objects: every proxy is measured in every round; the tables show the medians.
"""
import collections
import html
import json
import math
import os
import re
import statistics
import sys

TESTS = [
    ("http_1k", "HTTP, 1 KiB"), ("http_64k", "HTTP, 64 KiB"), ("https_1k", "HTTPS, 1 KiB"),
    ("tcp_1k", "TCP relay, 1 KiB"), ("http_1k_log", "HTTP, 1 KiB, access log written"),
    ("h2_m1", "HTTP/2, one request at a time"), ("h2_m10", "HTTP/2, ten requests at a time"),
    ("h3_m1", "HTTP/3, one request at a time"), ("h3_m10", "HTTP/3, ten requests at a time"),
    ("udp_1024", "UDP, 1,024-byte datagrams"), ("udp_64", "UDP, 64-byte datagrams"),
]
LABEL = dict(TESTS)
SHORT = {"http_1k": "HTTP 1 KiB", "http_64k": "HTTP 64 KiB", "https_1k": "HTTPS 1 KiB", "tcp_1k": "TCP relay",
         "http_1k_log": "HTTP, log written", "h2_m1": "HTTP/2, one at a time", "h2_m10": "HTTP/2, ten at a time",
         "h3_m1": "HTTP/3, one at a time", "h3_m10": "HTTP/3, ten at a time", "udp_1024": "UDP 1,024 B", "udp_64": "UDP 64 B"}
GROUPS = [
    ("HTTP/1.1, HTTPS and TCP", "Requests per second", ["http_1k", "http_64k", "https_1k", "tcp_1k", "http_1k_log"]),
    ("HTTP/2 and HTTP/3", "Requests per second", ["h2_m1", "h2_m10", "h3_m1", "h3_m10"]),
    ("UDP", "Replies per second", ["udp_1024", "udp_64"]),
]
ORDER = ["nvelox", "nginx", "haproxy", "envoy", "traefik", "caddy", "nvelox-prev"]
BRAND = {"nvelox": "nvelox", "nvelox-prev": "nvelox", "nginx": "nginx", "haproxy": "HAProxy", "envoy": "Envoy",
         "traefik": "Traefik", "caddy": "Caddy"}
NO_MODE = {("caddy", "tcp_1k"): "no TCP proxy", ("caddy", "udp_1024"): "no UDP proxy", ("caddy", "udp_64"): "no UDP proxy",
           ("haproxy", "udp_1024"): "no UDP proxy", ("haproxy", "udp_64"): "no UDP proxy"}


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def n0(x):
    return "n/a" if x is None else f"{x:,.0f}"


def f2(x):
    return "n/a" if x is None else f"{x:.2f}"


def f1(x):
    return "n/a" if x is None else f"{x:.1f}"


# ---------------------------------------------------------------- data

def jl(path):
    return [json.loads(l) for l in open(path) if l.strip()] if os.path.exists(path) else []


def load(d):
    rows = [json.loads(l) for l in open(os.path.join(d, "results.jsonl")) if l.strip()]
    idle = [json.loads(l) for l in open(os.path.join(d, "idle.jsonl")) if l.strip()] if os.path.exists(os.path.join(d, "idle.jsonl")) else []
    env = open(os.path.join(d, "env.txt")).read() if os.path.exists(os.path.join(d, "env.txt")) else ""
    return rows, idle, env


def names(env):
    """candidate -> display name with its version, from the 'version <candidate>: ...' lines of env.txt."""
    out = {}
    for c in ORDER:
        m = re.search(r"^version %s: (.*)$" % re.escape(c), env, re.M)
        v = re.search(r"\d+\.\d+\.\d+(?:-rc\.\d+)?", m.group(1)) if m else None
        out[c] = "%s %s" % (BRAND[c], v.group(0)) if v else BRAND[c] + (" (earlier release)" if c == "nvelox-prev" else "")
    return out


def envval(env, key):
    m = re.search(r"^%s:? *(.*)$" % re.escape(key), env, re.M)
    return m.group(1).strip() if m else ""


class Run:
    def __init__(self, d):
        self.dir = d
        self.rows, self.idle, self.env = load(d)
        self.large, self.slow = jl(os.path.join(d, "large.jsonl")), jl(os.path.join(d, "slow.jsonl"))
        self.R = collections.defaultdict(dict)   # (candidate, test) -> round -> row
        for r in self.rows:
            if r.get("rps"):
                self.R[(r["proxy"], r["test"])][int(r["round"])] = r
        self.failed = [r for r in self.rows if not r.get("rps")]
        self.name = names(self.env)
        self.rounds = sorted({int(r["round"]) for r in self.rows})
        others = [c for c in ORDER if c not in ("nvelox", "nginx")]
        self.field_rounds = sorted({k for c in others for t, _ in TESTS for k in self.R.get((c, t), {})})
        self.cands = [c for c in ORDER if any(self.R.get((c, t)) for t, _ in TESTS)]

    def head(self, t):
        a, b = self.R.get(("nvelox", t), {}), self.R.get(("nginx", t), {})
        rs = sorted(set(a) & set(b))
        if not rs:
            return None
        ratios = [a[k]["rps"] / b[k]["rps"] for k in rs]
        cpu = [a[k]["proxy_us_per_req"] / b[k]["proxy_us_per_req"] - 1 for k in rs
               if a[k].get("proxy_us_per_req") and b[k].get("proxy_us_per_req")]
        g = lambda rows, key: med([rows[k].get(key) for k in rs])
        return {
            "rounds": len(rs), "ratio": med(ratios), "faster": sum(1 for x in ratios if x > 1), "ratios": ratios,
            "round_ids": rs, "cpu_diff": med(cpu),
            "nvelox": {"rps": g(a, "rps"), "p50_ms": g(a, "p50_ms"), "p99_ms": g(a, "p99_ms"), "cpu_us": g(a, "proxy_us_per_req")},
            "nginx": {"rps": g(b, "rps"), "p50_ms": g(b, "p50_ms"), "p99_ms": g(b, "p99_ms"), "cpu_us": g(b, "proxy_us_per_req")},
        }

    def field(self, c, t):
        rows = [r for k, r in self.R.get((c, t), {}).items() if k in self.field_rounds]
        if not rows:
            return None
        g = lambda key: med([r.get(key) for r in rows])
        return {"rps": g("rps"), "p50_ms": g("p50_ms"), "p99_ms": g("p99_ms"), "cpu_us": g("proxy_us_per_req"),
                "cpu_pct": g("proxy_cpu_pct"), "mem_mib": g("peak_anon_mib"), "threads": g("threads"), "rounds": len(rows),
                "lost_pct": g("lost_pct"), "min": min(r["rps"] for r in rows), "max": max(r["rps"] for r in rows)}


# ---------------------------------------------------------------- charts (SVG, no dependencies)

THEMES = {
    "light": {"bg": "#ffffff", "ink": "#1f2328", "muted": "#59636e", "grid": "#d1d9e0", "a": "#c2630c", "b": "#2563c9"},
    "dark": {"bg": "#0d1117", "ink": "#f0f6fc", "muted": "#9198a1", "grid": "#3d444d", "a": "#c97a2e", "b": "#4f83dd"},
}
FONT = "system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"


class Svg:
    def __init__(self, w, h, th, title):
        self.w, self.h, self.t, self.title, self.o = w, h, THEMES[th], title, []

    def text(self, x, y, s, size=12, fill=None, anchor="start", weight="400"):
        self.o.append('<text x="%.1f" y="%.1f" font-size="%s" fill="%s" text-anchor="%s" font-weight="%s">%s</text>'
                      % (x, y, size, fill or self.t["ink"], anchor, weight, html.escape(str(s))))

    def line(self, x1, y1, x2, y2, stroke=None, width=1, dash=None):
        self.o.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="%s"%s/>'
                      % (x1, y1, x2, y2, stroke or self.t["grid"], width, ' stroke-dasharray="%s"' % dash if dash else ""))

    def bar(self, x, y, w, h, fill):
        """A horizontal bar anchored at x, its data end rounded."""
        w = max(w, 1.0)
        r = min(3.0, w / 2, h / 2)
        self.o.append('<path d="M%.1f %.1fH%.1fa%.1f %.1f 0 0 1 %.1f %.1fv%.1fa%.1f %.1f 0 0 1 -%.1f %.1fH%.1fz" fill="%s"/>'
                      % (x, y, x + w - r, r, r, r, r, h - 2 * r, r, r, r, r, x, fill))

    def dot(self, x, y, r, fill):
        self.o.append('<circle cx="%.1f" cy="%.1f" r="%s" fill="%s" stroke="%s" stroke-width="2"/>' % (x, y, r, fill, self.t["bg"]))

    def out(self):
        return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s" font-family="%s">'
                '<title>%s</title><rect width="%d" height="%d" rx="8" fill="%s"/>%s</svg>\n'
                % (self.w, self.h, self.w, self.h, html.escape(self.title, quote=True), FONT, html.escape(self.title),
                   self.w, self.h, self.t["bg"], "".join(self.o)))


def chart_panels(run, th, key, title, sub, fmt, low_first=False):
    """One panel per test: the proxies ranked by one median figure (key of Run.field)."""
    cols, pw, rowh, top = 2, 380, 19, 58
    lab, barw = 118, 176
    panels = [(t, [(c, run.field(c, t)) for c in run.cands]) for t, _ in TESTS]
    panels = [(t, [(c, v if v and v.get(key) else None) for c, v in rows]) for t, rows in panels]
    panels = [(t, rows) for t, rows in panels if any(v for _, v in rows)]
    ph = 30 + rowh * len(run.cands) + 14
    nrows = math.ceil(len(panels) / cols)
    s = Svg(cols * pw + 20, top + nrows * ph + 6, th, title)
    s.text(14, 26, title, 15, weight="600")
    s.text(14, 45, sub, 12, s.t["muted"])
    for i, (t, rows) in enumerate(panels):
        x0, y0 = 14 + (i % cols) * pw, top + (i // cols) * ph
        s.text(x0, y0 + 14, LABEL[t], 12.5, weight="600")
        have = sorted([(c, v) for c, v in rows if v], key=lambda cv: cv[1][key] if low_first else -cv[1][key])
        miss = [(c, None) for c, v in rows if not v]
        top_v = max(v[key] for _, v in have)
        for j, (c, v) in enumerate(have + miss):
            y = y0 + 26 + j * rowh
            me = c == "nvelox"
            s.text(x0 + lab - 8, y + 10.5, run.name[c], 11.5, s.t["ink"] if me else s.t["muted"], "end", "600" if me else "400")
            if v:
                w = barw * v[key] / top_v
                s.bar(x0 + lab, y, w, 13, s.t["a"] if me else s.t["b"])
                s.text(x0 + lab + w + 6, y + 10.5, fmt(v[key]), 11.5, s.t["ink"], weight="600" if me else "400")
            else:
                s.text(x0 + lab, y + 10.5, NO_MODE.get((c, t), "not measured"), 11.5, s.t["muted"])
    return s.out()


def cores(run):
    return (re.search(r"WORKERS=(\d+)", envval(run.env, "settings")) or [0, "4"])[1]


def chart_requests(run, th):
    return chart_panels(run, th, "rps", "Requests per second, by proxy",
                        "Median of %d rounds, the proxy on %s cores. UDP: replies per second. Longer is faster." % (len(run.field_rounds), cores(run)), n0)


def chart_lead(run, th):
    """nvelox next to the fastest of the other proxies, per test: one glance at the whole field."""
    rows = []
    for t, _ in TESTS:
        v = {c: x["rps"] for c in run.cands for x in [run.field(c, t)] if x and c != "nvelox-prev"}
        if "nvelox" not in v or len(v) < 2:
            continue
        o = max((c for c in v if c != "nvelox"), key=lambda c: v[c])
        rows.append((t, v["nvelox"], o, v[o], len(v)))
    lab, barw, rowh, top = 176, 330, 40, 84
    hi = max(max(a, b) for _, a, _, b, _ in rows)
    s = Svg(lab + barw + 214, top + rowh * len(rows) + 8, th, "nvelox and the fastest other proxy, per test")
    s.text(14, 26, "nvelox and the fastest of the other proxies", 15, weight="600")
    s.text(14, 45, "Requests per second (UDP: replies), median of %d rounds, each proxy on %s cores. Longer is faster."
           % (len(run.field_rounds), cores(run)), 12, s.t["muted"])
    s.bar(20, 58, 14, 11, s.t["a"])
    s.text(40, 68, run.name["nvelox"], 12)
    x2 = 40 + 7.2 * len(run.name["nvelox"]) + 22
    s.bar(x2, 58, 14, 11, s.t["b"])
    s.text(x2 + 20, 68, "the fastest of: %s" % ", ".join(BRAND[c] for c in run.cands if c not in ("nvelox", "nvelox-prev")), 12)
    for i, (t, a, o, b, n) in enumerate(rows):
        y = top + i * rowh
        s.text(lab - 10, y + 19, SHORT[t], 12, anchor="end")
        w = barw * a / hi
        s.bar(lab, y, w, 13, s.t["a"])
        s.text(lab + w + 6, y + 10.5, "%s  (%.2f×)" % (n0(a), a / b), 11.5, weight="600")
        w = barw * b / hi
        s.bar(lab, y + 15, w, 13, s.t["b"])
        s.text(lab + w + 6, y + 25.5, "%s  %s" % (n0(b), run.name[o]), 11.5, s.t["muted"])
    return s.out()


def chart_cpu_all(run, th):
    return chart_panels(run, th, "cpu_us", "CPU time per request, by proxy",
                        "Microseconds of the proxy's CPU per request (UDP: per reply), median of %d rounds. Shorter is cheaper." % len(run.field_rounds),
                        lambda v: "%.1f" % v, low_first=True)


def memory(run):
    """candidate -> (idle MiB, lowest and highest test median under load, most threads)"""
    idle = {r["container"]: r for r in run.idle}
    out = {}
    for c in run.cands:
        mem = [v["mem_mib"] for v in (run.field(c, t) for t, _ in TESTS) if v and v.get("mem_mib") is not None]
        if not mem:
            mem = [x for x in (med([r.get("peak_anon_mib") for r in run.R.get((c, t), {}).values()]) for t, _ in TESTS) if x is not None]
        thr = [v["threads"] for v in (run.field(c, t) for t, _ in TESTS) if v and v.get("threads")]
        i = idle.get("nvbench-" + c, {})
        out[c] = {"idle": i.get("anon_mib"), "idle_cpu": i.get("idle_cpu_pct"), "lo": min(mem) if mem else None, "hi": max(mem) if mem else None,
                  "threads": max(thr) if thr else None}
    return out


def chart_memory(run, th):
    """Every proxy's own memory: idle, and the highest test median under load."""
    m = {c: v for c, v in memory(run).items() if v["hi"] is not None}
    order = sorted(m, key=lambda c: m[c]["hi"])
    lab, barw, rowh, top = 150, 330, 34, 86
    hi = max(v["hi"] for v in m.values())
    s = Svg(lab + barw + 110, top + rowh * len(order) + 12, th, "Memory of every proxy, idle and under load")
    s.text(14, 26, "Memory, by proxy", 15, weight="600")
    s.text(14, 45, "The proxy's own memory in MiB, without kernel socket buffers. Shorter is less.", 12, s.t["muted"])
    s.bar(20, 58, 14, 11, s.t["muted"])
    s.text(40, 68, "idle, after start", 12)
    s.bar(160, 58, 14, 11, s.t["b"])
    s.text(180, 68, "under load, the highest test median", 12)
    for i, c in enumerate(order):
        y = top + i * rowh
        me = c == "nvelox"
        s.text(lab - 10, y + 17, run.name[c], 12, s.t["ink"] if me else s.t["muted"], "end", "600" if me else "400")
        if m[c]["idle"] is not None:
            w = barw * m[c]["idle"] / hi
            s.bar(lab, y, w, 12, s.t["muted"])
            s.text(lab + max(w, 1) + 6, y + 10, "%.0f" % m[c]["idle"], 11.5, s.t["muted"])
        w = barw * m[c]["hi"] / hi
        s.bar(lab, y + 14, w, 12, s.t["a"] if me else s.t["b"])
        s.text(lab + w + 6, y + 24, "%.0f" % m[c]["hi"], 11.5, s.t["ink"], weight="600" if me else "400")
    return s.out()


# ---------------------------------------------------------------- large objects

SIZES = {"1m": "1 MiB", "16m": "16 MiB", "1g": "1 GiB"}
LCASES = [("down", "1m"), ("down", "16m"), ("down", "1g"), ("up", "16m"), ("up", "1g")]
LORDER = ["nvelox", "nginx-tuned", "nginx-streamed", "nginx", "haproxy", "envoy", "traefik", "caddy", "nvelox-prev"]


def lname(run, c, d, short=False):
    if c == "nginx":
        return ("nginx, defaults" if d == "down" else "nginx, buffering") if short else (
            "%s, defaults" % run.name["nginx"] if d == "down" else "%s, buffering (its default)" % run.name["nginx"])
    if c == "nginx-tuned":
        return "nginx, tuned" if short else "%s, tuned for large files" % run.name["nginx"]
    if c == "nginx-streamed":
        return "nginx, streaming" if short else "%s, streaming" % run.name["nginx"]
    return run.name.get(c, c)


def large(run):
    """(direction, size) -> candidate -> the medians of its rounds"""
    g = collections.defaultdict(list)
    for r in run.large:
        g[(r["dir"], r["size"], r["proxy"])].append(r)
    out = collections.defaultdict(dict)
    for (d, sz, c), v in g.items():
        gb = [x for x in ((r.get("delivered_gbps") if d == "up" else r.get("client_gbps")) for r in v) if x]
        if not gb:
            continue
        out[(d, sz)][c] = {
            "gbps": med(gb), "cpu": med([r.get("proxy_cpu_s_per_gb") for r in v]), "cpu_pct": med([r.get("proxy_cpu_pct") for r in v]),
            "mem": med([(r.get("peak_anon_mib") or 0) for r in v]), "sock": med([(r.get("peak_sock_mib") or 0) for r in v]),
            "sock_max": max((r.get("peak_sock_mib") or 0) for r in v),
            # temp files: only nginx writes them, and the kit keeps them in memory (shmem of its cgroup)
            "temp": med([(r.get("peak_shmem_mib") or 0) for r in v]) if c.startswith("nginx") else 0,
            "rounds": len(gb), "conns": v[0]["conns"], "errors": sum((r.get("errors") or 0) for r in v)}
    return out


def slow(run):
    """candidate -> what one slow download did (the samples of slow.jsonl)"""
    samples, summ = collections.defaultdict(list), {}
    for r in run.slow:
        if r.get("summary"):
            summ[r["proxy"]] = r
        elif "origin_sent" in r:
            samples[r["proxy"]].append(r)
    out = {}
    for c, v in samples.items():
        live = [x for x in v if x["client_got"] > 0] or v
        whole = [x["ms"] for x in v if x["origin_sent"] >= 2 ** 30]
        client = (summ.get(c, {}).get("client") or "").split()
        out[c] = {"ahead_mib": max(x["origin_sent"] - x["client_got"] for x in live) / 2 ** 20,
                  "mem_mib": max(x["anon"] for x in v) / 2 ** 20, "temp_mib": max(x.get("temp_used", 0) for x in v) / 2 ** 20,
                  "sock_mib": max(x.get("sock", 0) for x in v) / 2 ** 20, "cpu_s": summ.get(c, {}).get("cpu_s"),
                  "whole_s": whole[0] / 1000 if whole else None, "seconds": summ.get(c, {}).get("ms", 0) / 1000,
                  "bytes": int(client[0]) if client and client[0].isdigit() else None}
    return out


def chart_large(run, th):
    """One panel per large-object test: the proxies ranked by GB per second."""
    data = large(run)
    cases = [k for k in LCASES if data.get(k)]
    cols, pw, rowh, top = 2, 400, 19, 58
    lab, barw = 132, 190
    most = max(len([c for c in v if c not in ("origin", "sink")]) for v in data.values())
    ph = 30 + rowh * most + 14
    s = Svg(cols * pw + 20, top + math.ceil(len(cases) / cols) * ph + 6, th, "Large objects: gigabytes per second by proxy")
    s.text(14, 26, "Large objects over HTTP/1.1, by proxy", 15, weight="600")
    s.text(14, 45, "Gigabytes per second, median of the rounds, the proxy on %s cores. Longer is faster." % cores(run), 12, s.t["muted"])
    for i, (d, sz) in enumerate(cases):
        x0, y0 = 14 + (i % cols) * pw, top + (i // cols) * ph
        rows = sorted([(c, v) for c, v in data[(d, sz)].items() if c not in ("origin", "sink")], key=lambda cv: -cv[1]["gbps"])
        conns = rows[0][1]["conns"]
        s.text(x0, y0 + 14, "%s of %s, %s connections" % ("Downloads" if d == "down" else "Uploads", SIZES[sz], conns), 12.5, weight="600")
        top_v = rows[0][1]["gbps"]
        for j, (c, v) in enumerate(rows):
            y = y0 + 26 + j * rowh
            me = c == "nvelox"
            s.text(x0 + lab - 8, y + 10.5, lname(run, c, d, True), 11.5, s.t["ink"] if me else s.t["muted"], "end", "600" if me else "400")
            w = barw * v["gbps"] / top_v
            s.bar(x0 + lab, y, w, 13, s.t["a"] if me else s.t["b"])
            s.text(x0 + lab + w + 6, y + 10.5, "%.2f" % v["gbps"], 11.5, s.t["ink"], weight="600" if me else "400")
    return s.out()


def chart_slow(run, th):
    """The slow download: how far ahead of the client each proxy let the origin get (logarithmic)."""
    data = slow(run)
    order = sorted(data, key=lambda c: data[c]["ahead_mib"])
    lab, barw, rowh, top = 150, 420, 24, 62
    lo, hi = 1.0, max(1024.0, max(v["ahead_mib"] for v in data.values()))
    X = lambda v: barw * (math.log10(max(v, lo)) - math.log10(lo)) / (math.log10(hi) - math.log10(lo))
    s = Svg(lab + barw + 130, top + rowh * len(order) + 34, th, "A slow client: what each proxy holds ahead of the client")
    s.text(14, 26, "A client that reads slowly", 15, weight="600")
    s.text(14, 45, "One 1 GiB download read at 20 MiB/s: the most the origin was ahead of the client. MiB, logarithmic scale.", 12, s.t["muted"])
    for v in (1, 10, 100, 1000):
        s.line(lab + X(v), top - 6, lab + X(v), top + rowh * len(order), s.t["grid"])
        s.text(lab + X(v), top + rowh * len(order) + 16, "%d MiB" % v, 11, s.t["muted"], "middle")
    for i, c in enumerate(order):
        y = top + i * rowh
        me = c == "nvelox"
        s.text(lab - 10, y + 14, lname(run, c, "down", True), 12, s.t["ink"] if me else s.t["muted"], "end", "600" if me else "400")
        w = max(X(data[c]["ahead_mib"]), 2)
        s.bar(lab, y + 3, w, 14, s.t["a"] if me else s.t["b"])
        s.text(lab + w + 6, y + 14, "%.0f MiB" % data[c]["ahead_mib"], 11.5, s.t["ink"], weight="600" if me else "400")
    return s.out()


def chart_ratio(run, th):
    """Every round's nvelox / nginx ratio per test, and the median."""
    heads = [(t, run.head(t)) for t, _ in TESTS]
    heads = [(t, h) for t, h in heads if h]
    allr = [x for _, h in heads for x in h["ratios"]]
    lo = min(0.8, math.floor(min(allr) * 10) / 10)
    hi = max(1.2, math.ceil(max(allr) * 10) / 10)
    lab, pw, rowh, top = 206, 360, 27, 78
    w, h = lab + pw + 186, top + rowh * len(heads) + 34
    s = Svg(w, h, th, "nvelox against nginx, every round")
    X = lambda v: lab + pw * (v - lo) / (hi - lo)
    s.text(14, 26, "nvelox against nginx, round by round", 15, weight="600")
    s.text(14, 45, "Each dot is one round: nvelox's rate divided by nginx's, measured back to back. The bar marks the median.", 12, s.t["muted"])
    step = 0.2 if hi - lo <= 1.6 else 0.5
    v = math.ceil(lo / step - 1e-9) * step
    while v <= hi + 1e-9:
        s.line(X(v), top - 8, X(v), top + rowh * len(heads), s.t["grid"])
        s.text(X(v), top + rowh * len(heads) + 16, "%.1f×" % v, 11, s.t["muted"], "middle")
        v += step
    s.line(X(1), top - 12, X(1), top + rowh * len(heads), s.t["muted"], 1.5)
    s.text(X(1), top - 16, "same speed as nginx", 11, s.t["muted"], "middle")
    for i, (t, hd) in enumerate(heads):
        y = top + i * rowh + rowh / 2
        s.text(lab - 12, y + 4, SHORT[t], 12, anchor="end")
        for x in hd["ratios"]:
            s.dot(X(x), y, 4, s.t["a"])
        s.line(X(hd["ratio"]), y - 9, X(hd["ratio"]), y + 9, s.t["ink"], 2.5)
        s.text(lab + pw + 14, y + 4, "%.2f×" % hd["ratio"], 12, weight="600")
        s.text(lab + pw + 62, y + 4, "faster in %d of %d" % (hd["faster"], hd["rounds"]), 12, s.t["muted"])
    return s.out()


def chart_pair(run, th, key, title, sub, unit, log):
    """nvelox and nginx side by side per test, one dot each (medians)."""
    heads = [(t, run.head(t)) for t, _ in TESTS]
    heads = [(t, h) for t, h in heads if h and h["nvelox"].get(key) and h["nginx"].get(key)]
    vals = [h[c][key] for _, h in heads for c in ("nvelox", "nginx")]
    lab, pw, rowh, top = 206, 400, 27, 92
    w, hgt = lab + pw + 150, top + rowh * len(heads) + 34
    s = Svg(w, hgt, th, title)
    if log:
        lo, hi = 10 ** math.floor(math.log10(min(vals))), 10 ** math.ceil(math.log10(max(vals)))
        X = lambda v: lab + pw * (math.log10(v) - math.log10(lo)) / (math.log10(hi) - math.log10(lo))
        ticks = [m * 10 ** e for e in range(int(math.log10(lo)), int(math.log10(hi)) + 1) for m in (1, 2, 5) if lo <= m * 10 ** e <= hi]
    else:
        lo, hi = 0, max(vals) * 1.08
        X = lambda v: lab + pw * v / hi
        step = 10 ** math.floor(math.log10(hi / 4))
        step = step * (5 if hi / step > 20 else 2 if hi / step > 8 else 1)
        ticks = [i * step for i in range(0, int(hi / step) + 1)]
    s.text(14, 26, title, 15, weight="600")
    s.text(14, 45, sub, 12, s.t["muted"])
    s.dot(20, 64, 5, s.t["a"])
    s.text(30, 68, run.name["nvelox"], 12)
    x2 = 30 + 7.2 * len(run.name["nvelox"]) + 22
    s.dot(x2, 64, 5, s.t["b"])
    s.text(x2 + 10, 68, run.name["nginx"], 12)
    for v in ticks:
        s.line(X(v), top - 8, X(v), top + rowh * len(heads), s.t["grid"])
        s.text(X(v), top + rowh * len(heads) + 16, ("%g" % v) + unit, 11, s.t["muted"], "middle")
    for i, (t, hd) in enumerate(heads):
        y = top + i * rowh + rowh / 2
        a, b = hd["nvelox"][key], hd["nginx"][key]
        s.text(lab - 12, y + 4, SHORT[t], 12, anchor="end")
        s.line(X(a), y, X(b), y, s.t["muted"], 1.5)
        s.dot(X(b), y, 5, s.t["b"])
        s.dot(X(a), y, 5, s.t["a"])
        fmt = (lambda v: "%.2f" % v if v < 10 else "%.1f" % v) if log else (lambda v: "%.1f" % v)
        s.text(lab + pw + 14, y + 4, fmt(a), 12, weight="600")
        s.text(lab + pw + 58, y + 4, "vs " + fmt(b), 12, s.t["muted"])
    return s.out()


def charts(run):
    d = os.path.join(run.dir, "charts")
    os.makedirs(d, exist_ok=True)
    made = []
    for th in ("light", "dark"):
        suf = "" if th == "light" else "-dark"
        extra = []
        if run.field_rounds:
            extra += [("lead", chart_lead(run, th)), ("cpu-all", chart_cpu_all(run, th)), ("memory", chart_memory(run, th))]
        if run.large:
            extra.append(("large", chart_large(run, th)))
        if slow(run):
            extra.append(("slow", chart_slow(run, th)))
        for name, svg in extra + [
            ("requests", chart_requests(run, th)),
            ("ratio", chart_ratio(run, th)),
            ("latency", chart_pair(run, th, "p99_ms", "Slowest 1% of requests (99th percentile), at full load",
                                   "Milliseconds, median of the rounds, logarithmic scale. Further left is faster.", " ms", True)),
            ("cpu", chart_pair(run, th, "cpu_us", "CPU time the proxy spends per request, at full load",
                               "Microseconds of CPU per request (UDP: per reply), median of the rounds. Further left is cheaper.", " µs", False)),
        ]:
            open(os.path.join(d, name + suf + ".svg"), "w").write(svg)
            made.append(name + suf + ".svg")
    return made


def picture(prefix, name, alt):
    return ('<picture><source media="(prefers-color-scheme: dark)" srcset="%s/%s-dark.svg">'
            '<img alt="%s" src="%s/%s.svg"></picture>' % (prefix, name, html.escape(alt, quote=True), prefix, name))


# ---------------------------------------------------------------- markdown

def summary_md(run, prefix):
    """The block a documentation page shows: the head-to-head table, the charts and the tables of all proxies."""
    nv, ng = run.name["nvelox"], run.name["nginx"]
    o = []
    p = o.append
    heads = [(t, run.head(t)) for t, _ in TESTS]
    heads = [(t, h) for t, h in heads if h]
    won = sum(h["faster"] for _, h in heads)
    tot = sum(h["rounds"] for _, h in heads)
    level = [SHORT[t] for t, h in heads if h["rounds"] * 0.25 < h["faster"] < h["rounds"] * 0.75]
    p("### %s against %s\n" % (nv, ng))
    p("Both are measured back to back in each of the %d rounds, so every round gives one ratio. *Ratio* is the median of "
      "those ratios; *faster in* counts the rounds in which nvelox was the faster of the two. nvelox was the faster in "
      "%d of the %d paired measurements.%s\n" % (len(run.rounds), won, tot,
                                                 " Level, with the rounds split between the two: %s." % ", ".join(level) if level else ""))
    p("| Test | %s | %s | Ratio | Faster in | 99th percentile, ms | CPU per request, µs |" % (nv, ng))
    p("|---|---:|---:|---:|---:|---:|---:|")
    for t, h in heads:
        p("| %s | %s | %s | %s× | %d of %d | %s vs %s | %s vs %s |" % (
            LABEL[t], n0(h["nvelox"]["rps"]), n0(h["nginx"]["rps"]), f2(h["ratio"]), h["faster"], h["rounds"],
            f2(h["nvelox"]["p99_ms"]), f2(h["nginx"]["p99_ms"]), f1(h["nvelox"]["cpu_us"]), f1(h["nginx"]["cpu_us"])))
    p("")
    p("Rates are requests per second (UDP: replies per second), latency and CPU are nvelox vs nginx; all are medians of the rounds.\n")
    p(picture(prefix, "ratio", "nvelox against nginx: the ratio of every round, per test") + "\n")
    p(picture(prefix, "latency", "99th percentile latency of nvelox and nginx per test") + "\n")
    p(picture(prefix, "cpu", "CPU time per request of nvelox and nginx per test") + "\n")
    if run.field_rounds:
        p("### All proxies\n")
        p("Medians of the %d rounds in which every proxy was measured (the first rounds of the same run). "
          "The best of each column is bold.\n" % len(run.field_rounds))
        p(picture(prefix, "lead", "nvelox and the fastest other proxy, per test") + "\n")
        p(picture(prefix, "requests", "Requests per second of every proxy, per test") + "\n")
        for title, unit, tests in GROUPS:
            p("%s. %s, median of %d rounds:\n" % (title, unit, len(run.field_rounds)))
            p("| Proxy | " + " | ".join(SHORT[t] for t in tests) + " |")
            p("|---|" + "---:|" * len(tests))
            best = {t: max((run.field(c, t)["rps"] for c in run.cands if run.field(c, t)), default=None) for t in tests}
            cands = [c for c in run.cands if any(run.field(c, t) for t in tests)]
            cands.sort(key=lambda c: -(run.field(c, tests[0]) or {"rps": 0})["rps"])
            for c in cands:
                cells = []
                for t in tests:
                    v = run.field(c, t)
                    if not v:
                        cells.append("n/a")
                    else:
                        cell = n0(v["rps"]) + (" (%.2f%% lost)" % v["lost_pct"] if v.get("lost_pct") and v["lost_pct"] >= 0.01 else "")
                        cells.append("**%s**" % cell if v["rps"] == best[t] else cell)
                p("| %s | %s |" % ("**%s**" % run.name[c] if c == "nvelox" else run.name[c], " | ".join(cells)))
            p("")
        p("### CPU and memory of every proxy\n")
        p("CPU time per request is the proxy's CPU time (user and kernel) over the measured window, divided by the requests it "
          "served; microseconds (UDP: per reply), median of the same %d rounds. The lowest of each column is bold.\n" % len(run.field_rounds))
        p(picture(prefix, "cpu-all", "CPU time per request of every proxy, per test") + "\n")
        for title, _, tests in GROUPS:
            p("%s. CPU per request, µs:\n" % title)
            p("| Proxy | " + " | ".join(SHORT[t] for t in tests) + " |")
            p("|---|" + "---:|" * len(tests))
            best = {t: min((run.field(c, t)["cpu_us"] for c in run.cands if run.field(c, t) and run.field(c, t).get("cpu_us")), default=None) for t in tests}
            cands = [c for c in run.cands if any(run.field(c, t) for t in tests)]
            cands.sort(key=lambda c: (run.field(c, tests[0]) or {}).get("cpu_us") or 1e9)
            for c in cands:
                cells = []
                for t in tests:
                    v = run.field(c, t)
                    if not v or not v.get("cpu_us"):
                        cells.append("n/a")
                    else:
                        cells.append("**%.1f**" % v["cpu_us"] if v["cpu_us"] == best[t] else "%.1f" % v["cpu_us"])
                p("| %s | %s |" % ("**%s**" % run.name[c] if c == "nvelox" else run.name[c], " | ".join(cells)))
            p("")
    p(resources_md(run, prefix))
    if run.large or run.slow:
        p(large_md(run, prefix))
    return "\n".join(o)


def large_md(run, prefix):
    data, o = large(run), []
    p = o.append
    p("### Large objects\n")
    if data:
        rounds = max(v["rounds"] for d in data.values() for v in d.values())
        p("Plain HTTP/1.1, every proxy in each of %d rounds. Downloads are files the origin holds in memory; uploads go to a sink that "
          "reads every body to its end. The figures are gigabytes per second (median of the rounds), with the proxy's CPU seconds per "
          "gigabyte in parentheses; the best of each column is bold.\n" % rounds)
        p("nginx is measured twice in each direction. With its defaults it buffers: a response in temp files when the client is the "
          "slower side, and a whole request body before any of it goes upstream (its temp files are in memory in this test, so they "
          "cost no disk writes). *Tuned for large files* is `proxy_max_temp_file_size 0` with 16 buffers of 64k; *streaming* is "
          "`proxy_request_buffering off`. The other proxies run with the configuration of the request tests.\n")
        for d, title in (("down", "Downloads"), ("up", "Uploads")):
            cases = [k for k in LCASES if k[0] == d and data.get(k)]
            if not cases:
                continue
            cands = [c for c in LORDER if any(c in data[k] for k in cases)]
            cands.sort(key=lambda c: -(data[cases[0]].get(c) or {"gbps": 0})["gbps"])
            best = {k: max(v["gbps"] for c, v in data[k].items() if c not in ("origin", "sink")) for k in cases}
            p("| %s | " % title + " | ".join("%s, %s connections" % (SIZES[k[1]], next(iter(data[k].values()))["conns"]) for k in cases) + " |")
            p("|---|" + "---:|" * len(cases))
            for c in cands:
                cells = []
                for k in cases:
                    v = data[k].get(c)
                    if not v:
                        cells.append("n/a")
                        continue
                    cell = "%.2f (%.2f)" % (v["gbps"], v["cpu"]) if v.get("cpu") else "%.2f" % v["gbps"]
                    if v["errors"]:
                        cell += ", %d failed" % v["errors"]
                    cells.append("**%s**" % cell if v["gbps"] == best[k] else cell)
                p("| %s | %s |" % ("**%s**" % lname(run, c, d) if c == "nvelox" else lname(run, c, d), " | ".join(cells)))
            alone = "origin" if d == "down" else "sink"
            if all(alone in data[k] for k in cases):
                p("| *the %s alone* | %s |" % (alone, " | ".join("*%.2f*" % data[k][alone]["gbps"] for k in cases)))
            p("")
        p(picture(prefix, "large", "Large downloads and uploads: gigabytes per second of every proxy") + "\n")
        p("What the proxies held while they did this: for each figure the highest of the tests' medians (the proxies are freshly "
          "started before these tests).\n")
        p("| Proxy | Own memory, MiB | Kernel socket buffers, MiB | Temp files (in memory here), MiB |")
        p("|---|---:|---:|---:|")
        seen = []
        for c in LORDER:
            vs = [(k, data[k][c]) for k in LCASES if data.get(k) and c in data[k]]
            if not vs:
                continue
            d = vs[0][0][0]
            name = run.name["nginx"] + " (the four setups)" if c == "nginx" else lname(run, c, d)
            if c in ("nginx-tuned", "nginx-streamed"):
                continue
            if c == "nginx":
                vs += [(k, data[k][x]) for x in ("nginx-tuned", "nginx-streamed") for k in LCASES if data.get(k) and x in data[k]]
            p("| %s | %.0f | %.0f | %s |" % ("**%s**" % name if c == "nvelox" else name, max(v["mem"] for _, v in vs), max(v["sock"] for _, v in vs),
                                            "%.0f" % max(v["temp"] for _, v in vs) if max(v["temp"] for _, v in vs) >= 1 else "none"))
        p("")
    sl = slow(run)
    if sl:
        p("**A client that reads slowly.** One 1 GiB download read at 20 MiB/s through each proxy, freshly started. A proxy that reads "
          "from the origin only as fast as its client takes the data holds a few megabytes; one that buffers holds the file.\n")
        p("| Proxy | Origin ahead of the client, at most | Own memory, at most | Temp files, at most | CPU for the whole download |")
        p("|---|---:|---:|---:|---:|")
        for c in sorted(sl, key=lambda c: sl[c]["ahead_mib"]):
            v = sl[c]
            note = "" if v["bytes"] in (None, 2 ** 30) else " (the client got %s of 1,073,741,824 bytes)" % format(v["bytes"], ",")
            p("| %s | %s MiB%s | %.1f MiB | %s | %s |" % (
                "**%s**" % lname(run, c, "down") if c == "nvelox" else lname(run, c, "down"), format(round(v["ahead_mib"]), ","),
                " (the whole file after %.0f s)" % v["whole_s"] if v["whole_s"] and v["whole_s"] < v["seconds"] * 0.5 else "", v["mem_mib"],
                "none" if v["temp_mib"] < 1 else "%s MiB" % format(round(v["temp_mib"]), ","),
                ("%.2f s" % v["cpu_s"] if v["cpu_s"] is not None else "n/a") + note))
        p("")
        p(picture(prefix, "slow", "A slow client: what each proxy holds ahead of the client") + "\n")
    return "\n".join(o)


def resources_md(run, prefix="charts"):
    o = []
    p = o.append
    m = memory(run)
    if not run.field_rounds:
        p("### Memory, threads and idle cost\n")
    p("*Memory under load* is the proxy's own memory (anonymous memory of its cgroup, the peak of each measurement), the "
      "lowest and the highest test median. *Idle* is 10 seconds of the freshly started proxy with no traffic.\n")
    if run.field_rounds:
        p(picture(prefix, "memory", "Memory of every proxy, idle and under load") + "\n")
    p("| Proxy | Memory under load, MiB | Idle memory, MiB | Idle CPU, % of one core | Threads or processes under load |")
    p("|---|---:|---:|---:|---:|")
    for c in run.cands:
        v = m[c]
        p("| %s | %s | %s | %s | %s |" % (
            "**%s**" % run.name[c] if c == "nvelox" else run.name[c], "%.0f to %.0f" % (v["lo"], v["hi"]) if v["hi"] is not None else "n/a",
            f1(v["idle"]), f2(v["idle_cpu"]), "%.0f" % v["threads"] if v["threads"] else "n/a"))
    p("")
    return "\n".join(o)


def checks_md(run):
    o = []
    p = o.append
    p("## Checks on the test setup\n")
    orig = [r["rps"] for r in run.R.get(("origin", "http_1k"), {}).values()]
    if orig:
        p("- **The origin alone, HTTP 1 KiB**, at the start of every round: median %s requests per second, from %s to %s. "
          "It shows how much the machine's speed moves between rounds, which is why nvelox and nginx are compared within a round."
          % (n0(med(orig)), n0(min(orig)), n0(max(orig))))
    uo = [r["rps"] for r in run.R.get(("origin", "udp_1024"), {}).values()]
    if uo:
        p("- **The UDP echo origin alone, 1,024 bytes:** median %s replies per second, from %s to %s." % (n0(med(uo)), n0(min(uo)), n0(max(uo))))
    meas = [r for r in run.rows if r.get("rps") and r["proxy"] != "origin"]
    if meas:
        lg = max(r["lg_cpu_pct"] for r in meas)
        og = max(r["origin_cpu_pct"] for r in meas)
        p("- **Headroom:** the load generator used at most %.0f%% of a core in any measurement, the origin at most %.0f%%." % (lg, og))
        m = re.search(r"WORKERS=(\d+)", envval(run.env, "settings"))
        cores = int(m.group(1)) if m else 4
        busy = collections.defaultdict(list)
        for r in meas:
            if r["origin_cpu_pct"] > 85 * cores:
                busy[(r["proxy"], r["test"])].append(r["origin_cpu_pct"])
        if busy:
            p("- **The origin was above 85%% of its cores** while these ran, so their figures may be held back by the origin: %s."
              % "; ".join("%s, %s (%.0f%%)" % (run.name.get(c, c), SHORT[t], max(v)) for (c, t), v in sorted(busy.items())))
        slack = collections.defaultdict(list)
        for r in meas:
            if r.get("proxy_cpu_pct") is not None and r["proxy_cpu_pct"] < 90 * cores:
                slack[(r["proxy"], r["test"])].append(r["proxy_cpu_pct"])
        if slack:
            p("- **Proxies that did not use 90%% of their cores** (median CPU of the measurements below that): %s."
              % "; ".join("%s, %s (%.0f%%)" % (run.name.get(c, c), SHORT[t], med(v)) for (c, t), v in sorted(slack.items())))
    errs = [r for r in run.rows if r.get("errors") or r.get("non2xx")]
    lost = [r for r in run.rows if r.get("lost_pct")]
    p("- **Errors:** %s." % ("none: no failed request, no answer other than 2xx" if not errs else "; ".join(
        "%s, %s, round %s: %s errors, %s non-2xx" % (run.name.get(r["proxy"], r["proxy"]), SHORT[r["test"]], r["round"], r.get("errors", 0), r.get("non2xx", 0)) for r in errs[:20])))
    p("- **UDP datagrams lost:** %s." % ("none" if not lost else "; ".join(
        "%s, %s, round %s: %.2f%%" % (run.name.get(r["proxy"], r["proxy"]), SHORT[r["test"]], r["round"], r["lost_pct"]) for r in lost[:20])))
    alpn = [r for r in run.rows if r["test"][:2] in ("h2", "h3") and r.get("alpn") != r["test"][:2]]
    p("- **Protocol negotiated** in the HTTP/2 and HTTP/3 tests: %s." % ("h2 and h3 as asked, in every measurement" if not alpn else "NOT as asked in %d measurements" % len(alpn)))
    if run.failed:
        p("- **Measurements without a result:** %s." % "; ".join("%s, %s, round %s" % (r["proxy"], r["test"], r["round"]) for r in run.failed[:20]))
    if run.large:
        top = max((r for r in run.large if r.get("peak_sock_mib") is not None), key=lambda r: r["peak_sock_mib"], default=None)
        if top:
            p("- **Large objects, kernel socket buffers:** the highest single reading of any proxy was %.0f MiB (%s, %s of %s, round %s); "
              "the table shows medians of the rounds." % (top["peak_sock_mib"], run.name.get(top["proxy"], top["proxy"]),
                                                          "downloads" if top["dir"] == "down" else "uploads", SIZES[top["size"]], top["round"]))
        bad = [r for r in run.large if r.get("errors") or not (r.get("client_gbps") or r.get("delivered_gbps"))]
        p("- **Large objects, failed transfers:** %s." % ("none" if not bad else "; ".join(
            "%s, %s %s, round %s: %s (%s)" % (r["proxy"], r["dir"], r["size"], r["round"], r.get("errors", "no result"), r.get("last_error") or "") for r in bad[:20])))
    p("")
    return "\n".join(o)


def rounds_md(run):
    o = ["## Every round\n", "Requests (UDP: replies) per second. The origin alone is measured at the start of the round "
         "(for UDP: the echo origin, before the UDP tests).\n"]
    for t, _ in TESTS:
        h = run.head(t)
        if not h:
            continue
        ot = "udp_1024" if t.startswith("udp") else "http_1k"
        o.append("**%s**\n" % LABEL[t])
        o.append("| Round | Origin alone | %s | %s | Ratio |" % (run.name["nvelox"], run.name["nginx"]))
        o.append("|---:|---:|---:|---:|---:|")
        for k, x in zip(h["round_ids"], h["ratios"]):
            og = run.R.get(("origin", ot), {}).get(k, {}).get("rps")
            o.append("| %d | %s | %s | %s | %.2f |" % (k, n0(og), n0(run.R[("nvelox", t)][k]["rps"]), n0(run.R[("nginx", t)][k]["rps"]), x))
        o.append("")
    return "\n".join(o)


def setup_md(run):
    env = run.env
    cpu = envval(env, "Model name")
    o = ["## Setup\n"]
    o.append("| | |")
    o.append("|---|---|")
    o.append("| Date | %s |" % envval(env, "date"))
    o.append("| Machine | %s CPUs, %s%s, %s RAM, Linux %s |" % (envval(env, "CPU(s)"), cpu, " (%s)" % envval(env, "Hypervisor vendor") if envval(env, "Hypervisor vendor") else "", envval(env, "memory"), envval(env, "kernel")))
    o.append("| Cores | %s |" % envval(env, "cpus"))
    o.append("| Settings | %s |" % envval(env, "settings"))
    o.append("| Proxies | %s |" % ", ".join(run.name[c] for c in run.cands))
    o.append("| Load tools | %s; %s; udptool (in this kit) |" % (envval(env, "version wrk"), envval(env, "version h2load")))
    o.append("")
    o.append("`env.txt` has the image digests and the checksums of the binaries, the configs and the scripts of this run; "
             "`results.jsonl` one line per measurement (`large.jsonl` for the large objects, `slow.jsonl` the samples of the slow "
             "downloads); `tools.log` what the load tools printed.\n")
    return "\n".join(o)


def summary_json(run):
    tests = [{"id": t, "label": LABEL[t], "short": SHORT[t], "unit": "replies/s" if t.startswith("udp") else "requests/s"} for t, _ in TESTS]
    head = {}
    for t, _ in TESTS:
        h = run.head(t)
        if h:
            head[t] = {"rounds": h["rounds"], "ratio": h["ratio"], "faster": h["faster"], "cpu_diff": h["cpu_diff"],
                       "nvelox": h["nvelox"], "nginx": h["nginx"],
                       "per_round": [{"round": k, "nvelox": run.R[("nvelox", t)][k]["rps"], "nginx": run.R[("nginx", t)][k]["rps"]}
                                     for k in h["round_ids"]]}
    field = {t: {c: run.field(c, t) for c in run.cands if run.field(c, t)} for t, _ in TESTS}
    env = run.env
    return {
        "date": envval(env, "date"), "kernel": envval(env, "kernel"), "cpu": envval(env, "Model name"), "cpus": envval(env, "CPU(s)"),
        "hypervisor": envval(env, "Hypervisor vendor"), "memory": envval(env, "memory"), "settings": envval(env, "settings"),
        "cores": envval(env, "cpus"), "rounds": len(run.rounds), "field_rounds": len(run.field_rounds),
        "proxies": [{"id": c, "name": run.name[c]} for c in run.cands], "tests": tests, "head": head, "field": field,
        "idle": run.idle, "origin_alone": sorted(r["rps"] for r in run.R.get(("origin", "http_1k"), {}).values()),
        "large": {"%s_%s" % k: v for k, v in large(run).items()}, "slow": slow(run),
    }


def main():
    args = sys.argv[1:]
    docs = None
    if "--docs" in args:
        i = args.index("--docs")
        docs = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        sys.exit(__doc__)
    run = Run(args[0].rstrip("/"))
    if not run.rows:
        sys.exit("no results in " + run.dir)
    made = charts(run)
    json.dump(summary_json(run), open(os.path.join(run.dir, "summary.json"), "w"), indent=1)
    title = "# %s against %s and %d other proxies: results\n" % (run.name["nvelox"], run.name["nginx"], max(0, len(run.cands) - 2))
    body = "\n".join([title, "Made by `bench.sh report` from the files in this directory. ../../README.md describes the tests.\n",
                      summary_md(run, "charts"), checks_md(run), setup_md(run), rounds_md(run)])
    open(os.path.join(run.dir, "REPORT.md"), "w").write(body)
    print("%s: REPORT.md, summary.json, %d charts; %d measurements, %d rounds (%d with every proxy), %d without a result"
          % (run.dir, len(made), len(run.rows), len(run.rounds), len(run.field_rounds), len(run.failed)))
    if docs:
        text = open(docs).read()
        a, b = "<!-- bench:begin -->", "<!-- bench:end -->"
        if a not in text or b not in text:
            sys.exit("%s has no %s ... %s block" % (docs, a, b))
        prefix = os.path.relpath(os.path.join(run.dir, "charts"), os.path.dirname(os.path.abspath(docs)))
        block = "%s\n<!-- made by bench/report.py from %s: do not edit by hand -->\n\n%s\n%s" % (
            a, os.path.relpath(run.dir, os.path.dirname(os.path.abspath(docs))), summary_md(run, prefix), b)
        open(docs, "w").write(text[:text.index(a)] + block + text[text.index(b) + len(b):])
        print("updated the benchmark block of", docs)


if __name__ == "__main__":
    main()
