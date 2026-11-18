-- wrk done() hook: one machine-readable JSON line per run (latencies in microseconds).
done = function(summary, latency, requests)
  local e = summary.errors
  io.write(string.format(
    'WRKJSON {"requests":%d,"duration_us":%d,"bytes":%d,"err_connect":%d,"err_read":%d,"err_write":%d,"err_status":%d,"err_timeout":%d,"lat_mean_us":%.1f,"lat_stdev_us":%.1f,"lat_max_us":%d,"p50_us":%d,"p75_us":%d,"p90_us":%d,"p99_us":%d,"p999_us":%d}\n',
    summary.requests, summary.duration, summary.bytes,
    e.connect, e.read, e.write, e.status, e.timeout,
    latency.mean, latency.stdev, latency.max,
    latency:percentile(50), latency:percentile(75), latency:percentile(90),
    latency:percentile(99), latency:percentile(99.9)))
end
