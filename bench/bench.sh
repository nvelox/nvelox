#!/usr/bin/env bash
# The nvelox benchmark kit: reverse proxies in front of one origin, one proxy at a time.
#
#   bench.sh setup     builds the load-generator image and the two load tools, fetches the nvelox
#                      release binaries (checksums verified), writes a certificate and the payloads,
#                      and creates the containers
#   bench.sh run       measures, into results/<UTC time>/ (or $RESULTS)
#   bench.sh report    tables and charts of a results directory: bench.sh report results/<name>
#   bench.sh down      stops and removes the kit's containers
#
# Everything runs on 127.0.0.1 with host networking, one Docker container per process:
#   load generator (LOAD_CPUS)  ->  proxy under test (PROXY_CPUS)  ->  origin (ORIGIN_CPUS)
# The settings are environment variables; the defaults are those of the published runs.
# README.md describes the tests and how to read the results.
set -u
K=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
W=${WORK:-$K/.work}

NVELOX_VERSION=${NVELOX_VERSION:-v2.0.0-rc.3}   # the release under test
PREV_VERSION=${PREV_VERSION:-v1.3.0}            # the earlier release, as a reference
NVELOX_BIN=${NVELOX_BIN:-}                      # a binary of your own instead of the release under test
ORIGIN_CPUS=${ORIGIN_CPUS:-4-7}
PROXY_CPUS=${PROXY_CPUS:-8-11}
LOAD_CPUS=${LOAD_CPUS:-12-19}
ROUNDS=${ROUNDS:-12}                            # rounds of nvelox and nginx
FIELD_ROUNDS=${FIELD_ROUNDS:-5}                 # the first rounds also measure the other proxies
DUR=${DUR:-10}                                  # seconds measured
WARM=${WARM:-3}                                 # seconds of warm-up before them
BURNIN=${BURNIN:-180}                           # seconds of load before round 1 that are not measured
CONNS=${CONNS:-128}                             # connections (UDP: flows)
LARGE_ROUNDS=${LARGE_ROUNDS:-3}                 # rounds of the large-object tests, every proxy in each (0: none)
LARGE_DUR=${LARGE_DUR:-12}                      # seconds measured in them
SLOW=${SLOW:-1}                                 # 1: also one slow download through every proxy
LOCK=${LOCK:-}                                  # a lock file to hold during a run, on a shared machine

die() { echo "bench: $*" >&2; exit 1; }
cpus_in() { # "8-11,14" -> 5
  local n=0 p parts
  IFS=, read -ra parts <<<"$1"
  for p in "${parts[@]}"; do
    if [[ $p == *-* ]]; then n=$((n + ${p#*-} - ${p%-*} + 1)); else n=$((n + 1)); fi
  done
  echo "$n"
}
WORKERS=$(cpus_in "$PROXY_CPUS")                # workers of every proxy = its cores
ORIGIN_WORKERS=$(cpus_in "$ORIGIN_CPUS")
THREADS=${THREADS:-$(cpus_in "$LOAD_CPUS")}     # threads of the load generators

IMG_NGINX=nginx:1.31.8
IMG_HAPROXY=haproxy:3.4.7
IMG_ENVOY=envoyproxy/envoy:v1.40.2
IMG_TRAEFIK=traefik:v3.7.18
IMG_CADDY=caddy:2.11.9
IMG_BASE=ubuntu:24.04                           # nvelox runs from its static binary in this image
IMG_GO=golang:1.27.3                            # builds the two load tools
IMG_LOAD=nvbench-loadgen:local

C_ORIGIN=nvbench-origin
C_UDP_ORIGIN=nvbench-udp-origin
C_SINK=nvbench-sink                             # where the large uploads go: reads every body to its end
C_LOAD=nvbench-load
C_TRAEFIK_LOG=nvbench-traefik-log
declare -A CT=( [nvelox]=nvbench-nvelox [nginx]=nvbench-nginx [haproxy]=nvbench-haproxy [envoy]=nvbench-envoy
                [traefik]=nvbench-traefik [caddy]=nvbench-caddy [nvelox-prev]=nvbench-nvelox-prev )
declare -A BASE=( [nvelox]=27100 [nginx]=27110 [haproxy]=27120 [envoy]=27130 [traefik]=27140 [caddy]=27150 [nvelox-prev]=27160 )
PROXY_CTS="${CT[nvelox]} ${CT[nginx]} ${CT[haproxy]} ${CT[envoy]} ${CT[traefik]} $C_TRAEFIK_LOG ${CT[caddy]} ${CT[nvelox-prev]}"
ALL_CTS="$C_ORIGIN $C_UDP_ORIGIN $C_SINK $C_LOAD $PROXY_CTS"

TESTS=(http_1k http_64k https_1k tcp_1k http_1k_log h2_m1 h2_m10 h3_m1 h3_m10 udp_1024 udp_64)
HEAD=(nvelox nginx)                             # measured in every round
FIELD=(haproxy envoy traefik caddy nvelox-prev) # measured in the first FIELD_ROUNDS rounds

# port_for <candidate> <test>: the port of the listener that serves the test; fails when the
# proxy has no such listener (Caddy's stock image: no TCP or UDP proxy; HAProxy: no UDP proxy).
port_for() {
  local c=$1 t=$2 o
  case $c:$t in caddy:tcp_*|caddy:udp_*|haproxy:udp_*) return 1 ;; esac
  case $t in
    http_1k|http_64k) o=0 ;;
    https_1k)         o=1 ;;
    tcp_1k)           o=2 ;;
    http_1k_log)      o=3 ;;
    h2_*)             o=4 ;;
    h3_*)             o=5 ;;
    udp_*)            o=6 ;;
    *) return 1 ;;
  esac
  # nvelox writes its access log in every HTTP test, and serves HTTPS, HTTP/2 and HTTP/3 on one listener.
  case $c in nvelox|nvelox-prev) case $t in http_1k_log) o=0 ;; h2_*|h3_*) o=1 ;; esac ;; esac
  echo $((BASE[$c] + o))
}
ct_for() { if [[ $1 == traefik && $2 == http_1k_log ]]; then echo $C_TRAEFIK_LOG; else echo "${CT[$1]}"; fi; }
url_for() { # candidate test (candidate "origin": the origin itself)
  local port path=/1k.bin
  if [[ $1 == origin ]]; then port=27000; else port=$(port_for "$1" "$2") || return 1; fi
  [[ $2 == http_64k ]] && path=/64k.bin
  case $2 in https_1k|h2_*|h3_*) echo "https://bench.local:$port$path" ;; *) echo "http://bench.local:$port$path" ;; esac
}

# The large-object tests (HTTP/1.1): downloads of /big/<size>.bin through the HTTP listener, uploads
# through a listener of their own to the sink. nginx is measured twice in each direction: with its
# defaults ("nginx") and tuned for large files or streaming ("nginx-tuned", "nginx-streamed").
LARGE_DL=(nvelox nginx nginx-tuned haproxy envoy traefik caddy nvelox-prev)
LARGE_UL=(nvelox nginx nginx-streamed haproxy envoy traefik caddy nvelox-prev)
DL_CASES=("1m 1048576 64" "16m 16777216 16" "1g 1073741824 4")   # name, bytes, connections
UL_CASES=("16m 16777216 16" "1g 1073741824 2")
large_ct() { case $1 in nginx-*) echo "${CT[nginx]}" ;; *) echo "${CT[$1]}" ;; esac; }
dl_port() { case $1 in origin) echo 27000 ;; nginx-tuned) echo $((BASE[nginx] + 8)) ;; *) echo "${BASE[$1]}" ;; esac; }
ul_port() { case $1 in sink) echo 27600 ;; nginx-streamed) echo $((BASE[nginx] + 9)) ;; *) echo $((BASE[$1] + 7)) ;; esac; }

fetch_nvelox() { # version -> $W/bin/nvelox-<version>, from the GitHub release, checksum verified
  local v=$1 arch d=$W/dl/$1 base=https://github.com/nvelox/nvelox/releases/download/$1
  case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die "no nvelox release for $(uname -m)" ;; esac
  [[ -x $W/bin/nvelox-$v ]] && return 0
  mkdir -p "$d"
  curl -fsSL -o "$d/nvelox_linux_$arch.tar.gz" "$base/nvelox_linux_$arch.tar.gz" || die "download of nvelox $v failed"
  curl -fsSL -o "$d/checksums.txt" "$base/checksums.txt" || die "download of the checksums of nvelox $v failed"
  (cd "$d" && grep " nvelox_linux_$arch.tar.gz\$" checksums.txt | sha256sum -c - >/dev/null) || die "the checksum of nvelox $v does not match"
  tar -xzf "$d/nvelox_linux_$arch.tar.gz" -C "$d" nvelox || die "no nvelox binary in the archive of $v"
  install -m 0755 "$d/nvelox" "$W/bin/nvelox-$v"
}

setup() {
  command -v docker >/dev/null || die "docker is needed"
  local s last top; top=$(nproc --all)
  for s in "$ORIGIN_CPUS" "$PROXY_CPUS" "$LOAD_CPUS"; do
    last=${s##*[-,]}
    (( last < top )) || die "CPU $last of '$s' does not exist here ($top CPUs): set ORIGIN_CPUS, PROXY_CPUS and LOAD_CPUS"
  done
  mkdir -p "$W"/{bin,certs,data,conf,dl}

  echo "== load-generator image (wrk, h2load with HTTP/3)"
  docker build -t $IMG_LOAD "$K/loadgen" || die "the load-generator image did not build"

  echo "== load tools (UDP; large downloads and uploads)"
  local tool
  for tool in udptool bigtool; do
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/go-cache -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
      -v "$K/$tool:/src:ro" -v "$W/bin:/out" -w /src $IMG_GO go build -trimpath -o /out/$tool . || die "$tool did not build"
  done

  echo "== nvelox binaries"
  fetch_nvelox "$PREV_VERSION"
  if [[ -n $NVELOX_BIN ]]; then
    install -m 0755 "$NVELOX_BIN" "$W/bin/nvelox-under-test" || die "cannot read $NVELOX_BIN"
  else
    fetch_nvelox "$NVELOX_VERSION"
    install -m 0755 "$W/bin/nvelox-$NVELOX_VERSION" "$W/bin/nvelox-under-test"
  fi

  echo "== certificate (ECDSA P-256, self-signed) and payloads"
  docker run --rm --user "$(id -u):$(id -g)" -v "$W/certs:/certs" $IMG_LOAD sh -c '
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=bench.local" -addext "subjectAltName=DNS:bench.local,IP:127.0.0.1" \
      -keyout /certs/key.pem -out /certs/cert.pem 2>/dev/null \
    && cat /certs/cert.pem /certs/key.pem > /certs/combined.pem && chmod 644 /certs/*.pem' || die "no certificate"
  head -c 1024 /dev/zero | tr '\0' 'n' > "$W/data/1k.bin"
  head -c 65536 /dev/zero | tr '\0' 'n' > "$W/data/64k.bin"

  echo "== configs: $WORKERS workers per proxy, $ORIGIN_WORKERS for the origin"
  local f
  for f in "$K"/conf/*; do
    sed -e "s/__WORKERS__/$WORKERS/g" -e "s/__ORIGIN_WORKERS__/$ORIGIN_WORKERS/g" "$f" > "$W/conf/$(basename "$f")"
  done

  echo "== containers"
  local U="--network host --ulimit nofile=200000:200000 --log-driver json-file --log-opt max-size=5m --log-opt max-file=1"
  local P="$U --cpuset-cpus $PROXY_CPUS" NV="--user 65534:65534 -v $W/certs:/certs:ro"
  mk() { docker rm -f -v "$1" >/dev/null 2>&1; docker create --name "$@" >/dev/null || die "container $1 was not created"; }
  # /big holds the files of the large-object tests, in memory (1 MiB, 16 MiB, 1 GiB; written by "run")
  mk $C_ORIGIN $U --cpuset-cpus "$ORIGIN_CPUS" -v "$W/conf/origin.conf:/etc/nginx/nginx.conf:ro" -v "$W/data:/data:ro" \
    --tmpfs /big:rw,size=1200m $IMG_NGINX
  mk $C_SINK $U --init --cpuset-cpus "$ORIGIN_CPUS" -v "$W/bin:/kit/bin:ro" $IMG_BASE /kit/bin/bigtool sink -addr 127.0.0.1:27600
  mk $C_UDP_ORIGIN $U --init --cpuset-cpus "$ORIGIN_CPUS" -v "$W/bin:/kit/bin:ro" $IMG_BASE /kit/bin/udptool echo -addr 127.0.0.1:27500 -workers "$ORIGIN_WORKERS"
  mk $C_LOAD $U --init --cpuset-cpus "$LOAD_CPUS" --add-host bench.local:127.0.0.1 -e OPENSSL_CONF=/kit/loadgen/openssl.cnf \
    -v "$K/loadgen:/kit/loadgen:ro" -v "$W/bin:/kit/bin:ro" $IMG_LOAD sleep infinity
  mk "${CT[nvelox]}" $P $NV -v "$W/bin/nvelox-under-test:/usr/local/bin/nvelox:ro" -v "$W/conf/nvelox.yaml:/etc/nvelox/nvelox.yaml:ro" \
    $IMG_BASE /usr/local/bin/nvelox -config /etc/nvelox/nvelox.yaml
  mk "${CT[nvelox-prev]}" $P $NV -v "$W/bin/nvelox-$PREV_VERSION:/usr/local/bin/nvelox:ro" -v "$W/conf/nvelox-prev.yaml:/etc/nvelox/nvelox.yaml:ro" \
    $IMG_BASE /usr/local/bin/nvelox -config /etc/nvelox/nvelox.yaml
  # nginx's temp files in memory: with its defaults it buffers large bodies in them
  mk "${CT[nginx]}" $P -v "$W/conf/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$W/certs:/certs:ro" --tmpfs /var/cache/nginx:rw,size=4g $IMG_NGINX
  mk "${CT[haproxy]}" $P -v "$W/conf/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" -v "$W/certs:/certs:ro" $IMG_HAPROXY
  mk "${CT[envoy]}" $P -v "$W/conf/envoy.yaml:/etc/envoy/envoy.yaml:ro" -v "$W/certs:/certs:ro" \
    $IMG_ENVOY envoy -c /etc/envoy/envoy.yaml --concurrency "$WORKERS" --log-level warn
  mk "${CT[traefik]}" $P -v "$W/conf/traefik.yml:/etc/traefik/traefik.yml:ro" -v "$W/conf/traefik-dynamic.yml:/etc/traefik/dynamic.yml:ro" \
    -v "$W/certs:/certs:ro" $IMG_TRAEFIK
  mk $C_TRAEFIK_LOG $P -v "$W/conf/traefik-log.yml:/etc/traefik/traefik.yml:ro" -v "$W/conf/traefik-log-dynamic.yml:/etc/traefik/dynamic.yml:ro" $IMG_TRAEFIK
  mk "${CT[caddy]}" $P -v "$W/conf/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$W/certs:/certs:ro" \
    $IMG_CADDY caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
  echo "setup done: bench.sh run"
}

ready() { # candidate test: does the listener answer?
  local c=$1 t=$2 u port i
  u=$(url_for "$c" "$t") || return 0
  port=${u##*:}; port=${port%%/*}
  for i in $(seq 1 20); do
    case $t in
      udp_*) docker exec $C_LOAD /kit/bin/udptool load -target "127.0.0.1:$port" -flows 1 -size 64 -warm 0s -dur 200ms 2>&1 | grep -q '"replies":[1-9]' && return 0 ;;
      h2_*|h3_*) docker exec $C_LOAD timeout 5 h2load -n 1 -c 1 --alpn-list="${t%%_*}" "$u" 2>&1 | grep -q 'status codes: 1 2xx' && return 0 ;;
      *) [[ $(docker exec $C_LOAD curl -sk --max-time 2 -o /dev/null -w '%{http_code}' "$u") == 200 ]] && return 0 ;;
    esac
    sleep 0.25
  done
  return 1
}

run() {
  local RUN=${RESULTS:-$K/results/$(date -u +%Y%m%dT%H%M%SZ)} c t rep si
  [[ -x $W/bin/udptool ]] || die "run 'bench.sh setup' first"
  if [[ -n $LOCK ]]; then
    exec 9>"$LOCK"
    echo "$(date -u +%T) waiting for the lock $LOCK"
    flock -w 14400 9 || die "the lock is held"
  fi
  mkdir -p "$RUN"
  local OUT=$RUN/results.jsonl LOG=$RUN/tools.log CON=$RUN/console.txt BIGOUT=$RUN/large.jsonl SLOWOUT=$RUN/slow.jsonl
  local large=0; (( LARGE_ROUNDS > 0 || SLOW )) && large=1
  say() { echo "$*" | tee -a "$CON"; }
  say "$(date -u +%T) results in $RUN"

  docker stop -t 5 $ALL_CTS >/dev/null 2>&1
  docker start $ALL_CTS >/dev/null || die "the containers did not start: bench.sh setup"
  sleep 3
  for c in "${HEAD[@]}" "${FIELD[@]}"; do
    for t in http_1k https_1k tcp_1k http_1k_log h2_m1 h3_m1 udp_1024; do
      ready "$c" "$t" || die "$c does not answer the $t test at $(url_for "$c" "$t")"
    done
  done
  if (( large )); then
    [[ -x $W/bin/bigtool ]] || die "run 'bench.sh setup' again: the large-object tool is not built"
    command -v ss >/dev/null || die "ss (iproute2) is needed for the slow-download test"
    docker exec $C_ORIGIN sh -c 'head -c 1048576 /dev/urandom > /big/1m.bin && head -c 16777216 /dev/urandom > /big/16m.bin && head -c 1073741824 /dev/urandom > /big/1g.bin' \
      || die "the origin's large files could not be written"
    for c in origin "${LARGE_DL[@]}"; do
      [[ $(docker exec $C_LOAD curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$(dl_port "$c")/big/1m.bin") == 200 ]] || die "$c does not serve the large downloads"
    done
    for c in sink "${LARGE_UL[@]}"; do
      [[ $(docker exec $C_LOAD sh -c "head -c 100000 /dev/zero | curl -s --max-time 5 -o /dev/null -w '%{http_code}' --data-binary @- http://127.0.0.1:$(ul_port "$c")/up") == 200 ]] || die "$c does not take the large uploads"
    done
  fi
  say "$(date -u +%T) every listener answers"

  {
    echo "date: $(date -u +%FT%TZ)"
    echo "kernel: $(uname -r)"
    lscpu | grep -E 'Model name|^CPU\(s\)|Hypervisor vendor' | sed -E 's/: +/: /'
    echo "memory: $(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
    echo "docker: $(docker version --format '{{.Server.Version}}')"
    echo "settings: ROUNDS=$ROUNDS FIELD_ROUNDS=$FIELD_ROUNDS DUR=${DUR}s WARM=${WARM}s BURNIN=${BURNIN}s CONNS=$CONNS THREADS=$THREADS WORKERS=$WORKERS LARGE_ROUNDS=$LARGE_ROUNDS LARGE_DUR=${LARGE_DUR}s SLOW=$SLOW"
    echo "cpus: origin $ORIGIN_CPUS, proxy $PROXY_CPUS, load $LOAD_CPUS"
    for c in $ALL_CTS; do
      echo "container $c: $(docker inspect -f '{{.Config.Image}} cpuset={{.HostConfig.CpusetCpus}}' "$c") $(docker image inspect -f '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "$(docker inspect -f '{{.Config.Image}}' "$c")" 2>/dev/null)"
    done
    echo "version nvelox: $(docker exec "${CT[nvelox]}" /usr/local/bin/nvelox -version 2>&1 | head -n 1)"
    echo "version nvelox-prev: $(docker exec "${CT[nvelox-prev]}" /usr/local/bin/nvelox -version 2>&1 | head -n 1)"
    echo "version nginx: $(docker exec "${CT[nginx]}" nginx -v 2>&1)"
    echo "version haproxy: $(docker exec "${CT[haproxy]}" haproxy -v 2>&1 | head -n 1)"
    echo "version envoy: $(docker exec "${CT[envoy]}" envoy --version 2>&1 | grep -o 'version: [^ ]*' | head -n 1)"
    echo "version traefik: $(docker exec "${CT[traefik]}" traefik version 2>&1 | grep -i '^version' | tr -s ' ')"
    echo "version caddy: $(docker exec "${CT[caddy]}" caddy version 2>&1 | head -n 1)"
    echo "version wrk: $(docker exec $C_LOAD wrk --version 2>&1 | head -n 1)"
    echo "version h2load: $(docker exec $C_LOAD h2load --version 2>&1 | head -n 1)"
    echo "sha256:"
    (cd "$W" && sha256sum bin/nvelox-under-test "bin/nvelox-$PREV_VERSION" bin/udptool bin/bigtool)
    (cd "$K" && sha256sum bench.sh measure.py conf/* loadgen/* udptool/* bigtool/*)
    for c in net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.netdev_max_backlog; do echo "sysctl $c = $(sysctl -n $c)"; done
  } > "$RUN/env.txt" 2>&1

  # What every proxy costs while it does nothing: they all stay up for the whole run.
  sleep 5
  python3 -I "$K/measure.py" idle 10 $PROXY_CTS > "$RUN/idle.jsonl"

  one() { # round candidate test
    local rep=$1 c=$2 t=$3 url ct=- origin=$C_ORIGIN port
    url=$(url_for "$c" "$t") || return 0
    port=${url##*:}; port=${port%%/*}
    [[ $c == origin ]] || ct=$(ct_for "$c" "$t")
    local lab=(--label "round=$rep" --label "proxy=$c" --label "test=$t" --log "$LOG")
    case $t in
      http_*|https_*|tcp_*)
        docker exec $C_LOAD wrk -t"$THREADS" -c"$CONNS" -d"${WARM}s" -s /kit/loadgen/report.lua "$url" >/dev/null 2>&1
        python3 -I "$K/measure.py" --tool wrk --warm 0 --dur "$DUR" --proxy "$ct" --origin "$origin" --lg $C_LOAD "${lab[@]}" -- \
          docker exec $C_LOAD wrk -t"$THREADS" -c"$CONNS" -d"${DUR}s" --latency -s /kit/loadgen/report.lua "$url" >> "$OUT" ;;
      h2_*|h3_*)
        python3 -I "$K/measure.py" --tool h2load --warm "$WARM" --dur "$DUR" --proxy "$ct" --origin "$origin" --lg $C_LOAD "${lab[@]}" -- \
          docker exec $C_LOAD timeout $((WARM + DUR + 30)) h2load -t"$THREADS" -c"$CONNS" -m"${t##*_m}" -D"$DUR" --warm-up-time="$WARM" \
          --tls13-ciphers=TLS_AES_128_GCM_SHA256 --groups=X25519 --alpn-list="${t%%_*}" "$url" >> "$OUT" ;;
      udp_*)
        origin=$C_UDP_ORIGIN
        [[ $c == origin ]] && port=27500
        python3 -I "$K/measure.py" --tool udp --warm "$WARM" --dur "$DUR" --proxy "$ct" --origin "$origin" --lg $C_LOAD "${lab[@]}" -- \
          docker exec $C_LOAD /kit/bin/udptool load -target "127.0.0.1:$port" -flows "$CONNS" -size "${t#udp_}" -warm "${WARM}s" -dur "${DUR}s" -timeout 100ms >> "$OUT" ;;
    esac
    say "$(tail -n 1 "$OUT" | python3 -I "$K/measure.py" line)"
  }

  # A machine that has been idle is faster for its first minutes under load: bring it to its
  # working speed before anything is measured.
  if (( BURNIN > 0 )); then
    say "$(date -u +%T) ${BURNIN}s of load that is not measured"
    for c in "${HEAD[@]}"; do
      docker exec $C_LOAD wrk -t"$THREADS" -c"$CONNS" -d"$((BURNIN / ${#HEAD[@]}))s" "$(url_for "$c" http_1k)" >/dev/null 2>&1
    done
  fi

  say "$(date -u +%T) start: $ROUNDS rounds (${HEAD[*]}), the first $FIELD_ROUNDS also with ${FIELD[*]}; ${DUR}s measured, ${WARM}s warm-up"
  local units n off i
  for rep in $(seq 1 "$ROUNDS"); do
    one "$rep" origin http_1k
    for si in "${!TESTS[@]}"; do
      t=${TESTS[$si]}
      [[ $t == udp_1024 ]] && one "$rep" origin udp_1024
      # nvelox and nginx are one unit: always measured back to back, and who goes first alternates.
      # The unit and the other proxies take turns; who goes first changes with the round and the test.
      if (( (rep + si) % 2 )); then units=("${HEAD[1]} ${HEAD[0]}"); else units=("${HEAD[0]} ${HEAD[1]}"); fi
      if (( rep <= FIELD_ROUNDS )); then
        for c in "${FIELD[@]}"; do port_for "$c" "$t" >/dev/null && units+=("$c"); done
      fi
      n=${#units[@]}; off=$(( (rep + si) % n ))
      for i in $(seq 0 $((n - 1))); do
        for c in ${units[$(( (i + off) % n ))]}; do one "$rep" "$c" "$t"; done
      done
    done
  done
  # Large objects: every proxy in every round, the origin (or the sink) alone first, the order rotating.
  big() { # round direction candidate case...
    local rep=$1 dir=$2 c=$3 lab=$4 size=$5 conns=$6 ct=- target=$C_ORIGIN mode=get url extra=()
    if [[ $dir == down ]]; then
      url="http://127.0.0.1:$(dl_port "$c")/big/$lab.bin"
    else
      url="http://127.0.0.1:$(ul_port "$c")/up"; target=$C_SINK; mode=put; extra=(--sink-stats http://127.0.0.1:27600/stats)
    fi
    [[ $c == origin || $c == sink ]] || ct=$(large_ct "$c")
    python3 -I "$K/measure.py" --tool big --warm "$WARM" --dur "$LARGE_DUR" --proxy "$ct" --origin "$target" --lg $C_LOAD "${extra[@]}" \
      --label "round=$rep" --label "dir=$dir" --label "proxy=$c" --label "size=$lab" --label "conns=$conns" --log "$LOG" -- \
      docker exec $C_LOAD /kit/bin/bigtool $mode -url "$url" -c "$conns" -size "$size" -warm "${WARM}s" -dur "${LARGE_DUR}s" >> "$BIGOUT"
    say "$(tail -n 1 "$BIGOUT" | python3 -I "$K/measure.py" line)"
  }
  if (( LARGE_ROUNDS > 0 )); then
    # Fresh proxies: what they hold in these tests is then what large objects need, not what the
    # earlier tests left behind.
    docker restart -t 5 $PROXY_CTS >/dev/null
    for c in "${LARGE_DL[@]}"; do
      for i in $(seq 1 50); do
        [[ $(docker exec $C_LOAD curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$(dl_port "$c")/big/1m.bin") == 200 ]] && break
        sleep 0.2
      done
    done
    say "$(date -u +%T) large objects: $LARGE_ROUNDS rounds, ${LARGE_DUR}s measured, ${WARM}s warm-up, the proxies freshly started"
    local k
    for rep in $(seq 1 "$LARGE_ROUNDS"); do
      for k in "${DL_CASES[@]}"; do
        big "$rep" down origin $k
        n=${#LARGE_DL[@]}
        for i in $(seq 0 $((n - 1))); do big "$rep" down "${LARGE_DL[$(( (i + rep) % n ))]}" $k; done
      done
      for k in "${UL_CASES[@]}"; do
        big "$rep" up sink $k
        n=${#LARGE_UL[@]}
        for i in $(seq 0 $((n - 1))); do big "$rep" up "${LARGE_UL[$(( (i + rep) % n ))]}" $k; done
      done
    done
  fi

  # A slow client: one 1 GiB download read at 20 MiB/s through a freshly started proxy, the other
  # proxies stopped (so that the origin's sockets are those of the proxy under test).
  if (( SLOW )); then
    say "$(date -u +%T) slow download: 1 GiB at 20 MiB/s through every proxy, about a minute each"
    docker stop -t 5 $PROXY_CTS >/dev/null
    local port temp ct
    for c in "${LARGE_DL[@]}"; do
      ct=$(large_ct "$c"); port=$(dl_port "$c"); temp=()
      [[ $ct == "${CT[nginx]}" ]] && temp=(--temp /var/cache/nginx)
      docker start "$ct" >/dev/null
      for i in $(seq 1 50); do
        [[ $(docker exec $C_LOAD curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/big/1m.bin") == 200 ]] && break
        sleep 0.2
      done
      sleep 1
      python3 -I "$K/measure.py" slow --proxy "$ct" --origin-port 27000 --port "$port" "${temp[@]}" --label "proxy=$c" -- \
        docker exec $C_LOAD curl -s -o /dev/null --limit-rate 20M -w '%{size_download} %{time_total}' "http://127.0.0.1:$port/big/1g.bin" >> "$SLOWOUT"
      say "$(date -u +%T) slow download through $c: $(tail -n 1 "$SLOWOUT")"
      docker stop -t 5 "$ct" >/dev/null
    done
  fi
  docker stop -t 5 $ALL_CTS >/dev/null
  say "$(date -u +%T) done: bench.sh report $RUN"
}

case ${1:-} in
  setup) setup ;;
  run) run ;;
  report) shift; exec python3 -I "$K/report.py" "$@" ;;
  down) docker rm -f -v $ALL_CTS >/dev/null 2>&1; echo "containers removed" ;;
  *) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
