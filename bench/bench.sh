#!/bin/sh
# meshgate benchmark: RAM and CPU of the agent, old build against new.
#
#   bench/bench.sh compare OLD_BINARY NEW_BINARY [SECONDS_PER_PHASE]
#       Runs the same small mesh for each binary in network namespaces
#       (needs Linux, nftables, python3; root or unprivileged user
#       namespaces) and prints a side-by-side table. Phases:
#         idle     the mesh just running (probes, sync, status)
#         traffic  a friend streams data through a port forward to home
#         ui       the dashboard / TUI asking for the view every second
#       Samples land in bench/results/<time>.csv.
#
#   bench/bench.sh watch [PROCESS_NAME|PID] [SECONDS]
#       Measures a running meshgate (default: the one named "meshgate") on
#       a real server: Linux or FreeBSD/pfSense. Read-only.
#
# RSS is the RAM the process really occupies; CPU % is of one core.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

# ---------- sampling (Linux /proc, FreeBSD ps) ----------

# sample PID -> "rss_kb cpu_seconds"
sample() {
  if [ -r "/proc/$1/stat" ]; then
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0)
    # utime + stime are fields 14 and 15 (after the "(comm)" field).
    ticks=$(sed 's/^.*) //' "/proc/$1/stat" | awk '{print $12 + $13}')
    echo "${rss:-0} $(awk -v t="$ticks" -v hz="$HZ" 'BEGIN { printf "%.3f", t / hz }')"
  else
    # FreeBSD: time is [hh:]mm:ss.hh of CPU used so far.
    ps -o rss= -o time= -p "$1" 2>/dev/null | awk '{
      n = split($2, p, ":"); s = 0
      for (i = 1; i <= n; i++) s = s * 60 + p[i]
      printf "%d %.3f\n", $1, s }'
  fi
}
HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)

# measure LABEL PID SECONDS OUTFILE: one line per second "label rss_kb cpu_pct"
measure() {
  label=$1 pid=$2 secs=$3 out=$4
  set -- $(sample "$pid")
  prev_cpu=$2
  i=0
  while [ "$i" -lt "$secs" ]; do
    sleep 1
    set -- $(sample "$pid") || break
    [ -n "${1:-}" ] || break
    awk -v l="$label" -v r="$1" -v c="$2" -v p="$prev_cpu" 'BEGIN { printf "%s %d %.2f\n", l, r, (c - p) * 100 }' >> "$out"
    prev_cpu=$2
    i=$((i + 1))
  done
}

# summary FILE: "label avgMB peakMB avgCPU peakCPU" per label
summary() {
  awk '{ n[$1]++; r[$1] += $2; c[$1] += $3
         if ($2 > rp[$1]) rp[$1] = $2; if ($3 > cp[$1]) cp[$1] = $3 }
       END { for (l in n) printf "%s %.1f %.1f %.2f %.2f\n", l, r[l]/n[l]/1024, rp[l]/1024, c[l]/n[l], cp[l] }' "$1" | sort
}

# ---------- watch: a live server ----------

watch_cmd() {
  target=${1:-meshgate} secs=${2:-60}
  case $target in
    *[!0-9]*) pid=$(pgrep -x "$target" 2>/dev/null | head -1 || true)
              [ -n "$pid" ] || pid=$(pgrep -f "$target agent" 2>/dev/null | head -1 || true) ;;
    *) pid=$target ;;
  esac
  [ -n "${pid:-}" ] || { echo "no running process '$target' (try: bench.sh watch PID)"; exit 1; }
  echo "measuring PID $pid for ${secs}s..."
  f=$(mktemp)
  measure live "$pid" "$secs" "$f"
  echo
  printf "%-10s %10s %10s %9s %9s\n" "" "RAM avg" "RAM peak" "CPU avg" "CPU peak"
  summary "$f" | while read -r l ra rp ca cp; do
    printf "%-10s %8s MB %8s MB %8s %% %8s %%\n" "$l" "$ra" "$rp" "$ca" "$cp"
  done
  rm -f "$f"
}

# ---------- compare: the same mesh for each binary ----------

compare_cmd() {
  [ $# -ge 2 ] || usage
  old=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
  new=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
  phase=${3:-30}
  for b in "$old" "$new"; do [ -x "$b" ] || { echo "not executable: $b"; exit 1; }; done
  if [ "$(id -u)" != 0 ]; then
    exec unshare -r -n -m sh "$0" compare-ns "$old" "$new" "$phase"
  fi
  compare_ns "$old" "$new" "$phase"
}

compare_ns() {
  old=$1 new=$2 phase=$3
  mkdir -p "$HERE/results"
  csv="$HERE/results/$(date +%Y%m%d-%H%M%S).csv"
  echo "impl,version,node,phase,second,rss_kb,cpu_pct" > "$csv"
  mount -t tmpfs none /run
  mkdir -p /run/netns
  for impl in old new; do
    bin=$old; [ "$impl" = new ] && bin=$new
    run_mesh "$impl" "$bin" "$phase" "$csv"
  done
  report "$csv"
}

# run_mesh IMPL BINARY PHASE_SECONDS CSV
run_mesh() {
  impl=$1 BIN=$2 phase=$3 csv=$4
  D=$(mktemp -d)
  ver=$("$BIN" version 2>/dev/null | awk '{print $NF}')
  echo "== $impl: $BIN ($ver)"
  for n in inet vps hr home fr; do ip netns add "$impl-$n"; ip -n "$impl-$n" link set lo up; done
  x() { ns=$impl-$1; shift; ip netns exec "$ns" "$@"; }
  link() {
    ip link add "$2" netns "$impl-$1" type veth peer name "$5" netns "$impl-$4"
    [ -n "$3" ] && x "$1" ip addr add "$3" dev "$2"; x "$1" ip link set "$2" up
    [ -n "$6" ] && x "$4" ip addr add "$6" dev "$5"; x "$4" ip link set "$5" up
  }
  link inet i-vps 203.0.113.1/24  vps  eth0 203.0.113.10/24
  link inet i-hr  198.51.100.1/24 hr   wan  198.51.100.20/24
  link inet i-fr  198.18.1.1/24   fr   eth0 198.18.1.5/24
  link hr   lan   192.168.1.1/24  home eth0 192.168.1.10/24
  for n in inet hr; do x $n sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; done
  x hr nft add table ip nat
  x hr nft add chain ip nat post '{ type nat hook postrouting priority srcnat; }'
  x hr nft add rule ip nat post oifname wan masquerade
  x vps  ip route add default via 203.0.113.1
  x hr   ip route add default via 198.51.100.1
  x fr   ip route add default via 198.18.1.1
  x home ip route add default via 192.168.1.1

  mg() { ns=$1; shift; x "$ns" "$BIN" -config "$D/$ns/node.json" "$@"; }
  api() { x "$1" curl -sf --unix-socket "$D/$1/meshgate.sock" -H 'Content-Type: application/json' "http://x/v1/$2" ${3:+-d "$3"}; }
  start() {
    ip netns exec "$impl-$1" "$BIN" -config "$D/$1/node.json" agent > "$D/$1.log" 2>&1 &
    echo $! > "$D/$1.pid"
    i=0; while ! api "$1" view >/dev/null 2>&1; do
      i=$((i + 1)); [ $i -le 75 ] || { echo "agent $1 did not start:"; cat "$D/$1.log"; exit 1; }; sleep 0.2
    done
  }
  mg vps init --role controller -y --name vps --admin-pass benchpassword --data-dir "$D/vps" > /dev/null
  start vps
  tok=$(mg vps token --kind server --uses 1 | grep '^mg1\.')
  mg home join "$tok" -y --kind server --name home --data-dir "$D/home" > /dev/null
  start home
  # A sink standing in for a game server, and a forward to it.
  x home python3 -c '
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 25565)); s.listen()
def drain(c):
    with c:
        while c.recv(65536): pass
while True:
    c, _ = s.accept(); threading.Thread(target=drain, args=(c,), daemon=True).start()
' > /dev/null 2>&1 & echo $! > "$D/sink.pid"
  home_id=$(api vps view | python3 -c 'import json,sys; v=json.load(sys.stdin); print([n["value"]["id"] for n in v["nodes"] if n["value"]["name"]=="home"][0])')
  vps_id=$(api vps view | python3 -c 'import json,sys; print(json.load(sys.stdin)["self_id"])')
  api vps forward "{\"scope\":\"cluster\",\"forward\":{\"name\":\"game\",\"proto\":\"tcp\",\"edge_node\":\"$vps_id\",\"listen_port\":25565,\"target_node\":\"$home_id\",\"target_port\":25565,\"enabled\":true}}" > /dev/null
  echo "   mesh up; settling 15s"
  sleep 15

  tmp=$D/samples
  phase_run() { # name: measure both agents at once
    : > "$tmp.vps"; : > "$tmp.home"
    measure "$1" "$(cat "$D/vps.pid")" "$phase" "$tmp.vps" &
    m1=$!
    measure "$1" "$(cat "$D/home.pid")" "$phase" "$tmp.home"
    wait $m1
    for node in vps home; do
      awk -v i="$impl" -v v="$ver" -v n="$node" '{ printf "%s,%s,%s,%s,%d,%d,%.2f\n", i, v, n, $1, NR, $2, $3 }' "$tmp.$node" >> "$csv"
    done
  }
  echo "   phase idle (${phase}s)"
  phase_run idle
  echo "   phase traffic (${phase}s)"
  x fr python3 -c '
import socket, time
end = time.time() + '"$phase"' + 2
s = socket.create_connection(("203.0.113.10", 25565)); chunk = b"x" * 65536
while time.time() < end: s.sendall(chunk)
' > /dev/null 2>&1 &
  load=$!
  phase_run traffic
  kill $load 2>/dev/null || true
  echo "   phase ui (${phase}s)"
  ( while :; do api vps view > /dev/null; api vps traffic > /dev/null 2>&1; api home view > /dev/null; sleep 1; done ) &
  poll=$!
  phase_run ui
  kill $poll 2>/dev/null || true

  for p in "$D"/*.pid; do kill "$(cat "$p")" 2>/dev/null || true; done
  sleep 2
  for n in inet vps hr home fr; do ip netns del "$impl-$n" 2>/dev/null || true; done
  rm -rf "$D"
}

# report CSV: side-by-side table per node and phase
report() {
  echo
  printf "%-5s %-8s | %-21s | %-21s | %s\n" "node" "phase" "RAM avg/peak (MB)" "CPU avg/peak (%)" "old -> new"
  for node in vps home; do
    for ph in idle traffic ui; do
      awk -F, -v n="$node" -v p="$ph" '
        $3 == n && $4 == p { k = $1; c[k]++; r[k] += $6; u[k] += $7
                             if ($6 > rp[k]) rp[k] = $6; if ($7 > up[k]) up[k] = $7 }
        END {
          for (k in c) { ra[k] = r[k]/c[k]/1024; ua[k] = u[k]/c[k] }
          d = (c["old"] && c["new"]) ? sprintf("RAM %+.1f MB (%+.0f%%), CPU %+.2f", ra["new"]-ra["old"], (ra["new"]/ra["old"]-1)*100, ua["new"]-ua["old"]) : ""
          for (k in c) printf "%-5s %-8s | %-4s %5.1f / %5.1f     | %-4s %5.2f / %6.2f   | %s\n", n, p, k, ra[k], rp[k]/1024, k, ua[k], up[k], (k == "new" ? d : "")
        }' "$1" | sort -t'|' -k1,1 -k2,2r
    done
  done
  echo
  echo "samples: $1"
}

case ${1:-} in
  compare) shift; compare_cmd "$@" ;;
  compare-ns) shift; compare_ns "$@" ;;
  watch) shift; watch_cmd "$@" ;;
  *) usage ;;
esac
