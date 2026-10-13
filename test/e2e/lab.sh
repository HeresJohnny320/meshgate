#!/bin/sh
# End-to-end lab: runs real meshgate agents in network namespaces.
# Usage: unshare -r -n -m sh test/e2e/lab.sh /path/to/meshgate /path/to/phonesim
#
#            friend 198.18.1.5          laptop LTE 198.18.2.50
#                  \                      /
#   vps 203.0.113.10 ---- [ internet ] ----
#                              |
#                  home router 198.51.100.20 (NAT)
#                              |  LAN 192.168.1.0/24
#                home server 192.168.1.10   laptop Wi-Fi 192.168.1.50
set -eu
BIN=$1
PHONESIM=$2
HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d)
mount -t tmpfs none /run
mkdir -p /run/netns
for n in inet vps vps2 hr home lap fr phone nas; do ip netns add $n; ip -n $n link set lo up; done
x() { ns=$1; shift; ip netns exec "$ns" "$@"; }
link() { # ns1 if1 addr1 ns2 if2 addr2
  ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
  [ -n "$3" ] && x "$1" ip addr add "$3" dev "$2"; x "$1" ip link set "$2" up
  [ -n "$6" ] && x "$4" ip addr add "$6" dev "$5"; x "$4" ip link set "$5" up
}
link inet i-vps 203.0.113.1/24  vps eth0 203.0.113.10/24
link inet i-hr  198.51.100.1/24 hr  wan  198.51.100.20/24
link inet i-fr  198.18.1.1/24   fr  eth0 198.18.1.5/24
link inet i-lte 198.18.2.1/24   lap lte  198.18.2.50/24
link inet i-vps2 203.0.114.1/24 vps2 eth0 203.0.114.10/24
link inet i-ph  198.18.3.1/24   phone lte 198.18.3.60/24
x hr ip link add br0 type bridge; x hr ip addr add 192.168.1.1/24 dev br0; x hr ip link set br0 up
link hr hr-home "" home eth0 192.168.1.10/24
link hr hr-lap  "" lap  wifi 192.168.1.50/24
link hr hr-ph   "" phone wifi 192.168.1.60/24
link hr hr-nas  "" nas eth0 192.168.1.20/24
x hr ip link set hr-home master br0; x hr ip link set hr-lap master br0; x hr ip link set hr-ph master br0; x hr ip link set hr-nas master br0
for n in inet hr; do x $n sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; done
x hr nft add table ip nat
x hr nft add chain ip nat post '{ type nat hook postrouting priority srcnat; }'
x hr nft add rule ip nat post oifname wan masquerade
x vps  ip route add default via 203.0.113.1
x hr   ip route add default via 198.51.100.1
x fr   ip route add default via 198.18.1.1
x home ip route add default via 192.168.1.1
x nas  ip route add default via 192.168.1.1
x lap  ip route add default via 198.18.2.1   # laptop starts on LTE
x lap  ip link set wifi down
x vps2 ip route add default via 203.0.114.1
x phone ip route add default via 198.18.3.1 # phone starts on LTE
x phone ip link set wifi down

mg() { ns=$1; shift; x "$ns" "$BIN" -config "$D/$ns/node.json" "$@"; }
api() { x "$1" curl -sf --unix-socket "$D/$1/meshgate.sock" -H 'Content-Type: application/json' "http://x/v1/$2" ${3:+-d "$3"}; }
start() {
  ip netns exec "$1" "$BIN" -config "$D/$1/node.json" agent > "$D/$1.log" 2>&1 & echo $! > "$D/$1.pid"
  i=0; while ! api "$1" view >/dev/null 2>&1; do
    i=$((i+1)); if [ $i -gt 50 ]; then echo "agent $1 did not start:"; cat "$D/$1.log"; exit 1; fi; sleep 0.2
  done
}
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; FAILED=1; fi; }
FAILED=0
cleanup() { for p in "$D"/*.pid; do kill "$(cat "$p")" 2>/dev/null || true; done; sleep 1; }
trap cleanup EXIT

busy_udp() { # ns port: hold a UDP port like an existing WireGuard would
  ip netns exec "$1" python3 -c "import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',$2)); time.sleep(1e6)" &
  echo $! > "$D/busy-$1-$2.pid"
}
echo "== vps: init controller (something already uses TCP 8080)"
ip netns exec vps python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 & echo $! > "$D/busy-vps-8080.pid"
sleep 1
mg vps init --role controller -y --name vps --admin-pass labpassword --data-dir "$D/vps" > "$D/vps-init.out"
grep -q "TCP 8080 is already in use; the web UI will use 8081" "$D/vps-init.out" && echo "PASS  web UI moved off busy 8080 during setup" || { echo "FAIL  web UI port switch"; FAILED=1; }
start vps
TOK=$(mg vps token --kind server --uses 1 | grep '^mg1\.' )
echo "== home: join as server (UDP 51820 already taken, like an existing WireGuard)"
busy_udp home 51820
ip netns exec home python3 -m http.server 51823 --bind 0.0.0.0 >/dev/null 2>&1 & echo $! > "$D/busy-home-51823.pid"
sleep 1
mg home join "$TOK" -y --kind server --name home --data-dir "$D/home" | grep Joined
start home
CTOK=$(mg vps token --kind client | grep '^mg1\.')
echo "== laptop: join as client (on LTE)"
busy_udp lap 51840
sleep 1
if mg lap join "$CTOK" -y --kind client --name laptop --port 51840 --data-dir "$D/lap" > "$D/lap-busy.out" 2>&1; then
  echo "FAIL  explicit busy --port was accepted"; FAILED=1
else
  grep -q "already in use" "$D/lap-busy.out" && echo "PASS  explicit busy --port is refused, not silently moved" || { echo "FAIL  wrong error: $(cat "$D/lap-busy.out")"; FAILED=1; }
fi
mg lap join "$CTOK" -y --kind client --name laptop --data-dir "$D/lap" | grep Joined
start lap

ip netns exec home python3 "$HERE/gameserver.py" 25565 > /dev/null 2>&1 & echo $! > "$D/game.pid"
HOME_ID=$(api vps view | python3 -c 'import json,sys; v=json.load(sys.stdin); print([n["value"]["id"] for n in v["nodes"] if n["value"]["name"]=="home"][0])')
VPS_ID=$(api vps view | python3 -c 'import json,sys; print(json.load(sys.stdin)["self_id"])')
api vps forward "{\"scope\":\"cluster\",\"forward\":{\"name\":\"minecraft\",\"proto\":\"tcp\",\"edge_node\":\"$VPS_ID\",\"listen_port\":25565,\"target_node\":\"$HOME_ID\",\"target_port\":25565,\"preserve_client_ip\":true,\"enabled\":true}}" >/dev/null
api vps forward "{\"scope\":\"cluster\",\"forward\":{\"name\":\"masq\",\"proto\":\"tcp\",\"edge_node\":\"$VPS_ID\",\"listen_port\":25566,\"target_node\":\"$HOME_ID\",\"target_port\":25565,\"enabled\":true}}" >/dev/null
sleep 12

check "home moved WireGuard to 51830 and published it" "api vps view | grep -q '\"listen_port\":51830'"
check "home endpoint uses the new port" "api vps view | grep -q '192.168.1.10:51830'"
check "web UI answers on 8081" "x vps curl -sf -m3 http://127.0.0.1:8081/ | grep -q meshgate"
check "home moved its sync port off busy 51823 and published it" "api vps view | grep -q '\"mesh_port\":51824'"
check "ports command reports the moved ports" "mg home ports | grep -q 'udp 51830' && mg home ports | grep -q 'udp 51832'"
HOME_IP=$(api home view | python3 -c 'import json,sys; v=json.load(sys.stdin); print([n["value"]["mesh_ip"] for n in v["nodes"] if n["value"]["name"]=="home"][0])')
echo; echo "== laptop status (LTE)"; mg lap status
check "laptop reaches home mesh IP over LTE" "x lap ping -c2 -W2 $HOME_IP >/dev/null"
check "laptop reaches home LAN subnet over LTE" "x lap ping -c2 -W2 192.168.1.10 >/dev/null"
check "laptop path to home goes via vps" "mg lap status | grep '^home' | grep -q 'via vps'"
OUT=$(x fr sh -c 'echo | nc -w3 203.0.113.10 25565' || true)
echo "friend sees: $OUT"
check "friend reaches game via VPS with real IP preserved" "echo '$OUT' | grep -q 'you are 198.18.1.5'"
OUT2=$(x fr sh -c 'echo | nc -w3 203.0.113.10 25566' || true)
echo "friend sees (masq): $OUT2"
VPS_MESH=$(api vps view | python3 -c 'import json,sys; v=json.load(sys.stdin); print([n["value"]["mesh_ip"] for n in v["nodes"] if n["value"]["id"]==v["self_id"]][0])')
check "masqueraded forward shows vps mesh IP" "echo '$OUT2' | grep -q 'you are $VPS_MESH'"

echo; echo "== local-only change on home (not replicated)"
api home forward "{\"scope\":\"local\",\"forward\":{\"name\":\"local-only\",\"proto\":\"udp\",\"edge_node\":\"$VPS_ID\",\"listen_port\":3000,\"target_node\":\"$HOME_ID\",\"target_port\":3000,\"enabled\":true}}" >/dev/null
api home forward "{\"scope\":\"cluster\",\"forward\":{\"name\":\"from-home\",\"proto\":\"udp\",\"edge_node\":\"$VPS_ID\",\"listen_port\":3001,\"target_node\":\"$HOME_ID\",\"target_port\":3001,\"enabled\":true}}" >/dev/null
sleep 3
check "cluster change made on home replicates to vps" "api vps view | grep -q from-home"
check "local change stays on home" "! api vps view | grep -q local-only"

echo; echo "== web UI node down: home still applies changes from its TUI"
kill "$(cat "$D/vps.pid")"; while kill -0 "$(cat "$D/vps.pid")" 2>/dev/null; do sleep 0.2; done
api home forward "{\"scope\":\"cluster\",\"forward\":{\"name\":\"while-down\",\"proto\":\"tcp\",\"edge_node\":\"$VPS_ID\",\"listen_port\":4000,\"target_node\":\"$HOME_ID\",\"target_port\":4000,\"enabled\":true}}" >/dev/null
check "home accepts edits while vps is down" "api home view | grep -q while-down"
start vps; sleep 8
check "vps catches up after restart" "api vps view | grep -q while-down"
OUT3=$(x fr sh -c 'echo | nc -w3 203.0.113.10 25565' || true)
check "game forward works again after vps restart" "echo '$OUT3' | grep -q 'you are 198.18.1.5'"

echo; echo "== laptop moves to home Wi-Fi"
x lap ip link set wifi up
x lap ip route replace default via 192.168.1.1 dev wifi
x lap ip link set lte down
sleep 15
mg lap status
check "laptop goes direct to home on LAN" "mg lap status | grep '^home' | grep -q direct"
check "laptop reaches home mesh IP on LAN" "x lap ping -c2 -W2 $HOME_IP >/dev/null"

echo; echo "== laptop back on LTE"
x lap ip link set lte up
x lap ip route replace default via 198.18.2.1 dev lte
x lap ip link set wifi down
sleep 20
mg lap status
check "laptop falls back to relay" "mg lap status | grep '^home' | grep -q 'via vps'"
check "laptop reaches home again via relay" "x lap ping -c3 -W2 $HOME_IP >/dev/null"

echo; echo "== second VPS joins as another relay"
TOK2=$(mg vps token --kind server | grep '^mg1\.')
mg vps2 join "$TOK2" -y --kind server --name vps2 --data-dir "$D/vps2" | grep Joined
start vps2

echo "== phone (mobile engine) joins over LTE"
PTOK=$(mg vps token --kind client | grep '^mg1\.')
ip netns exec phone "$PHONESIM" -dir "$D/phone" -join "$PTOK" -name phone -status "$D/phone.json" > "$D/phone.log" 2>&1 &
echo $! > "$D/phone.pid"
sleep 15
pj() { python3 -c "import json,sys; s=json.load(open('$D/phone.json')); $1" 2>/dev/null || true; }
if [ ! -s "$D/phone.json" ]; then echo "phone did not start:"; cat "$D/phone.log"; echo "PTOK=$PTOK"; api vps view | python3 -c 'import json,sys; print(json.load(sys.stdin)["tokens"])'; tail -5 "$D/vps.log"; exit 1; fi
peerpath() { pj "print([p['path'] for p in s['peers'] if p['name']=='$1'][0])"; }
echo "phone: relay=$(pj "print(s['home_relay'])")  home path=$(peerpath home)"
check "phone joined and tunnel running" "pj 'assert s[\"running\"] and s[\"mesh_ip\"]'"
check "phone reaches home over LTE via a relay" "x phone ping -c2 -W2 $HOME_IP >/dev/null"
check "phone reaches home LAN over LTE" "x phone ping -c2 -W2 192.168.1.10 >/dev/null"
check "phone path to home is relayed" "peerpath home | grep -q '^via '"

RELAY=$(pj "print(s['home_relay'])")
if [ "$RELAY" = vps ]; then DOWN=i-vps; OTHER=vps2; else DOWN=i-vps2; OTHER=vps; fi
echo; echo "== relay $RELAY goes offline"
x inet ip link set $DOWN down
sleep 25
echo "phone: relay=$(pj "print(s['home_relay'])")  home path=$(peerpath home)"
check "phone fails over to $OTHER" "test \"\$(pj \"print(s['home_relay'])\")\" = $OTHER"
check "phone reaches home through $OTHER" "x phone ping -c3 -W2 $HOME_IP >/dev/null"
x inet ip link set $DOWN up

echo; echo "== exit node: phone's internet traffic leaves through vps"
ip netns exec fr python3 "$HERE/gameserver.py" 7000 > /dev/null 2>&1 & echo $! > "$D/whoami.pid"
sleep 1
myip() { x phone sh -c 'echo | nc -w3 198.18.1.5 7000' 2>/dev/null | sed -n 's/.*you are //p'; }
check "without exit node the internet sees the phone's LTE IP" "test \"\$(myip)\" = 198.18.3.60"
PHONE_ID=$(api vps view | python3 -c 'import json,sys; v=json.load(sys.stdin); print([n["value"]["id"] for n in v["nodes"] if n["value"]["name"]=="phone"][0])')
api vps node "{\"id\":\"$VPS_ID\",\"patch\":{\"exit\":true},\"scope\":\"cluster\"}" >/dev/null
api vps node "{\"id\":\"$PHONE_ID\",\"patch\":{\"exit_via\":\"$VPS_ID\"},\"scope\":\"cluster\"}" >/dev/null
i=0; while [ "$(pj "print(s.get('exit',''))")" != vps ] && [ $i -lt 45 ]; do i=$((i+1)); sleep 1; done
echo "phone: exit=$(pj "print(s.get('exit',''))")"
check "phone uses vps as exit node" "test \"\$(pj \"print(s.get('exit',''))\")\" = vps"
check "the internet sees the vps IP" "test \"\$(myip)\" = 203.0.113.10"
check "phone DNS goes through the exit" "grep -q 'dns: \\[1.1.1.1' '$D/phone.log'"
check "phone still reaches home LAN with exit node" "x phone ping -c2 -W2 192.168.1.10 >/dev/null"

echo; echo "== phone walks into home Wi-Fi"
x phone ip link set wifi up
x phone ip route replace default via 192.168.1.1 dev wifi
x phone ip link set lte down
kill -USR1 "$(cat "$D/phone.pid")"
sleep 12
echo "phone: home path=$(peerpath home)"
if [ "${DEBUG:-}" ]; then cat "$D/phone.json"; echo; x phone ip route; x phone ip addr show wifi; tail -15 "$D/phone.log"; x phone sh -c 'echo; timeout 2 nc -u -w1 192.168.1.10 51822 </dev/null; echo nc=$?'; fi
check "phone goes direct to home on Wi-Fi" "test \"\$(peerpath home)\" = direct"
check "phone excludes home LAN from tunnel on Wi-Fi" "! x phone ip route show table 51820 | grep -q 192.168.1.0"
check "phone skips the exit node at home" "test \"\$(myip)\" = 198.51.100.20"
check "phone reaches home mesh IP on Wi-Fi" "x phone ping -c2 -W2 $HOME_IP >/dev/null"

echo; echo "== disable a forward: its port must be blocked, then enable it again"
MASQ_ID=$(api vps view | python3 -c 'import json,sys; v=json.load(sys.stdin); print([f["value"]["id"] for f in v["forwards"] if f["value"]["name"]=="masq"][0])')
api vps toggle "{\"kind\":\"forward\",\"id\":\"$MASQ_ID\",\"enabled\":false}" >/dev/null
sleep 2
OFF=$(x fr sh -c 'echo | nc -w3 203.0.113.10 25566' 2>/dev/null || true)
check "disabled forward blocks the friend" "[ -z '$OFF' ]"
check "disabled forward keeps its name" "api vps view | grep -q '\"name\":\"masq\"'"
api vps toggle "{\"kind\":\"forward\",\"id\":\"$MASQ_ID\",\"enabled\":true}" >/dev/null
sleep 2
ON=$(x fr sh -c 'echo | nc -w3 203.0.113.10 25566' 2>/dev/null || true)
check "re-enabled forward works again" "echo '$ON' | grep -q 'hello from game server'"

echo; echo "== lock down the home LAN (restricted policy + access rules)"
ip netns exec nas python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 & echo $! > "$D/nas1.pid"
ip netns exec nas python3 -m http.server 9000 --bind 0.0.0.0 >/dev/null 2>&1 & echo $! > "$D/nas2.pid"
LAP_ID=$(api vps view | python3 -c 'import json,sys; v=json.load(sys.stdin); print([n["value"]["id"] for n in v["nodes"] if n["value"]["name"]=="laptop"][0])')
sleep 1
check "before lockdown: vps2 reaches NAS port 9000" "x vps2 curl -sf -m3 http://192.168.1.20:9000/ >/dev/null"
api vps node "{\"id\":\"$HOME_ID\",\"patch\":{\"lan_policy\":\"restricted\"},\"scope\":\"cluster\"}" >/dev/null
api vps acl "{\"scope\":\"cluster\",\"acl\":{\"name\":\"laptop to nas web\",\"node\":\"$HOME_ID\",\"from\":[\"$LAP_ID\"],\"to\":\"192.168.1.20\",\"proto\":\"tcp\",\"ports\":\"8080\",\"enabled\":true}}" >/dev/null
sleep 6
check "laptop reaches NAS on allowed port 8080" "x lap curl -sf -m3 http://192.168.1.20:8080/ >/dev/null"
check "laptop blocked on NAS port 9000" "! x lap curl -sf -m3 http://192.168.1.20:9000/ >/dev/null"
check "laptop cannot ping NAS" "! x lap ping -c1 -W2 192.168.1.20 >/dev/null"
check "vps2 (not in rule) blocked from NAS 8080" "! x vps2 curl -sf -m3 http://192.168.1.20:8080/ >/dev/null"
check "laptop cannot ping home node itself" "! x lap ping -c1 -W2 $HOME_IP >/dev/null"
api vps acl "{\"scope\":\"cluster\",\"acl\":{\"name\":\"laptop ping home\",\"node\":\"$HOME_ID\",\"from\":[\"$LAP_ID\"],\"to\":\"self\",\"proto\":\"icmp\",\"enabled\":true}}" >/dev/null
sleep 5
check "icmp rule to self lets laptop ping home" "x lap ping -c2 -W2 $HOME_IP >/dev/null"
OUT4=$(x fr sh -c 'echo | nc -w3 203.0.113.10 25565' || true)
check "game forward still works while locked down" "echo '$OUT4' | grep -q 'you are 198.18.1.5'"
api vps forward "{\"scope\":\"cluster\",\"forward\":{\"name\":\"after-lockdown\",\"proto\":\"tcp\",\"edge_node\":\"$VPS_ID\",\"listen_port\":4100,\"target_node\":\"$HOME_ID\",\"target_port\":4100,\"enabled\":true}}" >/dev/null
sleep 3
check "config sync still reaches locked-down home" "api home view | grep -q after-lockdown"

if [ "$FAILED" = 1 ]; then
  echo "--- phone log"; tail -30 "$D/phone.log"
  for n in vps home lap; do echo "--- $n log"; tail -20 "$D/$n.log"; done
  exit 1
fi
echo; echo "ALL PASSED"
