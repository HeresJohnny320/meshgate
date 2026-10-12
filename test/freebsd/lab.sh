#!/bin/sh
# FreeBSD / pfSense-style end-to-end lab using vnet jails, real if_wg and pf.
# Run as root on FreeBSD 14+:  sh lab.sh /path/to/meshgate
#
#   friend 198.18.1.5     laptop 198.18.2.50 (client)
#            \               /
#  vps 203.0.113.10 --- [ inet ] --- home 198.51.100.20  ("pfSense": WAN + LAN + VLAN 20,
#   (relay, edge)                       |         |        LAN policy restricted)
#                               nas 192.168.1.20  iot 192.168.20.5 (VLAN 20)
set -u
BIN=$(realpath "$1")
HERE=$(cd "$(dirname "$0")" && pwd)
D=/root/mglab
API="python3 $HERE/api.py"
FAILED=0

cleanup() {
  for j in vps home lap fr nas iot inet; do jail -r $j 2>/dev/null; done
  for i in $(ifconfig -l); do case $i in epair*) ifconfig $i destroy 2>/dev/null;; esac; done
  rm -f /etc/platform
}
cleanup; rm -rf $D; mkdir -p $D
[ -z "${KEEP:-}" ] && trap cleanup EXIT
kldload -n if_wg pf

for j in inet vps home lap fr nas iot; do
  jail -c name=$j path=/ vnet persist host.hostname=$j allow.raw_sockets >/dev/null
  jexec $j ifconfig lo0 up
done
x() { j=$1; shift; jexec $j "$@"; }
# link j1 if1 addr1 j2 if2 addr2
link() {
  e=$(ifconfig epair create); b=${e%a}b
  ifconfig $e vnet $1; ifconfig $b vnet $4
  x $1 ifconfig $e name $2 >/dev/null; x $4 ifconfig $b name $5 >/dev/null
  [ -n "$3" ] && x $1 ifconfig $2 inet $3; x $1 ifconfig $2 up
  [ -n "$6" ] && x $4 ifconfig $5 inet $6; x $4 ifconfig $5 up
}
link inet i-vps 203.0.113.1/24  vps  wan  203.0.113.10/24
link inet i-home 198.51.100.1/24 home wan 198.51.100.20/24
link inet i-fr  198.18.1.1/24   fr   wan  198.18.1.5/24
link inet i-lap 198.18.2.1/24   lap  wan  198.18.2.50/24
link home lan 192.168.1.1/24    nas  eth0 192.168.1.20/24
link home trunk ""              iot  trunk ""
# VLAN 20 on both ends of the trunk (like igb1.20 on pfSense)
x home ifconfig trunk.20 create vlan 20 vlandev trunk inet 192.168.20.1/24 up
x iot  ifconfig trunk.20 create vlan 20 vlandev trunk inet 192.168.20.5/24 up
x inet sysctl -q net.inet.ip.forwarding=1 >/dev/null
x home sysctl -q net.inet.ip.forwarding=1 >/dev/null
x vps  route -q add default 203.0.113.1
x home route -q add default 198.51.100.1
x fr   route -q add default 198.18.1.1
x lap  route -q add default 198.18.2.1
x nas  route -q add default 192.168.1.1
x iot  route -q add default 192.168.20.1

# pf exactly as pfSense lays out its anchors (CE 2.7.2 / Plus filter.inc):
# nat-anchor natrules/*, rdr-anchor tftp-proxy/*, anchor userrules/*;
# default block in, LAN allowed. /etc/platform makes meshgate detect pfSense.
[ -n "${PFSENSE:-1}" ] && echo pfSense > /etc/platform
for j in vps home; do
  cat > $D/pf-$j.conf <<PF
set skip on lo0
nat-anchor "natearly/*"
nat-anchor "natrules/*"
rdr-anchor "tftp-proxy/*"
block in all
pass out all keep state
anchor "userrules/*"
PF
  [ $j = home ] && printf 'pass in on lan all keep state\npass in on trunk.20 all keep state\n' >> $D/pf-$j.conf
  x $j pfctl -q -f $D/pf-$j.conf && x $j pfctl -q -e
done

mg() { j=$1; shift; x $j "$BIN" -config $D/$j/node.json "$@"; }
api() { x $1 $API $D/$1/meshgate.sock $2 ${3:+"$3"}; }
start() {
  x $1 daemon -o $D/$1.log "$BIN" -config $D/$1/node.json agent
  i=0; while ! api $1 view >/dev/null 2>&1; do
    i=$((i+1)); [ $i -gt 50 ] && { echo "agent $1 did not start"; cat $D/$1.log; exit 1; }; sleep 0.2
  done
}
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; FAILED=1; fi; }
jq() { python3 -c "import json,sys; v=json.load(sys.stdin); print($1)"; }

echo "== vps: web UI + first node (FreeBSD, pf edge)"
mg vps init --role controller -y --name vps --relay --admin-pass labpassword --data-dir $D/vps >/dev/null || exit 1
start vps
TOK=$(mg vps token --kind server | grep '^mg1\.')
# pfSense's own WireGuard package often already holds UDP 51820.
x home daemon -f python3 -c "import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',51820)); time.sleep(1e6)"
sleep 1
echo "== home: pfSense-style router, shares LAN + VLAN 20, restricted"
mg home join "$TOK" -y --kind server --name home --data-dir $D/home \
  --route 192.168.1.0/24 --route 192.168.20.0/24 --lan-policy restricted | grep Joined
start home
CTOK=$(mg vps token --kind client | grep '^mg1\.')
echo "== laptop: client"
mg lap join "$CTOK" -y --kind client --name laptop --data-dir $D/lap | grep Joined
start lap

x nas daemon -f python3 $HERE/web.py 8080
x nas daemon -f python3 $HERE/web.py 9000
x iot daemon -f python3 $HERE/web.py 80
x home daemon -f python3 $HERE/gameserver.py 25565
for t in "nas 8080" "nas 9000" "iot 80" "home 25565"; do
  set -- $t; i=0
  until x $1 sockstat -4l -p $2 | grep -q python; do i=$((i+1)); [ $i -gt 50 ] && { echo "$1:$2 not listening"; exit 1; }; sleep 0.2; done
done

V=$(api vps view)
VPS_ID=$(echo "$V" | jq 'v["self_id"]')
HOME_ID=$(echo "$V" | jq '[n["value"]["id"] for n in v["nodes"] if n["value"]["name"]=="home"][0]')
LAP_ID=$(echo "$V" | jq '[n["value"]["id"] for n in v["nodes"] if n["value"]["name"]=="laptop"][0]')
HOME_IP=$(echo "$V" | jq '[n["value"]["mesh_ip"] for n in v["nodes"] if n["value"]["name"]=="home"][0]')
api vps forward "{\"scope\":\"cluster\",\"forward\":{\"name\":\"minecraft\",\"proto\":\"tcp\",\"edge_node\":\"$VPS_ID\",\"listen_port\":25565,\"target_node\":\"$HOME_ID\",\"target_port\":25565,\"preserve_client_ip\":true,\"enabled\":true}}" >/dev/null
api vps forward "{\"scope\":\"cluster\",\"forward\":{\"name\":\"nas-web\",\"proto\":\"tcp\",\"edge_node\":\"$VPS_ID\",\"listen_port\":8081,\"target_node\":\"$HOME_ID\",\"target_ip\":\"192.168.1.20\",\"target_port\":8080,\"enabled\":true}}" >/dev/null
api vps acl "{\"scope\":\"cluster\",\"acl\":{\"name\":\"laptop to nas web\",\"node\":\"$HOME_ID\",\"from\":[\"$LAP_ID\"],\"to\":\"192.168.1.20\",\"proto\":\"tcp\",\"ports\":\"8080\",\"enabled\":true}}" >/dev/null
sleep 15

echo; echo "== status (laptop)"; mg lap status
check "home moved off busy UDP 51820 to 51830" "api vps view | grep -q '\"listen_port\":51830'"
check "pf opens the moved WireGuard port on the WAN" "x home pfctl -a userrules/meshgate -sr | grep -q 'port = 51830'"
echo; echo "== pf anchors on home"; x home pfctl -a userrules/meshgate -sr; x home pfctl -a natrules/meshgate -sn
echo; echo "== pf anchors on vps (nat, rdr)"; x vps pfctl -a natrules/meshgate -sn; x vps pfctl -a tftp-proxy/meshgate -sn
echo
check "laptop has handshake with vps" "mg lap status | grep '^vps' | grep -q ' ago'"
check "home's VLAN is published for the UIs" "api vps view | grep -q trunk.20"
check "laptop reaches NAS 8080 (allowed by rule)" "x lap fetch -q -T 3 -o /dev/null http://192.168.1.20:8080/"
check "laptop blocked on NAS 9000" "! x lap fetch -q -T 3 -o /dev/null http://192.168.1.20:9000/"
check "laptop blocked from VLAN 20 device" "! x lap fetch -q -T 3 -o /dev/null http://192.168.20.5/"
check "laptop cannot ping home itself" "! x lap ping -c1 -t2 $HOME_IP"
OUT=$(x fr sh -c 'echo | nc -w 3 203.0.113.10 25565' 2>/dev/null)
echo "friend sees: $OUT"
check "game forward through pf rdr keeps friend's real IP (reply-to)" "echo '$OUT' | grep -q 'you are 198.18.1.5'"
check "forward to NAS behind restricted pfSense works" "x fr fetch -q -T 3 -o /dev/null http://203.0.113.10:8081/"

NASFWD=$(api vps view | jq '[f["value"]["id"] for f in v["forwards"] if f["value"]["name"]=="nas-web"][0]')
api vps toggle "{\"kind\":\"forward\",\"id\":\"$NASFWD\",\"enabled\":false}" >/dev/null
sleep 3
check "disabled forward is blocked by pf" "! x fr fetch -q -T 3 -o /dev/null http://203.0.113.10:8081/"
check "pf anchor has the block rule" "x vps pfctl -a userrules/meshgate -sr | grep -q 'block drop in quick on wan.*8081'"
api vps toggle "{\"kind\":\"forward\",\"id\":\"$NASFWD\",\"enabled\":true}" >/dev/null
sleep 3
check "re-enabled forward works again" "x fr fetch -q -T 3 -o /dev/null http://203.0.113.10:8081/"

api vps acl "{\"scope\":\"cluster\",\"acl\":{\"name\":\"laptop to iot vlan web\",\"node\":\"$HOME_ID\",\"from\":[\"$LAP_ID\"],\"to\":\"192.168.20.0/24\",\"proto\":\"tcp\",\"ports\":\"80\",\"enabled\":true}}" >/dev/null
sleep 6
check "VLAN rule opens VLAN 20 web for the laptop" "x lap fetch -q -T 3 -o /dev/null http://192.168.20.5/"
check "rule edited on vps reached home's pf anchor" "x home pfctl -a userrules/meshgate -sr | grep -q 192.168.20.0/24"

echo; echo "== TUI change on home (local only) does not replicate"
api home acl "{\"scope\":\"local\",\"acl\":{\"name\":\"local-test\",\"node\":\"$HOME_ID\",\"to\":\"self\",\"proto\":\"icmp\",\"enabled\":true}}" >/dev/null
sleep 5
check "local rule applied on home" "x lap ping -c2 -t3 $HOME_IP"
check "local rule not on vps" "! api vps view | grep -q local-test"

echo; echo "== web UI down: home keeps forwarding and accepts edits"
pkill -f "$D/vps/node.json agent"; sleep 2
check "home accepts a rule while vps is down" "api home acl '{\"scope\":\"cluster\",\"acl\":{\"name\":\"while-down\",\"node\":\"$HOME_ID\",\"to\":\"192.168.1.20\",\"proto\":\"tcp\",\"ports\":\"9000\",\"enabled\":true}}'"
start vps; sleep 10
check "vps catches up after restart" "api vps view | grep -q while-down"

if [ $FAILED = 1 ]; then
  for j in vps home lap; do echo "--- $j log"; tail -15 $D/$j.log; done
  exit 1
fi
echo; echo "ALL PASSED"
