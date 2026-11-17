#!/bin/sh
# An existing Go node switches to the Rust build in place, the way the self-
# update does it: same node.json, same data directory, the running tunnel
# taken over. Usage:
#   unshare -r -n -m sh test/e2e/upgrade.sh path/to/meshgate-go path/to/meshgate-rust
set -eu
GO=$1
RS=$2
D=$(mktemp -d)
mount -t tmpfs none /run
ip link set lo up
ip link add eth0 type dummy && ip addr add 203.0.113.10/24 dev eth0 && ip link set eth0 up
ip route add default dev eth0
C="$D/etc/node.json"
api() { curl -sf --unix-socket "$D/data/meshgate.sock" -H 'Content-Type: application/json' "http://x/v1/$1" ${2:+-d "$2"}; }
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; FAILED=1; fi; }
FAILED=0
start() { "$1" -config "$C" agent > "$D/$2.log" 2>&1 & echo $! > "$D/pid"; i=0; while ! api view > /dev/null 2>&1; do i=$((i+1)); [ $i -gt 50 ] && { cat "$D/$2.log"; exit 1; }; sleep 0.2; done; }
stop() { kill "$(cat "$D/pid")"; while kill -0 "$(cat "$D/pid")" 2> /dev/null; do sleep 0.1; done; }

echo "== Go: set up and run"
"$GO" -config "$C" init --role controller -y --name vps --admin-pass upgradepass --data-dir "$D/data" --web-public > /dev/null
start "$GO" go
SELF=$(api view | python3 -c 'import json,sys; print(json.load(sys.stdin)["self_id"])')
api forward "{\"forward\":{\"name\":\"mc\",\"proto\":\"tcp\",\"edge_node\":\"$SELF\",\"listen_port\":25565,\"target_node\":\"$SELF\",\"target_port\":25566,\"enabled\":true},\"scope\":\"cluster\"}" > /dev/null || true
api token '{"kind":"client","uses":3,"ttl_hours":24,"note":"phone"}' > /dev/null
sleep 2
GO_VIEW=$(api view)
GO_TID=$(cat "$D/data/tunnel-id")
GO_KEY=$(wg show mg0 public-key)
GO_FP=$(echo "$GO_VIEW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["runtime"]["web_cert_fp"])')
GO_IDX=$(ip -o link show mg0 | cut -d: -f1)
stop

echo "== Rust: same config and data"
start "$RS" rust
sleep 2
RS_VIEW=$(api view)
check "same node and network" "[ \"\$(echo '$RS_VIEW' | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v[\"self_id\"], v[\"network\"][\"cidr\"])')\" = \"\$(echo '$GO_VIEW' | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v[\"self_id\"], v[\"network\"][\"cidr\"])')\" ]"
check "tokens kept" "echo '$RS_VIEW' | grep -q '\"note\":\"phone\"'"
check "WireGuard interface taken over, not recreated" "[ \"\$(ip -o link show mg0 | cut -d: -f1)\" = '$GO_IDX' ]"
check "tunnel-id kept (peers keep their sessions)" "[ \"\$(cat $D/data/tunnel-id)\" = '$GO_TID' ]"
check "same WireGuard key" "[ \"\$(wg show mg0 public-key)\" = '$GO_KEY' ]"
check "same web UI certificate" "echo '$RS_VIEW' | grep -q '\"web_cert_fp\":\"$GO_FP\"'"
check "Go's admin login works" "curl -sfk -m3 -c $D/jar -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"upgradepass\"}' https://127.0.0.1:8080/auth/login | grep -q ok"
check "web UI answers with the session" "curl -sfk -m3 -b $D/jar https://127.0.0.1:8080/api/view | grep -q '\"self_id\"'"
check "join API still has the Go certificate" "echo | openssl s_client -connect 127.0.0.1:51821 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | tr -d : | tr 'A-F' 'a-f' | grep -qi \"\$(echo '$GO_VIEW' | python3 -c 'import json,sys; v=json.load(sys.stdin); print([n[\"value\"][\"join_fp\"] for n in v[\"nodes\"]][0])')\""
check "nft table loaded" "nft list table inet meshgate > /dev/null"
stop

echo "== and back to Go"
start "$GO" go2
check "Go reads what Rust wrote" "api view | grep -q '\"note\":\"phone\"'"
check "tunnel still not recreated" "[ \"\$(ip -o link show mg0 | cut -d: -f1)\" = '$GO_IDX' ]"
stop
[ $FAILED = 0 ] && echo "ALL PASSED"
exit $FAILED
