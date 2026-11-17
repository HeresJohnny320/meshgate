#!/bin/sh
# HTTPS route with a certificate from an ACME server (Pebble, Let's
# Encrypt's test server): HTTP-01 validation against meshgate's proxy, then
# HTTPS with the issued certificate. Usage:
#   unshare -r -n -m sh test/e2e/acme.sh path/to/meshgate path/to/pebble path/to/pebble-repo
set -eu
BIN=$1
PEBBLE=$2
PREPO=$3
D=$(mktemp -d)
mount -t tmpfs none /run
ip link set lo up
ip link add eth0 type dummy && ip addr add 203.0.113.10/24 dev eth0 && ip link set eth0 up
ip route add default dev eth0
# app.test resolves to this machine, for Pebble's validation and curl.
printf '127.0.0.1 localhost app.test\n' > "$D/hosts" && mount --bind "$D/hosts" /etc/hosts
cat > "$D/pebble.json" <<EOF
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
 "certificate": "$PREPO/test/certs/localhost/cert.pem", "privateKey": "$PREPO/test/certs/localhost/key.pem",
 "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false}}
EOF
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 "$PEBBLE" -config "$D/pebble.json" > "$D/pebble.log" 2>&1 &
PPID_=$!
C="$D/etc/node.json"
api() { curl -sf --unix-socket "$D/data/meshgate.sock" -H 'Content-Type: application/json' "http://x/v1/$1" ${2:+-d "$2"}; }
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; FAILED=1; fi; }
FAILED=0
"$BIN" -config "$C" init --role standalone -y --name vps --data-dir "$D/data" --acme-email test@example.org > /dev/null
MESHGATE_ACME_URL=https://localhost:14000/dir SSL_CERT_FILE="$PREPO/test/certs/pebble.minica.pem" "$BIN" -config "$C" agent > "$D/agent.log" 2>&1 &
APID=$!
trap 'kill $APID $PPID_ 2>/dev/null || true' EXIT
i=0; while ! api view > /dev/null 2>&1; do i=$((i+1)); [ $i -gt 50 ] && { cat "$D/agent.log"; exit 1; }; sleep 0.2; done
SELF=$(api view | python3 -c 'import json,sys; print(json.load(sys.stdin)["self_id"])')
api node "{\"id\":\"$SELF\",\"patch\":{\"test_port\":8099},\"scope\":\"cluster\"}" > /dev/null
api route "{\"route\":{\"hostname\":\"app.test\",\"edge_node\":\"$SELF\",\"target_node\":\"$SELF\",\"target_ip\":\"127.0.0.1\",\"target_port\":8099,\"force_https\":true,\"enabled\":true},\"scope\":\"cluster\"}" > /dev/null
CRT="$D/data/certs/certificates/acme-v02.api.letsencrypt.org-directory/app.test/app.test.crt"
i=0; while [ ! -s "$CRT" ] && [ $i -lt 60 ]; do i=$((i+1)); sleep 1; done
check "certificate issued through HTTP-01" "[ -s '$CRT' ]"
curl -sfk https://127.0.0.1:15000/roots/0 > "$D/root.pem"
check "HTTPS answers with the issued certificate (trusted by the ACME root)" "curl -sf -m5 --cacert '$D/root.pem' https://app.test/ | grep -q 'node:      vps'"
check "plain HTTP redirects to HTTPS" "curl -s -m5 -o /dev/null -w '%{http_code} %{redirect_url}' http://app.test/x | grep -q '308 https://app.test/x'"
check "the request is in the traffic stats" "api traffic | grep -q '\"requests\":[1-9]'"
grep -E "proxy|certificate" "$D/agent.log" | head -5
[ $FAILED = 0 ] && echo "ALL PASSED"
exit $FAILED
