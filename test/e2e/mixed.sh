#!/bin/sh
# Runs the end-to-end lab with Go and Rust nodes in one mesh, both ways
# round: A = Go web UI/VPS with Rust home server, laptop and second VPS;
# B = the opposite. Usage: test/e2e/mixed.sh path/to/meshgate-go path/to/meshgate-rust
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
W=$(mktemp -d)
# Copies, so nothing the lab does can touch the originals.
cp "$1" "$W/go" && cp "$2" "$W/rust"
GO=$W/go
RS=$W/rust
export MESHGATE_LAB_NO_UPDATE=1
(cd "$ROOT/go" && go build -o "$W/phonesim" ./mobile/phonesim)
status=0
for mix in A B; do
	if [ $mix = A ]; then rust="home|lap|vps2"; else rust="vps|fr|inet|hr|nas|phone"; fi
	# The lab runs every node as "$BIN"; pick the build by network namespace.
	cat > "$W/meshgate-$mix" <<EOF
#!/bin/sh
ns=\$(ip netns identify \$\$ 2>/dev/null)
case "\$ns" in $rust) exec "$RS" "\$@";; *) exec "$GO" "\$@";; esac
EOF
	chmod +x "$W/meshgate-$mix"
	echo "== mixed mesh $mix (Rust on: $rust)"
	if ! unshare -r -n -m sh "$HERE/lab.sh" "$W/meshgate-$mix" "$W/phonesim"; then
		status=1
	fi
done
exit $status
