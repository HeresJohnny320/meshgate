#!/bin/sh
# meshgate installer for Linux and FreeBSD/pfSense.
#
#   curl -fsSL https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sudo sh
#   curl -fsSL .../install.sh | sudo sh -s -- join <token>      # join without questions about the role
#   curl -fsSL .../install.sh | sudo sh -s -- uninstall
#
# pfSense, from the web GUI (Diagnostics > Command Prompt > Execute Shell
# Command); with no terminal every question takes its default:
#   fetch -qo - https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sh -s -- join <token>
#   fetch -qo - .../install.sh | sh -s -- init --role controller --admin-pass '<password>'   # web UI on pfSense
#
# On pfSense, run it from an SSH shell (console menu option 8); the web GUI's
# Command Prompt cannot answer the setup questions:
#   fetch -o - https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sh
#
# Environment:
#   MESHGATE_BIN=/path/to/meshgate   use a local binary instead of downloading
#   MESHGATE_VERSION=v0.1.0          release to download (default: latest)
#   MESHGATE_PFSENSE_GUI=0           pfSense: skip VPN > meshgate and the
#                                    Firewall > Rules > MESHGATE tab
set -eu

REPO="heresjohnny320/meshgate"
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
OS=$(uname -s)
case "$OS" in
  Linux|FreeBSD) ;;
  *) die "meshgate nodes run on Linux or FreeBSD/pfSense; use the phone app for iOS/Android" ;;
esac
GOOS=$(echo "$OS" | tr '[:upper:]' '[:lower:]')
PFSENSE=0
if [ -f /etc/platform ] && grep -qi pfsense /etc/platform; then PFSENSE=1; fi
fetch_url() { # url dest
  if command -v curl >/dev/null; then curl -fsSL "$1" -o "$2"; else fetch -q -o "$2" "$1"; fi
}

if [ "${1:-}" = uninstall ]; then
  if [ -x /usr/local/bin/meshgate ]; then
    [ $PFSENSE = 1 ] && { /usr/local/bin/meshgate pfsense remove || true; }
    /usr/local/bin/meshgate leave -y || true
  fi
  rm -f /usr/local/bin/meshgate /usr/local/etc/rc.d/meshgate.sh /etc/systemd/system/meshgate.service
  [ "$OS" = Linux ] && systemctl daemon-reload 2>/dev/null
  say "meshgate removed. Remove this node in the web UI/TUI of another node if it is still listed."
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7) ARCH=arm ;;
  *) die "unsupported CPU $(uname -m)" ;;
esac

pm_install() {
  if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v dnf >/dev/null; then dnf install -y -q "$@"
  elif command -v yum >/dev/null; then yum install -y -q "$@"
  elif command -v apk >/dev/null; then apk add -q "$@"
  elif command -v pacman >/dev/null; then pacman -Sy --noconfirm --needed "$@"
  elif command -v zypper >/dev/null; then zypper -q install -y "$@"
  else return 1; fi
}

if [ "$OS" = FreeBSD ]; then
  say "Installing WireGuard tools"
  if ! command -v wg >/dev/null; then
    if [ $PFSENSE = 1 ]; then
      pkg install -y wireguard-tools >/dev/null 2>&1 || \
        die "install the WireGuard package first (System > Package Manager > WireGuard), then rerun"
    else
      pkg install -y wireguard-tools || die "pkg install wireguard-tools failed"
    fi
  fi
  if kldload -n if_wg 2>/dev/null; then
    say "Kernel WireGuard (if_wg) loaded"
    grep -q '^if_wg_load=' /boot/loader.conf.local 2>/dev/null || echo 'if_wg_load="YES"' >> /boot/loader.conf.local
  else
    say "if_wg not available; meshgate will use its built-in userspace WireGuard"
  fi
  if [ $PFSENSE = 0 ] && ! pfctl -s rules 2>/dev/null | grep -q 'userrules/\*'; then
    say "pf: add these lines to /etc/pf.conf so meshgate's rules are evaluated, then 'service pf reload':"
    printf '  nat-anchor "natrules/*"\n  rdr-anchor "natrules/*"\n  anchor "userrules/*"\n'
  fi
else
say "Installing WireGuard tools and nftables"
NEED=""
command -v nft >/dev/null || NEED="$NEED nftables"
command -v wg >/dev/null || NEED="$NEED wireguard-tools"
command -v curl >/dev/null || NEED="$NEED curl"
if [ -n "$NEED" ]; then
  # shellcheck disable=SC2086
  pm_install $NEED || say "could not install$NEED automatically; install it manually"
fi
command -v nft >/dev/null || die "nftables is required for port forwarding"

if modprobe wireguard 2>/dev/null || [ -d /sys/module/wireguard ]; then
  say "Kernel WireGuard available"
  echo wireguard > /etc/modules-load.d/meshgate.conf 2>/dev/null || true
else
  say "Kernel WireGuard not available; meshgate will use its built-in userspace WireGuard"
fi
fi

say "Installing meshgate"
if [ -n "${MESHGATE_BIN:-}" ]; then
  install -m 0755 "$MESHGATE_BIN" /usr/local/bin/meshgate
else
  VER="${MESHGATE_VERSION:-latest}"
  if [ "$VER" = latest ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
  else
    BASE="https://github.com/$REPO/releases/download/$VER"
  fi
  FILE="meshgate-$GOOS-$ARCH"
  TMP=$(mktemp)
  SUMS=$(mktemp)
  fetch_url "$BASE/$FILE" "$TMP" || die "download failed: $BASE/$FILE"
  # Check the binary against the release's published checksums.
  fetch_url "$BASE/SHA256SUMS" "$SUMS" || die "could not download SHA256SUMS for verification"
  WANT=$(awk -v f="$FILE" '$2 == f || $2 == "*" f { print $1 }' "$SUMS")
  if command -v sha256sum >/dev/null; then GOT=$(sha256sum "$TMP" | awk '{print $1}'); else GOT=$(sha256 -q "$TMP"); fi
  [ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || { rm -f "$TMP" "$SUMS"; die "checksum mismatch for $FILE: refusing to install"; }
  say "Checksum verified"
  install -m 0755 "$TMP" /usr/local/bin/meshgate
  rm -f "$TMP" "$SUMS"
fi
/usr/local/bin/meshgate version

HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo .)
RAW="https://raw.githubusercontent.com/$REPO/main/packaging"
if [ "$OS" = FreeBSD ]; then
  RC=/usr/local/etc/rc.d/meshgate.sh
  if [ -f "$HERE/../packaging/meshgate.rc" ]; then cp "$HERE/../packaging/meshgate.rc" "$RC"; else fetch_url "$RAW/meshgate.rc" "$RC"; fi
  chmod 0755 "$RC"
  CONF=/usr/local/etc/meshgate/node.json
else
  if [ -f "$HERE/../packaging/meshgate.service" ]; then
    install -m 0644 "$HERE/../packaging/meshgate.service" /etc/systemd/system/meshgate.service
  else
    fetch_url "$RAW/meshgate.service" /etc/systemd/system/meshgate.service
  fi
  systemctl daemon-reload
  CONF=/etc/meshgate/node.json
fi

# Questions need the terminal even when this script is piped into sh. With
# no terminal at all (pfSense's web Command Prompt, cloud-init) every
# question takes its default.
TTY=/dev/tty
YES=""
if ! ( : < /dev/tty ) 2>/dev/null; then TTY=/dev/null; YES="-y"; fi

ACTION="${1:-init}"
[ $# -gt 0 ] && shift
if [ -f "$CONF" ]; then
  say "Already configured; restarting"
elif [ "$ACTION" = join ]; then
  # shellcheck disable=SC2086
  /usr/local/bin/meshgate join "$@" $YES < "$TTY" || die "join failed"
else
  if [ -n "$YES" ]; then
    case " $* " in *" --role "*) ;; *) die "no terminal for questions: pass --role controller|standalone (and --admin-pass for the web UI)";; esac
  fi
  # shellcheck disable=SC2086
  /usr/local/bin/meshgate init "$@" $YES < "$TTY" || die "setup failed"
fi

# Trust the mesh interface in host firewalls. The ports meshgate needs from
# outside (WireGuard, probes, joins, 80/443 for HTTPS routes and every port
# forward) are opened and closed by the running agent itself, tagged
# "meshgate: ..." (Nodes > Edit > "Open ports in ufw / firewalld").
# (On FreeBSD/pfSense meshgate opens its ports itself in its pf anchor.)
if [ "$OS" = FreeBSD ]; then
  :
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  say "Configuring firewalld (meshgate opens its ports and forwards automatically)"
  firewall-cmd -q --permanent --zone=trusted --add-interface=mg0 || true
  firewall-cmd -q --reload || true
elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  say "Configuring ufw (meshgate opens its ports and forwards automatically)"
  ufw allow in on mg0 >/dev/null
  ufw route allow in on mg0 >/dev/null; ufw route allow out on mg0 >/dev/null
fi

if [ "$OS" = FreeBSD ]; then
  "$RC" restart </dev/null >/dev/null 2>&1
else
  systemctl enable --now meshgate
fi
i=0
until /usr/local/bin/meshgate status >/dev/null 2>&1; do
  i=$((i+1)); [ $i -gt 30 ] && break; sleep 1
done
/usr/local/bin/meshgate status || {
  if [ "$OS" = FreeBSD ]; then tail -20 /var/log/meshgate.log; else journalctl -u meshgate -n 20 --no-pager; fi
  die "meshgate did not start"
}
if grep -q web_listen "$CONF" 2>/dev/null; then
  say "Web UI: http://127.0.0.1:8080 on this machine, or http://<mesh ip>:8080 from any mesh device"
fi
if [ $PFSENSE = 1 ] && [ "${MESHGATE_PFSENSE_GUI:-1}" != 0 ]; then
  say "Adding meshgate to the pfSense GUI"
  /usr/local/bin/meshgate pfsense install || say "could not add the pfSense GUI pages; retry with: meshgate pfsense install"
fi
if [ $PFSENSE = 1 ]; then
  say "Done. Manage from VPN > meshgate in the pfSense GUI, or in an SSH shell: meshgate tui"
else
  say "Done. Try: sudo meshgate status   |   sudo meshgate tui"
fi
