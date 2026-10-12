#!/bin/sh
# Simulates installing meshgate on pfSense from the web GUI's Command
# Prompt (no terminal) on a FreeBSD 14 VM, then checks it after a reboot.
#   sh pfsense_install.sh prepare   # make the VM look like pfSense (LAN, VLAN, pf)
#   sh pfsense_install.sh install /path/to/meshgate
#   sh pfsense_install.sh check     # run again after reboot
#   sh pfsense_install.sh uninstall
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
FAILED=0
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; FAILED=1; fi; }

case "$1" in
prepare)
  echo pfSense > /etc/platform
  # LAN + VLAN 20 like igb1 / igb1.20, recreated at boot by rc.conf
  sysrc -q cloned_interfaces="epair0" >/dev/null
  sysrc -q ifconfig_epair0a="inet 192.168.1.1/24 up" ifconfig_epair0b="up" >/dev/null
  sysrc -q vlans_epair0a="20" ifconfig_epair0a_20="inet 192.168.20.1/24" >/dev/null
  sysrc -q pf_enable=YES pf_rules=/etc/pf.conf >/dev/null
  cat > /etc/pf.conf <<PF
set skip on lo0
nat-anchor "natearly/*"
nat-anchor "natrules/*"
rdr-anchor "tftp-proxy/*"
block in all
pass out all keep state
pass in quick on vtnet0 proto tcp to port 22 flags any keep state
anchor "userrules/*"
pass in on epair0a all keep state
PF
  service netif start epair0 >/dev/null 2>&1 || true
  ifconfig epair0 create >/dev/null 2>&1 || true
  service netif restart >/dev/null 2>&1; service routing restart >/dev/null 2>&1
  service pf start >/dev/null 2>&1; pfctl -q -f /etc/pf.conf
  ifconfig -l
  ;;
install)
  # Exactly what the Command Prompt runs, minus the download (repo not public yet).
  MESHGATE_BIN="$2" sh "$HERE/../../scripts/install.sh" init --role controller --admin-pass labpassword123 </dev/null
  echo "install exit: $?"
  ;;
check)
  CONF=/usr/local/etc/meshgate/node.json
  check "service script installed" "test -x /usr/local/etc/rc.d/meshgate.sh"
  check "config in /usr/local/etc (survives RAM disks)" "test -f $CONF"
  check "meshgate agent running" "pgrep -f 'meshgate -config $CONF agent'"
  check "meshgate status works" "meshgate status"
  check "mg0 interface up" "ifconfig mg0 | grep -q UP"
  check "if_wg kernel module used" "kldstat -n if_wg"
  ROUTES=$(python3 $HERE/api.py /var/run/meshgate.sock view | python3 -c 'import json,sys; v=json.load(sys.stdin); print([n["value"].get("routes") for n in v["nodes"] if n["value"]["id"]==v["self_id"]][0])')
  check "LAN and VLAN 20 shared, WAN not" "echo '$ROUTES' | grep -q 192.168.20.0/24 && echo '$ROUTES' | grep -q 192.168.1.0/24 && ! echo '$ROUTES' | grep -q 10.0.2"
  check "WAN not offered as a rule target" "sleep 4; ! python3 $HERE/api.py /var/run/meshgate.sock view | grep -q 'vtnet0'"
  check "LAN + VLAN endpoints for home devices" "python3 $HERE/api.py /var/run/meshgate.sock view | grep -q '192.168.1.1:51820' && python3 $HERE/api.py /var/run/meshgate.sock view | grep -q '192.168.20.1:51820'"
  check "pfSense defaults to restricted LAN policy" "python3 $HERE/api.py /var/run/meshgate.sock view | grep -q '\"lan_policy\":\"restricted\"'"
  check "pfSense home node is not a relay" "! python3 $HERE/api.py /var/run/meshgate.sock view | grep -q '\"relay\":true'"
  check "pf filter anchor loaded" "pfctl -a userrules/meshgate -sr | grep -q 'block drop in quick on mg0 all'"
  check "web UI answers on 127.0.0.1:8080" "fetch -qo - http://127.0.0.1:8080/ | grep -q meshgate"
  meshgate status
  ;;
uninstall)
  sh "$HERE/../../scripts/install.sh" uninstall </dev/null
  check "binary removed" "! test -e /usr/local/bin/meshgate"
  check "service script removed" "! test -e /usr/local/etc/rc.d/meshgate.sh"
  check "config removed" "! test -e /usr/local/etc/meshgate/node.json"
  check "mg0 removed" "! ifconfig mg0"
  check "pf anchor flushed" "test -z \"\$(pfctl -a userrules/meshgate -sr 2>/dev/null)\""
  check "agent stopped" "! pgrep -f 'meshgate.*agent'"
  ;;
esac
[ $FAILED = 0 ] || exit 1
