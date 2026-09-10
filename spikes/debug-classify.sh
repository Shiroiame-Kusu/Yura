#!/usr/bin/env bash
#
# Instrumented walk through the classification chain, one stage at a time.
#
# The full spike answers "did it work?". This answers "which link broke?", by putting an
# nftables counter on every rule and reporting which ones the packet actually reached.
#
# Usage: sudo ./spikes/debug-classify.sh

set -euo pipefail

DUMMY_IF="yuradbg0"
LOCAL_ADDR="198.51.100.1"
TARGET_HOST="198.51.100.7"
TARGET_PORT=8080
TPROXY_PORT=17899
FWMARK=0x711
BYPASS_MARK=0x712
RT_TABLE=719
CGROUP="/sys/fs/cgroup/yuradbg/a"
CG_REL="yuradbg/a"
NFT_TABLE="yura_dbg"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

step() { printf '\n=== %s ===\n' "$*"; }

cleanup() {
  set +e
  [[ -n "${LISTENER_PID:-}" ]] && kill -9 "$LISTENER_PID" 2>/dev/null
  [[ -n "${CLIENT_PID:-}" ]] && kill -9 "$CLIENT_PID" 2>/dev/null
  nft delete table inet "$NFT_TABLE" 2>/dev/null
  ip rule del fwmark "$FWMARK" lookup "$RT_TABLE" 2>/dev/null
  ip route flush table "$RT_TABLE" 2>/dev/null
  ip link del "$DUMMY_IF" 2>/dev/null
  if [[ -d "$CGROUP" ]]; then
    while read -r p; do [[ -n "$p" ]] && echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < "$CGROUP/cgroup.procs" 2>/dev/null
    rmdir "$CGROUP" 2>/dev/null
  fi
  rmdir /sys/fs/cgroup/yuradbg 2>/dev/null
  [[ -n "${SAVED_RP_ALL:-}" ]] && sysctl -qw net.ipv4.conf.all.rp_filter="$SAVED_RP_ALL" 2>/dev/null
  [[ -n "${SAVED_RP_LO:-}" ]]  && sysctl -qw net.ipv4.conf.lo.rp_filter="$SAVED_RP_LO" 2>/dev/null
  set -e
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

step "Environment"
modprobe nft_tproxy nft_socket dummy 2>/dev/null || true
ip link add "$DUMMY_IF" type dummy
ip link set "$DUMMY_IF" up
ip addr add "${LOCAL_ADDR}/24" dev "$DUMMY_IF"

SAVED_RP_ALL="$(sysctl -n net.ipv4.conf.all.rp_filter)"
SAVED_RP_LO="$(sysctl -n net.ipv4.conf.lo.rp_filter)"
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.lo.rp_filter=0

ip route add local default dev lo table "$RT_TABLE"
ip rule add fwmark "$FWMARK" lookup "$RT_TABLE"
mkdir -p "$CGROUP"
echo "  dummy iface, policy routing and cgroup ready"

step "Transparent listener on :${TPROXY_PORT}"
python3 - "$TPROXY_PORT" > /tmp/yuradbg-listener.log 2>&1 &
LISTENER_PID=$!
sleep 0.5
cat > /tmp/yuradbg-listener.py <<'PY'
import socket, sys
IP_TRANSPARENT = 19
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(0, IP_TRANSPARENT, 1)
s.bind(("0.0.0.0", port))
s.listen(16)
print(f"listening on {port}", flush=True)
while True:
    c, peer = s.accept()
    print(f"ACCEPTED from {peer} original-dest={c.getsockname()}", flush=True)
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nCAPTURED-OK\n")
    c.close()
PY
kill -9 "$LISTENER_PID" 2>/dev/null || true
python3 /tmp/yuradbg-listener.py "$TPROXY_PORT" > /tmp/yuradbg-listener.log 2>&1 &
LISTENER_PID=$!
sleep 0.8
cat /tmp/yuradbg-listener.log

step "nftables ruleset, every rule counted"
nft -f - <<EOF
table inet ${NFT_TABLE} {
  chain classify {
    type route hook output priority mangle; policy accept;
    meta mark ${BYPASS_MARK} counter return comment "bypass-own-traffic"
    meta l4proto tcp ip daddr ${TARGET_HOST} counter comment "saw-target-tcp"
    meta l4proto tcp socket cgroupv2 level 2 "${CG_REL}" counter comment "cgroup-matched"
    meta l4proto tcp socket cgroupv2 level 2 "${CG_REL}" meta mark set ${FWMARK} counter comment "mark-set"
  }
  chain capture {
    type filter hook prerouting priority mangle; policy accept;
    counter comment "prerouting-total"
    meta mark ${FWMARK} counter comment "prerouting-marked"
    meta mark ${FWMARK} meta l4proto tcp tproxy ip to :${TPROXY_PORT} counter accept comment "tproxy-applied"
  }
}
EOF
echo "  installed"

step "Running a client INSIDE the cgroup"
# Put the shell into the cgroup first, then exec curl, so the socket is created by a
# process that is already a member.
bash -c "echo \$\$ > ${CGROUP}/cgroup.procs; exec curl -s --max-time 4 http://${TARGET_HOST}:${TARGET_PORT}/" \
  > /tmp/yuradbg-client.out 2>&1 &
CLIENT_PID=$!
wait "$CLIENT_PID" 2>/dev/null || true
echo "  client output: $(cat /tmp/yuradbg-client.out)"

step "Counters"
nft list table inet "$NFT_TABLE" | grep -E "comment|counter" | sed 's/^/  /'

step "Listener log"
sed 's/^/  /' /tmp/yuradbg-listener.log

step "Policy routing state"
ip rule show | sed 's/^/  /'
ip route show table "$RT_TABLE" | sed 's/^/  /'
