#!/usr/bin/env bash
#
# Yura routing spike — proves that an already-running, unmodified process can be
# re-routed through a user-supplied SOCKS5 proxy, per process instance.
#
# This is the de-risking experiment the specification asks for before any of the product
# is built. It answers, with evidence rather than assertion:
#
#   1. Can we capture the traffic of a process that is ALREADY running, without a wrapper,
#      without restarting it, and without changing the user it runs as?
#   2. Can we do that for ONE INSTANCE of an executable while another instance of the SAME
#      executable keeps going out directly?
#   3. Does it work for TCP and for UDP?
#   4. Do connections that existed before the rule keep their old route, and can we tell
#      the difference?
#   5. Does removing the rule actually restore direct routing?
#
# Everything runs on this machine. No packet leaves the host: the spike's destination
# addresses live on a dummy interface that goes nowhere, and the only way to reach the
# marker payload is through the spike's own SOCKS5 proxy. Receiving the marker is
# therefore proof of proxying, not an inference from configuration.
#
# Usage:  sudo ./spikes/routing-spike.sh [--keep] [--verbose]
#
#   --keep     leave the environment in place after the run for manual inspection
#   --verbose  echo every privileged command before running it
#
# Everything this script creates is namespaced 'yura-spike' / 'yura_spike' and is removed
# by the cleanup trap, including on failure.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration. All of it is spike-local and chosen to avoid collisions.
# ---------------------------------------------------------------------------

DUMMY_IF="yuraspike0"
TEST_NET="198.51.100.0/24"          # TEST-NET-2, reserved for documentation (RFC 5737)
LOCAL_ADDR="198.51.100.1"           # assigned to the dummy interface: directly reachable
UNREACHABLE_HOST="198.51.100.7"     # same subnet, nothing there: reachable ONLY via proxy

MARKER_TCP_PORT=18080
MARKER_HOLD_PORT=18081
MARKER_UDP_PORT=19090
TCP_MARKER="YURA-TCP-PROXIED-OK"
UDP_MARKER="YURA-UDP-PROXIED-OK"

SOCKS_HOST="127.0.0.1"
SOCKS_PORT=11080

TPROXY_PORT=17891
FWMARK=0x711                        # "capture this" — set by the classifier
BYPASS_MARK=0x712                   # "this is Yura's own upstream" — never reclassify
RT_TABLE=711

CGROUP_ROOT="/sys/fs/cgroup/yura"
CG_A="${CGROUP_ROOT}/spike-a"
CG_A_REL="yura/spike-a"             # path relative to the cgroup mount, for nftables
CG_LEVEL=2                          # depth of CG_A_REL

NFT_TABLE="yura_spike"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
RUN_DIR="${SCRIPT_DIR}/.run"

KEEP=0
VERBOSE=0
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --verbose) VERBOSE=1 ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
else
  C_RESET=; C_DIM=; C_BOLD=; C_RED=; C_GREEN=; C_YELLOW=; C_CYAN=
fi

TESTS_PASSED=0
TESTS_FAILED=0
declare -a FAILED_NAMES=()

step()  { printf '\n%s==>%s %s%s%s\n' "$C_CYAN" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }
info()  { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
warn()  { printf '    %s! %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }

pass()  { TESTS_PASSED=$((TESTS_PASSED+1)); printf '    %sPASS%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
fail()  { TESTS_FAILED=$((TESTS_FAILED+1)); FAILED_NAMES+=("$*"); printf '    %sFAIL%s %s\n' "$C_RED" "$C_RESET" "$*"; }

run() {
  [[ $VERBOSE -eq 1 ]] && printf '    %s$ %s%s\n' "$C_DIM" "$*" "$C_RESET"
  "$@"
}

# Runs a command as the invoking desktop user, never as root. The spike insists on this:
# a routed process must keep running as its original user.
as_user() {
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    setpriv --reuid "$(id -u "$SUDO_USER")" --regid "$(id -g "$SUDO_USER")" --init-groups -- "$@"
  else
    "$@"
  fi
}

py() { python3 "$@"; }

# Waits for a client to report its own pid, then echoes it.
await_client_pid() {
  local file="$1"
  for _ in $(seq 1 60); do
    if [[ -s "$file" ]]; then
      local pid
      pid="$(python3 -c "
import json, sys
for line in open(sys.argv[1]):
    try:
        record = json.loads(line)
    except ValueError:
        continue
    if record.get('event') == 'start':
        print(record['pid'])
        break
" "$file" 2>/dev/null)"
      if [[ -n "$pid" ]] && [[ -d "/proc/$pid" ]]; then
        echo "$pid"
        return 0
      fi
    fi
    sleep 0.25
  done
  return 1
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

preflight() {
  step "Preflight"

  if [[ $EUID -ne 0 ]]; then
    echo "This spike configures nftables, policy routing and cgroups. Run it with sudo." >&2
    exit 1
  fi

  local missing=()
  for tool in nft ip python3 setpriv; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if (( ${#missing[@]} )); then
    echo "missing required tools: ${missing[*]}" >&2
    exit 1
  fi

  if [[ "$(stat -fc %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
    echo "cgroup v2 unified hierarchy is required at /sys/fs/cgroup" >&2
    exit 1
  fi

  info "kernel      $(uname -r)"
  info "nftables    $(nft --version | awk '{print $2}')"
  info "cgroup      v2 unified"
  info "run dir     ${RUN_DIR}"

  # TPROXY lives in the xt_TPROXY / nft_tproxy modules; load them up front so a failure
  # here is reported as a missing kernel feature rather than a confusing nft syntax error.
  modprobe nft_tproxy   2>/dev/null || true
  modprobe nf_tproxy_ipv4 2>/dev/null || true
  modprobe nft_socket   2>/dev/null || true
  modprobe dummy        2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Teardown — registered before anything is created
# ---------------------------------------------------------------------------

declare -a BG_PIDS=()
SAVED_RP_ALL=""
SAVED_RP_LO=""

cleanup() {
  local status=$?
  if [[ $KEEP -eq 1 && $status -eq 0 ]]; then
    step "Leaving environment in place (--keep)"
    info "nft list table inet ${NFT_TABLE}"
    info "cat ${CG_A}/cgroup.procs"
    info "logs in ${RUN_DIR}"
    return
  fi

  step "Teardown"
  set +e

  for pid in "${BG_PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
  done
  # Give children a moment, then make sure nothing is left holding our ports.
  sleep 0.3
  for pid in "${BG_PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null
  done

  nft delete table inet "${NFT_TABLE}" 2>/dev/null
  ip rule del fwmark "${FWMARK}" lookup "${RT_TABLE}" 2>/dev/null
  ip route flush table "${RT_TABLE}" 2>/dev/null
  ip link del "${DUMMY_IF}" 2>/dev/null

  # Move any survivors back to the root cgroup before removing ours, otherwise rmdir fails.
  if [[ -d "${CG_A}" ]]; then
    while read -r pid; do
      [[ -n "$pid" ]] && echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null
    done < "${CG_A}/cgroup.procs" 2>/dev/null
    rmdir "${CG_A}" 2>/dev/null
  fi
  rmdir "${CGROUP_ROOT}" 2>/dev/null

  [[ -n "$SAVED_RP_ALL" ]] && sysctl -qw net.ipv4.conf.all.rp_filter="$SAVED_RP_ALL" 2>/dev/null
  [[ -n "$SAVED_RP_LO"  ]] && sysctl -qw net.ipv4.conf.lo.rp_filter="$SAVED_RP_LO" 2>/dev/null

  set -e
  info "removed dummy interface, nft table, ip rule, routing table ${RT_TABLE} and cgroups"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------

setup_network() {
  step "Building an isolated test network"

  run ip link add "${DUMMY_IF}" type dummy
  run ip link set "${DUMMY_IF}" up
  run ip addr add "${LOCAL_ADDR}/24" dev "${DUMMY_IF}"
  info "${LOCAL_ADDR}/24 on ${DUMMY_IF} — ${LOCAL_ADDR} is reachable, ${UNREACHABLE_HOST} is not"

  # rp_filter would drop the looped-back packets that TPROXY relies on for locally
  # generated traffic. Saved and restored by the cleanup trap.
  SAVED_RP_ALL="$(sysctl -n net.ipv4.conf.all.rp_filter)"
  SAVED_RP_LO="$(sysctl -n net.ipv4.conf.lo.rp_filter)"
  run sysctl -qw net.ipv4.conf.all.rp_filter=0
  run sysctl -qw net.ipv4.conf.lo.rp_filter=0

  # The routing table that pulls marked packets back into the local input path so that
  # TPROXY in prerouting can claim them. This is the standard technique for capturing
  # locally generated traffic.
  run ip route add local default dev lo table "${RT_TABLE}"
  run ip rule add fwmark "${FWMARK}" lookup "${RT_TABLE}"
  info "fwmark ${FWMARK} -> table ${RT_TABLE} (local default dev lo)"
}

setup_cgroups() {
  step "Creating cgroups"
  run mkdir -p "${CG_A}"
  info "${CG_A}  (relative path '${CG_A_REL}', nftables level ${CG_LEVEL})"
}

start_services() {
  step "Starting the controlled destination and the user-supplied proxy"

  mkdir -p "${RUN_DIR}"
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    chown -R "${SUDO_USER}:$(id -gn "$SUDO_USER")" "${RUN_DIR}"
  fi

  as_user python3 "${LIB_DIR}/marker_server.py" \
    --listen "${LOCAL_ADDR}" \
    --tcp-port "${MARKER_TCP_PORT}" \
    --hold-port "${MARKER_HOLD_PORT}" \
    --udp-port "${MARKER_UDP_PORT}" \
    --tcp-marker "${TCP_MARKER}" \
    --udp-marker "${UDP_MARKER}" \
    --log "${RUN_DIR}/marker.jsonl" \
    > "${RUN_DIR}/marker.out" 2>&1 &
  BG_PIDS+=($!)
  info "destination server on ${LOCAL_ADDR}: tcp/${MARKER_TCP_PORT} hold/${MARKER_HOLD_PORT} udp/${MARKER_UDP_PORT}"

  # Stands in for the user's own proxy. It rewrites the unreachable spike target to the
  # marker server, so only proxied flows can ever see the marker payload.
  as_user python3 "${LIB_DIR}/socks5_proxy.py" \
    --listen "${SOCKS_HOST}" --port "${SOCKS_PORT}" \
    --log "${RUN_DIR}/socks.jsonl" \
    --rewrite "${UNREACHABLE_HOST}:8080=${LOCAL_ADDR}:${MARKER_TCP_PORT}" \
    --rewrite "${UNREACHABLE_HOST}:9090=${LOCAL_ADDR}:${MARKER_UDP_PORT}" \
    > "${RUN_DIR}/socks.out" 2>&1 &
  BG_PIDS+=($!)
  info "SOCKS5 proxy on ${SOCKS_HOST}:${SOCKS_PORT} (audit log: ${RUN_DIR}/socks.jsonl)"

  # The transparent forwarder is the only component that needs privilege.
  python3 "${LIB_DIR}/tproxy_forwarder.py" \
    --port "${TPROXY_PORT}" \
    --socks "${SOCKS_HOST}:${SOCKS_PORT}" \
    --mark "${BYPASS_MARK}" \
    --log "${RUN_DIR}/forwarder.jsonl" \
    > "${RUN_DIR}/forwarder.out" 2>&1 &
  BG_PIDS+=($!)
  info "TPROXY forwarder on :${TPROXY_PORT} -> SOCKS5, upstream SO_MARK ${BYPASS_MARK}"

  sleep 1.2
  for name in marker socks forwarder; do
    if grep -qiE 'traceback|error' "${RUN_DIR}/${name}.out" 2>/dev/null; then
      warn "${name} reported a problem:"
      sed 's/^/      /' "${RUN_DIR}/${name}.out" >&2
      echo "spike cannot continue" >&2
      exit 1
    fi
  done
}

start_clients() {
  step "Starting two instances of the same ordinary application"

  # Both are started exactly the same way, as the desktop user, with no wrapper and no
  # knowledge of Yura. This is the population the spike then discriminates within.
  for label in A B; do
    local lower="${label,,}"
    as_user python3 "${LIB_DIR}/spike_client.py" \
      --label "instance-${label}" \
      --tcp-target "${UNREACHABLE_HOST}:8080" \
      --udp-target "${UNREACHABLE_HOST}:9090" \
      --preexisting-target "${LOCAL_ADDR}:${MARKER_HOLD_PORT}" \
      --out "${RUN_DIR}/client-${lower}.jsonl" \
      --interval 0.4 --timeout 1.5 \
      > "${RUN_DIR}/client-${lower}.out" 2>&1 &
    BG_PIDS+=($!)
  done

  # $! is the pid of the backgrounded subshell, not of the client that setpriv execs
  # inside it. Using it would migrate the wrong process into the cgroup and silently
  # classify nothing. The client reports its own pid on its first line; that is the only
  # trustworthy source.
  PID_A="$(await_client_pid "${RUN_DIR}/client-a.jsonl")" || {
    echo "instance A never reported its pid" >&2; exit 1; }
  PID_B="$(await_client_pid "${RUN_DIR}/client-b.jsonl")" || {
    echo "instance B never reported its pid" >&2; exit 1; }

  # Track the real clients too: killing the subshell would leave setpriv's child running.
  BG_PIDS+=("$PID_A" "$PID_B")

  PID_A_START="$(awk '{print $22}' "/proc/${PID_A}/stat")"
  PID_B_START="$(awk '{print $22}' "/proc/${PID_B}/stat")"
  info "instance A: pid ${PID_A} (start ticks ${PID_A_START}), user $(id -un "$(stat -c %u "/proc/${PID_A}")")"
  info "instance B: pid ${PID_B} (start ticks ${PID_B_START}), user $(id -un "$(stat -c %u "/proc/${PID_B}")")"
  info "both run the same executable: $(readlink -f "/proc/${PID_A}/exe")"
}

# ---------------------------------------------------------------------------
# The routing change itself
# ---------------------------------------------------------------------------

apply_instance_rule() {
  step "Applying an instance rule to A only"

  # 1. Verify the instance is still the one we were asked about. PID alone is not an
  #    identity; the start time is what makes this safe against PID reuse.
  local now_start
  now_start="$(awk '{print $22}' "/proc/${PID_A}/stat")"
  if [[ "$now_start" != "$PID_A_START" ]]; then
    echo "pid ${PID_A} is no longer the instance we selected (start ticks changed)" >&2
    exit 1
  fi
  info "re-verified pid ${PID_A} start ticks ${now_start} before acting"

  # 2. Migrate the RUNNING process into the classifier cgroup. This is the step that makes
  #    running-process selection possible at all: no restart, no wrapper, no uid change.
  run bash -c "echo ${PID_A} > ${CG_A}/cgroup.procs"
  info "migrated pid ${PID_A} into ${CG_A_REL} while it was running"
  info "cgroup now contains: $(tr '\n' ' ' < "${CG_A}/cgroup.procs")"
  info "process still runs as uid $(stat -c %u "/proc/${PID_A}")"

  # 3. Install the classifier. 'socket cgroupv2' resolves the path to a cgroup id when the
  #    rule is loaded, so the cgroup must already exist — and a recreated cgroup needs the
  #    rule reloaded. The daemon has to know this; it is not a detail we can leave implicit.
  run nft -f - <<EOF
table inet ${NFT_TABLE} {
  chain classify {
    type route hook output priority mangle; policy accept;

    # Loop prevention: Yura's own upstream sockets carry BYPASS_MARK and must never be
    # reclassified, or the forwarder would feed itself.
    meta mark ${BYPASS_MARK} return

    # Never capture traffic aimed at the proxy itself.
    ip daddr ${SOCKS_HOST} tcp dport ${SOCKS_PORT} return

    # The instance rule. Membership is decided by cgroup, not by executable path, which is
    # why the other instance of the same binary is unaffected.
    meta l4proto { tcp, udp } socket cgroupv2 level ${CG_LEVEL} "${CG_A_REL}" meta mark set ${FWMARK}
  }

  chain capture {
    type filter hook prerouting priority mangle; policy accept;
    meta mark ${FWMARK} meta l4proto tcp tproxy ip to :${TPROXY_PORT} accept
    meta mark ${FWMARK} meta l4proto udp tproxy ip to :${TPROXY_PORT} accept
  }
}
EOF
  info "nftables classifier installed"
  RULE_APPLIED_AT="$(date +%s.%N)"
  info "rule applied at ${RULE_APPLIED_AT}"
}

remove_instance_rule() {
  step "Removing the temporary override"
  run nft delete table inet "${NFT_TABLE}"
  run bash -c "echo ${PID_A} > /sys/fs/cgroup/cgroup.procs"
  RULE_REMOVED_AT="$(date +%s.%N)"
  info "classifier withdrawn and pid ${PID_A} returned to the root cgroup"
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

check() {
  local name="$1"; shift
  if "$@" > "${RUN_DIR}/.check.out" 2>&1; then
    pass "${name} — $(tail -1 "${RUN_DIR}/.check.out")"
  else
    fail "${name}"
    sed 's/^/         /' "${RUN_DIR}/.check.out"
  fi
}

settle() {
  local seconds="${1:-4}"
  info "waiting ${seconds}s for the clients to make fresh attempts"
  sleep "$seconds"
}

main() {
  preflight
  setup_network
  setup_cgroups
  start_services
  start_clients

  # ---- Baseline -----------------------------------------------------------
  step "Baseline: nothing is routed yet"
  settle 3
  local baseline_at; baseline_at="$(date +%s.%N)"

  check "baseline A cannot reach the proxy-only destination" \
    py "${LIB_DIR}/logquery.py" assert "${RUN_DIR}/client-a.jsonl" \
       --event tcp --window 2 --min-count 1 --expect-ok false
  check "baseline B cannot reach the proxy-only destination" \
    py "${LIB_DIR}/logquery.py" assert "${RUN_DIR}/client-b.jsonl" \
       --event tcp --window 2 --min-count 1 --expect-ok false
  check "baseline: the proxy has seen no traffic at all" \
    bash -c "[[ \$(python3 '${LIB_DIR}/logquery.py' count '${RUN_DIR}/socks.jsonl' --event connect) -eq 0 ]] && echo 'proxy log empty'"

  # ---- The routing change -------------------------------------------------
  apply_instance_rule
  # Sized for the direct instance, not the proxied one: instance B spends a full timeout on
  # every TCP and UDP attempt, so it produces records far more slowly than instance A.
  settle 10

  # Acceptance test 1: an ordinary running application, selected after the fact, has its
  # NEW connections routed through the selected proxy.
  check "A's new TCP connections now traverse the proxy (acceptance test 1)" \
    py "${LIB_DIR}/logquery.py" assert "${RUN_DIR}/client-a.jsonl" \
       --event tcp --since "${RULE_APPLIED_AT}" --window 3 --min-count 2 \
       --expect-ok true --expect-contains "${TCP_MARKER}"

  # Acceptance test 2: the other instance of the same executable is untouched.
  check "B, the same executable, is still direct and still fails (acceptance test 2)" \
    py "${LIB_DIR}/logquery.py" assert "${RUN_DIR}/client-b.jsonl" \
       --event tcp --since "${RULE_APPLIED_AT}" --window 3 --min-count 2 --expect-ok false

  # Acceptance test 7: UDP from the same selected process.
  check "A's UDP traffic traverses the proxy (acceptance test 7)" \
    py "${LIB_DIR}/logquery.py" assert "${RUN_DIR}/client-a.jsonl" \
       --event udp --since "${RULE_APPLIED_AT}" --window 3 --min-count 2 \
       --expect-ok true --expect-contains "${UDP_MARKER}"
  check "B's UDP traffic is unaffected" \
    py "${LIB_DIR}/logquery.py" assert "${RUN_DIR}/client-b.jsonl" \
       --event udp --since "${RULE_APPLIED_AT}" --window 3 --min-count 2 --expect-ok false

  # Independent confirmation from the proxy's own side, not from the client's belief.
  check "proxy-side log confirms A's flows and only A's" \
    bash -c "
      n=\$(python3 '${LIB_DIR}/logquery.py' count '${RUN_DIR}/socks.jsonl' --event connect --since ${RULE_APPLIED_AT})
      u=\$(python3 '${LIB_DIR}/logquery.py' count '${RUN_DIR}/socks.jsonl' --event udp_send --since ${RULE_APPLIED_AT})
      [[ \$n -ge 2 && \$u -ge 2 ]] && echo \"proxy observed \$n CONNECT and \$u UDP relays\"
    "

  # Acceptance test 11: pre-existing connections are distinguishable and keep their route.
  check "A's pre-rule connection is still open on its previous route (acceptance test 11)" \
    py "${LIB_DIR}/logquery.py" assert "${RUN_DIR}/client-a.jsonl" \
       --event preexisting_state --since "${RULE_APPLIED_AT}" --window 3 --min-count 2 \
       --expect-ok true
  check "the proxy never saw the pre-rule connection's destination" \
    bash -c "
      n=\$(python3 '${LIB_DIR}/logquery.py' count '${RUN_DIR}/socks.jsonl' --where-contains 'requested=${MARKER_HOLD_PORT}')
      [[ \$n -eq 0 ]] && echo 'no proxy record for the held connection: it stayed on its original route'
    "

  # ---- Removing the override ---------------------------------------------
  remove_instance_rule
  settle 4

  check "A returns to direct routing once the override is removed" \
    py "${LIB_DIR}/logquery.py" assert "${RUN_DIR}/client-a.jsonl" \
       --event tcp --since "${RULE_REMOVED_AT}" --window 2 --min-count 1 --expect-ok false
  check "the cgroup is empty after the override is removed" \
    bash -c "[[ ! -s '${CG_A}/cgroup.procs' ]] && echo 'cgroup.procs is empty: nothing inherits this policy'"

  # ---- Summary ------------------------------------------------------------
  step "Result"
  printf '    %d passed, %d failed\n' "$TESTS_PASSED" "$TESTS_FAILED"
  if (( TESTS_FAILED > 0 )); then
    for name in "${FAILED_NAMES[@]}"; do
      printf '    %s- %s%s\n' "$C_RED" "$name" "$C_RESET"
    done
    printf '    logs: %s\n' "${RUN_DIR}"
    return 1
  fi
  printf '    %sRunning-process proxying works, per instance, for TCP and UDP.%s\n' "$C_GREEN" "$C_RESET"
  printf '    logs: %s\n' "${RUN_DIR}"
}

main "$@"
