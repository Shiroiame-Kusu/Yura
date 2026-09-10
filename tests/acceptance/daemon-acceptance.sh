#!/usr/bin/env bash
#
# Acceptance tests for the privileged daemon, driven through its real IPC socket.
#
# Same controlled network as the routing spike: destinations live on a dummy interface
# that goes nowhere, and each marker payload is reachable only through one specific proxy.
# Receiving a marker therefore proves which proxy — if any — a flow traversed.
#
# What differs from the spike is that nothing here touches nftables, cgroups or policy
# routing directly. Every kernel change is made by yura-daemon in response to a rule sent
# over the socket, which is exactly how the desktop app will drive it.
#
# Usage:  sudo tests/acceptance/daemon-acceptance.sh [--keep]
# Build first:  dotnet build src/Yura.Daemon

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="${ROOT}/spikes/lib"
RUN="${ROOT}/tests/acceptance/.run"
DAEMON="${ROOT}/src/Yura.Daemon/bin/Debug/net10.0/yura-daemon"
SOCK="/run/yura/yura.sock"

DUMMY_IF="yuraacc0"
LOCAL_ADDR="198.51.100.1"
UNREACHABLE="198.51.100.7"
MARK_A="YURA-VIA-PROXY-A"
MARK_B="YURA-VIA-PROXY-B"
MARK_UDP_A="YURA-UDP-VIA-PROXY-A"
PROXY_A_ID="aaaaaaaa-0000-4000-8000-00000000000a"
PROXY_B_ID="bbbbbbbb-0000-4000-8000-00000000000b"

KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then C_G=$'\033[32m'; C_R=$'\033[31m'; C_B=$'\033[1m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else C_G=; C_R=; C_B=; C_D=; C_0=; fi

PASSED=0; FAILED=0; declare -a FAILURES=()
step() { printf '\n%s==> %s%s\n' "$C_B" "$*" "$C_0"; }
info() { printf '    %s%s%s\n' "$C_D" "$*" "$C_0"; }
pass() { PASSED=$((PASSED+1)); printf '    %sPASS%s %s\n' "$C_G" "$C_0" "$*"; }
# Must always return 0: under set -e a non-zero return from the else-branch of check() ends
# the whole run, and an empty detail string would do exactly that.
fail() { FAILED=$((FAILED+1)); FAILURES+=("$1"); printf '    %sFAIL%s %s\n' "$C_R" "$C_0" "$1"; if [[ -n "${2:-}" ]]; then sed 's/^/         /' <<< "$2"; fi; return 0; }

check() {
  local name="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then pass "$name — $(tail -1 <<< "$out")"; else fail "$name" "$out"; fi
}

as_user() {
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
    setpriv --reuid "$(id -u "$SUDO_USER")" --regid "$(id -g "$SUDO_USER")" --init-groups -- "$@"
  else "$@"; fi
}

ctl() { "$DAEMON" ctl --socket "$SOCK" "$@"; }
lq() { python3 "${LIB}/logquery.py" "$@"; }

await_pid() {
  local file="$1"
  for _ in $(seq 1 60); do
    if [[ -s "$file" ]]; then
      local pid
      pid="$(python3 -c "
import json,sys
for l in open(sys.argv[1]):
    try: r=json.loads(l)
    except ValueError: continue
    if r.get('event')=='start': print(r['pid']); break" "$file" 2>/dev/null)"
      [[ -n "$pid" && -d "/proc/$pid" ]] && { echo "$pid"; return 0; }
    fi
    sleep 0.25
  done
  return 1
}

# Builds the JSON body for an instance rule from a live pid.
instance_rule() {
  local id="$1" name="$2" pid="$3" action="$4" proxy="$5" order="$6" descendants="${7:-exclude}"
  local start uid boot
  start="$(awk '{print $22}' "/proc/${pid}/stat")"
  uid="$(stat -c %u "/proc/${pid}")"
  boot="$(cat /proc/sys/kernel/random/boot_id)"
  printf '{"rule":{"id":"%s","order":%d,"name":"%s","enabled":true,"origin":"processSelection","lifetime":"instance","createdAtUtc":"2026-09-10T00:00:00Z","processKind":"instance","pid":%d,"startTicks":%s,"uid":%s,"bootId":"%s","descendants":"%s","protocol":"any","action":"%s","proxyId":%s}}' \
    "$id" "$order" "$name" "$pid" "$start" "$uid" "$boot" "$descendants" "$action" "$proxy"
}

# ---------------------------------------------------------------------------

declare -a BG=()
DAEMON_PID=""

cleanup() {
  local status=$?
  set +e
  if [[ $KEEP -eq 1 && $status -eq 0 ]]; then
    step "Leaving environment up (--keep); daemon pid ${DAEMON_PID}"; return
  fi
  step "Teardown"
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID"; for _ in $(seq 1 40); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$DAEMON_PID" 2>/dev/null
  fi
  for p in "${BG[@]:-}"; do [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null; done
  "${ROOT}/spikes/kill-orphans.sh" >/dev/null 2>&1
  # Belt and braces: if the daemon did not clean up, do it here so the machine is left tidy.
  nft delete table inet yura 2>/dev/null
  ip rule del priority 7100 2>/dev/null
  ip route flush table 711 2>/dev/null
  ip link del "$DUMMY_IF" 2>/dev/null
  if [[ -d /sys/fs/cgroup/yura ]]; then
    for d in /sys/fs/cgroup/yura/*/; do
      [[ -d "$d" ]] || continue
      while read -r p; do [[ -n "$p" ]] && echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < "${d}cgroup.procs"
      rmdir "$d" 2>/dev/null
    done
    rmdir /sys/fs/cgroup/yura 2>/dev/null
  fi
  set -e
}
trap cleanup EXIT

# ---------------------------------------------------------------------------

step "Preflight"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ -x "$DAEMON" ]] || { echo "daemon not built: $DAEMON (run: dotnet build src/Yura.Daemon)" >&2; exit 1; }
for t in nft ip python3 setpriv; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 1; }; done
"${ROOT}/spikes/kill-orphans.sh" >/dev/null
mkdir -p "$RUN"; rm -f "$RUN"/*.jsonl "$RUN"/*.out "$RUN"/*.log "$RUN"/*.pid "$RUN"/*.txt "$RUN"/*.json
[[ -n "${SUDO_USER:-}" ]] && chown -R "$SUDO_USER" "$RUN"
info "daemon  $DAEMON"
info "run dir $RUN"

step "Isolated test network"
ip link add "$DUMMY_IF" type dummy && ip link set "$DUMMY_IF" up && ip addr add "${LOCAL_ADDR}/24" dev "$DUMMY_IF"
info "${LOCAL_ADDR}/24 on ${DUMMY_IF}; ${UNREACHABLE} has no host"

step "Two markers, two proxies"
as_user python3 "${LIB}/marker_server.py" --listen "$LOCAL_ADDR" --tcp-port 18080 --hold-port 18081 --udp-port 19090 \
  --tcp-marker "$MARK_A" --udp-marker "$MARK_UDP_A" --log "$RUN/marker-a.jsonl" > "$RUN/marker-a.out" 2>&1 & BG+=($!)
as_user python3 "${LIB}/marker_server.py" --listen "$LOCAL_ADDR" --tcp-port 18090 --hold-port 18091 --udp-port 19091 \
  --tcp-marker "$MARK_B" --udp-marker "unused" --log "$RUN/marker-b.jsonl" > "$RUN/marker-b.out" 2>&1 & BG+=($!)
as_user python3 "${LIB}/socks5_proxy.py" --listen 127.0.0.1 --port 11080 --log "$RUN/proxy-a.jsonl" \
  --rewrite "${UNREACHABLE}:8080=${LOCAL_ADDR}:18080" --rewrite "${UNREACHABLE}:9090=${LOCAL_ADDR}:19090" > "$RUN/proxy-a.out" 2>&1 & BG+=($!)
as_user python3 "${LIB}/socks5_proxy.py" --listen 127.0.0.1 --port 11081 --log "$RUN/proxy-b.jsonl" \
  --rewrite "${UNREACHABLE}:8080=${LOCAL_ADDR}:18090" > "$RUN/proxy-b.out" 2>&1 & BG+=($!)
sleep 1
info "proxy A :11080 -> marker A (${MARK_A});  proxy B :11081 -> marker B (${MARK_B})"

step "Daemon"
# A socket file left by a killed daemon would make the readiness wait below pass
# instantly and the first request fail with "connection refused".
rm -f "$SOCK"
"$DAEMON" --socket "$SOCK" --verbose > "$RUN/daemon.log" 2>&1 & DAEMON_PID=$!
ready=0
for _ in $(seq 1 60); do
  if [[ -S "$SOCK" ]] && ctl status >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.25
done
[[ $ready -eq 1 ]] || { echo "daemon never became ready:"; cat "$RUN/daemon.log"; exit 1; }
check "daemon answers status over the socket" ctl status
check "daemon accepts the proxy list" ctl set-proxies \
  "{\"proxies\":[{\"id\":\"$PROXY_A_ID\",\"name\":\"Proxy A\",\"protocol\":\"socks5\",\"host\":\"127.0.0.1\",\"port\":11080},{\"id\":\"$PROXY_B_ID\",\"name\":\"Proxy B\",\"protocol\":\"socks5\",\"host\":\"127.0.0.1\",\"port\":11081}]}"

step "Two instances of the same ordinary application, started normally"
start_client() {
  local label="$1"
  as_user python3 "${LIB}/spike_client.py" --label "$label" \
    --tcp-target "${UNREACHABLE}:8080" --udp-target "${UNREACHABLE}:9090" \
    --preexisting-target "${LOCAL_ADDR}:18081" --out "$RUN/client-${label}.jsonl" \
    --interval 0.4 --timeout 1.5 > "$RUN/client-${label}.out" 2>&1 & BG+=($!)
  await_pid "$RUN/client-${label}.jsonl"
}
PID_A="$(start_client a)"; PID_B="$(start_client b)"; BG+=("$PID_A" "$PID_B")
info "A: pid $PID_A ($(id -un "$(stat -c %u /proc/$PID_A)"))   B: pid $PID_B   exe $(readlink -f /proc/$PID_A/exe)"

step "Baseline"
sleep 4
check "A cannot reach the proxy-only destination" lq assert "$RUN/client-a.jsonl" --event tcp --window 2 --min-count 1 --expect-ok false
check "B cannot reach the proxy-only destination" lq assert "$RUN/client-b.jsonl" --event tcp --window 2 --min-count 1 --expect-ok false

# ---------------------------------------------------------------------------
step "Acceptance 1 & 2 & 7 & 11: instance rule on A -> proxy A"
RULE_A="11111111-0000-4000-8000-000000000001"
check "daemon applies an instance rule for A" ctl apply-rule "$(instance_rule "$RULE_A" "A via proxy A" "$PID_A" proxy "\"$PROXY_A_ID\"" 100)"
T_A="$(date +%s.%N)"
sleep 10
check "1: A's new TCP connections traverse proxy A" lq assert "$RUN/client-a.jsonl" --event tcp --since "$T_A" --window 3 --min-count 2 --expect-ok true --expect-contains "$MARK_A"
check "2: B, same executable, is still direct" lq assert "$RUN/client-b.jsonl" --event tcp --since "$T_A" --window 3 --min-count 2 --expect-ok false
check "7: A's UDP traverses proxy A" lq assert "$RUN/client-a.jsonl" --event udp --since "$T_A" --window 3 --min-count 2 --expect-ok true --expect-contains "$MARK_UDP_A"
check "11: A's pre-rule connection is still open on its old route" lq assert "$RUN/client-a.jsonl" --event preexisting_state --since "$T_A" --window 3 --min-count 2 --expect-ok true
check "proxy A's own log confirms A's flows" bash -c "n=\$(python3 '$LIB/logquery.py' count '$RUN/proxy-a.jsonl' --event connect --since $T_A); [[ \$n -ge 2 ]] && echo \"proxy A saw \$n CONNECTs\""
check "proxy B saw nothing" bash -c "n=\$(python3 '$LIB/logquery.py' count '$RUN/proxy-b.jsonl' --event connect); [[ \$n -eq 0 ]] && echo 'proxy B log empty'"
check "daemon reports A's flows as confirmed proxied" bash -c "
  out=\$('$DAEMON' ctl --socket '$SOCK' list-flows)
  python3 -c \"
import json,sys
r=json.loads(sys.argv[1]); fl=[f for f in r['flows'] if f['ruleId']=='$RULE_A']
ok=[f for f in fl if f['route']=='confirmedProxied']
assert len(ok)>=2, f'expected >=2 confirmed flows for rule A, got {len(ok)} of {len(fl)}'
print(f'{len(ok)} flows confirmedProxied, proxy={ok[0][\\\"proxyName\\\"]}, dest={ok[0][\\\"destination\\\"]}')\" \"\$out\""
check "A's process still runs as its original user" bash -c "u=\$(id -un \$(stat -c %u /proc/$PID_A)); [[ \$u != root ]] && echo \"uid owner: \$u\""

# ---------------------------------------------------------------------------
step "Acceptance 5: B -> proxy B, simultaneously with A -> proxy A"
RULE_B="22222222-0000-4000-8000-000000000002"
check "daemon applies an instance rule for B" ctl apply-rule "$(instance_rule "$RULE_B" "B via proxy B" "$PID_B" proxy "\"$PROXY_B_ID\"" 101)"
T_B="$(date +%s.%N)"
sample_b() {
  {
    echo "--- t+$1 ---"
    echo "s002 members: $(tr '\n' ' ' < /sys/fs/cgroup/yura/s002/cgroup.procs 2>/dev/null)"
    echo "B pid $PID_B cgroup: $(cat /proc/$PID_B/cgroup 2>/dev/null)"
    nft list table inet yura 2>&1 | grep -E 'counter|# s00'
  } >> "$RUN/b-samples.txt"
}
sleep 4; sample_b 4s
sleep 8; sample_b 12s
check "5: B traverses proxy B" lq assert "$RUN/client-b.jsonl" --event tcp --since "$T_B" --window 3 --min-count 2 --expect-ok true --expect-contains "$MARK_B"
check "5: A still traverses proxy A at the same time" lq assert "$RUN/client-a.jsonl" --event tcp --since "$T_B" --window 3 --min-count 2 --expect-ok true --expect-contains "$MARK_A"
# Diagnostics for the intermittent-classification investigation.
nft list table inet yura > "$RUN/nft-after-B.txt" 2>&1
ctl list-flows > "$RUN/flows-after-B.json" 2>&1 || true
info "counters and flows dumped to $RUN/nft-after-B.txt, flows-after-B.json"

# ---------------------------------------------------------------------------
step "Acceptance 6: Block, then Direct, for B"
check "daemon replaces B's rule with Block" ctl apply-rule "$(instance_rule "$RULE_B" "B blocked" "$PID_B" block null 101)"
T_BLK="$(date +%s.%N)"
sleep 4
check "6: B's connections are refused, not merely timing out" lq assert "$RUN/client-b.jsonl" --event tcp --since "$T_BLK" --window 3 --min-count 2 --expect-ok false --expect-contains "ConnectionRefused"
check "daemon replaces B's rule with Direct" ctl apply-rule "$(instance_rule "$RULE_B" "B direct" "$PID_B" direct null 101)"
T_DIR="$(date +%s.%N)"
sleep 8
check "6: B is direct again (unreachable destination times out)" lq assert "$RUN/client-b.jsonl" --event tcp --since "$T_DIR" --window 2 --min-count 1 --expect-ok false --expect-contains "timed out"

# ---------------------------------------------------------------------------
step "Acceptance 8 (inclusion): a process tree, children forked after the rule"
# The loop writes its own pid: $! would name the backgrounded subshell, whose only child is
# setpriv, and a process that never forks a curl cannot demonstrate child inheritance.
as_user bash -c "echo \$\$ > '$RUN/tree.pid'; while true; do curl -s --max-time 2 http://${UNREACHABLE}:8080/ >> '$RUN/tree.out' 2>&1; echo >> '$RUN/tree.out'; sleep 0.5; done" > /dev/null 2>&1 &
BG+=($!)
for _ in $(seq 1 40); do [[ -s "$RUN/tree.pid" ]] && break; sleep 0.25; done
TREE_PID="$(cat "$RUN/tree.pid")"; BG+=("$TREE_PID")
info "loop shell pid $TREE_PID; every curl it forks is a fresh child process"
RULE_T="33333333-0000-4000-8000-000000000003"
check "daemon applies a tree rule (include future children) on the loop shell" ctl apply-rule "$(instance_rule "$RULE_T" "shell and children via A" "$TREE_PID" proxy "\"$PROXY_A_ID\"" 102 includeFuture)"
sleep 6
check "8: curl children forked after the rule are proxied" bash -c "n=\$(grep -c '$MARK_A' '$RUN/tree.out'); [[ \$n -ge 2 ]] && echo \"\$n child curls received the marker\""

# ---------------------------------------------------------------------------
step "Acceptance 4: instance rule expires when its process exits"
check "rule A is listed while A runs" bash -c "'$DAEMON' ctl --socket '$SOCK' list-rules | grep -q '$RULE_A' && echo listed"
SLOT_DIR="$( { grep -l "^${PID_A}\$" /sys/fs/cgroup/yura/*/cgroup.procs 2>/dev/null || true; } | head -1 | xargs -r dirname)"
info "A lives in cgroup ${SLOT_DIR:-<none>}"
kill -9 "$PID_A"; sleep 5
check "4: rule A is gone from the daemon after A exited" bash -c "! '$DAEMON' ctl --socket '$SOCK' list-rules | grep -q '$RULE_A' && echo 'rule expired'"
check "4: A's cgroup was removed, so nothing can inherit its policy" bash -c "[[ -z '$SLOT_DIR' || ! -d '$SLOT_DIR' ]] && echo 'cgroup gone'"
PID_C="$(start_client c)"; BG+=("$PID_C")
sleep 4
check "4: a fresh instance of the same executable is unaffected" lq assert "$RUN/client-c.jsonl" --event tcp --window 2 --min-count 1 --expect-ok false

# ---------------------------------------------------------------------------
step "Clean shutdown"
kill -TERM "$DAEMON_PID"
for _ in $(seq 1 40); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.25; done
check "nft table removed on shutdown" bash -c "! nft list table inet yura >/dev/null 2>&1 && echo removed"
check "policy routing removed on shutdown" bash -c "! ip rule show | grep -q 'fwmark 0x7100/0xffffff00' && echo removed"
check "cgroup subtree removed on shutdown" bash -c "[[ ! -d /sys/fs/cgroup/yura ]] && echo removed"
DAEMON_PID=""

step "Result"
printf '    %d passed, %d failed\n' "$PASSED" "$FAILED"
for f in "${FAILURES[@]:-}"; do [[ -n "$f" ]] && printf '    %s- %s%s\n' "$C_R" "$f" "$C_0"; done
printf '    daemon log: %s/daemon.log\n' "$RUN"
[[ $FAILED -eq 0 ]]
