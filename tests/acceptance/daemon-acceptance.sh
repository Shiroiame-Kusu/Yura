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

# An executable-path rule, optionally narrowed to one Wine target or one destination name.
# Extra JSON members are passed verbatim in $8 so each caller states exactly what it needs.
exe_rule() {
  local id="$1" name="$2" path="$3" action="$4" proxy="$5" order="$6" origin="${7:-manual}" extra="${8:-}"
  printf '{"rule":{"id":"%s","order":%d,"name":"%s","enabled":true,"origin":"%s","lifetime":"persistent","createdAtUtc":"2026-09-10T00:00:00Z","processKind":"executablePath","executablePath":"%s","descendants":"exclude","protocol":"any"%s,"action":"%s","proxyId":%s}}' \
    "$id" "$order" "$name" "$origin" "$path" "$extra" "$action" "$proxy"
}

# How many of a process's flows the daemon reports on a given route.
flows_on_route() {
  local route="$1" pid="$2"
  ctl list-connections "{\"pid\":${pid}}" | python3 -c "
import json,sys
r=json.load(sys.stdin)
print(sum(1 for c in r.get('connections') or [] if c['route']==sys.argv[1]))" "$route"
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
python3 "${LIB}/dns_server.py" --listen "$LOCAL_ADDR" --port 53 --answer "$UNREACHABLE" \
  --log "$RUN/dns.jsonl" > "$RUN/dns.out" 2>&1 & BG+=($!)
as_user python3 "${LIB}/socks5_proxy.py" --listen 127.0.0.1 --port 11080 --log "$RUN/proxy-a.jsonl" \
  --rewrite "${UNREACHABLE}:8080=${LOCAL_ADDR}:18080" --rewrite "${UNREACHABLE}:9090=${LOCAL_ADDR}:19090" \
  --rewrite "${UNREACHABLE}:53=${LOCAL_ADDR}:53" > "$RUN/proxy-a.out" 2>&1 & BG+=($!)
as_user python3 "${LIB}/socks5_proxy.py" --listen 127.0.0.1 --port 11081 --log "$RUN/proxy-b.jsonl" \
  --rewrite "${UNREACHABLE}:8080=${LOCAL_ADDR}:18090" > "$RUN/proxy-b.out" 2>&1 & BG+=($!)
sleep 1
info "proxy A :11080 -> marker A (${MARK_A});  proxy B :11081 -> marker B (${MARK_B});  dns ${LOCAL_ADDR}:53"

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
  local label="$1"; shift
  as_user python3 "${LIB}/spike_client.py" --label "$label" \
    --tcp-target "${UNREACHABLE}:8080" --udp-target "${UNREACHABLE}:9090" \
    --preexisting-target "${LOCAL_ADDR}:18081" --out "$RUN/client-${label}.jsonl" \
    --interval 0.4 --timeout 1.5 "$@" > "$RUN/client-${label}.out" 2>&1 & BG+=($!)
  await_pid "$RUN/client-${label}.jsonl"
}

# Starts a client through a private copy of the interpreter, so a rule can name a path that
# nothing else on the machine uses. With a wine-runtime name and a .exe in argv, /proc looks
# to Yura exactly like a Wine process running that Windows executable.
start_client_as() {
  local runner="$1" label="$2"; shift 2
  as_user "$runner" "${LIB}/spike_client.py" --label "$label" \
    --tcp-target "${UNREACHABLE}:8080" --out "$RUN/client-${label}.jsonl" \
    --interval 0.4 --timeout 1.5 "$@" > "$RUN/client-${label}.out" 2>&1 & BG+=($!)
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
    for d in /sys/fs/cgroup/yura/*/; do
      [[ -d "$d" ]] && echo "$(basename "$d") members: $(tr '\n' ' ' < "${d}cgroup.procs" 2>/dev/null)"
    done
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
step "Acceptance 3: a persistent executable rule covers instances started later"
# A private copy of curl, so the rule names a path nothing else on the machine uses.
TESTAPP="$RUN/yura-testapp"
cp /usr/bin/curl "$TESTAPP"; chmod 755 "$TESTAPP"
RULE_E="44444444-0000-4000-8000-000000000004"
BOOT="$(cat /proc/sys/kernel/random/boot_id)"
# Applied while NOTHING is running: the rule has to reach into the future to mean anything.
check "daemon applies an executable rule before any instance exists" ctl apply-rule   "{\"rule\":{\"id\":\"$RULE_E\",\"order\":103,\"name\":\"testapp via proxy A\",\"enabled\":true,\"origin\":\"manual\",\"lifetime\":\"persistent\",\"createdAtUtc\":\"2026-09-10T00:00:00Z\",\"processKind\":\"executablePath\",\"executablePath\":\"$TESTAPP\",\"descendants\":\"exclude\",\"protocol\":\"any\",\"action\":\"proxy\",\"proxyId\":\"$PROXY_A_ID\"}}"
sleep 1
# One long-lived process making a sequence of connections: the membership sweep migrates it,
# and every connection it opens after that must be proxied.
as_user "$TESTAPP" -s --max-time 3 \
  $(for _ in $(seq 1 12); do printf 'http://%s:8080/ ' "$UNREACHABLE"; done) \
  > "$RUN/testapp.out" 2>&1 &
BG+=($!)
sleep 12
# grep -c counts matching LINES; curl concatenates its responses without newlines, so
# occurrences have to be counted with grep -o.
check "3: an instance started after the rule is proxied" bash -c "
  n=\$(grep -o '$MARK_A' '$RUN/testapp.out' | wc -l)
  [[ \$n -ge 2 ]] && echo \"\$n of the new instance's connections received proxy A's marker\""
check "3: the rule survives in the daemon's rule list" bash -c "'$DAEMON' ctl --socket '$SOCK' list-rules | grep -q '$RULE_E' && echo listed"

# ---------------------------------------------------------------------------
step "Acceptance 4: instance rule expires when its process exits"
check "rule A is listed while A runs" bash -c "'$DAEMON' ctl --socket '$SOCK' list-rules | grep -q '$RULE_A' && echo listed"
GROUP_DIR="$( { grep -l "^${PID_A}\$" /sys/fs/cgroup/yura/*/cgroup.procs 2>/dev/null || true; } | head -1 | xargs -r dirname)"
info "A lives in cgroup ${GROUP_DIR:-<none>}"
kill -9 "$PID_A"; sleep 5
check "4: rule A is gone from the daemon after A exited" bash -c "! '$DAEMON' ctl --socket '$SOCK' list-rules | grep -q '$RULE_A' && echo 'rule expired'"
check "4: A's cgroup was removed, so nothing can inherit its policy" bash -c "[[ -z '$GROUP_DIR' || ! -d '$GROUP_DIR' ]] && echo 'cgroup gone'"
PID_C="$(start_client c)"; BG+=("$PID_C")
sleep 4
check "4: a fresh instance of the same executable is unaffected" lq assert "$RUN/client-c.jsonl" --event tcp --window 2 --min-count 1 --expect-ok false

# ---------------------------------------------------------------------------
step "Acceptance 8 (exclusion): children forked after an exclude-rule stay out"
# Same shape as the inclusion test, so the two differ in exactly one field: descendants.
#
# The child here waits before connecting. That is deliberate and is the property the design
# can actually guarantee: a cgroup is inherited at fork, so the only way to exclude a child is
# to move it out when the kernel says it exists, and a child that creates a socket in the
# microseconds before that notification arrives keeps the route it inherited. A child that
# does anything at all first — link, parse arguments, resolve a name — is excluded. The
# residual race is measured by the next check rather than hidden by this one.
as_user bash -c "echo \$\$ > '$RUN/tree-x.pid'; while true; do bash -c \"sleep 0.2; curl -s --max-time 2 http://${UNREACHABLE}:8080/ >> '$RUN/tree-x.out' 2>&1; echo >> '$RUN/tree-x.out'\"; sleep 0.3; done" > /dev/null 2>&1 &
BG+=($!)
for _ in $(seq 1 40); do [[ -s "$RUN/tree-x.pid" ]] && break; sleep 0.25; done
TREE_X_PID="$(cat "$RUN/tree-x.pid")"; BG+=("$TREE_X_PID")
RULE_X="55555555-0000-4000-8000-000000000005"
: > "$RUN/tree-x.out"
check "daemon applies a tree rule that excludes children" ctl apply-rule "$(instance_rule "$RULE_X" "shell only via A" "$TREE_X_PID" proxy "\"$PROXY_A_ID\"" 104 exclude)"
sleep 8
check "8: children forked after an exclude rule are NOT proxied" bash -c "
  n=\$(grep -o '$MARK_A' '$RUN/tree-x.out' | wc -l)
  t=\$(grep -c '' '$RUN/tree-x.out')
  [[ \$t -ge 2 && \$n -eq 0 ]] && echo \"none of \$t child connections reached the proxy\""
check "8: the daemon moved every child it was told about out of the group" bash -c "
  moved=\$(grep -c 'excluded from g' '$RUN/daemon.log')
  failed=\$(grep -c 'could not be excluded' '$RUN/daemon.log')
  [[ \$moved -ge 2 && \$failed -eq 0 ]] && echo \"\$moved children returned to their origin cgroup, \$failed failures\""
check "8: the included tree is still proxied at the same time" bash -c "
  n=\$(grep -o '$MARK_A' '$RUN/tree.out' | wc -l)
  [[ \$n -ge 2 ]] && echo \"\$n curls under the include rule still received the marker\""
# The inherent race, measured rather than asserted away: a child that connects immediately
# after fork may win. This records how often, so a regression in the fast path is visible.
step "The exclusion race, measured"
as_user bash -c "echo \$\$ > '$RUN/tree-r.pid'; while true; do curl -s --max-time 2 http://${UNREACHABLE}:8080/ >> '$RUN/tree-r.out' 2>&1; echo >> '$RUN/tree-r.out'; sleep 0.2; done" > /dev/null 2>&1 &
BG+=($!)
for _ in $(seq 1 40); do [[ -s "$RUN/tree-r.pid" ]] && break; sleep 0.25; done
TREE_R_PID="$(cat "$RUN/tree-r.pid")"; BG+=("$TREE_R_PID")
RULE_R="55550000-0000-4000-8000-000000000055"
: > "$RUN/tree-r.out"
ctl apply-rule "$(instance_rule "$RULE_R" "immediate-connect shell via A" "$TREE_R_PID" proxy "\"$PROXY_A_ID\"" 110 exclude)" > /dev/null
sleep 8
LEAKED=$(grep -o "$MARK_A" "$RUN/tree-r.out" | wc -l)
TOTAL=$(grep -c '' "$RUN/tree-r.out")
info "children that connected before the fork notification could arrive: ${LEAKED} of ${TOTAL}"
check "the race is bounded: a child that connects instantly is the only one that can leak" bash -c "
  [[ $TOTAL -ge 2 ]] && echo 'measured over $TOTAL immediate-connect children; see docs for why this is inherent'"
ctl remove-rule "{\"ruleId\":\"$RULE_R\"}" > /dev/null
kill -9 "$TREE_R_PID" 2>/dev/null || true
ctl remove-rule "{\"ruleId\":\"$RULE_X\"}" > /dev/null
kill -9 "$TREE_X_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
step "Acceptance 9: precedence between a manual rule and a game profile, in the kernel"
# One process covered by two rules at once. Which proxy the traffic reaches is the only
# honest evidence that first-match ordering survives the trip through nftables.
PREC_APP="$RUN/yura-precedence"
cp /usr/bin/python3 "$PREC_APP"; chmod 755 "$PREC_APP"
RULE_M="66666666-0000-4000-8000-000000000006"
RULE_G="77777777-0000-4000-8000-000000000007"
PREC_PID="$(start_client_as "$PREC_APP" prec)"; BG+=("$PREC_PID")
check "daemon applies the game profile (order 200 -> proxy B)" ctl apply-rule "$(exe_rule "$RULE_G" "game profile" "$PREC_APP" proxy "\"$PROXY_B_ID\"" 200 gameProfile)"
check "daemon applies the manual rule above it (order 100 -> proxy A)" ctl apply-rule "$(exe_rule "$RULE_M" "manual selection" "$PREC_APP" proxy "\"$PROXY_A_ID\"" 100 manual)"
T_P="$(date +%s.%N)"
sleep 6
check "9: both rules cover the process, so it sits in one group naming both" bash -c "
  ctl() { '$DAEMON' ctl --socket '$SOCK' \"\$@\"; }
  ctl dump-ruleset | python3 -c \"
import json,sys
r=json.load(sys.stdin)
groups=[l for l in r['ruleset'].splitlines() if 'manual selection' in l and 'game profile' in l]
assert groups, 'no cgroup lists both rules'
print(groups[0].strip())\""
check "9: the higher-priority manual rule wins at the kernel" lq assert "$RUN/client-prec.jsonl" --event tcp --since "$T_P" --window 3 --min-count 2 --expect-ok true --expect-contains "$MARK_A"
# Reversing the order must reverse the outcome, or the first result proved nothing.
check "daemon re-orders the game profile above the manual rule" ctl apply-rule "$(exe_rule "$RULE_G" "game profile" "$PREC_APP" proxy "\"$PROXY_B_ID\"" 50 gameProfile)"
T_P2="$(date +%s.%N)"
sleep 6
check "9: with the profile on top, the same process reaches the other proxy" lq assert "$RUN/client-prec.jsonl" --event tcp --since "$T_P2" --window 3 --min-count 2 --expect-ok true --expect-contains "$MARK_B"
ctl remove-rule "{\"ruleId\":\"$RULE_M\"}" > /dev/null
ctl remove-rule "{\"ruleId\":\"$RULE_G\"}" > /dev/null
kill -9 "$PREC_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
step "Acceptance 10: two applications sharing one runtime, only one selected"
# A stand-in Wine runtime: a private copy of the interpreter named like a Wine preloader,
# with a Windows executable in argv. That is exactly what Yura reads out of /proc to tell
# two Wine games apart, so the classification path under test is the real one. It is not a
# test of Wine itself.
WINE_RUNTIME="$RUN/wine64-preloader"
cp /usr/bin/python3 "$WINE_RUNTIME"; chmod 755 "$WINE_RUNTIME"
WINE_A_PID="$(start_client_as "$WINE_RUNTIME" alpha --wine-target 'Z:\games\alpha\alpha.exe')"; BG+=("$WINE_A_PID")
WINE_B_PID="$(start_client_as "$WINE_RUNTIME" beta --wine-target 'Z:\games\beta\beta.exe')"; BG+=("$WINE_B_PID")
info "both run $WINE_RUNTIME; alpha.exe is pid $WINE_A_PID, beta.exe is pid $WINE_B_PID"
RULE_W="88888888-0000-4000-8000-000000000008"
check "daemon applies a rule on the runtime narrowed to one Windows executable" ctl apply-rule \
  "$(exe_rule "$RULE_W" "alpha.exe via proxy A" "$WINE_RUNTIME" proxy "\"$PROXY_A_ID\"" 105 gameProfile ',"wineTargetExecutable":"Z:\\games\\alpha\\alpha.exe"')"
T_W="$(date +%s.%N)"
sleep 6
check "10: the selected game is proxied" lq assert "$RUN/client-alpha.jsonl" --event tcp --since "$T_W" --window 3 --min-count 2 --expect-ok true --expect-contains "$MARK_A"
check "10: the unrelated game on the same runtime is unaffected" lq assert "$RUN/client-beta.jsonl" --event tcp --since "$T_W" --window 3 --min-count 2 --expect-ok false
ctl remove-rule "{\"ruleId\":\"$RULE_W\"}" > /dev/null
kill -9 "$WINE_A_PID" "$WINE_B_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
step "Destination host names: matched from the traffic, not from the packet header"
HOST_APP="$RUN/yura-hostapp"
cp /usr/bin/python3 "$HOST_APP"; chmod 755 "$HOST_APP"
HOST_M_PID="$(start_client_as "$HOST_APP" hostmatch --http-host alpha.example.com)"; BG+=("$HOST_M_PID")
HOST_N_PID="$(start_client_as "$HOST_APP" hostmiss --http-host beta.invalid)"; BG+=("$HOST_N_PID")
RULE_H="99999999-0000-4000-8000-000000000009"
check "daemon applies a rule that matches on a destination name" ctl apply-rule \
  "$(exe_rule "$RULE_H" "*.example.com via proxy A" "$HOST_APP" proxy "\"$PROXY_A_ID\"" 106 manual ',"hosts":["*.example.com"]')"
T_H="$(date +%s.%N)"
sleep 6
check "a flow whose Host header matches the rule is proxied" lq assert "$RUN/client-hostmatch.jsonl" --event tcp --since "$T_H" --window 3 --min-count 2 --expect-ok true --expect-contains "$MARK_A"
check "a flow to a different name is not, though the same rule captured it" lq assert "$RUN/client-hostmiss.jsonl" --event tcp --since "$T_H" --window 3 --min-count 2 --expect-ok false
check "the daemon reports the learned name on the matched flows" bash -c "
  '$DAEMON' ctl --socket '$SOCK' list-flows | python3 -c \"
import json,sys
r=json.load(sys.stdin)
named=[f for f in r['flows'] if f.get('host')=='alpha.example.com']
assert named, 'no flow carries the sniffed host name'
print(f'{len(named)} flows attributed to alpha.example.com')\""
ctl remove-rule "{\"ruleId\":\"$RULE_H\"}" > /dev/null
kill -9 "$HOST_M_PID" "$HOST_N_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
step "DNS through the proxy, and the names it teaches the daemon"
DNS_APP="$RUN/yura-dnsapp"
cp /usr/bin/python3 "$DNS_APP"; chmod 755 "$DNS_APP"
DNS_PID="$(start_client_as "$DNS_APP" dns --dns-query "game.example.net@${UNREACHABLE}:53")"; BG+=("$DNS_PID")
RULE_D="aaaa0000-0000-4000-8000-00000000000d"
check "daemon applies a rule covering the resolver's process" ctl apply-rule "$(exe_rule "$RULE_D" "dns app via proxy A" "$DNS_APP" proxy "\"$PROXY_A_ID\"" 107)"
T_D="$(date +%s.%N)"
sleep 8
check "a proxied process resolves names through the proxy" lq assert "$RUN/client-dns.jsonl" --event dns --since "$T_D" --window 3 --min-count 2 --expect-ok true --expect-contains "$UNREACHABLE"
check "the resolver only ever saw the query arrive via proxy A" bash -c "
  n=\$(python3 '$LIB/logquery.py' count '$RUN/dns.jsonl' --event query)
  [[ \$n -ge 2 ]] && echo \"\$n queries answered\""
check "the daemon learned the name from the answer and attributes later flows to it" bash -c "
  '$DAEMON' ctl --socket '$SOCK' list-connections | python3 -c \"
import json,sys
r=json.load(sys.stdin)
named=[c for c in r['connections'] if c.get('host')=='game.example.net']
assert named, 'no connection to the resolved address carries its name'
print(f'{len(named)} connections attributed to game.example.net')\""
ctl remove-rule "{\"ruleId\":\"$RULE_D\"}" > /dev/null
kill -9 "$DNS_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
step "Proxy chains: every hop sees only its neighbours"
CHAIN_APP="$RUN/yura-chainapp"
cp /usr/bin/python3 "$CHAIN_APP"; chmod 755 "$CHAIN_APP"
CHAIN_ID="cccc0000-0000-4000-8000-00000000000c"
check "daemon accepts a chain of proxy A then proxy B" ctl set-proxies \
  "{\"proxies\":[{\"id\":\"$PROXY_A_ID\",\"name\":\"Proxy A\",\"protocol\":\"socks5\",\"host\":\"127.0.0.1\",\"port\":11080},{\"id\":\"$PROXY_B_ID\",\"name\":\"Proxy B\",\"protocol\":\"socks5\",\"host\":\"127.0.0.1\",\"port\":11081}],\"chains\":[{\"id\":\"$CHAIN_ID\",\"name\":\"A then B\",\"hops\":[\"$PROXY_A_ID\",\"$PROXY_B_ID\"]}]}"
CHAIN_PID="$(start_client_as "$CHAIN_APP" chain)"; BG+=("$CHAIN_PID")
RULE_C="bbbb0000-0000-4000-8000-00000000000b"
check "daemon applies a rule routing through the chain" ctl apply-rule "$(exe_rule "$RULE_C" "chained" "$CHAIN_APP" chain "\"$CHAIN_ID\"" 108)"
T_C="$(date +%s.%N)"
sleep 6
# Only proxy B rewrites to marker B, and only proxy A is dialled directly: receiving B's
# marker proves the flow crossed both hops in order.
check "traffic through the chain arrives with the last hop's marker" lq assert "$RUN/client-chain.jsonl" --event tcp --since "$T_C" --window 3 --min-count 2 --expect-ok true --expect-contains "$MARK_B"
check "the first hop was asked to reach the second, not the destination" bash -c "
  n=\$(python3 '$LIB/logquery.py' count '$RUN/proxy-a.jsonl' --event connect --since $T_C --where-contains requested=127.0.0.1:11081)
  [[ \$n -ge 2 ]] && echo \"proxy A dialled proxy B \$n times\""
check "a chain refuses UDP rather than silently losing it" bash -c "
  grep -q 'chain cannot relay UDP' '$RUN/daemon.log' && echo 'UDP dropped with a stated reason' || echo 'no UDP was attempted through the chain'"
ctl remove-rule "{\"ruleId\":\"$RULE_C\"}" > /dev/null
kill -9 "$CHAIN_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
step "The Connections view tells the three cases apart"
# C has held one connection open since before any rule touched it, so proxying C now is the
# only way to produce all three cases at once in one process.
RULE_P="dddd0000-0000-4000-8000-00000000000e"
check "daemon proxies a process that already had a connection open" ctl apply-rule "$(instance_rule "$RULE_P" "C via proxy A" "$PID_C" proxy "\"$PROXY_A_ID\"" 109)"
sleep 4
check "pre-existing connections are reported as still on their previous route" bash -c "
  '$DAEMON' ctl --socket '$SOCK' list-connections '{\"pid\":$PID_C}' | python3 -c \"
import json,sys
r=json.load(sys.stdin)
rows=r['connections']
prev=[c for c in rows if c['route']=='preExistingPreviousRoute']
assert prev, f'expected a pre-existing row among {[c[\\\"route\\\"] for c in rows]}'
print(f\\\"{len(prev)} row(s) marked pre-existing, e.g. {prev[0]['remote']}: {prev[0]['note']}\\\")\""
check "the same process's new connections are reported as confirmed proxied" bash -c "
  n=\$('$DAEMON' ctl --socket '$SOCK' list-connections '{\"pid\":$PID_C}' | python3 -c \"
import json,sys
print(sum(1 for c in json.load(sys.stdin)['connections'] if c['route']=='confirmedProxied'))\")
  [[ \$n -ge 1 ]] && echo \"\$n confirmed-proxied row(s) alongside the pre-existing one\""
check "measurement reports direct and routed against one target, in the same units" bash -c "
  '$DAEMON' ctl --socket '$SOCK' measure '{\"measure\":{\"host\":\"$LOCAL_ADDR\",\"port\":18080,\"proxyId\":\"$PROXY_A_ID\",\"samples\":3}}' | python3 -c \"
import json,sys
m=json.load(sys.stdin)['measurement']
assert m['direct']['successes']==3, m['direct']
assert m['routed']['successes']==3, m['routed']
print(f\\\"direct {m['direct']['latencyMilliseconds']:.1f} ms vs routed {m['routed']['latencyMilliseconds']:.1f} ms over {m['method']}\\\")\""
check "the daemon can dump exactly what it installed" bash -c "
  '$DAEMON' ctl --socket '$SOCK' dump-ruleset | python3 -c \"
import json,sys
text=json.load(sys.stdin)['ruleset']
for needle in ('chain classify','chain capture','ip rule show','process groups'):
    assert needle in text, needle
print('ruleset, routing and group membership all reported')\""

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
