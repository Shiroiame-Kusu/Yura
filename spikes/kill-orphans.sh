#!/usr/bin/env bash
#
# Kills spike helper processes left behind by an interrupted run.
#
# Lives in a file rather than being typed at a shell on purpose: a `pkill -f` pattern typed
# interactively also matches the invoking shell's own command line, so the cleanup kills the
# thing running it.

set -uo pipefail

killed=0
for name in marker_server socks5_proxy tproxy_forwarder spike_client; do
  while read -r pid; do
    [[ -z "$pid" || "$pid" == "$$" ]] && continue
    kill -9 "$pid" 2>/dev/null && killed=$((killed + 1))
  done < <(pgrep -f "lib/${name}\.py" 2>/dev/null)
done

echo "killed ${killed} orphaned spike process(es)"
