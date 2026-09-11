#!/usr/bin/env bash
#
# Publishes the agent as one self-contained file per architecture, so a server needs nothing
# installed to run it — not even .NET.
#
# Usage:  tools/publish-agent.sh [linux-x64|linux-arm64 ...]
#
# The result is artifacts/yura-agent-<rid>/yura-agent. Copy it to the server, run
# "sudo ./yura-agent install", and paste the connect string it prints into Yura.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

rids=("$@")
[[ ${#rids[@]} -eq 0 ]] && rids=(linux-x64 linux-arm64)

for rid in "${rids[@]}"; do
  out="artifacts/yura-agent-${rid}"
  echo "==> ${rid}"
  # Not trimmed: the certificate and TLS stacks use enough reflection that a trimmed build is
  # a risk taken for a smaller file nobody is counting the bytes of.
  dotnet publish src/Yura.Agent \
    --configuration Release \
    --runtime "${rid}" \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:DebugType=none \
    --output "${out}" \
    --verbosity quiet
  printf '    %s (%s)\n' "${out}/yura-agent" "$(du -h "${out}/yura-agent" | cut -f1)"
done

cat <<'EOF'

On the server:

    sudo ./yura-agent install            # service, hardened unit, prints the connect string
    sudo ./yura-agent show               # print it again
    sudo ./yura-agent rotate             # replace the token if it leaks

Open the port it prints, TCP and UDP both — the datagram channel is what carries a game's
traffic, and without it only TCP is accelerated.
EOF
