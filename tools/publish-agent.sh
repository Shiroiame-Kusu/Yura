#!/usr/bin/env bash
#
# Publishes the agent as one file per architecture, so a server needs nothing installed to run
# it — not even .NET.
#
# Usage:  tools/publish-agent.sh [--self-contained] [linux-x64|linux-arm64 ...]
#
# NativeAOT wherever this machine can build it: a native binary of a few megabytes that starts at
# once and compiles nothing at run time. Two limits come with it. It is linked against this
# machine's C library, so it runs only where glibc is at least the version it binds to; that
# version is written beside it, in "glibc". And it can only be linked for this machine's own
# architecture unless a cross toolchain is installed. For any other architecture, or with
# --self-contained, the agent is published as it was before NativeAOT: one self-contained file
# with the .NET runtime inside, larger, and able to run on any glibc .NET supports.
#
# The result is artifacts/yura-agent-<rid>/yura-agent. Copy it to the server, run
# "sudo ./yura-agent install", and paste the connect string it prints into Yura;
# ./deploy-agent.sh does all of that, and picks the form the server can run.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

mode=native
rids=()
for argument in "$@"; do
  case "$argument" in
    --self-contained) mode=self-contained ;;
    -*) echo "unknown option: $argument" >&2; exit 2 ;;
    *) rids+=("$argument") ;;
  esac
done
[[ ${#rids[@]} -eq 0 ]] && rids=(linux-x64 linux-arm64)

case "$(uname -m)" in
  x86_64) host=linux-x64 ;;
  aarch64 | arm64) host=linux-arm64 ;;
  *) host="" ;;
esac

publish() {  # rid out [extra msbuild arguments]
  local rid="$1" out="$2"
  shift 2
  rm -rf "$out"
  dotnet publish src/Yura.Agent \
    --configuration Release \
    --runtime "$rid" \
    -p:DebugType=none \
    --output "$out" \
    --verbosity quiet \
    "$@" &&
    rm -f "$out"/*.dbg "$out"/*.pdb  # symbols, possibly from an earlier build; no server needs them
}

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

for rid in "${rids[@]}"; do
  out="artifacts/yura-agent-${rid}"
  echo "==> ${rid}"

  if [[ "$mode" == native ]] && publish "$rid" "$out" > "$log" 2>&1; then
    # The newest symbol version the binary binds to is the oldest glibc it can run on.
    glibc="$(grep -ao 'GLIBC_2\.[0-9]*' "$out/yura-agent" | sed 's/^GLIBC_//' | sort -uV | tail -1)"
    printf '%s\n' "$glibc" > "$out/glibc"
    printf '    %s (%s): NativeAOT, for glibc %s or newer\n' "$out/yura-agent" "$(du -h "$out/yura-agent" | cut -f1)" "$glibc"
    continue
  fi

  if [[ "$mode" == native && "$rid" == "$host" ]]; then
    # On its own architecture NativeAOT has everything it needs, so a failure is a real one.
    cat "$log" >&2
    exit 1
  fi

  if [[ "$mode" == native ]]; then
    echo "    NativeAOT cannot link for ${rid} on this ${host:-unknown} machine without a cross toolchain;"
    echo "    publishing it self-contained instead"
  fi

  # The same agent with the runtime inside, compiled as it runs. Untrimmed, as it always was.
  publish "$rid" "$out" -p:PublishAot=false --self-contained true -p:PublishSingleFile=true > "$log" 2>&1 || {
    cat "$log" >&2
    exit 1
  }
  printf '    %s (%s): self-contained .NET\n' "$out/yura-agent" "$(du -h "$out/yura-agent" | cut -f1)"
done

cat <<'EOF'

On the server:

    sudo ./yura-agent install            # service, hardened unit, prints the connect string
    sudo ./yura-agent show               # print it again
    sudo ./yura-agent rotate             # replace the token if it leaks

Open the port it prints, TCP and UDP both — the datagram channel is what carries a game's
traffic, and without it only TCP is accelerated.
EOF
