#!/usr/bin/env bash
#
# Publishes the desktop app and the daemon as NativeAOT binaries, side by side, which is where
# the app looks for the daemon when Settings installs it as a service.
#
# Usage:  tools/publish.sh [linux-x64|linux-arm64]      (default: this machine's architecture)
#
# The result is artifacts/yura-<rid>/: Yura.App, yura-daemon, and the two native libraries the
# UI draws with. Nothing else is needed, not even .NET: run ./Yura.App from there. The service
# Settings installs then runs the native yura-daemon directly.
#
# Both binaries are linked against this machine's glibc and run where glibc is at least as new,
# so publish on the oldest system they are meant for. The agent goes to a server instead; see
# tools/publish-agent.sh, or ./deploy-agent.sh.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

case "$(uname -m)" in
  x86_64) host=linux-x64 ;;
  aarch64 | arm64) host=linux-arm64 ;;
  *) host="" ;;
esac
rid="${1:-$host}"
[[ -n "$rid" ]] || { echo "this machine's architecture ($(uname -m)) has no Yura build" >&2; exit 1; }

out="artifacts/yura-${rid}"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# A clean directory: a yura-daemon.dll left from a framework-dependent build would make the app
# run that instead, through a dotnet host the machine may not have.
rm -rf "$out"

for project in src/Yura.App src/Yura.Daemon; do
  echo "==> ${project} (${rid})"
  dotnet publish "$project" \
    --configuration Release \
    --runtime "$rid" \
    -p:DebugType=none \
    --output "$out" \
    --verbosity quiet > "$log" 2>&1 || {
    cat "$log" >&2
    [[ "$rid" != "$host" ]] && echo "NativeAOT links for its own architecture only, unless a cross toolchain is installed" >&2
    exit 1
  }
done
rm -f "$out"/*.dbg "$out"/*.pdb

glibc="$(cat "$out/Yura.App" "$out/yura-daemon" | grep -ao 'GLIBC_2\.[0-9]*' | sed 's/^GLIBC_//' | sort -uV | tail -1)"
echo
for file in Yura.App yura-daemon libSkiaSharp.so libHarfBuzzSharp.so; do
  printf '    %-20s %s\n' "$file" "$(du -h "$out/$file" | cut -f1)"
done
cat <<EOF

${out}/ needs glibc ${glibc} or newer, and nothing else. Run it with:

    ${out}/Yura.App

Settings → Service installs the yura-daemon beside it as the system service.
EOF
