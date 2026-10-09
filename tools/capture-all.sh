#!/usr/bin/env bash
#
# Captures the screenshot set used for design and usability review.
#
# Covers the matrix the specification asks to be verified: every page, both themes, both
# languages, the reference and minimum window sizes, fractional and integer scaling, and the
# empty / populated / disconnected / error states.
#
# Screenshots whose name contains "demo" are rendered against a SIMULATED daemon. They show
# what a connected, populated UI looks like; they are not evidence that routing works.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

OUT="docs/screenshots"
mkdir -p "$OUT"

shot() { ./tools/screenshot.sh "$@"; }

echo "== themes: Processes at the reference size =="
shot --out "$OUT/01-processes-dark.png"  --page processes --theme dark
shot --out "$OUT/02-processes-light.png" --page processes --theme light

echo "== populated states (simulated daemon) =="
shot --out "$OUT/03-games-dark-demo.png"      --page games    --theme dark  --demo
shot --out "$OUT/04-games-light-demo.png"     --page games    --theme light --demo
# Tall enough for the whole session monitor: its tiles, both charts, and the table under them.
shot --out "$OUT/37-games-monitor-dark-demo.png" --page games --theme dark --size 1280x1500 --demo
shot --out "$OUT/05-proxy-editor-dark-demo.png"  --page proxies --theme dark  --demo
shot --out "$OUT/06-proxy-editor-light-demo.png" --page proxies --theme light --demo

echo "== Simplified Chinese =="
shot --out "$OUT/07-processes-zh.png" --page processes --theme dark  --lang zh-Hans
shot --out "$OUT/08-games-zh-demo.png"  --page games    --theme dark  --lang zh-Hans --demo
shot --out "$OUT/09-proxy-editor-zh-demo.png" --page proxies --theme light --lang zh-Hans --demo

echo "== minimum supported window (960x640) =="
shot --out "$OUT/10-processes-min.png" --page processes --theme dark --size 960x640
shot --out "$OUT/11-games-min-demo.png"  --page games  --theme dark --size 960x640 --demo

echo "== scaling =="
shot --out "$OUT/12-processes-125.png" --page processes --theme dark --scale 1.25
shot --out "$OUT/13-processes-150.png" --page processes --theme dark --scale 1.5
shot --out "$OUT/14-processes-200.png" --page processes --theme dark --scale 2

echo "== the remaining pages =="
shot --out "$OUT/17-connections-dark-demo.png"  --page connections --theme dark  --demo
shot --out "$OUT/18-connections-light-demo.png" --page connections --theme light --demo
shot --out "$OUT/19-rules-dark-demo.png"        --page rules       --theme dark  --demo
shot --out "$OUT/20-rules-light-demo.png"       --page rules       --theme light --demo
shot --out "$OUT/21-diagnostics-dark-demo.png"  --page diagnostics --theme dark  --demo
shot --out "$OUT/22-settings-dark-demo.png"     --page settings    --theme dark  --demo

echo "== the remaining pages in Chinese, and at the minimum size =="
shot --out "$OUT/23-connections-zh-demo.png" --page connections --theme dark --lang zh-Hans --demo
shot --out "$OUT/24-rules-zh-demo.png"       --page rules       --theme dark --lang zh-Hans --demo
shot --out "$OUT/25-settings-zh-demo.png"    --page settings    --theme dark --lang zh-Hans --demo
shot --out "$OUT/26-connections-min-demo.png" --page connections --theme dark --size 960x640 --demo
shot --out "$OUT/27-rules-min-demo.png"       --page rules       --theme dark --size 960x640 --demo

echo "== WireGuard exits, chains and the service section =="
shot --out "$OUT/30-proxies-wireguard-dark-demo.png"  --page proxies  --theme dark  --demo --demo-editor wireguard
shot --out "$OUT/31-proxies-chain-light-demo.png"     --page proxies  --theme light --demo --demo-editor chain
shot --out "$OUT/32-settings-light-demo.png"          --page settings --theme light --demo
shot --out "$OUT/33-settings-min-demo.png"            --page settings --theme dark  --size 960x640 --demo
shot --out "$OUT/34-proxies-min-demo.png"             --page proxies  --theme dark  --size 960x640 --demo --demo-editor wireguard
shot --out "$OUT/35-proxies-wireguard-zh-demo.png"    --page proxies  --theme dark  --lang zh-Hans --demo --demo-editor wireguard
# The real service manager and the real systemd, asked about a unit that is installed nowhere,
# so the shot is the not-installed page wherever it is taken, this machine's own service or not.
NOT_INSTALLED="$(mktemp -d)"
cat > "$NOT_INSTALLED/systemctl" <<'STUB'
#!/usr/bin/env bash
args=()
for a in "$@"; do
  [[ $a == yura-daemon.service ]] && a=yura-screenshot-not-installed.service
  args+=("$a")
done
exec /usr/bin/systemctl "${args[@]}"
STUB
chmod +x "$NOT_INSTALLED/systemctl"
PATH="$NOT_INSTALLED:$PATH" shot --out "$OUT/36-settings-not-installed.png" --page settings --theme dark
rm -rf "$NOT_INSTALLED"

echo "== disconnected: the default, with no daemon =="
shot --out "$OUT/28-connections-disconnected.png" --page connections --theme dark
shot --out "$OUT/29-diagnostics-disconnected.png" --page diagnostics --theme dark

echo
echo "captured $(ls -1 "$OUT"/*.png | wc -l) screenshots into $OUT"
