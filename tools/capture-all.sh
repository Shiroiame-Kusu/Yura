#!/usr/bin/env bash
#
# Captures the screenshot set used for design and usability review.
#
# Covers the matrix the specification asks to be verified: both themes, both languages,
# the reference and minimum window sizes, fractional and integer scaling, and the empty /
# populated / disconnected states.
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

echo
echo "captured $(ls -1 "$OUT"/*.png | wc -l) screenshots into $OUT"
