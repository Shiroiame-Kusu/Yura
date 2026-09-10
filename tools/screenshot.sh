#!/usr/bin/env bash
#
# Renders Yura offscreen and captures a PNG.
#
# Uses Xvfb rather than the live session so captures are deterministic: an exact surface
# size, a known scale factor, no compositor decorations and no other windows. That is what
# makes it meaningful to compare two screenshots, or to check a layout at 200% scaling
# without owning a HiDPI display.
#
# Usage:
#   tools/screenshot.sh --out docs/screenshots/processes-dark.png \
#                       [--size 1280x800] [--scale 1] [--theme dark] [--lang en] \
#                       [--page processes] [--demo] [--settle 4]

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

OUT=""
SIZE="1280x800"
SCALE="1"
THEME="dark"
LANG_TAG="en"
PAGE="processes"
SETTLE="4"
DEMO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --size) SIZE="$2"; shift 2 ;;
    --scale) SCALE="$2"; shift 2 ;;
    --theme) THEME="$2"; shift 2 ;;
    --lang) LANG_TAG="$2"; shift 2 ;;
    --page) PAGE="$2"; shift 2 ;;
    --settle) SETTLE="$2"; shift 2 ;;
    --demo) DEMO="--demo"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$OUT" ]] || { echo "--out is required" >&2; exit 2; }

WIDTH="${SIZE%x*}"
HEIGHT="${SIZE#*x}"

# Xvfb needs the framebuffer sized in physical pixels, so a scaled run needs a
# proportionally larger screen or the window is clipped.
FB_WIDTH=$(python3 -c "print(int($WIDTH * $SCALE))")
FB_HEIGHT=$(python3 -c "print(int($HEIGHT * $SCALE))")

DISPLAY_NUM=$(( 90 + RANDOM % 8 ))
mkdir -p "$(dirname "$OUT")"

cleanup() {
  [[ -n "${APP_PID:-}" ]] && kill "$APP_PID" 2>/dev/null || true
  [[ -n "${XVFB_PID:-}" ]] && kill "$XVFB_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

Xvfb ":${DISPLAY_NUM}" -screen 0 "${FB_WIDTH}x${FB_HEIGHT}x24" -nolisten tcp >/dev/null 2>&1 &
XVFB_PID=$!
sleep 1

export DISPLAY=":${DISPLAY_NUM}"
# Force the X11 backend: the capture tools work against an X server, and Wayland would
# ignore the Xvfb display entirely.
unset WAYLAND_DISPLAY
export AVALONIA_GLOBAL_SCALE_FACTOR="$SCALE"

dotnet run --project src/Yura.App/Yura.App.csproj -v q -- \
  --screenshot-mode \
  --width "$WIDTH" --height "$HEIGHT" \
  --theme "$THEME" --lang "$LANG_TAG" --page "$PAGE" $DEMO \
  > /tmp/yura-screenshot.log 2>&1 &
APP_PID=$!

# Wait for a window to actually appear rather than sleeping blindly.
for _ in $(seq 1 "$((SETTLE * 4))"); do
  if xdotool search --onlyvisible --name "Yura" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
sleep "$SETTLE"

import -window root -display ":${DISPLAY_NUM}" "$OUT" 2>/dev/null || {
  echo "capture failed; app log:" >&2
  tail -30 /tmp/yura-screenshot.log >&2
  exit 1
}

echo "$(basename "$OUT")  ${WIDTH}x${HEIGHT} @${SCALE}x  ${THEME}  ${LANG_TAG}  ${PAGE}"
