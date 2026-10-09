#!/usr/bin/env bash
#
# Checks Yura's own title bar and frame in a real window manager: KWin, nested and offscreen,
# with a D-Bus session and a configuration of its own, so nothing appears on the desktop and
# nothing of the running session is touched.
#
# Xvfb has no window manager, so the screenshots taken there cannot show whether the window can
# be moved, resized, maximised or closed. This drives all of that the way a pointer would,
# through the X server KWin starts for X11 clients (Yura is one), and reads back what KWin did:
#
#   - the window asks for no decorations, and has an alpha channel for its shadow and corners
#   - dragging the title bar moves it, and dragging the frame's edge resizes it
#   - a double click maximises it, and the restore button puts it back where it was
#   - minimise hides it, and close closes it, process and all
#   - with "Use the desktop's title bar" set, KWin decorates it instead
#
# It also saves a composited screenshot of each kind of frame into docs/screenshots.
#
# Needs kwin_wayland with Xwayland, xdotool, xprop, xwininfo, spectacle and ImageMagick. Runs
# the app with --demo only, so it never reaches the real daemon.
#
# Usage: tools/check-window.sh [--no-screenshots]
#
# YURA_APP=artifacts/yura-linux-x64/Yura.App checks a published build instead of the
# development one.

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"
SCREEN_W=1600
SCREEN_H=1000

# ---- inside the nested KWin, which starts this script again as its session ---------------
if [[ -n "${YURA_CHECK_RESULTS:-}" ]]; then
  RESULTS="$YURA_CHECK_RESULTS"
  SHOTS="$YURA_CHECK_SHOTS"
  CAPTURE="$YURA_CHECK_CAPTURE"
  APP="${YURA_APP:-$ROOT/src/Yura.App/bin/Debug/net10.0/Yura.App}"

  pass() { echo "PASS $1" >> "$RESULTS"; }
  fail() { echo "FAIL $1 — $2" >> "$RESULTS"; }
  expect() { if eval "$2"; then pass "$1"; else fail "$1" "$3"; fi; }

  start_app() {
    # Without the Wayland socket, which spectacle needs and Yura, drawing for X11, does not.
    WAYLAND_DISPLAY= "$APP" --demo --page games "$@" > "$SHOTS/app.log" 2>&1 &
    PID=$!
    WID=""
    for _ in $(seq 1 120); do
      WID=$(xdotool search --onlyvisible --classname Yura.App 2>/dev/null | head -1)
      [[ -n "$WID" ]] && break
      sleep 0.25
    done
    sleep 3
  }
  geometry() { eval "$(xdotool getwindowgeometry --shell "$WID")"; }
  state() { xprop -id "$WID" _NET_WM_STATE 2>/dev/null; }
  # Press, wait for the window manager to take the pointer, then move in steps and let go. A
  # resize waits for the app to repaint at every step, and offscreen it paints in software, so
  # the steps there are slower or the release overtakes them.
  drag() {  # x y dx dy [seconds per step]
    xdotool mousemove "$1" "$2" mousedown 1
    sleep 0.6
    for _ in $(seq 10); do xdotool mousemove_relative -- "$(($3 / 10))" "$(($4 / 10))"; sleep "${5:-0.08}"; done
    sleep 0.5
    xdotool mouseup 1
    sleep 1
  }
  shoot() {  # file
    [[ "$CAPTURE" == 1 ]] || return 0
    rm -f "$SHOTS/screen.png"
    spectacle -b -n -f -o "$SHOTS/screen.png" > /dev/null 2>&1 || return
    # Spectacle can return before the file is written.
    for _ in $(seq 1 40); do [[ -s "$SHOTS/screen.png" ]] && break; sleep 0.25; done
    sleep 0.5
    geometry
    local margin=40
    local x=$((X > margin ? X - margin : 0)) y=$((Y > margin ? Y - margin : 0))
    magick "$SHOTS/screen.png" -background '#4F6382' -flatten \
      -crop "$((WIDTH + 2 * margin))x$((HEIGHT + 2 * margin))+$x+$y" +repage "$1"
  }

  start_app
  if [[ -z "$WID" ]]; then
    fail "the window appears" "no window; see $SHOTS/app.log"
    exit 0
  fi
  # The first synthetic input of a session is lost while KWin connects the X server's input
  # emulation, so spend it on a move to a corner the window does not cover.
  xdotool mousemove 2 2
  sleep 1
  # The frame Avalonia draws: a 10-DIP shadow and a 1-DIP line on every side.
  CONTENT_W=1280 CONTENT_H=800 FRAME=11
  geometry
  expect "the window asks the window manager for no decorations" \
    "xprop -id $WID _MOTIF_WM_HINTS | grep -q '= 0x3, 0x[0-9a-f]*, 0x0,'" "$(xprop -id "$WID" _MOTIF_WM_HINTS)"
  expect "it has an alpha channel, for the shadow and the rounded corners" \
    "xwininfo -id $WID | grep -q 'Depth: 32'" "$(xwininfo -id "$WID" | grep Depth)"
  expect "the frame surrounds the content instead of eating into it" \
    "[[ $WIDTH -eq $((CONTENT_W + 2 * FRAME)) && $HEIGHT -eq $((CONTENT_H + 2 * FRAME)) ]]" "${WIDTH}x${HEIGHT}"
  shoot "$ROOT/docs/screenshots/38-window-frame-kwin-demo.png"

  X0=$X Y0=$Y
  drag $((X + 700)) $((Y + FRAME + 18)) 100 60
  geometry
  expect "dragging the title bar moves the window" \
    "[[ $((X - X0)) -ge 50 && $((Y - Y0)) -ge 30 ]]" "moved by $((X - X0)),$((Y - Y0))"

  # Inwards: the move has just put the right edge near the screen's, where the pointer stops.
  W0=$WIDTH
  drag $((X + WIDTH - 5)) $((Y + HEIGHT / 2)) -120 0 0.3
  geometry
  expect "dragging the frame's edge resizes it" "[[ $((W0 - WIDTH)) -ge 100 ]]" "narrower by $((W0 - WIDTH))"

  XN=$X YN=$Y WN=$WIDTH HN=$HEIGHT
  xdotool mousemove $((X + 700)) $((Y + FRAME + 18)) click --repeat 2 --delay 100 1
  sleep 1.5
  geometry
  expect "a double click on the title bar maximises it" \
    "state | grep -q MAXIMIZED_HORZ && [[ $WIDTH -eq $SCREEN_W && $HEIGHT -eq $SCREEN_H ]]" "${WIDTH}x${HEIGHT} $(state)"

  # Maximised, there is no frame: the buttons are at the very top right.
  xdotool mousemove $((X + WIDTH - 46 - 23)) $((Y + 18)) click 1
  sleep 1.5
  geometry
  expect "the restore button puts it back where it was" \
    "! state | grep -q MAXIMIZED && [[ $X -eq $XN && $Y -eq $YN && $WIDTH -eq $WN && $HEIGHT -eq $HN ]]" \
    "${X},${Y} ${WIDTH}x${HEIGHT} $(state)"

  xdotool mousemove $((X + WIDTH - FRAME - 46 * 2 - 23)) $((Y + FRAME + 18)) click 1
  sleep 1.5
  expect "the minimise button hides it" "state | grep -q HIDDEN" "$(state)"

  xdotool windowactivate "$WID"
  sleep 1.5
  geometry
  xdotool mousemove $((X + WIDTH - FRAME - 23)) $((Y + FRAME + 18)) click 1
  for _ in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || break; sleep 0.25; done
  expect "the close button closes it, and the process exits" "! kill -0 $PID 2>/dev/null" "still running"
  kill "$PID" 2>/dev/null

  CONFIG="$(mktemp -d)"
  echo '{"version":1,"settings":{"theme":"dark","language":"en","useSystemTitleBar":true}}' > "$CONFIG/config.json"
  start_app --config-dir "$CONFIG"
  geometry
  expect "with the desktop's title bar set, KWin decorates the window" \
    "xprop -id $WID _NET_FRAME_EXTENTS | grep -qv '= 0, 0, 0, 0' && ! xprop -id $WID _MOTIF_WM_HINTS | grep -q '= 0x3, 0x[0-9a-f]*, 0x0,'" \
    "$(xprop -id "$WID" _NET_FRAME_EXTENTS _MOTIF_WM_HINTS | tr '\n' ' ')"
  expect "and the window is the content alone" "[[ $WIDTH -eq $CONTENT_W && $HEIGHT -eq $CONTENT_H ]]" "${WIDTH}x${HEIGHT}"
  shoot "$ROOT/docs/screenshots/39-window-desktop-frame-kwin-demo.png"
  kill "$PID" 2>/dev/null
  rm -rf "$CONFIG"
  exit 0
fi

# ---- outside: start the nested KWin and report ---------------------------------------------
SHOTS="$(mktemp -d)"
[[ "${1:-}" == "--no-screenshots" ]] && CAPTURE=0 || CAPTURE=1
RESULTS="$SHOTS/results"
: > "$RESULTS"

APP="${YURA_APP:-$ROOT/src/Yura.App/bin/Debug/net10.0/Yura.App}"
if [[ -z "${YURA_APP:-}" ]]; then
  dotnet build src/Yura.App/Yura.App.csproj -v q -nologo > "$SHOTS/build.log" 2>&1 || {
    echo "the app did not build; see $SHOTS/build.log" >&2
    exit 1
  }
fi

# A configuration of its own: XTEST input from xdotool reaches the session only when KWin is
# told not to ask whether an X11 program may control the pointer, and nobody is there to answer.
mkdir -p "$SHOTS/config"
printf '[Xwayland]\nXwaylandEisNoPrompt=true\n' > "$SHOTS/config/kwinrc"

XDG_CONFIG_HOME="$SHOTS/config" YURA_CHECK_RESULTS="$RESULTS" YURA_CHECK_SHOTS="$SHOTS" \
  YURA_CHECK_CAPTURE="$CAPTURE" YURA_APP="$APP" \
  timeout 240 dbus-run-session -- \
  kwin_wayland --virtual --xwayland --width "$SCREEN_W" --height "$SCREEN_H" \
  --socket "wayland-yura-check-$$" --no-lockscreen --no-global-shortcuts \
  --exit-with-session "$ROOT/tools/check-window.sh" \
  > "$SHOTS/kwin.log" 2>&1

cat "$RESULTS"
passed=$(grep -c '^PASS' "$RESULTS")
failed=$(grep -c '^FAIL' "$RESULTS")
echo "$passed passed, $failed failed (logs in $SHOTS)"
[[ $failed -eq 0 && $passed -gt 0 ]]
