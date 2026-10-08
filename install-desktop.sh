#!/usr/bin/env bash
#
# Installs Yura for the current user: the app, its application-menu entry and its icon.
#
#   ./install-desktop.sh              install the native build, publishing it first if there is none
#   ./install-desktop.sh --rebuild    publish a fresh native build, then install it
#   ./install-desktop.sh --uninstall  remove the menu entry, the icon and the installed app
#
# The app is copied out of the repository, to ~/.local/share/yura/app, so the menu entry keeps
# working whatever happens to the checkout, and a later publish never changes an app that is
# running. Nothing here needs root. The daemon is installed from the app itself: Settings → Service.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

data="${XDG_DATA_HOME:-$HOME/.local/share}"
home="$data/yura"
app_dir="$home/app"
desktop_file="$data/applications/yura.desktop"
icons="$data/icons/hicolor"
build="artifacts/yura-linux-x64"
png_sizes=(48 128 256)

mode=install
rebuild=0
for arg in "$@"; do
  case "$arg" in
    --rebuild) rebuild=1 ;;
    --uninstall) mode=uninstall ;;
    -h | --help) sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg (see --help)" >&2; exit 2 ;;
  esac
done

# Menus and icon themes cache what they found; told now, the entry appears without a re-login.
refresh() {
  if command -v update-desktop-database >/dev/null; then
    update-desktop-database -q "$data/applications" 2>/dev/null || true
  fi
  if command -v gtk-update-icon-cache >/dev/null && [[ -f "$icons/index.theme" ]]; then
    gtk-update-icon-cache -q -t "$icons" 2>/dev/null || true
  fi
  for sycoca in kbuildsycoca6 kbuildsycoca5; do
    if command -v "$sycoca" >/dev/null; then
      "$sycoca" >/dev/null 2>&1 || true
      break
    fi
  done
}

if [[ $mode == uninstall ]]; then
  rm -f "$desktop_file" "$icons/scalable/apps/yura.svg"
  for size in "${png_sizes[@]}"; do
    rm -f "$icons/${size}x${size}/apps/yura.png"
  done
  rm -rf "$app_dir"
  rmdir "$home" 2>/dev/null || true
  refresh
  echo "Removed the menu entry, the icon and $app_dir."
  echo "A daemon installed as a service is not touched here: remove it from the app first, Settings → Service."
  exit 0
fi

# ---- the build
if [[ $rebuild -eq 1 || ! -x "$build/Yura.App" ]]; then
  echo "==> publishing a native build (tools/publish.sh)"
  tools/publish.sh
fi
[[ -x "$build/Yura.App" && -x "$build/yura-daemon" ]] || {
  echo "no native build at $build; run tools/publish.sh and look at what it says" >&2
  exit 1
}

# ---- the app, beside its daemon: Settings → Service installs the daemon it finds there.
# Copied whole into a new directory and swapped in with a rename, so an app that is running
# keeps the files it started from instead of having them rewritten under it.
echo "==> installing the app to $app_dir"
mkdir -p "$home"
staging="$(mktemp -d "$home/.app.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
cp -a "$build/." "$staging/"
chmod 755 "$staging"
if [[ -d "$app_dir" ]]; then
  previous="$home/.app.previous.$$"
  mv "$app_dir" "$previous"
  mv "$staging" "$app_dir"
  rm -rf "$previous"
else
  mv "$staging" "$app_dir"
fi
trap - EXIT

# ---- the icon, as SVG and as PNG for anything that does not draw SVG
echo "==> installing the icon"
install -Dm644 packaging/yura.svg "$icons/scalable/apps/yura.svg"
if command -v rsvg-convert >/dev/null; then
  for size in "${png_sizes[@]}"; do
    mkdir -p "$icons/${size}x${size}/apps"
    rsvg-convert -w "$size" -h "$size" packaging/yura.svg -o "$icons/${size}x${size}/apps/yura.png"
  done
fi

# ---- the menu entry
# StartupWMClass is the app's X11 window class (Avalonia takes it from the entry assembly), which
# is how the desktop puts the running window under this entry and its icon. Under Wayland the
# app still runs through XWayland, so the same class applies there.
echo "==> installing the menu entry $desktop_file"
mkdir -p "$data/applications"
cat > "$desktop_file" <<EOF
[Desktop Entry]
Type=Application
Version=1.5
Name=Yura
GenericName=Per-process routing
GenericName[zh_CN]=按进程路由
Comment=Route chosen programs and games through a proxy, a WireGuard exit or a Yura agent
Comment[zh_CN]=让选定的程序和游戏经由代理、WireGuard 出口或 Yura 代理端联网
Exec="$app_dir/Yura.App"
TryExec=$app_dir/Yura.App
Icon=yura
Terminal=false
Categories=Network;
Keywords=proxy;routing;game;boost;latency;wireguard;socks;agent;
Keywords[zh_CN]=代理;路由;游戏;加速;延迟;
StartupNotify=true
StartupWMClass=Yura.App
EOF
chmod 644 "$desktop_file"

if command -v desktop-file-validate >/dev/null; then
  desktop-file-validate "$desktop_file"
fi

refresh

built="$(date -r "$app_dir/Yura.App" '+%Y-%m-%d %H:%M')"
echo
echo "Yura (built $built) is in the application menu, and runs from $app_dir/Yura.App."
echo "To install the daemon as a service, open Yura: Settings → Service."
echo "Run ./install-desktop.sh again after a new build to update it; --uninstall removes it."
