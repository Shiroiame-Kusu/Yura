#!/usr/bin/env bash
#
# Puts a Yura agent on a server over SSH, and prints the connect string to paste into Yura.
#
# Usage:  ./deploy-agent.sh [-i key] [user@]host[:port] [password] [--no-firewall] [-- install options]
#
#   ./deploy-agent.sh 203.0.113.10                    as root, with your SSH keys
#   ./deploy-agent.sh 203.0.113.10:2222 'secret'      as root, with a password
#   ./deploy-agent.sh ubuntu@[2001:db8::10]           as a user with sudo, over IPv6
#   ./deploy-agent.sh -i oracle.key ubuntu@203.0.113.10  with a key file a cloud provider gave you
#   ./deploy-agent.sh 203.0.113.10 -- --name tokyo    options for "yura-agent install"
#
# Builds the agent for the server's architecture as one file, so the server needs nothing
# installed, not even .NET; copies it over; and runs "yura-agent install" there, which writes a
# hardened systemd unit, starts it, and prints the connect string. Run it again to upgrade: the
# key and token are kept, so the connect string stays the same. The file is a NativeAOT binary
# when this machine can build one the server can run, and a self-contained .NET one when the
# server's glibc is older than the binary needs or its architecture is not this machine's.
#
# The user is root unless you name another, or your SSH configuration does. A password is used
# to log in and, for a user other than root, for sudo. Without one, ssh uses your keys or asks.
# A password typed on the command line stays in your shell history; YURA_SSH_PASSWORD in the
# environment does the same job without that. Anything else ssh should be told goes in
# YURA_SSH_OPTIONS, e.g. "-o ProxyJump=bastion".
#
# If the server runs ufw or firewalld, the agent's ports are opened in it (--no-firewall leaves
# it alone). A cloud provider's security group is outside the server and has to be opened by
# hand: TCP and UDP 7311, and UDP 40000-40999 for peer-to-peer games.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() { awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "${BASH_SOURCE[0]}"; }
die() { printf 'deploy-agent: %s\n' "$*" >&2; exit 1; }
step() { printf '==> %s\n' "$*"; }

# Quotes one word for the server's shell, whichever POSIX shell that is.
shq() { printf "'%s'" "${1//\'/\'\\\'\'}"; }

# -- arguments ---------------------------------------------------------------

target="" password="${YURA_SSH_PASSWORD:-}" have_password=0 firewall=1
install_args=()
read -r -a ssh_extra <<< "${YURA_SSH_OPTIONS:-}"
while (($#)); do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --no-firewall) firewall=0 ;;
    -i)
      [[ -r "${2:-}" ]] || die "-i needs a readable key file"
      ssh_extra+=(-i "$2" -o IdentitiesOnly=yes); shift
      ;;
    --) shift; install_args=("$@"); break ;;
    *)
      if [[ -z "$target" ]]; then
        [[ "$1" == -* ]] && die "unknown option '$1'; options for the agent go after --"
        target="$1"
      elif ((!have_password)); then
        password="$1"; have_password=1
      else
        die "unexpected argument '$1'; options for the agent go after --"
      fi
      ;;
  esac
  shift
done
[[ -n "$target" ]] || { usage >&2; exit 2; }

user="" host="" port="" spec="$target"
if [[ "$spec" == *@* ]]; then user="${spec%@*}"; spec="${spec##*@}"; fi
bracketed='^\[([^]]+)\](:([0-9]+))?$'
with_port='^([^:]+):([0-9]+)$'
if [[ "$spec" =~ $bracketed ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]}"
elif [[ "$spec" =~ $with_port ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
else host="$spec"  # a name, an IPv4 address, or an IPv6 address written without a port
fi
[[ -n "$host" ]] || die "no host in '$target'"
if [[ -n "$port" ]]; then
  port=$((10#$port))
  ((port >= 1 && port <= 65535)) || die "'$port' is not a port"
fi

# What the agent will listen on, to open in a firewall: install's own defaults, unless overridden.
tcp=7311 udp="" cone=40000-40999 udp_on=1 cone_on=1 custom_host=0
for ((i = 0; i < ${#install_args[@]}; i++)); do
  case "${install_args[i]}" in
    --port) tcp="${install_args[i + 1]:-}" ;;
    --udp-port) udp="${install_args[i + 1]:-}" ;;
    --cone-ports) cone="${install_args[i + 1]:-}" ;;
    --no-udp) udp_on=0 ;;
    --no-full-cone) cone_on=0 ;;
    --host) custom_host=1 ;;
  esac
done
[[ -n "$udp" ]] || udp="$tcp"
((udp_on)) || udp=""
((udp_on && cone_on)) || cone=""

# -- ssh ---------------------------------------------------------------------

# ssh's own view of the target, so a Host entry in ~/.ssh/config is honoured: the address it
# really connects to is what goes into the connect string.
settings=(-G "${ssh_extra[@]}")
[[ -n "$port" ]] && settings+=(-p "$port")
[[ -n "$user" ]] && settings+=(-l "$user")
effective="$(ssh "${settings[@]}" "$host" 2>/dev/null)" || die "ssh cannot make sense of '$host'"
address="$(awk '$1 == "hostname" { print $2; exit }' <<< "$effective")"
if [[ -z "$user" ]]; then
  # ssh reports your own name when nothing configures another; a server you reach by its
  # address is far more likely to want root.
  configured="$(awk '$1 == "user" { print $2; exit }' <<< "$effective")"
  if [[ -n "$configured" && "$configured" != "$(id -un)" ]]; then user="$configured"; else user=root; fi
fi

work="$(mktemp -d)"
cleanup() {
  ssh -o "ControlPath=$work/ssh" -O exit "$host" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# One connection for everything, so a password is given, or asked for, once. A server never seen
# before is trusted on first use; one whose key has changed since is refused, as ssh always does.
ssh_options=(
  -o ControlMaster=auto -o "ControlPath=$work/ssh" -o ControlPersist=300
  -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -l "$user" "${ssh_extra[@]}"
)
[[ -n "$port" ]] && ssh_options+=(-p "$port")

if [[ -n "$password" ]]; then
  # Handed to ssh by its own askpass mechanism (OpenSSH 8.4 or later), through the environment
  # rather than an argument, so it never shows in the process list. Asked for once, so a wrong
  # one fails instead of looping, and without trying keys first: an agent holding several can
  # use up the server's attempts before the password is reached.
  printf '#!/bin/sh\nprintf "%%s\\n" "$YURA_SSH_PASSWORD"\n' > "$work/askpass"
  chmod 700 "$work/askpass"
  ssh_options+=(-o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1
    -o PreferredAuthentications=keyboard-interactive,password)
fi

# remote [-t] COMMAND: runs COMMAND on the server, in its login shell.
remote() {
  local tty=()
  if [[ "$1" == -t ]]; then tty=(-t); shift; fi
  if [[ -n "$password" ]]; then
    YURA_SSH_PASSWORD="$password" SSH_ASKPASS="$work/askpass" SSH_ASKPASS_REQUIRE=force \
      ssh "${ssh_options[@]}" "${tty[@]}" "$host" "$@"
  else
    ssh "${ssh_options[@]}" "${tty[@]}" "$host" "$@"
  fi
}

# -- the server --------------------------------------------------------------

step "Connecting to ${user}@${address}${port:+, port $port}"
probe="$(remote 'echo "yura-probe $(uname -s) $(uname -m) $(id -u)" \
  "$(command -v systemctl >/dev/null 2>&1 && echo systemd || echo none)" \
  "$(command -v sudo >/dev/null 2>&1 && echo sudo || echo none)" \
  "$(getconf GNU_LIBC_VERSION 2>/dev/null | sed -n "s/^glibc //p")"' | grep '^yura-probe ' | tail -1)" ||
  die "could not log in to ${user}@${address}"
read -r _ os machine uid init sudo glibc <<< "$probe"
[[ "$os" == Linux ]] || die "the server runs $os; the agent is built for Linux"
case "$machine" in
  x86_64 | amd64) rid=linux-x64 ;;
  aarch64 | arm64) rid=linux-arm64 ;;
  *) die "there is no agent build for a $machine server, only for x86_64 and aarch64" ;;
esac
[[ "$init" == systemd ]] ||
  die "the server has no systemd, which 'yura-agent install' sets the service up with; copy the agent over and run 'yura-agent run' under whatever starts services there"
[[ -n "$glibc" ]] || die "the server's C library is not glibc (Alpine's musl, say), and the agent is built for glibc"

as_root=""
if [[ "$uid" == 0 ]]; then
  :
elif [[ "$sudo" != sudo ]]; then
  die "${user} is not root and the server has no sudo; log in as root instead"
elif remote 'sudo -n true' >/dev/null 2>&1; then
  as_root="sudo -n"
elif [[ -n "$password" ]]; then
  as_root="sudo -S -p ''"  # given the password on its input
else
  as_root="sudo"           # asks, through a terminal
fi
printf '    %s %s, glibc %s, %s\n' "$os" "$machine" "$glibc" "$( ((uid == 0)) && echo root || echo "${user}, through sudo")"

# True when glibc $1 is at least $2.
glibc_at_least() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

build() {  # [--self-contained]
  "$ROOT/tools/publish-agent.sh" "$@" "$rid" > "$work/publish.log" 2>&1 || {
    cat "$work/publish.log" >&2
    die "the agent did not build"
  }
}

step "Building the agent for $rid"
build
built="$ROOT/artifacts/yura-agent-$rid"
# A NativeAOT build is linked against this machine's glibc and records the oldest it runs on.
if [[ -f "$built/glibc" ]] && ! glibc_at_least "$glibc" "$(cat "$built/glibc")"; then
  printf '    NativeAOT needs glibc %s and the server has %s; building it self-contained instead\n' "$(cat "$built/glibc")" "$glibc"
  build --self-contained
fi
binary="$built/yura-agent"
[[ -x "$binary" ]] || die "the build left nothing at $binary"
printf '    %s (%s), %s\n' "${binary#"$ROOT"/}" "$(du -h "$binary" | cut -f1)" \
  "$([[ -f "$built/glibc" ]] && echo "NativeAOT" || echo "self-contained .NET")"

# Runs as root on the server: installs the agent, opens its ports if a firewall there is managed
# by ufw or firewalld, and removes the copied files whatever happens.
read -r -d '' setup <<'SETUP' || true
set -eu
dir=$1 firewall=$2 tcp=$3 udp=$4 cone=$5
shift 5
trap 'rm -rf "$dir"' EXIT
exec </dev/null  # nothing here reads input; with sudo -S, whatever sudo left unread is the password

"$dir/yura-agent" install "$@"
[ "$firewall" = 1 ] || exit 0

ports="TCP $tcp${udp:+, UDP $udp}${cone:+, UDP $cone}"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow "$tcp/tcp" >/dev/null
  [ -z "$udp" ] || ufw allow "$udp/udp" >/dev/null
  [ -z "$cone" ] || ufw allow "$(printf %s "$cone" | tr - :)/udp" >/dev/null
  echo "Opened $ports in ufw."
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --quiet --permanent --add-port="$tcp/tcp"
  [ -z "$udp" ] || firewall-cmd --quiet --permanent --add-port="$udp/udp"
  [ -z "$cone" ] || firewall-cmd --quiet --permanent --add-port="$cone/udp"
  firewall-cmd --quiet --reload
  echo "Opened $ports in firewalld."
elif command -v iptables >/dev/null 2>&1 &&
     iptables -S INPUT 2>/dev/null | grep -Eq -- '^-P INPUT DROP|^-A INPUT -j (DROP|REJECT)'; then
  echo "This server's own iptables rules turn away incoming traffic, and neither ufw nor"
  echo "firewalld manages them: open $ports in them, or the agent cannot be reached."
else
  echo "No running ufw or firewalld was found here, so no firewall was changed."
fi
SETUP

step "Copying it to the server"
dir="$(remote 'mktemp -d "$HOME/.yura-agent.XXXXXX"' | tail -1)" || dir=""
[[ "$dir" == /* ]] || die "could not make a directory on the server"
remote "cat > $(shq "$dir/yura-agent") && chmod 0755 $(shq "$dir/yura-agent")" < "$binary"
printf '%s\n' "$setup" | remote "cat > $(shq "$dir/setup.sh")"

step "Installing"
[[ "$custom_host" == 1 ]] || install_args=(--host "$address" "${install_args[@]}")
command="${as_root:+$as_root }bash $(shq "$dir/setup.sh") $(shq "$dir") $firewall $(shq "$tcp") $(shq "$udp") $(shq "$cone")"
for argument in "${install_args[@]}"; do command+=" $(shq "$argument")"; done

run_install() {
  if [[ "$as_root" == sudo ]]; then
    remote -t "$command"
  elif [[ "$as_root" == sudo\ -S* ]]; then
    printf '%s\n' "$password" | remote "$command"
  else
    remote "$command"
  fi
}
run_install 2>&1 | tee "$work/install.log" || die "the install failed; what it printed is above"
connect="$(grep -o 'yura://[^[:space:]]*' "$work/install.log" | tail -1 || true)"
[[ -n "$connect" ]] || die "the install printed no connect string; what it did print is above"

# The one port that can be tried from here. UDP cannot: nothing answers a stray datagram.
step "Checking that the agent can be reached from here"
reach="${address#[}" reach="${reach%]}"
if timeout 5 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$reach" "$tcp" 2>/dev/null; then
  printf '    TCP %s answers.\n' "$tcp"
else
  printf '    TCP %s does not answer from here. If a cloud security group or another firewall sits in\n' "$tcp"
  printf '    front of the server, open TCP %s%s there.\n' "$tcp" "${udp:+ and UDP $udp}${cone:+, and UDP $cone for peer-to-peer games}"
fi

printf '\nPaste this into Yura → Proxies → Add agent:\n\n  %s\n\n' "$connect"
