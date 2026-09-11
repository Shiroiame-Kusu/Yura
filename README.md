# Yura

A Linux-first alternative to Proxifier and ProxyBridge, with an integrated game
acceleration workflow.

Yura routes the traffic of **specific running processes** through exits you already have.
It does not ship or manage a routing engine: you point it at your own SOCKS5 or HTTP(S)
proxy, or at a WireGuard peer to use as an exit node, and Yura decides which process's
traffic goes there.

> **Status: working end to end.** The privileged daemon routes selected running processes
> through user-supplied proxies and WireGuard exits, verified by
> [83 acceptance checks](docs/daemon-acceptance.md) driven through its real IPC socket, and
> the desktop application drives it and can install it as a systemd service. All eleven
> mandatory acceptance tests are covered. See [Current state](#current-state) for what is
> proven and what is not.

## Why per-process routing is hard on Linux

The interesting requirement is not "proxy an application" — it is "proxy *this instance*
of an application that is **already running**, without restarting it, without a wrapper,
and without touching the other instance of the same binary."

Yura's answer:

| Concern | Mechanism |
| --- | --- |
| Select a running process | Write its PID into a dedicated **cgroup v2**, migrating it live |
| Classify its packets | **nftables** `socket cgroupv2` sets an fwmark in a `route` output chain |
| Capture them | fwmark → policy routing → `local` route on `lo` → **TPROXY** in prerouting |
| Forward them | The daemon's own transparent forwarder re-originates each flow to your proxy |
| Instance identity | PID **plus process start time plus uid**, re-verified before every action |
| Child processes | Free: a forked child inherits its parent's cgroup |
| Wine/Proton isolation | Classification is by cgroup, not executable path, so shared runtimes don't collide |
| Pre-existing connections | Keep their old route, because a socket's cgroup is fixed at creation |
| Process lifecycle | The kernel's **process connector** reports fork, exec and exit; a sweep re-derives from `/proc` as a safety net |
| Destination host names | Learned from DNS answers passing through the relay, and from TLS SNI / HTTP `Host` |
| WireGuard exit nodes | A kernel `wireguard` interface per exit, entered only by the daemon's own sockets through a per-tunnel fwmark and routing table; nothing else on the machine is routed through it |

That last row is a feature, not a limitation: it is exactly the semantic the UI reports.

## Repository layout

```
src/Yura.Core          domain model: process identity, rules, proxies, connections, IPC
src/Yura.Daemon        privileged daemon: cgroups, nftables, TPROXY forwarder, IPC server
src/Yura.Agent         the server-side relay: Yura's own exit, for a machine near the game
src/Yura.App           Avalonia 12 + FluentAvalonia desktop application (unprivileged)
tests/Yura.Core.Tests  unit tests for the rule system, /proc reader and agent protocol
tests/Yura.Daemon.Tests unit tests for the nftables ruleset builder
tests/Yura.Agent.Tests  end-to-end tests of the agent: real server, real client, real sockets
tests/acceptance/      the daemon acceptance suite, driven through the real IPC socket
spikes/                the routing spike: proves running-process routing end to end
tools/                 screenshot harness, contrast checker, string-table checker
docs/                  architecture notes, verification reports, screenshots
```

## Requirements

- .NET 10 SDK
- Linux with cgroup v2 unified hierarchy and nftables (for the daemon and the spike)
- `nft`, `ip`, `python3` for the spike
- `wireguard-tools` (`wg`) and a kernel with the `wireguard` module, for WireGuard exits only;
  without them the daemon runs and says so in Diagnostics

Verified on CachyOS, kernel 7.2, nftables 1.1.7, .NET 10.0.302.

## Build and test

```bash
dotnet build
```

```bash
./test.sh
```

`dotnet test` is not used: on the .NET 10 SDK it still routes through the VSTest bridge,
which Microsoft.Testing.Platform rejects. The xunit.v3 projects are self-executing, so
`test.sh` runs them directly.

## Run the app

```bash
dotnet run --project src/Yura.App
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `--theme light\|dark` | Start in a theme |
| `--lang en\|zh-Hans` | Start in a language |
| `--page processes\|games\|connections\|proxies\|rules\|diagnostics\|settings` | Start on a page |
| `--demo` | Populate from a **simulated** daemon, for design review only |
| `--demo-editor socks\|wireguard\|chain` | Which editor the demo opens on the Proxies page |
| `--font-report` | Print what Avalonia's font manager actually resolves |
| `--config-report` | Print where configuration and secrets are stored |
| `--service-report` | Print the systemd unit and install script the Settings page would use |
| `--config-dir DIR` | Use a different configuration directory |

## The routing spike

The spike proves, with evidence rather than assertion, that an already-running process can
be re-routed per instance. It builds an isolated test network on a dummy interface, so no
packet leaves the machine, and the marker payload is reachable *only* through the spike's
own SOCKS5 proxy — receiving it is proof of proxying.

```bash
sudo ./spikes/routing-spike.sh
```

It checks: baseline isolation, per-instance routing (TCP and UDP), that a second instance
of the same executable stays direct, that pre-existing connections keep their previous
route, and that removing the override restores direct routing. Everything it creates is
namespaced `yura-spike` and removed by its cleanup trap, including on failure.

**Result: 12 passed, 0 failed**, reproduced across three consecutive runs. Acceptance tests
1, 2, 7 and 11 are verified with evidence from three independent logs. Full write-up in
[docs/spike-results.md](docs/spike-results.md).

When something breaks, `sudo ./spikes/debug-classify.sh` puts an nftables counter on every
rule and reports which links a packet actually reached.

## Run the daemon

The daemon is the only privileged component. It configures nftables, policy routing,
cgroups and WireGuard interfaces, and forwards captured flows to your exits.

```bash
dotnet build src/Yura.Daemon
sudo ./src/Yura.Daemon/bin/Debug/net10.0/yura-daemon --verbose
```

It authorises callers by peer credential (`SO_PEERCRED`): root, plus whichever user invoked
it via sudo. On SIGTERM it removes every rule, route, tunnel and cgroup it created.

**As a service.** The Settings page installs it as `yura-daemon.service`: it shows the unit
and the exact script that will run as root, then asks for your password once through polkit.
The unit runs the daemon with `ProtectHome=yes`, `ProtectSystem=strict`, `NoNewPrivileges`
and `HOME` pointed at its tmpfs runtime directory, so it can never write into a home
directory. Without a polkit agent, the same script is offered to run with sudo:

```bash
dotnet run --project src/Yura.App -- --service-report
```

`yura-daemon ctl <op>` speaks the same socket for scripting and diagnostics:

```bash
yura-daemon ctl status
yura-daemon ctl list-rules
yura-daemon ctl list-connections
yura-daemon ctl dump-ruleset
yura-daemon ctl log
```

## Acceptance tests

```bash
sudo tests/acceptance/daemon-acceptance.sh
```

113 checks against a controlled network on a dummy interface, where each marker payload is
reachable only through one specific proxy — or, for a WireGuard exit and a Yura agent, only
inside a network namespace that the tunnel or the agent is the sole way into. **113 passed, 0
failed.** All eleven mandatory acceptance tests are covered, including child exclusion, rule
precedence in the kernel, and Wine/Proton isolation. See
[docs/daemon-acceptance.md](docs/daemon-acceptance.md) for the evidence behind each one and for
the limits that remain — including the one that decides whether a rule appears to work at all:
a program that opens a socket within about two milliseconds of starting is not captured, and
Yura reports that rather than claiming otherwise.

## Run an agent on a server

An agent is Yura's own relay: put it on a machine near the game's servers and selected games
leave from there instead of from your own connection, over UDP as well as TCP.

```bash
tools/publish-agent.sh linux-x64          # one self-contained file; no .NET on the server
scp artifacts/yura-agent-linux-x64/yura-agent user@server:
ssh user@server 'sudo ./yura-agent install'
```

`install` writes a hardened systemd unit, starts it, and prints one connect string. Paste that
into Yura → Proxies → **Add agent**; the token in it goes to the secret store and the key
fingerprint — which is what identifies the agent, instead of a certificate authority — goes to
the configuration file. Open the port it names, TCP **and** UDP: the datagram channel is what
carries a game's traffic.

```bash
./yura-agent show       # print the connect string again
./yura-agent rotate     # replace the token, invalidating every client
./yura-agent unit       # print the unit install would write, without installing
sudo ./yura-agent uninstall [--purge]
```

By default the agent refuses private, loopback and link-local destinations, so a client holding
the token cannot use it to reach the server's own network. `--allow`, `--deny`, `--ports` and
`--allow-private` change that deliberately.

## Configuration

Settings, proxies, WireGuard exits, chains and persistent rules live in
**`~/.config/Yura/config.json`** (`$XDG_CONFIG_HOME` is honoured). Passwords and WireGuard
keys are kept in the desktop secret service, never in that file. See
[docs/configuration.md](docs/configuration.md).

```bash
dotnet run --project src/Yura.App -- --config-report
```

## Design system

Tokens live in [`Themes/Tokens.axaml`](src/Yura.App/Themes/Tokens.axaml): graphite/slate
neutrals, one restrained teal accent, semantic colour reserved for success/warning/failure,
a 4-DIP spacing scale, and opaque surfaces throughout.

Contrast is measured, not assumed:

```bash
python3 tools/check-contrast.py --verbose
```

All 52 required foreground/background pairs meet their target in both themes.

The string table is checked the same way, so a mistyped key cannot survive a build:

```bash
python3 tools/check-strings.py
```

All 434 keys exist in both languages, everything referenced exists, and nothing in the table
is unreferenced.

## Current state

**Built and verified**

- Domain model with ordered first-match rule evaluation, instance identity and PID-reuse
  defence
- Live `/proc` reader that degrades honestly on permission-denied and deleted executables
- All seven pages: Processes, Games, Connections, Proxies, Rules, Diagnostics, Settings
- Design system, both themes, both languages, 960×640 to 1280×800, 100–200% scaling —
  see [docs/ux-verification.md](docs/ux-verification.md)
- **Routing spike passing 12/12** and the **daemon acceptance suite passing 113/113**: a
  running process migrated into a cgroup live, classified by nftables, captured by TPROXY and
  forwarded to a SOCKS5 proxy, through a WireGuard tunnel, or through a Yura agent — TCP and
  UDP, per instance, with the process still running as its original user
- The privileged daemon: cgroup manager, nftables ruleset builder, transparent TCP and UDP
  forwarder, SOCKS5 / HTTP CONNECT / HTTPS clients, WireGuard exits on kernel interfaces,
  proxy chains (with a WireGuard exit as the first hop), socket-ownership attribution, kernel
  process events, DNS name learning, SNI and `Host` sniffing, a direct-versus-routed
  measurement, and a peer-credential-authorised IPC server
- WireGuard exits imported from a wg-quick `.conf`, probed by a real handshake and a DNS
  answer through the tunnel, with the peer's handshake time and transfer shown live
- **Yura agents**: a server-side relay with its own protocol — TLS 1.3 with a pinned public
  key, a shared token, an AES-GCM datagram channel for UDP, latency measured from the agent's
  own vantage point, and the resolver it offers used for lookups on that exit. Added by
  pasting one connect string, deployable as one self-contained file with one command
- **Honest reporting of what is actually routed**: the Games page reads the daemon's account of
  each of the game's connections and says how many are going through the route, how many are
  going to a proxy on this machine, and how many predate the rule — because a rule being
  installed was never evidence that traffic obeys it
- A systemd service installed from Settings through polkit, with the unit and the script
  shown before anything runs as root, and start / stop / restart / uninstall from the same
  page
- 266 unit tests over the rule system, the `/proc` reader, the nftables ruleset, the netlink
  wire format, the DNS parser, the SNI parser, the WireGuard configuration importer and
  tunnel manager, the agent protocol end to end against a real agent, the connect string, the
  datagram sealing and its replay window, the systemd unit generators, the Steam library
  reader and its KeyValues parser, the rule store, the proxy, agent and chain editors, the
  routing-evidence sentences, and the configuration file
- Configuration under `~/.config/Yura`, with passwords and keys in the desktop secret service
  and persistent rules reapplied to the daemon on every connection

**Known limits, stated where they matter**

- **Child exclusion is a race.** A child inherits its parent's cgroup at fork and a socket's
  cgroup is fixed at creation, so a child that connects in its first millisecond keeps the
  parent's route. The daemon narrows the window with an inline fork handler and a 1 ms guard;
  closing it needs an eBPF hook at socket creation, which is not built. Measured, bounded and
  reported — see [the exclusion race](docs/daemon-acceptance.md#the-exclusion-race).
- **UDP through a chain, or through an HTTP proxy, is refused rather than lost.** DNS is
  carried over TCP in that case so name resolution still works.
- **A WireGuard exit can only be the first hop of a chain.** The daemon reaches later hops
  through the tunnel, but a kernel tunnel cannot be carried inside a SOCKS connection; the
  app and the daemon both refuse such a chain with the reason.
- **IPv6** works for TCP; the UDP path is IPv4-only by construction, and the daemon originates
  inside a tunnel from its IPv4 address.
- Keyboard-only walkthroughs, screen-reader behaviour and real application icons are not
  verified — see [docs/ux-verification.md](docs/ux-verification.md#not-verified).
