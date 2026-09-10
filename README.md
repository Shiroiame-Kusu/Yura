# Yura

A Linux-first alternative to Proxifier and ProxyBridge, with an integrated game
acceleration workflow.

Yura routes the traffic of **specific running processes** through proxies you already run.
It does not ship or manage a routing engine: you point it at your own SOCKS5 or HTTP(S)
endpoint, and Yura decides which process's traffic goes there.

> **Status: working end to end.** The privileged daemon routes selected running processes
> through user-supplied proxies, verified by
> [29 acceptance tests](docs/daemon-acceptance.md) driven through its real IPC socket, and
> the desktop application drives it. Persistence, the Connections page and the process-event
> watcher are still missing. See [Current state](#current-state).

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

That last row is a feature, not a limitation: it is exactly the semantic the UI reports.

## Repository layout

```
src/Yura.Core          domain model: process identity, rules, proxies, connections, IPC
src/Yura.Daemon        privileged daemon: cgroups, nftables, TPROXY forwarder, IPC server
src/Yura.App           Avalonia 12 + FluentAvalonia desktop application (unprivileged)
tests/Yura.Core.Tests  unit tests for the rule system and /proc reader
tests/Yura.Daemon.Tests unit tests for the nftables ruleset builder
tests/acceptance/      the daemon acceptance suite, driven through the real IPC socket
spikes/                the routing spike: proves running-process routing end to end
tools/                 screenshot harness, contrast checker
docs/                  architecture notes, verification reports, screenshots
```

## Requirements

- .NET 10 SDK
- Linux with cgroup v2 unified hierarchy and nftables (for the daemon and the spike)
- `nft`, `ip`, `python3` for the spike

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
| `--page processes\|games\|proxies` | Start on a page |
| `--demo` | Populate from a **simulated** daemon, for design review only |
| `--font-report` | Print what Avalonia's font manager actually resolves |
| `--config-report` | Print where configuration and secrets are stored |
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

The daemon is the only privileged component. It configures nftables, policy routing and
cgroups, and forwards captured flows to your proxies.

```bash
dotnet build src/Yura.Daemon
sudo ./src/Yura.Daemon/bin/Debug/net10.0/yura-daemon --verbose
```

It authorises callers by peer credential (`SO_PEERCRED`): root, plus whichever user invoked
it via sudo. On SIGTERM it removes every rule, route and cgroup it created.

`yura-daemon ctl <op>` speaks the same socket for scripting and diagnostics:

```bash
yura-daemon ctl status
yura-daemon ctl list-rules
yura-daemon ctl list-flows
yura-daemon ctl connection-counts
```

## Acceptance tests

```bash
sudo tests/acceptance/daemon-acceptance.sh
```

32 checks against a controlled network on a dummy interface, where each marker payload is
reachable only through one specific proxy. **32 passed, 0 failed.** Mandatory acceptance
tests 1, 2, 3, 4, 5, 6, 7, 8 (inclusion) and 11 are verified; see
[docs/daemon-acceptance.md](docs/daemon-acceptance.md) for what is not.

## Configuration

Settings, proxies and persistent rules live in **`~/.config/Yura/config.json`**
(`$XDG_CONFIG_HOME` is honoured). Passwords are kept in the desktop secret service, never in
that file. See [docs/configuration.md](docs/configuration.md).

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

## Current state

**Built and verified**

- Domain model with ordered first-match rule evaluation, instance identity and PID-reuse
  defence (26 passing tests)
- Live `/proc` reader that degrades honestly on permission-denied and deleted executables
- Design system, and the Processes, Games and Proxy Editor screens
- Screenshot harness covering both themes, both languages, 960×640 and 1280×800, and
  100–200% scaling
- **Routing spike passing 12/12** and the **daemon acceptance suite passing 29/29**: a
  running process migrated into a cgroup live, classified by nftables, captured by TPROXY
  and forwarded to a SOCKS5 proxy — for TCP and UDP, per instance, with the process still
  running as its original user
- The privileged daemon: cgroup manager, nftables ruleset builder, transparent TCP and UDP
  forwarder, SOCKS5 and HTTP CONNECT clients, socket-ownership attribution, and a
  peer-credential-authorised IPC server
- The app driving the real daemon over its socket, including live per-process connection
  counts
- Configuration under `~/.config/Yura`, with passwords in the desktop secret service and
  persistent rules reapplied to the daemon on every connection

**Not yet built**

- The netlink process-event watcher. New processes are picked up by a 500 ms poll, so a
  process that starts *and connects* within one interval keeps its original route; child
  *exclusion* is also unimplemented
- Connections, Rules, Diagnostics and Settings pages
- Proxy chains, and IPv6 in the UDP path

See [docs/ux-verification.md](docs/ux-verification.md) for what was checked and what could
not be.
