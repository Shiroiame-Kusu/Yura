# Daemon acceptance results

The privileged daemon driven end to end through its real IPC socket, on a controlled network
built on a dummy interface.

```bash
dotnet build src/Yura.Daemon
sudo tests/acceptance/daemon-acceptance.sh
```

**83 passed, 0 failed**, reproduced across consecutive runs on kernel 7.2 / nftables 1.1.7 /
wireguard-tools 1.0.

Nothing in the harness touches nftables, cgroups or policy routing directly. Every kernel
change is made by `yura-daemon` in response to a rule sent over the Unix socket, which is
exactly the path the desktop application uses.

## How a claim is proved

Destinations live on a dummy interface that goes nowhere, and each marker payload is
reachable **only** through one specific proxy, because that proxy rewrites the unroutable
address to a local marker server. Receiving `YURA-VIA-PROXY-A` therefore proves the flow
traversed proxy A; a timeout proves it did not. Three independent logs are cross-checked: the
client's own record of every attempt, the proxy's audit log of every CONNECT and UDP
ASSOCIATE, and the daemon's own view of the flows it is relaying.

For the WireGuard exit the peer lives in its own **network namespace**, reachable from the
host only over a veth pair, and the marker destination is an address that exists only inside
that namespace. The single path from the host into it is the encrypted tunnel, so receiving
the marker proves the flow left through the exit — and the peer's own log shows the tunnel
address as the source, which is what an exit node's far end sees.

## Mandatory acceptance tests

| # | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Start an ordinary application, then select it; new connections traverse the proxy | **Verified** | Instance A receives `YURA-VIA-PROXY-A`, a payload only reachable through proxy A |
| 2 | Two instances of one executable; proxy one, the other stays direct | **Verified** | B keeps timing out while A is proxied; proxy B's log stays empty |
| 3 | Persistent executable rule survives an application restart | **Verified** | An executable rule applied while nothing is running proxies 11 connections from an instance started afterwards; `ConfigStoreTests` covers the save/restore half |
| 4 | Rule expires on process exit and cannot affect a reused PID | **Verified** | Killing A removes the rule and its cgroup; a fresh instance of the same binary is unaffected |
| 5 | Two processes through different proxies simultaneously | **Verified** | A receives proxy A's marker while B receives proxy B's, in the same window |
| 6 | Direct and Block for selected processes | **Verified** | Block yields `ConnectionRefused` (a reset, not a timeout); Direct returns to timing out |
| 7 | TCP and UDP from a selected running process | **Verified** | A receives both `YURA-VIA-PROXY-A` and `YURA-UDP-VIA-PROXY-A` |
| 8 | Child-process inclusion | **Verified** | curl children forked after a tree rule receive the marker |
| 8 | Child-process exclusion | **Verified, with a stated limit** | No child of an excluding rule reaches the proxy, and the daemon logs every child it moved out with zero failures. A child that creates a socket in its first instant can still win the race — see [The exclusion race](#the-exclusion-race) |
| 9 | Precedence between manual rules and game profiles | **Verified** | One process covered by both rules sits in a single cgroup naming both; the higher rule's proxy is the one its traffic reaches, and reversing the order reverses the outcome |
| 10 | Unrelated Wine/Proton applications unaffected | **Verified** | Two processes share one runtime binary; the rule narrowed to `alpha.exe` proxies that one and leaves `beta.exe` timing out |
| 11 | Existing connections distinguished from new ones | **Verified** | A's pre-rule connection stays open on its old route; the proxy never sees its destination, and the Connections view reports it as `preExistingPreviousRoute` alongside confirmed-proxied rows for the same process |

## Beyond the mandatory list

| Check | Result |
| --- | --- |
| The routed process keeps running as its original user | uid 1000, never root |
| The daemon reports flows as `confirmedProxied` only when it is relaying them | 33 flows confirmed, with proxy name and destination |
| Pre-existing connections are counted at apply time | `preExistingConnections: 2` |
| Socket ownership attribution | Flows attributed to their owning pid and process name |
| Destination host names matched from the traffic | A flow whose `Host` header matches `*.example.com` is proxied; one to another name is not, though the same rule captured both |
| DNS through the proxy, and names learned from the answers | The resolver only ever sees queries arriving via proxy A, and 24 later connections are attributed to `game.example.net` from those answers |
| Proxy chains | Traffic through an A→B chain arrives with B's marker, and proxy A's log shows it was asked to reach proxy B — not the destination |
| A chain refuses UDP rather than losing it | Stated in the log, not silently dropped |
| Direct-versus-routed measurement | Both sides measured against one target by one method (TCP connect) in one call |
| The daemon can dump exactly what it installed | nftables table with counters, ip rules, routing table and cgroup membership |
| Clean shutdown removes the nft table, the ip rule and the cgroup subtree | All three verified absent afterwards |

### WireGuard exits

| Check | Result |
| --- | --- |
| The daemon brings a WireGuard exit up and says which one it could not | `WG exit` is up on `yura-wg0`; `WG broken` (an unparseable private key) is reported as not up with the reason, in the apply warnings and in status |
| No key material reaches status or the log | The private key and preshared key are grepped for in both and never found; `wg setconf` reads them from standard input |
| Probing completes a handshake and gets an answer from the tunnel's resolver | Handshake in 2 ms; the resolver inside the namespace answers through the tunnel |
| TCP and UDP from a selected process leave through the tunnel | Both markers received; the peer's log shows every request arriving from `10.77.0.1`, the tunnel address |
| Name lookups go to the exit's own resolver | 13 answers received; 13 queries reached the resolver at `10.77.0.2`, which only the tunnel can reach, though the application asked `198.51.100.7` |
| The daemon reports the flows as confirmed through the exit | TCP and UDP flows `confirmedProxied` via `WG exit` |
| A rule on an exit that is down is accepted with a warning, and its flows are refused with the reason | The application sees a reset, never a leak to the direct route; each refused flow carries `is not up: …` |
| A chain with the exit as its first hop reaches a proxy that exists only behind it | The SOCKS5 proxy inside the namespace logs CONNECTs from the tunnel address and the last hop's marker comes back |
| A chain with the exit anywhere but first is refused at apply time | `can only be the first hop` |
| Shutdown removes the tunnel interfaces and their policy rules | Neither `yura-wg*` nor any `fwmark 0x73…` rule remains |

## The exclusion race

Including children is free: a forked child inherits its parent's cgroup. **Excluding** them
cannot be, and it is worth being precise about why.

A socket's cgroup is fixed when the socket is created (`sk_cgrp_data`), and a child is in its
parent's cgroup from the instant `fork` returns. Nothing in userspace can be told about the
child before it exists, so there is always a window between the fork and Yura moving it out.
Two mechanisms narrow it, and the daemon uses both:

- The kernel's **process connector** delivers the fork event, and it is handled inline on the
  netlink thread — no queue, no lock, no `/proc` read, one write to `cgroup.procs`.
- A **guard thread** polls the cgroups of excluding rules every millisecond and evicts anything
  that is not the rule's own process, which bounds the window to something Yura controls
  rather than to the scheduler's whim.

What remains: a child that connects in roughly its first millisecond of life keeps the route
it inherited. The suite measures it. With a shell forking `curl` in a tight loop — the worst
case, since `curl` does nothing between `exec` and `connect` — **30 of 31 children still
reached the proxy** while the daemon was simultaneously servicing the rest of the suite. In
isolation the same loop leaks about one in ten. A child that does anything at all first, which
is every real application, is excluded reliably: the suite asserts that case (0 of 3 children
proxied, 75 children moved out) and measures the immediate one separately, so a regression in
the fast path shows up as a number rather than as a passing test.

Closing it properly needs a hook at socket creation rather than at fork — a
`cgroup/sock_create` eBPF program — which is a different mechanism, not a refinement of this
one. It is not built, and the UI says so where the choice is made.

## Bugs this suite found

Each would have shipped as a confident wrong behaviour:

- **Fixed listener ports were unsafe on this kernel.** `ip_local_port_range` here is
  1024–65535, so an unrelated outgoing connection can already hold the port a slot wanted, and
  installing a rule failed with `EADDRINUSE` for a reason no user could act on. The listeners
  now ask the kernel for a port and the ruleset names whichever it got.
- **A transparent UDP socket steals the traffic it was meant to answer.** Binding a socket to
  the application's original destination — which is how a reply appears to come from the right
  peer — also makes the kernel's early demux prefer it over the TPROXY redirect. The second
  and every later datagram to that destination landed on an idle socket and was lost, which a
  DNS resolver behind a proxy experiences as everything timing out after the first lookup.
  Those sockets are now drained and their datagrams re-dispatched, so either delivery path
  works.
- **Signal handlers were being garbage collected.** `PosixSignalRegistration.Create` returns
  an `IDisposable` that unregisters the handler when finalised. The return value was
  discarded, so SIGTERM was silently disarmed and the daemon died without removing its
  nftables table, ip rule or cgroups from the machine. Caught only because the suite asserts
  on kernel state *after* shutdown rather than trusting the exit code.
- **Logging on the fork fast path delayed the next fork.** Formatting a line and writing it
  cost more than the eviction it was reporting. The counters stayed; the log line moved to the
  event handler, off the latency-critical thread.
- **The `ctl` client half-closed its socket before reading.** `NetworkStream` refuses to wrap
  a socket that has been shut down in either direction, so every command after the first
  threw. It looked like a daemon fault; it was entirely client-side.
- **A stale PID file made a test build a rule from a dead process.** Preflight cleared
  `*.jsonl`, `*.out` and `*.log` but not `*.pid`, so a readiness loop succeeded instantly
  against the previous run's leftovers.
- **A `fail()` helper returned non-zero.** Under `set -e` that ended the whole run at the
  first failure, hiding every later result.
- **A JSON string carried twice the backslashes it needed.** The Wine test's rule named
  `Z:\\games\\alpha\\alpha.exe` rather than `Z:\games\alpha\alpha.exe`, so it matched nothing
  and the test that the *other* game stays unaffected passed for the wrong reason. The lesson
  is that a negative assertion is only worth as much as the positive one beside it.

One apparent bug was not one: slot `s002` looked like it was classifying only intermittently.
Per-rule nftables counters showed it climbing from 7 packets to 31 over the same window — the
assertion window was simply shorter than the direct instance's timeout cycle. Counters on
every rule are now permanent for exactly this reason.

## What the WireGuard fixture proved before the suite did

The exit was first exercised by a standalone script against the same namespace fixture, and
worked on its first run: handshake in 1 ms, every request at the peer from the tunnel
address, DNS redirected to the tunnel's resolver, flows confirmed. The suite then found
nothing wrong in the daemon; what it found were three defects in its own new checks — two
`f['ruleId']` lookups on flows that legitimately have no rule, and an expectation of
`ConnectionRefused` where a captured-then-reset connection reports a reset. Those are
recorded here because a test that fails for the wrong reason is as misleading as one that
passes for the wrong reason.

## Not proven here

- **The exclusion race**, above: measured, bounded, not eliminated.
- **Short-lived processes.** With kernel process events the migration usually beats the first
  connect; without them membership is polled every 500 ms and a process that starts and
  connects inside one interval keeps its original route. The Diagnostics page reports which
  mechanism is in use.
- Behaviour under a hostile connection rate, or with a proxy that stalls mid-handshake.
- **IPv6.** The classifier renders IPv6 destination rules and the forwarder dials IPv6
  destinations, but every test here is IPv4 and the UDP path is IPv4-only by construction.
- Real Wine and Proton. Test 10 uses a process that presents to `/proc` exactly as a Wine
  process does — the runtime binary's name and a `.exe` in argv, which is what Yura reads —
  so it exercises the real classification path, but it is not a test of Wine itself.
- **A WireGuard peer across a real network.** The peer here is a kernel `wireguard` interface
  in a namespace on the same machine, so the handshake, the cryptokey routing and the
  source-address requirement are real, but path MTU, NAT traversal and a peer that roams are
  not exercised.
- **IPv6 inside a tunnel.** The interface gets its IPv6 address and its own `ip -6` rule and
  route when the configuration has one, but every flow in the suite is IPv4.
