# Daemon acceptance results

The privileged daemon driven end to end through its real IPC socket, on a controlled network
built on a dummy interface.

```bash
dotnet build src/Yura.Daemon src/Yura.Agent
sudo tests/acceptance/daemon-acceptance.sh
```

**141 passed, 0 failed**, reproduced across consecutive runs on kernel 7.2 / nftables 1.1.7 /
wireguard-tools 1.0: on the development builds, and on the NativeAOT daemon and agent that
`tools/publish.sh` and `tools/publish-agent.sh` produce.

```bash
sudo YURA_DAEMON=artifacts/yura-linux-x64/yura-daemon \
     YURA_AGENT=artifacts/yura-agent-linux-x64/yura-agent tests/acceptance/daemon-acceptance.sh
```

Nothing in the harness touches nftables, cgroups or policy routing directly. Every kernel
change is made by `yura-daemon` in response to a rule sent over a Unix socket, which is
exactly the path the desktop application uses. The socket is the suite's own,
`/run/yura-acceptance/yura.sock`, not the service's: a Yura app left running reconnects to
`/run/yura/yura.sock` whenever a daemon appears there, and pushes its own proxies and rules.
Once it did that in the middle of a run, replacing the suite's proxies with the user's real ones
and removing every rule the suite had applied.

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
| A refused connection is an answer | A port nothing listens on is timed directly and through proxy A, which now reports `connection refused` as RFC 1928 has it and Dante sends it, instead of being counted as loss. Game servers mostly listen on UDP and refuse a TCP connect to their port, and they are no less there for it |
| A proxy that answers before it connects is said to, not timed | Proxy C reports success before it dials, as mihomo does, so a connect through it would time loopback. The daemon asks it once for port 1 on its own loopback, is told it is open, and gives the route no figure: the second measurement does not ask again, and neither times a connect through it |
| A proxy that connects first is not mistaken for one that answers first | Proxy A reports the same port refused, so its routed figures stand |
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

### Yura agents

The agent is proved the same way as the WireGuard exit, and for the same reason: the marker it
reaches exists only inside the agent's network namespace, so receiving that marker means the
agent dialled it. Twenty-three checks cover the connect string, the session, the refusal of a
stale token, the probe's real datagram round trip, TCP and UDP through the agent, the resolver
it advertises (on its own loopback, where nothing outside the namespace could answer), the
split measurement, a port nothing listens on answered both through the agent and from it, the
policy refusing a private destination, an agent as the first hop of a
chain and as a later one, and the daemon noticing when the agent goes away.

### The capture boundary

Two checks state where classification works and where it does not, because the difference is
what a user experiences as "the route does nothing":

- A program started after its rule, with an ordinary start-up, is captured from its first
  connection — 5 of 5.
- A program that connects about two milliseconds after `exec` is measured, not asserted: 0 of 8
  on this machine. The daemon places a process from the kernel's event thread with one readlink
  and one write, which is as fast as a notification-after-the-fact can be; `curl` is simply
  faster. The check that does assert something asserts the honest part — that nothing which
  escaped is reported as routed.
- IPv6 from a covered process is refused, and the refusal is counted in the kernel, so the
  ruleset cannot quietly go back to letting it out.

### NAT type, direct and through a route

What a peer-to-peer game needs is not that its packets leave but that a peer's packets arrive,
which depends on the route rather than on the machine. Sixteen checks measure it the way the
harness proves everything else — with a server that only one path can reach. The first seven
ask STUN servers what mapping each route gives:

| Check | Result |
| --- | --- |
| The direct path is measured, not guessed | `open`, `behindNat: false`, endpoint-independent mapping; the address a peer would be told is this machine's own |
| Both STUN servers were really asked | One binding request logged at each |
| A SOCKS5 route is measured the way the forwarder uses it | `strict`, `addressAndPortDependent`: one association per destination, as the forwarder opens them, and the test proxy gives each its own relay socket; `behindNat` is null because the socket facing the servers is the proxy's ¹ |
| The proxy's own log shows it carried the probes | `udp_send` entries naming the STUN ports, over at least two associations ¹ |
| **An agent route is measured from the agent** | Both servers live only inside the agent's network namespace, on two different addresses, so whatever they report can only have come from the agent; the mapped address is the agent's own ² |
| **And it keeps one address for every peer** | `moderate`, `endpointIndependent`: full-cone UDP gives the probe one socket at the agent for both servers. Moderate rather than Open only because the fixture does not answer the filtering question ² |
| A chain is reported as carrying no UDP | `blocked`, with "carries TCP only" — a definite answer, not an unknown |

¹ Changed with the NAT test itself, and verified on 2026-10-06: `strict`, with two STUN
datagrams through two associations. Before the change this row reported `moderate`: both
probes went down one association, a mapping no game routed through the proxy ever gets, since
the forwarder relays each destination over an association of its own.

² Changed with full-cone UDP, and verified on 2026-10-06: `moderate`, both servers seeing the
agent at `10.78.1.2:40092` — one address, from the default full-cone range. Before full cone
this row reported `strict`, `addressAndPortDependent` — a channel per destination, a port per
peer — with both servers on one address. The second server now has an address of its own,
since two ports of one address agreeing about a mapping say nothing about whether it depends on
the address; and the agent is told its own address with `--own-address`, because this fixture
puts its "remote" servers on the namespace's own loopback, which the agent otherwise refuses to
relay to. What this table cannot show is a peer the game never sent to getting through; the
next one does.

The other nine ask the question the STUN fixture leaves open: whether a peer the game has never
sent to gets in, and only the peers it should. A game routed through the agent learns its address
from the server at `198.51.100.7:3478`, and a second client at `198.51.100.8:6112`, on another
address and another port that both exist only inside the agent's namespace, sends to it. Then a
second game, whose rule covers only the server's address, hears from a stranger at that address
and from one somewhere else:

| Check | Result |
| --- | --- |
| A rule routes a peer-to-peer game through the agent | Applied before the game starts, as an executable rule |
| The game learns the address its peers will see | The server inside the namespace reports the agent's address and a port from the full-cone range |
| **A peer at an address the game never sent to gets through** | The game receives the peer's datagram from `198.51.100.8:6112`, having sent only to `198.51.100.7:3478` |
| **The game's answer reaches the peer from the address the server saw** | One socket at the agent for the server and the stranger alike, so the peer can tell the game's answer from anyone else's |
| Nothing from the agent's own loopback reaches the game | Two datagrams from `127.0.0.1` inside the namespace, sent ahead of the peer's on the same socket; the game hears only the peer |
| The Connections view lists the peer's flow under the game | `confirmedProxied` through the agent, with bytes both ways, and the note "Opened by the peer, through the full-cone channel at the agent." |
| A rule routes a second game through the agent for one address only | `networks: 198.51.100.7/32`, so only the server's address takes the agent's route |
| **A stranger at that one address still gets through** | From `198.51.100.7:6112`, a port the game never sent to, and it hears the answer from the game's address |
| **A stranger anywhere else is turned away, by the daemon** | Two datagrams from `198.51.100.8:6112`, which the agent passes on, as the check above shows: the game hears neither, and no flow is opened. Its answer would not take the agent's route, so the peer could never have heard it |

Nothing the game sent opened the way for the peer, and nothing but the agent connects the two,
so the datagram the game received from `198.51.100.8:6112` came through every stage: the agent's
full-cone socket, its datagram channel, the daemon's cone routing, and a transparent socket
answering as the peer. Verified on 2026-10-06 across consecutive runs: the game was told
`10.78.1.2:40755`, then `10.78.1.2:40583`, and each time it heard the peer, and the peer heard
the answer from that same address about 1.5 ms after sending. In the runs with the narrowed
rule, the stranger at the covered address was answered from the second game's own address
(`10.78.1.2:40305` in the last run), and the one elsewhere was heard by nothing. The agent's
half is also proved against a real agent in `FullConeTests`, and the daemon's routing by sender
in `AgentConeTests`.

The fixture (`spikes/lib/stun_server.py`) answers binding requests and logs every query, and
deliberately ignores `CHANGE-REQUEST`: it exists to pin the mapping behaviour, and simulating
the filtering tests would let the suite assert something the fixture was only pretending to do.
The game and its peer are `spikes/lib/p2p_game.py`. The game opens a new socket for each binding
attempt until one is answered, because a socket opened before the exec-time classification
reached the process is never routed; then it answers whoever sends to that socket.

### A rule reaching connections that were already open

The other half of the capture boundary. A socket's cgroup is fixed when it is created, so a
connection that predates its rule can never be captured — it can only be aborted, after which
the application opens a new socket that the rule does govern. Eight checks prove that is what
happens, against a destination in its own network namespace, so it is genuinely reachable
before the rule exists and genuinely capturable afterwards (a destination on this machine's
own address would leave over loopback, which the classifier ignores by design):

| Check | Result |
| --- | --- |
| The application holds a connection open before any rule exists | Open and alive across repeated observations |
| The daemon reports what it aborted | `preExistingConnections: 2`, `resetConnections: 2`, no failure |
| The connection really died, and the application reconnected by itself | `ConnectionAbortedError` at the application, then a new socket |
| **The replacement connection is on the route** | Proxy A's own log shows it was asked to dial `10.79.1.2:8091` — the destination of the connection that had been direct a second earlier |
| The destination saw the replacement arrive | A new accepted connection at the far end |
| New connections are proxied as well | Marker `YURA-VIA-PROXY-A` |
| Reapplying the same rule aborts nothing | `resetConnections: 0` — the reset is for sockets whose route changes, not for every socket a process holds |
| And the application keeps the connection it has | Still open across repeated observations |

Requirement 11 above is unchanged and still asserted: a rule applied *without* asking for a
reset leaves existing connections where they are, and the Connections view reports them as
`preExistingPreviousRoute` rather than claiming they are proxied. The two behaviours are
different answers to the same physical limit, and the suite proves both.

## The exclusion race

Including children is free: a forked child inherits its parent's cgroup. **Excluding** them
cannot be, and it is worth being precise about why.

A socket's cgroup is fixed when the socket is created (`sk_cgrp_data`), and a child is in its
parent's cgroup from the instant `fork` returns. Nothing in userspace can be told about the
child before it exists, so there is always a window between the fork and Yura moving it out.
Two mechanisms narrow it, and the daemon uses both:

- The kernel's **process connector** delivers the fork event, and it is handled inline on the
  netlink thread — no queue, no lock, no `/proc` read, one write to `cgroup.procs`.
- A **guard thread** polls the cgroups of excluding rules and evicts anything that is not the
  rule's own process, which bounds the window to something Yura controls rather than to the
  scheduler's whim. It polls every millisecond from the moment a guarded process forks and for
  as long as it keeps finding children to evict, backs off to every 50 ms when it finds none,
  and sleeps until woken while no rule excludes children. Polling every millisecond regardless
  kept a core from idling for as long as such a rule was installed — the default for "proxy
  this instance".

What remains: a child that connects in roughly its first millisecond of life keeps the route
it inherited. The suite measures it. With a shell forking `curl` in a tight loop — the worst
case, since `curl` does nothing between `exec` and `connect` — **31 of 32 children still
reached the proxy** while the daemon was simultaneously servicing the rest of the suite. In
isolation the same loop leaks about one in ten. A child that does anything at all first, which
is every real application, is excluded reliably: the suite asserts that case (0 of 3 children
proxied, every child the kernel reported moved out) and measures the immediate one separately,
so a regression in the fast path shows up as a number rather than as a passing test. Those
figures are from the guard as it is now — polling every millisecond only once a guarded process
forks — and match the 30 of 31 measured when it polled every millisecond regardless: a burst of
forks keeps it at full rate, which is the case measured.

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

### The end of a reply never reaching the client (agent, found by the acceptance suite)

The first agent run relayed requests correctly and every client timed out anyway. The reply
arrived — the bytes were there — but the *end* of it never did: when a destination closed, the
agent stopped reading and said nothing to the client, which went on waiting for an end of
stream that was not coming. Every client that reads to end-of-stream, which is most of them and
every HTTP client with `Connection: close`, reported a failure while holding the answer.

It was reproduced in seconds once it was stated that way, by a unit test with a destination
that answers and closes, and fixed by giving each direction a way to say "that is all": a
socket half close towards the destination, `close_notify` towards the client. The test is now
the first one in the agent suite.

### A rule's cgroup coming and going (found while investigating a user's report)

A rule's cgroup was created when a process first matched it and deleted when it went empty.
Because `socket cgroupv2` resolves a path to a cgroup id when the ruleset loads, each cycle
left the installed rule pointing at an id that no longer existed — matching nothing, with the
rule visibly present and the counters stuck at zero. A rule's group is now created with the
rule and kept for its lifetime.

### A superseded rule left live in the daemon (found in a user's own daemon)

Reported as "the app says proxied but nothing is routed". The daemon's rule list, read from a
live session, held two rules for the same process:

```
order 100  action direct   descendants exclude
order 101  action proxy    descendants includeFuture
```

Evaluation is first match, so the process was **direct** while the panel showed only rule 101
and labelled it *Proxied*. Neither rule was wrong; what was wrong was that both existed. The
app's rule store replaced a superseded selection in its own list and never asked the daemon to
remove it, and because positions are handed out in ascending order, the rule that had been
replaced always won.

The same dump proved two more faults at once. Rule 100 was `direct` because the panel's
"Proxy this instance" button fell back to Direct when no route was selected — a button that
installed the opposite of its label and then reported success. And rule 101 had
`descendants: includeFuture`, the instance scope, although the panel had "this process and
its children" selected: the button ignored the scope radio entirely.

All three are fixed at the point they were caused, and the app now also prunes rules the
daemon holds that it does not know about, so a daemon that survives an app crash mid-edit
does not keep deciding routes from a rule no page shows.

### IPv6 marked but never captured (found by reading the ruleset)

The classifier marked both families; the capture chain and the policy-routing rule were IPv4
only. An IPv6 flow from a covered process was therefore marked, not captured, and left on the
ordinary route — unproxied, unreported, and for an exit meant to hide an address, a leak of the
address it was hiding. It is now refused instead, counted, and stated in the startup checks.

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
- **A full-cone channel expiring** once the game stops sending, at either end: four minutes at
  the daemon, five at the agent. Nothing here waits that long, and the unit tests check only
  that the daemon's limit is the shorter one.
- **IPv6 inside a tunnel.** The interface gets its IPv6 address and its own `ip -6` rule and
  route when the configuration has one, but every flow in the suite is IPv4.
