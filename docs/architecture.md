# Architecture

## Trust boundary

Two processes, one narrow interface between them.

```
┌──────────────────────────────┐        ┌──────────────────────────────────┐
│ Yura.App (unprivileged)      │        │ yura-daemon (privileged)         │
│                              │        │                                  │
│  Processes / Games / Rules   │  Unix  │  cgroup manager                  │
│  Connections / Diagnostics   │◄──────►│  nftables ruleset                │
│  reads /proc directly        │ socket │  policy routing                  │
│  composes rules              │        │  kernel process events           │
│  owns the configuration      │        │  transparent forwarder ──► your  │
│  explains decisions          │        │  socket attribution         proxy│
└──────────────────────────────┘        └──────────────────────────────────┘
```

The app never touches nftables, cgroups or raw sockets. Everything that needs privilege is
behind `IDaemonClient`, which is the entire reviewable surface of the boundary.

`DisconnectedDaemonClient` is the default when no daemon is running. It refuses every
privileged operation with an actionable message rather than throwing or pretending to
succeed, so the app stays fully usable for browsing and composing rules and states plainly
that nothing will take effect.

## No bundled routing engine

Yura does not embed sing-box, mihomo, Xray or anything like them. The user runs whatever
proxy client they already trust and exposes it locally as SOCKS5 or HTTP(S), or supplies a
WireGuard peer; Yura classifies traffic per process and hands it to that exit.

The consequence is that the daemon owns its own transparent forwarder. Per-rule proxy
selection is therefore in-process: one transparent listener per rule, so the port a flow
arrives on identifies the rule that claimed it, with no ambiguity and no shared state.

The "replaceable routing-engine adapter" the specification asks for is an abstraction over
the *interception and forwarding* layer, not over an external engine binary.

## Per-instance classification

The core problem: route **this instance** of a program that is already running, without
restarting it, without a wrapper, without changing the user it runs as, and without
touching another instance of the same binary.

### 1. Identity

A PID is not an identity. The kernel reuses PIDs, and a rule written against a PID alone
would silently transfer to an unrelated process once the number came round again.
`ProcessIdentity` is **PID + start time + uid + boot id**:

- start time is field 22 of `/proc/[pid]/stat`, unique per PID for the lifetime of a boot
- boot id scopes it across reboots, since start times are measured from boot

`ProcessIdentity.Matches` is the single place PID reuse is defended against. Callers must
use it against freshly read `/proc` data immediately before acting, never against a cached
snapshot. The spike re-verifies the start time between selecting a process and migrating it.

### 2. Classification

The daemon creates a cgroup under `/sys/fs/cgroup/yura/` and writes the target PID into
`cgroup.procs`. This migrates a *running* process — no restart, no wrapper, no uid change.
That single write is what makes running-process selection possible at all.

nftables then matches on cgroup membership rather than on executable path:

```
chain classify {
    type route hook output priority mangle;

    meta mark 0x7200 return                      # loop prevention: our own upstream
    oifname "lo" return                          # loopback is never proxied
    ip daddr <proxy> th dport <port> return      # never capture traffic to the proxy

    # s001: cs2 (pid 4821)
    meta l4proto { tcp, udp } \
        socket cgroupv2 level 2 "yura/g001" meta mark set 0x7101 counter accept
}

chain capture {
    type filter hook prerouting priority mangle;
    meta mark 0x7101 meta l4proto tcp tproxy ip to :44231 counter accept
    meta mark 0x7101 meta l4proto udp tproxy ip to :44231 counter accept
}
```

Because the match is on cgroup and not on path, a second instance of the same executable is
untouched, and Wine/Proton games that share a runtime binary are distinguishable — which is
the only reason that requirement is satisfiable at all.

**A cgroup is not a rule.** It is a set of processes covered by exactly the same set of rules.
A process can be in only one cgroup, but several rules may cover it — an instance rule and an
executable rule on the same program, with different destination facets. If each rule owned a
cgroup, a process could satisfy only one of them and first-match evaluation would silently
break for the rest. Grouping by rule *set* instead lets the ruleset emit every rule's match
against every cgroup that contains it, in rule order, so the kernel evaluates exactly what
the rule list says. Acceptance test 9 is what proves it: one process covered by a manual rule
and a game profile reaches the higher rule's proxy, and reversing the order reverses which.

**The listener port is asked of the kernel, not chosen.** A fixed range looks tidier and is
wrong: `ip_local_port_range` commonly starts low enough to include whatever range we picked,
so an unrelated outgoing connection can be holding the port, and the rule fails to install
for a reason no user can act on. Each listener binds port 0 and the ruleset names the port it
was given.

### 3. Capture

Locally generated packets never reach the prerouting hook on their own. Marking them in a
`route`-type output chain forces a re-route; `ip rule fwmark 0x711 lookup 711` then sends
them to a table whose only entry is `local default dev lo`, which loops them back into the
receive path where TPROXY can claim them.

### 4. Forwarding

With `IP_TRANSPARENT`, an accepted TCP socket's own local address **is** the original
destination — no conntrack, no NAT, no `SO_ORIGINAL_DST`. For UDP the original destination
arrives out of band in an `IP_ORIGDSTADDR` control message, and replies must be sent from a
transparent socket bound to that foreign address so the client sees an answer from the peer
it addressed.

Loop prevention: every socket the forwarder opens toward the proxy carries `SO_MARK`, and
the classifier returns early on that mark. Without it the forwarder would feed itself.

### 5. Names

The kernel sees addresses; rules can name hosts. Two mechanisms close that gap, and both live
in the daemon because both need to see the traffic:

- **DNS answers.** When a proxied process resolves a name, the answer comes back through the
  relay. Every A/AAAA record in it is attributed to the question name, so a later flow to one
  of those addresses has a name to match against.
- **SNI and Host headers.** The first bytes of a captured TCP flow are peeked — not consumed —
  and a TLS `ClientHello`'s `server_name` or an HTTP `Host` header gives the name directly.
  Only done when some enabled rule actually names a host, because the peek costs a
  server-speaks-first protocol a few hundred milliseconds and buys nothing otherwise.

A rule that names a host is therefore always a *capture* rule whatever its action: the flow
has to reach the listener before the name is knowable. A host rule with no process selector
is refused rather than installed, because capturing everything to look for a name would mean
capturing the whole machine.

## WireGuard exits

A WireGuard peer is the other kind of exit, and it is handled without a userspace WireGuard
implementation and without touching the machine's default route.

```
selected process ──TPROXY──► daemon ──socket, SO_MARK 0x7300+n, bound to 10.8.0.7──►
   ip rule fwmark 0x7300+n lookup 7300+n ──► default dev yura-wg<n> ──► kernel encrypts ──► peer
```

- **The tunnel is a real kernel interface.** For each exit the daemon creates `yura-wg<n>`,
  hands the keys to `wg setconf` over standard input, assigns the tunnel addresses, and brings
  it up. The keys go to the kernel and are logged nowhere; `wg show` hides them by design.
- **Nothing is routed through it by default.** The only route pointing at the interface lives
  in table `7300+n`, selected by `ip rule fwmark 0x7300+n`. The daemon puts that mark on the
  sockets it opens for flows the rule sends to that exit, and binds them to the tunnel
  address so the far end sees a source it accepts. Every other socket on the machine, in
  every other process, never sees the tunnel: no NAT, no `AllowedIPs` juggling, no
  `wg-quick` default-route hijack.
- **The outer packets are protected the same way the daemon's proxy traffic is.** The
  interface's own `FwMark` is the bypass mark, and the classifier returns early on it and on
  the whole tunnel-mark range, so a rule with no process selector can never capture the
  tunnel's own encrypted packets or the daemon's flows inside it.
- **DNS goes to the exit's resolver.** A process behind a WireGuard exit usually asks a LAN or
  loopback resolver that is unreachable from the far end. When the exit declares resolvers,
  the daemon dials those instead of the address the application asked for, for port 53 only,
  and only under the *through the route* DNS policy. Without a declared resolver the query goes
  through the tunnel to whatever the application asked for, and the probe says so.
- **UDP is native.** A tunnel carries IP, so UDP passes by construction; the relay uses the
  same session it uses for a direct route, with the tunnel's mark and source address.
- **An exit can only start a chain.** The daemon originates the first connection inside the
  tunnel — towards the next hop, or the destination — and carries on with whatever handshakes
  the remaining hops need. A kernel tunnel cannot be carried inside a SOCKS connection, so an
  exit anywhere but first is refused by the app, by the daemon at apply time, and by the
  dialler.
- **Probing is a real handshake.** The probe brings the tunnel up (in place when it is
  already installed with the same configuration, otherwise on a temporary interface), sends a
  DNS query through it, and waits for the peer's handshake and for the resolver's answer.
  "Reachable" means the peer answered; the diagnostics say whether the resolver did too.
- **Unchanged exits are left alone.** Every configuration is fingerprinted (a digest that
  includes the keys and reveals none of them), so re-pushing the proxy list does not tear down
  and re-handshake a tunnel that flows are using.

Marks and tables, for reading `ip rule` and `nft list ruleset` on a machine running Yura:

| Range | Meaning |
| --- | --- |
| `0x7100–0x71FF`, table 711 | Slot marks: classified flows looped back to TPROXY |
| `0x7200` | Bypass: the daemon's upstream sockets, and every tunnel's outer packets |
| `0x7300+n`, table `7300+n`, rule priority `7300+n` | The daemon's sockets inside WireGuard exit *n* |

`rp_filter` is set to 0 on each tunnel interface: replies arrive from addresses the main table
routes elsewhere, and a strict reverse-path check would drop every one of them.

## Yura agents

An agent is Yura's own relay, run on a server near the game's servers. It is the one exit kind
Yura provides both halves of, and that is what it buys:

- **Authentication both ways, with nothing to type.** The agent prints one connect string —
  `yura://<token>@host:port?fp=<key fingerprint>` — which the user pastes into the Proxies
  page. The server is identified by a pinned SHA-256 of its public key, the way SSH pins a
  host key, so there is no certificate authority and no domain name to arrange; the client is
  identified by a 32-byte token, compared in constant time. The token is a secret and goes to
  the secret store; the fingerprint is a public key and goes to the configuration file.
- **UDP as a first-class transport.** Games are mostly UDP. The agent's datagram channel is
  its own UDP flow with its own AES-GCM sealing, keyed per session and per direction from a
  key issued inside the authenticated TLS connection, with a 64-packet replay window. Carrying
  UDP inside the TCP connection instead would put every game packet behind the retransmission
  of the one before it, which is the damage an accelerator exists to avoid.
- **Latency from the agent's own vantage point.** It will measure a destination on request, so
  the Games page can say where a routed round trip went: this far to the agent, that much
  further to the game. That is the difference between knowing a route is faster and knowing
  whether a better agent would help.
- **A resolver that means something at the far end.** The agent offers the resolver it uses
  itself, and lookups from processes on that exit go there. A game's servers are chosen by
  DNS, so resolving where the agent stands is part of the acceleration rather than a detail.

Structurally: one TLS 1.3 connection per relayed TCP flow, one long-lived control connection
per client, one shared UDP socket for the datagrams. Streams are separate connections rather
than multiplexed over one, so no flow waits behind another and the kernel does the flow
control. After the agent answers `Opened`, a stream connection carries nothing but the
application's bytes — which is also why an agent can sit anywhere in a chain, unlike a
WireGuard exit, and why TLS 1.3's `close_notify` can carry a half close all the way to the
destination, which an HTTP proxy reached over TLS cannot.

On the server the agent refuses private, loopback and link-local destinations unless told
otherwise, so a token holder can accelerate a game and cannot use the agent to reach the
server's own network. The one exception is the resolver it advertised, on port 53. Its unit
takes away everything it does not need: `DynamicUser`, no capabilities, `ProtectSystem=strict`,
and a state directory only it can read.

## The daemon as a service

The Settings page installs the daemon as `yura-daemon.service`. The unit is generated by the
app, shown in full, and installed by one script that is also shown in full before it runs as
root through `pkexec` — the desktop's polkit agent asks for the user's password, exactly as
a settings panel would. Nothing edits sudoers and nothing stores a credential.

The script copies the daemon's build directory to `/usr/local/lib/yura/daemon` so the service
does not depend on a source tree or a home directory, then writes the unit and enables it. The
unit runs the daemon with `ProtectHome=yes`, `ProtectSystem=strict`, `PrivateTmp`,
`NoNewPrivileges`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` and `HOME`
pointed at its tmpfs runtime directory, so anything the .NET runtime insists on writing lands
in `/run/yura` and never in anyone's home. `/proc/sys` and `/sys/fs/cgroup` stay writable
because the daemon writes to both; `ProtectKernelTunables` and `ProtectControlGroups` are
deliberately absent.

The script runs from a directory only the user can write to, so another local user cannot
swap it between the moment it is written and the moment root runs it. Start, stop and
restart go straight to `systemctl`, which asks polkit itself.

## What falls out for free, and what does not

- **Child processes.** A forked child inherits its parent's cgroup, so process-tree rules
  need no extra machinery. *Excluding* them is a race that cannot be won outright — see
  [the exclusion race](daemon-acceptance.md#the-exclusion-race).
- **Pre-existing connections.** A socket's cgroup is fixed at creation (`sk_cgrp_data`), so
  sockets opened before a rule was applied keep their original route. This is the correct
  semantic and the UI reports it truthfully rather than claiming the flow is proxied.
- **Process lifecycle.** The kernel's process connector (`NETLINK_CONNECTOR` / `CN_IDX_PROC`)
  reports fork, exec and exit. Exec is what lets a persistent executable rule catch a process
  before its first connection; exit is what expires an instance rule before its pid can be
  reused. A periodic sweep re-derives everything from `/proc` regardless, so a dropped event
  costs latency rather than correctness, and the Diagnostics page reports which mechanism is
  actually running.

## Rule evaluation

One ordered list, shared by manual process selections and game profiles. They are the same
kind of object and differ only in `Origin` and `Lifetime` — which is what makes precedence
between them explainable instead of emergent.

`RuleEvaluator` is pure and side-effect free, so the daemon and the UI cannot disagree about
which rule wins: the UI runs exactly the same code to render its explanation, including the
list of rules that also matched but lost on order.

Instance and process-tree membership is decided by the **classifier**, not by walking parent
PIDs at match time — a walk would race with re-parenting when an intermediate process exits.
When the kernel has spoken for a flow, `RoutingRequest.ClassifierMatchedRuleIds` carries
that answer and the evaluator treats it as authoritative.

Unmatched traffic defaults to Direct.

Because the listener re-evaluates the whole ordered list for each flow it captures — with the
kernel's answer for the process side and the learned name for the destination side — a rule
that only becomes decidable once the flow exists (a host-name rule) still wins over a lower
rule that the kernel could match on its own. The kernel narrows; it does not decide.

## Honesty in the model

Several types exist specifically to stop the UI asserting more than is known:

| Type | What it prevents |
| --- | --- |
| `ExecutablePathState` | A blank cell that could mean either "no path" or "we failed to read it" |
| `RouteObservation` | Reporting a flow as *Proxied* without having observed it. Only `ConfirmedProxied` — where the daemon holds both sockets — may render as proxied |
| `CapabilityState` | Inferring UDP support from the protocol instead of measuring it |
| `Metric.Value` (nullable) | Rendering an unmeasured figure as `0`, which reads as a perfect score |
| `ProcessSnapshot.ConnectionCount` (nullable) | `0` meaning both "none" and "unknown" |

## Known trade-offs

- **Migrating a process out of its systemd user slice** means `systemctl --user stop` and
  systemd's resource accounting no longer cover it while the rule is in effect. The obvious
  alternative — nesting our cgroup under the process's existing one — collides with cgroup
  v2's "no internal processes" rule once controllers are enabled. What the daemon does
  instead is remember where each process came from and put it back there when its rule goes
  away, so leaving Yura's tree returns a process to its own scope rather than dumping it in
  the root cgroup.
- **`socket cgroupv2` resolves the path to a cgroup id at rule-load time.** Deleting and
  recreating a cgroup silently breaks matching, so the daemon must reload the ruleset
  whenever it recreates one. This is a sharp edge and is called out in the spike.
- **A program that opens a socket within about two milliseconds of `exec` is not captured.**
  A socket's cgroup is fixed when it is created, and the kernel's notification that a process
  has exec'd arrives after that for the very fastest programs — `curl` is one. The daemon
  places a process from the netlink thread with one readlink and one write, which wins for
  anything with a normal start-up (a game, an interpreter, a launcher: measured at 5 of 5), and
  loses for a program that connects immediately (measured at 0 of 8). Closing it properly needs
  the kernel to decide at socket creation — an eBPF `cgroup/sock_create` hook — rather than a
  notification after the fact. What the daemon does instead is never claim otherwise: a
  connection it does not hold is reported as not routed, and the Games page says so.
- **A rule's cgroup is created with the rule and kept for its lifetime, even while empty.**
  Retiring an empty group looks tidier and is a trap, because `socket cgroupv2` resolved that
  path to a cgroup id when the ruleset was loaded: deleting and recreating the directory leaves
  the installed rule pointing at an id that no longer exists, matching nothing, until something
  happens to reload the ruleset. An empty cgroup costs a directory.
- **IPv4 only; IPv6 from a covered process is refused.** TPROXY hands a marked packet to a
  listener with `tproxy ip`, and the policy-routing rule that loops it back is an IPv4 rule.
  Marking an IPv6 packet would change nothing about where it went, so it would leave on the
  ordinary route while Yura reported the rule as being in effect — a silent leak of exactly
  what an exit is meant to carry. The classifier therefore marks IPv4 and refuses IPv6 for a
  covered process, which makes applications fall back to IPv4 within milliseconds, and the
  daemon states it among its startup checks. Capturing IPv6 properly needs an IPv6 rule and
  route, `tproxy ip6`, and an IPv6 listener with `IPV6_RECVORIGDSTADDR` for the UDP path.
- **Nothing can recapture a connection that escaped.** A socket keeps the cgroup it was born
  in, so a connection opened before its rule — or in the window above — cannot be moved onto
  the route. It can only be reported, which is what `PreExistingPreviousRoute` is for.
- **`rp_filter` must be relaxed** for the looped-back packets, or they are dropped.
- **Proxy chains are TCP-only.** Relaying UDP through more than one hop needs every hop to
  support UDP ASSOCIATE and to agree on the relay address, which cannot be verified end to
  end — so `ProxyChain.SupportsUdp` reports Unsupported rather than letting a game silently
  lose its UDP traffic. DNS is the exception: a query has a TCP form (RFC 1035 §4.2.2), so a
  process behind a chain or an HTTP proxy still resolves names instead of failing entirely.
- **A WireGuard exit is per-process without NAT, so the far end sees the tunnel address.**
  The daemon re-originates each flow from the tunnel address rather than re-routing the
  application's own socket, which is what makes a masquerade rule unnecessary and keeps the
  Connections page's *confirmed proxied* claim true for tunnels too: the daemon holds both
  ends of every flow it sends into one.
- **A transparent socket bound to a foreign address steals traffic addressed there.** That is
  how a UDP reply appears to come from the peer the application addressed, and it also makes
  the kernel's early demux prefer that socket over the TPROXY redirect. The daemon therefore
  drains those sockets and re-dispatches what arrives on them, so both delivery paths reach
  the same session. Without it, only the first datagram to a destination ever works.
