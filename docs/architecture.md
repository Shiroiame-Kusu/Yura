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
proxy client they already trust and exposes it locally as SOCKS5 or HTTP(S); Yura
classifies traffic per process and hands it to that endpoint.

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
- **`rp_filter` must be relaxed** for the looped-back packets, or they are dropped.
- **Proxy chains are TCP-only.** Relaying UDP through more than one hop needs every hop to
  support UDP ASSOCIATE and to agree on the relay address, which cannot be verified end to
  end — so `ProxyChain.SupportsUdp` reports Unsupported rather than letting a game silently
  lose its UDP traffic. DNS is the exception: a query has a TCP form (RFC 1035 §4.2.2), so a
  process behind a chain or an HTTP proxy still resolves names instead of failing entirely.
- **A transparent socket bound to a foreign address steals traffic addressed there.** That is
  how a UDP reply appears to come from the peer the application addressed, and it also makes
  the kernel's early demux prefer that socket over the TPROXY redirect. The daemon therefore
  drains those sockets and re-dispatches what arrives on them, so both delivery paths reach
  the same session. Without it, only the first datagram to a destination ever works.
