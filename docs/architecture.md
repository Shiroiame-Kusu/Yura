# Architecture

## Trust boundary

Two processes, one narrow interface between them.

```
┌──────────────────────────────┐        ┌──────────────────────────────────┐
│ Yura.App (unprivileged)      │        │ yura-daemon (privileged)         │
│                              │        │                                  │
│  Processes / Games / Rules   │  Unix  │  cgroup manager                  │
│  reads /proc directly        │◄──────►│  nftables ruleset                │
│  composes rules              │ socket │  policy routing                  │
│  explains decisions          │        │  transparent forwarder ──► your  │
│                              │        │  process/socket attribution      proxy
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

The daemon creates `/sys/fs/cgroup/yura/<rule-id>` and writes the target PID into
`cgroup.procs`. This migrates a *running* process — no restart, no wrapper, no uid change.
That single write is what makes running-process selection possible at all.

nftables then matches on cgroup membership rather than on executable path:

```
chain classify {
    type route hook output priority mangle;

    meta mark 0x712 return                       # loop prevention: our own upstream
    ip daddr <proxy> tcp dport <port> return     # never capture traffic to the proxy

    meta l4proto { tcp, udp } \
        socket cgroupv2 level 2 "yura/<rule-id>" meta mark set 0x711
}

chain capture {
    type filter hook prerouting priority mangle;
    meta mark 0x711 meta l4proto tcp tproxy ip to :<port> accept
    meta mark 0x711 meta l4proto udp tproxy ip to :<port> accept
}
```

Because the match is on cgroup and not on path, a second instance of the same executable is
untouched, and Wine/Proton games that share a runtime binary are distinguishable — which is
the only reason that requirement is satisfiable at all.

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

## What falls out for free

- **Child processes.** A forked child inherits its parent's cgroup, so process-tree rules
  need no extra machinery. *Excluding* children is the case that costs work: the daemon has
  to move them back out on the fork event.
- **Pre-existing connections.** A socket's cgroup is fixed at creation (`sk_cgrp_data`), so
  sockets opened before a rule was applied keep their original route. This is the correct
  semantic and the UI reports it truthfully rather than claiming the flow is proxied.

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
  systemd's resource accounting no longer cover it. The obvious alternative — nesting our
  cgroup under the process's existing one — collides with cgroup v2's "no internal
  processes" rule once controllers are enabled. Documented rather than hidden.
- **`socket cgroupv2` resolves the path to a cgroup id at rule-load time.** Deleting and
  recreating a cgroup silently breaks matching, so the daemon must reload the ruleset
  whenever it recreates one. This is a sharp edge and is called out in the spike.
- **`rp_filter` must be relaxed** for the looped-back packets, or they are dropped.
- **Proxy chains are TCP-only.** Relaying UDP through more than one hop needs every hop to
  support UDP ASSOCIATE and to agree on the relay address, which cannot be verified end to
  end — so `ProxyChain.SupportsUdp` reports Unsupported rather than letting a game silently
  lose its UDP traffic.
